//! Wi-Fi connection attempts and roams, from the APs' connection-tracking
//! notifications (`STA_ASSOC_TRACKER`), following the official controller's
//! rules:
//!
//! - An attempt is a `success`, `failure`, `soft failure` or `fixup` report. It
//!   succeeded unless it is a failure, when it was a roam (soft failure with
//!   an IP kept by roaming), saw traffic and DNS answers, or (older firmware)
//!   saw a DNS response. A failure is placed at the furthest stage any of its
//!   failure counters belongs to; failures on a signal below -75 dBm are left
//!   out. A later `fixup` for the same client, AP, network and event id
//!   (within 20 minutes) merges into the attempt, which then succeeded if
//!   either part did.
//! - Timings come from the cumulative microsecond deltas: association, then
//!   authentication (the first of WPA/RADIUS/open auth after association),
//!   DHCP, DNS/first traffic, each kept only when between 0 and 60 s.
//! - A roam pairs a `sta_roam`/`sta_leave` on one AP with the client's next
//!   report on another AP of the same network. It succeeded if the AP called
//!   it a roam or the client was back within a second; 802.11r ("ft") and the
//!   AP's roaming triggers (minimum RSSI, roaming assistant) are recorded.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};
use crate::engine::Live;
use crate::api::read;
use crate::insights::{RangeQuery, window};
use crate::model::Ts;
use crate::store::Db;

/// One field of a notification, as the AP sent it.
#[derive(Debug, Clone, PartialEq)]
pub enum Field {
    Null,
    Int(i64),
    Float(f64),
    Str(String),
    /// Anything else (true/false, a list, an object), kept for comparisons only.
    Other(Value),
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Field, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Null => Field::Null,
            Value::Number(n) => n.as_i64().map_or_else(|| Field::Float(n.as_f64().unwrap_or(f64::NAN)), Field::Int),
            Value::String(s) => Field::Str(s),
            v => Field::Other(v),
        })
    }
}

impl Field {
    /// A number, sent as one or as a string.
    fn num(&self) -> Option<f64> {
        match self {
            Field::Int(i) => Some(*i as f64),
            Field::Float(f) => Some(*f),
            Field::Str(s) => s.parse().ok(),
            _ => None,
        }
    }
}

/// A present field, even `null` (`None` is for an absent one).
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Field>, D::Error> {
    Field::deserialize(d).map(Some)
}

fn num(f: &Option<Field>) -> Option<f64> {
    f.as_ref().and_then(Field::num)
}

fn text(f: &Option<Field>) -> Option<&str> {
    match f {
        Some(Field::Str(s)) => Some(s),
        _ => None,
    }
}

fn int(f: &Option<Field>) -> Option<i64> {
    match f {
        Some(Field::Int(i)) => Some(*i),
        _ => None,
    }
}

/// The fields of a connection-tracking report apctl reads, each parsed once
/// (`None`: not in the report), and how a fixup's fields update a failure's.
macro_rules! detail {
    ($($f:ident),* $(,)?) => {
        #[derive(Debug, Clone, Default, PartialEq, Deserialize)]
        pub struct ConnDetail {
            $(#[serde(default, deserialize_with = "present")] pub $f: Option<Field>,)*
        }

        impl ConnDetail {
            /// Takes every field `other` has.
            fn merge(&mut self, other: &ConnDetail) {
                $(if other.$f.is_some() {
                    self.$f.clone_from(&other.$f);
                })*
            }
        }
    };
}

detail!(
    event_id, ip_assign_type, dns_resp_seen, traffic_delta, dns_responses, assoc_failures, auth_failures, wpa_auth_failures, radius_auth_status, ip_failures,
    dns_timeouts, traffic_failures, assoc_delta, wpa_auth_delta, radius_auth_delta, auth_delta, ip_delta, auth_rssi, avg_rssi, x_channel, x_bw, sta_dc_reason,
    assoc_status, auth_algo,
);

/// One connection-tracking notification from an AP.
#[derive(Debug, Clone)]
pub struct ConnEvent {
    pub ts: Ts,
    pub ap: String,
    pub client: String,
    pub vap: Option<String>,
    pub essid: Option<String>,
    pub radio: Option<String>,
    pub event_type: String,
    pub n: ConnDetail,
}

/// Connection stages in the order a client passes them.
pub const STAGES: [&str; 6] = ["association", "authentication", "dhcp", "dns", "traffic", "success"];

/// Failure counters present in a report, as (stage 1-5, label).
fn failures(n: &ConnDetail) -> Vec<(usize, &'static str)> {
    let pos = |f: &Option<Field>| num(f).is_some_and(|v| v > 0.0);
    let mut out = Vec::new();
    if pos(&n.assoc_failures) {
        out.push((1, "Association"));
    }
    if pos(&n.auth_failures) {
        out.push((2, "Authentication"));
    }
    if pos(&n.wpa_auth_failures) {
        out.push((2, "WPA authentication"));
    }
    if text(&n.radius_auth_status) == Some("failure") {
        out.push((2, "RADIUS authentication"));
    }
    if pos(&n.ip_failures) {
        out.push((3, "DHCP timeout"));
    }
    if pos(&n.dns_timeouts) {
        out.push((4, "DNS timeout"));
    }
    if text(&n.dns_resp_seen) == Some("no") {
        out.push((4, "DNS response not seen"));
    }
    if pos(&n.traffic_failures) {
        out.push((5, "Traffic failure"));
    }
    out
}

/// A soft failure that kept its IP by roaming.
fn roamed(event_type: &str, n: &ConnDetail) -> bool {
    event_type == "soft failure" && text(&n.ip_assign_type).is_some_and(|v| v.starts_with("roam"))
}

fn succeeded(event_type: &str, n: &ConnDetail) -> bool {
    let pos = |f: &Option<Field>| num(f).is_some_and(|v| v > 0.0);
    event_type != "failure"
        && (roamed(event_type, n) || (n.traffic_delta.is_none() && text(&n.dns_resp_seen) == Some("yes")) || (pos(&n.traffic_delta) && pos(&n.dns_responses)))
}

/// Milliseconds per stage, from the cumulative microsecond deltas.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Timings {
    pub association: Option<f64>,
    pub authentication: Option<f64>,
    pub dhcp: Option<f64>,
    pub dns: Option<f64>,
    pub total: Option<f64>,
}

fn timings(n: &ConnDetail) -> Timings {
    // Deltas over a minute are not believable; they are dropped.
    let d = |f: &Option<Field>| num(f).filter(|v| *v > 0.0 && *v <= 60_000_000.0);
    let ms = |us: f64| (us / 100.0).round() / 10.0;
    let assoc = d(&n.assoc_delta);
    let auth = [&n.wpa_auth_delta, &n.radius_auth_delta, &n.auth_delta].into_iter().find_map(|f| d(f).filter(|a| assoc.is_none_or(|x| *a > x)));
    let ip = d(&n.ip_delta);
    let traffic = d(&n.traffic_delta);
    Timings {
        association: assoc.map(ms),
        authentication: auth.zip(assoc).map(|(a, s)| ms(a - s)),
        dhcp: ip.zip(auth).filter(|(i, a)| i > a).map(|(i, a)| ms(i - a)),
        dns: traffic.zip(ip).filter(|(t, i)| t > i).map(|(t, i)| ms(t - i)),
        total: traffic.map(ms),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Attempt {
    pub ts: Ts,
    pub client: String,
    pub ap: String,
    pub essid: Option<String>,
    pub radio: Option<String>,
    pub channel: Option<i64>,
    pub bw: Option<i64>,
    pub success: bool,
    /// Furthest stage reached (1 association .. 6 success).
    pub stage: usize,
    /// Why it failed, for failures.
    pub failure: Option<&'static str>,
    pub rssi: Option<f64>,
    pub timings: Timings,
    /// The AP reported a roam (soft failure) rather than a fresh connection.
    pub roam: bool,
    /// A failure the AP later corrected.
    pub fixed_up: bool,
    /// The AP's own disconnect/failure reason text, when it gave one.
    pub reason: Option<String>,
}

/// How far back a fixup reaches for the failure it corrects.
const FIXUP_WITHIN: Ts = 1200;

/// Connection attempts from the notifications, oldest first.
pub fn attempts(mut events: Vec<ConnEvent>) -> Vec<Attempt> {
    events.retain(|e| matches!(e.event_type.as_str(), "failure" | "soft failure" | "success" | "fixup"));
    events.sort_by_key(|e| e.ts);
    // (event, succeeded on its own, merged with a fixup)
    let mut merged: Vec<(ConnEvent, bool, bool)> = Vec::new();
    for e in events {
        let ok = succeeded(&e.event_type, &e.n);
        if e.event_type == "fixup"
            && let Some(id) = e.n.event_id.as_ref().filter(|v| **v != Field::Null)
            // Sorted by time: only the last 20 minutes need looking at.
            && let Some(prev) = merged.iter_mut().rev().take_while(|(p, _, _)| e.ts - p.ts <= FIXUP_WITHIN).find(|(p, _, _)| {
                p.ap == e.ap && p.client == e.client && p.vap == e.vap && p.n.event_id.as_ref() == Some(id) && p.event_type.contains("failure")
            })
        {
            prev.0.n.merge(&e.n);
            prev.1 = prev.1 || ok;
            prev.2 = true;
            continue;
        }
        merged.push((e, ok, false));
    }
    merged
        .into_iter()
        .filter_map(|(e, ok, fixed)| {
            let n = &e.n;
            let rssi = num(&n.auth_rssi).or_else(|| num(&n.avg_rssi));
            let (stage, failure) = if ok {
                (6, None)
            } else {
                if rssi.is_some_and(|r| r < -75.0) {
                    return None;
                }
                let worst = *failures(n).iter().max_by_key(|f| f.0)?;
                (worst.0, Some(worst.1))
            };
            Some(Attempt {
                ts: e.ts,
                roam: roamed(&e.event_type, n),
                channel: int(&n.x_channel),
                bw: int(&n.x_bw),
                success: ok,
                stage,
                failure,
                rssi,
                timings: timings(n),
                fixed_up: fixed,
                reason: text(&n.sta_dc_reason).filter(|r| !r.is_empty() && !ok).map(str::to_string),
                client: e.client,
                ap: e.ap,
                essid: e.essid,
                radio: e.radio,
            })
        })
        .collect()
}
/// Connection success per client: each client counts once, at the furthest
/// stage any of its attempts reached; timings are averaged over the attempts
/// that have them.
pub fn connectivity_stats(attempts: &[Attempt], band: Option<&str>) -> Value {
    let list: Vec<&Attempt> = attempts.iter().filter(|a| band.is_none_or(|b| a.radio.as_deref() == Some(b))).collect();
    let mut furthest: BTreeMap<&str, usize> = BTreeMap::new();
    for a in &list {
        let f = furthest.entry(a.client.as_str()).or_insert(0);
        *f = (*f).max(a.stage);
    }
    let clients = furthest.len();
    let pct = |past: usize| (clients > 0).then(|| (100.0 * furthest.values().filter(|s| **s > past).count() as f64 / clients as f64).round());
    let avg = |f: &dyn Fn(&Timings) -> Option<f64>| {
        let v: Vec<f64> = list.iter().filter_map(|a| f(&a.timings)).collect();
        (!v.is_empty()).then(|| (v.iter().sum::<f64>() / v.len() as f64).round())
    };
    json!({
        "attempts": list.len(),
        "clients": clients,
        "failed_clients": furthest.values().filter(|s| **s < 6).count(),
        "association_pct": pct(1), "authentication_pct": pct(2), "dhcp_pct": pct(3), "dns_pct": pct(4),
        "success_pct": pct(5),
        "failed_at": STAGES.iter().take(5).enumerate().map(|(i, k)| (k.to_string(), json!(furthest.values().filter(|s| **s == i + 1).count()))).collect::<serde_json::Map<_, _>>(),
        "latency_ms": {
            "association": avg(&|t| t.association), "authentication": avg(&|t| t.authentication), "dhcp": avg(&|t| t.dhcp),
            "dns": avg(&|t| t.dns), "total": avg(&|t| t.total),
        },
    })
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RoamEnd {
    pub ap: String,
    pub essid: Option<String>,
    pub radio: Option<String>,
    pub channel: Option<i64>,
    pub bw: Option<i64>,
    pub rssi: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Roam {
    pub ts: Ts,
    pub client: String,
    pub from: RoamEnd,
    pub to: RoamEnd,
    pub success: bool,
    /// Seconds without a connection, for failed roams.
    pub gap_s: Option<i64>,
    /// 802.11r fast transition.
    pub fast: bool,
    /// The AP pushed the client off: its signal fell below the minimum RSSI.
    pub min_rssi: bool,
    /// The AP's roaming assistant steered the client.
    pub assistant: bool,
}

fn end_of(e: &ConnEvent, rssi: &Option<Field>) -> RoamEnd {
    RoamEnd {
        ap: e.ap.clone(),
        essid: e.essid.clone(),
        radio: e.radio.clone(),
        channel: int(&e.n.x_channel),
        bw: int(&e.n.x_bw),
        rssi: num(rssi),
    }
}

fn band_rank(radio: Option<&str>) -> u8 {
    match radio {
        Some("6e") => 3,
        Some("na") => 2,
        _ => 1,
    }
}

/// Roams: a client leaving one AP paired with it joining another.
pub fn roams(events: &[ConnEvent]) -> Vec<Roam> {
    let mut by_client: BTreeMap<&str, Vec<&ConnEvent>> = BTreeMap::new();
    for e in events {
        by_client.entry(e.client.as_str()).or_default().push(e);
    }
    let mut out = Vec::new();
    for (client, mut evs) in by_client {
        evs.sort_by_key(|e| e.ts);
        // Whether each event is a leave, and whether it carries the signal a join needs.
        let leave: Vec<bool> = evs.iter().map(|e| matches!(e.event_type.as_str(), "sta_roam" | "sta_leave")).collect();
        let joined: Vec<bool> = evs.iter().zip(&leave).map(|(e, l)| !l && num(&e.n.auth_rssi).is_some()).collect();
        let mut used: HashSet<usize> = HashSet::new();
        for (li, l) in evs.iter().enumerate() {
            if !leave[li] || num(&l.n.avg_rssi).is_none() {
                continue;
            }
            // The join: another AP on the same network, with the signal it joined at,
            // from 10 s before to 15 s after the leave.
            let (lo, hi) = (evs.partition_point(|j| j.ts < l.ts - 10), evs.partition_point(|j| j.ts <= l.ts + 15));
            let join = (lo..hi)
                .map(|ji| (ji, evs[ji]))
                .filter(|(ji, j)| joined[*ji] && !used.contains(ji) && j.ap != l.ap && (j.essid.is_none() || l.essid.is_none() || j.essid == l.essid))
                .max_by_key(|(_, j)| (band_rank(j.radio.as_deref()), std::cmp::Reverse((j.ts - l.ts).abs())));
            let Some((ji, j)) = join else { continue };
            used.insert(ji);
            let gap = j.ts - l.ts;
            let success = l.event_type == "sta_roam" || gap.abs() <= 1;
            let status = num(&l.n.assoc_status).unwrap_or(0.0) as i64;
            out.push(Roam {
                ts: j.ts.max(l.ts),
                client: client.to_string(),
                from: end_of(l, &l.n.avg_rssi),
                to: end_of(j, &j.n.auth_rssi),
                success,
                gap_s: (!success).then_some(gap.max(0)),
                fast: text(&j.n.auth_algo) == Some("ft"),
                min_rssi: status & 16 != 0,
                assistant: status & 8192 != 0,
            });
        }
    }
    out.sort_by_key(|r| r.ts);
    out
}

/// Roams per pair of APs (either direction), with per-direction counts.
pub fn roam_pairs(roams: &[Roam]) -> Vec<Value> {
    #[derive(Default)]
    struct Dir {
        attempts: u64,
        successes: u64,
        fast: u64,
        assistant: u64,
        min_rssi: u64,
    }
    // (AP, AP) -> (first to second, second to first, roams per client)
    type Pair = (Dir, Dir, HashMap<String, u64>);
    let mut pairs: BTreeMap<(String, String), Pair> = BTreeMap::new();
    for r in roams {
        let (a, b) = (r.from.ap.clone(), r.to.ap.clone());
        let forward = a <= b;
        let key = if forward { (a, b) } else { (b, a) };
        let e = pairs.entry(key).or_default();
        let d = if forward { &mut e.0 } else { &mut e.1 };
        d.attempts += 1;
        d.successes += u64::from(r.success);
        d.fast += u64::from(r.fast);
        d.assistant += u64::from(r.assistant);
        d.min_rssi += u64::from(r.min_rssi);
        *e.2.entry(r.client.clone()).or_default() += 1;
    }
    let dir = |d: &Dir| json!({ "attempts": d.attempts, "successes": d.successes, "fast": d.fast, "assistant": d.assistant, "min_rssi": d.min_rssi });
    pairs
        .into_iter()
        .map(|((a, b), (ab, ba, clients))| {
            let attempts = ab.attempts + ba.attempts;
            let ok = ab.successes + ba.successes;
            let mut top: Vec<(String, u64)> = clients.into_iter().collect();
            top.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
            top.truncate(10);
            json!({
                "ap_1": a, "ap_2": b, "attempts": attempts, "successes": ok,
                "success_pct": if attempts > 0 { (100.0 * ok as f64 / attempts as f64).round() } else { 0.0 },
                "forward": dir(&ab), "backward": dir(&ba),
                "top_clients": top.into_iter().map(|(c, n)| json!({ "mac": c, "roams": n })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// Per client: roams, failures, the signal it left at, and (apctl's own
/// measures, not in the official controller) roams to a clearly weaker AP
/// and quick returns to the AP it just left ("ping-pong").
pub fn roam_clients(roams: &[Roam]) -> Vec<Value> {
    let mut per: BTreeMap<&str, Vec<&Roam>> = BTreeMap::new();
    for r in roams {
        per.entry(&r.client).or_default().push(r);
    }
    let mut out: Vec<Value> = per
        .into_iter()
        .map(|(c, mut rs)| {
            rs.sort_by_key(|r| r.ts);
            let sig: Vec<f64> = rs.iter().filter_map(|r| r.from.rssi).collect();
            let weaker = rs.iter().filter(|r| matches!((r.from.rssi, r.to.rssi), (Some(f), Some(t)) if t < f - 3.0)).count();
            let back = rs.windows(2).filter(|w| w[1].to.ap == w[0].from.ap && w[1].ts - w[0].ts <= 120).count();
            json!({
                "mac": c, "roams": rs.len(), "failed": rs.iter().filter(|r| !r.success).count(),
                "fast": rs.iter().filter(|r| r.fast).count(),
                "avg_leave_rssi": (!sig.is_empty()).then(|| (sig.iter().sum::<f64>() / sig.len() as f64).round()),
                "to_weaker": weaker, "quick_returns": back,
            })
        })
        .collect();
    out.sort_by(|a, b| b["roams"].as_u64().cmp(&a["roams"].as_u64()));
    out
}

/// The notifications in a window (optionally one client's), oldest first; or
/// with `newest`, at most that many, newest first.
pub fn load_rows(c: &rusqlite::Connection, from: Ts, to: Ts, client: Option<&str>, newest: Option<usize>) -> rusqlite::Result<Vec<ConnEvent>> {
    const COLUMNS: &str = "SELECT ts, ap_mac, client_mac, vap, essid, radio, event_type, detail, ip_assign_type, dns_responses, dns_timeouts, rssi FROM connections";
    // Two statements: `(?3 IS NULL OR client_mac = ?3)` would keep SQLite off the per-client index.
    let filter = if client.is_some() { "client_mac = ?3 AND ts >= ?1 AND ts <= ?2" } else { "ts >= ?1 AND ts <= ?2" };
    let order = match newest {
        Some(n) => format!("ORDER BY ts DESC, id DESC LIMIT {n}"),
        None => "ORDER BY ts, id".into(),
    };
    let mut stmt = c.prepare(&format!("{COLUMNS} WHERE {filter} {order}"))?;
    let params: Vec<&dyn rusqlite::ToSql> = match &client {
        Some(m) => vec![&from, &to, m],
        None => vec![&from, &to],
    };
    stmt.query_map(params.as_slice(), |r| {
        let detail = r.get_ref(7)?.as_str_or_null()?;
        // Rows from before the full notification was kept: rebuild what we can.
        let n = detail.and_then(|d| serde_json::from_str(d).ok()).unwrap_or_else(|| ConnDetail {
            ip_assign_type: r.get::<_, Option<String>>(8).ok().flatten().map(Field::Str),
            dns_responses: r.get::<_, Option<i64>>(9).ok().flatten().map(Field::Int),
            dns_timeouts: r.get::<_, Option<i64>>(10).ok().flatten().map(Field::Int),
            avg_rssi: r.get::<_, Option<i64>>(11).ok().flatten().map(Field::Int),
            ..Default::default()
        });
        Ok(ConnEvent { ts: r.get(0)?, ap: r.get(1)?, client: r.get(2)?, vap: r.get(3)?, essid: r.get(4)?, radio: r.get(5)?, event_type: r.get(6)?, n })
    })?
    .collect()
}

/// Loads the notifications in a window (optionally one client's), oldest first.
async fn load(s: &AppState, from: Ts, to: Ts, client: Option<String>) -> Result<Vec<ConnEvent>, ApiError> {
    read(&s.store, Db::Config, move |c| Ok(load_rows(c, from, to, client.as_deref(), None)?)).await
}

/// The newest `limit` attempts (failed ones only with `failed`) and roams in
/// the window, newest first. Rows are read newest first, a growing batch at a
/// time, until both lists are full or the window is read: of a batch, only
/// what lies more than [`FIXUP_WITHIN`] after its oldest row counts, as a
/// fixup can still merge into a failure that long before it (and a roam's
/// two reports are seconds apart).
fn newest(c: &rusqlite::Connection, from: Ts, to: Ts, client: Option<&str>, limit: usize, failed: bool) -> rusqlite::Result<(Vec<Attempt>, Vec<Roam>)> {
    let mut batch = (limit * 4).max(2000);
    loop {
        let mut events = load_rows(c, from, to, client, Some(batch))?;
        let all = events.len() < batch;
        // The oldest time read may have more rows than were read.
        let oldest = events.last().map_or(from, |e| e.ts);
        let settled = |ts: Ts| all || ts > oldest.saturating_add(FIXUP_WITHIN);
        events.reverse();
        let r: Vec<Roam> = roams(&events).into_iter().rev().filter(|x| settled(x.ts)).take(limit).collect();
        let list: Vec<Attempt> = attempts(events).into_iter().rev().filter(|a| settled(a.ts) && (!failed || !a.success)).take(limit).collect();
        if all || (list.len() == limit && r.len() == limit) {
            return Ok((list, r));
        }
        batch *= 4;
    }
}

/// Every AP and client apctl knows, by MAC, with its display name if it has one.
#[derive(Debug, Default)]
pub struct Names {
    pub aps: HashMap<String, Option<String>>,
    pub clients: HashMap<String, Option<String>>,
}

impl Names {
    /// From the database: APs' names (else hostnames) and clients' hostnames.
    pub fn load(c: &rusqlite::Connection) -> rusqlite::Result<Names> {
        let pairs = |sql: &str| -> rusqlite::Result<HashMap<String, Option<String>>> {
            c.prepare(sql)?.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?.collect()
        };
        Ok(Names { aps: pairs("SELECT mac, COALESCE(name, hostname) FROM devices")?, clients: pairs("SELECT mac, hostname FROM clients")? })
    }

    /// The same for some clients only: every AP (there are few), and the clients asked for.
    fn load_for(c: &rusqlite::Connection, clients: &BTreeSet<&str>) -> rusqlite::Result<Names> {
        let aps = c.prepare("SELECT mac, COALESCE(name, hostname) FROM devices")?.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut names = Names { aps, clients: HashMap::new() };
        let list: Vec<&str> = clients.iter().copied().collect();
        for chunk in list.chunks(500) {
            let sql = format!("SELECT mac, hostname FROM clients WHERE mac IN ({})", vec!["?"; chunk.len()].join(", "));
            for row in c.prepare(&sql)?.query_map(rusqlite::params_from_iter(chunk), |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))? {
                let (mac, name) = row?;
                names.clients.insert(mac, name);
            }
        }
        Ok(names)
    }

    /// What the APs and clients report now on top, then aliases (which win).
    pub fn add_live(&mut self, live: &Live) {
        let put = |map: &mut HashMap<String, Option<String>>, mac: &inform::Mac, name: &Option<String>| {
            let e = map.entry(mac.to_string()).or_default();
            if name.is_some() {
                e.clone_from(name);
            }
        };
        for (mac, d) in &live.devices {
            put(&mut self.aps, mac, &d.snapshot.ap.hostname);
        }
        for mac in live.known_devices.keys() {
            put(&mut self.aps, mac, &None);
        }
        for (mac, c) in &live.clients {
            put(&mut self.clients, mac, &c.sample.hostname);
        }
        for (mac, a) in live.aliases.iter().filter(|(_, a)| a.alias.is_some()) {
            put(&mut self.clients, mac, &a.alias);
        }
    }
}

/// Display names (aliases first) of the APs and clients named in a response,
/// for the ones that have one.
async fn names<'a>(s: &AppState, macs: impl Iterator<Item = (&'a str, &'a str)>) -> Result<(HashMap<String, String>, HashMap<String, String>), ApiError> {
    let (aps, clients): (BTreeSet<&str>, BTreeSet<&str>) = macs.unzip();
    let wanted: BTreeSet<String> = clients.iter().map(|m| m.to_string()).collect();
    let mut names = read(&s.store, Db::Config, move |c| Ok(Names::load_for(c, &wanted.iter().map(String::as_str).collect())?)).await?;
    names.add_live(&s.live.read().unwrap());
    let named = |m: HashMap<String, Option<String>>, keep: &BTreeSet<&str>| m.into_iter().filter(|(mac, _)| keep.contains(mac.as_str())).filter_map(|(mac, n)| n.map(|n| (mac, n))).collect();
    Ok((named(names.aps, &aps), named(names.clients, &clients)))
}

/// (AP, client) of every attempt and both ends of every roam.
fn macs_of<'a>(attempts: &'a [Attempt], roams: &'a [Roam]) -> impl Iterator<Item = (&'a str, &'a str)> {
    let a = attempts.iter().map(|a| (a.ap.as_str(), a.client.as_str()));
    a.chain(roams.iter().flat_map(|r| [(r.from.ap.as_str(), r.client.as_str()), (r.to.ap.as_str(), r.client.as_str())]))
}

/// GET /api/site/connectivity: connection success per client and stage, for
/// all bands and each band.
pub async fn connectivity(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, _) = window(&q);
    let list = attempts(load(&s, from, to, None).await?);
    let mut bands = serde_json::Map::new();
    for b in [None, Some("ng"), Some("na"), Some("6e")] {
        let v = connectivity_stats(&list, b);
        if b.is_none() || v["attempts"].as_u64().unwrap_or(0) > 0 {
            bands.insert(b.unwrap_or("all").into(), v);
        }
    }
    Ok(Json(json!({ "bands": bands })))
}

#[derive(Deserialize)]
pub struct ListQuery {
    range: Option<Ts>,
    from: Option<Ts>,
    to: Option<Ts>,
    /// One client only.
    client: Option<String>,
    /// Only failed attempts.
    #[serde(default)]
    failed: bool,
    limit: Option<usize>,
}

/// GET /api/connections: connection attempts and roams, newest first.
pub async fn list(State(s): State<AppState>, Query(q): Query<ListQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, _) = window(&RangeQuery { range: q.range, from: q.from, to: q.to, ..Default::default() });
    let client = q.client.map(|c| c.to_ascii_lowercase());
    let limit = q.limit.unwrap_or(500).min(5000);
    let (list, r) = read(&s.store, Db::Config, move |c| Ok(newest(c, from, to, client.as_deref(), limit, q.failed)?)).await?;
    let (aps, clients) = names(&s, macs_of(&list, &r)).await?;
    Ok(Json(json!({ "attempts": list, "roams": r, "ap_names": aps, "client_names": clients })))
}

/// Roams, successful ones and fast (802.11r) ones.
fn roam_totals(roams: &[Roam]) -> Value {
    json!({ "roams": roams.len(), "successes": roams.iter().filter(|r| r.success).count(), "fast": roams.iter().filter(|r| r.fast).count() })
}

#[derive(Deserialize)]
pub struct RoamingQuery {
    range: Option<Ts>,
    from: Option<Ts>,
    to: Option<Ts>,
    /// How many of the newest roams to list (default 100); the totals count them all.
    limit: Option<usize>,
}

/// GET /api/roaming: the newest roams in the window (default two days), with
/// totals, per-AP-pair and per-client figures over all of them.
pub async fn roaming(State(s): State<AppState>, Query(q): Query<RoamingQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, _) = window(&RangeQuery { range: q.range.or(Some(2 * 86400)), from: q.from, to: q.to, ..Default::default() });
    let events = load(&s, from, to, None).await?;
    let r = roams(&events);
    let (total, pairs, clients) = (roam_totals(&r), roam_pairs(&r), roam_clients(&r));
    let (aps, names) = names(&s, macs_of(&[], &r)).await?;
    let mut list = r;
    list.reverse();
    list.truncate(q.limit.unwrap_or(100).min(1000));
    Ok(Json(json!({ "from": from, "to": to, "total": total, "roams": list, "pairs": pairs, "clients": clients, "ap_names": aps, "client_names": names })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(ts: Ts, client: &str, ap: &str, event_type: &str, n: Value) -> ConnEvent {
        ConnEvent {
            ts,
            ap: ap.into(),
            client: client.into(),
            vap: Some("wifi1ap0".into()),
            essid: Some("Home".into()),
            radio: Some("na".into()),
            event_type: event_type.into(),
            n: serde_json::from_value(n).unwrap(),
        }
    }

    #[test]
    fn connectivity_counts_clients_at_their_furthest_stage() {
        let ok = json!({ "traffic_delta": 120000, "dns_responses": 1, "dns_resp_seen": "yes" });
        let events = vec![
            // a: failed DHCP, then connected: counts as a success.
            conn(10, "a", "ap", "failure", json!({ "ip_failures": 1, "auth_rssi": -60 })),
            conn(20, "a", "ap", "success", ok.clone()),
            // b: failed at DNS only.
            conn(10, "b", "ap", "failure", json!({ "dns_timeouts": 2, "auth_rssi": -60 })),
            // c: a roam reported as a soft failure is a success.
            conn(10, "c", "ap", "soft failure", json!({ "ip_assign_type": "roamed" })),
            // d: failed authentication on a weak signal: not the network's fault, ignored.
            conn(10, "d", "ap", "failure", json!({ "auth_failures": 1, "auth_rssi": -82 })),
            // e: association events are not attempts.
            conn(10, "e", "ap", "association", json!({})),
        ];
        let list = attempts(events);
        assert_eq!(list.len(), 4);
        assert_eq!(list.iter().find(|a| a.client == "b").unwrap().failure, Some("DNS timeout"));
        assert!(list.iter().find(|a| a.client == "c").unwrap().roam);
        let v = connectivity_stats(&list, None);
        assert_eq!(v["clients"], 3);
        assert_eq!(v["failed_clients"], 1);
        assert_eq!((v["association_pct"].as_f64(), v["dhcp_pct"].as_f64(), v["dns_pct"].as_f64()), (Some(100.0), Some(100.0), Some(67.0)));
        assert_eq!(v["success_pct"].as_f64(), Some(67.0));
        assert_eq!(v["failed_at"]["dns"], 1);
        assert_eq!(connectivity_stats(&list, Some("ng"))["clients"], 0);
    }

    #[test]
    fn a_fixup_turns_a_failure_into_a_success() {
        let fail = conn(100, "a", "ap", "failure", json!({ "event_id": 7, "dns_timeouts": 1, "auth_rssi": -50 }));
        let fixup = conn(1000, "a", "ap", "fixup", json!({ "event_id": 7, "dns_timeouts": 0, "dns_responses": 3, "traffic_delta": 90000 }));
        let list = attempts(vec![fail.clone(), fixup.clone()]);
        assert_eq!(list.len(), 1);
        assert!(list[0].success && list[0].fixed_up);
        // Over twenty minutes later: no longer merged.
        let mut late = fixup.clone();
        late.ts = 100 + 1300;
        assert_eq!(attempts(vec![fail.clone(), late]).len(), 2);
        // Another network on the same AP: a different attempt.
        let mut other = fixup;
        other.vap = Some("wifi0ap0".into());
        assert_eq!(attempts(vec![fail, other]).len(), 2);
    }

    #[test]
    fn timings_split_the_cumulative_deltas() {
        let t = timings(&serde_json::from_value(json!({ "assoc_delta": 10000, "wpa_auth_delta": 40000, "ip_delta": 120000, "traffic_delta": 150000 })).unwrap());
        assert_eq!(t, Timings { association: Some(10.0), authentication: Some(30.0), dhcp: Some(80.0), dns: Some(30.0), total: Some(150.0) });
        // Over a minute is dropped; DHCP without a later IP time is unknown.
        let t = timings(&serde_json::from_value(json!({ "assoc_delta": 10000, "auth_delta": 20000, "ip_delta": 70_000_000 })).unwrap());
        assert_eq!((t.authentication, t.dhcp), (Some(10.0), None));
    }

    #[test]
    fn roam_totals_count_successes_and_fast_roams() {
        let end = |ap: &str| RoamEnd { ap: ap.into(), essid: None, radio: None, channel: None, bw: None, rssi: None };
        let roam = |success, fast| Roam { ts: 1, client: "c".into(), from: end("a"), to: end("b"), success, gap_s: None, fast, min_rssi: false, assistant: false };
        let t = roam_totals(&[roam(true, true), roam(true, false), roam(false, false)]);
        assert_eq!(t, json!({ "roams": 3, "successes": 2, "fast": 1 }));
    }

    #[test]
    fn roams_pair_a_leave_with_a_join_elsewhere() {
        let events = vec![
            conn(100, "c", "A", "sta_roam", json!({ "avg_rssi": -78, "assoc_status": 16 })),
            conn(101, "c", "B", "association", json!({ "auth_rssi": -55, "auth_algo": "ft" })),
            // A leave with the client back only 8 s later: a failed roam.
            conn(200, "c", "B", "sta_leave", json!({ "avg_rssi": -80 })),
            conn(208, "c", "A", "success", json!({ "auth_rssi": -60 })),
            // Same AP again: not a roam.
            conn(300, "c", "A", "sta_leave", json!({ "avg_rssi": -70 })),
            conn(301, "c", "A", "association", json!({ "auth_rssi": -65 })),
        ];
        let r = roams(&events);
        assert_eq!(r.len(), 2);
        assert!(r[0].success && r[0].fast && r[0].min_rssi && !r[0].assistant);
        assert_eq!((r[0].from.rssi, r[0].to.rssi), (Some(-78.0), Some(-55.0)));
        assert!(!r[1].success);
        assert_eq!(r[1].gap_s, Some(8));
        let p = roam_pairs(&r);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0]["attempts"].as_u64(), p[0]["success_pct"].as_f64()), (Some(2), Some(50.0)));
        assert_eq!((p[0]["forward"]["attempts"].as_u64(), p[0]["backward"]["attempts"].as_u64()), (Some(1), Some(1)));
        // A -> B at -78 -> -55 (better), then B -> A 107 s later at -80 -> -60 (back to where it was).
        let c = roam_clients(&r);
        assert_eq!((c[0]["roams"].as_u64(), c[0]["to_weaker"].as_u64(), c[0]["quick_returns"].as_u64()), (Some(2), Some(0), Some(1)));
    }

    #[test]
    fn report_fields_are_read_as_sent() {
        let n: ConnDetail = serde_json::from_value(json!({ "dns_timeouts": "2", "auth_rssi": -60.5, "x_channel": 36, "x_bw": "80", "traffic_delta": null, "other": [1] })).unwrap();
        assert_eq!((num(&n.dns_timeouts), num(&n.auth_rssi), int(&n.x_channel), int(&n.x_bw)), (Some(2.0), Some(-60.5), Some(36), None));
        // Present but null is not absent: a report with no traffic time is not "older firmware".
        assert_eq!((n.traffic_delta.clone(), n.dns_resp_seen.clone()), (Some(Field::Null), None));
        let mut f: ConnDetail = serde_json::from_value(json!({ "event_id": 7, "dns_timeouts": 1 })).unwrap();
        f.merge(&serde_json::from_value(json!({ "event_id": 7, "dns_timeouts": 0, "dns_responses": 3 })).unwrap());
        assert_eq!((num(&f.dns_timeouts), num(&f.dns_responses), f.event_id), (Some(0.0), Some(3.0), Some(Field::Int(7))));
    }

    #[test]
    fn the_newest_attempts_and_roams_are_read_from_the_end() {
        let dir = std::env::temp_dir().join(format!("apctl-connections-{}-{}", std::process::id(), crate::store::now_ts()));
        let (store, _writer) = crate::store::Store::open(&dir).unwrap();
        let c = rusqlite::Connection::open(dir.join("config.db")).unwrap();
        // Five clients, one report every 7 s for a day: failures with their fixups up
        // to 20 minutes later, successes, roams between two APs, and a few old rows
        // without the full report.
        let mut seed = 1u64;
        let mut rnd = |n: u64| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) % n
        };
        let sql = "INSERT INTO connections (ts, ap_mac, client_mac, vap, essid, radio, event_type, ip_assign_type, rssi, detail) VALUES (?1, ?2, ?3, 'wifi1ap0', 'Home', 'na', ?4, ?5, ?6, ?7)";
        c.execute_batch("BEGIN").unwrap();
        for i in 0..12_000i64 {
            let ts = 1_000_000 + i * 7;
            let client = format!("02:00:00:00:10:0{}", rnd(5));
            let ap = if rnd(2) == 0 { "02:00:00:00:00:a1" } else { "02:00:00:00:00:a2" };
            let id = i / 3;
            let (kind, detail) = match rnd(6) {
                0 => ("failure", json!({ "event_id": id, "dns_timeouts": 1, "auth_rssi": -60 })),
                1 => ("fixup", json!({ "event_id": id - rnd(200) as i64, "dns_responses": 2, "traffic_delta": 9000 })),
                2 => ("success", json!({ "traffic_delta": 120000, "dns_responses": 1, "auth_rssi": -55 })),
                3 => ("sta_leave", json!({ "avg_rssi": -78 })),
                4 => ("association", json!({ "auth_rssi": -50 })),
                _ => ("soft failure", json!({ "ip_assign_type": "roamed" })),
            };
            let detail = if i < 300 { None } else { Some(detail.to_string()) };
            c.execute(sql, rusqlite::params![ts, ap, client, kind, "roamed", -70, detail]).unwrap();
        }
        c.execute_batch("COMMIT").unwrap();
        let (from, to) = (1_000_000 + 3600, 1_000_000 + 12_000 * 7);
        // From the first batch of rows, from several, and from all of them.
        for (client, failed, limit) in [(None, false, 40), (Some("02:00:00:00:10:01"), true, 10), (None, false, 500), (None, true, 300), (Some("02:00:00:00:10:03"), false, 200), (None, false, 0), (None, false, 9000)] {
            let (list, r) = store.read(Db::Config, |c| Ok(newest(c, from, to, client, limit, failed)?)).unwrap();
            let all = store.read(Db::Config, |c| Ok(load_rows(c, from, to, client, None)?)).unwrap();
            let mut want_r = roams(&all);
            want_r.reverse();
            want_r.truncate(limit);
            let mut want = attempts(all);
            want.retain(|a| !failed || !a.success);
            want.reverse();
            want.truncate(limit);
            assert_eq!(json!(list), json!(want), "{client:?} {failed} {limit}");
            assert_eq!(json!(r), json!(want_r), "{client:?} {failed} {limit}");
            assert_eq!(list.len(), limit.min(want.len()));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
