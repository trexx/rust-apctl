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

use std::collections::{BTreeMap, HashMap, HashSet};

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
    pub n: Value,
}

/// Connection stages in the order a client passes them.
pub const STAGES: [&str; 6] = ["association", "authentication", "dhcp", "dns", "traffic", "success"];

fn num_of(n: &Value, k: &str) -> Option<f64> {
    n[k].as_f64().or_else(|| n[k].as_str().and_then(|v| v.parse().ok()))
}

/// Failure counters present in a report, as (stage 1-5, label).
fn failures(n: &Value) -> Vec<(usize, &'static str)> {
    let pos = |k: &str| num_of(n, k).is_some_and(|v| v > 0.0);
    let is = |k: &str, v: &str| n[k].as_str() == Some(v);
    let mut out = Vec::new();
    if pos("assoc_failures") {
        out.push((1, "Association"));
    }
    if pos("auth_failures") {
        out.push((2, "Authentication"));
    }
    if pos("wpa_auth_failures") {
        out.push((2, "WPA authentication"));
    }
    if is("radius_auth_status", "failure") {
        out.push((2, "RADIUS authentication"));
    }
    if pos("ip_failures") {
        out.push((3, "DHCP timeout"));
    }
    if pos("dns_timeouts") {
        out.push((4, "DNS timeout"));
    }
    if is("dns_resp_seen", "no") {
        out.push((4, "DNS response not seen"));
    }
    if pos("traffic_failures") {
        out.push((5, "Traffic failure"));
    }
    out
}

fn succeeded(event_type: &str, n: &Value) -> bool {
    let pos = |k: &str| num_of(n, k).is_some_and(|v| v > 0.0);
    event_type != "failure"
        && ((event_type == "soft failure" && n["ip_assign_type"].as_str().is_some_and(|v| v.starts_with("roam")))
            || (n.get("traffic_delta").is_none() && n["dns_resp_seen"].as_str() == Some("yes"))
            || (pos("traffic_delta") && pos("dns_responses")))
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

fn timings(n: &Value) -> Timings {
    // Deltas over a minute are not believable; they are dropped.
    let d = |k: &str| num_of(n, k).filter(|v| *v > 0.0 && *v <= 60_000_000.0);
    let ms = |us: f64| (us / 100.0).round() / 10.0;
    let assoc = d("assoc_delta");
    let auth = ["wpa_auth_delta", "radius_auth_delta", "auth_delta"].iter().find_map(|k| d(k).filter(|a| assoc.is_none_or(|x| *a > x)));
    let ip = d("ip_delta");
    let traffic = d("traffic_delta");
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

/// Connection attempts from the notifications, oldest first.
pub fn attempts(mut events: Vec<ConnEvent>) -> Vec<Attempt> {
    events.retain(|e| matches!(e.event_type.as_str(), "failure" | "soft failure" | "success" | "fixup"));
    events.sort_by_key(|e| e.ts);
    // (event, succeeded on its own, merged with a fixup)
    let mut merged: Vec<(ConnEvent, bool, bool)> = Vec::new();
    for e in events {
        let ok = succeeded(&e.event_type, &e.n);
        if e.event_type == "fixup"
            && let Some(id) = e.n.get("event_id").filter(|v| !v.is_null())
            // Sorted by time: only the last 20 minutes need looking at.
            && let Some(prev) = merged.iter_mut().rev().take_while(|(p, _, _)| e.ts - p.ts <= 1200).find(|(p, _, _)| {
                p.ap == e.ap && p.client == e.client && p.vap == e.vap && p.n.get("event_id") == Some(id) && p.event_type.contains("failure")
            })
        {
            if let (Some(a), Some(b)) = (prev.0.n.as_object_mut(), e.n.as_object()) {
                for (k, v) in b {
                    a.insert(k.clone(), v.clone());
                }
            }
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
            let rssi = num_of(n, "auth_rssi").or_else(|| num_of(n, "avg_rssi"));
            let fails = failures(n);
            let (stage, failure) = if ok {
                (6, None)
            } else {
                if rssi.is_some_and(|r| r < -75.0) {
                    return None;
                }
                let worst = fails.iter().max_by_key(|f| f.0)?;
                (worst.0, Some(worst.1))
            };
            Some(Attempt {
                ts: e.ts,
                roam: e.event_type == "soft failure" && n["ip_assign_type"].as_str().is_some_and(|v| v.starts_with("roam")),
                client: e.client,
                ap: e.ap,
                essid: e.essid,
                radio: e.radio,
                channel: n["x_channel"].as_i64(),
                bw: n["x_bw"].as_i64(),
                success: ok,
                stage,
                failure,
                rssi,
                timings: timings(n),
                fixed_up: fixed,
                reason: n["sta_dc_reason"].as_str().filter(|r| !r.is_empty() && !ok).map(str::to_string),
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

fn end_of(e: &ConnEvent, rssi_key: &str) -> RoamEnd {
    RoamEnd {
        ap: e.ap.clone(),
        essid: e.essid.clone(),
        radio: e.radio.clone(),
        channel: e.n["x_channel"].as_i64(),
        bw: e.n["x_bw"].as_i64(),
        rssi: num_of(&e.n, rssi_key),
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
        let joined: Vec<bool> = evs.iter().zip(&leave).map(|(e, l)| !l && num_of(&e.n, "auth_rssi").is_some()).collect();
        let mut used: HashSet<usize> = HashSet::new();
        for (li, l) in evs.iter().enumerate() {
            if !leave[li] || num_of(&l.n, "avg_rssi").is_none() {
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
            let status = num_of(&l.n, "assoc_status").unwrap_or(0.0) as i64;
            out.push(Roam {
                ts: j.ts.max(l.ts),
                client: client.to_string(),
                from: end_of(l, "avg_rssi"),
                to: end_of(j, "auth_rssi"),
                success,
                gap_s: (!success).then_some(gap.max(0)),
                fast: j.n["auth_algo"].as_str() == Some("ft"),
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

/// Loads the notifications in a window (optionally one client's).
async fn load(s: &AppState, from: Ts, to: Ts, client: Option<String>) -> Result<Vec<ConnEvent>, ApiError> {
    read(&s.store, Db::Config, move |c| {
        const COLUMNS: &str = "SELECT ts, ap_mac, client_mac, vap, essid, radio, event_type, detail, ip_assign_type, dns_responses, dns_timeouts, rssi FROM connections";
        // Two statements: `(?3 IS NULL OR client_mac = ?3)` would keep SQLite off the per-client index.
        let mut stmt = match client {
            Some(_) => c.prepare(&format!("{COLUMNS} WHERE client_mac = ?3 AND ts >= ?1 AND ts <= ?2"))?,
            None => c.prepare(&format!("{COLUMNS} WHERE ts >= ?1 AND ts <= ?2"))?,
        };
        let params: Vec<&dyn rusqlite::ToSql> = match &client {
            Some(m) => vec![&from, &to, m],
            None => vec![&from, &to],
        };
        let rows = stmt
            .query_map(params.as_slice(), |r| {
                let detail: Option<String> = r.get(7)?;
                // Rows from before the full notification was kept: rebuild what we can.
                let n = detail.and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_else(|| {
                    json!({
                        "ip_assign_type": r.get::<_, Option<String>>(8).ok().flatten(),
                        "dns_responses": r.get::<_, Option<i64>>(9).ok().flatten(),
                        "dns_timeouts": r.get::<_, Option<i64>>(10).ok().flatten(),
                        "avg_rssi": r.get::<_, Option<i64>>(11).ok().flatten(),
                    })
                });
                Ok(ConnEvent {
                    ts: r.get(0)?,
                    ap: r.get(1)?,
                    client: r.get(2)?,
                    vap: r.get(3)?,
                    essid: r.get(4)?,
                    radio: r.get(5)?,
                    event_type: r.get(6)?,
                    n,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await
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

/// Display names for APs and clients (aliases first), for the ones that have one.
async fn names(s: &AppState) -> Result<(HashMap<String, String>, HashMap<String, String>), ApiError> {
    let mut names = read(&s.store, Db::Config, |c| Ok(Names::load(c)?)).await?;
    names.add_live(&s.live.read().unwrap());
    let named = |m: HashMap<String, Option<String>>| m.into_iter().filter_map(|(mac, n)| n.map(|n| (mac, n))).collect();
    Ok((named(names.aps), named(names.clients)))
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
    let events = load(&s, from, to, client).await?;
    let limit = q.limit.unwrap_or(500).min(5000);
    let mut r = roams(&events);
    r.reverse();
    r.truncate(limit);
    let mut list = attempts(events);
    if q.failed {
        list.retain(|a| !a.success);
    }
    list.reverse();
    list.truncate(limit);
    let (aps, clients) = names(&s).await?;
    Ok(Json(json!({ "attempts": list, "roams": r, "ap_names": aps, "client_names": clients })))
}

/// GET /api/roaming: roams in the window (default two days) and per-AP-pair totals.
pub async fn roaming(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let q = RangeQuery { range: q.range.or(Some(2 * 86400)), ..q };
    let (from, to, _) = window(&q);
    let events = load(&s, from, to, None).await?;
    let r = roams(&events);
    let pairs = roam_pairs(&r);
    let clients = roam_clients(&r);
    let (aps, names) = names(&s).await?;
    let mut list = r;
    list.reverse();
    Ok(Json(json!({ "from": from, "to": to, "roams": list, "pairs": pairs, "clients": clients, "ap_names": aps, "client_names": names })))
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
            n,
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
        let t = timings(&json!({ "assoc_delta": 10000, "wpa_auth_delta": 40000, "ip_delta": 120000, "traffic_delta": 150000 }));
        assert_eq!(t, Timings { association: Some(10.0), authentication: Some(30.0), dhcp: Some(80.0), dns: Some(30.0), total: Some(150.0) });
        // Over a minute is dropped; DHCP without a later IP time is unknown.
        let t = timings(&json!({ "assoc_delta": 10000, "auth_delta": 20000, "ip_delta": 70_000_000 }));
        assert_eq!((t.authentication, t.dhcp), (Some(10.0), None));
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
}
