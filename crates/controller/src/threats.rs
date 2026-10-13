//! Rogue and impersonating networks, from the neighbouring networks the APs
//! hear in their background scans.
//!
//! What is flagged, most serious first:
//! - `spoofed_bssid`: one of our own BSSIDs heard on a channel, or with a
//!   network name, that our AP is not using: someone is cloning the AP itself.
//! - `impersonation`: one of our network names broadcast from a BSSID that is
//!   not ours (an "evil twin"), worst when it has weaker or no security.
//! - `lookalike`: a name made to pass for ours ("H0me WiFi",
//!   "Home WiFi_5G").
//! - `bridged`: a network whose BSSID is next to a MAC address one of our Wi-Fi
//!   clients uses: probably a phone hotspot or an extender that client runs.
//! - `new_nearby`: a strong network that appeared in the last day, once we have
//!   watched long enough to know it is new.
//!
//! Findings can be acknowledged ("my neighbour's network"), per kind and BSSID,
//! so a later, different finding for the same BSSID is still reported.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};
use crate::engine::{Input, SharedLive};
use crate::model::Ts;
use crate::store::{self, Db, Store};
use inform::Mac;

pub const KINDS: [&str; 5] = ["spoofed_bssid", "impersonation", "lookalike", "bridged", "new_nearby"];

/// A BSSID one of our APs broadcasts (or did recently).
#[derive(Debug, Clone)]
pub struct OwnBss {
    pub bssid: String,
    pub ap_mac: String,
    pub essid: Option<String>,
    /// Current primary channel, when the AP is reporting.
    pub channel: Option<i64>,
    /// Last time this radio was on another channel, or this BSSID had another
    /// name: scan results older than this may predate the change.
    pub changed_at: Ts,
}

/// One AP's latest sighting of a network.
#[derive(Debug, Clone)]
pub struct Heard {
    pub bssid: String,
    /// The AP that heard it.
    pub ap_mac: String,
    pub radio: Option<String>,
    pub essid: Option<String>,
    pub channel: Option<i64>,
    pub security: Option<String>,
    pub signal: Option<i64>,
    pub best_signal: Option<i64>,
    pub first_seen: Ts,
    pub last_seen: Ts,
}

#[derive(Debug, Default)]
pub struct Assessment {
    pub now: Ts,
    pub own: Vec<OwnBss>,
    /// Our APs: MAC and name.
    pub aps: BTreeMap<String, Option<String>>,
    /// Our network names (from the APs and the imported settings).
    pub ssids: HashSet<String>,
    /// Wi-Fi clients ever seen: MAC and display name.
    pub clients: Vec<(String, Option<String>)>,
    pub heard: Vec<Heard>,
    /// When the first neighbouring network was recorded.
    pub watching_since: Ts,
    /// (kind, bssid) -> acknowledgement note and time.
    pub acks: HashMap<(String, String), (Option<String>, Ts)>,
    /// (kind, bssid) -> when first reported.
    pub reported: HashMap<(String, String), Ts>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeardBy {
    pub mac: String,
    pub name: Option<String>,
    pub signal: Option<i64>,
    pub last_seen: Ts,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: &'static str,
    pub severity: &'static str,
    pub bssid: String,
    pub essid: Option<String>,
    pub security: Option<String>,
    pub channel: Option<i64>,
    pub radio: Option<String>,
    /// Strongest signal any of our APs heard it at.
    pub best_signal: Option<i64>,
    pub heard_by: Vec<HeardBy>,
    pub first_seen: Ts,
    pub last_seen: Ts,
    /// What it imitates or relates to: our network name, AP or client.
    pub target: Option<String>,
    pub detail: String,
    pub first_reported: Option<Ts>,
    pub acknowledged: Option<Ack>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ack {
    pub note: Option<String>,
    pub ts: Ts,
}

/// A MAC as a number with the locally-administered bit cleared, so the
/// variants an AP or phone derives from one address sit next to each other.
fn mac_num(s: &str) -> Option<u64> {
    let m: Mac = s.parse().ok()?;
    let mut b = m.0;
    b[0] &= !0x02;
    Some(b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

fn near(a: u64, b: u64, within: u64) -> bool {
    a.abs_diff(b) <= within
}

/// Folds case, spacing and look-alike characters (digits, symbols and
/// Cyrillic letters that pass for Latin ones).
fn fold(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().flat_map(char::to_lowercase) {
        let m = match c {
            ' ' | '-' | '_' | '.' | '\'' | '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}' | '\u{00a0}' => continue,
            '0' | 'о' | 'ο' => 'o',
            '1' | 'i' | '!' | '|' | 'і' | 'ӏ' | 'ι' => 'l',
            '3' | 'е' | 'ε' => 'e',
            '4' | '@' | 'а' | 'α' => 'a',
            '5' | '$' | 'ѕ' => 's',
            '7' => 't',
            '8' => 'b',
            'р' | 'ρ' => 'p',
            'с' => 'c',
            'х' | 'χ' => 'x',
            'у' => 'y',
            'ԁ' => 'd',
            'ν' => 'v',
            c => c,
        };
        out.push(m);
    }
    out.replace("rn", "m").replace("vv", "w")
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + usize::from(ca != cb)).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Why `name` might be passed off as `ours`, if it might.
fn lookalike(name: &str, ours: &str) -> Option<&'static str> {
    if name == ours {
        return None;
    }
    if name.trim().to_lowercase() == ours.trim().to_lowercase() {
        return Some("the same name with different capitals or spacing");
    }
    let (a, b) = (fold(name), fold(ours));
    let len = b.chars().count();
    if len < 4 {
        return None;
    }
    if a == b {
        return Some("looks the same, with look-alike characters swapped in (such as 0 for O)");
    }
    if levenshtein(&a, &b) <= if len >= 8 { 2 } else { 1 } {
        return Some("differs from your network's name by a character or two");
    }
    if a.starts_with(&b) && a.chars().count() - len <= 6 {
        return Some("your network's name with something added");
    }
    None
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

/// Everything suspicious in what the APs hear.
pub fn assess(a: &Assessment) -> Vec<Finding> {
    let own: HashMap<&str, &OwnBss> = a.own.iter().map(|b| (b.bssid.as_str(), b)).collect();
    // Addresses our APs and their radios use: anything this close is our hardware.
    let family: Vec<u64> = a.own.iter().map(|b| b.bssid.as_str()).chain(a.aps.keys().map(String::as_str)).filter_map(mac_num).collect();
    let is_family = |bssid: &str| mac_num(bssid).is_some_and(|n| family.iter().any(|f| near(n, *f, 16)));
    let clients: Vec<(u64, &str, Option<&String>)> = a.clients.iter().filter_map(|(m, n)| mac_num(m).map(|x| (x, m.as_str(), n.as_ref()))).collect();
    // The security our own networks show in scans, to compare copies against.
    let mut expected: HashMap<&str, &str> = HashMap::new();
    for h in &a.heard {
        if let (Some(e), Some(s)) = (&h.essid, &h.security)
            && own.contains_key(h.bssid.as_str())
        {
            expected.insert(e.as_str(), s.as_str());
        }
    }
    let watched_for = a.now - a.watching_since;
    let ap_name = |mac: &str| a.aps.get(mac).cloned().flatten();

    let mut by_bssid: BTreeMap<&str, Vec<&Heard>> = BTreeMap::new();
    for h in &a.heard {
        by_bssid.entry(&h.bssid).or_default().push(h);
    }

    let mut out = Vec::new();
    for (bssid, rows) in by_bssid {
        let latest = rows.iter().max_by_key(|h| h.last_seen).unwrap();
        let best = rows.iter().filter_map(|h| h.best_signal.or(h.signal)).max();
        let mut push = |kind: &'static str, severity: &'static str, target: Option<String>, detail: String, rows: &[&Heard]| {
            let key = (kind.to_string(), bssid.to_string());
            let mut heard_by: Vec<HeardBy> =
                rows.iter().map(|h| HeardBy { mac: h.ap_mac.clone(), name: ap_name(&h.ap_mac), signal: h.signal, last_seen: h.last_seen }).collect();
            heard_by.sort_by_key(|h| std::cmp::Reverse(h.signal.unwrap_or(-200)));
            let latest = rows.iter().max_by_key(|h| h.last_seen).unwrap();
            out.push(Finding {
                kind,
                severity,
                bssid: bssid.to_string(),
                essid: latest.essid.clone(),
                security: latest.security.clone(),
                channel: latest.channel,
                radio: latest.radio.clone(),
                best_signal: rows.iter().filter_map(|h| h.best_signal.or(h.signal)).max(),
                heard_by,
                first_seen: rows.iter().map(|h| h.first_seen).min().unwrap_or(latest.first_seen),
                last_seen: latest.last_seen,
                target,
                detail,
                first_reported: a.reported.get(&key).copied(),
                acknowledged: a.acks.get(&key).map(|(note, ts)| Ack { note: note.clone(), ts: *ts }),
            });
        };

        if let Some(o) = own.get(bssid) {
            // Our own BSSID: only suspicious when it shows up looking unlike our AP,
            // in a scan taken after our AP last changed channel or name.
            let fresh: Vec<&Heard> = rows.iter().copied().filter(|h| h.ap_mac != o.ap_mac && h.last_seen > o.changed_at + 60).collect();
            let odd_channel: Vec<&Heard> = fresh.iter().copied().filter(|h| matches!((h.channel, o.channel), (Some(x), Some(y)) if x != y)).collect();
            let odd_name: Vec<&Heard> = fresh
                .iter()
                .copied()
                .filter(|h| matches!((&h.essid, &o.essid), (Some(x), Some(y)) if !x.is_empty() && x != y))
                .collect();
            let owner = ap_name(&o.ap_mac).unwrap_or_else(|| o.ap_mac.clone());
            if let Some(h) = odd_channel.first() {
                push(
                    "spoofed_bssid",
                    "high",
                    Some(owner.clone()),
                    format!(
                        "Uses the address of {owner}'s \"{}\" network, but was heard on channel {} while {owner} is on {}. Something may be cloning your AP.",
                        o.essid.as_deref().unwrap_or("?"),
                        h.channel.unwrap_or_default(),
                        o.channel.unwrap_or_default()
                    ),
                    &odd_channel,
                );
            } else if let Some(h) = odd_name.first() {
                push(
                    "spoofed_bssid",
                    "high",
                    Some(owner.clone()),
                    format!(
                        "Uses the address of {owner}'s \"{}\" network, but calls itself \"{}\". Something may be cloning your AP.",
                        o.essid.as_deref().unwrap_or("?"),
                        h.essid.as_deref().unwrap_or("")
                    ),
                    &odd_name,
                );
            }
            continue;
        }

        let family = is_family(bssid);
        let essid = latest.essid.as_deref().filter(|e| !e.is_empty());
        if let Some(e) = essid {
            if a.ssids.contains(e) {
                let theirs = latest.security.as_deref();
                let ours = expected.get(e).copied();
                let open = theirs.is_some_and(|s| s.to_ascii_lowercase().contains("open") || s.eq_ignore_ascii_case("none"));
                let detail = if family {
                    format!("Broadcasts your network \"{e}\" from an address next to one of your APs'. It is probably your AP with an SSID apctl has not seen yet; if not, it is imitating it.")
                } else if open {
                    format!("Broadcasts your network name \"{e}\" with no password. Devices that join it can have their traffic intercepted: a classic evil twin.")
                } else if let (Some(t), Some(o)) = (theirs, ours)
                    && t != o
                {
                    format!("Broadcasts your network name \"{e}\" from a device that is not yours, with different security ({t}, yours is {o}).")
                } else {
                    format!("Broadcasts your network name \"{e}\" from a device that is not one of your APs.")
                };
                push("impersonation", if family { "medium" } else { "high" }, Some(e.to_string()), detail, &rows);
                continue;
            }
            if !family
                && let Some((ours, why)) = a.ssids.iter().find_map(|o| lookalike(e, o).map(|w| (o, w)))
            {
                push("lookalike", "medium", Some(ours.clone()), format!("\"{e}\" {why} (\"{ours}\")."), &rows);
                continue;
            }
        }
        if family {
            continue;
        }
        if let Some(n) = mac_num(bssid)
            && let Some((_, mac, name)) = clients.iter().find(|(c, _, _)| near(n, *c, 8))
        {
            let who = name.cloned().unwrap_or_else(|| mac.to_string());
            push(
                "bridged",
                "medium",
                Some(mac.to_string()),
                format!(
                    "Its address is next to that of your client {who}, so {who} probably broadcasts it: a phone hotspot, a Wi-Fi extender or the device's own setup network. Extenders and hotspots can bridge other devices onto your network."
                ),
                &rows,
            );
            continue;
        }
        let first = rows.iter().map(|h| h.first_seen).min().unwrap_or(latest.first_seen);
        if watched_for > 2 * 86400 && first > a.now - 86400 && best.is_some_and(|s| s >= -60) {
            push(
                "new_nearby",
                "low",
                None,
                format!("A strong network ({} dBm) that first appeared in the last day.", best.unwrap_or_default()),
                &rows,
            );
        }
    }
    out.sort_by(|x, y| severity_rank(x.severity).cmp(&severity_rank(y.severity)).then(y.best_signal.cmp(&x.best_signal)));
    out
}

/// Loads what `assess` needs from the database and live state.
pub fn gather(store: &Store, live: &SharedLive, now: Ts) -> anyhow::Result<Assessment> {
    let mut a = Assessment { now, ..Default::default() };
    let mut own: BTreeMap<String, OwnBss> = BTreeMap::new();
    {
        let live = live.read().unwrap();
        for (mac, d) in &live.devices {
            a.aps.insert(mac.to_string(), d.snapshot.ap.hostname.clone());
            for v in &d.snapshot.vaps {
                own.insert(
                    v.bssid.clone(),
                    OwnBss { bssid: v.bssid.clone(), ap_mac: mac.to_string(), essid: v.essid.clone(), channel: v.channel, changed_at: 0 },
                );
            }
        }
        for mac in live.known_devices.keys() {
            a.aps.entry(mac.to_string()).or_insert(None);
        }
        for c in live.clients.values() {
            let alias = live.aliases.get(&c.sample.mac).and_then(|x| x.alias.clone());
            a.clients.push((c.sample.mac.to_string(), alias.or(c.sample.hostname.clone())));
        }
        if let Some(state) = &live.state {
            for w in state.get("wlanconf").and_then(Value::as_array).into_iter().flatten() {
                if w.get("enabled").and_then(Value::as_bool) != Some(false)
                    && let Some(n) = w.get("name").and_then(Value::as_str)
                {
                    a.ssids.insert(n.to_string());
                }
            }
        }
    }

    // BSSIDs our APs used in the last 30 days, including ones not reporting now.
    store.read(Db::Metrics, |c| {
        let since = now - 30 * 86400;
        for suffix in ["", "_5m"] {
            let mut stmt = c.prepare(&format!("SELECT bssid, ap_mac, essid, MAX(ts) FROM vap_stats{suffix} WHERE ts >= ?1 GROUP BY bssid"))?;
            let rows = stmt.query_map([since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?)))?;
            for (bssid, ap, essid) in rows.flatten() {
                let ap = ap.unwrap_or_default();
                if !ap.is_empty() {
                    a.aps.entry(ap.clone()).or_insert(None);
                }
                if let Some(e) = &essid {
                    a.ssids.insert(e.clone());
                }
                own.entry(bssid.clone()).or_insert(OwnBss { bssid, ap_mac: ap, essid, channel: None, changed_at: 0 });
            }
        }
        for b in own.values_mut() {
            if let Some(e) = &b.essid {
                a.ssids.insert(e.clone());
            }
            b.changed_at = last_change(c, b)?;
        }
        Ok(())
    })?;
    a.own = own.into_values().collect();

    store.read(Db::Config, |c| {
        let mut stmt = c.prepare(
            "SELECT bssid, ap_mac, radio, essid, channel, security, signal, best_signal, first_seen, last_seen FROM neighbors WHERE last_seen >= ?1",
        )?;
        a.heard = stmt
            .query_map([now - 7 * 86400], |r| {
                Ok(Heard {
                    bssid: r.get(0)?,
                    ap_mac: r.get(1)?,
                    radio: r.get(2)?,
                    essid: r.get(3)?,
                    channel: r.get(4)?,
                    security: r.get(5)?,
                    signal: r.get(6)?,
                    best_signal: r.get(7)?,
                    first_seen: r.get(8)?,
                    last_seen: r.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        a.watching_since = c.query_row("SELECT MIN(first_seen) FROM neighbors", [], |r| r.get::<_, Option<Ts>>(0)).optional()?.flatten().unwrap_or(now);
        let mut stmt = c.prepare("SELECT mac, hostname FROM clients")?;
        let known: HashSet<String> = a.clients.iter().map(|c| c.0.clone()).collect();
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?.flatten() {
            if !known.contains(&row.0) {
                a.clients.push(row);
            }
        }
        let mut stmt = c.prepare("SELECT mac, COALESCE(name, hostname) FROM devices")?;
        for (mac, name) in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?.flatten() {
            let e = a.aps.entry(mac).or_insert(None);
            if e.is_none() {
                *e = name;
            }
        }
        let mut stmt = c.prepare("SELECT kind, bssid, note, ts FROM network_acks")?;
        for (k, b, n, t) in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?, r.get(3)?)))?.flatten() {
            a.acks.insert((k, b), (n, t));
        }
        let mut stmt = c.prepare("SELECT kind, bssid, first_reported FROM network_threats")?;
        for (k, b, t) in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?)))?.flatten() {
            a.reported.insert((k, b), t);
        }
        Ok(())
    })?;
    Ok(a)
}

/// When this BSSID's radio last ran another channel, or the BSSID another name.
fn last_change(c: &Connection, b: &OwnBss) -> rusqlite::Result<Ts> {
    let mut latest: Ts = 0;
    for suffix in ["", "_5m"] {
        if let Some(ch) = b.channel {
            let t: Option<Ts> = c.query_row(
                &format!(
                    "SELECT MAX(r.ts) FROM radio_stats{suffix} r JOIN (SELECT DISTINCT radio FROM vap_stats{suffix} WHERE bssid = ?1) v ON r.radio = v.radio \
                     WHERE r.mac = ?2 AND r.channel IS NOT NULL AND r.channel != ?3"
                ),
                rusqlite::params![b.bssid, b.ap_mac, ch],
                |r| r.get(0),
            )?;
            latest = latest.max(t.unwrap_or(0));
        }
        if let Some(e) = &b.essid {
            let t: Option<Ts> =
                c.query_row(&format!("SELECT MAX(ts) FROM vap_stats{suffix} WHERE bssid = ?1 AND essid IS NOT NULL AND essid != ?2"), rusqlite::params![b.bssid, e], |r| r.get(0))?;
            latest = latest.max(t.unwrap_or(0));
        }
    }
    Ok(latest)
}

async fn findings(s: &AppState) -> Result<(Vec<Finding>, Ts), ApiError> {
    let (store, live) = (s.store.clone(), s.live.clone());
    tokio::task::spawn_blocking(move || {
        let a = gather(&store, &live, store::now_ts())?;
        Ok::<_, anyhow::Error>((assess(&a), a.watching_since))
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(ApiError::from)
}

/// GET /api/rf/threats
pub async fn list(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (list, watching_since) = findings(&s).await?;
    // Vendors help tell a neighbour's router from a laptop or phone.
    let vendors: Vec<Option<String>> = list.iter().map(|f| s.vendors.lookup_str(&f.bssid)).collect();
    let items: Vec<Value> = list
        .into_iter()
        .zip(vendors)
        .map(|(f, v)| {
            let mut j = serde_json::to_value(f).unwrap_or_default();
            j["vendor"] = json!(v);
            j
        })
        .collect();
    Ok(Json(json!({ "watching_since": watching_since, "findings": items })))
}

#[derive(Deserialize)]
pub struct AckBody {
    kind: String,
    bssid: String,
    /// False to un-acknowledge.
    #[serde(default = "yes")]
    ack: bool,
    note: Option<String>,
}

fn yes() -> bool {
    true
}

/// PUT /api/rf/threats/ack
pub async fn ack(State(s): State<AppState>, headers: axum::http::HeaderMap, Json(b): Json<AckBody>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    let Some(kind) = KINDS.iter().find(|k| **k == b.kind) else {
        return Err(ApiError(StatusCode::BAD_REQUEST, "unknown kind".into()));
    };
    let bssid: Mac = b.bssid.parse().map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid BSSID".into()))?;
    let note = b.note.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if note.as_ref().is_some_and(|n| n.chars().count() > 200) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "note is too long (200 characters at most)".into()));
    }
    let input = Input::AckThreat { ts: store::now_ts(), kind, bssid: bssid.to_string(), note: if b.ack { Some(note) } else { None } };
    s.engine.send(input).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "engine stopped".into()))?;
    Ok(Json(json!({ "ok": true })))
}

/// Re-assesses every minute and reports each new, unacknowledged finding once.
pub fn watch(store: std::sync::Arc<Store>, live: SharedLive, engine: tokio::sync::mpsc::Sender<Input>) {
    tokio::spawn(async move {
        // Give the APs a few informs to report their networks first.
        tokio::time::sleep(Duration::from_secs(90)).await;
        let mut every = tokio::time::interval(Duration::from_secs(60));
        loop {
            every.tick().await;
            let (st, lv) = (store.clone(), live.clone());
            let found = tokio::task::spawn_blocking(move || gather(&st, &lv, store::now_ts()).map(|a| assess(&a))).await;
            let list = match found {
                Ok(Ok(l)) => l,
                Ok(Err(e)) => {
                    tracing::warn!("network threat check failed: {e:#}");
                    continue;
                }
                Err(_) => continue,
            };
            for f in list.into_iter().filter(|f| f.first_reported.is_none()) {
                let device = f.heard_by.first().and_then(|h| h.mac.parse().ok());
                let notify = f.acknowledged.is_none();
                let data = json!({
                    "kind": f.kind, "severity": f.severity, "bssid": f.bssid, "essid": f.essid, "target": f.target,
                    "signal": f.best_signal, "channel": f.channel, "detail": f.detail,
                });
                let input = Input::ThreatFound { ts: store::now_ts(), kind: f.kind, bssid: f.bssid, device_mac: device, data, notify };
                if engine.send(input).await.is_err() {
                    return;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const UP: &str = "78:45:58:3c:51:ac";
    const DOWN: &str = "78:45:58:3c:52:bc";

    fn heard(bssid: &str, by: &str, essid: &str, channel: i64, security: &str, signal: i64) -> Heard {
        Heard {
            bssid: bssid.into(),
            ap_mac: by.into(),
            radio: Some("na".into()),
            essid: Some(essid.into()),
            channel: Some(channel),
            security: Some(security.into()),
            signal: Some(signal),
            best_signal: Some(signal),
            first_seen: 1_000,
            last_seen: 10_000,
        }
    }

    fn site() -> Assessment {
        let mut a = Assessment { now: 400_000, watching_since: 1_000, ..Default::default() };
        a.aps.insert(UP.into(), Some("Upstairs".into()));
        a.aps.insert(DOWN.into(), Some("Garage".into()));
        for (b, ap, e, ch) in [
            ("78:45:58:3c:51:ae", UP, "Home", 44),
            ("7a:45:58:3c:51:ae", UP, "Home IoT", 1),
            ("78:45:58:3c:52:be", DOWN, "Home", 48),
            ("7a:45:58:3c:52:be", DOWN, "Home IoT", 1),
        ] {
            a.own.push(OwnBss { bssid: b.into(), ap_mac: ap.into(), essid: Some(e.into()), channel: Some(ch), changed_at: 0 });
            a.ssids.insert(e.into());
        }
        a.clients.push(("3c:55:76:00:00:03".into(), Some("phone".into())));
        // Our APs hear each other normally.
        a.heard.push(heard("78:45:58:3c:52:be", UP, "Home", 48, "WPA2-Personal (AES/CCMP)", -81));
        a.heard.push(heard("78:45:58:3c:51:ae", DOWN, "Home", 44, "WPA2-Personal (AES/CCMP)", -84));
        // A neighbour.
        a.heard.push(heard("2a:00:00:00:00:07", UP, "Neighbour Net", 44, "WPA2-Personal (AES/CCMP)", -74));
        a
    }

    fn kinds(a: &Assessment) -> Vec<(&'static str, &'static str, String)> {
        assess(a).into_iter().map(|f| (f.kind, f.severity, f.bssid)).collect()
    }

    #[test]
    fn a_normal_site_has_no_findings() {
        assert!(kinds(&site()).is_empty());
    }

    #[test]
    fn copies_of_our_network_name_are_impersonation() {
        let mut a = site();
        a.heard.push(heard("02:11:22:33:44:55", DOWN, "Home", 6, "Open", -55));
        let f = assess(&a);
        assert_eq!((f[0].kind, f[0].severity), ("impersonation", "high"));
        assert!(f[0].detail.contains("no password"), "{}", f[0].detail);
        // Different security is called out.
        let mut a = site();
        a.heard.push(heard("02:11:22:33:44:55", DOWN, "Home", 6, "WPA-Personal (TKIP)", -70));
        assert!(assess(&a)[0].detail.contains("different security"));
        // Next to our AP's own addresses: probably ours, so only medium.
        let mut a = site();
        a.heard.push(heard("7a:45:58:3c:52:bf", UP, "Home", 48, "WPA2-Personal (AES/CCMP)", -80));
        assert_eq!(kinds(&a), vec![("impersonation", "medium", "7a:45:58:3c:52:bf".into())]);
    }

    #[test]
    fn our_bssid_on_another_channel_is_spoofing_unless_we_moved() {
        let mut a = site();
        a.heard.push(heard("78:45:58:3c:52:be", UP, "Home", 149, "WPA2-Personal (AES/CCMP)", -60));
        // (replaces the normal sighting: one row per BSSID and hearing AP)
        a.heard.retain(|h| !(h.bssid == "78:45:58:3c:52:be" && h.channel == Some(48)));
        assert_eq!(kinds(&a), vec![("spoofed_bssid", "high", "78:45:58:3c:52:be".into())]);
        // The scan predates our own channel change: not reported.
        a.own.iter_mut().find(|o| o.bssid == "78:45:58:3c:52:be").unwrap().changed_at = 20_000;
        assert!(kinds(&a).is_empty());
        // Our BSSID with someone else's name.
        let mut a = site();
        a.heard.retain(|h| h.bssid != "78:45:58:3c:52:be");
        a.heard.push(heard("78:45:58:3c:52:be", UP, "Free WiFi", 48, "Open", -60));
        assert!(assess(&a)[0].detail.contains("calls itself \"Free WiFi\""));
    }

    #[test]
    fn lookalike_names() {
        assert!(lookalike("H0me", "Home").is_some());
        assert!(lookalike("home", "Home").is_some());
        assert!(lookalike("Home WiFi_5G", "Home WiFi").is_some());
        assert!(lookalike("Home WіFi", "Home WiFi").is_some()); // Cyrillic i
        assert!(lookalike("Home WiFii", "Home WiFi").is_some());
        assert!(lookalike("Housing Office", "Home WiFi").is_none());
        assert!(lookalike("Neighbour Net", "Home WiFi").is_none());
        assert!(lookalike("Home", "Home").is_none());
        // Short names only match closely.
        assert!(lookalike("Hone", "Home").is_some());
        assert!(lookalike("Hide", "Home").is_none());
        let mut a = site();
        a.heard.push(heard("02:aa:bb:cc:dd:ee", UP, "H0me", 36, "Open", -70));
        assert_eq!(kinds(&a), vec![("lookalike", "medium", "02:aa:bb:cc:dd:ee".into())]);
    }

    #[test]
    fn hotspots_next_to_a_client_address_are_bridged() {
        let mut a = site();
        a.heard.push(heard("3e:55:76:00:00:04", UP, "phone hotspot", 6, "WPA2-Personal (AES/CCMP)", -50));
        let f = assess(&a);
        assert_eq!((f[0].kind, f[0].target.as_deref()), ("bridged", Some("3c:55:76:00:00:03")));
        assert!(f[0].detail.contains("phone"));
    }

    #[test]
    fn new_strong_networks_once_we_have_watched_a_while() {
        let mut a = site();
        let mut n = heard("02:00:00:00:00:01", UP, "Neighbour", 36, "WPA2-Personal (AES/CCMP)", -55);
        n.first_seen = a.now - 3600;
        n.last_seen = a.now;
        a.heard.push(n.clone());
        assert_eq!(kinds(&a), vec![("new_nearby", "low", "02:00:00:00:00:01".into())]);
        // Weak ones are not interesting.
        a.heard.last_mut().unwrap().best_signal = Some(-80);
        assert!(kinds(&a).is_empty());
        // Nothing is "new" in the first two days of watching.
        let mut a = site();
        a.watching_since = a.now - 86400;
        a.heard.push(n);
        assert!(kinds(&a).is_empty());
    }

    #[test]
    fn acknowledgements_are_per_kind_and_bssid() {
        let mut a = site();
        a.heard.push(heard("02:aa:bb:cc:dd:ee", UP, "H0me", 36, "Open", -70));
        a.acks.insert(("lookalike".into(), "02:aa:bb:cc:dd:ee".into()), (Some("the neighbours".into()), 5));
        let f = assess(&a);
        assert_eq!(f[0].acknowledged.as_ref().and_then(|x| x.note.as_deref()), Some("the neighbours"));
        // The same BSSID copying our name exactly is a different finding.
        a.heard.last_mut().unwrap().essid = Some("Home".into());
        assert!(assess(&a)[0].acknowledged.is_none());
    }
}
