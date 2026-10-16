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

use crate::alerts::named_enum;
use crate::api::{ApiError, AppState};
use crate::engine::{Input, SharedLive};
use crate::model::Ts;
use crate::store::{self, Db, Store, Writer};
use inform::Mac;

named_enum! {
    /// What a finding is (see above), as stored and as the API and events name it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Kind {
        SpoofedBssid = "spoofed_bssid", Impersonation = "impersonation", Lookalike = "lookalike", Bridged = "bridged", NewNearby = "new_nearby",
    }
}

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
    pub acks: HashMap<(Kind, String), (Option<String>, Ts)>,
    /// (kind, bssid) -> when first reported.
    pub reported: HashMap<(Kind, String), Ts>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeardBy {
    pub mac: String,
    pub name: Option<String>,
    pub signal: Option<i64>,
    pub last_seen: Ts,
}

/// How serious a finding is; sorts most serious first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: Kind,
    pub severity: Severity,
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

/// Whether `a` becomes `b` in at most `max` single-character edits.
fn within_edits(a: &[char], b: &[char], max: usize) -> bool {
    // Each edit changes the length by one at most.
    if a.len().abs_diff(b.len()) > max {
        return false;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(ca != cb)).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()] <= max
}

/// A network name with the forms [`similar`] compares, worked out once.
struct Name<'a> {
    raw: &'a str,
    lower: String,
    folded: Vec<char>,
}

impl<'a> Name<'a> {
    fn new(raw: &'a str) -> Name<'a> {
        Name { raw, lower: raw.trim().to_lowercase(), folded: fold(raw).chars().collect() }
    }
}

/// Why `name` might be passed off as `ours`, if it might.
#[cfg(test)]
fn lookalike(name: &str, ours: &str) -> Option<&'static str> {
    similar(&Name::new(name), &Name::new(ours))
}

/// [`lookalike`] on names already folded.
fn similar(name: &Name, ours: &Name) -> Option<&'static str> {
    if name.raw == ours.raw {
        return None;
    }
    if name.lower == ours.lower {
        return Some("the same name with different capitals or spacing");
    }
    let (a, b) = (&name.folded, &ours.folded);
    let len = b.len();
    if len < 4 {
        return None;
    }
    if a == b {
        return Some("looks the same, with look-alike characters swapped in (such as 0 for O)");
    }
    if within_edits(a, b, if len >= 8 { 2 } else { 1 }) {
        return Some("differs from your network's name by a character or two");
    }
    if a.starts_with(b) && a.len() - len <= 6 {
        return Some("your network's name with something added");
    }
    None
}

/// What a finding reports about the sightings it rests on.
struct Seen<'a> {
    latest: &'a Heard,
    best: Option<i64>,
    first: Ts,
}

fn seen<'a>(rows: &[&'a Heard]) -> Seen<'a> {
    let latest = *rows.iter().max_by_key(|h| h.last_seen).expect("a BSSID has sightings");
    Seen {
        latest,
        best: rows.iter().filter_map(|h| h.best_signal.or(h.signal)).max(),
        first: rows.iter().map(|h| h.first_seen).min().unwrap_or(latest.first_seen),
    }
}

/// Everything suspicious in what the APs hear.
pub fn assess(a: &Assessment) -> Vec<Finding> {
    let own: HashMap<&str, &OwnBss> = a.own.iter().map(|b| (b.bssid.as_str(), b)).collect();
    // Addresses our APs and their radios use: anything this close is our hardware.
    let family: Vec<u64> = a.own.iter().map(|b| b.bssid.as_str()).chain(a.aps.keys().map(String::as_str)).filter_map(mac_num).collect();
    let is_family = |bssid: &str| mac_num(bssid).is_some_and(|n| family.iter().any(|f| near(n, *f, 16)));
    // Clients by address, each with its place in the list (the first one near a BSSID is the one named).
    let mut clients: Vec<(u64, usize, &str, Option<&String>)> =
        a.clients.iter().enumerate().filter_map(|(i, (m, n))| mac_num(m).map(|x| (x, i, m.as_str(), n.as_ref()))).collect();
    clients.sort_unstable();
    let client_near = |n: u64| {
        let from = clients.partition_point(|c| c.0 < n.saturating_sub(8));
        clients[from..].iter().take_while(|c| c.0 <= n + 8).min_by_key(|c| c.1).map(|c| (c.2, c.3))
    };
    // Our network names, folded once (in name order, so the same one is named every time).
    let mut ours: Vec<&String> = a.ssids.iter().collect();
    ours.sort();
    let ours: Vec<Name> = ours.into_iter().map(|o| Name::new(o)).collect();
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

    // Which of our names each network name passes for, and why: worked out
    // once per name, however many BSSIDs broadcast it.
    let mut lookalikes: HashMap<&str, Option<(&str, &'static str)>> = HashMap::new();
    let mut out = Vec::new();
    for (bssid, rows) in by_bssid {
        let all = seen(&rows);
        let (latest, best) = (all.latest, all.best);
        // `rows` are the sightings the finding rests on, `s` what they add up to.
        let mut push = |kind: Kind, severity: Severity, target: Option<String>, detail: String, rows: &[&Heard], s: &Seen| {
            let key = (kind, bssid.to_string());
            let mut heard_by: Vec<HeardBy> =
                rows.iter().map(|h| HeardBy { mac: h.ap_mac.clone(), name: ap_name(&h.ap_mac), signal: h.signal, last_seen: h.last_seen }).collect();
            heard_by.sort_by_key(|h| std::cmp::Reverse(h.signal.unwrap_or(-200)));
            out.push(Finding {
                kind,
                severity,
                bssid: bssid.to_string(),
                essid: s.latest.essid.clone(),
                security: s.latest.security.clone(),
                channel: s.latest.channel,
                radio: s.latest.radio.clone(),
                best_signal: s.best,
                heard_by,
                first_seen: s.first,
                last_seen: s.latest.last_seen,
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
                    Kind::SpoofedBssid,
                    Severity::High,
                    Some(owner.clone()),
                    format!(
                        "Uses the address of {owner}'s \"{}\" network, but was heard on channel {} while {owner} is on {}. Something may be cloning your AP.",
                        o.essid.as_deref().unwrap_or("?"),
                        h.channel.unwrap_or_default(),
                        o.channel.unwrap_or_default()
                    ),
                    &odd_channel,
                    &seen(&odd_channel),
                );
            } else if let Some(h) = odd_name.first() {
                push(
                    Kind::SpoofedBssid,
                    Severity::High,
                    Some(owner.clone()),
                    format!(
                        "Uses the address of {owner}'s \"{}\" network, but calls itself \"{}\". Something may be cloning your AP.",
                        o.essid.as_deref().unwrap_or("?"),
                        h.essid.as_deref().unwrap_or("")
                    ),
                    &odd_name,
                    &seen(&odd_name),
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
                push(Kind::Impersonation, if family { Severity::Medium } else { Severity::High }, Some(e.to_string()), detail, &rows, &all);
                continue;
            }
            if !family
                && let Some((ours, why)) = *lookalikes.entry(e).or_insert_with(|| {
                    let name = Name::new(e);
                    ours.iter().find_map(|o| similar(&name, o).map(|w| (o.raw, w)))
                })
            {
                push(Kind::Lookalike, Severity::Medium, Some(ours.to_string()), format!("\"{e}\" {why} (\"{ours}\")."), &rows, &all);
                continue;
            }
        }
        if family {
            continue;
        }
        if let Some(n) = mac_num(bssid)
            && let Some((mac, name)) = client_near(n)
        {
            let who = name.cloned().unwrap_or_else(|| mac.to_string());
            push(
                Kind::Bridged,
                Severity::Medium,
                Some(mac.to_string()),
                format!(
                    "Its address is next to that of your client {who}, so {who} probably broadcasts it: a phone hotspot, a Wi-Fi extender or the device's own setup network. Extenders and hotspots can bridge other devices onto your network."
                ),
                &rows,
                &all,
            );
            continue;
        }
        if watched_for > 2 * 86400 && all.first > a.now - 86400 && best.is_some_and(|s| s >= -60) {
            push(Kind::NewNearby, Severity::Low, None, format!("A strong network ({} dBm) that first appeared in the last day.", best.unwrap_or_default()), &rows, &all);
        }
    }
    out.sort_by(|x, y| x.severity.cmp(&y.severity).then(y.best_signal.cmp(&x.best_signal)));
    out
}

/// How long the BSSIDs our APs used, and when each last changed, are reused
/// before they are read from the metrics again (the checks run every minute).
const CACHE_SECS: Ts = 600;

/// What `gather` last worked out from the metrics.
#[derive(Default)]
struct Cache {
    /// When `used` was read.
    used_at: Ts,
    /// BSSIDs our APs used in the last 30 days: (bssid, AP, network name).
    used: Vec<(String, String, Option<String>)>,
    /// Per BSSID: its last change, as last worked out.
    changes: HashMap<String, Change>,
}

/// When one of our BSSIDs last changed, for the AP, radio, channel and name it
/// had when that was worked out (`at`).
struct Change {
    of: (String, Option<String>, Option<i64>, Option<String>),
    at: Ts,
    changed_at: Ts,
}

static CACHE: std::sync::LazyLock<std::sync::Mutex<Cache>> = std::sync::LazyLock::new(Default::default);

/// Loads what `assess` needs from the database and live state.
pub fn gather(store: &Store, live: &SharedLive, now: Ts) -> anyhow::Result<Assessment> {
    let mut a = Assessment { now, ..Default::default() };
    let mut own: BTreeMap<String, OwnBss> = BTreeMap::new();
    // The radio each of our live BSSIDs is on.
    let mut radios: HashMap<String, Option<String>> = HashMap::new();
    {
        let live = live.read().unwrap();
        for (mac, d) in &live.devices {
            for v in &d.snapshot.vaps {
                own.insert(
                    v.bssid.clone(),
                    OwnBss { bssid: v.bssid.clone(), ap_mac: mac.to_string(), essid: v.essid.clone(), channel: v.channel, changed_at: 0 },
                );
                radios.insert(v.bssid.clone(), v.radio.clone());
            }
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

    let mut cache = CACHE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    store.read(Db::Metrics, |c| {
        if !(0..CACHE_SECS).contains(&(now - cache.used_at)) {
            cache.used = used_bssids(c, now)?;
            cache.used_at = now;
        }
        for (bssid, ap, essid) in &cache.used {
            if !ap.is_empty() {
                a.aps.entry(ap.clone()).or_insert(None);
            }
            if let Some(e) = essid {
                a.ssids.insert(e.clone());
            }
            own.entry(bssid.clone()).or_insert_with(|| OwnBss { bssid: bssid.clone(), ap_mac: ap.clone(), essid: essid.clone(), channel: None, changed_at: 0 });
        }
        // Read only when a BSSID's last change has to be worked out again.
        let mut history: Option<History> = None;
        for b in own.values_mut() {
            if let Some(e) = &b.essid {
                a.ssids.insert(e.clone());
            }
            let radio = radios.get(&b.bssid).cloned().flatten();
            let key = (b.ap_mac.clone(), radio, b.channel, b.essid.clone());
            b.changed_at = match cache.changes.get(&b.bssid) {
                Some(ch) if ch.of == key && (0..CACHE_SECS).contains(&(now - ch.at)) => ch.changed_at,
                _ => {
                    let h = match &mut history {
                        Some(h) => h,
                        None => history.insert(History::load(c, now)?),
                    };
                    let changed_at = h.last_change(b, key.1.as_deref());
                    cache.changes.insert(b.bssid.clone(), Change { of: key, at: now, changed_at });
                    changed_at
                }
            };
        }
        cache.changes.retain(|k, _| own.contains_key(k));
        Ok(())
    })?;
    drop(cache);
    a.own = own.into_values().collect();

    let mut names = store.read(Db::Config, |c| {
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
        let mut stmt = c.prepare("SELECT kind, bssid, note, ts FROM network_acks")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?, r.get(3)?)))? {
            let (k, b, n, t) = row?;
            if let Some(k) = Kind::parse(&k) {
                a.acks.insert((k, b), (n, t));
            }
        }
        let mut stmt = c.prepare("SELECT kind, bssid, first_reported FROM network_threats")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?)))? {
            let (k, b, t) = row?;
            if let Some(k) = Kind::parse(&k) {
                a.reported.insert((k, b), t);
            }
        }
        Ok(crate::connections::Names::load(c)?)
    })?;
    // Our APs and every Wi-Fi client ever seen, with their names (aliases first).
    names.add_live(&live.read().unwrap());
    for (mac, name) in names.aps {
        let e = a.aps.entry(mac).or_insert(None);
        if name.is_some() {
            *e = name;
        }
    }
    a.clients = names.clients.into_iter().collect();
    a.clients.sort();
    Ok(a)
}

/// BSSIDs our APs used in the last 30 days, with their AP and latest name.
/// The hourly tier covers all but the last hour or so (the roll-ups run every
/// five minutes, on complete buckets), the five-minute tier the last two
/// hours and the raw one the last twenty minutes; the finest tier's name wins.
fn used_bssids(c: &Connection, now: Ts) -> rusqlite::Result<Vec<(String, String, Option<String>)>> {
    let mut out: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
    // A rolled-up row carries its bucket's start: the hour holding `now - 30 days` counts too.
    for (suffix, since) in [("", now - 20 * 60), ("_5m", now - 2 * 3600), ("_1h", now - 30 * 86400 - 3599)] {
        let mut stmt = c.prepare(&format!("SELECT bssid, ap_mac, essid, MAX(ts) FROM vap_stats{suffix} WHERE ts >= ?1 GROUP BY bssid"))?;
        for row in stmt.query_map([since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?)))? {
            let (bssid, ap, essid) = row?;
            out.entry(bssid).or_insert((ap.unwrap_or_default(), essid));
        }
    }
    Ok(out.into_iter().map(|(b, (ap, e))| (b, ap, e)).collect())
}

/// When each radio last ran each channel, and each BSSID had each name (and
/// the radios it was on), from the raw and five-minute tiers: one grouped
/// query per table and tier, for all of our BSSIDs.
///
/// Only the last [`HISTORY_SECS`] count: a change before any scan result that
/// is still looked at (the last seven days) cannot change a finding. The raw
/// tier covers the last hour, which the five-minute roll-ups may not have
/// reached yet; before that, a five-minute row counts as lasting to its
/// bucket's end, so a change is never placed earlier than it happened.
#[derive(Default)]
struct History {
    /// (AP, radio) -> (channel, when last on it); a five-minute row's channel is its bucket's average.
    channels: HashMap<(String, String), Vec<(f64, Ts)>>,
    /// BSSID -> (name, when it last had it)
    names: HashMap<String, Vec<(String, Ts)>>,
    /// BSSID -> the radios it was on
    radios: HashMap<String, HashSet<String>>,
}

/// How far back [`History`] reads: the scan results' seven days and a day to spare.
const HISTORY_SECS: Ts = 8 * 86400;

impl History {
    fn load(c: &Connection, now: Ts) -> rusqlite::Result<History> {
        let mut h = History::default();
        // (tier, since, added to a row's time to reach the end of what it covers)
        for (suffix, since, end) in [("", now - 3600, 0), ("_5m", now - HISTORY_SECS, 299)] {
            let sql = format!("SELECT mac, radio, channel, MAX(ts) + {end} FROM radio_stats{suffix} WHERE ts >= ?1 AND channel IS NOT NULL GROUP BY mac, radio, channel");
            for row in c.prepare(&sql)?.query_map([since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, f64>(2)?, r.get::<_, Ts>(3)?)))? {
                let (mac, radio, ch, ts) = row?;
                h.channels.entry((mac, radio)).or_default().push((ch, ts));
            }
            let sql = format!("SELECT bssid, essid, radio, MAX(ts) + {end} FROM vap_stats{suffix} WHERE ts >= ?1 GROUP BY bssid, essid, radio");
            for row in c.prepare(&sql)?.query_map([since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Ts>(3)?)))? {
                let (bssid, essid, radio, ts) = row?;
                if let Some(e) = essid {
                    h.names.entry(bssid.clone()).or_default().push((e, ts));
                }
                if let Some(r) = radio {
                    h.radios.entry(bssid).or_default().insert(r);
                }
            }
        }
        Ok(h)
    }

    /// When this BSSID's radio last ran another channel, or the BSSID had
    /// another name. Without its radio: the radios the BSSID was on.
    fn last_change(&self, b: &OwnBss, radio: Option<&str>) -> Ts {
        let mut latest: Ts = 0;
        if let Some(ch) = b.channel {
            let radios: Vec<&str> = match radio {
                Some(r) => vec![r],
                None => self.radios.get(&b.bssid).into_iter().flatten().map(String::as_str).collect(),
            };
            for r in radios {
                let other = self.channels.get(&(b.ap_mac.clone(), r.to_string())).into_iter().flatten().filter(|(c, _)| *c != ch as f64);
                latest = latest.max(other.map(|(_, t)| *t).max().unwrap_or(0));
            }
        }
        if let Some(e) = &b.essid {
            let other = self.names.get(&b.bssid).into_iter().flatten().filter(|(n, _)| n != e);
            latest = latest.max(other.map(|(_, t)| *t).max().unwrap_or(0));
        }
        latest
    }
}

/// The findings last worked out (by [`watch`] every minute, or for a request),
/// which `list` serves while they are fresh rather than gathering them again.
struct Latest {
    at: Ts,
    findings: Vec<Finding>,
    watching_since: Ts,
}

/// How long [`Latest`] is served: a little over `watch`'s minute.
const LATEST_SECS: Ts = 90;

static LATEST: std::sync::Mutex<Option<Latest>> = std::sync::Mutex::new(None);

fn latest() -> std::sync::MutexGuard<'static, Option<Latest>> {
    LATEST.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn findings(s: &AppState) -> Result<(Vec<Finding>, Ts), ApiError> {
    let now = store::now_ts();
    if let Some(l) = latest().as_ref().filter(|l| (0..LATEST_SECS).contains(&(now - l.at))) {
        return Ok((l.findings.clone(), l.watching_since));
    }
    let (store, live) = (s.store.clone(), s.live.clone());
    let (list, watching_since) = tokio::task::spawn_blocking(move || {
        let a = gather(&store, &live, now)?;
        Ok::<_, anyhow::Error>((assess(&a), a.watching_since))
    })
    .await?
    .map_err(ApiError::from)?;
    *latest() = Some(Latest { at: now, findings: list.clone(), watching_since });
    Ok((list, watching_since))
}

/// GET /api/rf/threats
pub async fn list(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (list, watching_since) = findings(&s).await?;
    // Vendors help tell a neighbour's router from a laptop or phone.
    let items: Vec<Value> = list
        .iter()
        .map(|f| {
            let mut j = serde_json::to_value(f)?;
            j["vendor"] = json!(s.vendors.lookup_str(&f.bssid));
            Ok(j)
        })
        .collect::<serde_json::Result<_>>()
        .map_err(|e| ApiError::internal(e.to_string()))?;
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
pub async fn ack(State(s): State<AppState>, Json(b): Json<AckBody>) -> Result<Json<Value>, ApiError> {
    let Some(kind) = Kind::parse(&b.kind) else {
        return Err(ApiError(StatusCode::BAD_REQUEST, "unknown kind".into()));
    };
    let bssid: Mac = b.bssid.parse().map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid BSSID".into()))?;
    let note = b.note.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if note.as_ref().is_some_and(|n| n.chars().count() > 200) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "note is too long (200 characters at most)".into()));
    }
    let (ts, bssid) = (store::now_ts(), bssid.to_string());
    let ack = b.ack.then(|| Ack { note: note.clone(), ts });
    let input = Input::AckThreat { ts, kind, bssid: bssid.clone(), note: if b.ack { Some(note) } else { None } };
    s.send(input).await?;
    // The findings served from memory show it at once.
    if let Some(l) = latest().as_mut() {
        for f in l.findings.iter_mut().filter(|f| f.kind == kind && f.bssid == bssid) {
            f.acknowledged.clone_from(&ack);
        }
    }
    Ok(Json(json!({ "ok": true })))
}

/// Forgets the findings about networks no longer heard at all (the networks
/// heard are kept 30 days), so the list of reported findings does not grow
/// for ever; a network heard again later is reported again.
fn prune(writer: &Writer) {
    writer.exec(Db::Config, "DELETE FROM network_threats WHERE bssid NOT IN (SELECT bssid FROM neighbors)", vec![]);
}

/// Re-assesses every minute and reports each new, unacknowledged finding once.
pub fn watch(store: std::sync::Arc<Store>, live: SharedLive, engine: tokio::sync::mpsc::Sender<Input>, writer: Writer) {
    tokio::spawn(async move {
        // Give the APs a few informs to report their networks first.
        tokio::time::sleep(Duration::from_secs(90)).await;
        let mut every = tokio::time::interval(Duration::from_secs(60));
        let mut pruned: Ts = 0;
        loop {
            every.tick().await;
            if store::now_ts() - pruned >= 3600 {
                prune(&writer);
                pruned = store::now_ts();
            }
            let (st, lv, now) = (store.clone(), live.clone(), store::now_ts());
            let found = tokio::task::spawn_blocking(move || gather(&st, &lv, now).map(|a| (assess(&a), a.watching_since))).await;
            let (mut list, watching_since) = match found {
                Ok(Ok(l)) => l,
                Ok(Err(e)) => {
                    tracing::warn!("network threat check failed: {e:#}");
                    continue;
                }
                Err(e) => {
                    tracing::error!("network threat check crashed: {e}");
                    continue;
                }
            };
            for f in list.iter_mut().filter(|f| f.first_reported.is_none()) {
                let device = f.heard_by.first().and_then(|h| h.mac.parse().ok());
                let notify = f.acknowledged.is_none();
                let data = json!({
                    "kind": f.kind, "severity": f.severity, "bssid": f.bssid, "essid": f.essid, "target": f.target,
                    "signal": f.best_signal, "channel": f.channel, "detail": f.detail,
                });
                let input = Input::ThreatFound { ts: now, kind: f.kind, bssid: f.bssid.clone(), device_mac: device, data, notify };
                if engine.send(input).await.is_err() {
                    return;
                }
                // As the engine records it.
                f.first_reported = Some(now);
            }
            *latest() = Some(Latest { at: now, findings: list, watching_since });
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

    fn kinds(a: &Assessment) -> Vec<(Kind, Severity, String)> {
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
        assert_eq!((f[0].kind, f[0].severity), (Kind::Impersonation, Severity::High));
        assert!(f[0].detail.contains("no password"), "{}", f[0].detail);
        // Different security is called out.
        let mut a = site();
        a.heard.push(heard("02:11:22:33:44:55", DOWN, "Home", 6, "WPA-Personal (TKIP)", -70));
        assert!(assess(&a)[0].detail.contains("different security"));
        // Next to our AP's own addresses: probably ours, so only medium.
        let mut a = site();
        a.heard.push(heard("7a:45:58:3c:52:bf", UP, "Home", 48, "WPA2-Personal (AES/CCMP)", -80));
        assert_eq!(kinds(&a), vec![(Kind::Impersonation, Severity::Medium, "7a:45:58:3c:52:bf".into())]);
    }

    #[test]
    fn our_bssid_on_another_channel_is_spoofing_unless_we_moved() {
        let mut a = site();
        a.heard.push(heard("78:45:58:3c:52:be", UP, "Home", 149, "WPA2-Personal (AES/CCMP)", -60));
        // (replaces the normal sighting: one row per BSSID and hearing AP)
        a.heard.retain(|h| !(h.bssid == "78:45:58:3c:52:be" && h.channel == Some(48)));
        assert_eq!(kinds(&a), vec![(Kind::SpoofedBssid, Severity::High, "78:45:58:3c:52:be".into())]);
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
        assert_eq!(kinds(&a), vec![(Kind::Lookalike, Severity::Medium, "02:aa:bb:cc:dd:ee".into())]);
    }

    #[test]
    fn hotspots_next_to_a_client_address_are_bridged() {
        let mut a = site();
        a.heard.push(heard("3e:55:76:00:00:04", UP, "phone hotspot", 6, "WPA2-Personal (AES/CCMP)", -50));
        let f = assess(&a);
        assert_eq!((f[0].kind, f[0].target.as_deref()), (Kind::Bridged, Some("3c:55:76:00:00:03")));
        assert!(f[0].detail.contains("phone"));
    }

    #[test]
    fn new_strong_networks_once_we_have_watched_a_while() {
        let mut a = site();
        let mut n = heard("02:00:00:00:00:01", UP, "Neighbour", 36, "WPA2-Personal (AES/CCMP)", -55);
        n.first_seen = a.now - 3600;
        n.last_seen = a.now;
        a.heard.push(n.clone());
        assert_eq!(kinds(&a), vec![(Kind::NewNearby, Severity::Low, "02:00:00:00:00:01".into())]);
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
    fn our_bssids_and_their_changes_come_from_every_tier() {
        let dir = std::env::temp_dir().join(format!("apctl-threats-{}-{}", std::process::id(), store::now_ts()));
        let (store, _writer) = Store::open(&dir).unwrap();
        let c = Connection::open(dir.join("metrics.db")).unwrap();
        let now = 1_000_000_000;
        let vap = |suffix: &str, bssid: &str, ts: Ts, essid: &str, radio: &str| {
            let sql = format!("INSERT INTO vap_stats{suffix} (bssid, ts, ap_mac, essid, radio) VALUES (?1, ?2, ?3, ?4, ?5)");
            c.execute(&sql, rusqlite::params![bssid, ts, UP, essid, radio]).unwrap();
        };
        // Last heard 20 days ago (hourly tier only); an hour ago, renamed since; just now.
        vap("_1h", "02:00:00:00:00:01", now - 20 * 86400, "Old", "ng");
        vap("_1h", "02:00:00:00:00:02", now - 86400, "Home", "na");
        vap("_5m", "02:00:00:00:00:02", now - 3600, "Home", "na");
        vap("", "02:00:00:00:00:02", now - 60, "Home 2", "na");
        vap("", "02:00:00:00:00:03", now - 60, "IoT", "ng");
        // Too old for any tier's window.
        vap("_1h", "02:00:00:00:00:04", now - 31 * 86400 - 3600, "Gone", "ng");
        let radio = |suffix: &str, ts: Ts, radio: &str, ch: f64| {
            let sql = format!("INSERT INTO radio_stats{suffix} (mac, radio, ts, channel) VALUES (?1, ?2, ?3, ?4)");
            c.execute(&sql, rusqlite::params![UP, radio, ts, ch]).unwrap();
        };
        radio("_5m", now - 7200, "na", 40.0); // a bucket that saw a move from 36 to 44
        radio("_5m", now - 3600, "na", 44.0);
        radio("", now - 60, "na", 44.0);
        radio("_5m", now - 600, "ng", 6.0);
        radio("", now - 120, "ng", 1.0);
        // Raw rows past the last hour are left to the five-minute tier, and
        // nothing before the scan results' window counts.
        radio("", now - 2 * 3600, "na", 36.0);
        radio("_5m", now - 9 * 86400, "na", 52.0);
        vap("_5m", "02:00:00:00:00:02", now - 9 * 86400, "Ancient", "na");
        let (used, h) = store.read(Db::Metrics, |c| Ok((used_bssids(c, now)?, History::load(c, now)?))).unwrap();
        let names: Vec<(&str, Option<&str>)> = used.iter().map(|(b, _, e)| (b.as_str(), e.as_deref())).collect();
        assert_eq!(names, [("02:00:00:00:00:01", Some("Old")), ("02:00:00:00:00:02", Some("Home 2")), ("02:00:00:00:00:03", Some("IoT"))]);
        let own = |bssid: &str, essid: &str, channel: i64| OwnBss { bssid: bssid.into(), ap_mac: UP.into(), essid: Some(essid.into()), channel: Some(channel), changed_at: 0 };
        // Called "Home" an hour ago, and on channel 44 since the averaged bucket
        // before; a five-minute row lasts to its bucket's end.
        assert_eq!(h.last_change(&own("02:00:00:00:00:02", "Home", 44), Some("na")), now - 60, "the rename");
        assert_eq!(h.last_change(&own("02:00:00:00:00:02", "Home 2", 44), Some("na")), now - 3600 + 299);
        assert_eq!(h.last_change(&own("02:00:00:00:00:02", "Home 2", 36), Some("na")), now - 60);
        // Without its radio: the radios the BSSID was on.
        assert_eq!(h.last_change(&own("02:00:00:00:00:03", "IoT", 6), None), now - 120);
        assert_eq!(h.last_change(&own("02:00:00:00:00:03", "IoT", 1), Some("ng")), now - 600 + 299);
        assert_eq!(h.last_change(&own("02:00:00:00:00:01", "Old", 6), None), 0, "only in the hourly tier");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn findings_about_networks_no_longer_heard_are_forgotten() {
        let dir = std::env::temp_dir().join(format!("apctl-threats-prune-{}-{}", std::process::id(), store::now_ts()));
        let (store, writer) = Store::open(&dir).unwrap();
        let sql = "INSERT INTO neighbors (bssid, ap_mac, first_seen, last_seen) VALUES ('02:00:00:00:00:01', ?1, 1, 2)";
        writer.exec(Db::Config, sql, vec![rusqlite::types::Value::Text(UP.into())]);
        for (kind, bssid) in [("lookalike", "02:00:00:00:00:01"), ("bridged", "02:00:00:00:00:01"), ("new_nearby", "02:00:00:00:00:02")] {
            let sql = "INSERT INTO network_threats (kind, bssid, first_reported) VALUES (?1, ?2, 1)";
            writer.exec(Db::Config, sql, vec![rusqlite::types::Value::Text(kind.into()), rusqlite::types::Value::Text(bssid.into())]);
        }
        prune(&writer);
        assert!(writer.flush(Duration::from_secs(5)));
        let left: Vec<String> = store
            .read(Db::Config, |c| Ok(c.prepare("SELECT kind FROM network_threats ORDER BY kind")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?))
            .unwrap();
        assert_eq!(left, ["bridged", "lookalike"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_distance_with_a_limit() {
        let c = |s: &str| s.chars().collect::<Vec<char>>();
        assert!(within_edits(&c("home"), &c("hone"), 1));
        assert!(within_edits(&c("homewifi"), &c("homewlfii"), 2));
        assert!(!within_edits(&c("home"), &c("hide"), 1));
        assert!(!within_edits(&c("home"), &c("homewifi"), 2), "lengths too far apart");
        assert!(within_edits(&c(""), &c("ab"), 2));
    }

    #[test]
    fn acknowledgements_are_per_kind_and_bssid() {
        let mut a = site();
        a.heard.push(heard("02:aa:bb:cc:dd:ee", UP, "H0me", 36, "Open", -70));
        a.acks.insert((Kind::Lookalike, "02:aa:bb:cc:dd:ee".into()), (Some("the neighbours".into()), 5));
        assert_eq!((Kind::parse("lookalike"), json!(Kind::NewNearby)), (Some(Kind::Lookalike), json!("new_nearby")), "named as stored");
        let f = assess(&a);
        assert_eq!(f[0].acknowledged.as_ref().and_then(|x| x.note.as_deref()), Some("the neighbours"));
        // The same BSSID copying our name exactly is a different finding.
        a.heard.last_mut().unwrap().essid = Some("Home".into());
        assert!(assess(&a)[0].acknowledged.is_none());
    }
}
