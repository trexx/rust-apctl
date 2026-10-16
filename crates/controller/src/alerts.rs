//! Alerts: the few things worth interrupting someone for, shown in the UI and
//! as browser notifications while apctl is open.
//!
//! AP status follows the official controller: an AP is reported offline only
//! after 4 minutes without contact, at most twice a day per AP (after that,
//! one "keeps dropping off" alert a day), and its return is reported with how
//! long it was gone. Suspicious networks, AP restarts, firmware changes,
//! radar and applied configs come from events as they happen. Wi-Fi health
//! thresholds are apctl's own (the official controller has none): sustained
//! TX retries, channel use, interference and clients failing to connect,
//! each raised once and resolved when back to normal.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use rusqlite::types::Value as Sql;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};

use crate::api::{ApiError, AppState};
use crate::engine::{Event, EventKind, LiveMsg, SharedLive};
use crate::insights::{RETRY_AT, RETRY_COLS, Spec, retry_pct, retry_totals};
use crate::model::Ts;
use crate::settings::band_name;
use crate::store::{self, Db, Store, Writer};

/// An AP is offline after this long without contact.
pub const OFFLINE_AFTER: Ts = 240;
/// How long a Wi-Fi health condition must hold.
const HEALTH_WINDOW: Ts = 900;
/// The same health alert is not raised again sooner than this after it cleared.
const HEALTH_COOLDOWN: Ts = 6 * 3600;
/// A radio health alert is closed when the radio has not been judged for this
/// many checks in a row (a minute apart): it stopped reporting, or its AP went.
const HEALTH_STALE_CHECKS: u32 = 15;

/// Declares a fieldless enum whose variants are stored and sent by name, with
/// `as_str`, `parse` and serialisation as that name.
macro_rules! named_enum {
    ($(#[$attr:meta])* $vis:vis enum $name:ident { $($variant:ident = $str:literal),* $(,)? }) => {
        $(#[$attr])*
        $vis enum $name {
            $($variant,)*
        }

        impl $name {
            /// As stored and as the API names it.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $str,)*
                }
            }

            pub fn parse(s: &str) -> Option<$name> {
                match s {
                    $($str => Some($name::$variant),)*
                    _ => None,
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }
    };
}
pub(crate) use named_enum;

named_enum! {
    /// What an alert is about.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Category { ApStatus = "ap_status", Security = "security", Health = "health", Changes = "changes" }
}

named_enum! {
    /// How urgent an alert is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Severity { High = "high", Medium = "medium", Low = "low", Info = "info" }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Alert {
    pub id: String,
    pub ts: Ts,
    /// e.g. `ap_offline`, `high_retries`.
    pub key: String,
    pub category: Category,
    pub severity: Severity,
    /// What it is about (AP MAC, AP MAC + band, BSSID...).
    pub entity: String,
    pub title: String,
    pub message: String,
    /// Where to look in the UI.
    pub link: Option<String>,
    /// Notifications with the same tag replace each other (offline -> back online).
    pub tag: String,
    pub resolved_ts: Option<Ts>,
}

impl Alert {
    /// A new alert, linked nowhere, tagged with its key and entity.
    fn new(key: &str, category: Category, severity: Severity, entity: &str, title: String, message: String) -> Alert {
        let tag = format!("{key}:{entity}");
        Alert { id: String::new(), ts: 0, key: key.into(), category, severity, entity: entity.into(), title, message, link: None, tag, resolved_ts: None }
    }

    /// An alert about an AP (`mac`), linked to its page.
    fn for_device(key: &str, category: Category, severity: Severity, mac: &str, title: String, message: String) -> Alert {
        let link = (!mac.is_empty()).then(|| format!("/devices/{mac}"));
        Alert { link, ..Alert::new(key, category, severity, mac, title, message) }
    }

    fn link(self, link: impl Into<String>) -> Alert {
        Alert { link: Some(link.into()), ..self }
    }

    fn tagged(self, tag: impl Into<String>) -> Alert {
        Alert { tag: tag.into(), ..self }
    }

    /// Raised already resolved: a one-off notice.
    fn resolved(self, now: Ts) -> Alert {
        Alert { resolved_ts: Some(now), ..self }
    }
}

/// What a live subscriber is told.
#[derive(Debug, Clone, Serialize)]
pub struct AlertMsg {
    /// `raised` or `resolved`.
    pub action: &'static str,
    #[serde(flatten)]
    pub alert: Alert,
}

pub struct Alerts {
    writer: Writer,
    tx: broadcast::Sender<LiveMsg>,
    /// The last alert's number, which ids carry: it continues from the stored
    /// alerts' (see [`load_open`]), so an id is never used twice, even when
    /// apctl restarts within a second or the clock steps back.
    seq: u64,
    /// Open alerts by (key, entity).
    open: HashMap<(String, String), Alert>,
}

impl Alerts {
    fn raise(&mut self, now: Ts, mut a: Alert) -> Alert {
        self.seq += 1;
        a.id = format!("{now}-{}", self.seq);
        a.ts = now;
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO alerts (id, ts, key, category, severity, entity, title, message, link, tag, resolved_ts, read) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0)",
            vec![
                Sql::Text(a.id.clone()),
                Sql::Integer(now),
                Sql::Text(a.key.clone()),
                Sql::Text(a.category.as_str().into()),
                Sql::Text(a.severity.as_str().into()),
                Sql::Text(a.entity.clone()),
                Sql::Text(a.title.clone()),
                Sql::Text(a.message.clone()),
                a.link.clone().map_or(Sql::Null, Sql::Text),
                Sql::Text(a.tag.clone()),
                a.resolved_ts.map_or(Sql::Null, Sql::Integer),
            ],
        );
        let _ = self.tx.send(LiveMsg::Alert(AlertMsg { action: "raised", alert: a.clone() }));
        a
    }

    /// Raises an alert that stays open until resolved; nothing if already open.
    fn open(&mut self, now: Ts, a: Alert) {
        let k = (a.key.clone(), a.entity.clone());
        if self.open.contains_key(&k) {
            return;
        }
        let a = self.raise(now, a);
        self.open.insert(k, a);
    }

    fn resolve(&mut self, now: Ts, key: &str, entity: &str, note: Option<String>) -> Option<Alert> {
        let mut a = self.open.remove(&(key.to_string(), entity.to_string()))?;
        a.resolved_ts = Some(now);
        if let Some(n) = note {
            a.message = n;
        }
        // The message too: after a reload the alert reads as the live view said ("Back after 12 min").
        self.writer.exec(Db::Config, "UPDATE alerts SET resolved_ts = ?2, message = ?3 WHERE id = ?1", vec![Sql::Text(a.id.clone()), Sql::Integer(now), Sql::Text(a.message.clone())]);
        let _ = self.tx.send(LiveMsg::Alert(AlertMsg { action: "resolved", alert: a.clone() }));
        Some(a)
    }
}

/// An AP's name in an alert, looked up only when the alert is written.
struct Name<'a>(&'a dyn Fn() -> String);

impl std::fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&(self.0)())
    }
}

fn human(secs: Ts) -> String {
    match secs {
        s if s < 90 => format!("{s} s"),
        s if s < 5400 => format!("{} min", (s + 30) / 60),
        s if s < 2 * 86400 => format!("{:.1} h", s as f64 / 3600.0),
        s => format!("{} days", s / 86400),
    }
}

/// AP offline/online decisions, kept apart from I/O for testing.
#[derive(Default)]
pub struct ApWatch {
    /// Offline alerts sent per AP: times, for the two-a-day limit.
    sent: HashMap<String, Vec<Ts>>,
    /// APs currently considered offline, with the last contact time.
    down: HashMap<String, Ts>,
    /// Day (UTC) on which a "keeps dropping off" alert was last sent per AP.
    flapping_day: HashMap<String, Ts>,
}

#[derive(Debug, PartialEq)]
pub enum ApChange {
    Offline { last_seen: Ts },
    /// Too many offline alerts today: this one is summarised instead.
    Flapping { times: usize },
    /// Back; `alerted` says whether an offline alert had been sent.
    Online { down_for: Ts, alerted: bool },
}

impl ApWatch {
    pub fn check(&mut self, now: Ts, mac: &str, last_seen: Ts) -> Option<ApChange> {
        let gone = now - last_seen >= OFFLINE_AFTER;
        match (gone, self.down.get(mac).copied()) {
            (true, None) => {
                self.down.insert(mac.to_string(), last_seen);
                let sent = self.sent.entry(mac.to_string()).or_default();
                sent.retain(|t| *t > now - 86400);
                if sent.len() < 2 {
                    sent.push(now);
                    Some(ApChange::Offline { last_seen })
                } else if self.flapping_day.get(mac) != Some(&(now / 86400)) {
                    self.flapping_day.insert(mac.to_string(), now / 86400);
                    Some(ApChange::Flapping { times: sent.len() + 1 })
                } else {
                    None
                }
            }
            (false, Some(since)) => {
                self.down.remove(mac);
                let alerted = self.sent.get(mac).and_then(|s| s.last()).is_some_and(|t| *t >= since);
                Some(ApChange::Online { down_for: last_seen.max(now - 1) - since, alerted })
            }
            _ => None,
        }
    }
}

/// Whether [`from_event`] may turn an event of this kind into an alert: the
/// engine sends the watcher only these.
pub fn alertable(kind: EventKind) -> bool {
    use EventKind::*;
    matches!(kind, NetworkThreat | ApRestarted | ApFirmwareChanged | DfsRadar | ApIsolated | ApCrash | ApProcessRestarted | ApUpgradeFailed | ApUpgraded | ConfigApplied)
}

/// An alert for an event, if the event deserves one.
fn from_event(kind: EventKind, device: Option<&str>, data: &Value, ap_name: &dyn Fn(&str) -> String) -> Option<Alert> {
    use Category::{ApStatus, Changes};
    if !alertable(kind) {
        return None;
    }
    // Every alert but a suspicious network's is about an AP: without one (a
    // crash line from a sender apctl can't name) it makes none.
    let dev = match device {
        Some(d) => d,
        None if kind == EventKind::NetworkThreat => "",
        None => return None,
    };
    let lookup = || ap_name(dev);
    let name = Name(&lookup);
    let s = |k: &str| data[k].as_str().unwrap_or_default().to_string();
    let on = |key: &str, category: Category, severity: Severity, title: String, message: String| Alert::for_device(key, category, severity, dev, title, message);
    Some(match kind {
        EventKind::NetworkThreat => {
            let sev = match data["severity"].as_str() {
                Some("high") => Severity::High,
                Some("medium") => Severity::Medium,
                _ => return None,
            };
            let essid = data["essid"].as_str().map_or("A hidden network".to_string(), |e| format!("\"{e}\""));
            let (kind, bssid) = (s("kind"), s("bssid"));
            Alert::new("suspicious_network", Category::Security, sev, &format!("{kind}/{bssid}"), format!("Suspicious network: {essid}"), s("detail"))
                .link("/radios?tab=rogue")
                .tagged(format!("threat:{kind}:{bssid}"))
        }
        EventKind::ApRestarted => on("ap_restarted", Changes, Severity::Low, format!("{name} restarted"), format!("It had been up for {}.", human(data["uptime"].as_i64().unwrap_or(0))))
            .tagged(format!("restart:{dev}")),
        EventKind::ApFirmwareChanged => on("ap_firmware_changed", Changes, Severity::Info, format!("{name} firmware changed"), format!("{} → {}", s("from"), s("to"))).tagged(format!("firmware:{dev}")),
        EventKind::DfsRadar => {
            let message = match data["channel"].as_i64() {
                Some(c) => format!("Channel {c} had to be vacated (DFS); the AP moved to another channel."),
                None => "A DFS channel had to be vacated; the AP moved to another channel.".into(),
            };
            on("dfs_radar", Changes, Severity::Low, format!("Radar detected by {name}"), message).tagged(format!("radar:{dev}"))
        }
        EventKind::ApIsolated => {
            let message = "Its beacon says it has lost its uplink; clients on it may have no network.".into();
            on("ap_isolated", ApStatus, Severity::High, format!("{name} is isolated"), message).tagged(format!("ap-status:{dev}"))
        }
        EventKind::ApCrash => {
            let title = match data["process"].as_str() {
                Some(p) => format!("{p} crashed on {name}"),
                None => format!("{name}: {}", data["kind"].as_str().unwrap_or("crash")),
            };
            let first = data["lines"].as_array().and_then(|l| l.first()).and_then(Value::as_str).unwrap_or("See the event for details.");
            on("ap_crash", Changes, Severity::Medium, title, first.to_string()).tagged(format!("crash:{dev}"))
        }
        EventKind::ApProcessRestarted => {
            let title = format!("{} restarted on {name}", data["proc"].as_str().unwrap_or("A process"));
            let message = format!("It exited with code {} and was restarted by {}.", data["exit_status"], data["caller"].as_str().unwrap_or("the system"));
            on("ap_process_restarted", Changes, Severity::Low, title, message).tagged(format!("proc:{dev}"))
        }
        EventKind::ApUpgradeFailed => {
            let message = data["detail"].as_str().unwrap_or("The update did not complete.").to_string();
            on("ap_upgrade_failed", Changes, Severity::Medium, format!("{name} firmware update failed"), message).link("/config?tab=firmware").tagged(format!("upgrade:{dev}"))
        }
        EventKind::ApUpgraded => {
            let title = format!("{name} updated to {}", data["to"].as_str().unwrap_or("new firmware"));
            let message = format!("From {}.", data["from"].as_str().unwrap_or("the previous version"));
            on("ap_upgraded", Changes, Severity::Info, title, message).link("/config?tab=firmware").tagged(format!("upgrade:{dev}"))
        }
        EventKind::ConfigApplied => {
            let message = "The AP applied a configuration change.".into();
            on("config_applied", Changes, Severity::Info, format!("New settings applied on {name}"), message).link("/config").tagged(format!("config:{dev}"))
        }
        _ => return None,
    })
}

/// Health figures for one AP radio over the last window.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RadioHealth {
    /// Whether the radio's networks reported TX counters in the window.
    pub retries_reported: bool,
    pub retry_pct: Option<f64>,
    pub attempts: f64,
    pub utilisation: Option<f64>,
    pub interference: Option<f64>,
}

/// (key, raise when, clear when, title, unit) for each radio threshold.
fn radio_checks(h: &RadioHealth) -> [(&'static str, Option<f64>, f64, f64, &'static str); 3] {
    [
        ("high_retries", h.retry_pct.filter(|_| h.attempts >= 500.0), 25.0, 20.0, "TX retries"),
        ("busy_channel", h.utilisation, 80.0, 70.0, "channel utilisation"),
        ("interference", h.interference, 50.0, 40.0, "interference"),
    ]
}

async fn radio_health(store: &Arc<Store>, now: Ts) -> anyhow::Result<HashMap<(String, String), RadioHealth>> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || {
        store.read(Db::Metrics, |c| {
            let from = now - HEALTH_WINDOW;
            let mut out: HashMap<(String, String), RadioHealth> = HashMap::new();
            let mut stmt = c.prepare("SELECT mac, radio, AVG(cu_total), AVG(cu_interf), COUNT(*), MIN(ts), MAX(ts) FROM radio_stats WHERE ts >= ?1 GROUP BY mac, radio")?;
            let rows = stmt.query_map([from], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<f64>>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, i64>(4)?, r.get::<_, Ts>(5)?, r.get::<_, Ts>(6)?))
            })?;
            for row in rows {
                let (mac, radio, cu, interf, n, first, last) = row?;
                // Only judge a radio that reported through most of the window.
                // By time, not by count: an AP informs every 5 s per AP on the
                // site, so with many APs a window holds only a dozen reports.
                if n >= 3 && last - first >= HEALTH_WINDOW * 2 / 3 {
                    let h = out.entry((mac, radio)).or_default();
                    h.utilisation = cu;
                    h.interference = interf;
                }
            }
            // Retries from the SSIDs' counters, counted as the other views count them.
            let spec = Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: &RETRY_COLS, only: None };
            let vaps = crate::insights::load(c, spec, 0, from, now)?;
            for (k, t) in retry_totals(&vaps, RETRY_AT, from) {
                let h = out.entry(k).or_default();
                h.retries_reported = true;
                h.attempts = t[1];
                if t.iter().sum::<f64>() > 0.0 {
                    h.retry_pct = Some(retry_pct(t));
                }
            }
            Ok(out)
        })
    })
    .await?
}

/// How many clients failed every connection attempt in the window.
async fn failing_clients(store: &Arc<Store>, now: Ts) -> anyhow::Result<usize> {
    let store = store.clone();
    // Parsing the reports and pairing fixups is CPU work: off the async workers too.
    tokio::task::spawn_blocking(move || {
        let events = store.read(Db::Config, |c| Ok(crate::connections::load_rows(c, now - HEALTH_WINDOW, Ts::MAX, None, None, true)?))?;
        let attempts = crate::connections::attempts(events);
        let ok: HashSet<&str> = attempts.iter().filter(|a| a.success).map(|a| a.client.as_str()).collect();
        let failing: HashSet<&str> = attempts.iter().filter(|a| !a.success && !ok.contains(a.client.as_str())).map(|a| a.client.as_str()).collect();
        Ok(failing.len())
    })
    .await?
}

/// Alerts left open by a previous run, and the highest number a stored
/// alert's id carries (`{ts}-{number}`).
async fn load_open(store: &Arc<Store>) -> anyhow::Result<(Vec<Alert>, u64)> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || {
        store.read(Db::Config, |c| {
            let sql = "SELECT COALESCE(MAX(CAST(substr(id, instr(id, '-') + 1) AS INTEGER)), 0) FROM alerts";
            let seq = c.query_row(sql, [], |r| r.get::<_, i64>(0))?;
            let mut stmt = c.prepare("SELECT id, ts, key, category, severity, entity, title, message, link, tag FROM alerts WHERE resolved_ts IS NULL")?;
            let rows = stmt
                .query_map([], |r| {
                    let (cat, sev): (String, String) = (r.get(3)?, r.get(4)?);
                    Ok(Alert {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        key: r.get(2)?,
                        category: Category::parse(&cat).unwrap_or(Category::Changes),
                        severity: Severity::parse(&sev).unwrap_or(Severity::Info),
                        entity: r.get(5)?,
                        title: r.get(6)?,
                        message: r.get(7)?,
                        link: r.get(8)?,
                        tag: r.get(9)?,
                        resolved_ts: None,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((rows, u64::try_from(seq).unwrap_or(0)))
        })
    })
    .await?
}

/// Open health alerts to close: of radios not judged for [`HEALTH_STALE_CHECKS`]
/// checks in a row (`unjudged` counts them), or of APs no longer known.
fn stale_health(open: &HashMap<(String, String), Alert>, judged: &HashSet<(String, String)>, unjudged: &mut HashMap<(String, String), u32>, known: &HashSet<String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, a) in open {
        if a.category != Category::Health || k.0 == "connect_failures" {
            continue;
        }
        if judged.contains(k) {
            unjudged.remove(k);
            continue;
        }
        let n = unjudged.entry(k.clone()).or_default();
        *n += 1;
        let mac = k.1.split('/').next().unwrap_or_default();
        if *n >= HEALTH_STALE_CHECKS || !known.contains(mac) {
            out.push(k.clone());
        }
    }
    for k in &out {
        unjudged.remove(k);
    }
    out
}

/// The engine's side of the watcher's own event channel: alert-worthy events
/// only, so they are not lost among the log lines on the live broadcast. When
/// the watcher falls that far behind, events are dropped and counted.
#[derive(Clone)]
pub struct Sink {
    tx: mpsc::Sender<Event>,
    dropped: Arc<AtomicU64>,
}

impl Sink {
    /// Passes an event on if it may make an alert.
    pub fn offer(&self, ev: &Event) {
        if !alertable(ev.kind) {
            return;
        }
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(ev.clone()) {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // The first drop, then every time the count doubles.
            if n.is_power_of_two() {
                tracing::warn!("the alert watcher is behind: {n} events dropped so far");
            }
        }
    }
}

/// How many alert-worthy events may wait for the watcher.
const QUEUE: usize = 1024;

/// The engine's sender and the watcher's receiver (see [`spawn`]).
pub fn channel() -> (Sink, mpsc::Receiver<Event>) {
    let (tx, rx) = mpsc::channel(QUEUE);
    (Sink { tx, dropped: Default::default() }, rx)
}

/// The alert watcher: open alerts and what the checks remember between runs.
struct Watcher {
    book: Alerts,
    store: Arc<Store>,
    live: SharedLive,
    aps: ApWatch,
    /// When each health alert last cleared, for the cooldown.
    cleared: HashMap<(String, String), Ts>,
    /// Checks in a row each open radio health alert was not judged in.
    unjudged: HashMap<(String, String), u32>,
}

impl Watcher {
    /// Starts with the alerts a previous run left open.
    async fn start(store: Arc<Store>, writer: Writer, live: SharedLive, tx: broadcast::Sender<LiveMsg>) -> Watcher {
        let mut w = Watcher { book: Alerts { writer, tx, seq: 0, open: HashMap::new() }, store, live, aps: ApWatch::default(), cleared: HashMap::new(), unjudged: HashMap::new() };
        match load_open(&w.store).await {
            Ok((open, seq)) => {
                w.book.seq = seq;
                for a in open {
                    w.book.open.insert((a.key.clone(), a.entity.clone()), a);
                }
            }
            Err(e) => tracing::warn!("could not load the open alerts: {e:#}"),
        }
        // An AP already reported offline before a restart stays so.
        for ((key, mac), a) in &w.book.open {
            if key == "ap_offline" {
                w.aps.down.insert(mac.clone(), a.ts - OFFLINE_AFTER);
                w.aps.sent.entry(mac.clone()).or_default().push(a.ts);
            }
        }
        w
    }

    /// An event as it happens: a one-off alert, if it deserves one.
    fn event(&mut self, now: Ts, e: &Event) {
        // Most events make no alert: the name is looked up only for one that does.
        let name = |m: &str| crate::insights::ap_name(&self.live.read().unwrap(), m).unwrap_or_else(|| m.to_string());
        if let Some(a) = from_event(e.kind, e.device_mac.map(|m| m.to_string()).as_deref(), &e.data, &name) {
            self.book.raise(now, a.resolved(now));
        }
    }

    /// AP status: offline after a while without contact, back online.
    fn status_tick(&mut self, now: Ts) {
        let seen: Vec<(String, Option<String>, Ts)> = {
            let l = self.live.read().unwrap();
            let mut v: Vec<_> = l.devices.iter().map(|(m, d)| (m.to_string(), d.snapshot.ap.hostname.clone(), d.last_seen)).collect();
            for (m, k) in &l.known_devices {
                if !l.devices.contains_key(m) {
                    v.push((m.to_string(), None, k.last_seen));
                }
            }
            v
        };
        // APs neither reporting nor remembered (forgotten, replaced): their offline alert closes.
        let known: HashSet<&str> = seen.iter().map(|(m, _, _)| m.as_str()).collect();
        let gone: Vec<String> = self.book.open.keys().filter(|(k, m)| k == "ap_offline" && !known.contains(m.as_str())).map(|(_, m)| m.clone()).collect();
        for mac in gone {
            self.aps.down.remove(&mac);
            self.book.resolve(now, "ap_offline", &mac, Some("The AP is no longer managed.".into()));
        }
        for (mac, name, last_seen) in seen {
            let name = name.unwrap_or_else(|| mac.clone());
            let tag = format!("ap-status:{mac}");
            let status = |key: &str, severity: Severity, title: String, message: String| Alert::for_device(key, Category::ApStatus, severity, &mac, title, message).tagged(tag.clone());
            match self.aps.check(now, &mac, last_seen) {
                Some(ApChange::Offline { last_seen }) => {
                    let message = format!("No contact for {} (last seen {}).", human(now - last_seen), clock(last_seen));
                    self.book.open(now, status("ap_offline", Severity::High, format!("{name} is offline"), message));
                }
                Some(ApChange::Flapping { times }) => {
                    let message = format!("Offline {times} times in the last day; further drops today are not reported separately.");
                    self.book.open(now, status("ap_offline", Severity::Medium, format!("{name} keeps dropping off"), message));
                }
                Some(ApChange::Online { down_for, alerted }) => {
                    let note = format!("Back after {}.", human(down_for));
                    if self.book.resolve(now, "ap_offline", &mac, Some(note.clone())).is_some() || alerted {
                        self.book.raise(now, status("ap_online", Severity::Low, format!("{name} is back online"), note).resolved(now));
                    }
                }
                None => {}
            }
        }
    }

    /// Wi-Fi health over the last window: each radio, and clients failing to connect.
    async fn health_tick(&mut self, now: Ts) {
        let (online, known): (HashSet<String>, HashSet<String>) = {
            let l = self.live.read().unwrap();
            (l.devices.iter().filter(|(_, d)| d.online).map(|(m, _)| m.to_string()).collect(), l.devices.keys().map(|m| m.to_string()).collect())
        };
        match radio_health(&self.store, now).await {
            Ok(radios) => self.judge_radios(now, radios, &online, &known),
            Err(e) => tracing::warn!("radio health check failed: {e:#}"),
        }
        match failing_clients(&self.store, now).await {
            Ok(failing) => self.judge_connections(now, failing),
            Err(e) => tracing::warn!("connection health check failed: {e:#}"),
        }
    }

    /// Raises or clears each threshold of each online AP's radios, and closes
    /// the alerts of radios no longer judged.
    fn judge_radios(&mut self, now: Ts, radios: HashMap<(String, String), RadioHealth>, online: &HashSet<String>, known: &HashSet<String>) {
        let mut judged: HashSet<(String, String)> = HashSet::new();
        for ((mac, radio), h) in radios {
            if !online.contains(&mac) {
                continue;
            }
            for (key, value, raise_at, clear_at, what) in radio_checks(&h) {
                let Some(v) = value else {
                    // Retries are not judged on a radio carrying little traffic, but
                    // it still reports: an alert open for it stays as it is.
                    if key == "high_retries" && h.retries_reported {
                        judged.insert((key.to_string(), format!("{mac}/{radio}")));
                    }
                    continue;
                };
                let entity = format!("{mac}/{radio}");
                let k = (key.to_string(), entity.clone());
                judged.insert(k.clone());
                if v >= raise_at && !self.book.open.contains_key(&k) && self.cleared.get(&k).is_none_or(|t| now - t >= HEALTH_COOLDOWN) {
                    let name = crate::insights::ap_name(&self.live.read().unwrap(), &mac).unwrap_or_else(|| mac.clone());
                    let title = format!("High {what} on {name} {}", band_name(&radio));
                    let message = format!("{what} has averaged {v:.0}% over the last 15 minutes (alert at {raise_at:.0}%).");
                    let a = Alert::new(key, Category::Health, Severity::Medium, &entity, title, message).link(format!("/devices/{mac}")).tagged(format!("health:{key}:{entity}"));
                    self.book.open(now, a);
                } else if v < clear_at && self.book.resolve(now, key, &entity, Some(format!("Back to normal: {what} {v:.0}%."))).is_some() {
                    self.cleared.insert(k, now);
                }
            }
        }
        for (key, entity) in stale_health(&self.book.open, &judged, &mut self.unjudged, known) {
            if self.book.resolve(now, &key, &entity, Some("No longer reported: the radio or its AP stopped reporting.".into())).is_some() {
                self.cleared.insert((key, entity), now);
            }
        }
    }

    /// Raises an alert when at least three clients failed every connection
    /// attempt in the window; clears it when none did.
    fn judge_connections(&mut self, now: Ts, failing: usize) {
        let k = ("connect_failures".to_string(), "site".to_string());
        if failing >= 3 && !self.book.open.contains_key(&k) && self.cleared.get(&k).is_none_or(|t| now - t >= HEALTH_COOLDOWN) {
            let message = "Every connection attempt these clients made in the last 15 minutes failed.".into();
            let a = Alert::new("connect_failures", Category::Health, Severity::Medium, "site", format!("{failing} clients can't connect"), message);
            self.book.open(now, a.link("/clients?tab=attempts").tagged("health:connect_failures"));
        } else if failing == 0 && self.book.resolve(now, "connect_failures", "site", Some("Clients are connecting again.".into())).is_some() {
            self.cleared.insert(k, now);
        }
    }
}

/// Starts the alert watcher, fed by the engine through `events` (see [`channel`]).
pub fn spawn(store: Arc<Store>, writer: Writer, live: SharedLive, tx: broadcast::Sender<LiveMsg>, mut events: mpsc::Receiver<Event>) {
    tokio::spawn(async move {
        let mut w = Watcher::start(store, writer, live, tx).await;
        // Give APs a chance to report after a restart before judging them.
        let mut status = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(90), Duration::from_secs(30));
        let mut health = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(120), Duration::from_secs(60));
        loop {
            // Events wait in the channel while a check runs.
            tokio::select! {
                e = events.recv() => match e {
                    Some(e) => w.event(store::now_ts(), &e),
                    None => return,
                },
                _ = status.tick() => w.status_tick(store::now_ts()),
                _ = health.tick() => w.health_tick(store::now_ts()).await,
            }
        }
    });
}

fn clock(ts: Ts) -> String {
    let s = ts.rem_euclid(86400);
    format!("{:02}:{:02} UTC", s / 3600, (s % 3600) / 60)
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<usize>,
}

/// Recent alerts, newest first: by time, then as stored.
const LIST: &str = "SELECT id, ts, key, category, severity, entity, title, message, link, tag, resolved_ts, read FROM alerts ORDER BY ts DESC, rowid DESC LIMIT ?1";

/// GET /api/alerts: recent alerts, newest first, with the unread count.
pub async fn list(State(s): State<AppState>, Query(q): Query<ListQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500) as i64;
    let rows = crate::api::read(&s.store, Db::Config, move |c| {
        let mut stmt = c.prepare(LIST)?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok(json!({
                    "id": r.get::<_, String>(0)?, "ts": r.get::<_, Ts>(1)?, "key": r.get::<_, String>(2)?, "category": r.get::<_, String>(3)?,
                    "severity": r.get::<_, String>(4)?, "entity": r.get::<_, String>(5)?, "title": r.get::<_, String>(6)?,
                    "message": r.get::<_, String>(7)?, "link": r.get::<_, Option<String>>(8)?, "tag": r.get::<_, String>(9)?,
                    "resolved_ts": r.get::<_, Option<Ts>>(10)?, "read": r.get::<_, i64>(11)? != 0,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let unread: i64 = c.query_row("SELECT COUNT(*) FROM alerts WHERE read = 0", [], |r| r.get(0))?;
        Ok(json!({ "alerts": rows, "unread": unread }))
    })
    .await?;
    Ok(Json(rows))
}

/// POST /api/alerts/read: marks every alert read.
pub async fn mark_read(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    // Straight to the database: the engine's queue is for what changes its state.
    s.writer.exec(Db::Config, "UPDATE alerts SET read = 1 WHERE read = 0", vec![]);
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_after_four_minutes_and_at_most_twice_a_day() {
        let mut w = ApWatch::default();
        let ap = "78:45:58:3c:52:bc";
        // Missing for 3 minutes: nothing.
        assert_eq!(w.check(1000, ap, 1000 - 180), None);
        // 4 minutes: offline.
        assert_eq!(w.check(1000, ap, 1000 - 240), Some(ApChange::Offline { last_seen: 760 }));
        assert_eq!(w.check(1030, ap, 760), None, "reported once");
        // Back after 5 minutes.
        assert_eq!(w.check(1060, ap, 1059), Some(ApChange::Online { down_for: 1059 - 760, alerted: true }));
        // Second drop the same day: reported.
        assert!(matches!(w.check(2000, ap, 1700), Some(ApChange::Offline { .. })));
        w.check(2100, ap, 2099);
        // Third: summarised once as flapping, fourth: silent.
        assert_eq!(w.check(3000, ap, 2700), Some(ApChange::Flapping { times: 3 }));
        w.check(3100, ap, 3099);
        assert_eq!(w.check(4000, ap, 3700), None);
        // The next day it is reported again.
        w.check(4100, ap, 4099);
        assert!(matches!(w.check(1000 + 90_000, ap, 1000 + 90_000 - 300), Some(ApChange::Offline { .. })));
    }

    #[test]
    fn events_that_deserve_an_alert() {
        let name = |m: &str| if m == "aa" { "Garage".to_string() } else { m.to_string() };
        let t = from_event(EventKind::NetworkThreat, Some("aa"), &json!({ "kind": "impersonation", "severity": "high", "bssid": "02:00:00:00:00:01", "essid": "Home", "detail": "x" }), &name).unwrap();
        assert_eq!((t.category, t.severity, t.title.as_str()), (Category::Security, Severity::High, "Suspicious network: \"Home\""));
        assert_eq!((t.entity.as_str(), t.tag.as_str(), t.link.as_deref()), ("impersonation/02:00:00:00:00:01", "threat:impersonation:02:00:00:00:00:01", Some("/radios?tab=rogue")));
        let j = json!(t);
        assert_eq!((j["category"].as_str(), j["severity"].as_str()), (Some("security"), Some("high")), "named as before");
        assert!(from_event(EventKind::NetworkThreat, Some("aa"), &json!({ "severity": "low" }), &name).is_none(), "low findings only show in the list");
        let r = from_event(EventKind::ApRestarted, Some("aa"), &json!({ "uptime": 7200 }), &name).unwrap();
        assert_eq!((r.title.as_str(), r.message.as_str()), ("Garage restarted", "It had been up for 2.0 h."));
        assert_eq!((r.link.as_deref(), r.tag.as_str()), (Some("/devices/aa"), "restart:aa"));
        let u = from_event(EventKind::ApUpgraded, Some("aa"), &json!({ "to": "8.8.12" }), &name).unwrap();
        assert_eq!((u.link.as_deref(), u.tag.as_str(), u.severity), (Some("/config?tab=firmware"), "upgrade:aa", Severity::Info));
        assert!(from_event(EventKind::ClientConnected, Some("aa"), &json!({}), &name).is_none());
        // Exactly the kinds the engine passes on can make an alert.
        for &kind in EventKind::ALL {
            assert_eq!(from_event(kind, Some("aa"), &json!({ "severity": "high" }), &name).is_some(), alertable(kind), "{kind}");
        }
        // An AP's alert needs the AP: a crash line from anyone else makes none.
        let panic = json!({ "kind": "kernel panic", "lines": ["Kernel panic"] });
        assert!(from_event(EventKind::ApCrash, None, &panic, &name).is_none());
        assert_eq!(from_event(EventKind::ApCrash, Some("aa"), &panic, &name).unwrap().title, "Garage: kernel panic");
        assert!(from_event(EventKind::NetworkThreat, None, &json!({ "severity": "high" }), &name).is_some());
    }

    fn watcher() -> (Watcher, broadcast::Receiver<LiveMsg>) {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("apctl-alerts-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        let (store, writer) = Store::open(&dir).unwrap();
        let (tx, rx) = broadcast::channel(64);
        let book = Alerts { writer, tx, seq: 0, open: HashMap::new() };
        (Watcher { book, store, live: Default::default(), aps: ApWatch::default(), cleared: HashMap::new(), unjudged: HashMap::new() }, rx)
    }

    /// What live subscribers were told: (action, alert key).
    fn told(rx: &mut broadcast::Receiver<LiveMsg>) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        while let Ok(LiveMsg::Alert(m)) = rx.try_recv() {
            out.push((m.action, m.alert.key));
        }
        out
    }

    #[tokio::test]
    async fn events_reach_the_watcher_on_their_own_channel() {
        let (sink, mut events) = channel();
        let ev = |kind| Event { ts: 0, kind, device_mac: "02:00:00:00:00:01".parse().ok(), client_mac: None, data: json!({ "uptime": 60 }) };
        // Only what may make an alert is passed on.
        sink.offer(&ev(EventKind::ClientConnected));
        sink.offer(&ev(EventKind::ApRestarted));
        let e = events.recv().await.unwrap();
        assert_eq!(e.kind, EventKind::ApRestarted);
        assert!(events.try_recv().is_err());
        // A full queue drops and counts.
        for _ in 0..QUEUE + 3 {
            sink.offer(&ev(EventKind::ApRestarted));
        }
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 3);
        let (mut w, mut rx) = watcher();
        w.event(100, &e);
        assert_eq!(told(&mut rx), [("raised", "ap_restarted".to_string())]);
        assert!(w.book.open.is_empty(), "a one-off notice, raised resolved");
    }

    #[tokio::test]
    async fn alert_ids_are_never_reused_and_list_newest_first() {
        let (mut w, _rx) = watcher();
        let notice = || Alert::new("ap_restarted", Category::Changes, Severity::Low, "aa", "t".into(), "m".into());
        for _ in 0..11 {
            w.book.raise(1000, notice());
        }
        assert!(w.book.writer.flush(Duration::from_secs(5)));
        // A restart within the same second carries on from the stored ids.
        let mut again = Watcher::start(w.store.clone(), w.book.writer.clone(), Default::default(), broadcast::channel(4).0).await;
        let last = again.book.raise(1000, notice());
        assert_eq!(last.id, "1000-12");
        assert!(w.book.writer.flush(Duration::from_secs(5)));
        let ids: Vec<String> = w.store.read(Db::Config, |c| Ok(c.prepare(LIST)?.query_map([100], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?)).unwrap();
        assert_eq!(ids.len(), 12, "none overwritten");
        assert_eq!((ids[0].as_str(), ids[1].as_str(), ids[2].as_str()), ("1000-12", "1000-11", "1000-10"));
    }

    #[tokio::test]
    async fn connection_failures_open_once_and_clear() {
        let (mut w, mut rx) = watcher();
        w.judge_connections(1000, 2);
        assert!(told(&mut rx).is_empty(), "two clients are not enough");
        w.judge_connections(1000, 3);
        w.judge_connections(1060, 5);
        assert_eq!(told(&mut rx), [("raised", "connect_failures".to_string())]);
        w.judge_connections(1120, 1);
        assert!(told(&mut rx).is_empty(), "cleared only when nobody fails");
        w.judge_connections(1180, 0);
        assert_eq!(told(&mut rx), [("resolved", "connect_failures".to_string())]);
        // Stored as the live view showed it.
        assert!(w.book.writer.flush(std::time::Duration::from_secs(5)));
        let stored: String = w.store.read(Db::Config, |c| Ok(c.query_row("SELECT message FROM alerts WHERE resolved_ts = 1180", [], |r| r.get(0))?)).unwrap();
        assert_eq!(stored, "Clients are connecting again.");
        // Not again within the cooldown.
        w.judge_connections(1240, 9);
        assert!(told(&mut rx).is_empty());
        w.judge_connections(1180 + HEALTH_COOLDOWN, 9);
        assert_eq!(told(&mut rx), [("raised", "connect_failures".to_string())]);
    }

    #[tokio::test]
    async fn radio_thresholds_raise_and_clear() {
        let (mut w, mut rx) = watcher();
        let ap = "02:00:00:00:00:01".to_string();
        let set: HashSet<String> = [ap.clone()].into();
        let busy = |cu| HashMap::from([((ap.clone(), "na".to_string()), RadioHealth { utilisation: Some(cu), ..Default::default() })]);
        w.judge_radios(1000, busy(85.0), &HashSet::new(), &set);
        assert!(told(&mut rx).is_empty(), "offline APs are not judged");
        w.judge_radios(1000, busy(85.0), &set, &set);
        let a = &w.book.open[&("busy_channel".to_string(), format!("{ap}/na"))];
        assert_eq!((a.category, a.tag.as_str(), a.link.as_deref()), (Category::Health, "health:busy_channel:02:00:00:00:00:01/na", Some("/devices/02:00:00:00:00:01")));
        w.judge_radios(1060, busy(75.0), &set, &set);
        assert_eq!(told(&mut rx), [("raised", "busy_channel".to_string())], "75% is between the two thresholds");
        w.judge_radios(1120, busy(65.0), &set, &set);
        assert_eq!(told(&mut rx), [("resolved", "busy_channel".to_string())]);
    }

    #[tokio::test]
    async fn a_retries_alert_stays_open_while_its_radio_is_quiet() {
        let (mut w, mut rx) = watcher();
        let ap = "02:00:00:00:00:01".to_string();
        let set: HashSet<String> = [ap.clone()].into();
        let radio = |retry_pct, attempts| HashMap::from([((ap.clone(), "na".to_string()), RadioHealth { retries_reported: true, retry_pct: Some(retry_pct), attempts, ..Default::default() })]);
        w.judge_radios(1000, radio(40.0, 5000.0), &set, &set);
        assert_eq!(told(&mut rx), [("raised", "high_retries".to_string())]);
        // Too little traffic to judge, for longer than a radio that stopped reporting gets.
        for i in 1..=HEALTH_STALE_CHECKS as Ts + 1 {
            w.judge_radios(1000 + 60 * i, radio(40.0, 100.0), &set, &set);
        }
        assert!(told(&mut rx).is_empty(), "the radio still reports");
        assert!(w.book.open.contains_key(&("high_retries".to_string(), format!("{ap}/na"))));
        w.judge_radios(2200, radio(5.0, 5000.0), &set, &set);
        assert_eq!(told(&mut rx), [("resolved", "high_retries".to_string())]);
    }

    #[test]
    fn health_alerts_close_when_their_radio_stops_reporting() {
        let ap = "02:00:00:00:00:01";
        let k = ("busy_channel".to_string(), format!("{ap}/na"));
        let book: HashMap<(String, String), Alert> = [
            (k.clone(), Alert::new("busy_channel", Category::Health, Severity::Medium, &k.1, "t".into(), "m".into())),
            (("connect_failures".into(), "site".into()), Alert::new("connect_failures", Category::Health, Severity::Medium, "site", "t".into(), "m".into())),
        ]
        .into();
        let known: HashSet<String> = [ap.to_string()].into();
        let mut unjudged = HashMap::new();
        let judged: HashSet<(String, String)> = [k.clone()].into();
        assert!(stale_health(&book, &judged, &mut unjudged, &known).is_empty(), "judged this time");
        for _ in 1..HEALTH_STALE_CHECKS {
            assert!(stale_health(&book, &HashSet::new(), &mut unjudged, &known).is_empty());
        }
        assert_eq!(stale_health(&book, &HashSet::new(), &mut unjudged, &known), vec![k.clone()]);
        // An AP that is gone closes at once; the site-wide alert is never stale.
        assert_eq!(stale_health(&book, &HashSet::new(), &mut HashMap::new(), &HashSet::new()), vec![k]);
    }

    #[tokio::test]
    async fn radios_are_judged_when_they_reported_through_the_window() {
        let (w, _rx) = watcher();
        let now = 100_000;
        let row = |radio: &str, ts: Ts| {
            let sql = "INSERT INTO radio_stats (mac, radio, ts, cu_total, cu_interf) VALUES ('02:00:00:00:00:01', ?1, ?2, 90, 10)";
            w.book.writer.exec(Db::Metrics, sql, vec![Sql::Text(radio.into()), Sql::Integer(ts)]);
        };
        // One report every 75 s, as from a site of 15 APs: 12 in the window.
        for i in 0..12 {
            row("na", now - 30 - i * 75);
        }
        // Many reports, but only over the last two minutes.
        for i in 0..40 {
            row("ng", now - i * 3);
        }
        // Too few to judge.
        row("6e", now - 800);
        row("6e", now);
        assert!(w.book.writer.flush(Duration::from_secs(5)));
        let h = radio_health(&w.store, now).await.unwrap();
        let judged = |radio: &str| h.get(&("02:00:00:00:00:01".to_string(), radio.to_string())).and_then(|h| h.utilisation);
        assert_eq!((judged("na"), judged("ng"), judged("6e")), (Some(90.0), None, None));
    }

    #[test]
    fn radio_thresholds_need_enough_traffic() {
        let quiet = RadioHealth { retries_reported: true, retry_pct: Some(60.0), attempts: 100.0, utilisation: Some(10.0), interference: None };
        let checks = radio_checks(&quiet);
        assert_eq!(checks[0].1, None, "a few retries on an idle radio are not a problem");
        let busy = RadioHealth { retry_pct: Some(30.0), attempts: 5000.0, ..quiet };
        assert_eq!(radio_checks(&busy)[0].1, Some(30.0));
    }
}
