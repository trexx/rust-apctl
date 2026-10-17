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
use inform::Mac;
use rusqlite::types::Value as Sql;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};

use crate::api::{ApiError, AppState};
use crate::clock;
use crate::engine::{Event, EventKind, LiveMsg, SharedLive};
use crate::insights::{RETRY_AT, RETRY_COLS, Spec, retry_pct, retry_totals};
use crate::model::Ts;
use crate::settings::band_name;
use crate::store::{Db, Store, Writer};

/// An AP is offline after this long without contact.
const OFFLINE_AFTER: Ts = 240;
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

named_enum! {
    /// What an alert says.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Key {
        ApOffline = "ap_offline", ApOnline = "ap_online", SuspiciousNetwork = "suspicious_network", ApRestarted = "ap_restarted",
        ApFirmwareChanged = "ap_firmware_changed", DfsRadar = "dfs_radar", ApIsolated = "ap_isolated", ApCrash = "ap_crash",
        ApProcessRestarted = "ap_process_restarted", ApUpgradeFailed = "ap_upgrade_failed", ApUpgraded = "ap_upgraded", ConfigApplied = "config_applied",
        HighRetries = "high_retries", BusyChannel = "busy_channel", Interference = "interference", ConnectFailures = "connect_failures",
    }
}

/// What an alert is about, stored and sent as text: `site`, an AP's MAC,
/// `<MAC>/<radio>`, or a suspicious network's `<kind>/<BSSID>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Entity {
    Site,
    Ap(Mac),
    Radio(Mac, String),
    /// As text: only ever raised already resolved, so never looked up.
    Network(String),
}

impl Entity {
    /// As stored for an alert with this key.
    fn parse(key: Key, s: &str) -> Option<Entity> {
        match key {
            Key::ConnectFailures => (s == "site").then_some(Entity::Site),
            Key::HighRetries | Key::BusyChannel | Key::Interference => s.split_once('/').and_then(|(m, r)| Some(Entity::Radio(m.parse().ok()?, r.to_string()))),
            Key::SuspiciousNetwork => Some(Entity::Network(s.to_string())),
            _ => s.parse().ok().map(Entity::Ap),
        }
    }
}

impl std::fmt::Display for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Entity::Site => f.write_str("site"),
            Entity::Ap(m) => write!(f, "{m}"),
            Entity::Radio(m, r) => write!(f, "{m}/{r}"),
            Entity::Network(n) => f.write_str(n),
        }
    }
}

impl Serialize for Entity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// An open alert's place in [`Alerts::open`].
type OpenKey = (Key, Entity);

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Alert {
    pub id: String,
    pub ts: Ts,
    pub key: Key,
    pub category: Category,
    pub severity: Severity,
    pub entity: Entity,
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
    fn new(key: Key, category: Category, severity: Severity, entity: Entity, title: String, message: String) -> Alert {
        let tag = format!("{}:{entity}", key.as_str());
        Alert { id: String::new(), ts: 0, key, category, severity, entity, title, message, link: None, tag, resolved_ts: None }
    }

    /// An alert about an AP (`mac`), linked to its page.
    fn for_device(key: Key, category: Category, severity: Severity, mac: Mac, title: String, message: String) -> Alert {
        Alert { link: Some(format!("/devices/{mac}")), ..Alert::new(key, category, severity, Entity::Ap(mac), title, message) }
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
    open: HashMap<OpenKey, Alert>,
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
                Sql::Text(a.key.as_str().into()),
                Sql::Text(a.category.as_str().into()),
                Sql::Text(a.severity.as_str().into()),
                Sql::Text(a.entity.to_string()),
                Sql::Text(a.title.clone()),
                Sql::Text(a.message.clone()),
                a.link.clone().map_or(Sql::Null, Sql::Text),
                Sql::Text(a.tag.clone()),
                a.resolved_ts.map_or(Sql::Null, Sql::Integer),
            ],
        );
        let _ = self.tx.send(LiveMsg::Alert(Box::new(AlertMsg { action: "raised", alert: a.clone() })));
        a
    }

    /// Raises an alert that stays open until resolved; nothing if already open.
    fn open(&mut self, now: Ts, a: Alert) {
        let k = (a.key, a.entity.clone());
        if self.open.contains_key(&k) {
            return;
        }
        let a = self.raise(now, a);
        self.open.insert(k, a);
    }

    /// Closes an open alert, its message replaced by `note` (made only then).
    fn resolve(&mut self, now: Ts, k: &OpenKey, note: impl FnOnce() -> String) -> Option<Alert> {
        let mut a = self.open.remove(k)?;
        a.resolved_ts = Some(now);
        a.message = note();
        // The message too: after a reload the alert reads as the live view said ("Back after 12 min").
        self.writer.exec(Db::Config, "UPDATE alerts SET resolved_ts = ?2, message = ?3 WHERE id = ?1", vec![Sql::Text(a.id.clone()), Sql::Integer(now), Sql::Text(a.message.clone())]);
        let _ = self.tx.send(LiveMsg::Alert(Box::new(AlertMsg { action: "resolved", alert: a.clone() })));
        Some(a)
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
struct ApWatch {
    /// Offline alerts sent per AP: times, for the two-a-day limit.
    sent: HashMap<Mac, Vec<Ts>>,
    /// APs currently considered offline, with the last contact time.
    down: HashMap<Mac, Ts>,
    /// Day (UTC) on which a "keeps dropping off" alert was last sent per AP.
    flapping_day: HashMap<Mac, Ts>,
}

#[derive(Debug, PartialEq)]
enum ApChange {
    Offline { last_seen: Ts },
    /// Too many offline alerts today: this one is summarised instead.
    Flapping { times: usize },
    /// Back; `alerted` says whether an offline alert had been sent.
    Online { down_for: Ts, alerted: bool },
}

impl ApWatch {
    fn check(&mut self, now: Ts, mac: Mac, last_seen: Ts) -> Option<ApChange> {
        let gone = now - last_seen >= OFFLINE_AFTER;
        match (gone, self.down.get(&mac).copied()) {
            (true, None) => {
                self.down.insert(mac, last_seen);
                let sent = self.sent.entry(mac).or_default();
                sent.retain(|t| *t > now - 86400);
                if sent.len() < 2 {
                    sent.push(now);
                    Some(ApChange::Offline { last_seen })
                } else if self.flapping_day.get(&mac) != Some(&(now / 86400)) {
                    self.flapping_day.insert(mac, now / 86400);
                    Some(ApChange::Flapping { times: sent.len() + 1 })
                } else {
                    None
                }
            }
            (false, Some(since)) => {
                self.down.remove(&mac);
                let alerted = self.sent.get(&mac).and_then(|s| s.last()).is_some_and(|t| *t >= since);
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
fn from_event(kind: EventKind, device: Option<Mac>, data: &Value, ap_name: &dyn Fn(Mac) -> String) -> Option<Alert> {
    use Category::{ApStatus, Changes};
    if !alertable(kind) {
        return None;
    }
    let s = |k: &str| data[k].as_str().unwrap_or_default().to_string();
    if kind == EventKind::NetworkThreat {
        let sev = match data["severity"].as_str() {
            Some("high") => Severity::High,
            Some("medium") => Severity::Medium,
            _ => return None,
        };
        let essid = data["essid"].as_str().map_or("A hidden network".to_string(), |e| format!("\"{e}\""));
        let (kind, bssid) = (s("kind"), s("bssid"));
        let a = Alert::new(Key::SuspiciousNetwork, Category::Security, sev, Entity::Network(format!("{kind}/{bssid}")), format!("Suspicious network: {essid}"), s("detail"));
        return Some(a.link("/radios?tab=rogue").tagged(format!("threat:{kind}:{bssid}")));
    }
    // Every other alert is about an AP: without one (a crash line from a
    // sender apctl can't name) it makes none.
    let dev = device?;
    let name = ap_name(dev);
    let on = |key: Key, category: Category, severity: Severity, title: String, message: String| Alert::for_device(key, category, severity, dev, title, message);
    Some(match kind {
        EventKind::ApRestarted => on(Key::ApRestarted, Changes, Severity::Low, format!("{name} restarted"), format!("It had been up for {}.", human(data["uptime"].as_i64().unwrap_or(0))))
            .tagged(format!("restart:{dev}")),
        EventKind::ApFirmwareChanged => on(Key::ApFirmwareChanged, Changes, Severity::Info, format!("{name} firmware changed"), format!("{} → {}", s("from"), s("to"))).tagged(format!("firmware:{dev}")),
        EventKind::DfsRadar => {
            let message = match data["channel"].as_i64() {
                Some(c) => format!("Channel {c} had to be vacated (DFS); the AP moved to another channel."),
                None => "A DFS channel had to be vacated; the AP moved to another channel.".into(),
            };
            on(Key::DfsRadar, Changes, Severity::Low, format!("Radar detected by {name}"), message).tagged(format!("radar:{dev}"))
        }
        EventKind::ApIsolated => {
            let message = "Its beacon says it has lost its uplink; clients on it may have no network.".into();
            on(Key::ApIsolated, ApStatus, Severity::High, format!("{name} is isolated"), message).tagged(format!("ap-status:{dev}"))
        }
        EventKind::ApCrash => {
            let title = match data["process"].as_str() {
                Some(p) => format!("{p} crashed on {name}"),
                None => format!("{name}: {}", data["kind"].as_str().unwrap_or("crash")),
            };
            let first = data["lines"].as_array().and_then(|l| l.first()).and_then(Value::as_str).unwrap_or("See the event for details.");
            on(Key::ApCrash, Changes, Severity::Medium, title, first.to_string()).tagged(format!("crash:{dev}"))
        }
        EventKind::ApProcessRestarted => {
            let title = format!("{} restarted on {name}", data["proc"].as_str().unwrap_or("A process"));
            let message = format!("It exited with code {} and was restarted by {}.", data["exit_status"], data["caller"].as_str().unwrap_or("the system"));
            on(Key::ApProcessRestarted, Changes, Severity::Low, title, message).tagged(format!("proc:{dev}"))
        }
        EventKind::ApUpgradeFailed => {
            let message = data["detail"].as_str().unwrap_or("The update did not complete.").to_string();
            on(Key::ApUpgradeFailed, Changes, Severity::Medium, format!("{name} firmware update failed"), message).link("/config?tab=firmware").tagged(format!("upgrade:{dev}"))
        }
        EventKind::ApUpgraded => {
            let title = format!("{name} updated to {}", data["to"].as_str().unwrap_or("new firmware"));
            let message = format!("From {}.", data["from"].as_str().unwrap_or("the previous version"));
            on(Key::ApUpgraded, Changes, Severity::Info, title, message).link("/config?tab=firmware").tagged(format!("upgrade:{dev}"))
        }
        EventKind::ConfigApplied => {
            let message = "The AP applied a configuration change.".into();
            on(Key::ConfigApplied, Changes, Severity::Info, format!("New settings applied on {name}"), message).link("/config").tagged(format!("config:{dev}"))
        }
        _ => return None,
    })
}

/// Health figures for one AP radio over the last window.
#[derive(Debug, Default, Clone, PartialEq)]
struct RadioHealth {
    /// Whether the radio's networks reported TX counters in the window.
    pub retries_reported: bool,
    pub retry_pct: Option<f64>,
    pub attempts: f64,
    pub utilisation: Option<f64>,
    pub interference: Option<f64>,
}

/// (key, raise when, clear when, title, unit) for each radio threshold.
fn radio_checks(h: &RadioHealth) -> [(Key, Option<f64>, f64, f64, &'static str); 3] {
    [
        (Key::HighRetries, h.retry_pct.filter(|_| h.attempts >= 500.0), 25.0, 20.0, "TX retries"),
        (Key::BusyChannel, h.utilisation, 80.0, 70.0, "channel utilisation"),
        (Key::Interference, h.interference, 50.0, 40.0, "interference"),
    ]
}

async fn radio_health(store: &Arc<Store>, now: Ts) -> anyhow::Result<HashMap<(Mac, String), RadioHealth>> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || {
        store.read(Db::Metrics, |c| {
            let from = now - HEALTH_WINDOW;
            let mut out: HashMap<(Mac, String), RadioHealth> = HashMap::new();
            let mut stmt = c.prepare("SELECT mac, radio, AVG(cu_total), AVG(cu_interf), COUNT(*), MIN(ts), MAX(ts) FROM radio_stats WHERE ts >= ?1 GROUP BY mac, radio")?;
            let rows = stmt.query_map([from], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<f64>>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, i64>(4)?, r.get::<_, Ts>(5)?, r.get::<_, Ts>(6)?))
            })?;
            for row in rows {
                let (mac, radio, cu, interf, n, first, last) = row?;
                // Only judge a radio that reported through most of the window.
                // By time, not by count: an AP informs every 5 s per AP on the
                // site, so with many APs a window holds only a dozen reports.
                if n >= 3
                    && last - first >= HEALTH_WINDOW * 2 / 3
                    && let Ok(mac) = mac.parse()
                {
                    let h = out.entry((mac, radio)).or_default();
                    h.utilisation = cu;
                    h.interference = interf;
                }
            }
            // Retries from the SSIDs' counters, counted as the other views count them.
            let spec = Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: &RETRY_COLS, only: None };
            let vaps = crate::insights::load(c, spec, 0, from, now)?;
            for ((ap, band), t) in retry_totals(&vaps, RETRY_AT, from) {
                let Ok(ap) = ap.parse() else { continue };
                let h = out.entry((ap, band.to_string())).or_default();
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

/// What a previous run left: the alerts still open, the highest number a
/// stored alert's id carries (`{ts}-{number}`), and the AP offline alerts of
/// the day before `now`, oldest first: (AP, when, whether it was a "keeps
/// dropping off" one).
async fn load_open(store: &Arc<Store>, now: Ts) -> anyhow::Result<(Vec<Alert>, u64, Vec<(Mac, Ts, bool)>)> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || {
        store.read(Db::Config, |c| {
            // "Keeps dropping off" is the only offline alert raised as medium.
            let mut stmt = c.prepare("SELECT entity, ts, severity = 'medium' FROM alerts WHERE key = 'ap_offline' AND ts > ?1 ORDER BY ts")?;
            let offline = stmt
                .query_map([now - 86400], |r| Ok((r.get::<_, String>(0)?.parse().ok(), r.get(1)?, r.get(2)?)))?
                .filter_map(|r| r.map(|(mac, ts, flapping)| Some((mac?, ts, flapping))).transpose())
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let sql = "SELECT COALESCE(MAX(CAST(substr(id, instr(id, '-') + 1) AS INTEGER)), 0) FROM alerts";
            let seq = c.query_row(sql, [], |r| r.get::<_, i64>(0))?;
            let mut stmt = c.prepare("SELECT id, ts, key, category, severity, entity, title, message, link, tag FROM alerts WHERE resolved_ts IS NULL")?;
            let rows = stmt
                .query_map([], |r| {
                    let (key, cat, sev, entity): (String, String, String, String) = (r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
                    // An alert of a kind apctl no longer raises can't be resolved: it is left as stored.
                    let Some((key, entity)) = Key::parse(&key).and_then(|k| Some((k, Entity::parse(k, &entity)?))) else { return Ok(None) };
                    Ok(Some(Alert {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        key,
                        category: Category::parse(&cat).unwrap_or(Category::Changes),
                        severity: Severity::parse(&sev).unwrap_or(Severity::Info),
                        entity,
                        title: r.get(6)?,
                        message: r.get(7)?,
                        link: r.get(8)?,
                        tag: r.get(9)?,
                        resolved_ts: None,
                    }))
                })?
                .filter_map(Result::transpose)
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((rows, u64::try_from(seq).unwrap_or(0), offline))
        })
    })
    .await?
}

/// Open health alerts to close: of radios not judged for [`HEALTH_STALE_CHECKS`]
/// checks in a row (`unjudged` counts them), or of APs no longer known.
fn stale_health(open: &HashMap<OpenKey, Alert>, judged: &HashSet<OpenKey>, unjudged: &mut HashMap<OpenKey, u32>, known: &HashSet<Mac>) -> Vec<OpenKey> {
    let mut out = Vec::new();
    for k in open.keys() {
        // A radio's only: the site-wide one is judged every time.
        let Entity::Radio(mac, _) = &k.1 else { continue };
        if judged.contains(k) {
            unjudged.remove(k);
            continue;
        }
        let n = unjudged.entry(k.clone()).or_default();
        *n += 1;
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
    pub fn offer(&self, ev: Event) {
        if !alertable(ev.kind) {
            return;
        }
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(ev) {
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
    cleared: HashMap<OpenKey, Ts>,
    /// Checks in a row each open radio health alert was not judged in.
    unjudged: HashMap<OpenKey, u32>,
}

impl Watcher {
    /// Starts with the alerts a previous run left open, and the offline
    /// alerts it sent in the last day, which count towards today's limit.
    async fn start(store: Arc<Store>, writer: Writer, live: SharedLive, tx: broadcast::Sender<LiveMsg>, now: Ts) -> Watcher {
        let mut w = Watcher { book: Alerts { writer, tx, seq: 0, open: HashMap::new() }, store, live, aps: ApWatch::default(), cleared: HashMap::new(), unjudged: HashMap::new() };
        match load_open(&w.store, now).await {
            Ok((open, seq, offline)) => {
                w.book.seq = seq;
                for a in open {
                    w.book.open.insert((a.key, a.entity.clone()), a);
                }
                for (mac, ts, flapping) in offline {
                    if flapping {
                        w.aps.flapping_day.insert(mac, ts / 86400);
                    } else {
                        w.aps.sent.entry(mac).or_default().push(ts);
                    }
                }
            }
            Err(e) => tracing::warn!("could not load the open alerts: {e:#}"),
        }
        // An AP already reported offline before a restart stays so.
        for (k, a) in &w.book.open {
            if let (Key::ApOffline, Entity::Ap(mac)) = k {
                w.aps.down.insert(*mac, a.ts - OFFLINE_AFTER);
            }
        }
        w
    }

    /// An event as it happens: a one-off alert, if it deserves one.
    fn event(&mut self, now: Ts, e: &Event) {
        // Only events that may make an alert get here (see `alertable`).
        let name = |m: Mac| crate::insights::ap_name(&self.live.read().unwrap(), &m.to_string()).unwrap_or_else(|| m.to_string());
        if let Some(a) = from_event(e.kind, e.device_mac, &e.data, &name) {
            self.book.raise(now, a.resolved(now));
        }
    }

    /// AP status: offline after a while without contact, back online.
    fn status_tick(&mut self, now: Ts) {
        let seen: Vec<(Mac, Option<String>, Ts)> = {
            let l = self.live.read().unwrap();
            let mut v: Vec<_> = l.devices.iter().map(|(m, d)| (*m, d.snapshot.ap.hostname.clone(), d.last_seen)).collect();
            for (m, k) in &l.known_devices {
                if !l.devices.contains_key(m) {
                    v.push((*m, None, k.last_seen));
                }
            }
            v
        };
        // APs neither reporting nor remembered (forgotten, replaced): their offline alert closes.
        let known: HashSet<Mac> = seen.iter().map(|(m, _, _)| *m).collect();
        let gone: Vec<Mac> = self
            .book
            .open
            .keys()
            .filter_map(|k| match k {
                (Key::ApOffline, Entity::Ap(m)) if !known.contains(m) => Some(*m),
                _ => None,
            })
            .collect();
        for mac in gone {
            self.aps.down.remove(&mac);
            self.book.resolve(now, &(Key::ApOffline, Entity::Ap(mac)), || "The AP is no longer managed.".into());
        }
        for (mac, name, last_seen) in seen {
            let name = name.unwrap_or_else(|| mac.to_string());
            let status = |key: Key, severity: Severity, title: String, message: String| Alert::for_device(key, Category::ApStatus, severity, mac, title, message).tagged(format!("ap-status:{mac}"));
            match self.aps.check(now, mac, last_seen) {
                Some(ApChange::Offline { last_seen }) => {
                    let message = format!("No contact for {} (last seen {}).", human(now - last_seen), clock(last_seen));
                    self.book.open(now, status(Key::ApOffline, Severity::High, format!("{name} is offline"), message));
                }
                Some(ApChange::Flapping { times }) => {
                    let message = format!("Offline {times} times in the last day; further drops today are not reported separately.");
                    self.book.open(now, status(Key::ApOffline, Severity::Medium, format!("{name} keeps dropping off"), message));
                }
                Some(ApChange::Online { down_for, alerted }) => {
                    let note = format!("Back after {}.", human(down_for));
                    if self.book.resolve(now, &(Key::ApOffline, Entity::Ap(mac)), || note.clone()).is_some() || alerted {
                        self.book.raise(now, status(Key::ApOnline, Severity::Low, format!("{name} is back online"), note).resolved(now));
                    }
                }
                None => {}
            }
        }
    }

    /// Wi-Fi health over the last window: each radio, and clients failing to connect.
    async fn health_tick(&mut self, now: Ts) {
        let (online, known): (HashSet<Mac>, HashSet<Mac>) = {
            let l = self.live.read().unwrap();
            (l.devices.iter().filter(|(_, d)| d.online).map(|(m, _)| *m).collect(), l.devices.keys().copied().collect())
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
    fn judge_radios(&mut self, now: Ts, radios: HashMap<(Mac, String), RadioHealth>, online: &HashSet<Mac>, known: &HashSet<Mac>) {
        let mut judged: HashSet<OpenKey> = HashSet::new();
        for ((mac, radio), h) in radios {
            if !online.contains(&mac) {
                continue;
            }
            for (key, value, raise_at, clear_at, what) in radio_checks(&h) {
                let k = (key, Entity::Radio(mac, radio.clone()));
                let Some(v) = value else {
                    // Retries are not judged on a radio carrying little traffic, but
                    // it still reports: an alert open for it stays as it is.
                    if key == Key::HighRetries && h.retries_reported {
                        judged.insert(k);
                    }
                    continue;
                };
                if v >= raise_at && !self.book.open.contains_key(&k) && self.cleared.get(&k).is_none_or(|t| !(0..HEALTH_COOLDOWN).contains(&(now - t))) {
                    let name = crate::insights::ap_name(&self.live.read().unwrap(), &mac.to_string()).unwrap_or_else(|| mac.to_string());
                    let title = format!("High {what} on {name} {}", band_name(&radio));
                    let message = format!("{what} has averaged {v:.0}% over the last 15 minutes (alert at {raise_at:.0}%).");
                    let tag = format!("health:{}:{}", key.as_str(), k.1);
                    self.book.open(now, Alert::new(key, Category::Health, Severity::Medium, k.1.clone(), title, message).link(format!("/devices/{mac}")).tagged(tag));
                } else if v < clear_at && self.book.resolve(now, &k, || format!("Back to normal: {what} {v:.0}%.")).is_some() {
                    self.cleared.insert(k.clone(), now);
                }
                judged.insert(k);
            }
        }
        for k in stale_health(&self.book.open, &judged, &mut self.unjudged, known) {
            if self.book.resolve(now, &k, || "No longer reported: the radio or its AP stopped reporting.".into()).is_some() {
                self.cleared.insert(k, now);
            }
        }
    }

    /// Raises an alert when at least three clients failed every connection
    /// attempt in the window; clears it when none did.
    fn judge_connections(&mut self, now: Ts, failing: usize) {
        let k = (Key::ConnectFailures, Entity::Site);
        if failing >= 3 && !self.book.open.contains_key(&k) && self.cleared.get(&k).is_none_or(|t| !(0..HEALTH_COOLDOWN).contains(&(now - t))) {
            let message = "Every connection attempt these clients made in the last 15 minutes failed.".into();
            let a = Alert::new(Key::ConnectFailures, Category::Health, Severity::Medium, Entity::Site, format!("{failing} clients can't connect"), message);
            self.book.open(now, a.link("/clients?tab=attempts").tagged("health:connect_failures"));
        } else if failing == 0 && self.book.resolve(now, &k, || "Clients are connecting again.".into()).is_some() {
            self.cleared.insert(k, now);
        }
    }
}

/// Starts the alert watcher, fed by the engine through `events` (see [`channel`]).
pub fn spawn(store: Arc<Store>, writer: Writer, live: SharedLive, tx: broadcast::Sender<LiveMsg>, mut events: mpsc::Receiver<Event>) {
    tokio::spawn(async move {
        let mut w = Watcher::start(store, writer, live, tx, clock::now_ts()).await;
        // Give APs a chance to report after a restart before judging them.
        let mut status = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(90), Duration::from_secs(30));
        let mut health = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(120), Duration::from_secs(60));
        loop {
            // Events wait in the channel while a check runs.
            tokio::select! {
                e = events.recv() => match e {
                    Some(e) => w.event(clock::now_ts(), &e),
                    None => return,
                },
                _ = status.tick() => w.status_tick(clock::now_ts()),
                _ = health.tick() => w.health_tick(clock::now_ts()).await,
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
        let ap: Mac = "78:45:58:3c:52:bc".parse().unwrap();
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
        let aa: Mac = "02:00:00:00:00:aa".parse().unwrap();
        let name = |m: Mac| if m == aa { "Garage".to_string() } else { m.to_string() };
        let t = from_event(EventKind::NetworkThreat, Some(aa), &json!({ "kind": "impersonation", "severity": "high", "bssid": "02:00:00:00:00:01", "essid": "Home", "detail": "x" }), &name).unwrap();
        assert_eq!((t.category, t.severity, t.title.as_str()), (Category::Security, Severity::High, "Suspicious network: \"Home\""));
        assert_eq!((t.entity.to_string().as_str(), t.tag.as_str(), t.link.as_deref()), ("impersonation/02:00:00:00:00:01", "threat:impersonation:02:00:00:00:00:01", Some("/radios?tab=rogue")));
        let j = json!(t);
        assert_eq!((j["category"].as_str(), j["severity"].as_str()), (Some("security"), Some("high")), "named as before");
        assert!(from_event(EventKind::NetworkThreat, Some(aa), &json!({ "severity": "low" }), &name).is_none(), "low findings only show in the list");
        let r = from_event(EventKind::ApRestarted, Some(aa), &json!({ "uptime": 7200 }), &name).unwrap();
        assert_eq!((r.title.as_str(), r.message.as_str()), ("Garage restarted", "It had been up for 2.0 h."));
        assert_eq!((r.link.as_deref(), r.tag.as_str()), (Some("/devices/02:00:00:00:00:aa"), "restart:02:00:00:00:00:aa"));
        let u = from_event(EventKind::ApUpgraded, Some(aa), &json!({ "to": "8.8.12" }), &name).unwrap();
        assert_eq!((u.link.as_deref(), u.tag.as_str(), u.severity), (Some("/config?tab=firmware"), "upgrade:02:00:00:00:00:aa", Severity::Info));
        assert!(from_event(EventKind::ClientConnected, Some(aa), &json!({}), &name).is_none());
        // Exactly the kinds the engine passes on can make an alert.
        for &kind in EventKind::ALL {
            assert_eq!(from_event(kind, Some(aa), &json!({ "severity": "high" }), &name).is_some(), alertable(kind), "{kind}");
        }
        // An AP's alert needs the AP: a crash line from anyone else makes none.
        let panic = json!({ "kind": "kernel panic", "lines": ["Kernel panic"] });
        assert!(from_event(EventKind::ApCrash, None, &panic, &name).is_none());
        assert_eq!(from_event(EventKind::ApCrash, Some(aa), &panic, &name).unwrap().title, "Garage: kernel panic");
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
    fn told(rx: &mut broadcast::Receiver<LiveMsg>) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        while let Ok(LiveMsg::Alert(m)) = rx.try_recv() {
            out.push((m.action, m.alert.key.as_str()));
        }
        out
    }

    #[tokio::test]
    async fn events_reach_the_watcher_on_their_own_channel() {
        let (sink, mut events) = channel();
        let ev = |kind| Event { ts: 0, kind, device_mac: "02:00:00:00:00:01".parse().ok(), client_mac: None, data: json!({ "uptime": 60 }) };
        // Only what may make an alert is passed on.
        sink.offer(ev(EventKind::ClientConnected));
        sink.offer(ev(EventKind::ApRestarted));
        let e = events.recv().await.unwrap();
        assert_eq!(e.kind, EventKind::ApRestarted);
        assert!(events.try_recv().is_err());
        // A full queue drops and counts.
        for _ in 0..QUEUE + 3 {
            sink.offer(ev(EventKind::ApRestarted));
        }
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 3);
        let (mut w, mut rx) = watcher();
        w.event(100, &e);
        assert_eq!(told(&mut rx), [("raised", "ap_restarted")]);
        assert!(w.book.open.is_empty(), "a one-off notice, raised resolved");
    }

    #[tokio::test]
    async fn alert_ids_are_never_reused_and_list_newest_first() {
        let (mut w, _rx) = watcher();
        let notice = || Alert::new(Key::ApRestarted, Category::Changes, Severity::Low, Entity::Ap("02:00:00:00:00:aa".parse().unwrap()), "t".into(), "m".into());
        for _ in 0..11 {
            w.book.raise(1000, notice());
        }
        assert!(w.book.writer.flush(Duration::from_secs(5)));
        // A restart within the same second carries on from the stored ids.
        let mut again = Watcher::start(w.store.clone(), w.book.writer.clone(), Default::default(), broadcast::channel(4).0, 2000).await;
        let last = again.book.raise(1000, notice());
        assert_eq!(last.id, "1000-12");
        assert!(w.book.writer.flush(Duration::from_secs(5)));
        let ids: Vec<String> = w.store.read(Db::Config, |c| Ok(c.prepare(LIST)?.query_map([100], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?)).unwrap();
        assert_eq!(ids.len(), 12, "none overwritten");
        assert_eq!((ids[0].as_str(), ids[1].as_str(), ids[2].as_str()), ("1000-12", "1000-11", "1000-10"));
    }

    #[tokio::test]
    async fn a_restart_keeps_the_offline_alerts_of_the_day() {
        let (mut w, _rx) = watcher();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let offline = |severity| Alert::for_device(Key::ApOffline, Category::ApStatus, severity, ap, "t".into(), "m".into());
        // Two drops reported, the AP back after each.
        w.book.raise(1000, offline(Severity::High).resolved(1060));
        w.book.raise(2000, offline(Severity::High).resolved(2100));
        assert!(w.book.writer.flush(Duration::from_secs(5)));
        let restart = |now| Watcher::start(w.store.clone(), w.book.writer.clone(), Default::default(), broadcast::channel(4).0, now);
        // The third drop is summarised, as without the restart.
        let mut again = restart(3000).await;
        assert_eq!(again.aps.check(3000, ap, 2700), Some(ApChange::Flapping { times: 3 }));
        again.book.raise(3000, offline(Severity::Medium).resolved(3100));
        assert!(w.book.writer.flush(Duration::from_secs(5)));
        // The fourth is not reported, even after another restart.
        assert_eq!(restart(4000).await.aps.check(4000, ap, 3700), None);
        // A day after the first two, a drop is reported again.
        assert!(matches!(restart(91_000).await.aps.check(91_000, ap, 90_700), Some(ApChange::Offline { .. })));
    }

    #[tokio::test]
    async fn connection_failures_open_once_and_clear() {
        let (mut w, mut rx) = watcher();
        w.judge_connections(1000, 2);
        assert!(told(&mut rx).is_empty(), "two clients are not enough");
        w.judge_connections(1000, 3);
        w.judge_connections(1060, 5);
        assert_eq!(told(&mut rx), [("raised", "connect_failures")]);
        w.judge_connections(1120, 1);
        assert!(told(&mut rx).is_empty(), "cleared only when nobody fails");
        w.judge_connections(1180, 0);
        assert_eq!(told(&mut rx), [("resolved", "connect_failures")]);
        // Stored as the live view showed it.
        assert!(w.book.writer.flush(std::time::Duration::from_secs(5)));
        let stored: String = w.store.read(Db::Config, |c| Ok(c.query_row("SELECT message FROM alerts WHERE resolved_ts = 1180", [], |r| r.get(0))?)).unwrap();
        assert_eq!(stored, "Clients are connecting again.");
        // Not again within the cooldown.
        w.judge_connections(1240, 9);
        assert!(told(&mut rx).is_empty());
        w.judge_connections(1180 + HEALTH_COOLDOWN, 9);
        assert_eq!(told(&mut rx), [("raised", "connect_failures")]);
        // After the clock steps back, the cooldown does not last until it catches up.
        w.judge_connections(30_000, 0);
        w.judge_connections(29_000, 9);
        assert_eq!(told(&mut rx), [("resolved", "connect_failures"), ("raised", "connect_failures")]);
    }

    #[tokio::test]
    async fn radio_thresholds_raise_and_clear() {
        let (mut w, mut rx) = watcher();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let set: HashSet<Mac> = [ap].into();
        let busy = |cu| HashMap::from([((ap, "na".to_string()), RadioHealth { utilisation: Some(cu), ..Default::default() })]);
        w.judge_radios(1000, busy(85.0), &HashSet::new(), &set);
        assert!(told(&mut rx).is_empty(), "offline APs are not judged");
        w.judge_radios(1000, busy(85.0), &set, &set);
        let a = &w.book.open[&(Key::BusyChannel, Entity::Radio(ap, "na".into()))];
        assert_eq!((a.category, a.tag.as_str(), a.link.as_deref()), (Category::Health, "health:busy_channel:02:00:00:00:00:01/na", Some("/devices/02:00:00:00:00:01")));
        w.judge_radios(1060, busy(75.0), &set, &set);
        assert_eq!(told(&mut rx), [("raised", "busy_channel")], "75% is between the two thresholds");
        w.judge_radios(1120, busy(65.0), &set, &set);
        assert_eq!(told(&mut rx), [("resolved", "busy_channel")]);
    }

    #[tokio::test]
    async fn a_retries_alert_stays_open_while_its_radio_is_quiet() {
        let (mut w, mut rx) = watcher();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let set: HashSet<Mac> = [ap].into();
        let radio = |retry_pct, attempts| HashMap::from([((ap, "na".to_string()), RadioHealth { retries_reported: true, retry_pct: Some(retry_pct), attempts, ..Default::default() })]);
        w.judge_radios(1000, radio(40.0, 5000.0), &set, &set);
        assert_eq!(told(&mut rx), [("raised", "high_retries")]);
        // Too little traffic to judge, for longer than a radio that stopped reporting gets.
        for i in 1..=HEALTH_STALE_CHECKS as Ts + 1 {
            w.judge_radios(1000 + 60 * i, radio(40.0, 100.0), &set, &set);
        }
        assert!(told(&mut rx).is_empty(), "the radio still reports");
        assert!(w.book.open.contains_key(&(Key::HighRetries, Entity::Radio(ap, "na".into()))));
        w.judge_radios(2200, radio(5.0, 5000.0), &set, &set);
        assert_eq!(told(&mut rx), [("resolved", "high_retries")]);
    }

    #[test]
    fn health_alerts_close_when_their_radio_stops_reporting() {
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let k = (Key::BusyChannel, Entity::Radio(ap, "na".into()));
        let book: HashMap<OpenKey, Alert> = [
            (k.clone(), Alert::new(Key::BusyChannel, Category::Health, Severity::Medium, k.1.clone(), "t".into(), "m".into())),
            ((Key::ConnectFailures, Entity::Site), Alert::new(Key::ConnectFailures, Category::Health, Severity::Medium, Entity::Site, "t".into(), "m".into())),
        ]
        .into();
        let known: HashSet<Mac> = [ap].into();
        let mut unjudged = HashMap::new();
        let judged: HashSet<OpenKey> = [k.clone()].into();
        assert!(stale_health(&book, &judged, &mut unjudged, &known).is_empty(), "judged this time");
        for _ in 1..HEALTH_STALE_CHECKS {
            assert!(stale_health(&book, &HashSet::new(), &mut unjudged, &known).is_empty());
        }
        assert_eq!(stale_health(&book, &HashSet::new(), &mut unjudged, &known), vec![k.clone()]);
        // An AP that is gone closes at once; the site-wide alert is never stale.
        assert_eq!(stale_health(&book, &HashSet::new(), &mut HashMap::new(), &HashSet::new()), vec![k]);
    }

    #[tokio::test]
    async fn open_alerts_are_stored_as_text_and_read_back() {
        let (mut w, _rx) = watcher();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let set: HashSet<Mac> = [ap].into();
        w.judge_radios(1000, HashMap::from([((ap, "na".to_string()), RadioHealth { utilisation: Some(90.0), ..Default::default() })]), &set, &set);
        w.judge_connections(1000, 5);
        w.book.writer.exec(Db::Config, "INSERT INTO alerts (id, ts, key, category, severity, entity, title, message, tag) VALUES ('1-99', 1, 'gone', 'health', 'low', 'x', 't', 'm', 'g')", vec![]);
        assert!(w.book.writer.flush(Duration::from_secs(5)));
        let stored: Vec<(String, String)> = w.store.read(Db::Config, |c| Ok(c.prepare("SELECT key, entity FROM alerts WHERE key != 'gone' ORDER BY key")?.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?)).unwrap();
        assert_eq!(stored, [("busy_channel".to_string(), "02:00:00:00:00:01/na".to_string()), ("connect_failures".to_string(), "site".to_string())]);
        // After a restart they are open as they were; one apctl doesn't know is left alone.
        let again = Watcher::start(w.store.clone(), w.book.writer.clone(), Default::default(), broadcast::channel(4).0, 2000).await;
        let mut open: Vec<String> = again.book.open.keys().map(|(k, e)| format!("{}:{e}", k.as_str())).collect();
        open.sort();
        assert_eq!(open, ["busy_channel:02:00:00:00:00:01/na", "connect_failures:site"]);
        assert_eq!(again.book.seq, 99);
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
        let judged = |radio: &str| h.get(&("02:00:00:00:00:01".parse().unwrap(), radio.to_string())).and_then(|h| h.utilisation);
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
