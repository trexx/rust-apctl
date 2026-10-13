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
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use rusqlite::types::Value as Sql;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::api::{ApiError, AppState};
use crate::engine::{LiveMsg, SharedLive};
use crate::model::Ts;
use crate::store::{self, Db, Store, Writer};

/// An AP is offline after this long without contact.
pub const OFFLINE_AFTER: Ts = 240;
/// How long a Wi-Fi health condition must hold.
const HEALTH_WINDOW: Ts = 900;
/// The same health alert is not raised again sooner than this after it cleared.
const HEALTH_COOLDOWN: Ts = 6 * 3600;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Alert {
    pub id: String,
    pub ts: Ts,
    /// e.g. `ap_offline`, `high_retries`.
    pub key: String,
    /// `ap_status`, `security`, `health` or `changes`.
    pub category: &'static str,
    /// `high`, `medium`, `low` or `info`.
    pub severity: &'static str,
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
                Sql::Text(a.category.into()),
                Sql::Text(a.severity.into()),
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
        self.writer.exec(Db::Config, "UPDATE alerts SET resolved_ts = ?2 WHERE id = ?1", vec![Sql::Text(a.id.clone()), Sql::Integer(now)]);
        let _ = self.tx.send(LiveMsg::Alert(AlertMsg { action: "resolved", alert: a.clone() }));
        Some(a)
    }
}

#[allow(clippy::too_many_arguments)] // a plain constructor; named fields would only add noise at the call sites
fn alert(key: &str, category: &'static str, severity: &'static str, entity: &str, title: String, message: String, link: Option<String>, tag: String) -> Alert {
    Alert { id: String::new(), ts: 0, key: key.into(), category, severity, entity: entity.into(), title, message, link, tag, resolved_ts: None }
}

fn band_name(radio: &str) -> &str {
    match radio {
        "ng" => "2.4 GHz",
        "na" => "5 GHz",
        "6e" => "6 GHz",
        r => r,
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

/// An alert for an event, if the event deserves one.
fn from_event(kind: &str, device: Option<&str>, data: &Value, ap_name: &dyn Fn(&str) -> String) -> Option<Alert> {
    let dev = device.unwrap_or_default();
    let name = ap_name(dev);
    let link = (!dev.is_empty()).then(|| format!("/devices/{dev}"));
    let s = |k: &str| data[k].as_str().unwrap_or_default().to_string();
    Some(match kind {
        "network_threat" => {
            let sev = match data["severity"].as_str() {
                Some("high") => "high",
                Some("medium") => "medium",
                _ => return None,
            };
            let essid = data["essid"].as_str().map_or("A hidden network".to_string(), |e| format!("\"{e}\""));
            alert(
                "suspicious_network",
                "security",
                sev,
                &format!("{}/{}", s("kind"), s("bssid")),
                format!("Suspicious network: {essid}"),
                s("detail"),
                Some("/radios?tab=rogue".into()),
                format!("threat:{}:{}", s("kind"), s("bssid")),
            )
        }
        "ap_restarted" => alert(
            "ap_restarted",
            "changes",
            "low",
            dev,
            format!("{name} restarted"),
            format!("It had been up for {}.", human(data["uptime"].as_i64().unwrap_or(0))),
            link,
            format!("restart:{dev}"),
        ),
        "ap_firmware_changed" => alert(
            "ap_firmware_changed",
            "changes",
            "info",
            dev,
            format!("{name} firmware changed"),
            format!("{} → {}", s("from"), s("to")),
            link,
            format!("firmware:{dev}"),
        ),
        "dfs_radar" => alert(
            "dfs_radar",
            "changes",
            "low",
            dev,
            format!("Radar detected by {name}"),
            match data["channel"].as_i64() {
                Some(c) => format!("Channel {c} had to be vacated (DFS); the AP moved to another channel."),
                None => "A DFS channel had to be vacated; the AP moved to another channel.".into(),
            },
            link,
            format!("radar:{dev}"),
        ),
        "ap_isolated" => alert(
            "ap_isolated",
            "ap_status",
            "high",
            dev,
            format!("{name} is isolated"),
            "Its beacon says it has lost its uplink; clients on it may have no network.".into(),
            link,
            format!("ap-status:{dev}"),
        ),
        "ap_crash" => alert(
            "ap_crash",
            "changes",
            "medium",
            dev,
            match data["process"].as_str() {
                Some(p) => format!("{p} crashed on {name}"),
                None => format!("{name}: {}", data["kind"].as_str().unwrap_or("crash")),
            },
            data["lines"].as_array().and_then(|l| l.first()).and_then(Value::as_str).unwrap_or("See the event for details.").to_string(),
            link,
            format!("crash:{dev}"),
        ),
        "ap_process_restarted" => alert(
            "ap_process_restarted",
            "changes",
            "low",
            dev,
            format!("{} restarted on {name}", data["proc"].as_str().unwrap_or("A process")),
            format!("It exited with code {} and was restarted by {}.", data["exit_status"], data["caller"].as_str().unwrap_or("the system")),
            link,
            format!("proc:{dev}"),
        ),
        "ap_upgrade_failed" => alert(
            "ap_upgrade_failed",
            "changes",
            "medium",
            dev,
            format!("{name} firmware update failed"),
            data["detail"].as_str().unwrap_or("The update did not complete.").to_string(),
            Some("/config?tab=firmware".into()),
            format!("upgrade:{dev}"),
        ),
        "ap_upgraded" => alert(
            "ap_upgraded",
            "changes",
            "info",
            dev,
            format!("{name} updated to {}", data["to"].as_str().unwrap_or("new firmware")),
            format!("From {}.", data["from"].as_str().unwrap_or("the previous version")),
            Some("/config?tab=firmware".into()),
            format!("upgrade:{dev}"),
        ),
        "config_applied" => alert(
            "config_applied",
            "changes",
            "info",
            dev,
            format!("New settings applied on {name}"),
            "The AP applied a configuration change.".into(),
            Some("/config".into()),
            format!("config:{dev}"),
        ),
        _ => return None,
    })
}

/// Health figures for one AP radio over the last window.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RadioHealth {
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
            let mut stmt = c.prepare("SELECT mac, radio, AVG(cu_total), AVG(cu_interf), COUNT(*) FROM radio_stats WHERE ts >= ?1 GROUP BY mac, radio")?;
            for row in stmt.query_map([from], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<f64>>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, i64>(4)?)))? {
                let (mac, radio, cu, interf, n) = row?;
                // Only judge a radio that reported through most of the window.
                if n >= 30 {
                    let h = out.entry((mac, radio)).or_default();
                    h.utilisation = cu;
                    h.interference = interf;
                }
            }
            // Retries from the SSIDs' counters: increases between consecutive samples.
            let mut stmt = c.prepare(
                "SELECT ap_mac, radio, bssid, ts, tx_retries, wifi_tx_attempts, wifi_tx_dropped FROM vap_stats WHERE ts >= ?1 ORDER BY bssid, ts",
            )?;
            let mut prev: HashMap<String, (f64, f64, f64)> = HashMap::new();
            let mut sums: HashMap<(String, String), [f64; 3]> = HashMap::new();
            for row in stmt.query_map([from - 60], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<f64>>(4)?,
                    r.get::<_, Option<f64>>(5)?,
                    r.get::<_, Option<f64>>(6)?,
                ))
            })? {
                let (ap, radio, bssid, rt, at, dr) = row?;
                let (Some(ap), Some(radio), Some(rt), Some(at)) = (ap, radio, rt, at) else { continue };
                let dr = dr.unwrap_or(0.0);
                if let Some((pr, pa, pd)) = prev.insert(bssid, (rt, at, dr)) {
                    let e = sums.entry((ap, radio)).or_default();
                    e[0] += (rt - pr).max(0.0);
                    e[1] += (at - pa).max(0.0);
                    e[2] += (dr - pd).max(0.0);
                }
            }
            for (k, [r, a, d]) in sums {
                let h = out.entry(k).or_default();
                h.attempts = a;
                if r + a + d > 0.0 {
                    h.retry_pct = Some(100.0 * r / (r + a + d));
                }
            }
            Ok(out)
        })
    })
    .await?
}

/// Clients whose every connection attempt in the window failed.
async fn failing_clients(store: &Arc<Store>, now: Ts) -> anyhow::Result<Vec<String>> {
    let store = store.clone();
    let events = tokio::task::spawn_blocking(move || {
        store.read(Db::Config, |c| {
            let mut stmt = c.prepare("SELECT ts, ap_mac, client_mac, vap, essid, radio, event_type, detail FROM connections WHERE ts >= ?1")?;
            let rows = stmt
                .query_map([now - HEALTH_WINDOW], |r| {
                    let detail: Option<String> = r.get(7)?;
                    Ok(crate::connections::ConnEvent {
                        ts: r.get(0)?,
                        ap: r.get(1)?,
                        client: r.get(2)?,
                        vap: r.get(3)?,
                        essid: r.get(4)?,
                        radio: r.get(5)?,
                        event_type: r.get(6)?,
                        n: detail.and_then(|d| serde_json::from_str(&d).ok()).unwrap_or(Value::Null),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    })
    .await??;
    let attempts = crate::connections::attempts(events);
    let ok: HashSet<&str> = attempts.iter().filter(|a| a.success).map(|a| a.client.as_str()).collect();
    let mut failing: Vec<String> = attempts.iter().filter(|a| !a.success && !ok.contains(a.client.as_str())).map(|a| a.client.clone()).collect();
    failing.sort();
    failing.dedup();
    Ok(failing)
}

/// Starts the alert watcher.
pub fn spawn(store: Arc<Store>, writer: Writer, live: SharedLive, tx: broadcast::Sender<LiveMsg>) {
    let mut events = tx.subscribe();
    tokio::spawn(async move {
        let mut book = Alerts { writer, tx, seq: 0, open: HashMap::new() };
        // Alerts left open by a previous run.
        if let Ok(open) = store.read(Db::Config, |c| {
            let mut stmt = c.prepare("SELECT id, ts, key, category, severity, entity, title, message, link, tag FROM alerts WHERE resolved_ts IS NULL")?;
            let rows = stmt
                .query_map([], |r| {
                    let cat: String = r.get(3)?;
                    let sev: String = r.get(4)?;
                    Ok(Alert {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        key: r.get(2)?,
                        category: ["ap_status", "security", "health", "changes"].into_iter().find(|x| *x == cat).unwrap_or("changes"),
                        severity: ["high", "medium", "low", "info"].into_iter().find(|x| *x == sev).unwrap_or("info"),
                        entity: r.get(5)?,
                        title: r.get(6)?,
                        message: r.get(7)?,
                        link: r.get(8)?,
                        tag: r.get(9)?,
                        resolved_ts: None,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        }) {
            for a in open {
                book.open.insert((a.key.clone(), a.entity.clone()), a);
            }
        }
        let mut aps = ApWatch::default();
        // An AP already reported offline before a restart stays so.
        for ((key, mac), a) in &book.open {
            if key == "ap_offline" {
                aps.down.insert(mac.clone(), a.ts - OFFLINE_AFTER);
                aps.sent.entry(mac.clone()).or_default().push(a.ts);
            }
        }
        let mut cleared: HashMap<(String, String), Ts> = HashMap::new();
        // Give APs a chance to report after a restart before judging them.
        let mut status = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(90), Duration::from_secs(30));
        let mut health = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(120), Duration::from_secs(60));
        loop {
            tokio::select! {
                msg = events.recv() => match msg {
                    Ok(LiveMsg::Event(e)) => {
                        let names = ap_names(&live);
                        let name = |m: &str| names.get(m).cloned().unwrap_or_else(|| m.to_string());
                        if let Some(a) = from_event(e.kind, e.device_mac.map(|m| m.to_string()).as_deref(), &e.data, &name) {
                            let resolved = Alert { resolved_ts: Some(store::now_ts()), ..a };
                            book.raise(store::now_ts(), resolved);
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = status.tick() => {
                    let now = store::now_ts();
                    let seen: Vec<(String, Option<String>, Ts)> = {
                        let l = live.read().unwrap();
                        let mut v: Vec<_> = l.devices.iter().map(|(m, d)| (m.to_string(), d.snapshot.ap.hostname.clone(), d.last_seen)).collect();
                        for (m, k) in &l.known_devices {
                            if !l.devices.contains_key(m) {
                                v.push((m.to_string(), None, k.last_seen));
                            }
                        }
                        v
                    };
                    for (mac, name, last_seen) in seen {
                        let name = name.unwrap_or_else(|| mac.clone());
                        let tag = format!("ap-status:{mac}");
                        let link = Some(format!("/devices/{mac}"));
                        match aps.check(now, &mac, last_seen) {
                            Some(ApChange::Offline { last_seen }) => book.open(now, alert(
                                "ap_offline", "ap_status", "high", &mac,
                                format!("{name} is offline"),
                                format!("No contact for {} (last seen {}).", human(now - last_seen), clock(last_seen)),
                                link, tag,
                            )),
                            Some(ApChange::Flapping { times }) => book.open(now, alert(
                                "ap_offline", "ap_status", "medium", &mac,
                                format!("{name} keeps dropping off"),
                                format!("Offline {times} times in the last day; further drops today are not reported separately."),
                                link, tag,
                            )),
                            Some(ApChange::Online { down_for, alerted }) => {
                                let note = format!("Back after {}.", human(down_for));
                                if book.resolve(now, "ap_offline", &mac, Some(note.clone())).is_some() || alerted {
                                    let back = alert("ap_online", "ap_status", "low", &mac, format!("{name} is back online"), note, link, tag);
                                    book.raise(now, Alert { resolved_ts: Some(now), ..back });
                                }
                            }
                            None => {}
                        }
                    }
                }
                _ = health.tick() => {
                    let now = store::now_ts();
                    let names = ap_names(&live);
                    let online: HashSet<String> = live.read().unwrap().devices.iter().filter(|(_, d)| d.online).map(|(m, _)| m.to_string()).collect();
                    match radio_health(&store, now).await {
                        Ok(radios) => {
                            for ((mac, radio), h) in radios {
                                if !online.contains(&mac) {
                                    continue;
                                }
                                let name = names.get(&mac).cloned().unwrap_or_else(|| mac.clone());
                                for (key, value, raise_at, clear_at, what) in radio_checks(&h) {
                                    let entity = format!("{mac}/{radio}");
                                    let k = (key.to_string(), entity.clone());
                                    let Some(v) = value else { continue };
                                    if v >= raise_at && !book.open.contains_key(&k) && cleared.get(&k).is_none_or(|t| now - t >= HEALTH_COOLDOWN) {
                                        book.open(now, alert(
                                            key, "health", "medium", &entity,
                                            format!("High {what} on {name} {}", band_name(&radio)),
                                            format!("{what} has averaged {v:.0}% over the last 15 minutes (alert at {raise_at:.0}%)."),
                                            Some(format!("/devices/{mac}")), format!("health:{key}:{entity}"),
                                        ));
                                    } else if v < clear_at && book.resolve(now, key, &entity, Some(format!("Back to normal: {what} {v:.0}%."))).is_some() {
                                        cleared.insert(k, now);
                                    }
                                }
                            }
                        }
                        Err(e) => tracing::warn!("radio health check failed: {e:#}"),
                    }
                    match failing_clients(&store, now).await {
                        Ok(failing) => {
                            let k = ("connect_failures".to_string(), "site".to_string());
                            if failing.len() >= 3 && !book.open.contains_key(&k) && cleared.get(&k).is_none_or(|t| now - t >= HEALTH_COOLDOWN) {
                                book.open(now, alert(
                                    "connect_failures", "health", "medium", "site",
                                    format!("{} clients can't connect", failing.len()),
                                    "Every connection attempt these clients made in the last 15 minutes failed.".into(),
                                    Some("/clients?tab=attempts".into()), "health:connect_failures".into(),
                                ));
                            } else if failing.is_empty() && book.resolve(now, "connect_failures", "site", Some("Clients are connecting again.".into())).is_some() {
                                cleared.insert(k, now);
                            }
                        }
                        Err(e) => tracing::warn!("connection health check failed: {e:#}"),
                    }
                }
            }
        }
    });
}

fn ap_names(live: &SharedLive) -> HashMap<String, String> {
    let l = live.read().unwrap();
    l.devices.iter().filter_map(|(m, d)| d.snapshot.ap.hostname.clone().map(|n| (m.to_string(), n))).collect()
}

fn clock(ts: Ts) -> String {
    let s = ts.rem_euclid(86400);
    format!("{:02}:{:02} UTC", s / 3600, (s % 3600) / 60)
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<usize>,
}

/// GET /api/alerts: recent alerts, newest first, with the unread count.
pub async fn list(State(s): State<AppState>, Query(q): Query<ListQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500) as i64;
    let rows = crate::insights::read(&s, Db::Config, move |c| {
        let mut stmt = c.prepare(
            "SELECT id, ts, key, category, severity, entity, title, message, link, tag, resolved_ts, read FROM alerts ORDER BY ts DESC, id DESC LIMIT ?1",
        )?;
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
pub async fn mark_read(State(s): State<AppState>, headers: axum::http::HeaderMap) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    s.engine
        .send(crate::engine::Input::AlertsRead)
        .await
        .map_err(|_| ApiError(axum::http::StatusCode::SERVICE_UNAVAILABLE, "engine stopped".into()))?;
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
        let t = from_event("network_threat", Some("aa"), &json!({ "kind": "impersonation", "severity": "high", "bssid": "02:00:00:00:00:01", "essid": "Home", "detail": "x" }), &name).unwrap();
        assert_eq!((t.category, t.severity, t.title.as_str()), ("security", "high", "Suspicious network: \"Home\""));
        assert!(from_event("network_threat", Some("aa"), &json!({ "severity": "low" }), &name).is_none(), "low findings only show in the list");
        let r = from_event("ap_restarted", Some("aa"), &json!({ "uptime": 7200 }), &name).unwrap();
        assert_eq!((r.title.as_str(), r.message.as_str()), ("Garage restarted", "It had been up for 2.0 h."));
        assert!(from_event("client_connected", Some("aa"), &json!({}), &name).is_none());
    }

    #[test]
    fn radio_thresholds_need_enough_traffic() {
        let quiet = RadioHealth { retry_pct: Some(60.0), attempts: 100.0, utilisation: Some(10.0), interference: None };
        let checks = radio_checks(&quiet);
        assert_eq!(checks[0].1, None, "a few retries on an idle radio are not a problem");
        let busy = RadioHealth { retry_pct: Some(30.0), attempts: 5000.0, ..quiet };
        assert_eq!(radio_checks(&busy)[0].1, Some(30.0));
    }
}
