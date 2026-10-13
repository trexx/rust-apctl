//! Turns decoded informs, controller replies and AP logs into stored metrics,
//! events and the live view the API serves.
//!
//! The engine runs as one task that owns all mutable state; the API reads a
//! shared snapshot (`Live`) and subscribes to a broadcast of changes.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use inform::Mac;
use rusqlite::types::Value as Sql;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use wire::cfgdiff;
use wire::decode::Decoded;
use wire::keys::KeyStore;

use crate::model::{self, ClientSample, Snapshot, Ts};
use crate::store::{self, Db, Write, Writer};

/// A client is considered gone once no full inform has listed it for this long.
pub const CLIENT_GRACE_SECS: Ts = 60;
/// An AP is offline after missing this many of its inform intervals.
pub const OFFLINE_INTERVALS: Ts = 4;
const DEFAULT_INTERVAL: Ts = 15;

pub enum Input {
    Inform { ts: Ts, peer: String, decoded: Decoded },
    /// Replace the imported controller settings (an `informdump import` snapshot).
    SetState { ts: Ts, state: Value },
    /// Set or clear a client's alias and note (None clears). `only_if_unset`
    /// leaves existing aliases alone (for bulk imports).
    SetAlias { ts: Ts, mac: Mac, alias: Option<String>, note: Option<String>, only_if_unset: bool },
    /// A syslog datagram from an AP (captured in shadow mode or received directly).
    Datagram { ts: Ts, src_ip: String, payload: Vec<u8> },
    Reply { ts: Ts, mac: Mac, decoded: Decoded },
    Tick(Ts),
    DecodeError,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub ts: Ts,
    pub device_mac: Option<Mac>,
    pub src_ip: String,
    pub facility: Option<i64>,
    pub severity: Option<i64>,
    pub program: Option<String>,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub ts: Ts,
    pub kind: &'static str,
    pub device_mac: Option<Mac>,
    pub client_mac: Option<Mac>,
    pub data: Value,
}

/// Messages pushed to live subscribers (the UI's WebSocket).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveMsg {
    Device { mac: Mac },
    Clients,
    Event(Event),
    Log(LogLine),
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceView {
    pub snapshot: Snapshot,
    pub online: bool,
    pub first_seen: Ts,
    pub last_seen: Ts,
    pub peer: String,
    /// Inform interval most recently requested by the controller.
    pub interval: Ts,
    /// True while the AP sends short informs (no client data) after a config
    /// push, i.e. while it applies the new configuration.
    pub reconfiguring: bool,
    /// When the current reconfiguration began.
    pub reconfiguring_since: Option<Ts>,
    /// A config application being tracked until the AP has been stable for a while.
    #[serde(skip)]
    pub applying: Option<Applying>,
    pub last_config_push: Option<Ts>,
}

/// One config application: an AP may alternate short and full informs for a
/// while (e.g. several bursts during a channel change), so it is reported once,
/// after the AP has been stable for `APPLY_SETTLE_SECS`.
#[derive(Debug, Clone)]
pub struct Applying {
    since: Ts,
    /// First full inform after the last short one.
    returned: Option<Ts>,
    /// Clients connected to the AP when the application began.
    before: Vec<Mac>,
}

pub const APPLY_SETTLE_SECS: Ts = 30;

#[derive(Debug, Clone, Serialize)]
pub struct ClientView {
    pub sample: ClientSample,
    pub connected: bool,
    pub first_seen: Ts,
    pub last_seen: Ts,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Counters {
    pub informs: u64,
    pub log_errors: u64,
    pub replies: u64,
    pub config_pushes: u64,
    pub decode_errors: u64,
    pub logs: u64,
    pub events: u64,
}

/// A name and note the user gave a client.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Alias {
    pub alias: Option<String>,
    pub note: Option<String>,
}

#[derive(Default, Serialize)]
pub struct Live {
    pub devices: BTreeMap<Mac, DeviceView>,
    /// User-given client names, including clients not seen in this run.
    pub aliases: HashMap<Mac, Alias>,
    pub clients: BTreeMap<Mac, ClientView>,
    pub counters: Counters,
    /// For attributing syslog: an AP's `hash_id` and IP address.
    #[serde(skip)]
    pub by_hash_id: HashMap<String, Mac>,
    #[serde(skip)]
    pub by_ip: HashMap<String, Mac>,
    /// APs known from the database before their first inform in this process.
    #[serde(skip)]
    pub known_devices: HashMap<Mac, KnownDevice>,
    /// Imported controller settings (contain secrets: never serialised).
    #[serde(skip)]
    pub state: Option<Arc<Value>>,
    #[serde(skip)]
    pub state_imported_at: Option<Ts>,
    /// Latest full inform per AP (capabilities and radios, for rendering).
    #[serde(skip)]
    pub raw_informs: HashMap<Mac, Arc<Value>>,
    /// Last config pushed to each AP by the other controller, unredacted.
    #[serde(skip)]
    pub last_config: HashMap<Mac, (String, String, Option<String>)>,
}

/// What the database remembers about an AP from a previous run.
#[derive(Debug, Clone)]
pub struct KnownDevice {
    pub first_seen: Ts,
    pub last_seen: Ts,
    pub uptime: Option<i64>,
    pub version: Option<String>,
}

pub type SharedLive = Arc<RwLock<Live>>;

/// Channel, width and power of one radio.
type RadioSettings = (Option<i64>, Option<i64>, Option<i64>);

#[derive(Default)]
struct RadioTrack {
    committed: Option<RadioSettings>,
    /// Differing settings seen once; committed when the next full inform agrees.
    candidate: Option<RadioSettings>,
}

pub struct Engine {
    writer: Writer,
    keys: Arc<KeyStore>,
    renderer: Option<crate::dryrun::RenderFn>,
    live: SharedLive,
    tx: broadcast::Sender<LiveMsg>,
    /// Full (unredacted) last config per AP, for diffs. Only kept in memory.
    configs: HashMap<Mac, HashMap<&'static str, String>>,
    /// Debounced radio settings: right after a restart an AP briefly reports
    /// transient values (e.g. full transmit power) before settling.
    radios: HashMap<(Mac, String), RadioTrack>,
}

impl Engine {
    pub fn new(writer: Writer, keys: Arc<KeyStore>, live: SharedLive, tx: broadcast::Sender<LiveMsg>) -> Self {
        Engine { writer, keys, renderer: None, live, tx, configs: HashMap::new(), radios: HashMap::new() }
    }

    /// Enables dry-run comparisons of every captured config push.
    pub fn set_renderer(&mut self, renderer: crate::dryrun::RenderFn) {
        self.renderer = Some(renderer);
    }

    /// Loads APs and clients remembered from previous runs, so a restart does
    /// not report every client as newly connected.
    pub fn restore(&mut self, store: &store::Store) -> anyhow::Result<()> {
        let (devices, clients, aliases, state) = store.read(Db::Config, |c| {
            let mut stmt = c.prepare("SELECT mac, first_seen, last_seen, uptime, version, hash_id, ip FROM devices")?;
            let devices = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        KnownDevice { first_seen: r.get::<_, Option<i64>>(1)?.unwrap_or(0), last_seen: r.get::<_, Option<i64>>(2)?.unwrap_or(0), uptime: r.get(3)?, version: r.get(4)? },
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut stmt = c.prepare("SELECT mac, hostname, ip, first_seen, last_seen, ap_mac, bssid, essid, radio, connected FROM clients")?;
            let clients = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<i64>>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?, r.get::<_, Option<String>>(7)?, r.get::<_, Option<String>>(8)?,
                        r.get::<_, i64>(9)? != 0,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let state: Option<(String, i64)> = c
                .query_row("SELECT json, imported_at FROM controller_state WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
                .ok();
            let mut stmt = c.prepare("SELECT mac, alias, note FROM client_aliases")?;
            let aliases = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, Alias { alias: r.get(1)?, note: r.get(2)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((devices, clients, aliases, state))
        })?;
        let mut live = self.live.write().unwrap();
        for (mac, known, hash_id, ip) in devices {
            let Ok(mac) = mac.parse::<Mac>() else { continue };
            if let Some(h) = hash_id {
                live.by_hash_id.insert(h, mac);
            }
            if let Some(ip) = ip {
                live.by_ip.insert(ip, mac);
            }
            live.known_devices.insert(mac, known);
        }
        let n_clients = clients.len();
        for (mac, hostname, ip, first_seen, last_seen, ap_mac, bssid, essid, radio, connected) in clients {
            let (Ok(mac), Some(Ok(ap_mac))) = (mac.parse::<Mac>(), ap_mac.map(|a| a.parse::<Mac>())) else { continue };
            let sample = ClientSample { mac, ap_mac, bssid: bssid.unwrap_or_default(), essid, radio, hostname, ip, ..Default::default() };
            live.clients.insert(mac, ClientView { sample, connected, first_seen: first_seen.unwrap_or(0), last_seen: last_seen.unwrap_or(0) });
        }
        if let Some((json, at)) = state {
            match serde_json::from_str::<Value>(&json) {
                Ok(v) => {
                    live.state = Some(Arc::new(v));
                    live.state_imported_at = Some(at);
                }
                Err(e) => tracing::warn!("stored controller settings are unreadable: {e}"),
            }
        }
        for (mac, alias) in aliases {
            if let Ok(mac) = mac.parse::<Mac>() {
                live.aliases.insert(mac, alias);
            }
        }
        tracing::info!(
            "restored {} APs, {n_clients} clients and {} aliases from the database",
            live.known_devices.len(),
            live.aliases.len()
        );
        Ok(())
    }

    pub fn handle(&mut self, input: Input) {
        match input {
            Input::Inform { ts, peer, decoded } => self.inform(ts, peer, decoded),
            Input::Reply { ts, mac, decoded } => self.reply(ts, mac, decoded),
            Input::Datagram { ts, src_ip, payload } => self.datagram(ts, src_ip, &payload),
            Input::Tick(now) => self.tick(now),
            Input::DecodeError => self.live.write().unwrap().counters.decode_errors += 1,
            Input::SetAlias { ts, mac, alias, note, only_if_unset } => self.set_alias(ts, mac, alias, note, only_if_unset),
            Input::SetState { ts, state } => self.set_state(ts, state),
        }
    }

    fn emit(&self, live: &mut Live, ev: Event) {
        live.counters.events += 1;
        self.writer.exec(
            Db::Config,
            "INSERT INTO events (ts, kind, device_mac, client_mac, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                Sql::Integer(ev.ts),
                Sql::Text(ev.kind.into()),
                opt_text(ev.device_mac.map(|m| m.to_string())),
                opt_text(ev.client_mac.map(|m| m.to_string())),
                Sql::Text(ev.data.to_string()),
            ],
        );
        let _ = self.tx.send(LiveMsg::Event(ev));
    }

    fn inform(&mut self, ts: Ts, peer: String, decoded: Decoded) {
        let snap = match model::parse(ts, &decoded.payload) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("unparseable inform: {e:#}");
                self.live.write().unwrap().counters.decode_errors += 1;
                return;
            }
        };
        let mac = snap.ap.mac;
        self.write_metrics(&snap);
        if snap.has_vap_table {
            self.live.write().unwrap().raw_informs.insert(mac, Arc::new(decoded.payload.clone()));
        }

        let mut live = self.live.write().unwrap();
        live.counters.informs += 1;
        if let Some(h) = &snap.ap.hash_id {
            live.by_hash_id.insert(h.clone(), mac);
        }
        if let Some(ip) = &snap.ap.ip {
            live.by_ip.insert(ip.clone(), mac);
        }

        // Device lifecycle events.
        let prev = live.devices.get(&mac).cloned();
        let mut events = Vec::new();
        let known = if prev.is_none() { live.known_devices.remove(&mac) } else { None };
        match (&prev, &known) {
            (None, None) => events.push(ev(ts, "ap_seen", Some(mac), None, json!({ "ip": snap.ap.ip, "model": snap.ap.model, "version": snap.ap.version }))),
            // Known from a previous run: only report what we can prove changed while we were away.
            (None, Some(k)) => {
                let away = ts - k.last_seen;
                if let (Some(old), Some(up)) = (k.uptime, snap.ap.uptime)
                    && up + 60 < old + away {
                        events.push(ev(ts, "ap_restarted", Some(mac), None, json!({ "uptime": up })));
                    }
                if k.version.is_some() && snap.ap.version.is_some() && k.version != snap.ap.version {
                    events.push(ev(ts, "ap_firmware_changed", Some(mac), None, json!({ "from": k.version, "to": snap.ap.version })));
                }
            }
            (Some(p), _) if !p.online => events.push(ev(ts, "ap_online", Some(mac), None, json!({ "offline_for": ts - p.last_seen }))),
            _ => {}
        }
        if let (Some(p), Some(up)) = (&prev, snap.ap.uptime) {
            if p.snapshot.ap.uptime.is_some_and(|old| up + 30 < old) {
                events.push(ev(ts, "ap_restarted", Some(mac), None, json!({ "uptime": up })));
            }
            if p.snapshot.ap.version != snap.ap.version && snap.ap.version.is_some() {
                events.push(ev(ts, "ap_firmware_changed", Some(mac), None, json!({ "from": p.snapshot.ap.version, "to": snap.ap.version })));
            }
        }
        // While an AP applies a config push it sends short informs without client
        // data. Whether clients were affected is only known once it is back:
        // clients that had to reconnect show a session shorter than the gap.
        let reconfiguring_since = match (&prev, snap.has_vap_table) {
            (_, true) => None,
            (Some(p), false) if p.reconfiguring => p.reconfiguring_since,
            _ => Some(ts),
        };
        let mut applying = prev.as_ref().and_then(|p| p.applying.clone());
        if !snap.has_vap_table {
            match &mut applying {
                Some(a) => a.returned = None, // another burst of the same application
                None => {
                    let before = live.clients.values().filter(|c| c.connected && c.sample.ap_mac == mac).map(|c| c.sample.mac).collect();
                    applying = Some(Applying { since: ts, returned: None, before });
                }
            }
        } else if let Some(a) = &mut applying {
            match a.returned {
                None => a.returned = Some(ts),
                Some(r) if ts - r >= APPLY_SETTLE_SECS => {
                    events.push(config_applied(mac, a, ts, Some(&snap.clients)));
                    applying = None;
                }
                Some(_) => {}
            }
        }
        if snap.has_vap_table {
            for r in &snap.radios {
                let now = (r.channel, r.bw, r.tx_power);
                if now.0.is_none() {
                    continue; // no VAP on this radio, so nothing to compare
                }
                let track = self.radios.entry((mac, r.radio.clone())).or_default();
                match track.committed {
                    None => track.committed = Some(now),
                    Some(c) if c == now => track.candidate = None,
                    Some(c) if track.candidate == Some(now) => {
                        track.committed = Some(now);
                        track.candidate = None;
                        events.push(ev(ts, "radio_changed", Some(mac), None, json!({
                            "radio": r.radio,
                            "from": { "channel": c.0, "bw": c.1, "tx_power": c.2 },
                            "to": { "channel": now.0, "bw": now.1, "tx_power": now.2 },
                        })));
                    }
                    Some(_) => track.candidate = Some(now),
                }
            }
        }

        let view = DeviceView {
            // Keep the last full picture while the AP is reconfiguring.
            snapshot: match (&prev, snap.has_vap_table) {
                (Some(p), false) => Snapshot { ap: snap.ap.clone(), uplink: snap.uplink.clone().or(p.snapshot.uplink.clone()), ..p.snapshot.clone() },
                _ => snap.clone(),
            },
            online: true,
            first_seen: prev.as_ref().map(|p| p.first_seen).or(known.as_ref().map(|k| k.first_seen)).unwrap_or(ts),
            last_seen: ts,
            peer,
            interval: prev.as_ref().map_or(DEFAULT_INTERVAL, |p| p.interval),
            reconfiguring: !snap.has_vap_table,
            reconfiguring_since,
            applying,
            last_config_push: prev.as_ref().and_then(|p| p.last_config_push),
        };
        self.writer.exec(
            Db::Config,
            "INSERT INTO devices (mac, hostname, model, model_display, version, ip, serial, hash_id, first_seen, last_seen, uptime, cfgversion, online)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11, 1)
             ON CONFLICT (mac) DO UPDATE SET hostname = excluded.hostname, model = excluded.model, model_display = excluded.model_display,
               version = excluded.version, ip = excluded.ip, serial = excluded.serial, hash_id = excluded.hash_id,
               last_seen = excluded.last_seen, uptime = excluded.uptime, cfgversion = excluded.cfgversion, online = 1",
            vec![
                Sql::Text(mac.to_string()),
                opt_text(snap.ap.hostname.clone()),
                opt_text(snap.ap.model.clone()),
                opt_text(snap.ap.model_display.clone()),
                opt_text(snap.ap.version.clone()),
                opt_text(snap.ap.ip.clone()),
                opt_text(snap.ap.serial.clone()),
                opt_text(snap.ap.hash_id.clone()),
                Sql::Integer(ts),
                opt_int(snap.ap.uptime),
                opt_text(snap.ap.cfgversion.clone()),
            ],
        );
        live.devices.insert(mac, view);
        for e in events {
            self.emit(&mut live, e);
        }

        if snap.has_vap_table {
            self.update_clients(&mut live, ts, mac, &snap.clients);
        }
        drop(live);
        let _ = self.tx.send(LiveMsg::Device { mac });
    }

    fn update_clients(&self, live: &mut Live, ts: Ts, ap: Mac, clients: &[ClientSample]) {
        for c in clients {
            let mut events = Vec::new();
            match live.clients.get(&c.mac) {
                Some(prev) if prev.connected => {
                    let p = &prev.sample;
                    if p.ap_mac != c.ap_mac || p.bssid != c.bssid {
                        events.push(ev(ts, "client_roamed", Some(c.ap_mac), Some(c.mac), json!({
                            "from": { "ap": p.ap_mac, "radio": p.radio, "channel": p.channel, "essid": p.essid, "signal": p.signal },
                            "to": { "ap": c.ap_mac, "radio": c.radio, "channel": c.channel, "essid": c.essid, "signal": c.signal },
                        })));
                    }
                }
                prev => {
                    let was_known = prev.is_some();
                    events.push(ev(ts, "client_connected", Some(c.ap_mac), Some(c.mac), json!({
                        "essid": c.essid, "radio": c.radio, "channel": c.channel, "signal": c.signal,
                        "hostname": c.hostname, "ip": c.ip, "new": !was_known,
                    })));
                }
            }
            let first_seen = live.clients.get(&c.mac).map_or(ts, |p| p.first_seen);
            live.clients.insert(c.mac, ClientView { sample: c.clone(), connected: true, first_seen, last_seen: ts });
            self.writer.exec(
                Db::Config,
                "INSERT INTO clients (mac, hostname, ip, first_seen, last_seen, ap_mac, bssid, essid, radio, connected)
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7, ?8, 1)
                 ON CONFLICT (mac) DO UPDATE SET hostname = COALESCE(excluded.hostname, hostname), ip = COALESCE(excluded.ip, ip),
                   last_seen = excluded.last_seen, ap_mac = excluded.ap_mac, bssid = excluded.bssid, essid = excluded.essid,
                   radio = excluded.radio, connected = 1",
                vec![
                    Sql::Text(c.mac.to_string()),
                    opt_text(c.hostname.clone()),
                    opt_text(c.ip.clone()),
                    Sql::Integer(ts),
                    Sql::Text(c.ap_mac.to_string()),
                    Sql::Text(c.bssid.clone()),
                    opt_text(c.essid.clone()),
                    opt_text(c.radio.clone()),
                ],
            );
            for e in events {
                self.emit(live, e);
            }
        }
        let _ = ap;
        let _ = self.tx.send(LiveMsg::Clients);
    }

    fn reply(&mut self, ts: Ts, mac: Mac, decoded: Decoded) {
        let p = &decoded.payload;
        let mut live = self.live.write().unwrap();
        live.counters.replies += 1;
        if let (Some(interval), Some(d)) = (p["interval"].as_i64(), live.devices.get_mut(&mac)) {
            d.interval = interval;
        }
        if p["_type"].as_str() != Some("setparam") {
            return;
        }
        live.counters.config_pushes += 1;
        let mut data = serde_json::Map::new();
        data.insert("cfgversion".into(), p["cfgversion"].clone());
        let known = self.configs.entry(mac).or_default();
        for field in ["mgmt_cfg", "system_cfg"] {
            let Some(new) = p[field].as_str() else { continue };
            let summary = match known.get(field) {
                Some(old) => {
                    let d = cfgdiff::diff(old, new);
                    json!({ "added": d.added.len(), "removed": d.removed.len(), "changed": d.changed.len(), "diff": d.render("", true) })
                }
                None => json!({ "baseline": true, "lines": new.lines().count() }),
            };
            data.insert(field.into(), summary);
            known.insert(field, new.to_string());
        }
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO device_config (mac, ts, cfgversion, mgmt_cfg, system_cfg) VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                Sql::Text(mac.to_string()),
                Sql::Integer(ts),
                opt_text(p["cfgversion"].as_str().map(str::to_string)),
                opt_text(p["mgmt_cfg"].as_str().map(cfgdiff::redact)),
                opt_text(p["system_cfg"].as_str().map(cfgdiff::redact)),
            ],
        );
        if let Some(d) = live.devices.get_mut(&mac) {
            d.last_config_push = Some(ts);
        }
        let cfgversion = p["cfgversion"].as_str().map(str::to_string);
        let (mgmt, system) = (p["mgmt_cfg"].as_str().unwrap_or("").to_string(), p["system_cfg"].as_str().unwrap_or("").to_string());
        live.last_config.insert(mac, (mgmt.clone(), system.clone(), cfgversion.clone()));
        self.emit(&mut live, ev(ts, "config_pushed", Some(mac), None, Value::Object(data)));

        // Dry run: what would apctl have pushed for the same AP at this moment?
        if let (Some(render), Some(state)) = (&self.renderer, live.state.clone()) {
            let inform = live.raw_informs.get(&mac).cloned();
            let req = crate::dryrun::RenderRequest {
                state: &state,
                device_mac: &mac.to_string(),
                inform: inform.as_deref(),
                cfgversion: cfgversion.as_deref().unwrap_or(""),
                previous_system_cfg: Some(&system),
            };
            let result = render(&req).map(|ours| crate::dryrun::compare(&ours, &mgmt, &system, false));
            let (matches, payload) = match &result {
                Ok(c) => (c.matches(), serde_json::to_value(c).unwrap_or_default()),
                Err(e) => (false, json!({ "error": format!("{e:#}") })),
            };
            self.writer.exec(
                Db::Config,
                "INSERT INTO dryrun_results (ts, mac, cfgversion, matches, comparison) VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![Sql::Integer(ts), Sql::Text(mac.to_string()), opt_text(cfgversion), Sql::Integer(matches as i64), Sql::Text(payload.to_string())],
            );
            let summary = match &result {
                Ok(c) => json!({ "matches": matches, "system_cfg": { "added": c.system_cfg.added, "removed": c.system_cfg.removed, "changed": c.system_cfg.changed, "same_content": c.system_cfg.same_content } }),
                Err(e) => json!({ "matches": false, "error": format!("{e:#}") }),
            };
            self.emit(&mut live, ev(ts, "dryrun_compared", Some(mac), None, summary));
        }
    }

    fn set_state(&mut self, ts: Ts, state: Value) {
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO controller_state (id, json, imported_at) VALUES (1, ?1, ?2)",
            vec![Sql::Text(state.to_string()), Sql::Integer(ts)],
        );
        let summary = crate::dryrun::summarize_state(&state);
        let mut live = self.live.write().unwrap();
        live.state = Some(Arc::new(state));
        live.state_imported_at = Some(ts);
        self.emit(&mut live, ev(ts, "settings_imported", None, None, summary));
    }

    fn set_alias(&mut self, ts: Ts, mac: Mac, alias: Option<String>, note: Option<String>, only_if_unset: bool) {
        let clean = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let (alias, note) = (clean(alias), clean(note));
        let mut live = self.live.write().unwrap();
        let old = live.aliases.get(&mac).cloned().unwrap_or_default();
        if only_if_unset && old.alias.is_some() {
            return;
        }
        if old.alias == alias && old.note == note {
            return;
        }
        if alias.is_none() && note.is_none() {
            live.aliases.remove(&mac);
            self.writer.exec(Db::Config, "DELETE FROM client_aliases WHERE mac = ?1", vec![Sql::Text(mac.to_string())]);
        } else {
            live.aliases.insert(mac, Alias { alias: alias.clone(), note: note.clone() });
            self.writer.exec(
                Db::Config,
                "INSERT OR REPLACE INTO client_aliases (mac, alias, note, updated) VALUES (?1, ?2, ?3, ?4)",
                vec![Sql::Text(mac.to_string()), opt_text(alias.clone()), opt_text(note.clone()), Sql::Integer(ts)],
            );
        }
        if old.alias != alias {
            let ap = live.clients.get(&mac).map(|c| c.sample.ap_mac);
            self.emit(&mut live, ev(ts, "client_renamed", ap, Some(mac), json!({ "from": old.alias, "to": alias })));
        }
        drop(live);
        let _ = self.tx.send(LiveMsg::Clients);
    }

    fn datagram(&mut self, ts: Ts, src_ip: String, payload: &[u8]) {
        let (by_hash, by_ip) = {
            let live = self.live.read().unwrap();
            (live.by_hash_id.clone(), live.by_ip.get(&src_ip).copied())
        };
        let keys = &self.keys;
        let lookup = |hash: &str| by_hash.get(hash).and_then(|mac| keys.syslog_key(mac).map(|k| (*mac, *k)));
        let mut result = crate::syslog::open(payload, lookup);
        // Syslog can arrive before the AP's first inform tells us its hash_id:
        // try each known key (there are few) and remember the one that works.
        if result.is_err() && payload.starts_with(&crate::syslog::MAGIC) && payload.len() > 17 {
            for (mac, key) in keys.syslog_keys() {
                if let Ok(found) = crate::syslog::open(payload, |_| Some((*mac, *key))) {
                    self.live.write().unwrap().by_hash_id.insert(hex::encode(&payload[9..17]), *mac);
                    result = Ok(found);
                    break;
                }
            }
        }
        match result {
            Ok((mac, text)) => {
                // Netconsole and multi-line messages can carry several lines.
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    self.log(crate::syslog::parse(ts, src_ip.clone(), mac.or(by_ip), line));
                }
            }
            Err(e) => {
                tracing::debug!("syslog from {src_ip}: {e:#}");
                self.live.write().unwrap().counters.log_errors += 1;
            }
        }
    }

    fn log(&mut self, line: LogLine) {
        self.live.write().unwrap().counters.logs += 1;
        self.writer.exec(
            Db::Logs,
            "INSERT INTO logs (ts, device_mac, src_ip, facility, severity, program, msg) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            vec![
                Sql::Integer(line.ts),
                opt_text(line.device_mac.map(|m| m.to_string())),
                Sql::Text(line.src_ip.clone()),
                opt_int(line.facility),
                opt_int(line.severity),
                opt_text(line.program.clone()),
                Sql::Text(line.msg.clone()),
            ],
        );
        let _ = self.tx.send(LiveMsg::Log(line));
    }

    /// Time-based transitions: APs going quiet and clients disappearing.
    fn tick(&mut self, now: Ts) {
        let mut live = self.live.write().unwrap();
        let mut events = Vec::new();
        let mut offline = Vec::new();
        for (mac, d) in live.devices.iter_mut() {
            let limit = (d.interval.max(5) * OFFLINE_INTERVALS).max(60);
            if d.online && now - d.last_seen > limit {
                d.online = false;
                offline.push(*mac);
                events.push(ev(now, "ap_offline", Some(*mac), None, json!({ "last_seen": d.last_seen })));
                self.writer.exec(Db::Config, "UPDATE devices SET online = 0 WHERE mac = ?1", vec![Sql::Text(mac.to_string())]);
            }
        }
        // Report config applications whose AP has been stable long enough.
        for (mac, d) in live.devices.iter_mut() {
            if let Some(a) = &d.applying
                && a.returned.is_some_and(|r| now - r >= APPLY_SETTLE_SECS) {
                    events.push(config_applied(*mac, a, now, None));
                    d.applying = None;
                }
        }
        // A client is gone when its AP has reported a full client list since it was
        // last seen and the grace period has passed, or when its AP went offline.
        let ap_last_full: HashMap<Mac, (Ts, bool)> = live
            .devices
            .iter()
            .map(|(m, d)| (*m, (if d.reconfiguring { 0 } else { d.last_seen }, d.online)))
            .collect();
        let mut changed = false;
        for (cmac, c) in live.clients.iter_mut() {
            if !c.connected {
                continue;
            }
            // An AP we have not heard from yet in this run (e.g. right after a
            // restart) is unknown, not offline: leave its clients alone.
            let (ap_seen, ap_online, ap_known) = match ap_last_full.get(&c.sample.ap_mac) {
                Some(&(seen, online)) => (seen, online, true),
                None => (0, true, false),
            };
            let reason = if !ap_known {
                // Its AP never reappeared (e.g. removed): give up after an hour.
                (now - c.last_seen > 3600).then_some("stale")
            } else if !ap_online {
                Some("ap_offline")
            } else if now - c.last_seen > CLIENT_GRACE_SECS && ap_seen > c.last_seen {
                Some("not_seen")
            } else {
                None
            };
            if let Some(reason) = reason {
                c.connected = false;
                changed = true;
                events.push(ev(now, "client_disconnected", Some(c.sample.ap_mac), Some(*cmac), json!({
                    "reason": reason, "last_seen": c.last_seen, "essid": c.sample.essid,
                    "connected_for": c.sample.uptime, "last_signal": c.sample.signal,
                })));
                self.writer.exec(Db::Config, "UPDATE clients SET connected = 0 WHERE mac = ?1", vec![Sql::Text(cmac.to_string())]);
            }
        }
        for e in events {
            self.emit(&mut live, e);
        }
        drop(live);
        for mac in offline {
            let _ = self.tx.send(LiveMsg::Device { mac });
        }
        if changed {
            let _ = self.tx.send(LiveMsg::Clients);
        }
    }

    fn write_metrics(&self, s: &Snapshot) {
        let ts = s.ap.ts;
        let mac = || Sql::Text(s.ap.mac.to_string());
        let a = &s.ap;
        self.writer.send(Write::Metric {
            table: &store::AP,
            ts,
            values: vec![mac(), f(a.cpu), f(a.mem), f(a.load1), f(a.load5), f(a.load15), i(a.mem_used), i(a.mem_total), i(a.uptime), i(a.satisfaction), i(a.num_sta)],
        });
        if let Some(u) = &s.uplink {
            self.writer.send(Write::Metric {
                table: &store::UPLINK,
                ts,
                values: vec![mac(), i(u.speed), i(u.rx_bytes), i(u.tx_bytes), i(u.rx_packets), i(u.tx_packets), i(u.rx_errors), i(u.tx_errors), i(u.rx_dropped), i(u.tx_dropped)],
            });
        }
        if !s.has_vap_table {
            return; // radio, VAP and client figures are absent or meaningless while restarting
        }
        for r in &s.radios {
            self.writer.send(Write::Metric {
                table: &store::RADIO,
                ts,
                values: vec![
                    mac(), Sql::Text(r.radio.clone()), i(r.channel), i(r.bw), i(r.tx_power), i(r.cu_total), i(r.cu_self_rx),
                    i(r.cu_self_tx), i(r.cu_interf), i(r.noise_floor), Sql::Integer(r.num_sta), i(r.tx_packets), i(r.tx_retries),
                ],
            });
        }
        for v in &s.vaps {
            self.writer.send(Write::Metric {
                table: &store::VAP,
                ts,
                values: vec![
                    Sql::Text(v.bssid.clone()), mac(), opt_text(v.essid.clone()), opt_text(v.radio.clone()),
                    i(v.num_sta), i(v.ccq), i(v.satisfaction), i(v.avg_client_signal), i(v.latency_avg),
                    i(v.rx_bytes), i(v.tx_bytes), i(v.rx_packets), i(v.tx_packets), i(v.tx_retries), i(v.tx_dropped),
                ],
            });
        }
        for c in &s.clients {
            self.writer.send(Write::Metric {
                table: &store::CLIENT,
                ts,
                values: vec![
                    Sql::Text(c.mac.to_string()), mac(), Sql::Text(c.bssid.clone()), opt_text(c.essid.clone()), opt_text(c.radio.clone()),
                    i(c.rssi), i(c.signal), i(c.noise), i(c.tx_rate), i(c.rx_rate), i(c.satisfaction), i(c.latency_avg), i(c.channel),
                    i(c.tx_bytes), i(c.rx_bytes), i(c.tx_packets), i(c.rx_packets), i(c.tx_retries),
                ],
            });
        }
    }
}

/// The single event for a finished config application. `clients` is the AP's
/// current client list when known (from an inform), for spotting reconnects.
fn config_applied(mac: Mac, a: &Applying, ts: Ts, clients: Option<&[ClientSample]>) -> Event {
    let took = a.returned.unwrap_or(ts) - a.since;
    let window = ts - a.since + 5;
    let (after, reconnected) = match clients {
        Some(list) => (
            Some(list.len()),
            list.iter().filter(|c| a.before.contains(&c.mac) && c.uptime.is_some_and(|u| u <= window)).count(),
        ),
        None => (None, 0),
    };
    ev(a.returned.unwrap_or(ts), "ap_config_applied", Some(mac), None, json!({
        "seconds": took.max(1),
        "clients_before": a.before.len(),
        "clients_after": after,
        "reconnected": reconnected,
    }))
}

fn ev(ts: Ts, kind: &'static str, device_mac: Option<Mac>, client_mac: Option<Mac>, data: Value) -> Event {
    Event { ts, kind, device_mac, client_mac, data }
}

fn f(v: Option<f64>) -> Sql {
    v.map_or(Sql::Null, Sql::Real)
}

fn i(v: Option<i64>) -> Sql {
    v.map_or(Sql::Null, Sql::Integer)
}

fn opt_int(v: Option<i64>) -> Sql {
    i(v)
}

fn opt_text(v: Option<String>) -> Sql {
    v.map_or(Sql::Null, Sql::Text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use inform::{Flags, Header};
    use wire::decode::KeyUsed;

    fn decoded(payload: Value) -> Decoded {
        let header = Header {
            packet_version: 0,
            mac: Mac([0; 6]),
            flags: Flags(Flags::ENCRYPTED | Flags::GCM),
            iv: [0; 16],
            payload_version: 1,
            payload_len: 0,
        };
        Decoded { header, key: KeyUsed::Device, payload }
    }

    fn inform(ap: &str, uptime: i64, clients: &[(&str, &str)]) -> Value {
        // clients: (mac, bssid)
        let mut vaps: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
        for (mac, bssid) in clients {
            vaps.entry(bssid).or_default().push(json!({ "mac": mac, "signal": -60 }));
        }
        let vap_table: Vec<Value> = if clients.is_empty() {
            vec![json!({ "bssid": format!("{ap}-b"), "radio": "na", "channel": 36, "usage": "user", "sta_table": [] })]
        } else {
            vaps.into_iter().map(|(b, s)| json!({ "bssid": b, "radio": "na", "channel": 36, "usage": "user", "sta_table": s })).collect()
        };
        json!({ "mac": ap, "uptime": uptime, "vap_table": vap_table })
    }

    struct Harness {
        engine: Engine,
        live: SharedLive,
        rx: broadcast::Receiver<LiveMsg>,
        _dir: std::path::PathBuf,
    }

    fn harness() -> Harness {
        let dir = std::env::temp_dir().join(format!("apctl-engine-{}-{}", std::process::id(), rand_suffix()));
        let (_store, writer) = store::Store::open(&dir).unwrap();
        let live: SharedLive = Default::default();
        let (tx, rx) = broadcast::channel(1024);
        Harness { engine: Engine::new(writer, Default::default(), live.clone(), tx), live, rx, _dir: dir }
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    fn events(h: &mut Harness) -> Vec<(&'static str, Option<String>)> {
        let mut out = Vec::new();
        while let Ok(m) = h.rx.try_recv() {
            if let LiveMsg::Event(e) = m {
                out.push((e.kind, e.client_mac.map(|m| m.to_string())));
            }
        }
        out
    }

    const AP1: &str = "02:00:00:00:00:01";
    const AP2: &str = "02:00:00:00:00:02";
    const C1: &str = "02:00:00:00:01:01";

    #[test]
    fn client_connect_roam_and_disconnect() {
        let mut h = harness();
        let feed = |h: &mut Harness, ts, ap: &str, clients: &[(&str, &str)]| {
            h.engine.handle(Input::Inform { ts, peer: "10.0.0.1".into(), decoded: decoded(inform(ap, 1000 + ts, clients)) });
        };
        feed(&mut h, 0, AP1, &[(C1, "b1")]);
        feed(&mut h, 1, AP2, &[]);
        assert_eq!(events(&mut h), vec![("ap_seen", None), ("client_connected", Some(C1.into())), ("ap_seen", None)]);

        // Roams to AP2; AP1 no longer lists it.
        feed(&mut h, 10, AP2, &[(C1, "b2")]);
        feed(&mut h, 12, AP1, &[]);
        assert_eq!(events(&mut h), vec![("client_roamed", Some(C1.into()))]);

        // Leaves entirely: disconnect only after the grace period and a full list from its AP.
        feed(&mut h, 20, AP2, &[]);
        feed(&mut h, 20, AP1, &[]);
        // Last seen at t=10, so the grace period runs until t=10+GRACE.
        h.engine.handle(Input::Tick(10 + CLIENT_GRACE_SECS - 5));
        let early = events(&mut h);
        assert!(early.is_empty(), "still within grace: {early:?}");
        feed(&mut h, 20 + CLIENT_GRACE_SECS, AP2, &[]);
        feed(&mut h, 20 + CLIENT_GRACE_SECS, AP1, &[]);
        h.engine.handle(Input::Tick(20 + CLIENT_GRACE_SECS + 1));
        assert_eq!(events(&mut h), vec![("client_disconnected", Some(C1.into()))]);
        assert!(!h.live.read().unwrap().clients[&C1.parse().unwrap()].connected);
    }

    #[test]
    fn short_informs_during_radio_restart_do_not_disconnect_clients() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: "x".into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        events(&mut h);
        // 2 minutes of short informs (no vap_table), as seen after a config push.
        for ts in (5..120).step_by(5) {
            h.engine.handle(Input::Inform { ts, peer: "x".into(), decoded: decoded(json!({ "mac": AP1, "uptime": 1000 + ts })) });
            h.engine.handle(Input::Tick(ts));
        }
        let evs = events(&mut h);
        assert!(evs.is_empty(), "nothing is known until the AP is back: {evs:?}");
        assert!(h.live.read().unwrap().clients[&C1.parse().unwrap()].connected);

        // Back with full informs: the client kept its session (uptime 1120 s),
        // so this was a config change without a radio restart.
        for ts in [120, 125, 160] {
            let mut full = inform(AP1, 1000 + ts, &[(C1, "b1")]);
            full["vap_table"][0]["sta_table"][0]["uptime"] = json!(1000 + ts);
            h.engine.handle(Input::Inform { ts, peer: "x".into(), decoded: decoded(full) });
        }
        let applied: Vec<_> = std::iter::from_fn(|| h.rx.try_recv().ok())
            .filter_map(|m| match m { LiveMsg::Event(e) if e.kind == "ap_config_applied" => Some(e.data), _ => None })
            .collect();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0]["seconds"], 115, "from the first short inform to the AP's return");
        assert_eq!(applied[0]["reconnected"], 0);
    }

    #[test]
    fn restart_of_the_controller_does_not_reconnect_everyone() {
        let dir = std::env::temp_dir().join(format!("apctl-restore-{}-{}", std::process::id(), rand_suffix()));
        let feed = |e: &mut Engine, ts| e.handle(Input::Inform { ts, peer: "x".into(), decoded: decoded(inform(AP1, 1000 + ts, &[(C1, "b1")])) });
        {
            let (_store, writer) = store::Store::open(&dir).unwrap();
            let (tx, _rx) = broadcast::channel(1024);
            let mut e = Engine::new(writer, Default::default(), Default::default(), tx);
            feed(&mut e, 0);
            std::thread::sleep(std::time::Duration::from_millis(1500)); // let the writer flush
        }
        let (store, writer) = store::Store::open(&dir).unwrap();
        let (tx, mut rx) = broadcast::channel(1024);
        let mut e = Engine::new(writer, Default::default(), Default::default(), tx);
        e.restore(&store).unwrap();
        e.handle(Input::Tick(25)); // a tick before the first inform must not disconnect anyone
        feed(&mut e, 30);
        let kinds: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|m| match m { LiveMsg::Event(ev) => Some(ev.kind), _ => None })
            .collect();
        assert!(kinds.is_empty(), "{kinds:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn aliases_are_set_cleared_and_imported_without_overwriting() {
        let mut h = harness();
        let mac: Mac = C1.parse().unwrap();
        let set = |h: &mut Harness, alias: Option<&str>, only_if_unset: bool| {
            h.engine.handle(Input::SetAlias { ts: 1, mac, alias: alias.map(str::to_string), note: None, only_if_unset });
        };
        set(&mut h, Some("  Kitchen speaker "), false);
        assert_eq!(h.live.read().unwrap().aliases[&mac].alias.as_deref(), Some("Kitchen speaker"));
        set(&mut h, Some("Imported name"), true); // bulk import must not overwrite
        assert_eq!(h.live.read().unwrap().aliases[&mac].alias.as_deref(), Some("Kitchen speaker"));
        set(&mut h, Some(""), false); // empty clears
        assert!(!h.live.read().unwrap().aliases.contains_key(&mac));
        let renames: Vec<_> = std::iter::from_fn(|| h.rx.try_recv().ok())
            .filter_map(|m| match m { LiveMsg::Event(e) if e.kind == "client_renamed" => Some(e.data), _ => None })
            .collect();
        assert_eq!(renames.len(), 2, "{renames:?}");
        assert_eq!(renames[1]["from"], "Kitchen speaker");
    }

    #[test]
    fn bursts_of_short_informs_are_one_config_application() {
        let mut h = harness();
        let full = |ts: i64| decoded(inform(AP1, 1000 + ts, &[(C1, "b1")]));
        let short = |ts: i64| decoded(json!({ "mac": AP1, "uptime": 1000 + ts }));
        // Pattern seen during a channel change: short, full, short, full, ...
        for (ts, is_full) in [(0, true), (10, false), (12, true), (20, false), (25, true), (40, false), (44, true), (60, true), (80, true)] {
            let d = if is_full { full(ts) } else { short(ts) };
            h.engine.handle(Input::Inform { ts, peer: "x".into(), decoded: d });
        }
        let applied: Vec<_> = std::iter::from_fn(|| h.rx.try_recv().ok())
            .filter_map(|m| match m { LiveMsg::Event(e) if e.kind == "ap_config_applied" => Some(e), _ => None })
            .collect();
        assert_eq!(applied.len(), 1, "{applied:?}");
        assert_eq!(applied[0].data["seconds"], 34, "from the first burst (10) to the final return (44)");
    }

    #[test]
    fn dry_run_compares_each_push_with_the_generator() {
        let mut h = harness();
        let mac: Mac = AP1.parse().unwrap();
        let push = |cfg: &str| decoded(json!({ "_type": "setparam", "cfgversion": "abc", "system_cfg": cfg, "mgmt_cfg": "cfgversion=abc" }));
        // A stand-in generator that renders "hide_ssid=false" and a fixed PSK.
        let render: crate::dryrun::RenderFn = Arc::new(|req: &crate::dryrun::RenderRequest| {
            assert_eq!(req.cfgversion, "abc", "rendered for the pushed cfgversion");
            assert!(req.state["wlanconf"].is_array());
            Ok((format!("cfgversion={}", req.cfgversion), "aaa.1.hide_ssid=false\naaa.1.wpa.psk=pw".to_string()))
        });
        h.engine.set_renderer(render);
        // No settings imported yet: no comparison.
        h.engine.handle(Input::Reply { ts: 1, mac, decoded: push("aaa.1.hide_ssid=false\naaa.1.wpa.psk=pw") });
        h.engine.handle(Input::SetState { ts: 2, state: json!({ "sites": [], "wlanconf": [], "networkconf": [], "setting": [], "devices": [] }) });
        h.engine.handle(Input::Reply { ts: 3, mac, decoded: push("aaa.1.hide_ssid=false\naaa.1.wpa.psk=pw") });
        h.engine.handle(Input::Reply { ts: 4, mac, decoded: push("aaa.1.hide_ssid=true\naaa.1.wpa.psk=pw") });
        let results: Vec<_> = std::iter::from_fn(|| h.rx.try_recv().ok())
            .filter_map(|m| match m { LiveMsg::Event(e) if e.kind == "dryrun_compared" => Some(e.data), _ => None })
            .collect();
        assert_eq!(results.len(), 2, "{results:?}");
        assert_eq!(results[0]["matches"], true);
        assert_eq!(results[1]["matches"], false);
        assert_eq!(results[1]["system_cfg"]["changed"], 1);
    }

    #[test]
    fn radio_changes_are_debounced() {
        let mut h = harness();
        let with = |channel: i64, power: i64| {
            json!({ "mac": AP1, "uptime": 5000, "radio_table": [{ "radio": "na" }],
                    "vap_table": [{ "bssid": "b1", "radio": "na", "channel": channel, "bw": 80, "tx_power": power, "usage": "user", "sta_table": [] }] })
        };
        let mut t = 0;
        let mut feed = |h: &mut Harness, v: Value| {
            t += 10;
            h.engine.handle(Input::Inform { ts: t, peer: "x".into(), decoded: decoded(v) });
        };
        feed(&mut h, with(44, 9));
        feed(&mut h, with(44, 23)); // transient after a restart
        feed(&mut h, with(44, 9));
        feed(&mut h, with(36, 9)); // real change...
        feed(&mut h, with(36, 9)); // ...confirmed
        feed(&mut h, with(36, 9));
        let changes: Vec<_> = std::iter::from_fn(|| h.rx.try_recv().ok())
            .filter_map(|m| match m { LiveMsg::Event(e) if e.kind == "radio_changed" => Some(e.data), _ => None })
            .collect();
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0]["from"]["channel"], 44);
        assert_eq!(changes[0]["to"]["channel"], 36);
    }

    #[test]
    fn ap_offline_restart_and_config_push() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: "x".into(), decoded: decoded(inform(AP1, 5000, &[(C1, "b1")])) });
        h.engine.handle(Input::Tick(30));
        events(&mut h);
        h.engine.handle(Input::Tick(100));
        assert_eq!(events(&mut h), vec![("ap_offline", None), ("client_disconnected", Some(C1.into()))]);
        // Back with a low uptime: online again and restarted.
        h.engine.handle(Input::Inform { ts: 200, peer: "x".into(), decoded: decoded(inform(AP1, 50, &[])) });
        assert_eq!(events(&mut h), vec![("ap_online", None), ("ap_restarted", None)]);

        let mac: Mac = AP1.parse().unwrap();
        let push = |cfg: &str| decoded(json!({ "_type": "setparam", "cfgversion": "x", "system_cfg": cfg, "mgmt_cfg": "a=1" }));
        h.engine.handle(Input::Reply { ts: 210, mac, decoded: push("aaa.1.hide_ssid=false\naaa.1.wpa.psk=old") });
        h.engine.handle(Input::Reply { ts: 220, mac, decoded: push("aaa.1.hide_ssid=true\naaa.1.wpa.psk=new") });
        let mut pushes = Vec::new();
        while let Ok(m) = h.rx.try_recv() {
            if let LiveMsg::Event(e) = m {
                pushes.push(e.data);
            }
        }
        assert_eq!(pushes[0]["system_cfg"]["baseline"], true);
        let diff = pushes[1]["system_cfg"]["diff"].as_str().unwrap();
        assert!(diff.contains("~ aaa.1.hide_ssid: false -> true"), "{diff}");
        assert!(diff.contains("aaa.1.wpa.psk: <redacted> -> <redacted>") && !diff.contains("new"), "{diff}");
    }
}
