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

/// A change to the settings, applied by the engine.
pub type StateEdit = Box<dyn FnOnce(&mut Value) -> Result<(), String> + Send>;

pub enum Input {
    Inform { ts: Ts, peer: String, decoded: Decoded },
    /// Replace the imported controller settings (an `informdump import` snapshot).
    SetState { ts: Ts, state: Value },
    /// Active mode: the section numbering a render allocated for an AP.
    SetConfigMeta { mac: Mac, meta: Value },
    /// Active mode: apctl itself pushed this `setparam` to an AP.
    ConfigPushed { ts: Ts, mac: Mac, payload: Value },
    /// Set or clear a client's alias and note (None clears). `only_if_unset`
    /// leaves existing aliases alone (for bulk imports).
    SetAlias { ts: Ts, mac: Mac, alias: Option<String>, note: Option<String>, only_if_unset: bool },
    /// A syslog datagram from an AP (captured in shadow mode or received directly).
    Datagram { ts: Ts, src_ip: String, payload: Vec<u8> },
    Reply { ts: Ts, mac: Mac, decoded: Decoded },
    Tick(Ts),
    DecodeError,
    /// A suspicious network found for the first time: record it, and report it
    /// as an event unless it was already acknowledged.
    ThreatFound { ts: Ts, kind: &'static str, bssid: String, device_mac: Option<Mac>, data: Value, notify: bool },
    /// Mark every alert read.
    AlertsRead,
    /// Record an event raised elsewhere (e.g. active mode sending an upgrade).
    Note { ts: Ts, kind: &'static str, mac: Mac, data: Value },
    /// Record a client event raised elsewhere (e.g. blocked from the UI).
    ClientNote { ts: Ts, kind: &'static str, client: Mac, data: Value },
    /// Record a site-wide event raised elsewhere (e.g. a channel plan applied).
    SiteNote { ts: Ts, kind: &'static str, data: Value },
    /// Drop everything apctl keeps about a forgotten AP.
    Forget { mac: Mac },
    /// Change the settings (apctl's copy of the controller settings), store
    /// them, and record the change; `done` gets the result.
    EditState { ts: Ts, what: String, edit: StateEdit, done: tokio::sync::oneshot::Sender<Result<(), String>> },
    /// Store the automatic-backup settings (JSON).
    SaveBackupSettings(String),
    /// Acknowledge a finding with an optional note (`Some`), or withdraw the acknowledgement (`None`).
    AckThreat { ts: Ts, kind: &'static str, bssid: String, note: Option<Option<String>> },
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
    Alert(crate::alerts::AlertMsg),
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
    /// Time of the last inform that included the client list.
    pub last_full_inform: Ts,
    pub last_config_push: Option<Ts>,
}

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
    pub notifications: u64,
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
    /// Firmware upgrades queued or in progress (one AP at a time).
    #[serde(skip)]
    pub firmware: crate::firmware::Jobs,
    /// Commands waiting for each AP's next inform (restart, locate, kick...).
    #[serde(skip)]
    pub commands: HashMap<Mac, std::collections::VecDeque<Value>>,
    /// APs told to flash their LED.
    #[serde(skip)]
    pub locating: std::collections::HashSet<Mac>,
    /// APs to send their config again on the next inform.
    #[serde(skip)]
    pub reprovision: std::collections::HashSet<Mac>,
    /// Quick scans (RF environment) asked of each AP and not finished yet.
    #[serde(skip)]
    pub scans: HashMap<Mac, crate::channelai::Scan>,
    /// APs waiting for adoption, being adopted or being forgotten.
    #[serde(skip)]
    pub adoption: crate::adopt::Adoption,
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

type McastTypes = std::collections::BTreeMap<String, crate::model::McastCounts>;

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
    /// Each client's last multicast counters and the BSSID they came from.
    mcast_prev: HashMap<Mac, (Ts, String, McastTypes)>,
    /// Each BSSID's last "delivered to clients" counters. The AP reports these
    /// per network, repeated identically in every client's block.
    bss_prev: HashMap<String, (Ts, McastTypes)>,
    /// Events found in syslog lines.
    logevents: crate::logevents::LogEvents,
    /// When each AP was last reported isolated.
    isolated: HashMap<Mac, Ts>,
    /// When long-gone clients were last dropped from the live view.
    last_prune: Ts,
}

impl Engine {
    pub fn new(writer: Writer, keys: Arc<KeyStore>, live: SharedLive, tx: broadcast::Sender<LiveMsg>) -> Self {
        Engine { writer, keys, renderer: None, live, tx, configs: HashMap::new(), radios: HashMap::new(), mcast_prev: HashMap::new(), bss_prev: HashMap::new(), logevents: Default::default(), isolated: HashMap::new(), last_prune: 0 }
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
            Input::Reply { ts, mac, decoded } => self.reply(ts, mac, &decoded.payload, true),
            Input::ConfigPushed { ts, mac, payload } => self.reply(ts, mac, &payload, false),
            Input::SetConfigMeta { mac, meta } => self.set_config_meta(mac, meta),
            Input::Datagram { ts, src_ip, payload } => self.datagram(ts, src_ip, &payload),
            Input::Tick(now) => self.tick(now),
            Input::DecodeError => self.live.write().unwrap().counters.decode_errors += 1,
            Input::SetAlias { ts, mac, alias, note, only_if_unset } => self.set_alias(ts, mac, alias, note, only_if_unset),
            Input::SetState { ts, state } => self.set_state(ts, state),
            Input::ThreatFound { ts, kind, bssid, device_mac, data, notify } => {
                self.writer.exec(
                    Db::Config,
                    "INSERT OR IGNORE INTO network_threats (kind, bssid, first_reported) VALUES (?1, ?2, ?3)",
                    vec![Sql::Text(kind.into()), Sql::Text(bssid), Sql::Integer(ts)],
                );
                if notify {
                    let mut live = self.live.write().unwrap();
                    self.emit(&mut live, ev(ts, "network_threat", device_mac, None, data));
                }
            }
            Input::AlertsRead => self.writer.exec(Db::Config, "UPDATE alerts SET read = 1 WHERE read = 0", vec![]),
            Input::Note { ts, kind, mac, data } => {
                let mut live = self.live.write().unwrap();
                self.emit(&mut live, ev(ts, kind, Some(mac), None, data));
            }
            Input::ClientNote { ts, kind, client, data } => {
                let mut live = self.live.write().unwrap();
                self.emit(&mut live, ev(ts, kind, None, Some(client), data));
            }
            Input::SiteNote { ts, kind, data } => {
                let mut live = self.live.write().unwrap();
                self.emit(&mut live, ev(ts, kind, None, None, data));
            }
            Input::Forget { mac } => self.forget(mac),
            Input::EditState { ts, what, edit, done } => {
                let _ = done.send(self.edit_state(ts, what, edit));
            }
            Input::SaveBackupSettings(json) => {
                self.writer.exec(Db::Config, "INSERT OR REPLACE INTO backup_settings (id, json) VALUES (1, ?1)", vec![Sql::Text(json)])
            }
            Input::AckThreat { ts, kind, bssid, note } => match note {
                Some(note) => self.writer.exec(
                    Db::Config,
                    "INSERT OR REPLACE INTO network_acks (kind, bssid, note, ts) VALUES (?1, ?2, ?3, ?4)",
                    vec![Sql::Text(kind.into()), Sql::Text(bssid), opt_text(note), Sql::Integer(ts)],
                ),
                None => self.writer.exec(
                    Db::Config,
                    "DELETE FROM network_acks WHERE kind = ?1 AND bssid = ?2",
                    vec![Sql::Text(kind.into()), Sql::Text(bssid)],
                ),
            },
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
        // Notifications are short informs sent between regular ones: a config
        // acknowledgement or an event (client connection tracking, radar, scans).
        // They carry no client data and must not update the AP's status.
        if decoded.payload["inform_as_notif"].as_bool() == Some(true) {
            self.notification(ts, &decoded.payload);
            return;
        }
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
        self.check_isolated(ts, &snap);

        let mut live = self.live.write().unwrap();
        if snap.has_vap_table {
            live.raw_informs.insert(mac, Arc::new(decoded.payload));
        }
        live.counters.informs += 1;
        if let Some(h) = &snap.ap.hash_id {
            live.by_hash_id.insert(h.clone(), mac);
        }
        if let Some(ip) = &snap.ap.ip {
            live.by_ip.insert(ip.clone(), mac);
        }

        // Device lifecycle events. The previous view is taken out (no copy) and
        // replaced at the end; the lock is held throughout.
        let prev = live.devices.remove(&mac);
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
                i(snap.ap.uptime),
                opt_text(snap.ap.cfgversion.clone()),
            ],
        );
        // An upgrade we sent has landed: the AP reports the new version.
        if let Some(v) = &snap.ap.version
            && let Some(j) = live.firmware.version_seen(&mac.to_string(), v)
        {
            events.push(ev(ts, "ap_upgraded", Some(mac), None, json!({ "from": j.from, "to": v, "custom": j.custom })));
        }
        for e in events {
            self.emit(&mut live, e);
        }

        if snap.has_vap_table {
            self.update_clients(&mut live, ts, &snap.clients);
        }
        let first_seen = prev.as_ref().map(|p| p.first_seen).or(known.as_ref().map(|k| k.first_seen)).unwrap_or(ts);
        let view = match prev {
            Some(p) => DeviceView {
                // Keep the last full picture while the AP is reconfiguring.
                last_full_inform: if snap.has_vap_table { ts } else { p.last_full_inform },
                snapshot: if snap.has_vap_table { snap } else { Snapshot { uplink: snap.uplink.or(p.snapshot.uplink), ap: snap.ap, ..p.snapshot } },
                online: true,
                first_seen,
                last_seen: ts,
                peer,
                interval: p.interval,
                reconfiguring: false,
                reconfiguring_since: None,
                last_config_push: p.last_config_push,
            },
            None => DeviceView {
                last_full_inform: if snap.has_vap_table { ts } else { 0 },
                snapshot: snap,
                online: true,
                first_seen,
                last_seen: ts,
                peer,
                interval: DEFAULT_INTERVAL,
                reconfiguring: false,
                reconfiguring_since: None,
                last_config_push: None,
            },
        };
        live.devices.insert(mac, view);
        drop(live);
        let _ = self.tx.send(LiveMsg::Device { mac });
    }

    fn update_clients(&self, live: &mut Live, ts: Ts, clients: &[ClientSample]) {
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
        let _ = self.tx.send(LiveMsg::Clients);
    }

    /// A reply sent to an AP: by the other controller (shadow mode, compared in
    /// a dry run) or by apctl itself (active mode).
    ///
    /// The diffs and the dry-run render take a while, so the live view is only
    /// locked to read what they need and then to store the results.
    fn reply(&mut self, ts: Ts, mac: Mac, p: &Value, dry_run: bool) {
        let (radios, mgmt, system, state, inform) = {
            let mut live = self.live.write().unwrap();
            live.counters.replies += 1;
            if let (Some(interval), Some(d)) = (p["interval"].as_i64(), live.devices.get_mut(&mac)) {
                d.interval = interval;
            }
            if p["_type"].as_str() != Some("setparam") {
                return;
            }
            live.counters.config_pushes += 1;
            // A push can be management-only (e.g. after an LED change): it carries
            // mgmt_cfg alone, and the AP keeps its last full system_cfg.
            let previous = live.last_config.get(&mac);
            let field = |name: &str, prev: Option<&String>| p[name].as_str().map(str::to_string).or_else(|| prev.cloned()).unwrap_or_default();
            let mgmt = field("mgmt_cfg", previous.map(|x| &x.0));
            let system = field("system_cfg", previous.map(|x| &x.1));
            let radios = live.devices.get(&mac).map(|d| d.snapshot.radios.clone()).unwrap_or_default();
            let wanted = dry_run && !system.is_empty() && self.renderer.is_some();
            let state = live.state.clone().filter(|_| wanted);
            let inform = state.as_ref().and_then(|_| live.raw_informs.get(&mac).cloned());
            (radios, mgmt, system, state, inform)
        };
        let mut data = serde_json::Map::new();
        data.insert("cfgversion".into(), p["cfgversion"].clone());
        let known = self.configs.entry(mac).or_default();
        // Sections removed by this push are only named in the previous config.
        let old_system = known.get("system_cfg").cloned();
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
        // Names for numbered sections ("aaa.3" -> "Home WiFi (5 GHz)"), so the
        // config history can say what a change was about.
        if let Some(cfg) = known.get("system_cfg") {
            let mut labels = old_system.map(|o| section_labels(&o, &radios)).unwrap_or_default();
            labels.extend(section_labels(cfg, &radios));
            data.insert("labels".into(), Value::Object(labels));
        }
        let cfgversion = p["cfgversion"].as_str().map(str::to_string).or_else(|| {
            p["mgmt_cfg"].as_str().and_then(|m| m.lines().find_map(|l| l.strip_prefix("cfgversion=")).map(str::to_string))
        });
        self.writer.exec(
            Db::Config,
            "INSERT INTO device_config (mac, ts, cfgversion, mgmt_cfg, system_cfg) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (mac) DO UPDATE SET ts = excluded.ts, cfgversion = COALESCE(excluded.cfgversion, cfgversion),
               mgmt_cfg = COALESCE(excluded.mgmt_cfg, mgmt_cfg), system_cfg = COALESCE(excluded.system_cfg, system_cfg)",
            vec![
                Sql::Text(mac.to_string()),
                Sql::Integer(ts),
                opt_text(cfgversion.clone()),
                opt_text(p["mgmt_cfg"].as_str().map(cfgdiff::redact)),
                opt_text(p["system_cfg"].as_str().map(cfgdiff::redact)),
            ],
        );

        // Dry run: what would apctl have pushed for the same AP at this moment?
        let dry = match (&self.renderer, &state) {
            (Some(render), Some(state)) => {
                let req = crate::dryrun::RenderRequest {
                    state,
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
                    vec![Sql::Integer(ts), Sql::Text(mac.to_string()), opt_text(cfgversion.clone()), Sql::Integer(matches as i64), Sql::Text(payload.to_string())],
                );
                Some(match &result {
                    Ok(c) => json!({ "matches": matches, "system_cfg": { "added": c.system_cfg.added, "removed": c.system_cfg.removed, "changed": c.system_cfg.changed, "same_content": c.system_cfg.same_content } }),
                    Err(e) => json!({ "matches": false, "error": format!("{e:#}") }),
                })
            }
            _ => None,
        };

        let mut live = self.live.write().unwrap();
        if let Some(d) = live.devices.get_mut(&mac) {
            d.last_config_push = Some(ts);
        }
        live.last_config.insert(mac, (mgmt, system, cfgversion));
        self.emit(&mut live, ev(ts, "config_pushed", Some(mac), None, Value::Object(data)));
        if let Some(summary) = dry {
            self.emit(&mut live, ev(ts, "dryrun_compared", Some(mac), None, summary));
        }
    }

    /// Stores an AP's section numbering in the settings, so later renders keep it.
    fn set_config_meta(&mut self, mac: Mac, meta: Value) {
        let mut live = self.live.write().unwrap();
        let Some(state) = live.state.clone() else { return };
        let mac_s = mac.to_string();
        let same_mac = |m: &Value| m["mac"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(&mac_s));
        let current = state["config_meta"].as_array().and_then(|a| a.iter().find(|m| same_mac(m)));
        if current == Some(&meta) {
            return;
        }
        let mut next = (*state).clone();
        if !next["config_meta"].is_array() {
            next["config_meta"] = json!([]);
        }
        let list = next["config_meta"].as_array_mut().unwrap();
        list.retain(|m| !same_mac(m));
        list.push(meta);
        self.writer.exec(Db::Config, "UPDATE controller_state SET json = ?1 WHERE id = 1", vec![Sql::Text(next.to_string())]);
        live.state = Some(Arc::new(next));
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

    fn edit_state(&mut self, ts: Ts, what: String, edit: StateEdit) -> Result<(), String> {
        let mut live = self.live.write().unwrap();
        let mut state = live.state.as_deref().cloned().ok_or("no settings imported yet")?;
        edit(&mut state)?;
        let imported_at = live.state_imported_at.unwrap_or(ts);
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO controller_state (id, json, imported_at) VALUES (1, ?1, ?2)",
            vec![Sql::Text(state.to_string()), Sql::Integer(imported_at)],
        );
        live.state = Some(Arc::new(state));
        self.emit(&mut live, ev(ts, "settings_changed", None, None, json!({ "what": what })));
        // The APs pick the change up now rather than at their next interval.
        crate::stun::poke_all(&live);
        Ok(())
    }

    fn forget(&mut self, mac: Mac) {
        let mut live = self.live.write().unwrap();
        live.devices.remove(&mac);
        // Also what was restored from the database, or it could still be reported offline.
        live.known_devices.remove(&mac);
        live.by_hash_id.retain(|_, m| *m != mac);
        live.by_ip.retain(|_, m| *m != mac);
        live.raw_informs.remove(&mac);
        live.last_config.remove(&mac);
        live.adoption.forgetting.remove(&mac);
        live.adoption.adopting.remove(&mac);
        self.configs.remove(&mac);
        for sql in ["DELETE FROM devices WHERE mac = ?1", "DELETE FROM managed_devices WHERE mac = ?1", "DELETE FROM device_config WHERE mac = ?1"] {
            self.writer.exec(Db::Config, sql, vec![Sql::Text(mac.to_string())]);
        }
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

    fn notification(&mut self, ts: Ts, p: &Value) {
        let Some(mac) = p["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else { return };
        let mut live = self.live.write().unwrap();
        live.counters.notifications += 1;
        if let Some(d) = live.devices.get_mut(&mac) {
            d.last_seen = ts; // proof of life, but not a status report
        }
        match p["notif_reason"].as_str() {
            // The AP confirms it applied a pushed config.
            Some("setparam") => {
                let since_push = live.devices.get(&mac).and_then(|d| d.last_config_push).map(|t| ts - t);
                let data = json!({ "cfgversion": p["cfgversion"], "seconds_after_push": since_push });
                self.emit(&mut live, ev(ts, "config_applied", Some(mac), None, data));
            }
            Some("event") => {
                let n = &p["notif_payload"];
                if n["message_type"].as_str() == Some("STA_ASSOC_TRACKER") {
                    self.connection_event(&mut live, ts, mac, n);
                } else if let Some(kind) = n["event_string"].as_str() {
                    // AP events: radar (DFS), rogue APs, scan completion, process restarts...
                    let k = match kind {
                        "EVT_AP_RadarDetected" => "dfs_radar",
                        "EVT_AP_DetectRogueAP" => "rogue_ap",
                        "EVT_AP_QuickScanEvent" | "EVT_AP_AcsTriggerComplete" => "ap_scan_done",
                        // "{proc} exited with code {exit_status} and restarted by {caller}"
                        "EVT_AP_RestartProc" => "ap_process_restarted",
                        "Upgrade" => {
                            self.upgrade_notice(&mut live, ts, mac, n);
                            return;
                        }
                        _ => "ap_event",
                    };
                    self.emit(&mut live, ev(ts, k, Some(mac), None, n.clone()));
                }
            }
            // The AP starts an upgrade (ours, or one run on the AP itself).
            Some(r @ ("cmd-upgrade" | "cli-upgrade")) => {
                self.emit(&mut live, ev(ts, "ap_upgrade_started", Some(mac), None, json!({ "by": if r == "cli-upgrade" { "the AP's command line" } else { "the controller" } })));
            }
            // A crash or recovery report: base64 text from the AP's crash store.
            Some(reason @ ("crashlog" | "recovery")) => {
                use base64::Engine as _;
                let raw = p["notif_payload"].as_str().unwrap_or_default();
                let text = base64::engine::general_purpose::STANDARD
                    .decode(raw.trim())
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_else(|_| raw.to_string());
                let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
                let tail: Vec<&str> = lines.iter().rev().take(200).rev().copied().collect();
                let kind = if reason == "recovery" { "recovered after a crash" } else { "crash report" };
                self.emit(&mut live, ev(ts, "ap_crash", Some(mac), None, json!({ "kind": kind, "source": reason, "lines": tail })));
            }
            _ => {}
        }
    }

    /// A client connection-tracking event (`STA_ASSOC_TRACKER`): association,
    /// success (with association, WPA, IP and DNS timings), soft failure,
    /// roam, leave. Durations arrive in microseconds and are stored in ms.
    fn connection_event(&self, live: &mut Live, ts: Ts, ap: Mac, n: &Value) {
        let Some(client) = n["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else { return };
        let num = |k: &str| n[k].as_str().and_then(|v| v.parse::<f64>().ok()).or_else(|| n[k].as_f64());
        let ms = |k: &str| num(k).map(|us| (us / 1000.0).round() as i64);
        let text = |k: &str| n[k].as_str().map(str::to_string);
        let vap = text("vap");
        let dev = live.devices.get(&ap);
        let vap_info = dev.and_then(|d| d.snapshot.vaps.iter().find(|v| v.name.as_deref() == vap.as_deref()));
        let (essid, radio) = vap_info.map(|v| (v.essid.clone(), v.radio.clone())).unwrap_or((None, None));
        // Channel and width at the time, for the connection log and roaming views.
        let mut detail = n.clone();
        if let Some(v) = vap_info {
            let bw = dev.and_then(|d| d.snapshot.radios.iter().find(|r| Some(&r.radio) == v.radio.as_ref())).and_then(|r| r.bw);
            detail["x_channel"] = json!(v.channel);
            detail["x_bw"] = json!(bw);
        }
        let event_type = text("event_type").unwrap_or_default();
        self.writer.exec(
            Db::Config,
            "INSERT INTO connections (ts, ap_mac, client_mac, vap, essid, radio, event_type, auth_algo, assoc_ms, auth_ms, ip_ms, \
             ip_assign_type, dns_responses, dns_timeouts, rssi, reason, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            vec![
                Sql::Integer(ts),
                Sql::Text(ap.to_string()),
                Sql::Text(client.to_string()),
                opt_text(vap),
                opt_text(essid.clone()),
                opt_text(radio),
                Sql::Text(event_type.clone()),
                opt_text(text("auth_algo")),
                opt_int(ms("assoc_delta")),
                opt_int(ms("wpa_auth_delta")),
                opt_int(ms("ip_delta")),
                opt_text(text("ip_assign_type")),
                opt_int(num("dns_responses").map(|v| v as i64)),
                opt_int(num("dns_timeouts").map(|v| v as i64)),
                opt_int(num("avg_rssi").or_else(|| num("auth_rssi")).map(|v| v as i64)),
                opt_text(text("sta_dc_reason")),
                // The whole notification: failure counters and stage flags for connectivity stats.
                Sql::Text(detail.to_string()),
            ],
        );
        // Failed attempts are worth an event; the rest stay in the connection log.
        // A roam is reported as a "soft failure" but is a normal, successful move.
        let roamed = n["ip_assign_type"].as_str().is_some_and(|t| t.starts_with("roam"));
        if event_type == "failure" || (event_type == "soft failure" && !roamed) {
            let data = json!({ "essid": essid, "reason": n["sta_dc_reason"], "auth_algo": n["auth_algo"], "rssi": num("auth_rssi") });
            let e = ev(ts, "client_connect_failed", Some(ap), Some(client), data);
            live.counters.events += 1;
            self.writer.exec(
                Db::Config,
                "INSERT INTO events (ts, kind, device_mac, client_mac, data) VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![Sql::Integer(e.ts), Sql::Text(e.kind.into()), Sql::Text(ap.to_string()), Sql::Text(client.to_string()), Sql::Text(e.data.to_string())],
            );
            let _ = self.tx.send(LiveMsg::Event(e));
        }
    }

    fn datagram(&mut self, ts: Ts, src_ip: String, payload: &[u8]) {
        let (by_hash, by_ip) = {
            let live = self.live.read().unwrap();
            (crate::syslog::hash_id(payload).and_then(|h| live.by_hash_id.get(&h).copied()), live.by_ip.get(&src_ip).copied())
        };
        let keys = &self.keys;
        // `open` only asks for the datagram's own hash_id, looked up above.
        let lookup = |_: &str| by_hash.and_then(|mac| keys.syslog_key(&mac).map(|k| (mac, *k)));
        let mut result = crate::syslog::open(payload, lookup);
        // Syslog can arrive before the AP's first inform tells us its hash_id:
        // try each known key (there are few) and remember the one that works.
        if result.is_err()
            && let Some(hash_id) = crate::syslog::hash_id(payload)
        {
            for (mac, key) in keys.syslog_keys() {
                if let Ok(found) = crate::syslog::open(payload, |_| Some((*mac, *key))) {
                    self.live.write().unwrap().by_hash_id.insert(hash_id, *mac);
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

    /// Upgrade progress from the AP: downloading, writing, or an error.
    fn upgrade_notice(&self, live: &mut Live, ts: Ts, mac: Mac, n: &Value) {
        let s = |k: &str| n[k].as_str().unwrap_or_default().to_string();
        let key = mac.to_string();
        match (n["up_type"].as_str(), n["up_stage"].as_str()) {
            (Some("UpgradeReady"), stage) => {
                let step = match stage {
                    Some("FWDownloading") => "downloading",
                    Some("FWCheckOK") => "writing",
                    _ => "preparing",
                };
                if let Some(j) = live.firmware.current_for(&key) {
                    j.state = step;
                    // Re-arm the deadline as the official controller does on each step.
                    j.expires = Some(ts + 450);
                }
                self.emit(live, ev(ts, "ap_upgrade_progress", Some(mac), None, json!({ "step": step })));
            }
            (Some("UpgradeError"), _) => {
                let reason = s("reason");
                let detail = match reason.as_str() {
                    "FirmwareDownloadFailed" => format!("download failed (error: curl:{}, http:{})", n["curl_rc"], n["http_rc"]),
                    "FirmwareCheckFailed" => format!("firmware check failed (error: {})", n["rc"]),
                    "FWWriteFailed" => "writing the firmware failed".into(),
                    r => format!("failed ({r})"),
                };
                live.firmware.failed(&key, &detail);
                self.emit(live, ev(ts, "ap_upgrade_failed", Some(mac), None, json!({ "reason": reason, "detail": detail })));
            }
            _ => {}
        }
    }

    /// Another AP's beacon flagged "isolated" (lost its uplink) that belongs to one
    /// of our APs: reported at most once an hour per AP.
    fn check_isolated(&mut self, ts: Ts, s: &Snapshot) {
        let num = |m: &str| -> Option<u64> {
            let m: Mac = m.parse().ok()?;
            let mut b = m.0;
            b[0] &= !0x02;
            Some(b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
        };
        let flagged: Vec<&crate::model::NeighborSample> = s.neighbors.iter().filter(|n| n.is_isolated).collect();
        if flagged.is_empty() {
            return;
        }
        let mut live = self.live.write().unwrap();
        let ours: Vec<(Mac, u64)> = live.devices.keys().filter_map(|m| num(&m.to_string()).map(|n| (*m, n))).collect();
        for n in flagged {
            let Some(b) = num(&n.bssid) else { continue };
            let Some((ap, _)) = ours.iter().find(|(_, x)| x.abs_diff(b) <= 16) else { continue };
            if self.isolated.get(ap).is_some_and(|t| ts - t < 3600) {
                continue;
            }
            self.isolated.insert(*ap, ts);
            let data = json!({ "heard_by": s.ap.mac.to_string(), "bssid": n.bssid, "signal": n.signal });
            self.emit(&mut live, ev(ts, "ap_isolated", Some(*ap), None, data));
        }
    }

    fn log(&mut self, line: LogLine) {
        let found = self.logevents.feed(&line);
        if !found.is_empty() {
            let mut live = self.live.write().unwrap();
            for f in found {
                self.emit(&mut live, ev(line.ts, f.kind, f.device, f.client, f.data));
            }
        }
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
        self.mcast_prev.retain(|_, (ts, ..)| *ts > now - 3600);
        {
            let mut live = self.live.write().unwrap();
            if let Some(mac) = live.firmware.expired(now)
                && let Some(j) = live.firmware.failed(&mac, "it did not come back with the new firmware in time")
            {
                let data = json!({ "reason": "timed out", "detail": "it did not come back with the new firmware in time", "target": j.target });
                self.emit(&mut live, ev(now, "ap_upgrade_failed", mac.parse().ok(), None, data));
            }
        }
        let found = self.logevents.tick(now);
        if !found.is_empty() {
            let mut live = self.live.write().unwrap();
            for f in found {
                self.emit(&mut live, ev(now, f.kind, f.device, f.client, f.data));
            }
        }
        self.bss_prev.retain(|_, (ts, _)| *ts > now - 3600);
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
        // A client is gone when its AP has reported a full client list since it was
        // last seen and the grace period has passed, or when its AP went offline.
        let ap_last_full: HashMap<Mac, (Ts, bool)> = live
            .devices
            .iter()
            .map(|(m, d)| (*m, (d.last_full_inform, d.online)))
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
        // Clients gone longer than the database keeps them (see `store::maintenance`).
        if now - self.last_prune >= 3600 {
            self.last_prune = now;
            let cutoff = now - store::CLIENT_RETENTION;
            let Live { clients, aliases, .. } = &mut *live;
            let before = clients.len();
            clients.retain(|mac, c| c.last_seen >= cutoff || aliases.contains_key(mac));
            changed |= clients.len() != before;
        }
        drop(live);
        for mac in offline {
            let _ = self.tx.send(LiveMsg::Device { mac });
        }
        if changed {
            let _ = self.tx.send(LiveMsg::Clients);
        }
    }

    fn write_metrics(&mut self, s: &Snapshot) {
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
                    i(v.tx_mcast), i(v.rx_mcast), i(v.wifi_tx_attempts), i(v.wifi_tx_dropped), i(v.tx_bcast), i(v.rx_bcast),
                ],
            });
        }
        for n in &s.neighbors {
            self.writer.exec(
                Db::Config,
                "INSERT INTO neighbors (bssid, ap_mac, radio, essid, channel, bw, center_freq, security, signal, best_signal, noise, is_unifi, ap_name, model, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11, ?12, ?13, ?14, ?14)
                 ON CONFLICT (bssid, ap_mac) DO UPDATE SET radio = excluded.radio, essid = excluded.essid, channel = excluded.channel,
                   bw = excluded.bw, center_freq = excluded.center_freq, security = excluded.security, signal = excluded.signal,
                   best_signal = MAX(COALESCE(best_signal, -200), COALESCE(excluded.signal, -200)), noise = excluded.noise,
                   is_unifi = excluded.is_unifi, ap_name = excluded.ap_name, model = excluded.model, last_seen = excluded.last_seen",
                vec![
                    Sql::Text(n.bssid.clone()), mac(), opt_text(n.radio.clone()), opt_text(n.essid.clone()), i(n.channel), i(n.bw),
                    i(n.center_freq), opt_text(n.security.clone()), i(n.signal), i(n.noise), Sql::Integer(n.is_unifi as i64),
                    opt_text(n.ap_name.clone()), opt_text(n.model.clone()), Sql::Integer(ts),
                ],
            );
        }
        for c in &s.spectrum {
            self.writer.exec(
                Db::Config,
                "INSERT OR REPLACE INTO spectrum (ap_mac, radio, channel, width, utilization, interference, other_bss_count, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vec![mac(), Sql::Text(c.radio.clone()), Sql::Integer(c.channel), i(c.width), i(c.utilization), i(c.interference), i(c.other_bss_count), Sql::Integer(ts)],
            );
        }
        // Per traffic type: [to clients pps, from clients pps, to bytes/s, from bytes/s], and
        // how many clients sent any. "To clients" is counted once per network (BSSID),
        // "from clients" per client; only increases count (a client moving to another
        // network, or a restarted counter, adds nothing rather than its whole total).
        let mut mcast: std::collections::BTreeMap<String, ([f64; 4], i64)> = std::collections::BTreeMap::new();
        let rate = |c: i64, p: i64, dt: f64| (c - p).max(0) as f64 / dt;
        let mut bss_done: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for c in &s.clients {
            let m = c.multicast.as_ref();
            let t = m.map(|m| m.total());
            self.writer.send(Write::Metric {
                table: &store::CLIENT,
                ts,
                values: vec![
                    Sql::Text(c.mac.to_string()), mac(), Sql::Text(c.bssid.clone()), opt_text(c.essid.clone()), opt_text(c.radio.clone()),
                    i(c.rssi), i(c.signal), i(c.noise), i(c.tx_rate), i(c.rx_rate), i(c.satisfaction), i(c.latency_avg), i(c.channel),
                    i(c.tx_bytes), i(c.rx_bytes), i(c.tx_packets), i(c.rx_packets), i(c.tx_retries),
                    i(t.map(|t| t.tx_pkts)), i(t.map(|t| t.rx_pkts)), i(t.map(|t| t.tx_bytes)), i(t.map(|t| t.rx_bytes)),
                ],
            });
            let Some(m) = m else { continue };
            if bss_done.insert(c.bssid.as_str()) {
                if let Some((pts, prev)) = self.bss_prev.get(&c.bssid)
                    && ts > *pts
                    && ts - pts <= 120
                {
                    let dt = (ts - pts) as f64;
                    for (kind, cur) in &m.types {
                        let p = prev.get(kind).copied().unwrap_or(*cur);
                        let e = mcast.entry(kind.clone()).or_default();
                        e.0[0] += rate(cur.tx_pkts, p.tx_pkts, dt);
                        e.0[2] += rate(cur.tx_bytes, p.tx_bytes, dt);
                    }
                }
                self.bss_prev.insert(c.bssid.clone(), (ts, m.types.clone()));
            }
            if let Some((pts, bssid, prev)) = self.mcast_prev.get(&c.mac)
                && *bssid == c.bssid
                && ts > *pts
                && ts - pts <= 120
            {
                let dt = (ts - pts) as f64;
                for (kind, cur) in &m.types {
                    let p = prev.get(kind).copied().unwrap_or(*cur);
                    let (pk, by) = (rate(cur.rx_pkts, p.rx_pkts, dt), rate(cur.rx_bytes, p.rx_bytes, dt));
                    let e = mcast.entry(kind.clone()).or_default();
                    e.0[1] += pk;
                    e.0[3] += by;
                    if pk > 0.0 {
                        e.1 += 1;
                    }
                }
            }
            self.mcast_prev.insert(c.mac, (ts, c.bssid.clone(), m.types.clone()));
        }
        for (kind, (r, n)) in mcast {
            self.writer.send(Write::Metric {
                table: &store::MCAST,
                ts,
                values: vec![mac(), Sql::Text(kind), Sql::Real(r[0]), Sql::Real(r[1]), Sql::Real(r[2]), Sql::Real(r[3]), Sql::Integer(n)],
            });
        }
    }
}

/// Human names for numbered config sections: SSIDs (with band) for `aaa.N` and
/// `wireless.N`, the band for `radio.N`.
pub(crate) fn section_labels(cfg: &str, radios: &[crate::model::RadioSample]) -> serde_json::Map<String, Value> {
    let kv: HashMap<&str, &str> = cfg.lines().filter_map(|l| l.split_once('=')).collect();
    let band_of_phy = |phy: &str| {
        radios.iter().find(|r| r.name.as_deref() == Some(phy)).map(|r| match r.radio.as_str() {
            "ng" => "2.4 GHz",
            "na" => "5 GHz",
            "6e" => "6 GHz",
            other => other,
        })
    };
    // Interface (e.g. wifi1ap1) -> band, from the wireless sections' parent radio.
    let mut band_of_dev: HashMap<&str, &str> = HashMap::new();
    for (k, v) in &kv {
        if let Some(n) = k.strip_prefix("wireless.").and_then(|r| r.strip_suffix(".devname"))
            && let Some(b) = kv.get(format!("wireless.{n}.parent").as_str()).and_then(|p| band_of_phy(p))
        {
            band_of_dev.insert(v, b);
        }
    }
    let mut out = serde_json::Map::new();
    for (k, v) in &kv {
        for section in ["aaa", "wireless"] {
            if let Some(n) = k.strip_prefix(&format!("{section}.")).and_then(|r| r.strip_suffix(".ssid")) {
                let band = kv.get(format!("{section}.{n}.devname").as_str()).and_then(|d| band_of_dev.get(d));
                let label = match band {
                    Some(b) => format!("{v} ({b})"),
                    None => v.to_string(),
                };
                out.insert(format!("{section}.{n}"), json!(label));
            }
        }
        if let Some(n) = k.strip_prefix("radio.").and_then(|r| r.strip_suffix(".phyname"))
            && let Some(b) = band_of_phy(v)
        {
            out.insert(format!("radio.{n}"), json!(format!("{b} radio")));
        }
    }
    out
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

    #[test]
    fn config_sections_get_names() {
        let cfg = "radio.1.phyname=wifi0\nradio.2.phyname=wifi1\naaa.1.devname=wifi0ap0\naaa.1.ssid=Home IoT\nwireless.1.devname=wifi0ap0\n\
                   wireless.1.ssid=Home IoT\nwireless.1.parent=wifi0\naaa.2.devname=wifi1ap1\naaa.2.ssid=Home\nwireless.2.devname=wifi1ap1\n\
                   wireless.2.ssid=Home\nwireless.2.parent=wifi1\n";
        let radio = |name: &str, band: &str| crate::model::RadioSample { radio: band.into(), name: Some(name.into()), ..Default::default() };
        let l = section_labels(cfg, &[radio("wifi0", "ng"), radio("wifi1", "na")]);
        assert_eq!(l["aaa.1"], "Home IoT (2.4 GHz)");
        assert_eq!(l["wireless.2"], "Home (5 GHz)");
        assert_eq!(l["radio.2"], "5 GHz radio");
    }

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
    fn informs_without_a_client_list_do_not_disconnect_clients() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: "x".into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        events(&mut h);
        // Two minutes of informs that carry no client list (notifications, or any
        // short inform): nothing proves the client left.
        for ts in (5..120).step_by(5) {
            let d = if ts % 10 == 0 { notif(AP1, "event", json!({})) } else { decoded(json!({ "mac": AP1, "uptime": 1000 + ts })) };
            h.engine.handle(Input::Inform { ts, peer: "x".into(), decoded: d });
            h.engine.handle(Input::Tick(ts));
        }
        let evs = events(&mut h);
        assert!(evs.is_empty(), "{evs:?}");
        assert!(h.live.read().unwrap().clients[&C1.parse().unwrap()].connected);
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
    fn settings_edits_are_applied_recorded_or_refused() {
        let mut h = harness();
        let edit = |h: &mut Harness, f: StateEdit| {
            let (tx, mut rx) = tokio::sync::oneshot::channel();
            h.engine.handle(Input::EditState { ts: 5, what: "blocked client".into(), edit: f, done: tx });
            rx.try_recv().unwrap()
        };
        assert!(edit(&mut h, Box::new(|_| Ok(()))).is_err(), "nothing to edit before an import");
        h.engine.handle(Input::SetState { ts: 1, state: json!({ "clients": [] }) });
        edit(&mut h, Box::new(|s| crate::actions::edit_client(s, C1, &[("blocked", json!(true))]))).unwrap();
        assert_eq!(h.live.read().unwrap().state.as_ref().unwrap()["clients"][0]["blocked"], true);
        assert_eq!(h.live.read().unwrap().state_imported_at, Some(1), "an edit is not an import");
        assert_eq!(edit(&mut h, Box::new(|_| Err("no".into()))), Err("no".into()));
        let kinds: Vec<_> = events(&mut h).into_iter().map(|e| e.0).collect();
        assert_eq!(kinds, ["settings_imported", "settings_changed"]);
    }

    fn notif(ap: &str, reason: &str, payload: Value) -> Decoded {
        decoded(json!({ "mac": ap, "inform_as_notif": true, "notif_reason": reason, "notif_payload": payload, "cfgversion": "abc" }))
    }

    #[test]
    fn notifications_are_events_not_status() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: "x".into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        events(&mut h);
        // Config acknowledgement and a connection-tracker success: no client changes.
        h.engine.handle(Input::Inform { ts: 5, peer: "x".into(), decoded: notif(AP1, "setparam", Value::Null) });
        let success = json!({ "message_type": "STA_ASSOC_TRACKER", "event_type": "success", "mac": C1, "vap": "wifi1ap0",
            "assoc_delta": "40000", "wpa_auth_delta": "80000", "ip_delta": "100000", "dns_responses": "1", "dns_timeouts": "0", "avg_rssi": "-61" });
        h.engine.handle(Input::Inform { ts: 6, peer: "x".into(), decoded: notif(AP1, "event", success) });
        let failure = json!({ "message_type": "STA_ASSOC_TRACKER", "event_type": "soft failure", "mac": C1, "vap": "wifi1ap0", "sta_dc_reason": "roam", "auth_rssi": "-81" });
        h.engine.handle(Input::Inform { ts: 7, peer: "x".into(), decoded: notif(AP1, "event", failure) });
        h.engine.handle(Input::Inform { ts: 8, peer: "x".into(), decoded: notif(AP1, "event", json!({ "event_string": "EVT_AP_RadarDetected", "channel": 52 })) });
        assert_eq!(
            events(&mut h),
            vec![("config_applied", None), ("client_connect_failed", Some(C1.into())), ("dfs_radar", None)]
        );
        let live = h.live.read().unwrap();
        assert!(live.clients[&C1.parse().unwrap()].connected);
        assert_eq!(live.counters.notifications, 4);
        assert_eq!(live.devices[&AP1.parse().unwrap()].last_full_inform, 0, "notifications are not client lists");
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
