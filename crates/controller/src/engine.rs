//! Turns decoded informs, controller replies and AP logs into stored metrics,
//! events and the live view the API serves.
//!
//! The engine runs as one task that owns all mutable state; the API reads a
//! shared snapshot (`Live`) and subscribes to a broadcast of changes.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Set or clear clients' aliases and notes (None clears): one, or a bulk
    /// import. `only_if_unset` leaves existing aliases alone (for imports).
    SetAliases { ts: Ts, entries: Vec<AliasEdit>, only_if_unset: bool },
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
    /// Record an event raised elsewhere (e.g. active mode sending an upgrade, a
    /// client blocked from the UI, a channel plan applied).
    Note(Event),
    /// Drop everything apctl keeps about a forgotten AP.
    Forget { mac: Mac },
    /// Change the settings (apctl's copy of the controller settings), store
    /// them, and record the change; `done` gets the result.
    EditState { ts: Ts, what: String, edit: StateEdit, done: tokio::sync::oneshot::Sender<Result<(), String>> },
    /// Store the automatic-backup settings (JSON).
    SaveBackupSettings(String),
    /// Change the firmware upgrade queue; `done` gets how many upgrades were
    /// queued or cancelled.
    Firmware { op: crate::firmware::Op, done: tokio::sync::oneshot::Sender<usize> },
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

impl Event {
    /// An event about an AP.
    pub fn device(ts: Ts, kind: &'static str, mac: Mac, data: Value) -> Self {
        ev(ts, kind, Some(mac), None, data)
    }

    /// An event about a client.
    pub fn client(ts: Ts, kind: &'static str, client: Mac, data: Value) -> Self {
        ev(ts, kind, None, Some(client), data)
    }

    /// An event about the whole site.
    pub fn site(ts: Ts, kind: &'static str, data: Value) -> Self {
        ev(ts, kind, None, None, data)
    }
}

/// Messages pushed to live subscribers (the UI's WebSocket, serialised once
/// for all of them by `api::live_json`).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveMsg {
    Device { mac: Mac },
    Clients,
    Event(Event),
    /// A syslog line was stored: `{"type":"log","device_mac":...}`. The UI
    /// refetches the lines it shows, so the text is not sent along.
    Log { device_mac: Option<Mac> },
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
    /// The sample from its AP's last full inform, shared with that AP's snapshot.
    pub sample: Arc<ClientSample>,
    pub connected: bool,
    pub first_seen: Ts,
    pub last_seen: Ts,
}

/// Declares `Counters` with one atomic per name, serialised as plain numbers.
macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        /// Running totals since start. Atomics, shared by the engine and the
        /// live view, so counting a syslog line takes no lock.
        #[derive(Debug, Default)]
        pub struct Counters {
            $(pub $name: AtomicU64,)*
        }

        impl Serialize for Counters {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeStruct;
                let mut out = s.serialize_struct("Counters", [$(stringify!($name)),*].len())?;
                $(out.serialize_field(stringify!($name), &self.$name.load(Ordering::Relaxed))?;)*
                out.end()
            }
        }
    };
}

counters!(informs, notifications, log_errors, replies, config_pushes, decode_errors, logs, events);

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// A name and note the user gave a client.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Alias {
    pub alias: Option<String>,
    pub note: Option<String>,
}

/// A client's new alias and note, as given (trimmed by the engine; empty clears).
#[derive(Debug)]
pub struct AliasEdit {
    pub mac: Mac,
    pub alias: Option<String>,
    pub note: Option<String>,
}

#[derive(Default)]
pub struct Live {
    pub devices: BTreeMap<Mac, DeviceView>,
    /// User-given client names, including clients not seen in this run.
    pub aliases: HashMap<Mac, Alias>,
    pub clients: BTreeMap<Mac, ClientView>,
    /// Also held by the engine, which counts without taking the lock.
    pub counters: Arc<Counters>,
    /// For attributing syslog: an AP's `hash_id` and IP address.
    pub by_hash_id: HashMap<String, Mac>,
    pub by_ip: HashMap<String, Mac>,
    /// APs known from the database before their first inform in this process.
    pub known_devices: HashMap<Mac, KnownDevice>,
    /// Imported controller settings (contain secrets: never serialised).
    pub state: Option<Arc<Value>>,
    pub state_imported_at: Option<Ts>,
    /// Latest full inform per AP (capabilities and radios, for rendering).
    pub raw_informs: HashMap<Mac, Arc<Value>>,
    /// Firmware upgrades queued or in progress (one AP at a time).
    pub firmware: crate::firmware::Jobs,
    /// Commands waiting for each AP's next inform (restart, locate, kick...).
    pub commands: HashMap<Mac, std::collections::VecDeque<Value>>,
    /// APs told to flash their LED.
    pub locating: std::collections::HashSet<Mac>,
    /// APs to send their config again on the next inform.
    pub reprovision: std::collections::HashSet<Mac>,
    /// Quick scans (RF environment) asked of each AP and not finished yet.
    pub scans: HashMap<Mac, crate::channelai::Scan>,
    /// APs waiting for adoption, being adopted or being forgotten.
    pub adoption: crate::adopt::Adoption,
    /// Last config pushed to each AP (by the other controller or by apctl),
    /// unredacted. Only kept in memory; the database has a redacted copy.
    pub last_config: HashMap<Mac, PushedConfig>,
}

/// A config pushed to an AP.
#[derive(Debug, Clone, Default)]
pub struct PushedConfig {
    pub mgmt_cfg: String,
    /// Empty until a push with a `system_cfg` is seen (one can be management-only).
    pub system_cfg: String,
    pub cfgversion: Option<String>,
}

/// The last push stored for each AP, with its secrets masked.
pub fn stored_pushes(c: &rusqlite::Connection) -> rusqlite::Result<HashMap<Mac, PushedConfig>> {
    let mut stmt = c.prepare("SELECT mgmt_cfg, system_cfg, cfgversion, mac FROM device_config")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(3)?, stored_push_row(r)?)))?;
    let mut out = HashMap::new();
    for row in rows {
        let (mac, pushed) = row?;
        if let Ok(mac) = mac.parse() {
            out.insert(mac, pushed);
        }
    }
    Ok(out)
}

/// One AP's last stored push, with its secrets masked.
pub fn stored_push(c: &rusqlite::Connection, mac: &Mac) -> rusqlite::Result<Option<PushedConfig>> {
    use rusqlite::OptionalExtension;
    c.prepare_cached("SELECT mgmt_cfg, system_cfg, cfgversion FROM device_config WHERE mac = ?1")?.query_row([mac.to_string()], stored_push_row).optional()
}

fn stored_push_row(r: &rusqlite::Row) -> rusqlite::Result<PushedConfig> {
    Ok(PushedConfig { mgmt_cfg: r.get::<_, Option<String>>(0)?.unwrap_or_default(), system_cfg: r.get::<_, Option<String>>(1)?.unwrap_or_default(), cfgversion: r.get(2)? })
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

/// An unchanged device, client or neighbour row is written again at most this
/// often, to move its `last_seen` on; a changed one is written at once. The
/// database's `last_seen` (read at start, and for APs not reporting since)
/// can so lag the live view by this much.
const REFRESH_SECS: Ts = 60;
/// The same for an unchanged spectrum scan row and its `ts`.
const SPECTRUM_REFRESH_SECS: Ts = 3600;

/// What was last written of the rows rewritten on every inform, and when.
/// Empty at start, so each row is written on its first inform of a run.
#[derive(Default)]
struct Written {
    devices: HashMap<Mac, Ts>,
    clients: HashMap<Mac, Ts>,
    /// Per AP: each neighbour by BSSID.
    neighbors: HashMap<Mac, Rows<String, crate::model::NeighborSample>>,
    /// Per AP: each scanned channel by (radio, channel).
    spectrum: HashMap<Mac, Rows<(String, i64), crate::model::SpectrumSample>>,
}

/// Rows as last written, and when, by key.
type Rows<K, T> = HashMap<K, (T, Ts)>;

/// Whether a row last written at `at` (if ever) is due again at `ts`.
fn due(at: Option<&Ts>, ts: Ts, every: Ts) -> bool {
    at.is_none_or(|at| ts - at >= every || ts < *at)
}

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
    /// The live view's counters, updated without its lock.
    counters: Arc<Counters>,
    tx: broadcast::Sender<LiveMsg>,
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
    written: Written,
    /// Syslog hash_ids that none of the keys opened, and when that was tried.
    /// Time or new settings (which may hold new keys) clear an entry.
    syslog_unknown: HashMap<String, Ts>,
    /// Where alert-worthy events go: the alert watcher's own channel.
    alerts: Option<crate::alerts::Sink>,
}

/// How long a syslog hash_id no key opened is left untried.
const SYSLOG_RETRY_SECS: Ts = 300;

impl Engine {
    pub fn new(writer: Writer, keys: Arc<KeyStore>, live: SharedLive, tx: broadcast::Sender<LiveMsg>) -> Self {
        let counters = live.read().unwrap().counters.clone();
        Engine {
            writer, keys, renderer: None, live, counters, tx, radios: HashMap::new(), mcast_prev: HashMap::new(), bss_prev: HashMap::new(),
            logevents: Default::default(), isolated: HashMap::new(), last_prune: 0, written: Default::default(), syslog_unknown: HashMap::new(),
            alerts: None,
        }
    }

    /// Sends alert-worthy events to the alert watcher.
    pub fn set_alerts(&mut self, sink: crate::alerts::Sink) {
        self.alerts = Some(sink);
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
            // No row: nothing imported yet. Any other error fails the start rather
            // than running as if the settings were never imported.
            let state: Option<(String, i64)> = match c.query_row("SELECT json, imported_at FROM controller_state WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?))) {
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                r => Some(r?),
            };
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
            let sample = Arc::new(ClientSample { mac, ap_mac, bssid: bssid.unwrap_or_default(), essid, radio, hostname, ip, ..Default::default() });
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
            Input::DecodeError => bump(&self.counters.decode_errors),
            Input::SetAliases { ts, entries, only_if_unset } => self.set_aliases(ts, entries, only_if_unset),
            Input::SetState { ts, state } => self.set_state(ts, state),
            Input::ThreatFound { ts, kind, bssid, device_mac, data, notify } => {
                self.writer.exec(
                    Db::Config,
                    "INSERT OR IGNORE INTO network_threats (kind, bssid, first_reported) VALUES (?1, ?2, ?3)",
                    vec![Sql::Text(kind.into()), Sql::Text(bssid), Sql::Integer(ts)],
                );
                if notify {
                    self.emit(ev(ts, "network_threat", device_mac, None, data));
                }
            }
            Input::AlertsRead => self.writer.exec(Db::Config, "UPDATE alerts SET read = 1 WHERE read = 0", vec![]),
            Input::Note(e) => self.emit(e),
            Input::Forget { mac } => self.forget(mac),
            Input::EditState { ts, what, edit, done } => {
                let _ = done.send(self.edit_state(ts, what, edit));
            }
            Input::SaveBackupSettings(json) => {
                self.writer.exec(Db::Config, "INSERT OR REPLACE INTO backup_settings (id, json) VALUES (1, ?1)", vec![Sql::Text(json)])
            }
            Input::Firmware { op, done } => {
                let n = op.apply(&mut self.live.write().unwrap().firmware);
                let _ = done.send(n);
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

    fn emit(&self, ev: Event) {
        bump(&self.counters.events);
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
        if let Some(a) = &self.alerts {
            a.offer(&ev);
        }
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
                bump(&self.counters.decode_errors);
                return;
            }
        };
        let mac = snap.ap.mac;
        self.write_metrics(&snap);
        self.check_isolated(ts, &snap);

        // A handle of its own, so the engine's other fields stay usable while it is locked.
        let shared = self.live.clone();
        let mut live = shared.write().unwrap();
        if snap.has_vap_table {
            live.raw_informs.insert(mac, Arc::new(decoded.payload));
        }
        bump(&self.counters.informs);
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

        // The row changes with every inform (uptime, last_seen): written when
        // something else changed, or the AP came back, and otherwise once a
        // minute. Uptime and last_seen are always written together, so a
        // restart while apctl was away is still worked out right.
        let a = &snap.ap;
        let changed = prev.as_ref().is_none_or(|p| {
            let o = &p.snapshot.ap;
            !p.online || (&o.hostname, &o.model, &o.model_display, &o.version, &o.ip, &o.serial, &o.hash_id, &o.cfgversion)
                != (&a.hostname, &a.model, &a.model_display, &a.version, &a.ip, &a.serial, &a.hash_id, &a.cfgversion)
        });
        if changed || due(self.written.devices.get(&mac), ts, REFRESH_SECS) {
            self.written.devices.insert(mac, ts);
            self.write_device(&snap.ap);
        }
        // An upgrade we sent has landed: the AP reports the new version.
        if let Some(v) = &snap.ap.version
            && let Some(j) = live.firmware.version_seen(&mac, v)
        {
            events.push(ev(ts, "ap_upgraded", Some(mac), None, json!({ "from": j.from, "to": v, "custom": j.custom })));
        }
        for e in events {
            self.emit(e);
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

    fn update_clients(&mut self, live: &mut Live, ts: Ts, clients: &[Arc<ClientSample>]) {
        use std::collections::btree_map::Entry;
        for c in clients {
            // One lookup for the event, whether the row changed, and the update.
            let (event, changed) = match live.clients.entry(c.mac) {
                Entry::Occupied(mut e) => {
                    let view = e.get_mut();
                    let p = &view.sample;
                    let event = if !view.connected {
                        Some(connected_event(ts, c, false))
                    } else if p.ap_mac != c.ap_mac || p.bssid != c.bssid {
                        Some(ev(ts, "client_roamed", Some(c.ap_mac), Some(c.mac), json!({
                            "from": { "ap": p.ap_mac, "radio": p.radio, "channel": p.channel, "essid": p.essid, "signal": p.signal },
                            "to": { "ap": c.ap_mac, "radio": c.radio, "channel": c.channel, "essid": c.essid, "signal": c.signal },
                        })))
                    } else {
                        None
                    };
                    let changed = !view.connected
                        || (&p.hostname, &p.ip, p.ap_mac, &p.bssid, &p.essid, &p.radio) != (&c.hostname, &c.ip, c.ap_mac, &c.bssid, &c.essid, &c.radio);
                    *view = ClientView { sample: c.clone(), connected: true, first_seen: view.first_seen, last_seen: ts };
                    (event, changed)
                }
                Entry::Vacant(e) => {
                    e.insert(ClientView { sample: c.clone(), connected: true, first_seen: ts, last_seen: ts });
                    (Some(connected_event(ts, c, true)), true)
                }
            };
            // An unchanged row only to move last_seen on (see `REFRESH_SECS`).
            if changed || due(self.written.clients.get(&c.mac), ts, REFRESH_SECS) {
                self.written.clients.insert(c.mac, ts);
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
            }
            if let Some(e) = event {
                self.emit(e);
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
        let (radios, previous, state, inform) = {
            let mut live = self.live.write().unwrap();
            bump(&self.counters.replies);
            if let (Some(interval), Some(d)) = (p["interval"].as_i64(), live.devices.get_mut(&mac)) {
                d.interval = interval;
            }
            if p["_type"].as_str() != Some("setparam") {
                return;
            }
            bump(&self.counters.config_pushes);
            // The last push (unredacted), for the diffs; empty fields if none was seen.
            let previous = live.last_config.get(&mac).cloned().unwrap_or_default();
            let radios = live.devices.get(&mac).map(|d| d.snapshot.radios.clone()).unwrap_or_default();
            let has_system = !p["system_cfg"].as_str().unwrap_or(&previous.system_cfg).is_empty();
            let wanted = dry_run && has_system && self.renderer.is_some();
            let state = live.state.clone().filter(|_| wanted);
            let inform = state.as_ref().and_then(|_| live.raw_informs.get(&mac).cloned());
            (radios, previous, state, inform)
        };
        // A push can be management-only (e.g. after an LED change): it carries
        // mgmt_cfg alone, and the AP keeps its last full system_cfg.
        let field = |name: &str, prev: &str| p[name].as_str().unwrap_or(prev).to_string();
        let mgmt = field("mgmt_cfg", &previous.mgmt_cfg);
        let system = field("system_cfg", &previous.system_cfg);
        let mut data = serde_json::Map::new();
        data.insert("cfgversion".into(), p["cfgversion"].clone());
        for (field, old) in [("mgmt_cfg", &previous.mgmt_cfg), ("system_cfg", &previous.system_cfg)] {
            let Some(new) = p[field].as_str() else { continue };
            let summary = if old.is_empty() {
                json!({ "baseline": true, "lines": new.lines().count() })
            } else {
                let d = cfgdiff::diff(old, new);
                json!({ "added": d.added.len(), "removed": d.removed.len(), "changed": d.changed.len(), "diff": d.render("", true) })
            };
            data.insert(field.into(), summary);
        }
        // Names for numbered sections ("aaa.3" -> "Home WiFi (5 GHz)"), so the
        // config history can say what a change was about. Sections removed by
        // this push are only named in the previous config.
        if !system.is_empty() {
            let mut labels = if previous.system_cfg.is_empty() { Default::default() } else { section_labels(&previous.system_cfg, &radios) };
            labels.extend(section_labels(&system, &radios));
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
        live.last_config.insert(mac, PushedConfig { mgmt_cfg: mgmt, system_cfg: system, cfgversion });
        self.emit(ev(ts, "config_pushed", Some(mac), None, Value::Object(data)));
        if let Some(summary) = dry {
            self.emit(ev(ts, "dryrun_compared", Some(mac), None, summary));
        }
    }

    /// Stores an AP's section numbering in the settings, so later renders keep it.
    fn set_config_meta(&mut self, mac: Mac, meta: Value) {
        // Copied and serialised without the lock, as in `edit_state`.
        let Some(state) = self.live.read().unwrap().state.clone() else { return };
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
        self.live.write().unwrap().state = Some(Arc::new(next));
    }

    fn set_state(&mut self, ts: Ts, state: Value) {
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO controller_state (id, json, imported_at) VALUES (1, ?1, ?2)",
            vec![Sql::Text(state.to_string()), Sql::Integer(ts)],
        );
        let summary = crate::dryrun::summarize_state(&state);
        // The new settings may hold the syslog key of an AP given up on.
        self.syslog_unknown.clear();
        let mut live = self.live.write().unwrap();
        live.state = Some(Arc::new(state));
        live.state_imported_at = Some(ts);
        self.emit(ev(ts, "settings_imported", None, None, summary));
    }

    /// The engine is the only writer of the settings, so they cannot change
    /// between reading and swapping them in: the copy, the edit (which may hash
    /// a password) and the serialising run without holding the lock.
    fn edit_state(&mut self, ts: Ts, what: String, edit: StateEdit) -> Result<(), String> {
        let (current, imported_at) = {
            let live = self.live.read().unwrap();
            (live.state.clone(), live.state_imported_at.unwrap_or(ts))
        };
        let mut state = current.as_deref().cloned().ok_or("no settings imported yet")?;
        edit(&mut state)?;
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO controller_state (id, json, imported_at) VALUES (1, ?1, ?2)",
            vec![Sql::Text(state.to_string()), Sql::Integer(imported_at)],
        );
        self.live.write().unwrap().state = Some(Arc::new(state));
        self.syslog_unknown.clear();
        self.emit(ev(ts, "settings_changed", None, None, json!({ "what": what })));
        // The APs pick the change up now rather than at their next interval.
        crate::stun::poke_all(&self.live.read().unwrap());
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
        drop(live);
        self.radios.retain(|(m, _), _| *m != mac);
        self.isolated.remove(&mac);
        self.written.devices.remove(&mac);
        self.written.neighbors.remove(&mac);
        self.written.spectrum.remove(&mac);
        for sql in [
            "DELETE FROM devices WHERE mac = ?1",
            "DELETE FROM managed_devices WHERE mac = ?1",
            "DELETE FROM device_config WHERE mac = ?1",
            // What it heard: other APs' neighbours and scans are kept.
            "DELETE FROM neighbors WHERE ap_mac = ?1",
            "DELETE FROM spectrum WHERE ap_mac = ?1",
        ] {
            self.writer.exec(Db::Config, sql, vec![Sql::Text(mac.to_string())]);
        }
    }

    /// Each rename is its own event (a client's history shows it); the client
    /// list is announced once for the lot.
    fn set_aliases(&mut self, ts: Ts, entries: Vec<AliasEdit>, only_if_unset: bool) {
        let clean = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let mut changed = false;
        let mut live = self.live.write().unwrap();
        for AliasEdit { mac, alias, note } in entries {
            let (alias, note) = (clean(alias), clean(note));
            let old = live.aliases.get(&mac).cloned().unwrap_or_default();
            if (only_if_unset && old.alias.is_some()) || (old.alias == alias && old.note == note) {
                continue;
            }
            changed = true;
            if alias.is_none() && note.is_none() {
                live.aliases.remove(&mac);
                self.writer.exec(Db::Config, "DELETE FROM client_aliases WHERE mac = ?1", vec![Sql::Text(mac.to_string())]);
            } else {
                live.aliases.insert(mac, Alias { alias: alias.clone(), note: note.clone() });
                self.writer.exec(
                    Db::Config,
                    "INSERT OR REPLACE INTO client_aliases (mac, alias, note, updated) VALUES (?1, ?2, ?3, ?4)",
                    vec![Sql::Text(mac.to_string()), opt_text(alias.clone()), opt_text(note), Sql::Integer(ts)],
                );
            }
            if old.alias != alias {
                let ap = live.clients.get(&mac).map(|c| c.sample.ap_mac);
                self.emit(ev(ts, "client_renamed", ap, Some(mac), json!({ "from": old.alias, "to": alias })));
            }
        }
        drop(live);
        if changed {
            let _ = self.tx.send(LiveMsg::Clients);
        }
    }

    fn notification(&mut self, ts: Ts, p: &Value) {
        let Some(mac) = p["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else { return };
        let mut live = self.live.write().unwrap();
        bump(&self.counters.notifications);
        if let Some(d) = live.devices.get_mut(&mac) {
            d.last_seen = ts; // proof of life, but not a status report
        }
        match p["notif_reason"].as_str() {
            // The AP confirms it applied a pushed config.
            Some("setparam") => {
                let since_push = live.devices.get(&mac).and_then(|d| d.last_config_push).map(|t| ts - t);
                let data = json!({ "cfgversion": p["cfgversion"], "seconds_after_push": since_push });
                self.emit(ev(ts, "config_applied", Some(mac), None, data));
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
                    self.emit(ev(ts, k, Some(mac), None, n.clone()));
                }
            }
            // The AP starts an upgrade (ours, or one run on the AP itself).
            Some(r @ ("cmd-upgrade" | "cli-upgrade")) => {
                self.emit(ev(ts, "ap_upgrade_started", Some(mac), None, json!({ "by": if r == "cli-upgrade" { "the AP's command line" } else { "the controller" } })));
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
                self.emit(ev(ts, "ap_crash", Some(mac), None, json!({ "kind": kind, "source": reason, "lines": tail })));
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
                i(ms("assoc_delta")),
                i(ms("wpa_auth_delta")),
                i(ms("ip_delta")),
                opt_text(text("ip_assign_type")),
                i(num("dns_responses").map(|v| v as i64)),
                i(num("dns_timeouts").map(|v| v as i64)),
                i(num("avg_rssi").or_else(|| num("auth_rssi")).map(|v| v as i64)),
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
            self.emit(ev(ts, "client_connect_failed", Some(ap), Some(client), data));
        }
    }

    /// Decrypts a datagram from the AP with this `hash_id`: with the key of the
    /// AP known by it, else by trying each key.
    fn decrypt_syslog(&mut self, ts: Ts, payload: &[u8], hash_id: String, by_hash: Option<Mac>) -> anyhow::Result<(Mac, String)> {
        // Keys come from the settings (APs apctl adopted) and the key file.
        let state = self.live.read().unwrap().state.clone();
        if let Some(mac) = by_hash
            && let Some(key) = crate::adopt::syslog_key(state.as_deref(), &self.keys, &mac)
            && let Ok(text) = crate::syslog::decrypt(payload, mac, &key)
        {
            return Ok((mac, text));
        }
        // Syslog can arrive before the AP's first inform tells us its hash_id:
        // try each known key (there are few) and remember the one that works.
        // A hash_id no key opened is not tried again for a while: an AP whose
        // key apctl lacks sends a datagram per log line.
        if let Some(at) = self.syslog_unknown.get(&hash_id)
            && (*at..*at + SYSLOG_RETRY_SECS).contains(&ts)
        {
            anyhow::bail!("no syslog key for hash_id {hash_id} (none worked {}s ago)", ts - at);
        }
        for (mac, key) in crate::adopt::syslog_keys(state.as_deref(), &self.keys) {
            if let Ok(text) = crate::syslog::decrypt(payload, mac, &key) {
                self.syslog_unknown.remove(&hash_id);
                self.live.write().unwrap().by_hash_id.insert(hash_id, mac);
                return Ok((mac, text));
            }
        }
        // Bounded against made-up hash_ids; expired entries go at each tick.
        if self.syslog_unknown.len() < 10_000 {
            self.syslog_unknown.insert(hash_id.clone(), ts);
        }
        anyhow::bail!("no syslog key for hash_id {hash_id}")
    }

    fn datagram(&mut self, ts: Ts, src_ip: String, payload: &[u8]) {
        // Encrypted datagrams name their sender by hash_id; plain ones are passed through.
        let hash_id = crate::syslog::hash_id(payload);
        let (by_hash, by_ip) = {
            let live = self.live.read().unwrap();
            (hash_id.as_ref().and_then(|h| live.by_hash_id.get(h).copied()), live.by_ip.get(&src_ip).copied())
        };
        let result = match hash_id {
            Some(h) => self.decrypt_syslog(ts, payload, h, by_hash).map(|(mac, text)| (Some(mac), text)),
            None => crate::syslog::open(payload, |_| None),
        };
        match result {
            Ok((mac, text)) => {
                // Netconsole and multi-line messages can carry several lines.
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    self.log(crate::syslog::parse(ts, src_ip.clone(), mac.or(by_ip), line));
                }
            }
            Err(e) => {
                tracing::debug!("syslog from {src_ip}: {e:#}");
                bump(&self.counters.log_errors);
            }
        }
    }

    /// Upgrade progress from the AP: downloading, writing, or an error.
    fn upgrade_notice(&self, live: &mut Live, ts: Ts, mac: Mac, n: &Value) {
        let s = |k: &str| n[k].as_str().unwrap_or_default().to_string();
        match (n["up_type"].as_str(), n["up_stage"].as_str()) {
            (Some("UpgradeReady"), stage) => {
                use crate::firmware::JobState;
                let step = match stage {
                    Some("FWDownloading") => JobState::Downloading,
                    Some("FWCheckOK") => JobState::Writing,
                    _ => JobState::Preparing,
                };
                if let Some(j) = live.firmware.current_for(&mac) {
                    j.state = step;
                    // Re-arm the deadline as the official controller does on each step.
                    j.expires = Some(ts + 450);
                }
                self.emit(ev(ts, "ap_upgrade_progress", Some(mac), None, json!({ "step": step })));
            }
            (Some("UpgradeError"), _) => {
                let reason = s("reason");
                let detail = match reason.as_str() {
                    "FirmwareDownloadFailed" => format!("download failed (error: curl:{}, http:{})", n["curl_rc"], n["http_rc"]),
                    "FirmwareCheckFailed" => format!("firmware check failed (error: {})", n["rc"]),
                    "FWWriteFailed" => "writing the firmware failed".into(),
                    r => format!("failed ({r})"),
                };
                live.firmware.failed(&mac, &detail);
                self.emit(ev(ts, "ap_upgrade_failed", Some(mac), None, json!({ "reason": reason, "detail": detail })));
            }
            _ => {}
        }
    }

    /// Another AP's beacon flagged "isolated" (lost its uplink) that belongs to one
    /// of our APs: reported at most once an hour per AP.
    fn check_isolated(&mut self, ts: Ts, s: &Snapshot) {
        let num = |m: &Mac| -> u64 {
            let mut b = m.0;
            b[0] &= !0x02;
            b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x))
        };
        let flagged: Vec<&crate::model::NeighborSample> = s.neighbors.iter().filter(|n| n.is_isolated).collect();
        if flagged.is_empty() {
            return;
        }
        let ours: Vec<(Mac, u64)> = self.live.read().unwrap().devices.keys().map(|m| (*m, num(m))).collect();
        for n in flagged {
            let Ok(b) = n.bssid.parse::<Mac>().map(|m| num(&m)) else { continue };
            let Some((ap, _)) = ours.iter().find(|(_, x)| x.abs_diff(b) <= 16) else { continue };
            if self.isolated.get(ap).is_some_and(|t| ts - t < 3600) {
                continue;
            }
            self.isolated.insert(*ap, ts);
            let data = json!({ "heard_by": s.ap.mac.to_string(), "bssid": n.bssid, "signal": n.signal });
            self.emit(ev(ts, "ap_isolated", Some(*ap), None, data));
        }
    }

    fn log(&mut self, line: LogLine) {
        for f in self.logevents.feed(&line) {
            self.emit(ev(line.ts, f.kind, f.device, f.client, f.data));
        }
        bump(&self.counters.logs);
        self.writer.exec(
            Db::Logs,
            "INSERT INTO logs (ts, device_mac, src_ip, facility, severity, program, msg) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            vec![
                Sql::Integer(line.ts),
                opt_text(line.device_mac.map(|m| m.to_string())),
                Sql::Text(line.src_ip),
                i(line.facility),
                i(line.severity),
                opt_text(line.program),
                Sql::Text(line.msg),
            ],
        );
        let _ = self.tx.send(LiveMsg::Log { device_mac: line.device_mac });
    }

    /// Time-based transitions: APs going quiet and clients disappearing.
    fn tick(&mut self, now: Ts) {
        self.mcast_prev.retain(|_, (ts, ..)| *ts > now - 3600);
        self.syslog_unknown.retain(|_, at| (*at..*at + SYSLOG_RETRY_SECS).contains(&now));
        {
            let mut live = self.live.write().unwrap();
            if let Some(mac) = live.firmware.expired(now)
                && let Some(j) = live.firmware.failed(&mac, "it did not come back with the new firmware in time")
            {
                let data = json!({ "reason": "timed out", "detail": "it did not come back with the new firmware in time", "target": j.target });
                self.emit(ev(now, "ap_upgrade_failed", Some(mac), None, data));
            }
        }
        for f in self.logevents.tick(now) {
            self.emit(ev(now, f.kind, f.device, f.client, f.data));
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
            self.emit(e);
        }
        // Clients gone longer than the database keeps them (see `store::maintenance`).
        if now - self.last_prune >= 3600 {
            self.last_prune = now;
            let cutoff = now - store::CLIENT_RETENTION;
            let Live { clients, aliases, .. } = &mut *live;
            let before = clients.len();
            clients.retain(|mac, c| c.last_seen >= cutoff || aliases.contains_key(mac));
            changed |= clients.len() != before;
            self.written.clients.retain(|mac, _| clients.contains_key(mac));
        }
        drop(live);
        for mac in offline {
            let _ = self.tx.send(LiveMsg::Device { mac });
        }
        if changed {
            let _ = self.tx.send(LiveMsg::Clients);
        }
    }

    /// The AP's row in `devices`, as of the inform at `a.ts`.
    fn write_device(&self, a: &crate::model::ApSample) {
        self.writer.exec(
            Db::Config,
            "INSERT INTO devices (mac, hostname, model, model_display, version, ip, serial, hash_id, first_seen, last_seen, uptime, cfgversion, online)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11, 1)
             ON CONFLICT (mac) DO UPDATE SET hostname = excluded.hostname, model = excluded.model, model_display = excluded.model_display,
               version = excluded.version, ip = excluded.ip, serial = excluded.serial, hash_id = excluded.hash_id,
               last_seen = excluded.last_seen, uptime = excluded.uptime, cfgversion = excluded.cfgversion, online = 1",
            vec![
                Sql::Text(a.mac.to_string()),
                opt_text(a.hostname.clone()),
                opt_text(a.model.clone()),
                opt_text(a.model_display.clone()),
                opt_text(a.version.clone()),
                opt_text(a.ip.clone()),
                opt_text(a.serial.clone()),
                opt_text(a.hash_id.clone()),
                Sql::Integer(a.ts),
                i(a.uptime),
                opt_text(a.cfgversion.clone()),
            ],
        );
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
        // Scan results repeat in every inform until the next scan: an unchanged
        // neighbour is written once a minute (last_seen), an unchanged spectrum
        // row once an hour. What the AP no longer reports is forgotten here.
        let mut before = self.written.neighbors.remove(&s.ap.mac).unwrap_or_default();
        let mut now = HashMap::with_capacity(s.neighbors.len());
        for n in &s.neighbors {
            match before.remove(&n.bssid) {
                Some((old, at)) if old == *n && !due(Some(&at), ts, REFRESH_SECS) => {
                    now.insert(n.bssid.clone(), (old, at));
                    continue;
                }
                _ => {
                    now.insert(n.bssid.clone(), (n.clone(), ts));
                }
            }
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
        self.written.neighbors.insert(s.ap.mac, now);
        let mut before = self.written.spectrum.remove(&s.ap.mac).unwrap_or_default();
        let mut now = HashMap::with_capacity(s.spectrum.len());
        for c in &s.spectrum {
            let key = (c.radio.clone(), c.channel);
            match before.remove(&key) {
                Some((old, at)) if old == *c && !due(Some(&at), ts, SPECTRUM_REFRESH_SECS) => {
                    now.insert(key, (old, at));
                    continue;
                }
                _ => {
                    now.insert(key, (c.clone(), ts));
                }
            }
            self.writer.exec(
                Db::Config,
                "INSERT OR REPLACE INTO spectrum (ap_mac, radio, channel, width, utilization, interference, other_bss_count, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vec![mac(), Sql::Text(c.radio.clone()), Sql::Integer(c.channel), i(c.width), i(c.utilization), i(c.interference), i(c.other_bss_count), Sql::Integer(ts)],
            );
        }
        self.written.spectrum.insert(s.ap.mac, now);
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
        radios.iter().find(|r| r.name.as_deref() == Some(phy)).map(|r| crate::settings::band_name(&r.radio))
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

/// `new`: never seen before (not even in an earlier run).
fn connected_event(ts: Ts, c: &ClientSample, new: bool) -> Event {
    ev(ts, "client_connected", Some(c.ap_mac), Some(c.mac), json!({
        "essid": c.essid, "radio": c.radio, "channel": c.channel, "signal": c.signal,
        "hostname": c.hostname, "ip": c.ip, "new": new,
    }))
}

fn f(v: Option<f64>) -> Sql {
    v.map_or(Sql::Null, Sql::Real)
}

fn i(v: Option<i64>) -> Sql {
    v.map_or(Sql::Null, Sql::Integer)
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
    fn unchanged_rows_are_written_once_a_minute() {
        let dir = std::env::temp_dir().join(format!("apctl-written-{}-{}", std::process::id(), rand_suffix()));
        let (store, writer) = store::Store::open(&dir).unwrap();
        let (tx, _rx) = broadcast::channel(1024);
        let mut e = Engine::new(writer.clone(), Default::default(), Default::default(), tx);
        let feed = |e: &mut Engine, ts: Ts, name: &str| {
            let mut p = inform(AP1, 1000 + ts, &[(C1, "b1")]);
            p["hostname"] = json!(name);
            p["vap_table"][0]["sta_table"][0]["hostname"] = json!(name);
            e.handle(Input::Inform { ts, peer: "x".into(), decoded: decoded(p) });
        };
        let stored = |sql: &'static str| -> (i64, String) {
            assert!(writer.flush(std::time::Duration::from_secs(5)));
            store.read(Db::Config, |c| Ok(c.query_row(sql, [], |r| Ok((r.get(0)?, r.get(1)?)))?)).unwrap()
        };
        let (device, client) = ("SELECT last_seen, hostname FROM devices", "SELECT last_seen, hostname FROM clients");
        feed(&mut e, 0, "a");
        feed(&mut e, 15, "a");
        assert_eq!((stored(device), stored(client)), ((0, "a".into()), (0, "a".into())), "unchanged: not written again yet");
        feed(&mut e, 30, "b");
        assert_eq!((stored(device), stored(client)), ((30, "b".into()), (30, "b".into())), "a change is written at once");
        feed(&mut e, 45, "b");
        assert_eq!(stored(device).0, 30);
        feed(&mut e, 90, "b");
        assert_eq!((stored(device).0, stored(client).0), (90, 90), "last_seen moves on once a minute");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn aliases_are_set_cleared_and_imported_without_overwriting() {
        let mut h = harness();
        let mac: Mac = C1.parse().unwrap();
        let set = |h: &mut Harness, alias: Option<&str>, only_if_unset: bool| {
            h.engine.handle(Input::SetAliases { ts: 1, entries: vec![AliasEdit { mac, alias: alias.map(str::to_string), note: None }], only_if_unset });
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
    fn syslog_keys_are_tried_once_per_unknown_sender() {
        let mut keys = KeyStore::default();
        keys.insert_syslog(AP1, &hex::encode([7u8; 32])).unwrap();
        let dir = std::env::temp_dir().join(format!("apctl-syslog-{}-{}", std::process::id(), rand_suffix()));
        let (_store, writer) = store::Store::open(&dir).unwrap();
        let (tx, _rx) = broadcast::channel(1024);
        let live: SharedLive = Default::default();
        let mut e = Engine::new(writer, Arc::new(keys), live.clone(), tx);
        let send = |e: &mut Engine, ts: Ts, hash_id: u8, key: u8| {
            let payload = crate::syslog::tests::seal([hash_id; 8], [key; 32], "<14>hostapd: hello");
            e.handle(Input::Datagram { ts, src_ip: "192.0.2.1".into(), payload });
        };
        let logs = || live.read().unwrap().counters.logs.load(Ordering::Relaxed);
        // An AP whose key apctl lacks: remembered, not tried again for a while.
        send(&mut e, 0, 1, 9);
        assert_eq!(e.syslog_unknown.get(&hex::encode([1u8; 8])), Some(&0));
        send(&mut e, 10, 1, 9);
        assert_eq!(e.syslog_unknown.get(&hex::encode([1u8; 8])), Some(&0), "not retried within the window");
        e.handle(Input::Tick(SYSLOG_RETRY_SECS));
        assert!(e.syslog_unknown.is_empty(), "expired");
        // A known key under a hash_id not seen yet: found by trial and remembered.
        send(&mut e, 20, 2, 7);
        assert_eq!(logs(), 1);
        assert_eq!(live.read().unwrap().by_hash_id.get(&hex::encode([2u8; 8])), Some(&AP1.parse().unwrap()));
        // An AP apctl adopted: its key is in the settings only.
        send(&mut e, 30, 3, 5);
        assert_eq!(logs(), 1);
        let ap2 = "02:00:00:00:00:02";
        e.set_state(31, json!({ "devices": [{ "mac": ap2, "syslog_key": hex::encode([5u8; 32]) }] }));
        assert!(e.syslog_unknown.is_empty(), "new settings, new keys: tried again");
        send(&mut e, 32, 3, 5);
        assert_eq!(logs(), 2);
        assert_eq!(live.read().unwrap().by_hash_id.get(&hex::encode([3u8; 8])), Some(&ap2.parse().unwrap()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_bulk_import_announces_the_client_list_once() {
        let mut h = harness();
        let edit = |mac: &str, alias: &str| AliasEdit { mac: mac.parse().unwrap(), alias: Some(alias.into()), note: None };
        let entries = vec![edit(C1, "Speaker"), edit("02:00:00:00:01:02", "Printer"), edit("02:00:00:00:01:03", "")];
        h.engine.handle(Input::SetAliases { ts: 1, entries, only_if_unset: true });
        let msgs: Vec<LiveMsg> = std::iter::from_fn(|| h.rx.try_recv().ok()).collect();
        let renames = msgs.iter().filter(|m| matches!(m, LiveMsg::Event(e) if e.kind == "client_renamed")).count();
        let lists = msgs.iter().filter(|m| matches!(m, LiveMsg::Clients)).count();
        assert_eq!((renames, lists), (2, 1), "{msgs:?}");
        assert_eq!(h.live.read().unwrap().aliases.len(), 2);
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
        assert_eq!(live.counters.notifications.load(Ordering::Relaxed), 4);
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
