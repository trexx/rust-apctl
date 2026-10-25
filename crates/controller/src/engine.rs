//! Turns decoded informs, controller replies and AP logs into stored metrics,
//! events and the live view the API serves.
//!
//! The engine runs as one task that owns all mutable state; the API reads a
//! shared snapshot (`Live`) and subscribes to a broadcast of changes.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use inform::Mac;
use rusqlite::types::Value as Sql;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use wire::cfgdiff;
use wire::decode::Decoded;
use wire::keys::KeyStore;

use crate::model::{self, ClientSample, Snapshot, Ts};
use crate::store::{self, Db, PushedConfig, Write, Writer};

/// A client is considered gone once no full inform has listed it for this long.
pub const CLIENT_GRACE_SECS: Ts = 60;
/// An AP is offline after missing this many of its inform intervals.
pub const OFFLINE_INTERVALS: Ts = 4;
/// Nor sooner than this after its last inform, however short its interval.
const MIN_OFFLINE_SECS: Ts = 60;
const DEFAULT_INTERVAL: Ts = 15;

/// A change to the settings, applied by the engine: it edits, then says what
/// it changed in words (for the event and the config history).
pub type StateEdit = Box<dyn FnOnce(&mut Value) -> Result<String, String> + Send>;

pub enum Input {
    Inform { ts: Ts, peer: IpAddr, decoded: Decoded },
    /// Replace the imported controller settings (an `informdump import` snapshot).
    SetState { ts: Ts, state: Value },
    /// Active mode: the section numbering a render allocated for an AP.
    SetConfigMeta { mac: Mac, meta: Value },
    /// Active mode: apctl itself sent this reply to an AP (a `setparam`, or a
    /// reply that sets its inform interval).
    Replied { ts: Ts, mac: Mac, payload: Value },
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
    ThreatFound { ts: Ts, kind: crate::threats::Kind, bssid: String, device_mac: Option<Mac>, data: Value, notify: bool },
    /// Record an event raised elsewhere (e.g. active mode sending an upgrade, a
    /// client blocked from the UI, a channel plan applied).
    Note(Event),
    /// Drop everything apctl keeps about a forgotten AP.
    Forget { ts: Ts, mac: Mac },
    /// Change the settings (apctl's copy of the controller settings), store
    /// them, and record the change; `done` gets what changed, or the refusal.
    EditState { ts: Ts, edit: StateEdit, done: tokio::sync::oneshot::Sender<Result<String, String>> },
    /// Change the firmware upgrade queue; `done` gets how many upgrades were
    /// queued or cancelled.
    Firmware { op: crate::firmware::Op, done: tokio::sync::oneshot::Sender<usize> },
    /// Nothing to do: wakes an idle engine at exit, to see that it is closing.
    Wake,
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

crate::model::named_enum! {
    /// What an event is about. The names are stored with each event and read
    /// by the UI, so a name never changes once used.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum EventKind {
        ApSeen = "ap_seen", ApOnline = "ap_online", ApOffline = "ap_offline", ApRestarted = "ap_restarted", ApFirmwareChanged = "ap_firmware_changed",
        ApIsolated = "ap_isolated", ApCrash = "ap_crash", ApProcessRestarted = "ap_process_restarted", ApScanDone = "ap_scan_done", ApEvent = "ap_event",
        DfsRadar = "dfs_radar", RogueAp = "rogue_ap", NetworkThreat = "network_threat", RadioChanged = "radio_changed",
        ConfigPushed = "config_pushed", ConfigApplied = "config_applied", DryrunCompared = "dryrun_compared",
        ApUpgradeSent = "ap_upgrade_sent", ApUpgradeStarted = "ap_upgrade_started", ApUpgradeProgress = "ap_upgrade_progress", ApUpgradeFailed = "ap_upgrade_failed",
        ApUpgraded = "ap_upgraded",
        ApPending = "ap_pending", ApAdopting = "ap_adopting", ApAdopted = "ap_adopted", ApForgotten = "ap_forgotten", ApHostKeyMismatch = "ap_host_key_mismatch",
        ApRestartRequested = "ap_restart_requested", ApProvisionRequested = "ap_provision_requested",
        ClientConnected = "client_connected", ClientDisconnected = "client_disconnected", ClientConnectFailed = "client_connect_failed", ClientRoamed = "client_roamed",
        ClientRenamed = "client_renamed", ClientKicked = "client_kicked", ClientSteered = "client_steered", ClientWrongPassword = "client_wrong_password",
        ClientExperience = "client_experience", ClientReconnectRequested = "client_reconnect_requested", ClientBlocked = "client_blocked",
        ClientUnblocked = "client_unblocked",
        SettingsImported = "settings_imported", SettingsChanged = "settings_changed", ChannelPlan = "channel_plan",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub ts: Ts,
    pub kind: EventKind,
    pub device_mac: Option<Mac>,
    pub client_mac: Option<Mac>,
    pub data: Value,
}

impl Event {
    /// An event about an AP.
    pub fn device(ts: Ts, kind: EventKind, mac: Mac, data: Value) -> Self {
        Event { ts, kind, device_mac: Some(mac), client_mac: None, data }
    }

    /// An event about a client.
    pub fn client(ts: Ts, kind: EventKind, client: Mac, data: Value) -> Self {
        Event { ts, kind, device_mac: None, client_mac: Some(client), data }
    }

    /// An event about a client on an AP.
    pub fn client_on(ts: Ts, kind: EventKind, ap: Mac, client: Mac, data: Value) -> Self {
        Event { ts, kind, device_mac: Some(ap), client_mac: Some(client), data }
    }

    /// An event about the whole site.
    pub fn site(ts: Ts, kind: EventKind, data: Value) -> Self {
        Event { ts, kind, device_mac: None, client_mac: None, data }
    }
}

/// Messages pushed to live subscribers (the UI's WebSocket, serialised once
/// for all of them by `api::live_json`).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveMsg {
    Device { mac: Mac },
    Clients,
    /// An event was stored: `{"type":"event","kind":...,"device_mac":...,"client_mac":...}`.
    /// The UI refetches the event lists that show it, so the rest is not sent along.
    Event(EventHead),
    /// Syslog lines were stored: `{"type":"log","device_mac":...}`, at most
    /// once a second per AP. The UI refetches the lines it shows, so the text
    /// is not sent along.
    Log { device_mac: Option<Mac> },
    /// Boxed: an alert is far larger than the other messages.
    Alert(Box<crate::alerts::AlertMsg>),
}

/// What the UI is told of an event (see `LiveMsg::Event`). Without the data,
/// which can be large (a crash dump), as every subscriber gets its own copy.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct EventHead {
    pub kind: EventKind,
    pub device_mac: Option<Mac>,
    pub client_mac: Option<Mac>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceView {
    pub snapshot: Snapshot,
    pub online: bool,
    pub first_seen: Ts,
    pub last_seen: Ts,
    /// The address its last inform came from; none for an AP known from the database only.
    #[serde(serialize_with = "peer_or_empty")]
    pub peer: Option<IpAddr>,
    /// Inform interval most recently requested by the controller.
    pub interval: Ts,
    /// Time of the last inform that included the client list.
    pub last_full_inform: Ts,
    pub last_config_push: Option<Ts>,
}

/// A device view's `peer` as its address, or "" for none.
fn peer_or_empty<S: serde::Serializer>(peer: &Option<IpAddr>, s: S) -> Result<S::Ok, S::Error> {
    match peer {
        Some(ip) => s.collect_str(ip),
        None => s.serialize_str(""),
    }
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

counters!(informs, notifications, log_errors, replies, config_pushes, decode_errors, logs, events, syslog_dropped);

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
    /// The MACs of the connected clients, kept by the engine with `clients`,
    /// so that no reader need walk the year of clients to find them.
    pub connected: std::collections::BTreeSet<Mac>,
    /// Also held by the engine, which counts without taking the lock.
    pub counters: Arc<Counters>,
    /// For attributing syslog: an AP's `hash_id` (see `syslog::hash_id`) and IP address.
    pub by_hash_id: HashMap<u64, Mac>,
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
    /// Shared, so readers copy a pointer under the lock, not the config.
    pub last_config: HashMap<Mac, Arc<PushedConfig>>,
    /// The STUN socket (active mode), which connection requests are sent from.
    pub stun: Option<Arc<tokio::net::UdpSocket>>,
    /// Active mode: drops what it keeps of a forgotten AP (its config digest
    /// and AES-GCM pin). Called by the engine without the live view's lock.
    pub forget_managed: Option<ForgetFn>,
}

/// See `Live::forget_managed`.
pub type ForgetFn = Arc<dyn Fn(&Mac) + Send + Sync>;

impl Live {
    /// Records the AP's hash_id and address, for attributing syslog. An address
    /// or hash_id the AP no longer has is dropped: plain syslog from whichever
    /// host gets the address next is not the AP's.
    fn attribute(&mut self, a: &crate::model::ApSample) {
        if let Some(h) = a.hash_id.as_deref().and_then(crate::syslog::parse_hash_id) {
            self.set_hash_id(h, a.mac);
        }
        if let Some(ip) = &a.ip
            && self.by_ip.get(ip) != Some(&a.mac)
        {
            self.by_ip.retain(|_, m| *m != a.mac);
            self.by_ip.insert(ip.clone(), a.mac);
        }
    }

    /// Records `h` as the AP's syslog hash_id, its only one: one it had before
    /// is dropped.
    fn set_hash_id(&mut self, h: u64, mac: Mac) {
        if self.by_hash_id.get(&h) != Some(&mac) {
            self.by_hash_id.retain(|_, m| *m != mac);
            self.by_hash_id.insert(h, mac);
        }
    }

    /// The connected clients, by MAC.
    pub fn connected_clients(&self) -> impl Iterator<Item = (&Mac, &ClientView)> {
        self.connected.iter().filter_map(|m| self.clients.get_key_value(m)).filter(|(_, c)| c.connected)
    }

    /// Adds or replaces a client, keeping `connected` with it.
    pub fn put_client(&mut self, c: ClientView) {
        if c.connected {
            self.connected.insert(c.sample.mac);
        } else {
            self.connected.remove(&c.sample.mac);
        }
        self.clients.insert(c.sample.mac, c);
    }

    /// Fails unless `connected` holds exactly the clients marked connected.
    #[cfg(test)]
    pub fn assert_connected(&self) {
        let marked: std::collections::BTreeSet<Mac> = self.clients.iter().filter(|(_, c)| c.connected).map(|(m, _)| *m).collect();
        assert_eq!(self.connected, marked, "the connected set is out of step with the clients");
    }

    /// Drops what the live view keeps about a forgotten AP, except its clients
    /// (the engine disconnects those, with events). Every field is named, so a
    /// field added to `Live` has to be decided on here.
    fn forget_ap(&mut self, mac: &Mac) {
        let Live {
            devices, aliases: _, clients: _, connected: _, counters: _, by_hash_id, by_ip, known_devices, state: _, state_imported_at: _, raw_informs, firmware, commands,
            locating, reprovision, scans, adoption, last_config, stun: _, forget_managed: _,
        } = self;
        devices.remove(mac);
        // Also what was restored from the database, or it could still be reported offline.
        known_devices.remove(mac);
        by_hash_id.retain(|_, m| m != mac);
        by_ip.retain(|_, m| m != mac);
        raw_informs.remove(mac);
        last_config.remove(mac);
        adoption.forgetting.remove(mac);
        adoption.adopting.remove(mac);
        // Nothing queued for it may reach it if it is adopted again.
        firmware.remove(mac);
        commands.remove(mac);
        locating.remove(mac);
        reprovision.remove(mac);
        scans.remove(mac);
    }
}

/// What the database remembers about an AP from a previous run: what tells
/// what happened while apctl was away, and what the device list shows of it.
#[derive(Debug, Clone)]
pub struct KnownDevice {
    pub first_seen: Ts,
    pub last_seen: Ts,
    pub uptime: Option<i64>,
    pub version: Option<String>,
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub model_display: Option<String>,
    pub ip: Option<String>,
    pub serial: Option<String>,
    /// Reported offline (an `ap_offline` event), and not back since.
    pub offline: bool,
}

pub type SharedLive = Arc<RwLock<Live>>;

type McastTypes = BTreeMap<Cow<'static, str>, crate::model::McastCounts>;

/// A sample's multicast counters by traffic type (none if it has none).
fn mcast_types(c: &ClientSample) -> &McastTypes {
    static NONE: McastTypes = BTreeMap::new();
    c.multicast.as_ref().map_or(&NONE, |m| &m.types)
}

/// Channel, width and power of one radio.
type RadioSettings = (Option<i64>, Option<i64>, Option<i64>);

/// An unchanged device, client or neighbour row is written again at most this
/// often, to move its `last_seen` on; a changed one is written at once. The
/// database's `last_seen` (read at start, and for APs not reporting since)
/// can so lag the live view by this much.
const REFRESH_SECS: Ts = 60;
/// The same for an unchanged spectrum scan row and its `ts`.
const SPECTRUM_REFRESH_SECS: Ts = 3600;
/// The longest interval a multicast rate is worked out over: a client's or a
/// network's sample further apart from the one before gives no rate. A raw
/// sample in `mcast_stats` so covers at most this long before it.
pub(crate) const MCAST_GAP: Ts = 120;

/// What was last written of the rows rewritten on every inform, and when.
/// Empty at start, so each row is written on its first inform of a run.
#[derive(Default)]
struct Written {
    devices: HashMap<Mac, Ts>,
    /// Connected clients only: one that reconnects is written anyway.
    clients: HashMap<Mac, Ts>,
    /// Per AP: each neighbour by BSSID.
    neighbors: HashMap<Mac, Rows<String, crate::model::NeighborSample>>,
    /// Per AP and radio: each scanned channel.
    spectrum: HashMap<Mac, HashMap<String, Rows<i64, crate::model::SpectrumSample>>>,
}

/// Rows by key.
type Rows<K, T> = HashMap<K, Row<T>>;

/// A row as last written with the stamp it was written with, and when it was
/// last reported.
struct Row<T> {
    value: T,
    written: Ts,
    seen: Ts,
}

impl<T: PartialEq> Row<T> {
    fn new(value: T, ts: Ts, stamp: Ts) -> Self {
        Row { value, written: stamp, seen: ts }
    }

    /// Records `value` as reported at `ts`, with `stamp` the time its row
    /// carries (the report's time, or for a neighbour when the scan heard it);
    /// true if it is to be written: it changed, or its stamp moved `every`
    /// seconds either way since it was last written. A neighbour's stamp may
    /// come a second earlier than the last one, from the AP's rounding.
    fn report(&mut self, value: T, ts: Ts, stamp: Ts, every: Ts) -> bool {
        self.seen = ts;
        if self.value == value && (stamp - self.written).abs() < every {
            return false;
        }
        self.value = value;
        self.written = stamp;
        true
    }
}

/// Records `value` as reported under its `key` at `ts` with `stamp` (see
/// `Row::report`): its row if it is to be written, as one new or changed, or
/// due again. The row keeps the value; the key is copied only for a new row.
fn report<K, Q, T>(rows: &mut Rows<K, T>, value: T, key: impl Fn(&T) -> &Q, ts: Ts, stamp: Ts, every: Ts) -> Option<&T>
where
    K: std::borrow::Borrow<Q> + Eq + std::hash::Hash,
    Q: ToOwned<Owned = K> + Eq + std::hash::Hash + ?Sized,
    T: PartialEq,
{
    if rows.contains_key(key(&value)) {
        let row = rows.get_mut(key(&value)).expect("present");
        return row.report(value, ts, stamp, every).then_some(&row.value);
    }
    let k = key(&value).to_owned();
    Some(&rows.entry(k).or_insert(Row::new(value, ts, stamp)).value)
}

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
    /// Per AP and radio.
    radios: HashMap<Mac, HashMap<String, RadioTrack>>,
    /// Each client's last sample with multicast counters (and the BSSID they came from).
    mcast_prev: HashMap<Mac, (Ts, Arc<ClientSample>)>,
    /// Each BSSID's last "delivered to clients" counters. The AP reports these
    /// per network, repeated identically in every client's block.
    bss_prev: HashMap<String, (Ts, Arc<ClientSample>)>,
    /// Events found in syslog lines.
    logevents: crate::logevents::LogEvents,
    /// When the beacon each AP was last reported isolated for was heard.
    isolated: HashMap<Mac, Ts>,
    /// When long-gone clients were last dropped from the live view.
    last_prune: Ts,
    written: Written,
    /// Syslog hash_ids that none of the keys opened, and when that was tried.
    /// Time or new settings (which may hold new keys) clear an entry. An AP
    /// whose informs gave its hash_id is tried with its own key first, so an
    /// entry (even from a made-up datagram) holds up only an AP not heard yet.
    syslog_unknown: HashMap<u64, Ts>,
    /// The syslog keys, ready to decrypt with.
    syslog_ciphers: crate::syslog::Ciphers,
    /// Per AP: the second its stored syslog lines were last announced, and
    /// whether more came in that second (see `log`).
    logs_announced: HashMap<Option<Mac>, (Ts, bool)>,
    /// Where alert-worthy events go: the alert watcher's own channel.
    alerts: Option<crate::alerts::Sink>,
    /// The time of this run's first tick (the capture's time in shadow mode).
    first_tick: Option<Ts>,
    /// Each AP's last push as stored before this run (its secrets masked): what
    /// the pushes to it are compared with, each field until a push carries it.
    stored_config: HashMap<Mac, PushedConfig>,
}

/// How long a syslog hash_id no key opened is left untried.
const SYSLOG_RETRY_SECS: Ts = 300;
/// At most this many such hash_ids remembered; past it, new ones are not tried.
const SYSLOG_UNKNOWN_MAX: usize = 10_000;

impl Engine {
    pub fn new(writer: Writer, keys: Arc<KeyStore>, live: SharedLive, tx: broadcast::Sender<LiveMsg>) -> Self {
        let counters = live.read().unwrap().counters.clone();
        Engine {
            writer, keys, renderer: None, live, counters, tx, radios: HashMap::new(), mcast_prev: HashMap::new(), bss_prev: HashMap::new(),
            logevents: Default::default(), isolated: HashMap::new(), last_prune: 0, written: Default::default(), syslog_unknown: HashMap::new(),
            syslog_ciphers: Default::default(), logs_announced: HashMap::new(), alerts: None, first_tick: None, stored_config: HashMap::new(),
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
    /// not report every client as newly connected, and each AP's last push, so
    /// the first one after it says what it changed.
    pub fn restore(&mut self, store: &store::Store) -> anyhow::Result<()> {
        let (devices, clients, aliases, state, pushes) = store.read(Db::Config, |c| {
            let mut stmt = c.prepare("SELECT mac, first_seen, last_seen, uptime, version, hash_id, ip, hostname, model, model_display, serial, offline FROM devices")?;
            let devices = stmt
                .query_map([], |r| {
                    let known = KnownDevice {
                        first_seen: r.get::<_, Option<i64>>(1)?.unwrap_or(0), last_seen: r.get::<_, Option<i64>>(2)?.unwrap_or(0), uptime: r.get(3)?, version: r.get(4)?,
                        ip: r.get(6)?, hostname: r.get(7)?, model: r.get(8)?, model_display: r.get(9)?, serial: r.get(10)?, offline: r.get::<_, i64>(11)? != 0,
                    };
                    Ok((r.get::<_, String>(0)?, known, r.get::<_, Option<String>>(5)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut stmt = c.prepare("SELECT mac, hostname, ip, first_seen, last_seen, ap_mac, bssid, essid, radio, connected FROM clients")?;
            // A row whose MACs do not parse is no client to restore.
            let clients = stmt
                .query_map([], |r| {
                    let (Ok(mac), Some(Ok(ap_mac))) = (r.get::<_, String>(0)?.parse::<Mac>(), r.get::<_, Option<String>>(5)?.map(|a| a.parse::<Mac>())) else { return Ok(None) };
                    let sample = ClientSample { mac, ap_mac, hostname: r.get(1)?, ip: r.get(2)?, bssid: r.get::<_, Option<String>>(6)?.unwrap_or_default(), essid: r.get(7)?, radio: r.get(8)?, ..Default::default() };
                    Ok(Some(ClientView {
                        sample: Arc::new(sample), connected: r.get::<_, i64>(9)? != 0, first_seen: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                        last_seen: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    }))
                })?
                .filter_map(Result::transpose)
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
            Ok((devices, clients, aliases, state, store::stored_pushes(c)?))
        })?;
        self.stored_config = pushes;
        let mut live = self.live.write().unwrap();
        for (mac, known, hash_id) in devices {
            let Ok(mac) = mac.parse::<Mac>() else { continue };
            if let Some(h) = hash_id.as_deref().and_then(crate::syslog::parse_hash_id) {
                live.set_hash_id(h, mac);
            }
            if let Some(ip) = &known.ip {
                live.by_ip.insert(ip.clone(), mac);
            }
            live.known_devices.insert(mac, known);
        }
        let n_clients = clients.len();
        for c in clients {
            live.put_client(c);
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
        // An AP stored as offline is unavailable to the clients locked to it,
        // whatever the settings were saved (or restored from a backup) with.
        let presence = presence(&live);
        drop(live);
        self.set_fixed_ap_available(presence);
        Ok(())
    }

    pub fn handle(&mut self, input: Input) {
        match input {
            Input::Inform { ts, peer, decoded } => self.inform(ts, peer, decoded),
            Input::Reply { ts, mac, decoded } => self.reply(ts, mac, decoded.payload, true),
            Input::Replied { ts, mac, payload } => self.reply(ts, mac, payload, false),
            Input::SetConfigMeta { mac, meta } => self.set_config_meta(mac, meta),
            Input::Datagram { ts, src_ip, payload } => self.datagram(ts, &src_ip, &payload),
            Input::Tick(now) => self.tick(now),
            Input::DecodeError => bump(&self.counters.decode_errors),
            Input::SetAliases { ts, entries, only_if_unset } => self.set_aliases(ts, entries, only_if_unset),
            Input::SetState { ts, state } => self.set_state(ts, state),
            Input::ThreatFound { ts, kind, bssid, device_mac, data, notify } => {
                self.writer.exec(
                    Db::Config,
                    "INSERT OR IGNORE INTO network_threats (kind, bssid, first_reported) VALUES (?1, ?2, ?3)",
                    vec![Sql::Text(kind.as_str().into()), Sql::Text(bssid), Sql::Integer(ts)],
                );
                if notify {
                    self.emit(Event { ts, kind: EventKind::NetworkThreat, device_mac, client_mac: None, data });
                }
            }
            Input::Note(e) => self.emit(e),
            Input::Forget { ts, mac } => self.forget(ts, mac),
            Input::EditState { ts, edit, done } => {
                let _ = done.send(self.edit_state(ts, edit));
            }
            Input::Firmware { op, done } => {
                let n = op.apply(&mut self.live.write().unwrap().firmware);
                let _ = done.send(n);
            }
            Input::Wake => {}
        }
    }

    /// Stores an event and tells the live subscribers (see `record`).
    fn emit(&self, ev: Event) {
        let head = self.record(ev);
        let _ = self.tx.send(LiveMsg::Event(head));
    }

    /// Stores an event without telling the live subscribers, for the caller
    /// to announce (`emit` does); the alert watcher gets the event itself,
    /// last, so it is not copied.
    fn record(&self, ev: Event) -> EventHead {
        bump(&self.counters.events);
        self.writer.exec(
            Db::Config,
            "INSERT INTO events (ts, kind, device_mac, client_mac, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                Sql::Integer(ev.ts),
                Sql::Text(ev.kind.as_str().into()),
                ev.device_mac.map(|m| m.to_string()).into(),
                ev.client_mac.map(|m| m.to_string()).into(),
                Sql::Text(ev.data.to_string()),
            ],
        );
        let head = EventHead { kind: ev.kind, device_mac: ev.device_mac, client_mac: ev.client_mac };
        if let Some(a) = &self.alerts {
            a.offer(ev);
        }
        head
    }

    fn inform(&mut self, ts: Ts, peer: IpAddr, decoded: Decoded) {
        // Notifications are short informs sent between regular ones: a config
        // acknowledgement or an event (client connection tracking, radar, scans).
        // They carry no client data and must not update the AP's status.
        if decoded.payload["inform_as_notif"].as_bool() == Some(true) {
            self.notification(ts, decoded.payload);
            return;
        }
        let (snap, scans) = match model::parse_with_scans(ts, &decoded.payload) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("unparseable inform: {e:#}");
                bump(&self.counters.decode_errors);
                return;
            }
        };
        let mac = snap.ap.mac;
        // Only stored, not kept in the live view: the rows written of them own them.
        self.check_isolated(ts, mac, &scans.neighbors);
        self.write_metrics(&snap, scans);
        bump(&self.counters.informs);

        // A handle of its own, so the engine's other fields stay usable while it is locked.
        let shared = self.live.clone();
        // The AP's comings and goings are worked out under the read lock: the
        // engine is the only writer of the devices, so the view read here is
        // the one replaced below.
        let (mut events, came_back) = {
            let live = shared.read().unwrap();
            let prev = live.devices.get(&mac);
            let known = if prev.is_none() { live.known_devices.get(&mac) } else { None };
            self.write_device_if_due(ts, &snap.ap, prev);
            (lifecycle_events(ts, &snap.ap, prev, known), prev.is_none_or(|p| !p.online))
        };
        if snap.has_vap_table {
            self.radio_events(ts, &snap, &mut events);
        }
        // Only for a report that lists clients: the UI refetches its client lists on it.
        let has_clients = !snap.clients.is_empty();

        // The write lock is held for the swaps alone. What they replace (the last
        // full inform, the last snapshot, the clients' views) is dropped after it,
        // and the clients' rows and the events are made after it.
        let mut live = shared.write().unwrap();
        let old_inform = if snap.has_vap_table { live.raw_informs.insert(mac, Arc::new(decoded.payload)) } else { None };
        live.attribute(&snap.ap);
        let prev = live.devices.remove(&mac);
        let known = if prev.is_none() { live.known_devices.remove(&mac) } else { None };
        // An upgrade apctl sent has landed: the AP reports the new version. One
        // event says so, not also a firmware change (see `lifecycle_events`).
        if let Some(v) = &snap.ap.version
            && let Some(j) = live.firmware.version_seen(&mac, v)
        {
            events.retain(|e| e.kind != EventKind::ApFirmwareChanged);
            events.push(Event::device(ts, EventKind::ApUpgraded, mac, json!({ "from": j.from, "to": v, "custom": j.custom })));
        }
        let updated = if snap.has_vap_table { self.update_clients(&mut live, ts, &snap.clients) } else { Vec::new() };
        let (view, old_snapshot) = device_view(ts, peer, snap, prev, known.as_ref());
        live.devices.insert(mac, view);
        drop(live);
        drop((old_inform, old_snapshot));
        self.client_rows(ts, updated, &mut events);

        for e in events {
            self.emit(e);
        }
        if has_clients {
            let _ = self.tx.send(LiveMsg::Clients);
        }
        let _ = self.tx.send(LiveMsg::Device { mac });
        // Online: its first inform of this run, or back from offline.
        if came_back {
            self.set_fixed_ap_available(HashMap::from([(mac, true)]));
        }
    }

    /// Keeps the APs' `fixed_ap_available` in the settings in step with whether
    /// the engine counts them online, as the official controller does for an AP
    /// (a device with radios): a client locked to an AP that is away may use
    /// the others meanwhile (apcfg's `lock2ap`). `aps` maps an AP to whether it
    /// is available; one edit writes them all, and only when a value changes,
    /// as a change of the controller's own, not the user's: no settings event.
    /// The APs are asked to inform now only when a client is locked to one of
    /// them, when the official controller provisions them all; else no AP's
    /// config changes.
    fn set_fixed_ap_available(&mut self, aps: HashMap<Mac, bool>) {
        let locked = self.change_state(|state| {
            if !state["devices"].as_array().is_some_and(|d| d.iter().any(|d| availability_change(d, &aps).is_some())) {
                return false;
            }
            let changed = mark_available(state.to_mut(), &aps);
            state["clients"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|c| c["fixed_ap_enabled"].as_bool() == Some(true) && crate::settings::doc_mac(&c["fixed_ap_mac"]).is_some_and(|m| changed.contains(&m)))
        });
        if locked.is_some_and(|(locked, _)| locked) {
            crate::stun::poke_all(&self.live.read().unwrap());
        }
    }

    /// Settings changes on the AP's radios, debounced (see `radios`).
    fn radio_events(&mut self, ts: Ts, snap: &Snapshot, events: &mut Vec<Event>) {
        let mac = snap.ap.mac;
        let tracks = self.radios.entry(mac).or_default();
        for r in &snap.radios {
            let now = (r.channel, r.bw, r.tx_power);
            if now.0.is_none() {
                continue; // no VAP on this radio, so nothing to compare
            }
            // The band is copied only for a radio not seen before.
            if !tracks.contains_key(r.radio.as_str()) {
                tracks.insert(r.radio.clone(), RadioTrack::default());
            }
            let track = tracks.get_mut(r.radio.as_str()).expect("inserted above");
            match track.committed {
                None => track.committed = Some(now),
                Some(c) if c == now => track.candidate = None,
                Some(c) if track.candidate == Some(now) => {
                    track.committed = Some(now);
                    track.candidate = None;
                    events.push(Event::device(ts, EventKind::RadioChanged, mac, json!({
                        "radio": r.radio,
                        "from": { "channel": c.0, "bw": c.1, "tx_power": c.2 },
                        "to": { "channel": now.0, "bw": now.1, "tx_power": now.2 },
                    })));
                }
                Some(_) => track.candidate = Some(now),
            }
        }
    }

    /// The row changes with every inform (uptime, last_seen): written when
    /// something else changed, or the AP came back, and otherwise once a
    /// minute. Uptime and last_seen are always written together, so a
    /// restart while apctl was away is still worked out right.
    fn write_device_if_due(&mut self, ts: Ts, a: &crate::model::ApSample, prev: Option<&DeviceView>) {
        let changed = prev.is_none_or(|p| {
            let o = &p.snapshot.ap;
            !p.online || (&o.hostname, &o.model, &o.model_display, &o.version, &o.ip, &o.serial, &o.hash_id)
                != (&a.hostname, &a.model, &a.model_display, &a.version, &a.ip, &a.serial, &a.hash_id)
        });
        if changed || due(self.written.devices.get(&a.mac), ts, REFRESH_SECS) {
            self.written.devices.insert(a.mac, ts);
            self.write_device(a);
        }
    }

    /// Updates the clients a full inform lists in the live view, under its
    /// lock; returns each with the view it replaced (none for a new one), for
    /// `client_rows` once the lock is released.
    fn update_clients(&mut self, live: &mut Live, ts: Ts, clients: &[Arc<ClientSample>]) -> Vec<(Arc<ClientSample>, Option<ClientView>)> {
        use std::collections::btree_map::Entry;
        let mut updated = Vec::with_capacity(clients.len());
        for c in clients {
            live.connected.insert(c.mac);
            let view = ClientView { sample: c.clone(), connected: true, first_seen: ts, last_seen: ts };
            let old = match live.clients.entry(c.mac) {
                Entry::Occupied(mut e) => {
                    let first_seen = e.get().first_seen;
                    Some(std::mem::replace(e.get_mut(), ClientView { first_seen, ..view }))
                }
                Entry::Vacant(e) => {
                    e.insert(view);
                    None
                }
            };
            updated.push((c.clone(), old));
        }
        updated
    }

    /// The rows and events of the clients `update_clients` updated: a row
    /// written if it changed (or is due again), and their events added to
    /// `events`.
    fn client_rows(&mut self, ts: Ts, updated: Vec<(Arc<ClientSample>, Option<ClientView>)>, events: &mut Vec<Event>) {
        for (c, old) in updated {
            let (event, changed) = match &old {
                None => (Some(connected_event(ts, &c, true)), true),
                Some(view) => {
                    let p = &view.sample;
                    let event = if !view.connected {
                        Some(connected_event(ts, &c, false))
                    } else if p.ap_mac != c.ap_mac || p.bssid != c.bssid {
                        Some(Event::client_on(ts, EventKind::ClientRoamed, c.ap_mac, c.mac, json!({
                            "from": { "ap": p.ap_mac, "radio": p.radio, "channel": p.channel, "essid": p.essid, "signal": p.signal },
                            "to": { "ap": c.ap_mac, "radio": c.radio, "channel": c.channel, "essid": c.essid, "signal": c.signal },
                        })))
                    } else {
                        None
                    };
                    let changed = !view.connected
                        || (&p.hostname, &p.ip, p.ap_mac, &p.bssid, &p.essid, &p.radio) != (&c.hostname, &c.ip, c.ap_mac, &c.bssid, &c.essid, &c.radio);
                    (event, changed)
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
                        c.hostname.clone().into(),
                        c.ip.clone().into(),
                        Sql::Integer(ts),
                        Sql::Text(c.ap_mac.to_string()),
                        Sql::Text(c.bssid.clone()),
                        c.essid.clone().into(),
                        c.radio.clone().into(),
                    ],
                );
            }
            events.extend(event);
        }
    }

    /// A reply sent to an AP: by the other controller (shadow mode, compared in
    /// a dry run) or by apctl itself (active mode).
    ///
    /// The diffs and the dry-run render take a while, so the live view is only
    /// locked to read what they need and then to store the results.
    fn reply(&mut self, ts: Ts, mac: Mac, mut p: Value, dry_run: bool) {
        bump(&self.counters.replies);
        // Nearly every reply repeats the interval the AP already has.
        if let Some(interval) = p["interval"].as_i64() {
            let changed = self.live.read().unwrap().devices.get(&mac).is_some_and(|d| d.interval != interval);
            if changed && let Some(d) = self.live.write().unwrap().devices.get_mut(&mac) {
                d.interval = interval;
            }
        }
        if p["_type"].as_str() != Some("setparam") {
            return;
        }
        bump(&self.counters.config_pushes);
        // The push's own configs, moved out rather than copied. One can be
        // management-only (e.g. after an LED change): it carries mgmt_cfg
        // alone, and the AP keeps its last full system_cfg.
        let mut take = |name: &str| match p.get_mut(name).map(Value::take) {
            Some(Value::String(s)) => Some(s),
            _ => None,
        };
        let (new_mgmt, new_system) = (take("mgmt_cfg"), take("system_cfg"));
        let stored = self.stored_config.remove(&mac);
        let (radios, previous, redacted, state, inform) = {
            let live = self.live.read().unwrap();
            // The last push, for the diffs, field by field: the one seen in this run
            // (unredacted), else the one stored before it (secrets masked); empty if
            // there is none.
            let seen = live.last_config.get(&mac).cloned();
            let (previous, redacted) = previous_push(seen, stored);
            let has_system = new_system.as_ref().map_or(!previous.system_cfg.is_empty(), |s| !s.is_empty());
            // For the section labels, which only a push with a system_cfg gets.
            let radios = live.devices.get(&mac).filter(|_| new_system.as_ref().is_some_and(|s| !s.is_empty())).map(|d| d.snapshot.radios.clone()).unwrap_or_default();
            let wanted = dry_run && has_system && self.renderer.is_some();
            let state = live.state.clone().filter(|_| wanted);
            let inform = state.as_ref().and_then(|_| live.raw_informs.get(&mac).cloned());
            (radios, previous, redacted, state, inform)
        };
        let mgmt = new_mgmt.as_deref().unwrap_or(&previous.mgmt_cfg);
        let system = new_system.as_deref().unwrap_or(&previous.system_cfg);
        let mut data = serde_json::Map::new();
        data.insert("cfgversion".into(), p["cfgversion"].clone());
        for (field, new, old, redacted) in [("mgmt_cfg", &new_mgmt, &previous.mgmt_cfg, redacted[0]), ("system_cfg", &new_system, &previous.system_cfg, redacted[1])] {
            let Some(new) = new else { continue };
            let summary = if old.is_empty() {
                json!({ "baseline": true, "lines": new.lines().count() })
            } else if redacted {
                cfgdiff::diff(old, &cfgdiff::redact(new)).summary()
            } else {
                cfgdiff::diff(old, new).summary()
            };
            data.insert(field.into(), summary);
        }
        // Names for numbered sections ("aaa.3" -> "Home WiFi (5 GHz)"), so the
        // config history can say what a change was about. Only a system_cfg has
        // them, so a management-only push gets none. Sections removed by this
        // push are only named in the previous config.
        if let Some(system) = new_system.as_deref().filter(|s| !s.is_empty()) {
            let mut labels = section_labels(&previous.system_cfg, &radios);
            labels.extend(section_labels(system, &radios));
            data.insert("labels".into(), Value::Object(labels));
        }
        // Without one in the push: the one its mgmt_cfg carries (this push's, else
        // the last one's), else the last push's, as the stored copy keeps it
        // (COALESCE below).
        let cfgversion = p["cfgversion"]
            .as_str()
            .map(str::to_string)
            .or_else(|| mgmt.lines().find_map(|l| l.strip_prefix("cfgversion=")).map(str::to_string))
            .or_else(|| previous.cfgversion.clone());
        self.writer.exec(
            Db::Config,
            "INSERT INTO device_config (mac, ts, cfgversion, mgmt_cfg, system_cfg) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (mac) DO UPDATE SET ts = excluded.ts, cfgversion = COALESCE(excluded.cfgversion, cfgversion),
               mgmt_cfg = COALESCE(excluded.mgmt_cfg, mgmt_cfg), system_cfg = COALESCE(excluded.system_cfg, system_cfg)",
            vec![
                Sql::Text(mac.to_string()),
                Sql::Integer(ts),
                cfgversion.clone().into(),
                new_mgmt.as_deref().map(cfgdiff::redact).into(),
                new_system.as_deref().map(cfgdiff::redact).into(),
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
                    previous_system_cfg: Some(system),
                };
                // Masked when a field the push does not carry is the stored copy's.
                let masked = (redacted[0] && new_mgmt.is_none()) || (redacted[1] && new_system.is_none());
                Some(self.dry_run(render, ts, &req, cfgversion.as_deref(), mgmt, masked))
            }
            _ => None,
        };

        // As in `inform`: the write lock is held for the swap alone, and the old
        // push is dropped and the events emitted after it. A field the push does
        // not carry is the last push's, but only known in full from one seen in
        // this run: else it is left empty, readers go to the stored copy, and so
        // does the next push, which keeps it here until a push carries the field.
        let still_stored = |redacted: bool, new: &Option<String>, old: &String| if redacted && new.is_none() { old.clone() } else { String::new() };
        let left = PushedConfig {
            mgmt_cfg: still_stored(redacted[0], &new_mgmt, &previous.mgmt_cfg),
            system_cfg: still_stored(redacted[1], &new_system, &previous.system_cfg),
            cfgversion: None,
        };
        if !left.mgmt_cfg.is_empty() || !left.system_cfg.is_empty() {
            self.stored_config.insert(mac, left);
        }
        let kept = |redacted: bool, old: &String| if redacted { String::new() } else { old.clone() };
        let pushed = PushedConfig {
            mgmt_cfg: new_mgmt.unwrap_or_else(|| kept(redacted[0], &previous.mgmt_cfg)),
            system_cfg: new_system.unwrap_or_else(|| kept(redacted[1], &previous.system_cfg)),
            cfgversion,
        };
        let mut live = self.live.write().unwrap();
        if let Some(d) = live.devices.get_mut(&mac) {
            d.last_config_push = Some(ts);
        }
        let old_config = live.last_config.insert(mac, Arc::new(pushed));
        drop(live);
        drop((old_config, previous));
        self.emit(Event::device(ts, EventKind::ConfigPushed, mac, Value::Object(data)));
        if let Some(summary) = dry {
            self.emit(Event::device(ts, EventKind::DryrunCompared, mac, summary));
        }
    }

    /// Renders the AP's config for `req` and compares it with the push (its
    /// `mgmt` and `req.previous_system_cfg`, with secrets masked if `redacted`):
    /// stored, and summed up for the event.
    fn dry_run(&self, render: &crate::dryrun::RenderFn, ts: Ts, req: &crate::dryrun::RenderRequest, cfgversion: Option<&str>, mgmt: &str, redacted: bool) -> Value {
        let system = req.previous_system_cfg.unwrap_or_default();
        let result = render(req).map(|ours| crate::dryrun::compare(&ours, mgmt, system, redacted, false));
        let (matches, payload) = match &result {
            Ok(c) => (c.matches(), serde_json::to_string(c).expect("a comparison serialises")),
            Err(e) => (false, json!({ "error": format!("{e:#}") }).to_string()),
        };
        self.writer.exec(
            Db::Config,
            "INSERT INTO dryrun_results (ts, mac, cfgversion, matches, comparison) VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![Sql::Integer(ts), Sql::Text(req.device_mac.to_string()), cfgversion.map(str::to_string).into(), Sql::Integer(matches as i64), Sql::Text(payload)],
        );
        // Each field's counts: a mismatch names the field that differs, and says
        // when only the order of its lines does (no line added, removed or changed).
        let counts = |f: &crate::dryrun::FieldComparison| json!({ "added": f.added, "removed": f.removed, "changed": f.changed, "same_content": f.same_content });
        match &result {
            Ok(c) => json!({ "matches": matches, "mgmt_cfg": counts(&c.mgmt_cfg), "system_cfg": counts(&c.system_cfg) }),
            Err(e) => json!({ "matches": false, "error": format!("{e:#}") }),
        }
    }

    /// Stores an AP's section numbering in the settings, so later renders keep it.
    fn set_config_meta(&self, mac: Mac, meta: Value) {
        let mac_s = mac.to_string();
        let same_mac = |m: &Value| m["mac"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(&mac_s));
        self.change_state(|state| {
            let current = state["config_meta"].as_array().and_then(|a| a.iter().find(|m| same_mac(m)));
            if current == Some(&meta) {
                return;
            }
            let next = state.to_mut();
            if !next["config_meta"].is_array() {
                next["config_meta"] = json!([]);
            }
            let list = next["config_meta"].as_array_mut().unwrap();
            list.retain(|m| !same_mac(m));
            list.push(meta);
        });
    }

    /// Changes the settings: `f` gets them to copy (`to_mut`) only when it
    /// changes them, and a copy is stored, under the time the settings were
    /// imported (an edit is no import). None without settings; else what `f`
    /// returned and whether they were stored. The copy is made and serialised
    /// without the lock.
    fn change_state<R>(&self, f: impl FnOnce(&mut Cow<Value>) -> R) -> Option<(R, bool)> {
        let (current, imported_at) = {
            let live = self.live.read().unwrap();
            live.state.clone().zip(live.state_imported_at)?
        };
        let mut state = Cow::Borrowed(&*current);
        let r = f(&mut state);
        let Cow::Owned(next) = state else { return Some((r, false)) };
        drop(current);
        self.store_state(next, imported_at);
        Some((r, true))
    }

    /// Stores the settings, then swaps them into the live view. Serialised
    /// before the lock is taken.
    fn store_state(&self, state: Value, imported_at: Ts) {
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO controller_state (id, json, imported_at) VALUES (1, ?1, ?2)",
            vec![Sql::Text(state.to_string()), Sql::Integer(imported_at)],
        );
        let mut live = self.live.write().unwrap();
        live.state = Some(Arc::new(state));
        live.state_imported_at = Some(imported_at);
    }

    fn set_state(&mut self, ts: Ts, mut state: Value) {
        // The import's `fixed_ap_available` is the other controller's view of
        // the APs; the engine's own replaces it for every AP whose state it knows.
        mark_available(&mut state, &presence(&self.live.read().unwrap()));
        let summary = crate::dryrun::summarize_state(&state);
        self.store_state(state, ts);
        // The new settings may hold the syslog key of an AP given up on.
        self.syslog_unknown.clear();
        self.emit(Event::site(ts, EventKind::SettingsImported, summary));
    }

    /// The engine is the only writer of the settings, so they cannot change
    /// between reading and swapping them in: the copy, the edit (which may hash
    /// a password) and the serialising run without holding the lock.
    fn edit_state(&mut self, ts: Ts, edit: StateEdit) -> Result<String, String> {
        // A refused edit leaves the settings as they were.
        let (what, stored) = self
            .change_state(|state| {
                let mut next = Value::clone(state);
                let what = edit(&mut next)?;
                if next != **state {
                    *state = Cow::Owned(next);
                }
                Ok::<_, String>(what)
            })
            .ok_or("no settings imported yet")?;
        let what = what?;
        // Saved as they were (e.g. a form sent unchanged): nothing to record or tell the APs.
        if !stored {
            return Ok(what);
        }
        self.syslog_unknown.clear();
        self.emit(Event::site(ts, EventKind::SettingsChanged, json!({ "what": what })));
        // The APs pick the change up now rather than at their next interval.
        crate::stun::poke_all(&self.live.read().unwrap());
        Ok(what)
    }

    fn forget(&mut self, ts: Ts, mac: Mac) {
        self.stored_config.remove(&mac);
        let mut live = self.live.write().unwrap();
        live.forget_ap(&mac);
        let forget_managed = live.forget_managed.clone();
        // Its clients are gone with it, rather than left connected until they go stale.
        let mut events = Vec::new();
        let Live { clients, connected, .. } = &mut *live;
        connected.retain(|cmac| {
            let Some(c) = clients.get_mut(cmac).filter(|c| c.sample.ap_mac == mac) else { return true };
            events.push(disconnect(&self.writer, ts, *cmac, c, "ap_forgotten"));
            self.written.clients.remove(cmac);
            false
        });
        drop(live);
        if let Some(f) = forget_managed {
            f(&mac);
        }
        let had_clients = !events.is_empty();
        for e in events {
            self.emit(e);
        }
        if had_clients {
            let _ = self.tx.send(LiveMsg::Clients);
        }
        self.radios.remove(&mac);
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

    /// Each rename is its own event (a client's history shows it). The
    /// renames and the client list are announced once for the lot: a bulk
    /// import of thousands of names would otherwise overrun the live
    /// subscribers' queue, and send every browser to refetch everything.
    ///
    /// Only the names are changed under the live view's lock; they are
    /// stored, and the renames recorded, once it is released.
    fn set_aliases(&self, ts: Ts, entries: Vec<AliasEdit>, only_if_unset: bool) {
        let clean = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        // Each change: the client, its new alias and note, and for a rename its old alias and its AP.
        let mut changes = Vec::new();
        let mut live = self.live.write().unwrap();
        for AliasEdit { mac, alias, note } in entries {
            let (alias, mut note) = (clean(alias), clean(note));
            let old = live.aliases.get(&mac).cloned().unwrap_or_default();
            // An import only adds names: an entry without one, or for a client
            // already named, changes nothing, and a note it lacks is kept.
            if only_if_unset {
                if alias.is_none() || old.alias.is_some() {
                    continue;
                }
                note = note.or(old.note.clone());
            }
            if old.alias == alias && old.note == note {
                continue;
            }
            if alias.is_none() && note.is_none() {
                live.aliases.remove(&mac);
            } else {
                live.aliases.insert(mac, Alias { alias: alias.clone(), note: note.clone() });
            }
            let renamed = (old.alias != alias).then(|| (old.alias, live.clients.get(&mac).map(|c| c.sample.ap_mac)));
            changes.push((mac, alias, note, renamed));
        }
        drop(live);
        let changed = !changes.is_empty();
        let mut renames = Vec::new();
        for (mac, alias, note, renamed) in changes {
            if alias.is_none() && note.is_none() {
                self.writer.exec(Db::Config, "DELETE FROM client_aliases WHERE mac = ?1", vec![Sql::Text(mac.to_string())]);
            } else {
                self.writer.exec(
                    Db::Config,
                    "INSERT OR REPLACE INTO client_aliases (mac, alias, note, updated) VALUES (?1, ?2, ?3, ?4)",
                    vec![Sql::Text(mac.to_string()), alias.clone().into(), note.into(), Sql::Integer(ts)],
                );
            }
            if let Some((from, ap)) = renamed {
                renames.push(self.record(Event { ts, kind: EventKind::ClientRenamed, device_mac: ap, client_mac: Some(mac), data: json!({ "from": from, "to": alias }) }));
            }
        }
        // One rename names its client; more are announced as renames of anyone.
        let head = match renames[..] {
            [] => None,
            [one] => Some(one),
            _ => Some(EventHead { kind: EventKind::ClientRenamed, device_mac: None, client_mac: None }),
        };
        if let Some(head) = head {
            let _ = self.tx.send(LiveMsg::Event(head));
        }
        if changed {
            let _ = self.tx.send(LiveMsg::Clients);
        }
    }

    /// Taken by value: an event's data is moved out of the notification, not copied.
    fn notification(&self, ts: Ts, mut p: Value) {
        let Some(mac) = p["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else {
            // As an inform without one.
            tracing::debug!("notification without a valid mac");
            bump(&self.counters.decode_errors);
            return;
        };
        bump(&self.counters.notifications);
        // The live view is written for this alone, and only read (or, for an
        // upgrade notice, written) again where the notification needs it.
        let since_push = self.live.write().unwrap().devices.get_mut(&mac).and_then(|d| {
            // Proof of life, but not a status report. An AP reported offline
            // keeps the time it went quiet, which its return reports.
            if d.online {
                d.last_seen = ts;
            }
            d.last_config_push.map(|t| ts - t)
        });
        let n = p["notif_payload"].take();
        match p["notif_reason"].as_str() {
            // The AP confirms it applied a pushed config.
            Some("setparam") => {
                let data = json!({ "cfgversion": p["cfgversion"], "seconds_after_push": since_push });
                self.emit(Event::device(ts, EventKind::ConfigApplied, mac, data));
            }
            Some("event") => {
                if n["message_type"].as_str() == Some("STA_ASSOC_TRACKER") {
                    self.connection_event(ts, mac, n);
                } else if let Some(kind) = n["event_string"].as_str() {
                    // AP events: radar (DFS), rogue APs, scan completion, process restarts...
                    let k = match kind {
                        "EVT_AP_RadarDetected" => EventKind::DfsRadar,
                        "EVT_AP_DetectRogueAP" => EventKind::RogueAp,
                        "EVT_AP_QuickScanEvent" | "EVT_AP_AcsTriggerComplete" => EventKind::ApScanDone,
                        // "{proc} exited with code {exit_status} and restarted by {caller}"
                        "EVT_AP_RestartProc" => EventKind::ApProcessRestarted,
                        "Upgrade" => {
                            // The lock is released at the end of the statement, before the event is emitted.
                            let ev = Self::upgrade_notice(&mut self.live.write().unwrap(), ts, mac, &n);
                            if let Some(ev) = ev {
                                self.emit(ev);
                            }
                            return;
                        }
                        _ => EventKind::ApEvent,
                    };
                    let mut n = n;
                    if k == EventKind::ApProcessRestarted {
                        numeric_exit_status(&mut n);
                    }
                    self.emit(Event::device(ts, k, mac, n));
                }
            }
            // The AP starts an upgrade (ours, or one run on the AP itself).
            Some(r @ ("cmd-upgrade" | "cli-upgrade")) => {
                self.emit(Event::device(ts, EventKind::ApUpgradeStarted, mac, json!({ "by": if r == "cli-upgrade" { "the AP's command line" } else { "the controller" } })));
            }
            // A crash or recovery report: base64 text from the AP's crash store.
            Some(reason @ ("crashlog" | "recovery")) => {
                use base64::Engine as _;
                let raw = n.as_str().unwrap_or_default();
                let text = base64::engine::general_purpose::STANDARD
                    .decode(raw.trim())
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_else(|_| raw.to_string());
                let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
                let tail = &lines[lines.len().saturating_sub(200)..];
                let kind = if reason == "recovery" { "recovered after a crash" } else { "crash report" };
                let mut data = json!({ "kind": kind, "source": reason, "lines": tail });
                if let Some(summary) = crate::logevents::crash_summary(tail) {
                    data["summary"] = json!(summary);
                }
                self.emit(Event::device(ts, EventKind::ApCrash, mac, data));
            }
            _ => {}
        }
    }

    /// A client connection-tracking event (`STA_ASSOC_TRACKER`): association,
    /// success (with association, WPA, IP and DNS timings), soft failure,
    /// roam, leave. The timings are read from `detail`, the whole notification.
    fn connection_event(&self, ts: Ts, ap: Mac, mut n: Value) {
        let Some(client) = n["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else { return };
        let num = |k: &str| n[k].as_str().and_then(|v| v.parse::<f64>().ok()).or_else(|| n[k].as_f64());
        let text = |k: &str| n[k].as_str().map(str::to_string);
        let vap = text("vap");
        // The live view is read for the VAP alone; the row is built without the lock.
        // A notification naming no VAP gets none (not one of the AP's unnamed ones).
        let vap_info = vap.as_deref().and_then(|name| {
            let live = self.live.read().unwrap();
            let vap = live.devices.get(&ap).and_then(|d| d.snapshot.vaps.iter().find(|v| v.name.as_deref() == Some(name)));
            vap.map(|v| (v.essid.clone(), v.radio.clone(), v.channel, v.bw))
        });
        let (essid, radio, at) = match vap_info {
            Some((essid, radio, channel, bw)) => (essid, radio, Some((channel, bw))),
            None => (None, None, None),
        };
        let event_type = text("event_type").unwrap_or_default();
        // The table's `auth_algo`, `assoc_ms`, `auth_ms`, `ip_ms` and `reason` columns
        // are no longer written: `detail` holds them, as the AP sent them.
        let mut row = vec![
            Sql::Integer(ts),
            Sql::Text(ap.to_string()),
            Sql::Text(client.to_string()),
            vap.into(),
            essid.clone().into(),
            radio.into(),
            Sql::Text(event_type.clone()),
            text("ip_assign_type").into(),
            num("dns_responses").map(|v| v as i64).into(),
            num("dns_timeouts").map(|v| v as i64).into(),
            num("avg_rssi").or_else(|| num("auth_rssi")).map(|v| v as i64).into(),
        ];
        // Failed attempts are worth an event, as the connection views count them (a
        // roam, or a soft failure that got traffic and DNS answers, is none); the
        // rest stay in the connection log. Without a reason from the AP, the stage
        // it failed at is the reason.
        let detail = crate::connections::ConnDetail::deserialize(&n).unwrap_or_default();
        let failed = crate::connections::reported_failure(crate::connections::Report::parse(&event_type), &detail).map(|label| {
            let reason = match &n["sta_dc_reason"] {
                Value::Null => json!(label),
                Value::String(r) if r.is_empty() => json!(label),
                r => r.clone(),
            };
            json!({ "essid": essid, "reason": reason, "auth_algo": n["auth_algo"], "rssi": num("auth_rssi").or_else(|| num("avg_rssi")) })
        });
        // The whole notification, with the channel and width at the time: timings, failure
        // counters and stage flags for connectivity stats, and the roaming views.
        if let Some((channel, bw)) = at {
            n["x_channel"] = json!(channel);
            n["x_bw"] = json!(bw);
        }
        row.push(Sql::Text(n.to_string()));
        self.writer.exec(
            Db::Config,
            "INSERT INTO connections (ts, ap_mac, client_mac, vap, essid, radio, event_type, ip_assign_type, dns_responses, dns_timeouts, rssi, detail) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            row,
        );
        if let Some(data) = failed {
            self.emit(Event::client_on(ts, EventKind::ClientConnectFailed, ap, client, data));
        }
    }

    /// Decrypts a datagram from the AP with this `hash_id`: with the key of the
    /// AP known by it, else by trying each key.
    fn decrypt_syslog(&mut self, ts: Ts, payload: &[u8], hash_id: u64, by_hash: Option<Mac>, state: Option<&Arc<Value>>) -> anyhow::Result<(Mac, String)> {
        // Keys come from the settings (APs apctl adopted) and the key file.
        self.syslog_ciphers.refresh(state, &self.keys);
        if let Some(mac) = by_hash
            && let Some(cipher) = self.syslog_ciphers.get(&mac)
            && let Some(text) = crate::syslog::decrypt(payload, cipher)
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
            anyhow::bail!("no syslog key for hash_id {hash_id:016x} (none worked {}s ago)", ts - at);
        }
        // So many unknown hash_ids at once are made up: trying every key on each
        // would keep the engine busy. A real AP is found by its informs meanwhile.
        if self.syslog_unknown.len() >= SYSLOG_UNKNOWN_MAX {
            anyhow::bail!("no syslog key for hash_id {hash_id:016x} (too many unknown senders to try)");
        }
        for (mac, cipher) in self.syslog_ciphers.all() {
            if let Some(text) = crate::syslog::decrypt(payload, cipher) {
                self.syslog_unknown.remove(&hash_id);
                self.live.write().unwrap().set_hash_id(hash_id, mac);
                return Ok((mac, text));
            }
        }
        // Bounded (above) against made-up hash_ids; expired entries go at each tick.
        self.syslog_unknown.insert(hash_id, ts);
        anyhow::bail!("no syslog key for hash_id {hash_id:016x}")
    }

    fn datagram(&mut self, ts: Ts, src_ip: &str, payload: &[u8]) {
        // Encrypted datagrams name their sender by hash_id; plain ones are passed through.
        let hash_id = crate::syslog::hash_id(payload);
        let (by_hash, by_ip, state) = {
            let live = self.live.read().unwrap();
            let by_ip = live.by_ip.get(src_ip).copied();
            (hash_id.and_then(|h| live.by_hash_id.get(&h).copied()), by_ip, (hash_id.is_some() || by_ip.is_some()).then(|| live.state.clone()).flatten())
        };
        let result = match hash_id {
            Some(h) => self.decrypt_syslog(ts, payload, h, by_hash, state.as_ref()).map(|(mac, text)| (Some(mac), Cow::Owned(text))),
            None if payload.starts_with(&wire::syslog_frame::MAGIC) => Err(anyhow::anyhow!("encrypted syslog datagram too short ({} bytes)", payload.len())),
            None => Ok((None, String::from_utf8_lossy(payload))),
        };
        match result {
            Ok((mac, text)) => {
                // A plain datagram's source address can be forged. It names the
                // AP only if the AP has no syslog key (apctl's APs encrypt their
                // syslog), except for netconsole's lines: the kernel's, plain and
                // without a priority, which are only looked at for crashes.
                let keyed = by_ip.is_some_and(|m| {
                    self.syslog_ciphers.refresh(state.as_ref(), &self.keys);
                    self.syslog_ciphers.get(&m).is_some()
                });
                // Netconsole and multi-line messages can carry several lines.
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    let mut l = crate::syslog::parse(ts, src_ip, mac.or(by_ip.filter(|_| !keyed)), line);
                    if l.device_mac.is_none() && l.facility.is_none() {
                        l.device_mac = by_ip;
                    }
                    self.log(l);
                }
            }
            Err(e) => {
                tracing::debug!("syslog from {src_ip}: {e:#}");
                bump(&self.counters.log_errors);
            }
        }
    }

    /// Upgrade progress from the AP: downloading, writing, or an error; and
    /// its event, for the caller to emit once the lock is released.
    fn upgrade_notice(live: &mut Live, ts: Ts, mac: Mac, n: &Value) -> Option<Event> {
        let s = |k: &str| n[k].as_str().unwrap_or_default().to_string();
        match (n["up_type"].as_str(), n["up_stage"].as_str()) {
            (Some("UpgradeReady"), stage) => {
                use crate::firmware::JobState;
                let step = match stage {
                    Some("FWDownloading") => JobState::Downloading,
                    Some("FWCheckOK") => JobState::Writing,
                    _ => JobState::Preparing,
                };
                live.firmware.progress(&mac, step, ts);
                Some(Event::device(ts, EventKind::ApUpgradeProgress, mac, json!({ "step": step })))
            }
            (Some("UpgradeError"), _) => {
                let reason = s("reason");
                let detail = match reason.as_str() {
                    "FirmwareDownloadFailed" => format!("download failed (error: curl:{}, http:{})", n["curl_rc"], n["http_rc"]),
                    "FirmwareCheckFailed" => format!("firmware check failed (error: {})", n["rc"]),
                    "FWWriteFailed" => "writing the firmware failed".into(),
                    r => format!("failed ({r})"),
                };
                live.firmware.upgrade_error(&mac, &detail);
                Some(Event::device(ts, EventKind::ApUpgradeFailed, mac, json!({ "reason": reason, "detail": detail })))
            }
            _ => None,
        }
    }

    /// Another AP's beacon flagged "isolated" (lost its uplink) that belongs to one
    /// of our APs: reported at most once an hour per AP. An entry the AP keeps from
    /// a scan before this run, or from one before the last report, is no news.
    fn check_isolated(&mut self, ts: Ts, heard_by: Mac, neighbors: &[crate::model::NeighborSample]) {
        use crate::model::{hardware_num, same_hardware};
        let started = self.first_tick.unwrap_or(ts);
        let flagged: Vec<&crate::model::NeighborSample> = neighbors.iter().filter(|n| n.is_isolated && n.heard(ts) >= started).collect();
        if flagged.is_empty() {
            return;
        }
        // The APs reporting in this run, and those known from earlier ones that have not
        // reported yet: after a restart, the isolated AP may be unable to (the two are apart).
        let ours: Vec<(Mac, u64)> = {
            let live = self.live.read().unwrap();
            live.devices.keys().chain(live.known_devices.keys()).map(|m| (*m, hardware_num(m))).collect()
        };
        for n in flagged {
            // The AP the beacon names as its own (as the official controller reads it), or
            // without a name, the one of ours its BSSID likely derives from: an AP's BSSIDs
            // are its MAC plus a little, so the nearest at or below it, else the nearest.
            let ap = match n.serial {
                Some(serial) if ours.iter().any(|(m, _)| *m == serial) => serial,
                Some(_) => continue,
                None => {
                    let Ok(b) = n.bssid.parse::<Mac>().map(|m| hardware_num(&m)) else { continue };
                    let near = || ours.iter().filter(|(_, x)| same_hardware(*x, b));
                    let below = near().filter(|(_, x)| *x <= b).max_by_key(|(_, x)| *x);
                    let Some((ap, _)) = below.or_else(|| near().min_by_key(|(_, x)| x.abs_diff(b))) else { continue };
                    *ap
                }
            };
            let heard = n.heard(ts);
            if self.isolated.get(&ap).is_some_and(|t| heard - t < 3600) {
                continue;
            }
            self.isolated.insert(ap, heard);
            let data = json!({ "heard_by": heard_by.to_string(), "bssid": n.bssid, "signal": n.signal });
            self.emit(Event::device(ts, EventKind::ApIsolated, ap, data));
        }
    }

    fn log(&mut self, line: LogLine) {
        for e in self.logevents.feed(&line) {
            self.emit(e);
        }
        bump(&self.counters.logs);
        self.writer.exec(
            Db::Logs,
            "INSERT INTO logs (ts, device_mac, src_ip, facility, severity, program, msg) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            vec![
                Sql::Integer(line.ts),
                line.device_mac.map(|m| m.to_string()).into(),
                Sql::Text(line.src_ip),
                line.facility.into(),
                line.severity.into(),
                line.program.into(),
                Sql::Text(line.msg),
            ],
        );
        // One message per AP and second: a burst (a crash dump, debug logging)
        // would otherwise flood the sockets and force every browser to resync.
        // Lines later in the same second are announced at the next tick.
        match self.logs_announced.get_mut(&line.device_mac) {
            Some((at, later)) if *at == line.ts => *later = true,
            _ => {
                self.logs_announced.insert(line.device_mac, (line.ts, false));
                let _ = self.tx.send(LiveMsg::Log { device_mac: line.device_mac });
            }
        }
    }

    /// Time-based transitions: APs going quiet and clients disappearing.
    fn tick(&mut self, now: Ts) {
        // A previous multicast sample is only used up to MCAST_GAP old; the margin is for
        // informs received before this tick and still queued behind it.
        let stale = now - 2 * MCAST_GAP;
        self.mcast_prev.retain(|_, (ts, ..)| *ts > stale);
        self.syslog_unknown.retain(|_, at| (*at..*at + SYSLOG_RETRY_SECS).contains(&now));
        self.logs_announced.retain(|device_mac, (at, later)| {
            if std::mem::take(later) {
                let _ = self.tx.send(LiveMsg::Log { device_mac: *device_mac });
            }
            now - *at < 60
        });
        self.bss_prev.retain(|_, (ts, _)| *ts > stale);
        for e in self.logevents.tick(now) {
            self.emit(e);
        }
        let mut live = self.live.write().unwrap();
        let mut events = Vec::new();
        if let Some((mac, why)) = live.firmware.expired(now)
            && let Some(j) = live.firmware.failed(&mac, why)
        {
            let data = json!({ "reason": "timed out", "detail": why, "target": j.target });
            events.push(Event::device(now, EventKind::ApUpgradeFailed, mac, data));
        }
        let started = *self.first_tick.get_or_insert(now);
        let mut offline = Vec::new();
        for (mac, d) in live.devices.iter_mut() {
            let limit = (d.interval.max(5) * OFFLINE_INTERVALS).max(MIN_OFFLINE_SECS);
            if d.online && now - d.last_seen > limit {
                d.online = false;
                offline.push(*mac);
                events.push(Event::device(now, EventKind::ApOffline, *mac, json!({ "last_seen": d.last_seen })));
            }
        }
        // An AP last recorded online that has not informed in this run, as when it
        // went down while apctl was away: its interval is not known, so it is
        // given the longest one active mode asks for, counted from this run's start too.
        for (mac, k) in live.known_devices.iter_mut() {
            if !k.offline && now - k.last_seen.max(started) > crate::active::MAX_INFORM_INTERVAL * OFFLINE_INTERVALS {
                k.offline = true;
                offline.push(*mac);
                events.push(Event::device(now, EventKind::ApOffline, *mac, json!({ "last_seen": k.last_seen })));
            }
        }
        for mac in &offline {
            crate::actions::drop_online_only(&mut live, mac);
        }
        // A client is gone when its AP has reported a full client list since it was
        // last seen and the grace period has passed, or when its AP went offline.
        // Only the connected ones are looked at, not the year of clients kept.
        let mut changed = false;
        let Live { devices, known_devices, clients, connected, .. } = &mut *live;
        connected.retain(|cmac| {
            let Some(c) = clients.get_mut(cmac).filter(|c| c.connected) else { return false };
            // An AP we have not heard from yet in this run (e.g. right after a
            // restart) is unknown, not offline, until the wait above marks it
            // offline: until then, leave its clients alone.
            let reason = match devices.get(&c.sample.ap_mac) {
                None if known_devices.get(&c.sample.ap_mac).is_some_and(|k| k.offline) => Some("ap_offline"),
                // Its AP never reappeared (e.g. removed): give up after an hour.
                // Counted from this run's start too: after a long outage the
                // APs get time to inform before their clients are written off.
                None => (now - c.last_seen.max(started) > 3600).then_some("stale"),
                Some(d) if !d.online => Some("ap_offline"),
                Some(d) => (now - c.last_seen > CLIENT_GRACE_SECS && d.last_full_inform > c.last_seen).then_some("not_seen"),
            };
            let Some(reason) = reason else { return true };
            changed = true;
            events.push(disconnect(&self.writer, now, *cmac, c, reason));
            self.written.clients.remove(cmac);
            false
        });
        // Clients gone longer than the database keeps them (see `store::maintenance`).
        if now - self.last_prune >= 3600 {
            self.last_prune = now;
            let cutoff = now - store::CLIENT_RETENTION;
            let Live { clients, connected, aliases, .. } = &mut *live;
            let before = clients.len();
            clients.retain(|mac, c| c.last_seen >= cutoff || aliases.contains_key(mac));
            changed |= clients.len() != before;
            connected.retain(|mac| clients.contains_key(mac));
        }
        drop(live);
        for e in events {
            self.emit(e);
        }
        // Remembered, so that a restart still pairs the AP's return with it.
        for &mac in &offline {
            self.writer.exec(Db::Config, "UPDATE devices SET offline = 1 WHERE mac = ?1", vec![Sql::Text(mac.to_string())]);
            let _ = self.tx.send(LiveMsg::Device { mac });
        }
        if !offline.is_empty() {
            self.set_fixed_ap_available(offline.into_iter().map(|m| (m, false)).collect());
        }
        if changed {
            let _ = self.tx.send(LiveMsg::Clients);
        }
    }

    /// The AP's row in `devices`, as of the inform at `a.ts`: back online, if it
    /// was offline (see `tick`). The table's `name`, `cfgversion` and `online`
    /// columns are no longer used: its config version is in `device_config`.
    fn write_device(&self, a: &crate::model::ApSample) {
        self.writer.exec(
            Db::Config,
            "INSERT INTO devices (mac, hostname, model, model_display, version, ip, serial, hash_id, first_seen, last_seen, uptime)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10)
             ON CONFLICT (mac) DO UPDATE SET hostname = excluded.hostname, model = excluded.model, model_display = excluded.model_display,
               version = excluded.version, ip = excluded.ip, serial = excluded.serial, hash_id = excluded.hash_id,
               last_seen = excluded.last_seen, uptime = excluded.uptime, offline = 0",
            vec![
                Sql::Text(a.mac.to_string()),
                a.hostname.clone().into(),
                a.model.clone().into(),
                a.model_display.clone().into(),
                a.version.clone().into(),
                a.ip.clone().into(),
                a.serial.clone().into(),
                a.hash_id.clone().into(),
                Sql::Integer(a.ts),
                a.uptime.into(),
            ],
        );
    }

    /// The inform's metrics, and its scan results (see `Written`).
    fn write_metrics(&mut self, s: &Snapshot, model::Scans { neighbors, spectrum }: model::Scans) {
        let ts = s.ap.ts;
        // Formatted once: nearly every row of the inform carries the AP's MAC.
        let mac_text = Sql::Text(s.ap.mac.to_string());
        let mac = || mac_text.clone();
        let a = &s.ap;
        self.writer.send(Write::Metric {
            table: &store::AP,
            ts,
            values: vec![mac(), a.cpu.into(), a.mem.into(), a.load1.into(), a.load5.into(), a.load15.into(), a.mem_used.into(), a.mem_total.into(), a.uptime.into(), a.satisfaction.into(), a.num_sta.into()],
        });
        if let Some(u) = &s.uplink {
            self.writer.send(Write::Metric {
                table: &store::UPLINK,
                ts,
                values: vec![mac(), u.speed.into(), u.rx_bytes.into(), u.tx_bytes.into(), u.rx_packets.into(), u.tx_packets.into(), u.rx_errors.into(), u.tx_errors.into(), u.rx_dropped.into(), u.tx_dropped.into()],
            });
        }
        if !s.has_vap_table {
            return; // no VAP table: radio, VAP and client figures are absent
        }
        for r in &s.radios {
            self.writer.send(Write::Metric {
                table: &store::RADIO,
                ts,
                values: vec![
                    mac(), Sql::Text(r.radio.clone()), r.channel.into(), r.bw.into(), r.tx_power.into(), r.cu_total.into(), r.cu_self_rx.into(),
                    r.cu_self_tx.into(), r.cu_interf.into(), r.noise_floor.into(), Sql::Integer(r.num_sta), r.tx_packets.into(), r.tx_retries.into(),
                ],
            });
        }
        for v in &s.vaps {
            self.writer.send(Write::Metric {
                table: &store::VAP,
                ts,
                values: vec![
                    Sql::Text(v.bssid.clone()), mac(), v.essid.clone().into(), v.radio.clone().into(),
                    v.num_sta.into(), v.ccq.into(), v.satisfaction.into(), v.avg_client_signal.into(), v.latency_avg.into(),
                    v.rx_bytes.into(), v.tx_bytes.into(), v.rx_packets.into(), v.tx_packets.into(), v.tx_retries.into(), v.tx_dropped.into(),
                    v.tx_mcast.into(), v.rx_mcast.into(), v.wifi_tx_attempts.into(), v.wifi_tx_dropped.into(), v.tx_bcast.into(), v.rx_bcast.into(),
                ],
            });
        }
        // Scan results repeat in every inform until the next scan: an unchanged
        // neighbour heard again is written once a minute (last_seen), an unchanged spectrum
        // row once an hour. What the AP no longer reports is forgotten here.
        let rows = self.written.neighbors.entry(s.ap.mac).or_default();
        for mut n in neighbors {
            // When the scan heard it, which is when it was last seen as it is: an entry
            // the AP keeps reporting from an old scan is no sighting now. Its age
            // grows at every inform, so it is no change of the neighbour, and its
            // row is due again only when it is heard again (so the age is left out of the row).
            let heard = n.heard(ts);
            n.age = None;
            let Some(n) = report(rows, n, |n| n.bssid.as_str(), ts, heard, REFRESH_SECS) else { continue };
            self.writer.exec(
                Db::Config,
                "INSERT INTO neighbors (bssid, ap_mac, radio, essid, channel, bw, center_freq, security, signal, best_signal, noise, is_unifi, ap_name, model, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11, ?12, ?13, ?14, ?14)
                 ON CONFLICT (bssid, ap_mac) DO UPDATE SET radio = excluded.radio, essid = excluded.essid, channel = excluded.channel,
                   bw = excluded.bw, center_freq = excluded.center_freq, security = excluded.security, signal = excluded.signal,
                   best_signal = MAX(COALESCE(best_signal, -200), COALESCE(excluded.signal, -200)), noise = excluded.noise,
                   is_unifi = excluded.is_unifi, ap_name = excluded.ap_name, model = excluded.model, last_seen = excluded.last_seen",
                vec![
                    Sql::Text(n.bssid.clone()), mac(), n.radio.clone().into(), n.essid.clone().into(), n.channel.into(), n.bw.into(),
                    n.center_freq.into(), n.security.clone().into(), n.signal.into(), n.noise.into(), Sql::Integer(n.is_unifi as i64),
                    n.ap_name.clone().into(), n.model.clone().into(), Sql::Integer(heard),
                ],
            );
        }
        rows.retain(|_, r| r.seen == ts);
        let radios = self.written.spectrum.entry(s.ap.mac).or_default();
        for (radio, channels) in spectrum {
            // Looked up by reference: the radio's name is copied only for a new one.
            if !radios.contains_key(&radio) {
                radios.insert(radio.clone(), Rows::new());
            }
            let rows = radios.get_mut(&radio).expect("inserted above");
            for c in channels {
                let Some(c) = report(rows, c, |c| &c.channel, ts, ts, SPECTRUM_REFRESH_SECS) else { continue };
                self.writer.exec(
                    Db::Config,
                    "INSERT OR REPLACE INTO spectrum (ap_mac, radio, channel, width, utilization, interference, other_bss_count, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    vec![mac(), Sql::Text(radio.clone()), Sql::Integer(c.channel), c.width.into(), c.utilization.into(), c.interference.into(), c.other_bss_count.into(), Sql::Integer(ts)],
                );
            }
        }
        radios.retain(|_, rows| {
            rows.retain(|_, r| r.seen == ts);
            !rows.is_empty()
        });
        // Per traffic type: [to clients pps, from clients pps, to bytes/s, from bytes/s], and
        // how many clients sent any. "To clients" is counted once per network (BSSID),
        // "from clients" per client; only increases count (a client moving to another
        // network, or a restarted counter, adds nothing rather than its whole total).
        let mut mcast: BTreeMap<&str, ([f64; 4], i64)> = BTreeMap::new();
        let rate = |c: i64, p: i64, dt: f64| (c - p).max(0) as f64 / dt;
        let mut bss_done: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for c in &s.clients {
            let m = c.multicast.as_ref();
            let t = m.map(|m| m.total());
            self.writer.send(Write::Metric {
                table: &store::CLIENT,
                ts,
                values: vec![
                    Sql::Text(c.mac.to_string()), mac(), Sql::Text(c.bssid.clone()), c.essid.clone().into(), c.radio.clone().into(), c.channel.into(),
                    c.rssi.into(), c.signal.into(), c.noise.into(), c.tx_rate.into(), c.rx_rate.into(), c.satisfaction.into(), c.latency_avg.into(),
                    c.tx_bytes.into(), c.rx_bytes.into(), c.tx_packets.into(), c.rx_packets.into(), c.tx_retries.into(),
                    t.map(|t| t.tx_pkts).into(), t.map(|t| t.rx_pkts).into(), t.map(|t| t.tx_bytes).into(), t.map(|t| t.rx_bytes).into(),
                ],
            });
            let Some(m) = m else { continue };
            if bss_done.insert(c.bssid.as_str()) {
                if let Some((pts, prev)) = self.bss_prev.get(&c.bssid)
                    && ts > *pts
                    && ts - pts <= MCAST_GAP
                {
                    let dt = (ts - pts) as f64;
                    let prev = mcast_types(prev);
                    for (kind, cur) in &m.types {
                        let p = prev.get(kind).copied().unwrap_or(*cur);
                        let e = mcast.entry(kind.as_ref()).or_default();
                        e.0[0] += rate(cur.tx_pkts, p.tx_pkts, dt);
                        e.0[2] += rate(cur.tx_bytes, p.tx_bytes, dt);
                    }
                }
                match self.bss_prev.get_mut(&c.bssid) {
                    Some(prev) => *prev = (ts, c.clone()),
                    None => {
                        self.bss_prev.insert(c.bssid.clone(), (ts, c.clone()));
                    }
                }
            }
            if let Some((pts, prev)) = self.mcast_prev.get(&c.mac)
                && prev.bssid == c.bssid
                && ts > *pts
                && ts - pts <= MCAST_GAP
            {
                let dt = (ts - pts) as f64;
                let prev = mcast_types(prev);
                for (kind, cur) in &m.types {
                    let p = prev.get(kind).copied().unwrap_or(*cur);
                    let (pk, by) = (rate(cur.rx_pkts, p.rx_pkts, dt), rate(cur.rx_bytes, p.rx_bytes, dt));
                    let e = mcast.entry(kind.as_ref()).or_default();
                    e.0[1] += pk;
                    e.0[3] += by;
                    if pk > 0.0 {
                        e.1 += 1;
                    }
                }
            }
            self.mcast_prev.insert(c.mac, (ts, c.clone()));
        }
        for (kind, (r, n)) in mcast {
            self.writer.send(Write::Metric {
                table: &store::MCAST,
                ts,
                values: vec![mac(), Sql::Text(kind.to_string()), Sql::Real(r[0]), Sql::Real(r[1]), Sql::Real(r[2]), Sql::Real(r[3]), Sql::Integer(n)],
            });
        }
    }
}

/// An AP's last push, field by field: the one `seen` in this run, else the
/// `stored` one, whose fields are flagged (mgmt_cfg, system_cfg) as redacted.
fn previous_push(seen: Option<Arc<PushedConfig>>, stored: Option<PushedConfig>) -> (Arc<PushedConfig>, [bool; 2]) {
    let Some(stored) = stored else { return (seen.unwrap_or_default(), [false; 2]) };
    let Some(seen) = seen else {
        let redacted = [!stored.mgmt_cfg.is_empty(), !stored.system_cfg.is_empty()];
        return (Arc::new(stored), redacted);
    };
    let pick = |seen: &String, stored: String| if seen.is_empty() && !stored.is_empty() { (stored, true) } else { (seen.clone(), false) };
    let (mgmt_cfg, mgmt_redacted) = pick(&seen.mgmt_cfg, stored.mgmt_cfg);
    let (system_cfg, system_redacted) = pick(&seen.system_cfg, stored.system_cfg);
    let cfgversion = seen.cfgversion.clone().or(stored.cfgversion);
    (Arc::new(PushedConfig { mgmt_cfg, system_cfg, cfgversion }), [mgmt_redacted, system_redacted])
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
        for section in ["aaa.", "wireless."] {
            if let Some(n) = k.strip_prefix(section).and_then(|r| r.strip_suffix(".ssid")) {
                let band = kv.get(format!("{section}{n}.devname").as_str()).and_then(|d| band_of_dev.get(d));
                let label = match band {
                    Some(b) => format!("{v} ({b})"),
                    None => v.to_string(),
                };
                out.insert(format!("{section}{n}"), json!(label));
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

/// An AP's comings and goings, from its inform and what was known of it:
/// `prev` from this run, else `known` from the database.
fn lifecycle_events(ts: Ts, a: &crate::model::ApSample, prev: Option<&DeviceView>, known: Option<&KnownDevice>) -> Vec<Event> {
    let mac = a.mac;
    let mut events = Vec::new();
    // What was last known of the AP: its uptime and when it reported it, and its version.
    let (uptime, version) = match (prev, known) {
        (None, None) => {
            events.push(Event::device(ts, EventKind::ApSeen, mac, json!({ "ip": a.ip, "model": a.model, "version": a.version })));
            return events;
        }
        (Some(p), _) => {
            if !p.online {
                events.push(Event::device(ts, EventKind::ApOnline, mac, json!({ "offline_for": ts - p.last_seen })));
            }
            (p.snapshot.ap.uptime.map(|u| (u, p.snapshot.ap.ts)), &p.snapshot.ap.version)
        }
        (None, Some(k)) => {
            // Reported offline before a restart: its return is reported now.
            if k.offline {
                events.push(Event::device(ts, EventKind::ApOnline, mac, json!({ "offline_for": ts - k.last_seen })));
            }
            (k.uptime.map(|u| (u, k.last_seen)), &k.version)
        }
    };
    // Only what can be proved to have changed, in this run or while apctl was
    // away: up for less than it was then plus the time since (with a minute's
    // slack), and a version other than a known one.
    if let (Some((old, at)), Some(up)) = (uptime, a.uptime)
        && up.saturating_add(60) < old.saturating_add(ts - at)
    {
        events.push(Event::device(ts, EventKind::ApRestarted, mac, json!({ "uptime": up })));
    }
    if version.is_some() && a.version.is_some() && *version != a.version {
        events.push(Event::device(ts, EventKind::ApFirmwareChanged, mac, json!({ "from": version, "to": a.version })));
    }
    events
}

/// The AP's live view after an inform at `ts`, and the snapshot it replaces
/// (if whole), for the caller to drop once the lock is released.
fn device_view(ts: Ts, peer: IpAddr, snap: Snapshot, prev: Option<DeviceView>, known: Option<&KnownDevice>) -> (DeviceView, Option<Snapshot>) {
    let first_seen = prev.as_ref().map(|p| p.first_seen).or(known.map(|k| k.first_seen)).unwrap_or(ts);
    match prev {
        Some(mut p) => {
            // Without a VAP table the inform says nothing of radios, VAPs or clients: keep the last full picture.
            let old = if snap.has_vap_table {
                p.last_full_inform = ts;
                Some(std::mem::replace(&mut p.snapshot, snap))
            } else {
                p.snapshot.uplink = snap.uplink.or(p.snapshot.uplink.take());
                p.snapshot.ap = snap.ap;
                None
            };
            (DeviceView { online: true, first_seen, last_seen: ts, peer: Some(peer), ..p }, old)
        }
        None => {
            let view = DeviceView {
                last_full_inform: if snap.has_vap_table { ts } else { 0 },
                snapshot: snap,
                online: true,
                first_seen,
                last_seen: ts,
                peer: Some(peer),
                interval: DEFAULT_INTERVAL,
                last_config_push: None,
            };
            (view, None)
        }
    }
}

/// `new`: never seen before (not even in an earlier run).
fn connected_event(ts: Ts, c: &ClientSample, new: bool) -> Event {
    Event::client_on(ts, EventKind::ClientConnected, c.ap_mac, c.mac, json!({
        "essid": c.essid, "radio": c.radio, "channel": c.channel, "signal": c.signal,
        "hostname": c.hostname, "ip": c.ip, "new": new,
    }))
}

/// Marks a client disconnected, in the live view and the database, and
/// returns the event that says so, for the caller to emit.
fn disconnect(writer: &Writer, ts: Ts, mac: Mac, c: &mut ClientView, reason: &str) -> Event {
    c.connected = false;
    // The row's last_seen is only written once a minute while connected.
    writer.exec(
        Db::Config,
        "UPDATE clients SET connected = 0, last_seen = MAX(COALESCE(last_seen, ?2), ?2) WHERE mac = ?1",
        vec![Sql::Text(mac.to_string()), Sql::Integer(c.last_seen)],
    );
    Event::client_on(ts, EventKind::ClientDisconnected, c.sample.ap_mac, mac, json!({
        "reason": reason, "last_seen": c.last_seen, "essid": c.sample.essid,
        "connected_for": c.sample.uptime, "last_signal": c.sample.signal,
    }))
}

/// A process-restart notification's `exit_status` as a number: the AP may send
/// the code as text. One that is no number is left out, as one not sent.
fn numeric_exit_status(n: &mut Value) {
    let code = match &n["exit_status"] {
        Value::Number(c) => c.as_i64(),
        Value::String(c) => c.trim().parse::<i64>().ok(),
        _ => None,
    };
    match code {
        Some(c) => n["exit_status"] = json!(c),
        None => {
            if let Some(o) = n.as_object_mut() {
                o.remove("exit_status");
            }
        }
    }
}

/// Whether each AP the engine knows the state of is available: online or not
/// for one heard from in this run, unavailable for one stored as offline. One
/// last stored online that has not informed in this run yet is left out (its
/// state is not known yet).
fn presence(live: &Live) -> HashMap<Mac, bool> {
    let stored_offline = live.known_devices.iter().filter(|(_, k)| k.offline).map(|(m, _)| (*m, false));
    live.devices.iter().map(|(m, d)| (*m, d.online)).chain(stored_offline).collect()
}

/// The AP and its new `fixed_ap_available`, when this device record is an AP
/// (it has radios) in `aps` whose stored value (none reads as available) differs.
fn availability_change(doc: &Value, aps: &HashMap<Mac, bool>) -> Option<(Mac, bool)> {
    let mac = crate::settings::doc_mac(&doc["mac"])?;
    let available = *aps.get(&mac)?;
    let has_radios = doc["radio_table"].as_array().is_some_and(|r| !r.is_empty());
    (has_radios && doc["fixed_ap_available"].as_bool().unwrap_or(true) != available).then_some((mac, available))
}

/// Writes `fixed_ap_available` into the records of the APs in `aps` whose value
/// differs (see `availability_change`), and returns those APs.
fn mark_available(state: &mut Value, aps: &HashMap<Mac, bool>) -> Vec<Mac> {
    let mut changed = Vec::new();
    for doc in state["devices"].as_array_mut().into_iter().flatten() {
        if let Some((mac, available)) = availability_change(doc, aps) {
            doc["fixed_ap_available"] = json!(available);
            changed.push(mac);
        }
    }
    changed
}

#[cfg(test)]
mod tests {

    #[test]
    fn event_kinds_keep_their_names() {
        // Stored with every event and read by the UI: never renamed.
        let names: Vec<&str> = EventKind::ALL.iter().map(|k| k.as_str()).collect();
        let known = "ap_seen ap_online ap_offline ap_restarted ap_firmware_changed ap_isolated ap_crash ap_process_restarted ap_scan_done ap_event \
                     dfs_radar rogue_ap network_threat radio_changed config_pushed config_applied dryrun_compared ap_upgrade_sent ap_upgrade_started \
                     ap_upgrade_progress ap_upgrade_failed ap_upgraded ap_pending ap_adopting ap_adopted ap_forgotten ap_host_key_mismatch \
                     ap_restart_requested ap_provision_requested client_connected client_disconnected client_connect_failed client_roamed \
                     client_renamed client_kicked client_steered client_wrong_password client_experience client_reconnect_requested client_blocked \
                     client_unblocked settings_imported settings_changed channel_plan";
        assert_eq!(names, known.split_whitespace().collect::<Vec<_>>());
        for k in EventKind::ALL {
            assert_eq!(serde_json::to_value(k).unwrap(), k.as_str());
        }
    }

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
    use crate::model::tests::{TestDir, flushed};
    use inform::{Flags, Header};
    use wire::decode::KeyUsed;

    fn decoded(payload: Value) -> Decoded {
        let header = Header {
            packet_version: 0,
            mac: Mac([0; 6]),
            flags: Flags::ENCRYPTED | Flags::GCM,
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
        store: Arc<store::Store>,
        writer: Writer,
        _dir: TestDir,
    }

    fn harness() -> Harness {
        harness_with(KeyStore::default())
    }

    /// An engine that knows these syslog keys.
    fn harness_with(keys: KeyStore) -> Harness {
        Harness::open(TestDir::new("engine"), keys)
    }

    impl Harness {
        /// An engine on the store in `dir`, new or left by an engine before.
        fn open(dir: TestDir, keys: KeyStore) -> Harness {
            let (store, writer) = store::Store::open(&dir).unwrap();
            let live: SharedLive = Default::default();
            let (tx, rx) = broadcast::channel(1024);
            Harness { engine: Engine::new(writer.clone(), Arc::new(keys), live.clone(), tx), live, rx, store, writer, _dir: dir }
        }

        /// The engine after apctl restarted: what this one wrote is stored, and a
        /// new engine on the same store restores what it remembers from it.
        fn restarted(self) -> Harness {
            let Harness { engine, live, rx, store, writer, _dir: dir } = self;
            flushed(&writer);
            drop((engine, live, rx, store, writer));
            let mut h = Harness::open(dir, KeyStore::default());
            h.engine.restore(&h.store).unwrap();
            h.live.read().unwrap().assert_connected();
            h
        }
    }

    /// The data of the stored events of one kind, oldest first (the live
    /// messages only say that an event was stored).
    fn stored(h: &Harness, kind: EventKind) -> Vec<Value> {
        flushed(&h.writer);
        h.store
            .read(Db::Config, |c| {
                let mut stmt = c.prepare("SELECT data FROM events WHERE kind = ?1 ORDER BY id")?;
                let rows = stmt.query_map([kind.as_str()], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows.iter().map(|d| serde_json::from_str(d).unwrap()).collect())
            })
            .unwrap()
    }

    /// The events sent since the last call. Every scenario reads them, so the
    /// connected set is checked against the clients here too.
    fn events(h: &mut Harness) -> Vec<(&'static str, Option<String>)> {
        h.live.read().unwrap().assert_connected();
        let mut out = Vec::new();
        while let Ok(m) = h.rx.try_recv() {
            if let LiveMsg::Event(e) = m {
                out.push((e.kind.as_str(), e.client_mac.map(|m| m.to_string())));
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
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(ap, 1000 + ts, clients)) });
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
    fn a_device_views_peer_is_shown_as_its_address() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: "2001:db8::7".parse().unwrap(), decoded: decoded(inform(AP1, 1000, &[])) });
        let mut d = h.live.read().unwrap().devices[&AP1.parse().unwrap()].clone();
        assert_eq!(serde_json::to_value(&d).unwrap()["peer"], "2001:db8::7");
        d.peer = None;
        assert_eq!(serde_json::to_value(&d).unwrap()["peer"], "", "known from the database only");
    }

    #[test]
    fn informs_without_a_client_list_do_not_disconnect_clients() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        events(&mut h);
        // Two minutes of informs that carry no client list (notifications, or any
        // short inform): nothing proves the client left.
        for ts in (5..120).step_by(5) {
            let d = if ts % 10 == 0 { notif(AP1, "event", json!({})) } else { decoded(json!({ "mac": AP1, "uptime": 1000 + ts })) };
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: d });
            h.engine.handle(Input::Tick(ts));
        }
        let evs = events(&mut h);
        assert!(evs.is_empty(), "{evs:?}");
        assert!(h.live.read().unwrap().clients[&C1.parse().unwrap()].connected);
    }

    #[test]
    fn an_ap_with_every_network_off_has_no_clients() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        events(&mut h);
        // Every SSID off (e.g. by a schedule): the AP still informs, with an empty VAP table.
        let ts = CLIENT_GRACE_SECS + 5;
        h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(json!({ "mac": AP1, "uptime": 1000 + ts, "vap_table": [] })) });
        h.engine.handle(Input::Tick(ts + 1));
        assert_eq!(events(&mut h), vec![("client_disconnected", Some(C1.into()))]);
        let live = h.live.read().unwrap();
        let d = &live.devices[&AP1.parse().unwrap()];
        assert!(d.snapshot.vaps.is_empty() && d.snapshot.clients.is_empty());
        assert_eq!(d.last_full_inform, ts);
    }

    #[test]
    fn restart_of_the_controller_does_not_reconnect_everyone() {
        let feed = |e: &mut Engine, ts| e.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000 + ts, &[(C1, "b1")])) });
        let mut h = harness();
        feed(&mut h.engine, 0);
        let mut h = h.restarted();
        h.engine.handle(Input::Tick(25)); // a tick before the first inform must not disconnect anyone
        feed(&mut h.engine, 30);
        assert_eq!(events(&mut h), []);
    }

    #[test]
    fn an_ap_away_is_marked_unavailable_to_the_clients_locked_to_it() {
        let mut h = harness();
        h.engine.set_state(0, json!({
            "devices": [{ "mac": AP1, "radio_table": [{ "radio": "na" }] }, { "mac": AP2 }],
            "clients": [{ "mac": C1, "fixed_ap_enabled": true, "fixed_ap_mac": AP1 }],
        }));
        let feed = |h: &mut Harness, ap: &str, ts: Ts| h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(ap, 1000 + ts, &[])) });
        let available = |h: &Harness, i: usize| h.live.read().unwrap().state.as_ref().unwrap()["devices"][i].get("fixed_ap_available").cloned();
        feed(&mut h, AP1, 0);
        feed(&mut h, AP2, 0);
        assert_eq!(available(&h, 0), None, "online, as without the field: nothing written");
        h.engine.handle(Input::Tick(100));
        // Only a device with radios is marked; the settings are stored, but not as a change of the user's.
        assert_eq!((available(&h, 0), available(&h, 1)), (Some(json!(false)), None));
        flushed(&h.writer);
        let stored_state: String = h.store.read(Db::Config, |c| Ok(c.query_row("SELECT json FROM controller_state", [], |r| r.get(0))?)).unwrap();
        assert!(stored_state.contains("\"fixed_ap_available\":false"), "{stored_state}");
        feed(&mut h, AP1, 200);
        assert_eq!(available(&h, 0), Some(json!(true)));
        assert!(stored(&h, EventKind::SettingsChanged).is_empty());
    }

    #[test]
    fn imported_and_restored_settings_get_the_engines_view_of_the_aps() {
        let mut h = harness();
        let feed = |h: &mut Harness, ap: &str, ts: Ts| h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(ap, 1000 + ts, &[])) });
        let available = |h: &Harness, i: usize| h.live.read().unwrap().state.as_ref().unwrap()["devices"][i].get("fixed_ap_available").cloned();
        let radios = json!([{ "radio": "na" }]);
        feed(&mut h, AP1, 0);
        feed(&mut h, AP2, 0);
        h.engine.handle(Input::Tick(30));
        // AP1 informs to apctl, so the other controller's `false` is replaced;
        // AP3 is not heard of, so its value is kept as imported.
        let ap3 = "02:00:00:00:00:03";
        h.engine.set_state(40, json!({ "devices": [
            { "mac": AP1, "radio_table": radios, "fixed_ap_available": false },
            { "mac": AP2, "radio_table": radios },
            { "mac": ap3, "radio_table": radios, "fixed_ap_available": false },
        ] }));
        assert_eq!((available(&h, 0), available(&h, 1), available(&h, 2)), (Some(json!(true)), None, Some(json!(false))));
        // AP2 goes away, then the settings are imported again saying it is there.
        feed(&mut h, AP1, 100);
        h.engine.handle(Input::Tick(120));
        assert_eq!(available(&h, 1), Some(json!(false)));
        h.engine.set_state(130, json!({ "devices": [{ "mac": AP1, "radio_table": radios }, { "mac": AP2, "radio_table": radios, "fixed_ap_available": true }] }));
        assert_eq!((available(&h, 0), available(&h, 1)), (None, Some(json!(false))));
        // Settings saved while it was there, with AP2 stored offline: a restart marks it.
        h.engine.set_fixed_ap_available(HashMap::from([(AP2.parse().unwrap(), true)]));
        assert_eq!(available(&h, 1), Some(json!(true)));
        let h = h.restarted();
        assert_eq!((available(&h, 0), available(&h, 1)), (None, Some(json!(false))), "AP1 is not known yet; AP2 is stored offline");
    }

    #[test]
    fn going_offline_and_coming_back_are_paired_across_a_restart() {
        let feed = |h: &mut Harness, ts: Ts| h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000 + ts, &[])) });
        // Reported offline, then apctl restarts: its return is reported after it.
        let mut h = harness();
        feed(&mut h, 0);
        h.engine.handle(Input::Tick(100));
        assert_eq!(events(&mut h), [("ap_seen", None), ("ap_offline", None)]);
        let mut h = h.restarted();
        feed(&mut h, 500);
        assert_eq!(events(&mut h), [("ap_online", None)]);
        assert_eq!(stored(&h, EventKind::ApOnline)[0]["offline_for"], 500);
        // Back online, as the next restart knows: nothing more to report.
        let mut h = h.restarted();
        feed(&mut h, 510);
        assert_eq!(events(&mut h), []);
        // Gone while apctl was away: reported offline once this run has given it time to inform.
        let mut h = h.restarted();
        h.engine.handle(Input::Tick(1000));
        let limit = crate::active::MAX_INFORM_INTERVAL * OFFLINE_INTERVALS;
        h.engine.handle(Input::Tick(1000 + limit));
        assert_eq!(events(&mut h), []);
        h.engine.handle(Input::Tick(1001 + limit));
        h.engine.handle(Input::Tick(1100 + limit));
        assert_eq!(events(&mut h), [("ap_offline", None)]);
        assert_eq!(stored(&h, EventKind::ApOffline)[1]["last_seen"], 510);
        let mut h = h.restarted();
        feed(&mut h, 2000);
        assert_eq!(events(&mut h), [("ap_online", None)]);
    }

    #[test]
    fn a_long_outage_gives_the_aps_time_to_inform() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        // Back after two hours: the first tick comes before the AP's first inform.
        let mut h = h.restarted();
        let limit = crate::active::MAX_INFORM_INTERVAL * OFFLINE_INTERVALS;
        h.engine.handle(Input::Tick(7200));
        h.engine.handle(Input::Tick(7200 + limit));
        assert_eq!(events(&mut h), [], "the AP and its client are left alone while the AP has time to inform");
        // An AP that never informs again goes offline, and its clients with it.
        h.engine.handle(Input::Tick(7201 + limit));
        assert_eq!(events(&mut h), [("ap_offline", None), ("client_disconnected", Some(C1.into()))]);
        assert_eq!(stored(&h, EventKind::ClientDisconnected)[0]["reason"], "ap_offline");
        // A client of an AP that is not known at all (e.g. forgotten): it goes an hour into the run.
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        let mut h = h.restarted();
        h.engine.live.write().unwrap().known_devices.clear();
        h.engine.handle(Input::Tick(7200));
        h.engine.handle(Input::Tick(7200 + 3600));
        assert_eq!(events(&mut h), []);
        h.engine.handle(Input::Tick(7200 + 3601));
        assert_eq!(events(&mut h), [("client_disconnected", Some(C1.into()))]);
        assert_eq!(stored(&h, EventKind::ClientDisconnected)[0]["reason"], "stale");
    }

    #[test]
    fn unchanged_rows_are_written_once_a_minute() {
        let mut h = harness();
        let feed = |e: &mut Engine, ts: Ts, name: &str| {
            let mut p = inform(AP1, 1000 + ts, &[(C1, "b1")]);
            p["hostname"] = json!(name);
            p["vap_table"][0]["sta_table"][0]["hostname"] = json!(name);
            e.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
        };
        let stored = |sql: &'static str| -> (i64, String) {
            flushed(&h.writer);
            h.store.read(Db::Config, |c| Ok(c.query_row(sql, [], |r| Ok((r.get(0)?, r.get(1)?)))?)).unwrap()
        };
        let (device, client) = ("SELECT last_seen, hostname FROM devices", "SELECT last_seen, hostname FROM clients");
        feed(&mut h.engine, 0, "a");
        feed(&mut h.engine, 15, "a");
        assert_eq!((stored(device), stored(client)), ((0, "a".into()), (0, "a".into())), "unchanged: not written again yet");
        feed(&mut h.engine, 30, "b");
        assert_eq!((stored(device), stored(client)), ((30, "b".into()), (30, "b".into())), "a change is written at once");
        feed(&mut h.engine, 45, "b");
        assert_eq!(stored(device).0, 30);
        feed(&mut h.engine, 90, "b");
        assert_eq!((stored(device).0, stored(client).0), (90, 90), "last_seen moves on once a minute");
        // Gone: the row says when it was last seen, which a restart restores.
        feed(&mut h.engine, 105, "b");
        assert_eq!(stored(client).0, 90);
        h.engine.handle(Input::Tick(400));
        assert_eq!(stored(client).0, 105);
        assert!(h.engine.written.clients.is_empty(), "nothing kept of a client gone");
    }

    #[test]
    fn unchanged_neighbours_are_written_once_a_minute_and_forgotten_when_gone() {
        let mut h = harness();
        let feed = |h: &mut Harness, ts: Ts, signal: Option<i64>| {
            let mut p = inform(AP1, 1000 + ts, &[]);
            if let Some(signal) = signal {
                p["radio_table"] = json!([{ "radio": "na", "scan_table": [{ "bssid": "02:cd:00:00:00:01", "signal": signal }] }]);
            }
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
        };
        let last_seen = |h: &Harness| -> i64 {
            flushed(&h.writer);
            h.store.read(Db::Config, |c| Ok(c.query_row("SELECT last_seen FROM neighbors", [], |r| r.get(0))?)).unwrap()
        };
        feed(&mut h, 0, Some(-70));
        feed(&mut h, 15, Some(-70));
        assert_eq!(last_seen(&h), 0, "unchanged: not written again yet");
        feed(&mut h, 30, Some(-60));
        assert_eq!(last_seen(&h), 30, "a change is written at once");
        feed(&mut h, 45, None);
        assert!(h.engine.written.neighbors[&AP1.parse().unwrap()].is_empty(), "no longer reported: forgotten");
        feed(&mut h, 50, Some(-60));
        assert_eq!(last_seen(&h), 50, "reported again: written as new");
        // An entry from an earlier scan was last seen when that scan heard it.
        let mut p = inform(AP1, 1000 + 70, &[]);
        p["radio_table"] = json!([{ "radio": "na", "scan_table": [{ "bssid": "02:cd:00:00:00:01", "signal": -50, "age": 1200 }] }]);
        h.engine.handle(Input::Inform { ts: 2000, peer: [10, 0, 0, 1].into(), decoded: decoded(p.clone()) });
        assert_eq!(last_seen(&h), 800);
        // Its age growing is no change, and as it was heard no later, it is not written again,
        // nor for the AP's rounding putting it a second earlier.
        let row = |h: &Harness| h.engine.written.neighbors[&AP1.parse().unwrap()]["02:cd:00:00:00:01"].written;
        for (ts, age) in [(2015, 1215), (2100, 1300), (2200, 1401)] {
            p["radio_table"][0]["scan_table"][0]["age"] = json!(age);
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(p.clone()) });
            assert_eq!(row(&h), 800);
        }
        // Heard again by a new scan: written.
        p["radio_table"][0]["scan_table"][0]["age"] = json!(0);
        h.engine.handle(Input::Inform { ts: 2210, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
        assert_eq!(last_seen(&h), 2210);
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
        let renames = stored(&h, EventKind::ClientRenamed);
        assert_eq!(renames.len(), 2, "{renames:?}");
        assert_eq!(renames[1]["from"], "Kitchen speaker");
    }

    #[test]
    fn syslog_keys_are_tried_once_per_unknown_sender() {
        let mut keys = KeyStore::default();
        keys.insert_syslog(AP1, &hex::encode([7u8; 32])).unwrap();
        let mut h = harness_with(keys);
        let live = h.live.clone();
        let send = |h: &mut Harness, ts: Ts, hash_id: u8, key: u8| {
            let payload = crate::syslog::tests::seal([hash_id; 8], [key; 32], "<14>hostapd: hello");
            h.engine.handle(Input::Datagram { ts, src_ip: "192.0.2.1".into(), payload });
        };
        let logs = || live.read().unwrap().counters.logs.load(Ordering::Relaxed);
        // An AP whose key apctl lacks: remembered, not tried again for a while.
        send(&mut h, 0, 1, 9);
        assert_eq!(h.engine.syslog_unknown.get(&u64::from_be_bytes([1; 8])), Some(&0));
        send(&mut h, 10, 1, 9);
        assert_eq!(h.engine.syslog_unknown.get(&u64::from_be_bytes([1; 8])), Some(&0), "not retried within the window");
        h.engine.handle(Input::Tick(SYSLOG_RETRY_SECS));
        assert!(h.engine.syslog_unknown.is_empty(), "expired");
        // A known key under a hash_id not seen yet: found by trial and remembered.
        send(&mut h, 20, 2, 7);
        assert_eq!(logs(), 1);
        assert_eq!(live.read().unwrap().by_hash_id.get(&u64::from_be_bytes([2; 8])), Some(&AP1.parse().unwrap()));
        // A hash_id the AP has since (e.g. after a reset) replaces the one before.
        send(&mut h, 21, 6, 7);
        let by_hash_id = live.read().unwrap().by_hash_id.clone();
        assert_eq!(by_hash_id.into_iter().collect::<Vec<_>>(), vec![(u64::from_be_bytes([6; 8]), AP1.parse().unwrap())]);
        // An AP apctl adopted: its key is in the settings only.
        send(&mut h, 30, 3, 5);
        assert_eq!(logs(), 2);
        let ap2 = "02:00:00:00:00:02";
        h.engine.set_state(31, json!({ "devices": [{ "mac": ap2, "syslog_key": hex::encode([5u8; 32]) }] }));
        assert!(h.engine.syslog_unknown.is_empty(), "new settings, new keys: tried again");
        send(&mut h, 32, 3, 5);
        assert_eq!(logs(), 3);
        assert_eq!(live.read().unwrap().by_hash_id.get(&u64::from_be_bytes([3; 8])), Some(&ap2.parse().unwrap()));
        // So many unknown hash_ids at once: a new one is not tried with every key.
        for i in 0..SYSLOG_UNKNOWN_MAX {
            h.engine.syslog_unknown.insert(i as u64, 40);
        }
        send(&mut h, 41, 4, 7);
        assert_eq!((logs(), h.engine.syslog_unknown.len()), (3, SYSLOG_UNKNOWN_MAX));
        assert!(!live.read().unwrap().by_hash_id.contains_key(&u64::from_be_bytes([4; 8])));
    }

    #[test]
    fn a_datagram_no_key_opens_does_not_hold_up_the_syslog_of_an_ap_its_informs_name() {
        let mut keys = KeyStore::default();
        keys.insert_syslog(AP1, &hex::encode([7u8; 32])).unwrap();
        let mut h = harness_with(keys);
        let mut p = inform(AP1, 1000, &[]);
        p["hash_id"] = json!(hex::encode([1u8; 8]));
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
        let send = |h: &mut Harness, ts: Ts, key: u8| {
            let payload = crate::syslog::tests::seal([1; 8], [key; 32], "<14>hostapd: hello");
            h.engine.handle(Input::Datagram { ts, src_ip: "192.0.2.1".into(), payload });
        };
        // Under the AP's hash_id, sealed with a key that isn't its own (made up).
        send(&mut h, 1, 9);
        assert_eq!(h.engine.syslog_unknown.get(&u64::from_be_bytes([1; 8])), Some(&1));
        // The AP's own is read with its key at once, not left for the retry window.
        send(&mut h, 2, 7);
        assert_eq!(h.live.read().unwrap().counters.logs.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn plain_syslog_names_an_ap_by_its_address_only_without_a_key() {
        let mut keys = KeyStore::default();
        keys.insert_syslog(AP1, &hex::encode([7u8; 32])).unwrap();
        let mut h = harness_with(keys);
        let ap2: Mac = "02:00:00:00:00:02".parse().unwrap();
        h.live.write().unwrap().by_ip.insert("192.0.2.1".into(), AP1.parse().unwrap());
        h.live.write().unwrap().by_ip.insert("192.0.2.2".into(), ap2);
        let events = |h: &mut Harness, ts: Ts, src: &str, text: &str| {
            h.engine.handle(Input::Datagram { ts, src_ip: src.into(), payload: text.as_bytes().to_vec() });
            std::iter::from_fn(|| h.rx.try_recv().ok()).filter_map(|m| match m { LiveMsg::Event(e) => Some((e.kind, e.device_mac)), _ => None }).collect::<Vec<_>>()
        };
        let kick = "<14>stamgr: kick-sta-on 6c:ac:c2:00:00:01 wifi1ap1 (reason:Low RSSI rssi:19)";
        // From the address of an AP that encrypts its syslog: not taken for the AP's.
        assert_eq!(events(&mut h, 1, "192.0.2.1", kick), [(EventKind::ClientKicked, None)]);
        // Its netconsole's crash is, as the official controller takes it.
        assert_eq!(events(&mut h, 2, "192.0.2.1", "[ 12.3] Kernel panic - not syncing: Fatal exception"), [(EventKind::ApCrash, AP1.parse().ok())]);
        // An AP without a key logs in plain text: its address names it.
        assert_eq!(events(&mut h, 3, "192.0.2.2", "<14>stamgr: kick-sta-on 6c:ac:c2:00:00:02 wifi1ap1 (reason:Low RSSI rssi:19)"), [(EventKind::ClientKicked, Some(ap2))]);
    }

    #[test]
    fn a_bulk_import_announces_the_renames_and_the_client_list_once() {
        let mut h = harness();
        let edit = |mac: &str, alias: &str| AliasEdit { mac: mac.parse().unwrap(), alias: Some(alias.into()), note: None };
        let entries = vec![edit(C1, "Speaker"), edit("02:00:00:00:01:02", "Printer"), edit("02:00:00:00:01:03", "")];
        h.engine.handle(Input::SetAliases { ts: 1, entries, only_if_unset: true });
        let msgs: Vec<LiveMsg> = std::iter::from_fn(|| h.rx.try_recv().ok()).collect();
        let renames: Vec<_> = msgs.iter().filter_map(|m| match m { LiveMsg::Event(e) if e.kind == EventKind::ClientRenamed => Some(e.client_mac), _ => None }).collect();
        let lists = msgs.iter().filter(|m| matches!(m, LiveMsg::Clients)).count();
        assert_eq!((renames, lists), (vec![None], 1), "{msgs:?}");
        assert_eq!(h.live.read().unwrap().aliases.len(), 2);
        assert_eq!(stored(&h, EventKind::ClientRenamed).len(), 2, "each rename is still its own event");
        // A single rename names its client.
        h.engine.handle(Input::SetAliases { ts: 2, entries: vec![edit(C1, "Kitchen speaker")], only_if_unset: false });
        let renames: Vec<_> = std::iter::from_fn(|| h.rx.try_recv().ok()).filter_map(|m| match m { LiveMsg::Event(e) => Some(e.client_mac), _ => None }).collect();
        assert_eq!(renames, [C1.parse().ok()]);
    }

    #[test]
    fn an_import_keeps_notes_of_clients_without_a_name() {
        let mut h = harness();
        let (c2, c3): (Mac, Mac) = ("02:00:00:00:01:02".parse().unwrap(), "02:00:00:00:01:03".parse().unwrap());
        let edit = |mac: Mac, alias: Option<&str>, note: Option<&str>| AliasEdit { mac, alias: alias.map(str::to_string), note: note.map(str::to_string) };
        let entries = vec![edit(c2, None, Some("behind the TV")), edit(c3, None, Some("guest laptop"))];
        h.engine.handle(Input::SetAliases { ts: 1, entries, only_if_unset: false });
        // One import entry names a client that only has a note; another has no name at all.
        let entries = vec![edit(c2, Some("TV"), None), edit(c3, Some(""), None)];
        h.engine.handle(Input::SetAliases { ts: 2, entries, only_if_unset: true });
        let live = h.live.read().unwrap();
        assert_eq!((live.aliases[&c2].alias.as_deref(), live.aliases[&c2].note.as_deref()), (Some("TV"), Some("behind the TV")));
        assert_eq!((live.aliases[&c3].alias.as_deref(), live.aliases[&c3].note.as_deref()), (None, Some("guest laptop")));
    }

    #[test]
    fn settings_edits_are_applied_recorded_or_refused() {
        let mut h = harness();
        let edit = |h: &mut Harness, f: StateEdit| {
            let (tx, mut rx) = tokio::sync::oneshot::channel();
            h.engine.handle(Input::EditState { ts: 5, edit: f, done: tx });
            rx.try_recv().unwrap()
        };
        assert!(edit(&mut h, Box::new(|_| Ok("nothing".into()))).is_err(), "nothing to edit before an import");
        h.engine.handle(Input::SetState { ts: 1, state: json!({ "clients": [] }) });
        let what = edit(&mut h, Box::new(|s| {
            crate::actions::edit_client(s, C1.parse().unwrap(), &[("blocked", json!(true))]);
            Ok("blocked client".into())
        }));
        assert_eq!(what.as_deref(), Ok("blocked client"), "what the edit itself reports");
        assert_eq!(h.live.read().unwrap().state.as_ref().unwrap()["clients"][0]["blocked"], true);
        assert_eq!(h.live.read().unwrap().state_imported_at, Some(1), "an edit is not an import");
        assert_eq!(edit(&mut h, Box::new(|_| Err("no".into()))), Err("no".into()));
        // An edit that leaves the settings as they were still reports what it did, but is not recorded.
        assert_eq!(edit(&mut h, Box::new(|_| Ok("nothing changed".into()))).as_deref(), Ok("nothing changed"));
        let kinds: Vec<_> = events(&mut h).into_iter().map(|e| e.0).collect();
        assert_eq!(kinds, ["settings_imported", "settings_changed"]);
    }

    #[test]
    fn multicast_rates_count_networks_once_and_clients_each() {
        let mut h = harness();
        // Per-network "to clients" counters repeat in every client's block.
        let sta = |mac: &str, to: i64, from: i64| json!({ "mac": mac, "multicast": { "types": { "mdns": { "tx_pkts": to, "tx_bytes": to * 100, "rx_pkts": from, "rx_bytes": from * 100 } } } });
        let feed = |e: &mut Engine, ts: Ts, to: i64, from: i64| {
            let p = json!({ "mac": AP1, "uptime": 1000 + ts, "vap_table": [{ "bssid": "b1", "radio": "na", "usage": "user", "sta_table": [sta(C1, to, from), sta("02:00:00:00:01:02", to, 0)] }] });
            e.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
        };
        feed(&mut h.engine, 0, 100, 0);
        feed(&mut h.engine, 10, 200, 50);
        flushed(&h.writer);
        let row: (f64, f64, f64, f64) = h
            .store
            .read(Db::Metrics, |c| Ok(c.query_row("SELECT tx_pps, rx_pps, rx_bytes_ps, clients FROM mcast_stats WHERE ts = 10 AND type = 'mdns'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?))
            .unwrap();
        assert_eq!(row, (10.0, 5.0, 500.0, 1.0));
        // The previous samples are kept only as long as they can give a rate.
        h.engine.handle(Input::Tick(10 + MCAST_GAP));
        assert_eq!((h.engine.mcast_prev.len(), h.engine.bss_prev.len()), (2, 1));
        h.engine.handle(Input::Tick(10 + 2 * MCAST_GAP));
        assert!(h.engine.mcast_prev.is_empty() && h.engine.bss_prev.is_empty());
    }

    #[test]
    fn an_isolated_beacon_is_blamed_on_the_ap_it_derives_from() {
        // Which AP each beacon (BSSID, serial number) is blamed on, with our APs at `aps`.
        let blamed = |aps: [&str; 2], scan: Vec<(&str, Option<&str>)>| {
            let mut h = harness();
            for (i, ap) in aps.iter().enumerate() {
                h.engine.handle(Input::Inform { ts: i as Ts, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(ap, 1000, &[])) });
            }
            let mut p = inform(aps[0], 1002, &[]);
            let scan: Vec<Value> = scan.iter().map(|(bssid, serial)| json!({ "bssid": bssid, "serialno": serial, "is_isolated": true, "signal": -70 })).collect();
            p["radio_table"] = json!([{ "radio": "na", "scan_table": scan }]);
            h.engine.handle(Input::Inform { ts: 2, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
            std::iter::from_fn(|| h.rx.try_recv().ok())
                .filter_map(|m| match m { LiveMsg::Event(e) if e.kind == EventKind::ApIsolated => e.device_mac.map(|m| m.to_string()), _ => None })
                .collect::<Vec<_>>()
        };
        // Both MACs are within 16 of the BSSID: the one at or below it, even when the other is nearer.
        assert_eq!(blamed(["02:00:00:00:00:10", "02:00:00:00:00:18"], vec![("02:00:00:00:00:1a", None)]), ["02:00:00:00:00:18"]);
        assert_eq!(blamed(["02:00:00:00:00:10", "02:00:00:00:00:20"], vec![("02:00:00:00:00:1c", None)]), ["02:00:00:00:00:10"]);
        // None at or below it: the nearest above.
        assert_eq!(blamed(["02:00:00:00:00:10", "02:00:00:00:00:30"], vec![("02:00:00:00:00:0c", None)]), ["02:00:00:00:00:10"]);
        // A beacon naming its AP: that one, wherever its BSSID is, and none when it is not ours.
        assert_eq!(blamed(["02:00:00:00:00:10", "02:00:00:00:00:20"], vec![("02:00:00:00:00:1c", Some("020000000020"))]), ["02:00:00:00:00:20"]);
        assert!(blamed(["02:00:00:00:00:10", "02:00:00:00:00:20"], vec![("02:00:00:00:00:1c", Some("020000000099"))]).is_empty());
        // Zeros name no AP.
        assert_eq!(blamed(["02:00:00:00:00:10", "02:00:00:00:00:20"], vec![("02:00:00:00:00:1c", Some("00:00:00:00:00:00"))]), ["02:00:00:00:00:10"]);
    }

    #[test]
    fn an_isolated_beacon_kept_from_an_earlier_scan_is_no_news() {
        let mut h = harness();
        let (a, b) = ("02:00:00:00:00:10", "02:00:00:00:00:18");
        h.engine.handle(Input::Tick(100));
        h.engine.handle(Input::Inform { ts: 100, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(b, 1000, &[])) });
        let isolated = |h: &mut Harness, ts: Ts, age: Ts| {
            let mut p = inform(a, 1000 + ts, &[]);
            p["radio_table"] = json!([{ "radio": "na", "scan_table": [{ "bssid": "02:00:00:00:00:1a", "is_isolated": true, "signal": -70, "age": age }] }]);
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
            std::iter::from_fn(|| h.rx.try_recv().ok()).filter(|m| matches!(m, LiveMsg::Event(e) if e.kind == EventKind::ApIsolated)).count()
        };
        assert_eq!(isolated(&mut h, 120, 50), 0, "heard before this run");
        assert_eq!(isolated(&mut h, 130, 0), 1);
        assert_eq!(isolated(&mut h, 4000, 3870), 0, "the same sighting, an hour on");
        assert_eq!(isolated(&mut h, 4010, 270), 1, "heard again an hour after");
    }

    #[test]
    fn an_isolated_beacon_is_blamed_on_an_ap_known_from_an_earlier_run() {
        let mut h = harness();
        let (a, b) = ("02:00:00:00:00:10", "02:00:00:00:00:18");
        // B is only in the database: it lost its uplink before apctl restarted.
        let known = KnownDevice { first_seen: 0, last_seen: 0, uptime: None, version: None, hostname: None, model: None, model_display: None, ip: None, serial: None, offline: false };
        h.engine.live.write().unwrap().known_devices.insert(b.parse().unwrap(), known);
        let mut p = inform(a, 1000, &[]);
        p["radio_table"] = json!([{ "radio": "na", "scan_table": [{ "bssid": "02:00:00:00:00:1a", "is_isolated": true, "signal": -70 }] }]);
        h.engine.handle(Input::Inform { ts: 2, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
        let blamed: Vec<_> = std::iter::from_fn(|| h.rx.try_recv().ok())
            .filter_map(|m| match m { LiveMsg::Event(e) if e.kind == EventKind::ApIsolated => Some(e.device_mac), _ => None })
            .collect();
        assert_eq!(blamed, [b.parse().ok()]);
    }

    #[test]
    fn captured_informs_are_stored_without_a_failing_write() {
        use crate::model::tests::{fixture, fixtures};
        let Some(_) = fixtures() else { return };
        let (writer, store) = store::capture();
        let (tx, _rx) = broadcast::channel(1024);
        let mut e = Engine::new(writer, Default::default(), Default::default(), tx);
        // Twice each, so the second inform's rows are compared with the first's.
        for (ts, name) in [(0, "000001_020000000001_inform"), (1, "000003_020000000002_inform"), (100, "000001_020000000001_inform"), (101, "000003_020000000002_inform")] {
            e.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(fixture(name)) });
        }
        let dir = TestDir::new("fixture-writes");
        assert_eq!(store(&dir).unwrap(), 0);
    }

    #[test]
    fn live_messages_are_short() {
        let mut h = harness();
        let line = |ts| LogLine { ts, device_mac: AP1.parse().ok(), src_ip: "x".into(), facility: None, severity: None, program: None, msg: "m".into() };
        // A burst in one second is announced once, and what came after at the next tick.
        for ts in [10, 10, 10, 11] {
            h.engine.log(line(ts));
        }
        h.engine.handle(Input::Tick(12));
        let logs = std::iter::from_fn(|| h.rx.try_recv().ok()).filter(|m| matches!(m, LiveMsg::Log { .. })).count();
        assert_eq!(logs, 2);
        h.engine.log(line(12));
        h.engine.handle(Input::Tick(13));
        let logs = std::iter::from_fn(|| h.rx.try_recv().ok()).filter(|m| matches!(m, LiveMsg::Log { .. })).count();
        assert_eq!(logs, 1, "nothing more to announce");
        // An event's data is not sent to the browsers.
        h.engine.emit(Event::device(1, EventKind::ApCrash, AP1.parse().unwrap(), json!({ "lines": ["a long crash dump"] })));
        let text = std::iter::from_fn(|| h.rx.try_recv().ok()).find(|m| matches!(m, LiveMsg::Event(_))).map(|m| serde_json::to_string(&m).unwrap());
        assert_eq!(text.as_deref(), Some(r#"{"type":"event","kind":"ap_crash","device_mac":"02:00:00:00:00:01","client_mac":null}"#));
    }

    #[test]
    fn an_ap_going_offline_drops_the_commands_that_need_it_online() {
        let mut h = harness();
        let mac: Mac = AP1.parse().unwrap();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000, &[])) });
        let block = json!({ "_type": "cmd", "cmd": "block-sta", "mac": C1 });
        {
            let mut live = h.live.write().unwrap();
            crate::actions::queue(&mut live, mac, json!({ "_type": "reboot", "reboot_type": "soft" }));
            crate::actions::queue(&mut live, mac, json!({ "_type": "cmd", "cmd": "set-locate" }));
            live.locating.insert(mac);
            crate::actions::queue(&mut live, mac, json!({ "_type": "cmd", "cmd": "kick-sta", "mac": C1 }));
            crate::actions::queue(&mut live, mac, block.clone());
        }
        h.engine.handle(Input::Tick(100));
        // Blocking is carried by its config anyway: kept, as it does no harm.
        let live = h.live.read().unwrap();
        assert_eq!(live.commands[&mac], [block]);
        assert!(live.locating.is_empty());
    }

    #[test]
    fn a_forgotten_ap_leaves_nothing_behind() {
        let mut h = harness();
        let mac: Mac = AP1.parse().unwrap();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        {
            let mut live = h.live.write().unwrap();
            live.commands.entry(mac).or_default().push_back(json!({ "cmd": "restart" }));
            live.locating.insert(mac);
            live.reprovision.insert(mac);
            live.last_config.insert(mac, Default::default());
            live.adoption.forgetting.insert(mac, 1);
        }
        // What active mode keeps of it goes too.
        let managed = Arc::new(std::sync::Mutex::new(vec![mac]));
        let m = managed.clone();
        h.live.write().unwrap().forget_managed = Some(Arc::new(move |gone: &Mac| m.lock().unwrap().retain(|x| x != gone)));
        events(&mut h);
        h.engine.handle(Input::Forget { ts: 5, mac });
        assert_eq!(events(&mut h), vec![("client_disconnected", Some(C1.into()))]);
        let live = h.live.read().unwrap();
        assert!(!live.clients[&C1.parse().unwrap()].connected);
        assert!(live.commands.is_empty() && live.locating.is_empty() && live.reprovision.is_empty() && live.devices.is_empty());
        assert!(live.raw_informs.is_empty() && live.last_config.is_empty() && live.adoption.forgetting.is_empty() && live.by_ip.is_empty());
        assert!(managed.lock().unwrap().is_empty());
    }

    #[test]
    fn only_a_report_with_clients_announces_the_client_list() {
        let mut h = harness();
        let lists = |h: &mut Harness| std::iter::from_fn(|| h.rx.try_recv().ok()).filter(|m| matches!(m, LiveMsg::Clients)).count();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000, &[])) });
        assert_eq!(lists(&mut h), 0, "no clients: nothing for the client lists");
        h.engine.handle(Input::Inform { ts: 10, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1010, &[(C1, "b1")])) });
        assert_eq!(lists(&mut h), 1);
    }

    #[test]
    fn an_upgrade_apctl_sent_is_one_event() {
        let mut h = harness();
        let mac: Mac = AP1.parse().unwrap();
        let feed = |h: &mut Harness, ts: Ts, version: &str| {
            let mut p = inform(AP1, 1000 + ts, &[]);
            p["version"] = json!(version);
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(p) });
        };
        feed(&mut h, 0, "6.7.0");
        let job = crate::firmware::Job {
            mac, name: None, from: Some("6.7.0".into()), target: "6.8.2".into(), url: String::new(), md5: None, sha256: None, custom: false,
            state: crate::firmware::JobState::Sent, sent_at: Some(5), expires: None,
        };
        h.live.write().unwrap().firmware.current = Some(job);
        feed(&mut h, 10, "6.8.2");
        // A change apctl did not send is still reported as such.
        feed(&mut h, 20, "6.8.3");
        let kinds: Vec<_> = events(&mut h).into_iter().map(|e| e.0).collect();
        assert_eq!(kinds, ["ap_seen", "ap_upgraded", "ap_firmware_changed"]);
        assert_eq!(stored(&h, EventKind::ApUpgraded)[0]["from"], "6.7.0");
    }

    fn notif(ap: &str, reason: &str, payload: Value) -> Decoded {
        decoded(json!({ "mac": ap, "inform_as_notif": true, "notif_reason": reason, "notif_payload": payload, "cfgversion": "abc" }))
    }

    #[test]
    fn notifications_are_events_not_status() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 1000, &[(C1, "b1")])) });
        events(&mut h);
        // Config acknowledgement and a connection-tracker success: no client changes.
        h.engine.handle(Input::Inform { ts: 5, peer: [10, 0, 0, 1].into(), decoded: notif(AP1, "setparam", Value::Null) });
        let success = json!({ "message_type": "STA_ASSOC_TRACKER", "event_type": "success", "mac": C1, "vap": "wifi1ap0",
            "assoc_delta": "40000", "wpa_auth_delta": "80000", "ip_delta": "100000", "dns_responses": "1", "dns_timeouts": "0", "avg_rssi": "-61" });
        h.engine.handle(Input::Inform { ts: 6, peer: [10, 0, 0, 1].into(), decoded: notif(AP1, "event", success) });
        // Failures as the connection views count them: not one at a weak signal,
        // nor a soft failure that got traffic and DNS answers.
        let tracker = |fields: Value| {
            let mut n = json!({ "message_type": "STA_ASSOC_TRACKER", "mac": C1, "vap": "wifi1ap0" });
            n.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone());
            notif(AP1, "event", n)
        };
        h.engine.handle(Input::Inform { ts: 7, peer: [10, 0, 0, 1].into(), decoded: tracker(json!({ "event_type": "failure", "wpa_auth_failures": "1", "auth_rssi": "-81" })) });
        let fine = json!({ "event_type": "soft failure", "dns_timeouts": "1", "traffic_delta": "300000", "dns_responses": "2", "auth_rssi": "-60" });
        h.engine.handle(Input::Inform { ts: 7, peer: [10, 0, 0, 1].into(), decoded: tracker(fine) });
        h.engine.handle(Input::Inform { ts: 7, peer: [10, 0, 0, 1].into(), decoded: tracker(json!({ "event_type": "failure", "wpa_auth_failures": "1", "auth_rssi": "-60" })) });
        h.engine.handle(Input::Inform { ts: 8, peer: [10, 0, 0, 1].into(), decoded: notif(AP1, "event", json!({ "event_string": "EVT_AP_RadarDetected", "channel": 52 })) });
        assert_eq!(
            events(&mut h),
            vec![("config_applied", None), ("client_connect_failed", Some(C1.into())), ("dfs_radar", None)]
        );
        let failed = stored(&h, EventKind::ClientConnectFailed);
        assert_eq!((&failed[0]["reason"], &failed[0]["rssi"]), (&json!("WPA authentication"), &json!(-60.0)));
        // One whose mac is not one is counted as undecodable.
        let mut bad = notif(AP1, "setparam", Value::Null);
        bad.payload["mac"] = json!("nope");
        h.engine.handle(Input::Inform { ts: 9, peer: [10, 0, 0, 1].into(), decoded: bad });
        assert_eq!(events(&mut h), vec![]);
        let live = h.live.read().unwrap();
        assert_eq!(live.counters.decode_errors.load(Ordering::Relaxed), 1);
        assert!(live.clients[&C1.parse().unwrap()].connected);
        assert_eq!(live.counters.notifications.load(Ordering::Relaxed), 6);
        assert_eq!(live.devices[&AP1.parse().unwrap()].last_full_inform, 0, "notifications are not client lists");
    }

    #[test]
    fn crash_reports_and_restarts_are_summed_up_when_stored() {
        use base64::Engine as _;
        let mut h = harness();
        let crash = |h: &mut Harness, ts: Ts, text: &str| {
            let payload = json!(base64::engine::general_purpose::STANDARD.encode(text));
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: notif(AP1, "crashlog", payload) });
        };
        // The fault line, not the first of the lines kept.
        crash(&mut h, 1, "boot line\n[ 12.3] Kernel panic - not syncing: Fatal exception\nreboot");
        crash(&mut h, 2, "no fault here\nnor here");
        crash(&mut h, 3, "\n");
        let summaries: Vec<Value> = stored(&h, EventKind::ApCrash).into_iter().map(|d| d.get("summary").cloned().unwrap_or(Value::Null)).collect();
        assert_eq!(summaries, [json!("[ 12.3] Kernel panic - not syncing: Fatal exception"), json!("no fault here"), Value::Null]);
        // A code sent as text is stored as a number; one that is no number is left out.
        for (ts, code) in [(4, json!("139")), (5, json!(1)), (6, json!("n/a"))] {
            let n = json!({ "event_string": "EVT_AP_RestartProc", "proc": "mcad", "exit_status": code, "caller": "init" });
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: notif(AP1, "event", n) });
        }
        let codes: Vec<Option<Value>> = stored(&h, EventKind::ApProcessRestarted).into_iter().map(|d| d.get("exit_status").cloned()).collect();
        assert_eq!(codes, [Some(json!(139)), Some(json!(1)), None]);
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
            h.engine.handle(Input::Inform { ts: t, peer: [10, 0, 0, 1].into(), decoded: decoded(v) });
        };
        feed(&mut h, with(44, 9));
        feed(&mut h, with(44, 23)); // transient after a restart
        feed(&mut h, with(44, 9));
        feed(&mut h, with(36, 9)); // real change...
        feed(&mut h, with(36, 9)); // ...confirmed
        feed(&mut h, with(36, 9));
        let changes = stored(&h, EventKind::RadioChanged);
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0]["from"]["channel"], 44);
        assert_eq!(changes[0]["to"]["channel"], 36);
    }

    #[test]
    fn ap_offline_restart_and_config_push() {
        let mut h = harness();
        h.engine.handle(Input::Inform { ts: 0, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 5000, &[(C1, "b1")])) });
        h.engine.handle(Input::Tick(30));
        events(&mut h);
        h.engine.handle(Input::Tick(100));
        assert_eq!(events(&mut h), vec![("ap_offline", None), ("client_disconnected", Some(C1.into()))]);
        // A notification while offline does not shorten the time reported offline.
        h.engine.handle(Input::Inform { ts: 150, peer: [10, 0, 0, 1].into(), decoded: notif(AP1, "event", json!({})) });
        // Back with a low uptime: online again and restarted.
        h.engine.handle(Input::Inform { ts: 200, peer: [10, 0, 0, 1].into(), decoded: decoded(inform(AP1, 50, &[])) });
        assert_eq!(events(&mut h), vec![("ap_online", None), ("ap_restarted", None)]);
        assert_eq!(stored(&h, EventKind::ApOnline)[0]["offline_for"], 200);

        let mac: Mac = AP1.parse().unwrap();
        let push = |cfg: &str| decoded(json!({ "_type": "setparam", "cfgversion": "x", "system_cfg": cfg, "mgmt_cfg": "a=1" }));
        h.engine.handle(Input::Reply { ts: 210, mac, decoded: push("aaa.1.hide_ssid=false\naaa.1.wpa.psk=old") });
        h.engine.handle(Input::Reply { ts: 220, mac, decoded: push("aaa.1.hide_ssid=true\naaa.1.wpa.psk=new") });
        let pushes = stored(&h, EventKind::ConfigPushed);
        assert_eq!(pushes[0]["system_cfg"]["baseline"], true);
        assert_eq!(
            pushes[1]["system_cfg"]["changes"],
            json!([
                { "op": "~", "key": "aaa.1.hide_ssid", "old": "false", "new": "true" },
                { "op": "~", "key": "aaa.1.wpa.psk", "old": "<redacted>", "new": "<redacted>" },
            ])
        );

        // A push without a cfgversion keeps the last one, in memory as in the database.
        let push = json!({ "_type": "setparam", "mgmt_cfg": "cfgversion=v1\na=1", "system_cfg": "x=1" });
        h.engine.handle(Input::Reply { ts: 230, mac, decoded: decoded(push) });
        h.engine.handle(Input::Reply { ts: 240, mac, decoded: decoded(json!({ "_type": "setparam", "system_cfg": "x=2" })) });
        assert_eq!(h.live.read().unwrap().last_config[&mac].cfgversion.as_deref(), Some("v1"));
        flushed(&h.writer);
        let cfgversion: String = h.store.read(Db::Config, |c| Ok(c.query_row("SELECT cfgversion FROM device_config", [], |r| r.get(0))?)).unwrap();
        assert_eq!(cfgversion, "v1");

        // A management-only push keeps the last system_cfg.
        h.engine.handle(Input::Reply { ts: 250, mac, decoded: decoded(json!({ "_type": "setparam", "mgmt_cfg": "cfgversion=v2\na=2" })) });
        let last = h.live.read().unwrap().last_config[&mac].clone();
        assert_eq!((last.mgmt_cfg.as_str(), last.system_cfg.as_str(), last.cfgversion.as_deref()), ("cfgversion=v2\na=2", "x=2", Some("v2")));
        // With settings and a renderer, a push is compared with what apctl would push.
        h.engine.set_state(260, json!({}));
        h.engine.set_renderer(Arc::new(|_: &crate::dryrun::RenderRequest| -> anyhow::Result<crate::dryrun::Rendered> { anyhow::bail!("no template") }));
        h.engine.handle(Input::Reply { ts: 270, mac, decoded: decoded(json!({ "_type": "setparam", "system_cfg": "x=3" })) });
        assert_eq!(stored(&h, EventKind::DryrunCompared)[0]["error"], "no template");
        flushed(&h.writer);
        let row: (String, Option<String>, i64) =
            h.store.read(Db::Config, |c| Ok(c.query_row("SELECT mac, cfgversion, matches FROM dryrun_results", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?)).unwrap();
        assert_eq!(row, (AP1.to_string(), Some("v2".into()), 0));
        // The event names the field that differs, and when only the order does;
        // the stored comparison has the counts without the diffs' text.
        h.engine.set_renderer(Arc::new(|_: &crate::dryrun::RenderRequest| -> anyhow::Result<crate::dryrun::Rendered> { Ok(("cfgversion=v2\na=9".into(), "y=1\nx=4".into())) }));
        h.engine.handle(Input::Reply { ts: 280, mac, decoded: decoded(json!({ "_type": "setparam", "system_cfg": "x=4\ny=1" })) });
        let counts = |added, removed, changed, same_content| json!({ "added": added, "removed": removed, "changed": changed, "same_content": same_content });
        let compared = stored(&h, EventKind::DryrunCompared);
        assert_eq!(compared[1], json!({ "matches": false, "mgmt_cfg": counts(0, 0, 1, false), "system_cfg": counts(0, 0, 0, true) }));
        let comparison: Value =
            serde_json::from_str(&h.store.read(Db::Config, |c| Ok(c.query_row("SELECT comparison FROM dryrun_results ORDER BY ts DESC", [], |r| r.get::<_, String>(0))?)).unwrap()).unwrap();
        assert_eq!((comparison["mgmt_cfg"]["changed"].as_i64(), comparison["mgmt_cfg"].get("diff"), comparison["system_cfg"].get("diff")), (Some(1), None, None));
    }

    #[test]
    fn the_first_push_after_a_restart_is_compared_with_the_stored_one() {
        let mut h = harness();
        let mac: Mac = AP1.parse().unwrap();
        let push = |h: &mut Harness, ts: Ts, v: Value| h.engine.handle(Input::Reply { ts, mac, decoded: decoded(v) });
        push(&mut h, 10, json!({ "_type": "setparam", "mgmt_cfg": "cfgversion=v1\na=1", "system_cfg": "aaa.1.hide_ssid=false\naaa.1.wpa.psk=old" }));
        let mut h = h.restarted();
        // What it changed, not a baseline; the secret, masked in the stored copy, is not compared.
        push(&mut h, 20, json!({ "_type": "setparam", "mgmt_cfg": "cfgversion=v2\na=1", "system_cfg": "aaa.1.hide_ssid=true\naaa.1.wpa.psk=old" }));
        let pushed = stored(&h, EventKind::ConfigPushed).pop().unwrap();
        let changes = |p: &Value| (p["system_cfg"]["changes"].clone(), p["mgmt_cfg"]["changes"].clone());
        assert_eq!(
            changes(&pushed),
            (json!([{ "op": "~", "key": "aaa.1.hide_ssid", "old": "false", "new": "true" }]), json!([{ "op": "~", "key": "cfgversion", "old": "v1", "new": "v2" }]))
        );
        // A management-only push without a cfgversion, after another restart: the
        // stored version; the system_cfg is the stored one, not known in full.
        let mut h = h.restarted();
        push(&mut h, 30, json!({ "_type": "setparam", "mgmt_cfg": "a=2" }));
        let last = h.live.read().unwrap().last_config[&mac].clone();
        assert_eq!((last.mgmt_cfg.as_str(), last.system_cfg.as_str(), last.cfgversion.as_deref()), ("a=2", "", Some("v2")));
        flushed(&h.writer);
        let row: (String, String) = h.store.read(Db::Config, |c| Ok(c.query_row("SELECT cfgversion, system_cfg FROM device_config", [], |r| Ok((r.get(0)?, r.get(1)?)))?)).unwrap();
        assert_eq!(row, ("v2".into(), "aaa.1.hide_ssid=true\naaa.1.wpa.psk=<redacted>".into()));
        // The stored system_cfg stays what the next pushes are compared with: a
        // second management-only push (which names no sections) leaves it, and
        // the next full push gets a diff, not a baseline.
        push(&mut h, 35, json!({ "_type": "setparam", "mgmt_cfg": "a=3" }));
        assert_eq!(stored(&h, EventKind::ConfigPushed).pop().unwrap().get("labels"), None);
        push(&mut h, 40, json!({ "_type": "setparam", "mgmt_cfg": "a=4", "system_cfg": "aaa.1.hide_ssid=false\naaa.1.wpa.psk=old" }));
        let pushed = stored(&h, EventKind::ConfigPushed).pop().unwrap();
        assert_eq!(changes(&pushed), (json!([{ "op": "~", "key": "aaa.1.hide_ssid", "old": "true", "new": "false" }]), json!([{ "op": "~", "key": "a", "old": "3", "new": "4" }])));
        // From then on, the push seen in this run.
        push(&mut h, 50, json!({ "_type": "setparam", "system_cfg": "aaa.1.hide_ssid=false\naaa.1.wpa.psk=new" }));
        let pushed = stored(&h, EventKind::ConfigPushed).pop().unwrap();
        assert_eq!(pushed["system_cfg"]["changes"], json!([{ "op": "~", "key": "aaa.1.wpa.psk", "old": "<redacted>", "new": "<redacted>" }]));
    }

    #[test]
    fn a_restart_counts_the_time_since_the_last_uptime() {
        let mut h = harness();
        let at = |h: &mut Harness, ts: Ts, uptime: i64, version: Option<&str>| {
            let mut v = inform(AP1, uptime, &[]);
            if let Some(version) = version {
                v["version"] = json!(version);
            }
            h.engine.handle(Input::Inform { ts, peer: [10, 0, 0, 1].into(), decoded: decoded(v) });
        };
        at(&mut h, 0, 50, None);
        // The first version it reports is no change of firmware.
        at(&mut h, 10, 60, Some("6.7.0.1"));
        h.engine.handle(Input::Tick(200));
        assert_eq!(events(&mut h), vec![("ap_seen", None), ("ap_offline", None)]);
        // Away for an hour and back with more uptime than it had, though less
        // than it would have had: it restarted meanwhile.
        at(&mut h, 3800, 1000, Some("6.7.0.1"));
        assert_eq!(events(&mut h), vec![("ap_online", None), ("ap_restarted", None)]);
        // Informs a little early or late are no restart.
        at(&mut h, 3815, 1000, Some("6.7.0.1"));
        at(&mut h, 3820, 1060, Some("6.7.0.1"));
        assert_eq!(events(&mut h), vec![]);
    }
}
