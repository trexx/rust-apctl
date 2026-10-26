//! Renders the configuration a UniFi access point expects in a `setparam` reply:
//! `mgmt_cfg` (how to reach the controller) and `system_cfg` (everything else).
//!
//! The output follows the official UniFi Network Application (10.6.x) line for line,
//! including key order, section comments and duplicate keys, so a rendered config can be
//! compared byte for byte with a captured one. The input is a snapshot of the official
//! controller's settings (the shape of `informdump import`, with the collections in
//! [`COLLECTIONS`]) plus the AP's latest inform for its capability bits.
//!
//! No I/O happens here. Anything random (the `cfgversion` token, password hashes) is an
//! input.
//!
//! Not implemented, because nothing in our data exercises it yet: wireless meshing
//! (vport uplinks and mesh downlink VAPs when `connectivity` is enabled), a tagged
//! management VLAN (rejected with an error), guest portal / guest ebtables chains,
//! QoS mark rules for APs without mark bits, OWE transition companions, RadSec,
//! Hotspot 2.0, 6 GHz `freq`, site `config.properties` overrides, and extra VLAN
//! bridges for mDNS custom rules that bridge networks no SSID on the AP uses.
//!
//! Written from the official logic but not yet checked against a capture (none of
//! our data uses them): WLAN schedules (`schedule_*` lines), speed limits (`qos`),
//! SNMP (`snmp.*`) and the mDNS service codes other than Chromecast and Spotify.

mod cfg;
mod javahash;
mod json;
mod meta;
mod mgmt;
mod net;
mod system;
pub mod tz;

pub use json::{as_int, bool_of, flag, int_of, oid, override_of};
pub use net::ssid_vlan;
pub use system::{MDNS_SERVICES, is_dfs_channel, ssid_usergroup, usergroup_limits};
pub use wlan::{capable_width, configured_width, has_hard_noise_floor, radio_ai_na_dfs, radio_off, radio_width, wlan_bands, wpa_mode};
mod wlan;

use std::borrow::Cow;
use std::cell::OnceCell;

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// The country (ISO 3166 numeric code) an AP is given when the site's `country`
/// setting has no code it can read: the United States, as the official controller
/// does for a missing one.
pub const DEFAULT_COUNTRY: i64 = 840;

/// The country (ISO 3166 numeric code) the APs are given for the `code` of the site's
/// `country` setting: the code read as [`as_int`] reads a number, else
/// [`DEFAULT_COUNTRY`], for a missing code as for one that is no number.
pub fn country_code(code: &Value) -> i64 {
    json::as_int(code).unwrap_or(DEFAULT_COUNTRY)
}

/// The SSH account the site's APs get (`users.1.name`, also the user cron jobs run as):
/// the `mgmt` setting's `x_ssh_username`, else `ubnt`. A stored empty name is sent as
/// it is, as the official controller does.
pub fn ssh_username(mgmt: &Value) -> &str {
    json::str_of(mgmt, "x_ssh_username").unwrap_or("ubnt")
}

/// Facts about the controller itself that the settings snapshot does not hold.
#[derive(Clone)]
pub struct Controller {
    /// The controller's host, e.g. `unifi.example.net`: what the AP is given when neither
    /// a pending migration, the settings nor its stored inform URL names one.
    pub host: String,
    /// The port the controller takes informs on: the inform URL's when the device has no
    /// stored `inform_url` (official default 8080).
    pub inform_port: u16,
    /// The management UI's HTTPS port, in `mgmt_url` (official default 8443).
    pub https_port: u16,
    /// The port the controller answers STUN on, in `stun_url` (official default 3478).
    pub stun_port: u16,
    /// The port the controller takes the APs' syslog and netconsole on, when the site
    /// sends them "to this controller" (official default 5514).
    pub syslog_port: u16,
    /// Controller version written as `unifi.version` (the official one sends `10.6.106`).
    pub version: String,
    /// Anonymous controller id (`unifi.anonymous_controller_id` and `unifi.reporterid`).
    pub reporter_uuid: String,
}

impl Default for Controller {
    /// The official controller's default ports, on the host name `unifi` (the one APs
    /// look for on a fresh network), with no version or id.
    fn default() -> Controller {
        Controller { host: "unifi".into(), inform_port: 8080, https_port: 8443, stun_port: 3478, syslog_port: 5514, version: String::new(), reporter_uuid: String::new() }
    }
}

pub struct Input<'a> {
    /// The settings snapshot (shape of `controller-state.json`).
    pub state: &'a Value,
    /// The AP's MAC, `aa:bb:cc:dd:ee:ff` (case-insensitive).
    pub device_mac: &'a str,
    /// The AP's latest inform payload: capability bits, `vap_table`, `inform_ip`.
    pub inform: Option<&'a Value>,
    pub cfgversion: &'a str,
    pub controller: &'a Controller,
}

/// The fields of a `devices` document a render reads (the radios' settings are inside
/// `radio_table`; `table.field` is that field of each of a table's rows). Whatever
/// imports device documents must keep at least these.
pub const DEVICE_KEYS: &[&str] = &[
    "mac", "site_id", "type", "name", "disabled", "radio_table", "inform_url", "migrate_inform_url", "x_authkey",
    "syslog_key", "config_network", "mgmt_network_id", "led_override", "led_override_color", "led_override_color_brightness",
    "outdoor_mode_override", "bandsteering_mode", "atf_enabled", "green_ap_enabled", "resetbtn_enabled", "jumboframe_enabled",
    "switch_vlan_enabled", "ethernet_table", "port_overrides", "snmp_location", "snmp_contact", "mesh_uplink_1", "mesh_uplink_2",
    // Whether clients locked to this AP are kept off the others (false while it is offline).
    "fixed_ap_available",
    // Capability bits, used until the AP's first inform.
    "fw_caps", "fw2_caps", "fw3_caps", "wifi_caps", "wifi_caps2", "hw_caps",
    // A gateway's MACs (`Ctx::gateway_macs`): only these fields of each row.
    "network_table.mac", "network_table.networkgroup", "vap_table.bssid", "vwire_vap_table.bssid",
];

/// The top-level inform fields a render reads: the capability bits ([`Caps`]; until the
/// first inform they come from the device document), `has_eth1` (net.rs), `inform_ip`
/// and `uplink` (system.rs). [`INFORM_TABLE_KEYS`] lists what it reads from the tables.
pub const INFORM_KEYS: &[&str] = &["fw_caps", "fw2_caps", "fw3_caps", "wifi_caps", "wifi_caps2", "hw_caps", "has_eth1", "inform_ip", "uplink"];

/// The inform tables a render reads, each with the one field it reads from their rows:
/// the VAP names (net.rs) and the port interface names (system.rs).
pub const INFORM_TABLE_KEYS: &[(&str, &str)] = &[("vap_table", "name"), ("port_table", "ifname")];

/// The parts of an inform a render reads ([`INFORM_KEYS`], [`INFORM_TABLE_KEYS`]).
/// Informs that agree on these render the same config from the same settings, so the
/// rest (counters, uptime, clients) need not cause a new render. Raw values are
/// compared, which is stricter than what a render makes of them.
pub fn inform_inputs(inform: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for &k in INFORM_KEYS {
        out.insert(k.to_string(), inform[k].clone());
    }
    for &(table, key) in INFORM_TABLE_KEYS {
        let rows = inform[table].as_array().map(|t| t.iter().map(|row| row[key].clone()).collect());
        out.insert(table.to_string(), rows.map_or(Value::Null, Value::Array));
    }
    Value::Object(out)
}

/// Whether `inform` agrees on what a render reads with the inform `inputs` were
/// made from: `inform_inputs(inform) == *inputs`, without building it (the
/// controller asks this for every inform).
pub fn inform_inputs_match(inputs: &Value, inform: &Value) -> bool {
    INFORM_KEYS.iter().all(|&k| inputs[k] == inform[k])
        && INFORM_TABLE_KEYS.iter().all(|&(table, key)| match (&inputs[table], inform[table].as_array()) {
            (Value::Array(seen), Some(rows)) => seen.len() == rows.len() && seen.iter().zip(rows).all(|(s, row)| *s == row[key]),
            (Value::Null, None) => true,
            _ => false,
        })
}

/// The collections of the settings snapshot a render reads, by their names in the
/// snapshot (`informdump import` reads `sites`, `devices` and `clients` from the
/// official controller's `site`, `device` and `user`). Whatever imports settings must
/// fill at least these.
pub const COLLECTIONS: &[&str] = &["sites", "wlanconf", "networkconf", "setting", "apgroup", "config_meta", "usergroup", "radiusprofile", "devices", "clients"];

/// The `setting` documents (by `key`) a render or the controller reads; the controller
/// reads only `enabled` of `element_adopt` (the SSID limit per radio). Whatever imports
/// settings needs only these: the rest (mail, cloud access and guest portal
/// credentials, RADIUS secrets) would only spread secrets nothing uses.
pub const SETTING_KEYS: &[&str] = &["mgmt", "super_mgmt", "super_identity", "radio_ai", "country", "locale", "connectivity", "rsyslogd", "snmp", "ntp", "element_adopt"];

/// The fields of a `clients` (user) document a render reads: blocked clients and
/// clients locked to an AP.
pub const CLIENT_KEYS: &[&str] = &["mac", "site_id", "blocked", "fixed_ap_enabled", "fixed_ap_mac"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub mgmt_cfg: String,
    pub system_cfg: String,
}

/// A render plus the AP's updated `config_meta` document.
pub struct Output {
    pub rendered: Rendered,
    /// The persistent index allocation (section numbers, VAP names, netconf and bridge
    /// port indices) after this render, in the shape of a `config_meta` document. Store
    /// it in the state's `config_meta` so the next render keeps the same numbering.
    pub config_meta: Value,
}

pub fn render(input: &Input) -> Result<Rendered> {
    Ok(render_with_meta(input)?.rendered)
}

pub fn render_with_meta(input: &Input) -> Result<Output> {
    let ctx = Ctx::new(input)?;
    let mgmt_cfg = mgmt::render(&ctx, None);
    let (system_cfg, config_meta) = system::render(&ctx)?;
    Ok(Output { rendered: Rendered { mgmt_cfg, system_cfg }, config_meta })
}

/// Only the `mgmt_cfg` of [`render`]: what adopts an AP. `inform_authkey` is the key
/// (hex) the AP informs with when that is not its own: an AP being adopted uses the
/// factory key, so it is sent its own (an `authkey` line). What only `system_cfg` reads
/// cannot make this fail.
pub fn render_mgmt(input: &Input, inform_authkey: Option<&str>) -> Result<String> {
    let ctx = Ctx::new(input)?;
    Ok(mgmt::render(&ctx, inform_authkey))
}

/// The `blocked_sta` value of a provisioning reply: MACs of the site's blocked clients,
/// one per line, no trailing newline.
pub fn blocked_sta(state: &Value, site_id: &str) -> String {
    site_docs(state, site_id, "clients")
        .filter(|c| json::flag(c, "blocked", false))
        .filter_map(|c| json::str_of(c, "mac"))
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The AP's capability bit fields, in [`CAP_KEYS`] order.
#[derive(Default, Clone, Copy)]
pub(crate) struct Caps([u64; 6]);

impl Caps {
    fn read(inform: Option<&Value>, device: &Value) -> Caps {
        Caps(CAP_KEYS.map(|k| inform.and_then(|i| json::int_of(i, k)).or_else(|| json::int_of(device, k)).unwrap_or(0) as u64))
    }

    /// Whether any capability bits are known: from an inform, or stored with the device.
    fn is_known(&self) -> bool {
        self.0 != [0; 6]
    }

    pub fn has(&self, cap: Cap) -> bool {
        let (field, n) = cap.at();
        bit(self.0[field as usize], n)
    }

    /// Whether the AP has any one of these capabilities.
    pub fn any(&self, caps: &[Cap]) -> bool {
        caps.iter().any(|&c| self.has(c))
    }
}

/// The capability fields behind [`Caps`], in [`Field`] order: from the AP's inform,
/// else from its device document.
const CAP_KEYS: [&str; 6] = ["fw_caps", "fw2_caps", "fw3_caps", "wifi_caps", "wifi_caps2", "hw_caps"];

/// A capability field, by its index in [`CAP_KEYS`].
#[derive(Clone, Copy)]
enum Field {
    Fw,
    Fw2,
    Fw3,
    Wifi,
    Wifi2,
    Hw,
}

/// A capability bit the render tests. Each bit number is written down once, in
/// [`Cap::at`]: the render and the feature tables below both test it through
/// [`Caps::has`], so they cannot disagree on what an AP supports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Cap {
    /// The `switch.*` section, with jumbo frames.
    Switch,
    /// SSH passwords as SHA-512 crypt hashes rather than MD5 ones.
    Sha512Passwd,
    /// Several schedule blocks a day (`schedule_<day>.<i>`).
    ScheduleBlocks,
    /// SNMP v3 (v1/v2c needs no capability).
    SnmpV3,
    /// Schedules given as the blackout blocks (`schedule_invert`).
    ScheduleInvert,
    /// Hotspot 2.0 and OSEN SSIDs.
    Hotspot2,
    /// Encrypted syslog to the controller.
    EncryptedSyslog,
    /// The mDNS proxy (`mdns_sd.*`).
    MdnsProxy,
    /// DNS assistance (`dns_cache`, `dns_bypass`).
    DnsAssistance,
    /// The `pathmon` section.
    PathMonitor,
    /// `multicast.inspect` on each VAP.
    MulticastInspect,
    /// Band steering.
    BandSteering,
    /// Band steering between named 2.4 and 5 GHz VAP pairs.
    BandSteeringPairs,
    /// Airtime fairness.
    AirtimeFairness,
    /// `bga_filter` on each VAP.
    BgaFilter,
    /// Wireless meshing (`mesh.*`).
    Mesh,
    /// hostapd brings up every VAP, so netconf leaves them down.
    HostapdVaps,
    /// The packet `mark` section.
    Marks,
    /// Private pre-shared keys.
    Ppsk,
    /// VAP names after their radio (`wifi0ap1`) instead of `athN`.
    QcaV2,
    /// Green AP (radio power saving).
    GreenAp,
    /// DFS channels for automatic channel selection (`acsdfs`, `blklst`).
    AcsDfs,
    /// Roaming assistant (`btm_disassoc`).
    RoamingAssistant,
    /// The AP's name in its beacons.
    AdvertiseApName,
    /// Multicast suppression.
    MulticastSuppression,
    /// An LED whose colour can be set.
    LedColor,
    /// An LED whose brightness can be set.
    Led,
}

impl Cap {
    /// The field and bit number of this capability.
    const fn at(self) -> (Field, u32) {
        use Field::*;
        match self {
            Cap::Switch => (Fw, 4),
            Cap::Sha512Passwd => (Fw, 10),
            Cap::ScheduleBlocks => (Fw, 12),
            Cap::SnmpV3 => (Fw, 14),
            Cap::ScheduleInvert => (Fw, 22),
            Cap::Hotspot2 => (Fw, 23),
            Cap::EncryptedSyslog => (Fw, 24),
            Cap::MdnsProxy => (Fw2, 28),
            Cap::DnsAssistance => (Fw3, 3),
            Cap::PathMonitor => (Fw3, 6),
            Cap::MulticastInspect => (Fw3, 7),
            Cap::BandSteering => (Wifi, 2),
            Cap::BandSteeringPairs => (Wifi, 3),
            Cap::AirtimeFairness => (Wifi, 5),
            Cap::BgaFilter => (Wifi, 6),
            Cap::Mesh => (Wifi, 11),
            Cap::HostapdVaps => (Wifi, 13),
            Cap::Marks => (Wifi, 19),
            Cap::Ppsk => (Wifi, 20),
            Cap::QcaV2 => (Wifi, 29),
            Cap::GreenAp => (Wifi2, 2),
            Cap::AcsDfs => (Wifi2, 4),
            Cap::RoamingAssistant => (Wifi2, 5),
            Cap::AdvertiseApName => (Wifi2, 6),
            Cap::MulticastSuppression => (Wifi2, 22),
            Cap::LedColor => (Hw, 1),
            Cap::Led => (Hw, 14),
        }
    }
}

/// Either kind of LED: the `ledbar` section is sent for any.
pub(crate) const LED: &[Cap] = &[Cap::LedColor, Cap::Led];

pub(crate) fn bit(v: u64, n: u32) -> bool {
    v >> n & 1 == 1
}

/// What an optional feature needs from the AP.
#[derive(Clone, Copy)]
enum Need {
    /// Any one of these capabilities.
    Any(&'static [Cap]),
    /// Every radio supports WPA3 fast roaming (`radio_caps2`).
    RadiosFt,
    /// Nothing: the render sends it to every AP.
    Nothing,
}

type FeatureTable<const N: usize> = [(&'static str, Need); N];

const fn feature_names<const N: usize>(table: FeatureTable<N>) -> [&'static str; N] {
    let mut out = [""; N];
    let mut i = 0;
    while i < N {
        out[i] = table[i].0;
        i += 1;
    }
    out
}

/// Which features of a table the AP supports, or `None` while that is unknown: the AP
/// has not sent an inform and the settings hold no capability bits for it.
fn feature_support<const N: usize>(table: &FeatureTable<N>, device: &Value, inform: Option<&Value>) -> Option<Vec<(&'static str, bool)>> {
    let caps = Caps::read(inform, device);
    if !caps.is_known() {
        return None;
    }
    let radios = json::arr(device, "radio_table");
    let ft = !radios.is_empty() && radios.iter().all(|r| bit(json::int_of(r, "radio_caps2").unwrap_or(0) as u64, wlan::RCAP2_SAE_FT));
    let met = |need| match need {
        Need::Any(caps_needed) => caps.any(caps_needed),
        Need::RadiosFt => ft,
        Need::Nothing => true,
    };
    Some(table.iter().map(|&(f, need)| (f, met(need))).collect())
}

/// Optional SSID features with what `render` checks for each.
const SSID_FEATURE_CAPS: FeatureTable<6> = [
    ("dns_assistance", Need::Any(&[Cap::DnsAssistance])),
    ("advertise_ap_name", Need::Any(&[Cap::AdvertiseApName])),
    ("roaming_assistant", Need::Any(&[Cap::RoamingAssistant])),
    ("multicast_suppression", Need::Any(&[Cap::MulticastSuppression])),
    ("wpa3_fast_roaming", Need::RadiosFt),
    ("mdns_proxy", Need::Any(&[Cap::MdnsProxy])),
];

/// The optional SSID features [`ssid_feature_support`] reports on, by name. `render`
/// sends each only to an AP with its capability bit; an AP without it gets the SSID
/// without the feature (no config lines), as the official controller does. The
/// exception is `wpa3_fast_roaming`: the list counts an AP as supporting it only when
/// every radio has `radio_caps2`'s FT bit, while the render decides per radio and turns
/// FT off on each radio without the bit (its `wpa3.ft.status` line is still sent, set
/// to disabled).
pub const SSID_FEATURES: &[&str] = &feature_names(SSID_FEATURE_CAPS);

/// Which of [`SSID_FEATURES`] the AP supports, as `(feature, supported)`, or
/// `None` while that is unknown: the AP has not sent an inform and the
/// settings hold no capability bits for it.
pub fn ssid_feature_support(device: &Value, inform: Option<&Value>) -> Option<Vec<(&'static str, bool)>> {
    feature_support(&SSID_FEATURE_CAPS, device, inform)
}

const DEVICE_FEATURE_CAPS: FeatureTable<7> = [
    ("band_steering", Need::Any(&[Cap::BandSteering])),
    ("airtime_fairness", Need::Any(&[Cap::AirtimeFairness])),
    ("green_ap", Need::Any(&[Cap::GreenAp])),
    ("led", Need::Any(LED)),
    ("led_color", Need::Any(&[Cap::LedColor])),
    ("jumbo_frames", Need::Any(&[Cap::Switch])),
    // SNMP v1/v2c, and with it the AP's location and contact, is sent to every AP,
    // as the official controller does; only v3 needs a capability.
    ("snmp", Need::Nothing),
];

/// The AP-wide features [`device_feature_support`] reports on, by name. `render` sends
/// each only to an AP with its capability bit (without it the setting is not sent at
/// all), except `snmp`, which every AP gets.
pub const DEVICE_FEATURES: &[&str] = &feature_names(DEVICE_FEATURE_CAPS);

/// Which of [`DEVICE_FEATURES`] the AP supports, or `None` while unknown (see
/// [`ssid_feature_support`]).
pub fn device_feature_support(device: &Value, inform: Option<&Value>) -> Option<Vec<(&'static str, bool)>> {
    feature_support(&DEVICE_FEATURE_CAPS, device, inform)
}

/// Everything one render needs, resolved once.
pub(crate) struct Ctx<'a> {
    pub state: &'a Value,
    pub site: &'a Value,
    pub site_id: &'a str,
    pub device: &'a Value,
    pub mac: String,
    pub inform: Option<&'a Value>,
    pub caps: Caps,
    pub controller: &'a Controller,
    pub cfgversion: &'a str,
    /// The settings read most often (see [`Ctx::setting`]).
    pub mgmt: &'a Value,
    pub super_mgmt: &'a Value,
    pub radio_ai: &'a Value,
    /// The radios' country code: [`country_code`] of `setting[country].code`.
    pub country: i64,
    /// See [`Ctx::gateway_macs`].
    gateway_macs: OnceCell<Vec<Cow<'a, str>>>,
}

static NULL: Value = Value::Null;

/// Documents of a collection that belong to a site (or carry no site at all).
fn site_docs<'a, 's>(state: &'a Value, site_id: &'s str, collection: &str) -> impl Iterator<Item = &'a Value> + use<'a, 's> {
    json::arr(state, collection).iter().filter(move |d| json::str_of(d, "site_id").is_none_or(|id| id == site_id))
}

/// The `setting` document with this key: site-scoped, or global for `super_*` keys.
fn setting<'a>(state: &'a Value, site_id: &str, key: &str) -> &'a Value {
    site_docs(state, site_id, "setting").find(|s| json::str_of(s, "key") == Some(key)).unwrap_or(&NULL)
}

/// The site's network (`networkconf`) with this id.
fn network<'a>(state: &'a Value, site_id: &str, id: &str) -> Option<&'a Value> {
    site_docs(state, site_id, "networkconf").find(|n| json::oid(n) == Some(id))
}

impl<'a> Ctx<'a> {
    fn new(input: &Input<'a>) -> Result<Ctx<'a>> {
        let state = input.state;
        let mac = input.device_mac.to_ascii_lowercase();
        let device = json::arr(state, "devices")
            .iter()
            .find(|d| json::str_of(d, "mac").is_some_and(|m| json::mac_eq(m, &mac)))
            .with_context(|| format!("device {mac} is not in the state"))?;
        let site_id = json::str_of(device, "site_id").context("device has no site_id")?;
        let site = json::arr(state, "sites")
            .iter()
            .find(|s| json::oid(s) == Some(site_id))
            .with_context(|| format!("site {site_id} is not in the state"))?;
        if json::str_of(device, "type").is_some_and(|t| t != "uap") {
            bail!("device {mac} is not an access point");
        }
        Ok(Ctx {
            state,
            site,
            site_id,
            device,
            mac,
            inform: input.inform,
            caps: Caps::read(input.inform, device),
            controller: input.controller,
            cfgversion: input.cfgversion,
            mgmt: setting(state, site_id, "mgmt"),
            super_mgmt: setting(state, site_id, "super_mgmt"),
            radio_ai: setting(state, site_id, "radio_ai"),
            country: country_code(&setting(state, site_id, "country")["code"]),
            gateway_macs: OnceCell::new(),
        })
    }

    /// The `setting` document with this key: site-scoped, or global for `super_*` keys.
    /// `mgmt`, `super_mgmt` and `radio_ai` are at hand as fields.
    pub fn setting(&self, key: &str) -> &'a Value {
        setting(self.state, self.site_id, key)
    }

    /// Documents of a collection that belong to this site (or carry no site at all).
    pub fn site_docs(&self, collection: &str) -> impl Iterator<Item = &'a Value> + '_ {
        site_docs(self.state, self.site_id, collection)
    }

    /// The MACs the site's gateways send from, which every broadcast filter lets
    /// through, as the official controller collects them for a gateway: its own, its LAN
    /// networks' (`network_table`), its Ethernet interfaces' with their other MACs, and
    /// the BSSIDs of its own SSIDs (`vap_table`'s lower case). Blank ones are left out,
    /// duplicates are not. Looked up the first time a VAP's broadcast filter asks.
    pub fn gateway_macs(&self) -> &[Cow<'a, str>] {
        self.gateway_macs.get_or_init(|| {
            let mut macs = Vec::new();
            for gw in self.site_docs("devices").filter(|d| matches!(json::str_of(d, "type"), Some("ugw" | "udm" | "uxg"))) {
                let lan = json::arr(gw, "network_table").iter().filter(|n| json::str_of(n, "networkgroup") == Some("LAN")).filter_map(|n| json::str_of(n, "mac"));
                let eth = json::arr(gw, "ethernet_table").iter().flat_map(|e| json::str_of(e, "mac").into_iter().chain(json::str_list(e, "other_macs")));
                let bssids = |table| json::arr(gw, table).iter().filter_map(|v| json::str_of(v, "bssid")).filter(|b| !b.trim().is_empty());
                macs.extend(json::str_of(gw, "mac").into_iter().chain(lan).chain(eth).filter(|m| !m.trim().is_empty()).map(Cow::Borrowed));
                macs.extend(bssids("vap_table").map(|b| Cow::Owned(b.to_lowercase())));
                macs.extend(bssids("vwire_vap_table").map(Cow::Borrowed));
            }
            macs
        })
    }

    pub fn network(&self, id: &str) -> Option<&'a Value> {
        network(self.state, self.site_id, id)
    }

    /// The site's [`ssh_username`].
    pub fn ssh_username(&self) -> &'a str {
        ssh_username(self.mgmt)
    }

    pub fn inform_str(&self, key: &str) -> Option<&'a str> {
        self.inform.and_then(|i| json::str_of(i, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The render's sources, for the tests that check which fields they read.
    const SOURCES: [&str; 6] = [include_str!("lib.rs"), include_str!("mgmt.rs"), include_str!("net.rs"), include_str!("system.rs"), include_str!("wlan.rs"), include_str!("meta.rs")];

    #[test]
    fn ssid_features_follow_the_capability_bits() {
        let device = json!({ "radio_table": [{ "radio": "ng", "radio_caps2": 31 }, { "radio": "na", "radio_caps2": 1 }] });
        assert_eq!(ssid_feature_support(&device, None), None);
        // The bits a U6-Mesh on 8.8.11 reports.
        let inform = json!({ "fw_caps": 3892117055u64, "fw2_caps": 1481179136u64, "fw3_caps": 206, "wifi_caps": 2709438173u64, "wifi_caps2": 4206576, "hw_caps": 2050 });
        let got = ssid_feature_support(&device, Some(&inform)).unwrap();
        let missing: Vec<&str> = got.iter().filter(|(_, ok)| !ok).map(|(f, _)| *f).collect();
        assert_eq!(missing, ["wpa3_fast_roaming"]);
        let dev: Vec<&str> = device_feature_support(&device, Some(&inform)).unwrap().iter().filter(|(_, ok)| !ok).map(|(f, _)| *f).collect();
        assert_eq!(dev, ["airtime_fairness", "green_ap"]);
        let old = json!({ "fw_caps": 1, "fw3_caps": 0, "wifi_caps2": 0 });
        assert!(ssid_feature_support(&device, Some(&old)).unwrap().iter().all(|(f, ok)| !ok || *f == "wpa3_fast_roaming"));
        // Any capability field at all makes the support known, for both lists.
        for partial in [json!({ "hw_caps": 2 }), json!({ "fw3_caps": 8 })] {
            assert!(ssid_feature_support(&device, Some(&partial)).is_some() && device_feature_support(&device, Some(&partial)).is_some(), "{partial}");
        }
        // SNMP needs no capability bit: every AP whose bits are known supports it.
        assert_eq!(device_feature_support(&json!({ "wifi_caps2": 4 }), None).unwrap().iter().filter(|(_, ok)| *ok).map(|(f, _)| *f).collect::<Vec<_>>(), ["green_ap", "snmp"]);
    }

    /// Every device field the sources read (an accessor on `ctx.device` or `device`
    /// with a literal key, and the capability fields) is in `DEVICE_KEYS`, so an
    /// import that keeps those loses nothing a render needs.
    #[test]
    fn device_keys_cover_every_field_read() {
        let mut read: Vec<&str> = CAP_KEYS.to_vec();
        for src in SOURCES {
            for pattern in ["ctx.device, \"", "ctx.device.get(\"", "(device, \"", "(gw, \""] {
                for (at, _) in src.match_indices(pattern) {
                    let rest = &src[at + pattern.len()..];
                    read.push(&rest[..rest.find('"').unwrap()]);
                }
            }
        }
        assert!(read.len() > 30, "the patterns still find the reads: {read:?}");
        for key in read {
            let kept = DEVICE_KEYS.iter().any(|k| *k == key || k.strip_prefix(key).is_some_and(|row| row.starts_with('.')));
            assert!(kept, "`{key}` is read from the device document but missing from DEVICE_KEYS");
        }
    }

    /// Every setting the sources read (`setting("…")` on the context, or with the state
    /// and site) is in `SETTING_KEYS`.
    #[test]
    fn setting_keys_cover_every_setting_read() {
        let mut read: Vec<&str> = Vec::new();
        for src in SOURCES {
            let src = src.split("#[cfg(test)]").next().unwrap();
            for pattern in [".setting(\"", "setting(state, site_id, \""] {
                for (at, _) in src.match_indices(pattern) {
                    let rest = &src[at + pattern.len()..];
                    read.push(&rest[..rest.find('"').unwrap()]);
                }
            }
        }
        assert!(read.len() >= 8, "the patterns still find the reads: {read:?}");
        for key in read {
            assert!(SETTING_KEYS.contains(&key), "setting `{key}` is read but missing from SETTING_KEYS");
        }
    }

    /// Every collection the sources read (`site_docs` on the context, or with the state
    /// and site, and `arr` on the state) is in `COLLECTIONS`, so an import that fills
    /// those loses nothing a render needs.
    #[test]
    fn collections_cover_every_collection_read() {
        let mut read: Vec<&str> = Vec::new();
        for src in SOURCES {
            let src = src.split("#[cfg(test)]").next().unwrap();
            for pattern in ["site_docs(\"", "site_docs(state, site_id, \"", "arr(state, \"", "arr(ctx.state, \""] {
                for (at, _) in src.match_indices(pattern) {
                    let rest = &src[at + pattern.len()..];
                    read.push(&rest[..rest.find('"').unwrap()]);
                }
            }
        }
        for c in ["sites", "radiusprofile", "usergroup", "config_meta", "clients"] {
            assert!(read.contains(&c), "the patterns still find the reads of {c}: {read:?}");
        }
        for c in read {
            assert!(COLLECTIONS.contains(&c), "collection `{c}` is read but missing from COLLECTIONS");
        }
    }

    /// Every inform field the sources read (`inform_str`, and every quoted name in an
    /// expression on `ctx.inform`) is in `inform_inputs`, so the controller's render
    /// cache, keyed on it, never reuses a config made from an inform that differed.
    #[test]
    fn inform_inputs_cover_every_field_read() {
        let known = |k: &str| INFORM_KEYS.contains(&k) || INFORM_TABLE_KEYS.iter().any(|(t, f)| *t == k || *f == k);
        let mut read: Vec<&str> = CAP_KEYS.to_vec();
        for src in SOURCES {
            // Not the tests: their own patterns would match.
            let src = src.split("#[cfg(test)]").next().unwrap();
            for (at, _) in src.match_indices("inform_str(\"") {
                let rest = &src[at + "inform_str(\"".len()..];
                read.push(&rest[..rest.find('"').unwrap()]);
            }
            // `ctx.inform`, also split over lines (`ctx\n    .inform`).
            for (at, _) in src.match_indices(".inform") {
                let rest = &src[at + ".inform".len()..];
                if !src[..at].trim_end().ends_with("ctx") || rest.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                // Up to the end of the statement, or of an `if` condition.
                let statement = &rest[..rest.find([';', '{']).unwrap_or(rest.len())];
                read.extend(statement.split('"').skip(1).step_by(2));
            }
        }
        assert!(read.len() > 10, "the patterns still find the reads: {read:?}");
        for key in read {
            assert!(known(key), "`{key}` is read from the inform but missing from INFORM_KEYS / INFORM_TABLE_KEYS");
        }
        let inputs = inform_inputs(&json!({ "fw_caps": 1, "uptime": 5, "vap_table": [{ "name": "ath0", "tx_bytes": 9 }] }));
        assert_eq!((inputs["fw_caps"].as_i64(), inputs.get("uptime"), &inputs["vap_table"]), (Some(1), None, &json!(["ath0"])));
    }
}
