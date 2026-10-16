//! Renders the configuration a UniFi access point expects in a `setparam` reply:
//! `mgmt_cfg` (how to reach the controller) and `system_cfg` (everything else).
//!
//! The output follows the official UniFi Network Application (10.6.x) line for line,
//! including key order, section comments and duplicate keys, so a rendered config can be
//! compared byte for byte with a captured one. The input is a snapshot of the official
//! controller's settings (the shape of `informdump import`: `sites`, `wlanconf`,
//! `networkconf`, `setting`, `apgroup`, `config_meta`, `devices`, `clients`) plus the AP's
//! latest inform for its capability bits.
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
pub mod json;
mod meta;
mod mgmt;
mod net;
mod system;
pub mod tz;

pub use system::MDNS_SERVICES;
mod wlan;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::wlan::Band;

/// Facts about the controller itself that the settings snapshot does not hold.
pub struct Controller {
    /// The controller's inform URL, e.g. `http://unifi.example.net:8080/inform`. Its host
    /// is used when neither the settings nor the device name one; its port when the device
    /// has no stored `inform_url`.
    pub inform_url: String,
    /// Base URL of the management UI, e.g. `https://unifi.example.net:8443`. Only the
    /// port is used unless no other host is known; `/manage/site/<site>` is appended.
    pub mgmt_url: String,
    /// STUN URL, e.g. `stun://unifi.example.net:3478/`; supplies the STUN port.
    pub stun_url: String,
    /// Where APs send syslog when the site logs to "this controller". When `None`, the
    /// address the AP itself reports as its controller (`inform_ip` in its inform) is used.
    pub syslog_ip: Option<String>,
    /// Controller version written as `unifi.version` (the official one sends `10.6.106`).
    pub version: String,
    /// Anonymous controller id (`unifi.anonymous_controller_id` and `unifi.reporterid`).
    pub reporter_uuid: String,
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
/// `radio_table`). Whatever imports device documents must keep at least these.
pub const DEVICE_KEYS: &[&str] = &[
    "mac", "site_id", "type", "name", "disabled", "radio_table", "inform_url", "migrate_inform_url", "x_authkey", "x_inform_authkey",
    "syslog_key", "config_network", "mgmt_network_id", "led_override", "led_override_color", "led_override_color_brightness",
    "outdoor_mode_override", "bandsteering_mode", "atf_enabled", "green_ap_enabled", "resetbtn_enabled", "jumboframe_enabled",
    "switch_vlan_enabled", "ethernet_table", "port_overrides", "snmp_location", "snmp_contact", "mesh_uplink_1", "mesh_uplink_2",
    // Capability bits, used until the AP's first inform.
    "fw_caps", "fw2_caps", "fw3_caps", "wifi_caps", "wifi_caps2", "hw_caps",
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
    let mgmt_cfg = mgmt::render(&ctx);
    let (system_cfg, config_meta) = system::render(&ctx)?;
    Ok(Output { rendered: Rendered { mgmt_cfg, system_cfg }, config_meta })
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

/// Capability bit fields of the AP.
#[derive(Default, Clone, Copy)]
pub(crate) struct Caps {
    pub fw: u64,
    pub fw2: u64,
    pub fw3: u64,
    pub wifi: u64,
    pub wifi2: u64,
    pub hw: u64,
}

impl Caps {
    fn read(inform: Option<&Value>, device: &Value) -> Caps {
        let [fw, fw2, fw3, wifi, wifi2, hw] =
            CAP_KEYS.map(|k| inform.and_then(|i| json::int_of(i, k)).or_else(|| json::int_of(device, k)).unwrap_or(0) as u64);
        Caps { fw, fw2, fw3, wifi, wifi2, hw }
    }

    /// Whether any capability bits are known: from an inform, or stored with the device.
    fn is_known(&self) -> bool {
        [self.fw, self.fw2, self.fw3, self.wifi, self.wifi2, self.hw] != [0; 6]
    }
}

/// The capability fields behind [`Caps`], in its field order: from the AP's inform,
/// else from its device document.
const CAP_KEYS: [&str; 6] = ["fw_caps", "fw2_caps", "fw3_caps", "wifi_caps", "wifi_caps2", "hw_caps"];

pub(crate) fn bit(v: u64, n: u32) -> bool {
    v >> n & 1 == 1
}

/// A capability bit a feature needs (any one of a list will do).
#[derive(Clone, Copy)]
enum Need {
    Fw(u32),
    Fw2(u32),
    Fw3(u32),
    Wifi(u32),
    Wifi2(u32),
    Hw(u32),
    /// Every radio supports WPA3 fast roaming (`radio_caps2`).
    RadiosFt,
}

impl Need {
    fn met(self, caps: &Caps, radios_ft: bool) -> bool {
        match self {
            Need::Fw(b) => bit(caps.fw, b),
            Need::Fw2(b) => bit(caps.fw2, b),
            Need::Fw3(b) => bit(caps.fw3, b),
            Need::Wifi(b) => bit(caps.wifi, b),
            Need::Wifi2(b) => bit(caps.wifi2, b),
            Need::Hw(b) => bit(caps.hw, b),
            Need::RadiosFt => radios_ft,
        }
    }
}

type FeatureTable<const N: usize> = [(&'static str, &'static [Need]); N];

const fn feature_names<const N: usize>(table: FeatureTable<N>) -> [&'static str; N] {
    let mut out = [""; N];
    let mut i = 0;
    while i < N {
        out[i] = table[i].0;
        i += 1;
    }
    out
}

/// Optional SSID features with the capability bits `render` checks for each.
const SSID_FEATURE_CAPS: FeatureTable<6> = [
    ("dns_assistance", &[Need::Fw3(3)]),
    ("advertise_ap_name", &[Need::Wifi2(6)]),
    ("roaming_assistant", &[Need::Wifi2(5)]),
    ("multicast_suppression", &[Need::Wifi2(22)]),
    ("wpa3_fast_roaming", &[Need::RadiosFt]),
    ("mdns_proxy", &[Need::Fw2(28)]),
];

/// Optional SSID features that depend on what the AP supports, with the
/// capability bit `render` checks for each one. An AP without it gets the SSID
/// without the feature (no config lines), as the official controller does.
pub const SSID_FEATURES: &[&str] = &feature_names(SSID_FEATURE_CAPS);

/// Which of [`SSID_FEATURES`] the AP supports, as `(feature, supported)`, or
/// `None` while that is unknown: the AP has not sent an inform and the
/// settings hold no capability bits for it.
pub fn ssid_feature_support(device: &Value, inform: Option<&Value>) -> Option<Vec<(&'static str, bool)>> {
    let caps = Caps::read(inform, device);
    if !caps.is_known() {
        return None;
    }
    let radios = json::arr(device, "radio_table");
    let ft = !radios.is_empty() && radios.iter().all(|r| bit(json::int_of(r, "radio_caps2").unwrap_or(0) as u64, wlan::RCAP2_SAE_FT));
    Some(SSID_FEATURE_CAPS.iter().map(|&(f, needs)| (f, needs.iter().any(|n| n.met(&caps, ft)))).collect())
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
    /// The radios' country code (`setting[country].code`, US when unset).
    pub country: String,
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
            country: json::text_of(setting(state, site_id, "country"), "code").unwrap_or_else(|| "840".to_string()),
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

    pub fn network(&self, id: &str) -> Option<&'a Value> {
        self.site_docs("networkconf").find(|n| json::oid(n) == Some(id))
    }

    /// SSH account name: also the user cron jobs run as.
    pub fn ssh_username(&self) -> &'a str {
        json::str_of(self.mgmt, "x_ssh_username").unwrap_or("ubnt")
    }

    pub fn inform_str(&self, key: &str) -> Option<&'a str> {
        self.inform.and_then(|i| json::str_of(i, key))
    }

    /// The `radio_ai` settings for one band (`radios_configuration`).
    pub fn radio_ai_config(&self, band: Band) -> Option<&'a Value> {
        json::arr(self.radio_ai, "radios_configuration").iter().find(|c| json::str_of(c, "radio") == Some(band.as_str()))
    }
}

const DEVICE_FEATURE_CAPS: FeatureTable<7> = [
    ("band_steering", &[Need::Wifi(2)]),
    ("airtime_fairness", &[Need::Wifi(5)]),
    ("green_ap", &[Need::Wifi2(2)]),
    ("led", &[Need::Hw(1), Need::Hw(14)]),
    ("led_color", &[Need::Hw(1)]),
    ("jumbo_frames", &[Need::Fw(4)]),
    ("snmp", &[Need::Fw(13), Need::Fw(14)]),
];

/// AP-wide features that depend on the AP's capability bits, as `render`
/// checks them: without the bit the setting is not sent at all.
pub const DEVICE_FEATURES: &[&str] = &feature_names(DEVICE_FEATURE_CAPS);

/// Which of [`DEVICE_FEATURES`] the AP supports, or `None` while unknown (see
/// [`ssid_feature_support`]).
pub fn device_feature_support(device: &Value, inform: Option<&Value>) -> Option<Vec<(&'static str, bool)>> {
    let caps = Caps::read(inform, device);
    if !caps.is_known() {
        return None;
    }
    Some(DEVICE_FEATURE_CAPS.iter().map(|&(f, needs)| (f, needs.iter().any(|n| n.met(&caps, false)))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        assert_eq!(device_feature_support(&json!({ "wifi_caps2": 4 }), None).unwrap().iter().filter(|(_, ok)| *ok).map(|(f, _)| *f).collect::<Vec<_>>(), ["green_ap"]);
    }

    /// Every device field the sources read (an accessor on `ctx.device` or `device`
    /// with a literal key, and the capability fields) is in `DEVICE_KEYS`, so an
    /// import that keeps those loses nothing a render needs.
    #[test]
    fn device_keys_cover_every_field_read() {
        let sources = [include_str!("lib.rs"), include_str!("mgmt.rs"), include_str!("net.rs"), include_str!("system.rs"), include_str!("wlan.rs"), include_str!("meta.rs")];
        let mut read: Vec<&str> = CAP_KEYS.to_vec();
        for src in sources {
            for pattern in ["ctx.device, \"", "ctx.device.get(\"", "(device, \""] {
                for (at, _) in src.match_indices(pattern) {
                    let rest = &src[at + pattern.len()..];
                    read.push(&rest[..rest.find('"').unwrap()]);
                }
            }
        }
        assert!(read.len() > 30, "the patterns still find the reads: {read:?}");
        for key in read {
            assert!(DEVICE_KEYS.contains(&key), "`{key}` is read from the device document but missing from DEVICE_KEYS");
        }
    }

    /// Every inform field the sources read (`inform_str`, and every quoted name in an
    /// expression on `ctx.inform`) is in `inform_inputs`, so the controller's render
    /// cache, keyed on it, never reuses a config made from an inform that differed.
    #[test]
    fn inform_inputs_cover_every_field_read() {
        let sources = [include_str!("lib.rs"), include_str!("mgmt.rs"), include_str!("net.rs"), include_str!("system.rs"), include_str!("wlan.rs"), include_str!("meta.rs")];
        let known = |k: &str| INFORM_KEYS.contains(&k) || INFORM_TABLE_KEYS.iter().any(|(t, f)| *t == k || *f == k);
        let mut read: Vec<&str> = CAP_KEYS.to_vec();
        for src in sources {
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
