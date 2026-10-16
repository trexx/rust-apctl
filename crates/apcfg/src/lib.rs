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
//! Hotspot 2.0, 6 GHz `freq`, site `config.properties` overrides and the `mdns_sd`
//! "auto" service list.
//!
//! Written from the official logic but not yet checked against a capture (none of
//! our data uses them): WLAN schedules (`schedule_*` lines), speed limits (`qos`) and
//! SNMP (`snmp.*`).

mod cfg;
mod javahash;
mod json;
mod meta;
mod mgmt;
mod net;
mod system;
pub mod tz;
mod wlan;

use anyhow::{Context, Result, bail};
use serde_json::Value;

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
    json::arr(state, "clients")
        .iter()
        .filter(|c| json::str_of(c, "site_id").is_none_or(|s| s == site_id))
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
        let get = |k: &str| {
            inform
                .and_then(|i| json::int_of(i, k))
                .or_else(|| json::int_of(device, k))
                .unwrap_or(0) as u64
        };
        Caps {
            fw: get("fw_caps"),
            fw2: get("fw2_caps"),
            fw3: get("fw3_caps"),
            wifi: get("wifi_caps"),
            wifi2: get("wifi_caps2"),
            hw: get("hw_caps"),
        }
    }
}

pub(crate) fn bit(v: u64, n: u32) -> bool {
    v >> n & 1 == 1
}

/// Optional SSID features that depend on what the AP supports, with the
/// capability bit `render` checks for each one. An AP without it gets the SSID
/// without the feature (no config lines), as the official controller does.
pub const SSID_FEATURES: &[&str] = &["dns_assistance", "advertise_ap_name", "roaming_assistant", "multicast_suppression", "wpa3_fast_roaming"];

/// Which of [`SSID_FEATURES`] the AP supports, as `(feature, supported)`, or
/// `None` while that is unknown: the AP has not sent an inform and the
/// settings hold no capability bits for it.
pub fn ssid_feature_support(device: &Value, inform: Option<&Value>) -> Option<Vec<(&'static str, bool)>> {
    let caps = Caps::read(inform, device);
    if caps.fw == 0 && caps.fw3 == 0 && caps.wifi == 0 && caps.wifi2 == 0 {
        return None;
    }
    let radios = json::arr(device, "radio_table");
    let ft = !radios.is_empty() && radios.iter().all(|r| bit(json::int_of(r, "radio_caps2").unwrap_or(0) as u64, wlan::RCAP2_SAE_FT));
    Some(
        SSID_FEATURES
            .iter()
            .map(|&f| {
                let ok = match f {
                    "dns_assistance" => bit(caps.fw3, 3),
                    "advertise_ap_name" => bit(caps.wifi2, 6),
                    "roaming_assistant" => bit(caps.wifi2, 5),
                    "multicast_suppression" => bit(caps.wifi2, 22),
                    _ => ft,
                };
                (f, ok)
            })
            .collect(),
    )
}

/// Everything one render needs, resolved once.
pub(crate) struct Ctx<'a> {
    pub state: &'a Value,
    pub site: &'a Value,
    pub site_id: String,
    pub device: &'a Value,
    pub mac: String,
    pub inform: Option<&'a Value>,
    pub caps: Caps,
    pub controller: &'a Controller,
    pub cfgversion: &'a str,
}

static NULL: Value = Value::Null;

impl<'a> Ctx<'a> {
    fn new(input: &Input<'a>) -> Result<Ctx<'a>> {
        let state = input.state;
        let mac = input.device_mac.to_ascii_lowercase();
        let device = json::arr(state, "devices")
            .iter()
            .find(|d| json::str_of(d, "mac").is_some_and(|m| json::mac_eq(m, &mac)))
            .with_context(|| format!("device {mac} is not in the state"))?;
        let site_id = json::str_of(device, "site_id").context("device has no site_id")?.to_string();
        let site = json::arr(state, "sites")
            .iter()
            .find(|s| json::oid(s).as_deref() == Some(site_id.as_str()))
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
        })
    }

    /// The `setting` document with this key: site-scoped, or global for `super_*` keys.
    pub fn setting(&self, key: &str) -> &'a Value {
        json::arr(self.state, "setting")
            .iter()
            .find(|s| {
                json::str_of(s, "key") == Some(key)
                    && json::str_of(s, "site_id").is_none_or(|id| id == self.site_id)
            })
            .unwrap_or(&NULL)
    }

    /// Documents of a collection that belong to this site (or carry no site at all).
    pub fn site_docs(&self, collection: &str) -> impl Iterator<Item = &'a Value> + '_ {
        json::arr(self.state, collection)
            .iter()
            .filter(|d| json::str_of(d, "site_id").is_none_or(|id| id == self.site_id))
    }

    pub fn network(&self, id: &str) -> Option<&'a Value> {
        self.site_docs("networkconf").find(|n| json::oid(n).as_deref() == Some(id))
    }

    /// SSH account name: also the user cron jobs run as.
    pub fn ssh_username(&self) -> String {
        json::str_of(self.setting("mgmt"), "x_ssh_username").unwrap_or("ubnt").to_string()
    }

    pub fn inform_str(&self, key: &str) -> Option<&'a str> {
        self.inform.and_then(|i| json::str_of(i, key))
    }
}

/// AP-wide features that depend on the AP's capability bits, as `render`
/// checks them: without the bit the setting is not sent at all.
pub const DEVICE_FEATURES: &[&str] = &["band_steering", "airtime_fairness", "green_ap", "led", "led_color", "jumbo_frames", "snmp"];

/// Which of [`DEVICE_FEATURES`] the AP supports, or `None` while unknown (see
/// [`ssid_feature_support`]).
pub fn device_feature_support(device: &Value, inform: Option<&Value>) -> Option<Vec<(&'static str, bool)>> {
    let caps = Caps::read(inform, device);
    if caps.fw == 0 && caps.wifi == 0 && caps.hw == 0 {
        return None;
    }
    Some(
        DEVICE_FEATURES
            .iter()
            .map(|&f| {
                let ok = match f {
                    "band_steering" => bit(caps.wifi, 2),
                    "airtime_fairness" => bit(caps.wifi, 5),
                    "green_ap" => bit(caps.wifi2, 2),
                    "led" => bit(caps.hw, 1) || bit(caps.hw, 14),
                    "led_color" => bit(caps.hw, 1),
                    "snmp" => bit(caps.fw, 13) || bit(caps.fw, 14),
                    _ => bit(caps.fw, 4),
                };
                (f, ok)
            })
            .collect(),
    )
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
        let inform = json!({ "fw_caps": 3892117055u64, "fw3_caps": 206, "wifi_caps": 2709438173u64, "wifi_caps2": 4206576, "hw_caps": 2050 });
        let got = ssid_feature_support(&device, Some(&inform)).unwrap();
        let missing: Vec<&str> = got.iter().filter(|(_, ok)| !ok).map(|(f, _)| *f).collect();
        assert_eq!(missing, ["wpa3_fast_roaming"]);
        let dev: Vec<&str> = device_feature_support(&device, Some(&inform)).unwrap().iter().filter(|(_, ok)| !ok).map(|(f, _)| *f).collect();
        assert_eq!(dev, ["airtime_fairness", "green_ap"]);
        let old = json!({ "fw_caps": 1, "fw3_caps": 0, "wifi_caps2": 0 });
        assert!(ssid_feature_support(&device, Some(&old)).unwrap().iter().all(|(f, ok)| !ok || *f == "wpa3_fast_roaming"));
    }
}
