//! Radios and WLANs: which WLAN goes on which radio, and the `radio.R.*`, `aaa.N.*`
//! and `wireless.N.*` blocks.

use std::borrow::Cow;
use std::fmt::Write;

use serde_json::Value;

use crate::cfg::{Cfg, Prefix};
use crate::javahash::hash_set_order;
use crate::json::{Text, arr, as_text, bool_of, flag, int_of, mac_eq, oid, on_off, str_list, str_of, text_of};
use crate::meta::WifiSlot;
use crate::{Cap, Ctx, bit};

/// `radio_caps2` bits for WPA3 features. Both U6-Mesh radios report 31 (all of them);
/// the assignment of the individual bits is our assumption.
const RCAP2_SAE: u32 = 0;
pub(crate) const RCAP2_SAE_FT: u32 = 1;
const RCAP2_WPA3_192: u32 = 2;
const RCAP2_OWE: u32 = 3;
/// `radio_caps` bit for a hardware noise floor (sensitivity) setting.
const RCAP_HARD_NOISE_FLOOR: u32 = 17;

/// A radio's band, as the settings name it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Band<'a> {
    /// 2.4 GHz, `ng`.
    Ng,
    /// 5 GHz, `na`.
    Na,
    /// 6 GHz, `6e`.
    Six,
    /// Any other name, kept as it is.
    Other(&'a str),
}

impl<'a> Band<'a> {
    pub fn parse(name: &'a str) -> Band<'a> {
        match name {
            "ng" => Band::Ng,
            "na" => Band::Na,
            "6e" => Band::Six,
            other => Band::Other(other),
        }
    }

    pub fn as_str(self) -> &'a str {
        match self {
            Band::Ng => "ng",
            Band::Na => "na",
            Band::Six => "6e",
            Band::Other(name) => name,
        }
    }

    /// This band's one of a field's per-band names, given for `ng`, `na` and `6e`
    /// (`["dtim_ng", "dtim_na", "dtim_6e"]`); none for another band.
    fn key(self, keys: [&'static str; 3]) -> Option<&'static str> {
        match self {
            Band::Ng => Some(keys[0]),
            Band::Na => Some(keys[1]),
            Band::Six => Some(keys[2]),
            Band::Other(_) => None,
        }
    }

    /// The band of a WLAN's `wlan_bands` entry (`2g`, `5g`, `6g`).
    fn of_wlan_band(b: &str) -> Option<Band<'static>> {
        match b {
            "2g" => Some(Band::Ng),
            "5g" => Some(Band::Na),
            "6g" => Some(Band::Six),
            _ => None,
        }
    }
}

impl std::fmt::Display for Band<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub struct Radio<'a> {
    /// 1-based position in the name-sorted radio table (`radio.R`).
    pub idx: usize,
    pub name: &'a str,
    pub band: Band<'a>,
    pub doc: &'a Value,
    /// Transmit power mode `disabled`: the radio and its VAPs are switched off.
    pub disabled: bool,
}

/// One WLAN deployed on one radio.
pub struct Vap<'a> {
    /// [`wlan_id`] of the WLAN: the same for its VAPs on every radio.
    pub id: String,
    /// The WLAN document after per-radio adjustments (e.g. WPA3 turned off); a copy
    /// only when something was adjusted.
    pub w: Cow<'a, Value>,
    /// Index into the radio list.
    pub radio: usize,
    pub slot: WifiSlot,
}

impl Vap<'_> {
    pub fn dev(&self) -> &str {
        &self.slot.device_name
    }
}

pub fn wlan_id(w: &Value) -> &str {
    oid(w).or_else(|| str_of(w, "name")).unwrap_or_default()
}

/// The device's radios, sorted by name (`wifi0`, `wifi1`, ...).
pub fn radios<'a>(ctx: &Ctx<'a>) -> Vec<Radio<'a>> {
    let mut table: Vec<&'a Value> = arr(ctx.device, "radio_table").iter().collect();
    table.sort_by_key(|&r| str_of(r, "name").unwrap_or_default());
    table
        .into_iter()
        .enumerate()
        .map(|(i, r)| Radio {
            idx: i + 1,
            name: str_of(r, "name").unwrap_or_default(),
            band: Band::parse(str_of(r, "radio").unwrap_or("ng")),
            doc: r,
            disabled: str_of(r, "tx_power_mode").is_some_and(|m| m.eq_ignore_ascii_case("disabled")),
        })
        .collect()
}

/// The AP's AP groups: the site default group plus every group listing its MAC.
pub fn ap_groups<'a>(ctx: &Ctx<'a>) -> Vec<&'a str> {
    ctx.site_docs("apgroup")
        .filter(|g| {
            str_of(g, "attr_hidden_id") == Some("default")
                || str_list(g, "device_macs").iter().any(|m| mac_eq(m, &ctx.mac))
        })
        .filter_map(oid)
        .collect()
}

/// Whether a document scoped to AP groups (a WLAN, an mDNS entry) names one of `groups`,
/// the AP's (see [`ap_groups`]), in its `ap_group_ids`.
pub fn in_groups(doc: &Value, groups: &[&str]) -> bool {
    arr(doc, "ap_group_ids").iter().filter_map(Value::as_str).any(|g| groups.contains(&g))
}

/// Sets a field of the WLAN, copying the document first if it is still the original.
/// A field that already has the value leaves the document alone (most WPA3, open and
/// enterprise WLANs already hold the values `adapt` writes).
fn set(w: &mut Cow<Value>, key: &str, v: impl Into<Value>) {
    let v = v.into();
    if w.get(key) == Some(&v) {
        return;
    }
    if let Some(o) = w.to_mut().as_object_mut() {
        o.insert(key.to_string(), v);
    }
}

/// Per-radio security adjustments; `None` drops the WLAN from this radio.
fn adapt<'a>(ctx: &Ctx, wlan: &'a Value, radio: &Radio) -> Option<Cow<'a, Value>> {
    let mut w = Cow::Borrowed(wlan);
    let caps2 = int_of(radio.doc, "radio_caps2").unwrap_or(0) as u64;
    let rcap = |b| bit(caps2, b);
    let security = str_of(wlan, "security").unwrap_or("open");
    let wpa3 = flag(wlan, "wpa3_support", false);
    let transition = flag(wlan, "wpa3_transition", false);
    let ppsk = flag(wlan, "private_preshared_keys_enabled", false) || str_of(wlan, "attr_hidden_id") == Some("UidIot");
    if ppsk && !ctx.caps.has(Cap::Ppsk) {
        return None;
    }
    if (flag(wlan, "hotspot2conf_enabled", false) || security == "osen") && !ctx.caps.has(Cap::Hotspot2) {
        return None;
    }
    match security {
        "wpapsk" if wpa3 => {
            if !rcap(RCAP2_SAE) {
                if !transition {
                    return None;
                }
                set(&mut w, "wpa3_support", false);
                set(&mut w, "wpa3_transition", false);
            } else {
                if !rcap(RCAP2_SAE_FT) {
                    set(&mut w, "wpa3_fast_roaming", false);
                    if !transition {
                        set(&mut w, "fast_roaming_enabled", false);
                    }
                }
                if radio.band == Band::Six && transition {
                    set(&mut w, "wpa3_transition", false);
                    set(&mut w, "pmf_mode", "required");
                }
                set(&mut w, "wpa_mode", "wpa2");
            }
        }
        "wpaeap" | "osen" => {
            if flag(wlan, "wpa3_enhanced_192", false) {
                if !rcap(RCAP2_WPA3_192) {
                    return None;
                }
                set(&mut w, "wpa_enc", "gcmp-256");
                set(&mut w, "pmf_cipher", "bip-gmac-256");
            }
            if wpa3 {
                set(&mut w, "wpa_mode", "wpa2");
            }
        }
        "open" if wpa3 => {
            if !rcap(RCAP2_OWE) {
                if !transition {
                    return None;
                }
                set(&mut w, "wpa3_support", false);
                set(&mut w, "wpa3_transition", false);
            }
            set(&mut w, "fast_roaming_enabled", false);
        }
        "wpapsk" => {}
        _ => set(&mut w, "fast_roaming_enabled", false),
    }
    Some(w)
}

/// The WLANs to deploy as `(adjusted WLAN, radio index)`, radio by radio, each radio in
/// the site's WLAN order.
pub fn deploy<'a>(ctx: &Ctx<'a>, radios: &[Radio]) -> Vec<(Cow<'a, Value>, usize)> {
    if flag(ctx.device, "disabled", false) {
        return Vec::new();
    }
    let groups = ap_groups(ctx);
    let wlans: Vec<&'a Value> = ctx
        .site_docs("wlanconf")
        .filter(|w| flag(w, "enabled", true))
        .filter(|w| in_groups(w, &groups))
        .collect();
    let mut out = Vec::new();
    for (ri, radio) in radios.iter().enumerate() {
        for w in &wlans {
            let bands: Vec<Band> = str_list(w, "wlan_bands").into_iter().filter_map(Band::of_wlan_band).collect();
            let on_band = if bands.is_empty() { matches!(radio.band, Band::Ng | Band::Na) } else { bands.contains(&radio.band) };
            if on_band && let Some(adapted) = adapt(ctx, w, radio) {
                out.push((adapted, ri));
            }
        }
    }
    out
}

/// Effective channel width in MHz.
fn width(ctx: &Ctx, r: &Radio) -> i64 {
    let country_max = match r.band {
        Band::Ng => 40,
        Band::Na => 160,
        _ => 320,
    };
    let configured = int_of(r.doc, "ht")
        .or_else(|| ctx.radio_ai_config(r.band).and_then(|c| int_of(c, "channel_width")))
        .unwrap_or(match r.band {
            Band::Ng => 20,
            Band::Na => 80,
            _ => 160,
        });
    let f = |k| flag(r.doc, k, false);
    let capable = if f("has_eht320") {
        320
    } else if f("has_eht240") {
        240
    } else if f("has_ht160") {
        160
    } else if f("is_11ac") || f("is_11ax") {
        80
    } else {
        40
    };
    country_max.min(configured).min(capable)
}

/// `radio.R.*` for every radio. Returns whether any radio wrote a `stamgr.R` block.
pub fn render_radios(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap]) -> bool {
    let advanced = flag(ctx.mgmt, "advanced_feature_enabled", false);
    let mut any_stamgr = false;
    for (ri, r) in radios.iter().enumerate() {
        let d = r.doc;
        let k = Prefix::new("radio", r.idx);
        let on_radio: Vec<&Vap> = vaps.iter().filter(|v| v.radio == ri).collect();
        let width = width(ctx, r);
        c.set(k.at("phyname"), r.name);
        c.set(k.at("ack.auto"), "disabled");
        c.set(k.at("acktimeout"), 64);
        c.set(k.at("ampdu.status"), "enabled");
        c.set(k.at("clksel"), 1);
        c.set(k.at("countrycode"), &ctx.country);
        c.set(k.at("cwm.enable"), 0);
        c.set(k.at("cwm.mode"), u8::from(r.band == Band::Ng && width != 20));
        c.set(k.at("forbiasauto"), 0);
        // No VAP is an uplink (mesh uplinks are not implemented), so always master.
        c.set(k.at("mode"), "master");
        c.set(k.at("rate.auto"), "enabled");
        c.set(k.at("rate.mcs"), "auto");
        c.set(k.at("rfscan"), on_off(flag(d, "spectrum_enabled", false)));
        c.set(k.at("bcmc_l2_filter.status"), "enabled");
        c.set(k.at("bgscan.status"), "disabled");
        c.set(k.at("antenna.gain"), int_of(d, "antenna_gain").unwrap_or(6));
        c.set(k.at("antenna"), int_of(d, "antenna_id").unwrap_or(-1));
        c.set(k.at("txpower_mode"), str_of(d, "tx_power_mode").unwrap_or("auto").to_ascii_lowercase());
        c.set(k.at("txpower"), text_of(d, "tx_power").unwrap_or(Text::Str("auto")));
        let channel = text_of(d, "channel").unwrap_or(Text::Str("0"));
        c.set(k.at("channel"), channel);
        let g = if r.band == Band::Ng { "g" } else { "a" };
        c.set(k.at("ieee_mode"), format_args!("11n{g}ht{width}"));
        let acs_dfs = ctx.caps.has(Cap::AcsDfs);
        if r.band == Band::Na && acs_dfs {
            let dfs = ctx.radio_ai_config(Band::Na).is_some_and(|c| flag(c, "dfs", false));
            c.set(k.at("acsdfs"), on_off(dfs));
        }
        if channel.is("auto") && acs_dfs {
            let blocked: Vec<&str> = arr(ctx.radio_ai, "channels_blacklist")
                .iter()
                .filter(|b| str_of(b, "radio") == Some(r.band.as_str()))
                .filter_map(|b| str_of(b, "channel"))
                .collect();
            if !blocked.is_empty() {
                c.set(k.at("blklst"), hash_set_order(&blocked).join(","));
            }
        }
        if ctx.caps.has(Cap::GreenAp) {
            c.set(k.at("green_ap"), if flag(ctx.device, "green_ap_enabled", false) { 2 } else { 0 });
        }
        // Sensitivity values are offsets above -95 dBm (saturating: an imported value
        // can be any number).
        let min_rssi = int_of(d, "min_rssi").unwrap_or(-80).saturating_add(95).max(1);
        let sens = if bit(int_of(d, "radio_caps").unwrap_or(0) as u64, RCAP_HARD_NOISE_FLOOR) {
            if flag(d, "sens_level_enabled", false) {
                Some(int_of(d, "sens_level").unwrap_or(-94).saturating_add(95))
            } else if flag(d, "min_rssi_enabled", false) && flag(d, "hard_noise_floor_enabled", false) {
                Some(min_rssi - 6)
            } else {
                None
            }
            .map(|s| s.min(55))
        } else {
            None
        };
        match sens {
            Some(s) if advanced => {
                c.set(k.at("hard_noisefloor.status"), "enabled");
                c.set(k.at("hard_noisefloor.max_sens"), -40);
                c.set(k.at("hard_noisefloor.minrssi.value"), s);
                c.set(k.at("hard_noisefloor.minrssi_backoff"), 0);
            }
            _ => c.set(k.at("hard_noisefloor.status"), "disabled"),
        }
        let rssi_on = flag(d, "min_rssi_enabled", false);
        let lb_on = flag(d, "loadbalance_enabled", false);
        if advanced && (rssi_on || lb_on) {
            any_stamgr = true;
            let s = Prefix::new("stamgr", r.idx);
            c.set(s.at("status"), "true");
            c.set(s.at("radio"), r.band);
            c.set(s.at("minrssi.status"), rssi_on);
            c.set(s.at("minrssi.rssi"), min_rssi);
            c.set(s.at("loadbalance.status"), lb_on);
            c.opt(s.at("loadbalance.maxsta"), text_of(d, "maxsta"));
        }
        let status = on_off(!r.disabled);
        for v in on_radio {
            if v.slot.first_on_radio {
                c.set(k.at("devname"), v.dev());
                c.set(k.at("status"), status);
            } else {
                let o = v.slot.on_radio;
                c.set(format_args!("{k}virtual.{o}.devname"), v.dev());
                c.set(format_args!("{k}virtual.{o}.status"), status);
                c.set(format_args!("{k}virtual.{o}.mode"), "master");
            }
        }
    }
    any_stamgr
}

fn b(w: &Value, key: &str) -> bool {
    flag(w, key, false)
}

/// A VLAN id that tags frames: 2 to 4094. Anything else means untagged: 0 and 4095
/// are reserved by 802.1Q, and 1 is the default, untagged VLAN (the official
/// controller treats a network on VLAN 1 as untagged, and its settings API takes
/// network VLANs from 2), so an imported value outside the range is ignored.
pub fn vlan_id(v: i64) -> Option<u16> {
    u16::try_from(v).ok().filter(|v| (2..=4094).contains(v))
}

/// The VLAN a network tags its traffic with, `None` for an untagged one.
pub fn network_vlan(ctx: &Ctx, network_id: Option<&str>) -> Option<u16> {
    network_id.and_then(|id| ctx.network(id)).and_then(tagged_vlan)
}

/// The VLAN a network document tags its traffic with, if it is tagged.
pub fn tagged_vlan(network: &Value) -> Option<u16> {
    b(network, "vlan_enabled").then(|| int_of(network, "vlan").unwrap_or(2)).and_then(vlan_id)
}

fn radius_profile<'a>(ctx: &Ctx<'a>, w: &Value) -> Option<&'a Value> {
    let id = str_of(w, "radiusprofile_id")?;
    ctx.site_docs("radiusprofile").find(|p| oid(p) == Some(id))
}

/// Dynamic VLAN mode of an EAP WLAN: 0 off, 1 optional, 2 required.
pub fn dynamic_vlan(ctx: &Ctx, w: &Value) -> u8 {
    match radius_profile(ctx, w).and_then(|p| str_of(p, "vlan_wlan_mode")) {
        Some("optional") => 1,
        Some("required") => 2,
        _ => 0,
    }
}

/// `radius.auth.*`, `radius.acct.*` and interim updates from the WLAN's RADIUS profile.
fn radius_servers(c: &mut Cfg, ctx: &Ctx, w: &Value, k: Prefix) {
    let Some(p) = radius_profile(ctx, w) else { return };
    let servers = |list: &str, default_port: i64| {
        arr(p, list)
            .iter()
            .filter_map(move |s| {
                let ip = str_of(s, "ip").filter(|v| !v.is_empty())?;
                let secret = str_of(s, "x_secret").filter(|v| !v.is_empty())?;
                Some((ip, int_of(s, "port").unwrap_or(default_port), secret))
            })
            .take(4)
    };
    for (i, (ip, port, secret)) in servers("auth_servers", 1812).enumerate() {
        c.set(format_args!("{k}radius.auth.{}.ip", i + 1), ip);
        c.set(format_args!("{k}radius.auth.{}.port", i + 1), port);
        c.set(format_args!("{k}radius.auth.{}.secret", i + 1), secret);
    }
    for (i, (ip, port, secret)) in servers("acct_servers", 1813).enumerate() {
        c.set(format_args!("{k}radius.acct.{}.ip", i + 1), ip);
        c.set(format_args!("{k}radius.acct.{}.port", i + 1), port);
        c.set(format_args!("{k}radius.acct.{}.secret", i + 1), secret);
    }
    if b(p, "interim_update_enabled") {
        c.set(k.at("interim_update.status"), "enabled");
        c.set(k.at("interim_update.interval"), int_of(p, "interim_update_interval").unwrap_or(3600));
    }
}

/// WEP key as hex plus the key type (`wep64`, `wep128`, otherwise `aes128`). A 5- or 13-character key is
/// an ASCII passphrase and is always hex-encoded, even when it looks like hex; the official controller
/// does the same, and sends the placeholder "wrong" (so hex-encoded too) when no key is set.
fn wep_key(w: &Value) -> (String, &'static str) {
    let key = str_of(w, "x_wep").unwrap_or("wrong");
    let hex = if key.len() == 5 || key.len() == 13 {
        key.bytes().fold(String::with_capacity(2 * key.len()), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
    } else {
        key.to_string()
    };
    let kind = match hex.len() {
        10 => "wep64",
        26 => "wep128",
        _ => "aes128",
    };
    (hex, kind)
}

/// A WEP WLAN's key lines, the same in its `aaa.N` and `wireless.N` sections.
fn wep(c: &mut Cfg, p: Prefix, w: &Value) {
    let (key, kind) = wep_key(w);
    let idx = int_of(w, "wep_idx").unwrap_or(1);
    c.set(p.at("security"), kind);
    c.set(format_args!("{p}security.{idx}.key"), key);
    c.set(p.at("security.default_key"), idx);
}

/// `aaa.N.*` and `wireless.N.*` for one VAP. `bridge` is the bridge the VAP is a port of.
pub fn render_vap(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap], i: usize, bridge: &str) {
    let v = &vaps[i];
    let w: &Value = &v.w;
    let r = &radios[v.radio];
    let n = v.slot.section;
    let a = Prefix::new("aaa", n as usize);
    let security = str_of(w, "security").unwrap_or("open");
    let is_6e = r.band == Band::Six;
    let wpa3 = b(w, "wpa3_support");
    let transition = b(w, "wpa3_transition");
    let ssid = str_of(w, "name").unwrap_or_default();
    let id = text_of(w, "short_id").unwrap_or(Text::Str(""));
    let is_guest = b(w, "is_guest");

    let pmf = match str_of(w, "pmf_mode") {
        Some("optional") => 1,
        Some("required") => 2,
        _ => 0,
    };
    c.set(a.at("pmf.status"), on_off(pmf != 0));
    c.set(a.at("pmf.mode"), pmf);
    c.set(a.at("ft.status"), on_off(b(w, "fast_roaming_enabled")));
    if let Some(level) = int_of(w, "log_level").filter(|l| *l >= 0) {
        c.set(a.at("log_level"), level);
    }
    c.set(a.at("country_beacon"), on_off(b(w, "country_beacon")));
    c.set(a.at("11k.status"), on_off(b(w, "rrm_enabled")));
    let common_tail = |c: &mut Cfg| {
        c.set(a.at("p2p"), on_off(b(w, "p2p")));
        c.set(a.at("p2p_cross_connect"), on_off(b(w, "p2p_cross_connect")));
        c.set(a.at("proxy_arp"), on_off(b(w, "proxy_arp")));
        c.set(a.at("is_guest"), is_guest);
        c.set(a.at("tdls_prohibit"), on_off(b(w, "tdls_prohibit")));
        c.set(a.at("bss_transition"), on_off(flag(w, "bss_transition", true)));
    };
    let eap = matches!(security, "wpaeap" | "osen");
    if security == "open" || security == "wep" {
        c.set(a.at("br.devname"), bridge);
        c.set(a.at("devname"), v.dev());
        c.set(a.at("driver"), "madwifi");
        c.set(a.at("ssid"), ssid);
        c.set(a.at("status"), on_off(ctx.caps.has(Cap::HostapdVaps) && !r.disabled));
        c.set(a.at("id"), id);
        c.set(a.at("verbose"), 2);
        common_tail(c);
        if security == "open" && wpa3 && !transition {
            // OWE transition pairs (an open VAP plus a hidden OWE companion) are not
            // implemented; a transition WLAN is deployed as its open half only.
            c.set(a.at("wpa.key.1.mgmt"), "OWE");
        }
        if security == "wep" {
            wep(c, a, w);
        }
    } else {
        let wpa_mode = str_of(w, "wpa_mode").unwrap_or("auto");
        c.set(a.at("br.devname"), bridge);
        c.set(a.at("devname"), v.dev());
        c.set(a.at("driver"), "madwifi");
        c.set(a.at("ssid"), ssid);
        c.set(a.at("status"), on_off(!r.disabled));
        c.set(a.at("verbose"), 2);
        c.set(
            a.at("wpa"),
            match wpa_mode {
                "wpa1" => 1,
                "wpa2" => 2,
                _ => 3,
            },
        );
        c.set(a.at("eapol_version"), if wpa_mode == "wpa1" { 1 } else { 2 });
        c.set(a.at("wpa.group_rekey"), int_of(w, "group_rekey").unwrap_or(3600));
        common_tail(c);
        c.set(a.at("id"), id);
        if wpa3 || is_6e {
            c.set(a.at("wpa3.support"), "enabled");
            c.set(a.at("wpa3.transition"), on_off(transition));
        }
        let passphrase = str_of(w, "x_passphrase").unwrap_or("letmeinnow");
        if eap {
            if b(w, "wpa3_enhanced_192") {
                c.set(a.at("wpa3.enhanced_192"), "enabled");
            }
            c.set(a.at("wpa.key.1.mgmt"), if security == "osen" { "OSEN" } else { "WPA-EAP" });
            c.set(a.at("wpa.psk"), passphrase);
            c.set(a.at("auth_cache"), on_off(flag(w, "auth_cache", true)));
            radius_servers(c, ctx, w, a);
            c.set(a.at("dynamic_vlan"), dynamic_vlan(ctx, w));
            c.set(a.at("hs20.status"), "disabled");
        } else {
            let sae = wpa3 || is_6e;
            if sae {
                let ft = if transition { b(w, "wpa3_fast_roaming") } else { b(w, "fast_roaming_enabled") };
                c.set(a.at("wpa3.ft.status"), on_off(ft));
                if let Some(x) = int_of(w, "sae_anti_clogging").filter(|x| *x > 0) {
                    c.set(a.at("sae.anti_clogging"), x);
                }
                if let Some(x) = int_of(w, "sae_sync").filter(|x| *x > 0) {
                    c.set(a.at("sae.sync"), x);
                }
                let groups = arr(w, "sae_groups");
                for (gi, g) in groups.iter().enumerate() {
                    c.opt(format_args!("{a}sae.groups.{}.group", gi + 1), as_text(g));
                }
                if !groups.is_empty() {
                    c.set(a.at("sae.has_groups"), "enabled");
                }
                let entries = arr(w, "sae_psk");
                let default_psk = entries
                    .iter()
                    .find(|e| {
                        str_of(e, "mac").is_none_or(|m| m.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff"))
                            && str_of(e, "id").is_none_or(str::is_empty)
                    })
                    .and_then(|e| str_of(e, "psk"))
                    .filter(|p| p.len() <= 64);
                let mut k = 0;
                if transition {
                    c.set(a.at("wpa.psk"), default_psk.unwrap_or(passphrase));
                } else if default_psk.is_none() {
                    k += 1;
                    c.set(format_args!("{a}sae.psk.{k}.psk"), passphrase);
                    c.set(format_args!("{a}sae.psk.{k}.mac"), "ff:ff:ff:ff:ff:ff");
                }
                for e in entries {
                    k += 1;
                    c.opt(format_args!("{a}sae.psk.{k}.psk"), str_of(e, "psk"));
                    c.opt(format_args!("{a}sae.psk.{k}.mac"), str_of(e, "mac"));
                    c.opt(format_args!("{a}sae.psk.{k}.vlan"), text_of(e, "vlan"));
                    c.opt(format_args!("{a}sae.psk.{k}.id"), str_of(e, "id"));
                }
                if entries.iter().any(|e| e.get("vlan").is_some()) {
                    c.set(a.at("dynamic_vlan"), if b(w, "sae_psk_vlan_required") { 2 } else { 1 });
                }
            }
            c.set(a.at("wpa.key.1.mgmt"), if sae { "SAE" } else { "WPA-PSK" });
            c.set(a.at("wpa.psk"), passphrase);
            if b(w, "private_preshared_keys_enabled") {
                c.set(a.at("dynamic_vlan"), 1);
                c.set(a.at("wpa.psk_file.status"), "enabled");
                for (pi, key) in arr(w, "private_preshared_keys").iter().enumerate() {
                    c.opt(format_args!("{a}wpa.psk_file.{}.psk", pi + 1), str_of(key, "password"));
                    if let Some(vlan) = network_vlan(ctx, str_of(key, "networkconf_id")) {
                        c.set(format_args!("{a}wpa.psk_file.{}.vlanid", pi + 1), vlan);
                    }
                }
            }
        }
        let enc = str_of(w, "wpa_enc").unwrap_or("auto");
        let pairwise = match enc {
            "auto" if wpa_mode == "wpa1" && !wpa3 => "TKIP CCMP".to_string(),
            "auto" => "CCMP".to_string(),
            other => other.to_ascii_uppercase(),
        };
        c.set(a.at("wpa.1.pairwise"), pairwise);
        let cipher = match str_of(w, "pmf_cipher") {
            Some("bip-gmac-256") => "BIP-GMAC-256",
            _ => "AES-128-CMAC",
        };
        c.set(a.at("pmf.cipher"), cipher);
    }
    let mac_auth = b(w, "radius_mac_auth_enabled");
    if eap || mac_auth {
        nas_identifier(c, ctx, w, a);
    }
    if mac_auth {
        c.set(a.at("radius.macacl.status"), "enabled");
        c.set(a.at("radius.macacl.emptypassword"), on_off(b(w, "radius_macacl_empty_password")));
        if !eap {
            radius_servers(c, ctx, w, a);
        }
    } else {
        c.set(a.at("radius.macacl.status"), "disabled");
    }
    c.set(a.at("hide_ssid"), b(w, "hide_ssid"));
    render_wireless(c, ctx, radios, vaps, i);
    if flag(w, "iapp_enabled", true)
        && let Some(key) = str_of(w, "x_iapp_key").filter(|k| !k.is_empty())
    {
        c.set(a.at("iapp_key"), key);
    }
}

fn nas_identifier(c: &mut Cfg, ctx: &Ctx, w: &Value, a: Prefix) {
    let value = match str_of(w, "nas_identifier_type") {
        Some("ap_mac") => Some(ctx.mac.as_str()),
        Some("ap_name") => str_of(ctx.device, "name"),
        Some("site_name") => str_of(ctx.site, "desc").or(str_of(ctx.site, "name")),
        Some("custom") => str_of(w, "nas_identifier"),
        _ => None,
    };
    if let Some(v) = value {
        // The first 48 characters.
        let end = v.char_indices().nth(48).map_or(v.len(), |(i, _)| i);
        c.set(a.at("nas_identifier"), &v[..end]);
    }
}

/// Minimum data rate lines; `None` when the band has no minimum rate configured.
fn min_rate(w: &Value, band: Band) -> Option<i64> {
    match band {
        Band::Ng => Some(int_of(w, "minrate_ng_data_rate_kbps").unwrap_or(1000)),
        Band::Na if b(w, "minrate_na_enabled") => Some(int_of(w, "minrate_na_data_rate_kbps").unwrap_or(6000)),
        _ => None,
    }
}

/// Rates at which 2.4 GHz still allows 802.11b clients.
fn allows_11b(rate: i64) -> bool {
    matches!(rate, 1000 | 2000 | 5500 | 11000 | 6000 | 9000)
}

fn render_wireless(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap], i: usize) {
    let v = &vaps[i];
    let r = &radios[v.radio];
    let w: &Value = &v.w;
    let n = v.slot.section;
    let k = Prefix::new("wireless", n as usize);
    let security = str_of(w, "security").unwrap_or("open");
    let is_guest = b(w, "is_guest");
    let rate = min_rate(w, r.band);
    let caps = ctx.caps;

    c.set(k.at("mode"), "master");
    c.set(k.at("devname"), v.dev());
    c.opt(k.at("id"), text_of(w, "short_id"));
    c.set(k.at("status"), on_off(!r.disabled));
    c.set(k.at("authmode"), if security == "open" { 0 } else { 1 });
    c.set(k.at("l2_isolation"), on_off(bool_of(w, "l2_isolation").unwrap_or(is_guest)));
    c.set(k.at("is_guest"), is_guest);
    if security == "wep" {
        wep(c, k, w);
    } else {
        c.set(k.at("security"), "none");
    }
    c.set(k.at("addmtikie"), "disabled");
    c.set(k.at("ssid"), str_of(w, "name").unwrap_or_default());
    c.set(k.at("hide_ssid"), b(w, "hide_ssid"));
    c.set(k.at("mac_acl.status"), "enabled");
    c.set(k.at("mac_acl.policy"), "deny");
    c.set(k.at("wmm"), "enabled");
    c.set(k.at("uapsd"), on_off(b(w, "uapsd_enabled")));
    c.set(k.at("parent"), r.name);
    c.set(k.at("puren"), 0);
    c.set(k.at("pureg"), u8::from(!(r.band == Band::Ng && rate.is_none_or(allows_11b))));
    c.set(k.at("usage"), if is_guest { "guest" } else { "user" });
    c.set(k.at("wds"), "disabled");
    c.set(k.at("mcast.enhance"), u8::from(b(w, "mcastenhance_enabled")));
    c.set(k.at("multicast.inspect"), caps.has(Cap::MulticastInspect));
    c.set(k.at("autowds"), "disabled");
    c.set(k.at("vport"), "disabled");
    c.set(k.at("vwire"), "disabled");
    c.set(k.at("schedule_enabled"), on_off(!arr(w, "schedule_with_duration").is_empty()));
    let has_5g_twin = vaps.iter().any(|o| o.id == v.id && radios[o.radio].band == Band::Na);
    c.set(k.at("no2ghz_oui"), on_off(b(w, "no2ghz_oui") && r.band == Band::Ng && has_5g_twin));
    c.set(k.at("element_adopt"), on_off(b(w, "element_adopt")));
    if b(w, "enhanced_iot") {
        c.set(k.at("iot"), "enabled");
        c.set(k.at("qbssload"), "disabled");
    }
    if caps.has(Cap::AdvertiseApName) {
        c.set(k.at("advertise_ap_name"), on_off(b(w, "advertise_device_name_in_beacon")));
    }
    let suppressor = str_of(w, "multicast_suppressor_mode");
    let suppress_cap = caps.has(Cap::MulticastSuppression);
    if suppress_cap && matches!(suppressor, Some("conservative" | "aggressive")) {
        c.set(k.at("multicast.suppressor"), "enabled");
    }
    c.set(k.at("mcastrate"), text_of(w, "mcast_rate").unwrap_or(Text::Str("auto")));
    if caps.has(Cap::BgaFilter) {
        c.set(k.at("bga_filter"), "enabled");
    }
    schedule(c, w, k, caps.has(Cap::ScheduleInvert), caps.has(Cap::ScheduleBlocks));
    let ng = r.band == Band::Ng;
    let dtim = if ng && b(w, "iot_dtim_lock") {
        3
    } else if str_of(w, "dtim_mode") == Some("custom") {
        r.band.key(["dtim_ng", "dtim_na", "dtim_6e"]).and_then(|key| int_of(w, key)).unwrap_or(if ng { 1 } else { 3 })
    } else if ng {
        1
    } else {
        3
    };
    c.set(k.at("dtim_period"), dtim);
    if let Some(rate) = rate {
        c.set(k.at("minrate_data"), rate);
        let beacon = if ng {
            match rate {
                6000 | 9000 => 11000,
                18000 | 36000 | 48000 | 54000 => 24000,
                x => x,
            }
        } else {
            rate
        };
        c.set(k.at("beacon_rate"), beacon);
        c.set(k.at("mgmt_rate"), beacon);
        if ng {
            c.set(k.at("minrate_cck_rates.status"), allows_11b(rate));
        }
        if r.band.key(["minrate_ng_advertising_rates", "minrate_na_advertising_rates", "minrate_6e_advertising_rates"]).is_some_and(|key| b(w, key)) {
            c.set(k.at("minrate_below_disable"), "true");
        }
    }
    let aggressive = suppress_cap && suppressor == Some("aggressive");
    if b(w, "bc_filter_enabled") || aggressive {
        c.set(k.at("bcfilt.status"), "enabled");
        if aggressive {
            c.set(k.at("bcfilt.bypass_types"), "ARP|NSNA|DHCPV4|DHCPV6");
        }
        let mut macs: Vec<String> = str_list(w, "bc_filter_list").iter().map(|m| m.to_ascii_lowercase()).collect();
        macs.extend(gateway_macs(ctx));
        for (mi, mac) in hash_set_order(&macs).iter().enumerate() {
            c.set(format_args!("{k}bcfilt.{}.status", mi + 1), "enabled");
            c.set(format_args!("{k}bcfilt.{}.mac", mi + 1), mac);
        }
    }
    if caps.has(Cap::RoamingAssistant) {
        let (on, rssi) = match r.band {
            Band::Na => (b(w, "roaming_assistant_na_enabled"), int_of(w, "roaming_assistant_na_rssi").unwrap_or(-75)),
            Band::Six => (b(w, "roaming_assistant_6e_enabled"), int_of(w, "roaming_assistant_6e_rssi").unwrap_or(-88)),
            _ => (false, 0),
        };
        if on {
            c.set(k.at("btm_disassoc.status"), "enabled");
            c.set(k.at("btm_disassoc.threshold"), rssi);
        }
    }
    let dns_mode = str_of(w, "dns_assistance_mode").unwrap_or("off");
    if caps.has(Cap::DnsAssistance) && dns_mode != "off" {
        c.set(k.at("dns_cache.status"), "enabled");
        c.set(k.at("dns_bypass.status"), "enabled");
        if dns_mode == "manual" {
            c.set(k.at("dns_bypass.servers"), str_list(w, "dns_assistance_servers").join(","));
        }
    }
}

/// LAN MACs of the site's gateways; broadcast filters always let them through.
fn gateway_macs(ctx: &Ctx) -> Vec<String> {
    ctx.site_docs("devices")
        .filter(|d| matches!(str_of(d, "type"), Some("ugw" | "udm" | "uxg")))
        .filter_map(|d| str_of(d, "mac"))
        .map(str::to_ascii_lowercase)
        .collect()
}

const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// The blackout blocks (minutes from midnight, end exclusive: 1440 is midnight) per weekday
/// (0 = Sunday) of a WLAN's `schedule_with_duration`. Each entry is a period
/// the WLAN is off: from each start day at the start time, for its duration,
/// across midnight (and days) as needed. Blocks that overlap or touch merge.
pub fn blackout_blocks(w: &Value) -> [Vec<(i64, i64)>; 7] {
    let mut days: [Vec<(i64, i64)>; 7] = Default::default();
    for e in arr(w, "schedule_with_duration") {
        // Imported values are not trusted: the start stays within the day and a
        // block lasts at most a week, so the loop below runs at most eight times.
        let start = int_of(e, "start_hour").unwrap_or(0).saturating_mul(60).saturating_add(int_of(e, "start_minute").unwrap_or(0)).clamp(0, 1439);
        let end = start + int_of(e, "duration_minutes").unwrap_or(0).clamp(0, 7 * 1440);
        if end <= start {
            continue;
        }
        for day in str_list(e, "start_days_of_week") {
            let Some(d) = DAYS.iter().position(|x| x.eq_ignore_ascii_case(day)) else { continue };
            let mut k = 0;
            // An entry ending exactly at midnight leaves nothing on the next day.
            while start.max(k * 1440) < end {
                let from = start.max(k * 1440) - k * 1440;
                let to = (end - k * 1440).min(1440);
                days[(d + k as usize) % 7].push((from, to));
                k += 1;
            }
        }
    }
    for blocks in &mut days {
        blocks.sort();
        let mut merged: Vec<(i64, i64)> = Vec::new();
        for (s, e) in blocks.drain(..) {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        *blocks = merged;
    }
    days
}

/// `HHMM`; midnight at the end of a day is written 2359.
fn hhmm(m: i64) -> String {
    let m = m.min(1439);
    format!("{:02}{:02}", m / 60, m % 60)
}

/// The schedule lines of a VAP: blackout blocks when the firmware takes them
/// inverted (`invert`), else the times the WLAN is on; one key per block when
/// it takes several (`multi`), else the day's key repeated.
fn schedule(c: &mut Cfg, w: &Value, k: Prefix, invert: bool, multi: bool) {
    if arr(w, "schedule_with_duration").is_empty() {
        return;
    }
    let off = blackout_blocks(w);
    if invert {
        c.set(k.at("schedule_invert"), "enabled");
    }
    for (d, blocks) in off.iter().enumerate() {
        let blocks: Vec<(i64, i64)> = if invert {
            blocks.clone()
        } else {
            // The gaps between blackouts.
            let mut on = Vec::new();
            let mut from = 0;
            for (s, e) in blocks {
                if *s > from {
                    on.push((from, *s));
                }
                from = *e;
            }
            if from < 1440 {
                on.push((from, 1440));
            }
            on
        };
        for (i, (s, e)) in blocks.iter().enumerate() {
            let time = format_args!("{}-{}", hhmm(*s), hhmm(*e));
            if multi {
                c.set(format_args!("{k}schedule_{}.{i}", DAYS[d]), time);
            } else {
                c.set(format_args!("{k}schedule_{}", DAYS[d]), time);
            }
        }
    }
}

#[cfg(test)]
mod schedule_tests {
    use super::*;
    use serde_json::json;

    fn lines(w: &Value, invert: bool, multi: bool) -> Vec<String> {
        let mut c = Cfg::default();
        schedule(&mut c, w, Prefix::new("wireless", 1), invert, multi);
        c.finish().lines().map(str::to_string).collect()
    }

    #[test]
    fn a_wlan_is_copied_only_for_a_real_change() {
        let w = json!({ "security": "open", "fast_roaming_enabled": false });
        let mut c = Cow::Borrowed(&w);
        set(&mut c, "fast_roaming_enabled", false);
        assert!(matches!(c, Cow::Borrowed(_)));
        set(&mut c, "wpa_mode", "wpa2");
        assert_eq!((matches!(c, Cow::Owned(_)), &c["wpa_mode"]), (true, &json!("wpa2")));
    }

    #[test]
    fn blackouts_cross_midnight_and_merge() {
        let w = json!({ "schedule_with_duration": [
            { "start_days_of_week": ["mon", "tue"], "start_hour": 22, "start_minute": 0, "duration_minutes": 480 },
            { "start_days_of_week": ["sat"], "start_hour": 23, "start_minute": 0, "duration_minutes": 120 },
            { "start_days_of_week": ["wed"], "start_hour": 5, "start_minute": 30, "duration_minutes": 60 },
        ]});
        assert_eq!(
            lines(&w, true, true),
            vec![
                "wireless.1.schedule_invert=enabled",
                "wireless.1.schedule_sun.0=0000-0100",
                "wireless.1.schedule_mon.0=2200-2359",
                "wireless.1.schedule_tue.0=0000-0600",
                "wireless.1.schedule_tue.1=2200-2359",
                // 00:00-06:00 from Tuesday night and 05:30-06:30 overlap.
                "wireless.1.schedule_wed.0=0000-0630",
                "wireless.1.schedule_sat.0=2300-2359",
            ]
        );
    }

    #[test]
    fn older_firmware_gets_the_on_times() {
        let w = json!({ "schedule_with_duration": [
            { "start_days_of_week": ["mon"], "start_hour": 22, "start_minute": 0, "duration_minutes": 120 },
            { "start_days_of_week": ["fri"], "start_hour": 0, "start_minute": 0, "duration_minutes": 1440 },
        ]});
        let l = lines(&w, false, true);
        assert!(!l.iter().any(|x| x.contains("invert")));
        assert!(l.contains(&"wireless.1.schedule_mon.0=0000-2200".to_string()));
        assert_eq!(l.iter().filter(|x| x.contains("schedule_mon")).count(), 1, "nothing after the blackout to 23:59");
        assert!(l.contains(&"wireless.1.schedule_sun.0=0000-2359".to_string()), "a day without blackout is on all day");
        assert!(!l.iter().any(|x| x.contains("schedule_fri")), "a whole-day blackout has no on time");
        // An entry ending at midnight leaves the next day alone.
        let w = json!({ "schedule_with_duration": [{ "start_days_of_week": ["mon"], "start_hour": 23, "start_minute": 0, "duration_minutes": 60 }] });
        let b = blackout_blocks(&w);
        assert_eq!((b[1].clone(), b[2].len()), (vec![(1380, 1440)], 0));
        assert_eq!(lines(&w, true, false), vec!["wireless.1.schedule_invert=enabled", "wireless.1.schedule_mon=2300-2359"]);
    }

    #[test]
    fn wep_keys_of_5_or_13_characters_are_always_hex_encoded() {
        let key = |w: Value| wep_key(&w);
        assert_eq!(key(json!({ "x_wep": "abcde" })), ("6162636465".to_string(), "wep64"), "hex-looking, but a passphrase");
        assert_eq!(key(json!({ "x_wep": "12345" })), ("3132333435".to_string(), "wep64"));
        assert_eq!(key(json!({ "x_wep": "0123456789abc" })), ("30313233343536373839616263".to_string(), "wep128"));
        assert_eq!(key(json!({ "x_wep": "0123456789" })), ("0123456789".to_string(), "wep64"), "10 characters are hex already");
        assert_eq!(key(json!({ "x_wep": "0123456789abcdef0123456789" })).1, "wep128");
        assert_eq!(key(json!({})), ("77726f6e67".to_string(), "wep64"), "a missing key is \"wrong\"");
    }

    #[test]
    fn out_of_range_schedules_are_clamped() {
        // A duration of years and absurd start times: at most a week, within the day.
        let w = json!({ "schedule_with_duration": [
            { "start_days_of_week": ["mon"], "start_hour": 12, "start_minute": 0, "duration_minutes": i64::MAX },
            { "start_days_of_week": ["tue"], "start_hour": i64::MAX, "start_minute": i64::MAX, "duration_minutes": 30 },
            { "start_days_of_week": ["wed"], "start_hour": -5, "start_minute": 0, "duration_minutes": 60 },
        ]});
        let b = blackout_blocks(&w);
        assert!(b.iter().all(|day| day.iter().all(|&(s, e)| (0..1440).contains(&s) && s < e && e <= 1440)), "{b:?}");
        assert_eq!(b[1], vec![(0, 1440)], "a week from Monday noon covers Monday");
        assert_eq!(b[3], vec![(0, 1440)]);
    }
}
