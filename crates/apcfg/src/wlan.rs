//! Radios and WLANs: which WLAN goes on which radio, and the `radio.R.*`, `aaa.N.*`
//! and `wireless.N.*` blocks.

use serde_json::Value;

use crate::cfg::Cfg;
use crate::javahash::hash_set_order;
use crate::json::{arr, bool_of, flag, int_of, mac_eq, oid, on_off, str_list, str_of, text_of};
use crate::meta::WifiSlot;
use crate::{Ctx, bit};

/// `radio_caps2` bits for WPA3 features. Both U6-Mesh radios report 31 (all of them);
/// the assignment of the individual bits is our assumption.
const RCAP2_SAE: u32 = 0;
const RCAP2_SAE_FT: u32 = 1;
const RCAP2_WPA3_192: u32 = 2;
const RCAP2_OWE: u32 = 3;
/// `radio_caps` bit for a hardware noise floor (sensitivity) setting.
const RCAP_HARD_NOISE_FLOOR: u32 = 17;

pub struct Radio<'a> {
    /// 1-based position in the name-sorted radio table (`radio.R`).
    pub idx: usize,
    pub name: String,
    /// `ng`, `na` or `6e`.
    pub band: String,
    pub doc: &'a Value,
    /// Transmit power mode `disabled`: the radio and its VAPs are switched off.
    pub disabled: bool,
}

/// One WLAN deployed on one radio.
pub struct Vap {
    /// The WLAN document after per-radio adjustments (e.g. WPA3 turned off).
    pub w: Value,
    /// Index into the radio list.
    pub radio: usize,
    pub slot: WifiSlot,
}

impl Vap {
    pub fn dev(&self) -> &str {
        &self.slot.device_name
    }
}

pub fn wlan_id(w: &Value) -> String {
    oid(w).or_else(|| str_of(w, "name").map(str::to_string)).unwrap_or_default()
}

/// The device's radios, sorted by name (`wifi0`, `wifi1`, ...).
pub fn radios<'a>(ctx: &Ctx<'a>) -> Vec<Radio<'a>> {
    let mut table: Vec<&Value> = arr(ctx.device, "radio_table").iter().collect();
    table.sort_by_key(|r| str_of(r, "name").unwrap_or_default().to_string());
    table
        .into_iter()
        .enumerate()
        .map(|(i, r)| Radio {
            idx: i + 1,
            name: str_of(r, "name").unwrap_or_default().to_string(),
            band: str_of(r, "radio").unwrap_or("ng").to_string(),
            doc: r,
            disabled: str_of(r, "tx_power_mode").is_some_and(|m| m.eq_ignore_ascii_case("disabled")),
        })
        .collect()
}

fn band_of_wlan_band(b: &str) -> Option<&'static str> {
    match b {
        "2g" => Some("ng"),
        "5g" => Some("na"),
        "6g" => Some("6e"),
        _ => None,
    }
}

/// The AP's AP groups: the site default group plus every group listing its MAC.
fn ap_groups(ctx: &Ctx) -> Vec<String> {
    ctx.site_docs("apgroup")
        .filter(|g| {
            str_of(g, "attr_hidden_id") == Some("default")
                || str_list(g, "device_macs").iter().any(|m| mac_eq(m, &ctx.mac))
        })
        .filter_map(oid)
        .collect()
}

fn set(w: &mut Value, key: &str, v: impl Into<Value>) {
    if let Some(o) = w.as_object_mut() {
        o.insert(key.to_string(), v.into());
    }
}

/// Per-radio security adjustments; `None` drops the WLAN from this radio.
fn adapt(ctx: &Ctx, wlan: &Value, radio: &Radio) -> Option<Value> {
    let mut w = wlan.clone();
    let caps2 = int_of(radio.doc, "radio_caps2").unwrap_or(0) as u64;
    let rcap = |b| bit(caps2, b);
    let security = str_of(&w, "security").unwrap_or("open").to_string();
    let wpa3 = flag(&w, "wpa3_support", false);
    let transition = flag(&w, "wpa3_transition", false);
    let ppsk = flag(&w, "private_preshared_keys_enabled", false) || str_of(&w, "attr_hidden_id") == Some("UidIot");
    if ppsk && !bit(ctx.caps.wifi, 20) {
        return None;
    }
    if (flag(&w, "hotspot2conf_enabled", false) || security == "osen") && !bit(ctx.caps.fw, 23) {
        return None;
    }
    match security.as_str() {
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
                if radio.band == "6e" && transition {
                    set(&mut w, "wpa3_transition", false);
                    set(&mut w, "pmf_mode", "required");
                }
                set(&mut w, "wpa_mode", "wpa2");
            }
        }
        "wpaeap" | "osen" => {
            if flag(&w, "wpa3_enhanced_192", false) {
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
pub fn deploy(ctx: &Ctx, radios: &[Radio]) -> Vec<(Value, usize)> {
    if flag(ctx.device, "disabled", false) {
        return Vec::new();
    }
    let groups = ap_groups(ctx);
    let wlans: Vec<&Value> = ctx
        .site_docs("wlanconf")
        .filter(|w| flag(w, "enabled", true))
        .filter(|w| str_list(w, "ap_group_ids").iter().any(|g| groups.iter().any(|m| m == g)))
        .collect();
    let mut out = Vec::new();
    for (ri, radio) in radios.iter().enumerate() {
        for w in &wlans {
            let bands: Vec<&str> = str_list(w, "wlan_bands").into_iter().filter_map(band_of_wlan_band).collect();
            let on_band = if bands.is_empty() { radio.band == "ng" || radio.band == "na" } else { bands.contains(&radio.band.as_str()) };
            if on_band && let Some(adapted) = adapt(ctx, w, radio) {
                out.push((adapted, ri));
            }
        }
    }
    out
}

/// Effective channel width in MHz.
fn width(ctx: &Ctx, r: &Radio) -> i64 {
    let country_max = match r.band.as_str() {
        "ng" => 40,
        "na" => 160,
        _ => 320,
    };
    let configured = int_of(r.doc, "ht")
        .or_else(|| {
            arr(ctx.setting("radio_ai"), "radios_configuration")
                .iter()
                .find(|c| str_of(c, "radio") == Some(r.band.as_str()))
                .and_then(|c| int_of(c, "channel_width"))
        })
        .unwrap_or(match r.band.as_str() {
            "ng" => 20,
            "na" => 80,
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

pub fn country(ctx: &Ctx) -> String {
    text_of(ctx.setting("country"), "code").unwrap_or_else(|| "840".to_string())
}

/// `radio.R.*` for every radio. Returns whether any radio wrote a `stamgr.R` block.
pub fn render_radios(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap]) -> bool {
    let mgmt = ctx.setting("mgmt");
    let advanced = flag(mgmt, "advanced_feature_enabled", false);
    let country = country(ctx);
    let mut any_stamgr = false;
    for (ri, r) in radios.iter().enumerate() {
        let d = r.doc;
        let k = |s: &str| format!("radio.{}.{s}", r.idx);
        let on_radio: Vec<&Vap> = vaps.iter().filter(|v| v.radio == ri).collect();
        let width = width(ctx, r);
        c.set(k("phyname"), &r.name);
        c.set(k("ack.auto"), "disabled");
        c.set(k("acktimeout"), 64);
        c.set(k("ampdu.status"), "enabled");
        c.set(k("clksel"), 1);
        c.set(k("countrycode"), &country);
        c.set(k("cwm.enable"), 0);
        c.set(k("cwm.mode"), u8::from(r.band == "ng" && width != 20));
        c.set(k("forbiasauto"), 0);
        // No VAP is an uplink (mesh uplinks are not implemented), so always master.
        c.set(k("mode"), "master");
        c.set(k("rate.auto"), "enabled");
        c.set(k("rate.mcs"), "auto");
        c.set(k("rfscan"), on_off(flag(d, "spectrum_enabled", false)));
        c.set(k("bcmc_l2_filter.status"), "enabled");
        c.set(k("bgscan.status"), "disabled");
        c.set(k("antenna.gain"), int_of(d, "antenna_gain").unwrap_or(6));
        c.set(k("antenna"), int_of(d, "antenna_id").unwrap_or(-1));
        c.set(k("txpower_mode"), str_of(d, "tx_power_mode").unwrap_or("auto").to_ascii_lowercase());
        c.set(k("txpower"), text_of(d, "tx_power").unwrap_or_else(|| "auto".into()));
        let channel = text_of(d, "channel").unwrap_or_else(|| "0".into());
        c.set(k("channel"), &channel);
        let g = if r.band == "ng" { "g" } else { "a" };
        c.set(k("ieee_mode"), format!("11n{g}ht{width}"));
        let acs_dfs = bit(ctx.caps.wifi2, 4);
        let radio_ai = ctx.setting("radio_ai");
        if r.band == "na" && acs_dfs {
            let dfs = arr(radio_ai, "radios_configuration")
                .iter()
                .find(|c| str_of(c, "radio") == Some("na"))
                .is_some_and(|c| flag(c, "dfs", false));
            c.set(k("acsdfs"), on_off(dfs));
        }
        if channel == "auto" && acs_dfs {
            let blocked: Vec<&str> = arr(radio_ai, "channels_blacklist")
                .iter()
                .filter(|b| str_of(b, "radio") == Some(r.band.as_str()))
                .filter_map(|b| str_of(b, "channel"))
                .collect();
            if !blocked.is_empty() {
                c.set(k("blklst"), hash_set_order(&blocked).join(","));
            }
        }
        if bit(ctx.caps.wifi2, 2) {
            c.set(k("green_ap"), if flag(ctx.device, "green_ap_enabled", false) { 2 } else { 0 });
        }
        // Sensitivity values are offsets above -95 dBm.
        let min_rssi = (int_of(d, "min_rssi").unwrap_or(-80) + 95).max(1);
        let sens = if bit(int_of(d, "radio_caps").unwrap_or(0) as u64, RCAP_HARD_NOISE_FLOOR) {
            if flag(d, "sens_level_enabled", false) {
                Some(int_of(d, "sens_level").unwrap_or(-94) + 95)
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
                c.set(k("hard_noisefloor.status"), "enabled");
                c.set(k("hard_noisefloor.max_sens"), -40);
                c.set(k("hard_noisefloor.minrssi.value"), s);
                c.set(k("hard_noisefloor.minrssi_backoff"), 0);
            }
            _ => c.set(k("hard_noisefloor.status"), "disabled"),
        }
        let rssi_on = flag(d, "min_rssi_enabled", false);
        let lb_on = flag(d, "loadbalance_enabled", false);
        if advanced && (rssi_on || lb_on) {
            any_stamgr = true;
            let s = |x: &str| format!("stamgr.{}.{x}", r.idx);
            c.set(s("status"), "true");
            c.set(s("radio"), &r.band);
            c.set(s("minrssi.status"), rssi_on);
            c.set(s("minrssi.rssi"), min_rssi);
            c.set(s("loadbalance.status"), lb_on);
            c.opt(s("loadbalance.maxsta"), text_of(d, "maxsta"));
        }
        let status = on_off(!r.disabled);
        for v in on_radio {
            if v.slot.first_on_radio {
                c.set(k("devname"), v.dev());
                c.set(k("status"), status);
            } else {
                let o = v.slot.on_radio;
                c.set(k(&format!("virtual.{o}.devname")), v.dev());
                c.set(k(&format!("virtual.{o}.status")), status);
                c.set(k(&format!("virtual.{o}.mode")), "master");
            }
        }
    }
    any_stamgr
}

fn b(w: &Value, key: &str) -> bool {
    flag(w, key, false)
}

/// The VLAN of a network (1 for an untagged one).
pub fn network_vlan(ctx: &Ctx, network_id: Option<&str>) -> i64 {
    network_id
        .and_then(|id| ctx.network(id))
        .filter(|n| b(n, "vlan_enabled"))
        .map_or(1, |n| int_of(n, "vlan").unwrap_or(2))
}

fn radius_profile<'a>(ctx: &Ctx<'a>, w: &Value) -> Option<&'a Value> {
    let id = str_of(w, "radiusprofile_id")?;
    ctx.site_docs("radiusprofile").find(|p| oid(p).as_deref() == Some(id))
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
fn radius_servers(c: &mut Cfg, ctx: &Ctx, w: &Value, k: &dyn Fn(&str) -> String) {
    let Some(p) = radius_profile(ctx, w) else { return };
    let servers = |list: &str, default_port: i64| -> Vec<(String, i64, String)> {
        arr(p, list)
            .iter()
            .filter_map(|s| {
                let ip = str_of(s, "ip").filter(|v| !v.is_empty())?;
                let secret = str_of(s, "x_secret").filter(|v| !v.is_empty())?;
                Some((ip.to_string(), int_of(s, "port").unwrap_or(default_port), secret.to_string()))
            })
            .take(4)
            .collect()
    };
    for (i, (ip, port, secret)) in servers("auth_servers", 1812).iter().enumerate() {
        c.set(k(&format!("radius.auth.{}.ip", i + 1)), ip);
        c.set(k(&format!("radius.auth.{}.port", i + 1)), port);
        c.set(k(&format!("radius.auth.{}.secret", i + 1)), secret);
    }
    for (i, (ip, port, secret)) in servers("acct_servers", 1813).iter().enumerate() {
        c.set(k(&format!("radius.acct.{}.ip", i + 1)), ip);
        c.set(k(&format!("radius.acct.{}.port", i + 1)), port);
        c.set(k(&format!("radius.acct.{}.secret", i + 1)), secret);
    }
    if b(p, "interim_update_enabled") {
        c.set(k("interim_update.status"), "enabled");
        c.set(k("interim_update.interval"), int_of(p, "interim_update_interval").unwrap_or(3600));
    }
}

/// WEP key as hex plus the key type (`wep64`, `wep128`, otherwise `aes128`).
fn wep_key(w: &Value) -> (String, &'static str) {
    let key = str_of(w, "x_wep").unwrap_or_default();
    let is_hex = key.chars().all(|ch| ch.is_ascii_hexdigit());
    let hex = if !is_hex && (key.len() == 5 || key.len() == 13) {
        key.bytes().map(|b| format!("{b:02x}")).collect()
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

/// `aaa.N.*` and `wireless.N.*` for one VAP. `bridge` is the bridge the VAP is a port of.
pub fn render_vap(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap], i: usize, bridge: &str) {
    let v = &vaps[i];
    let w = &v.w;
    let r = &radios[v.radio];
    let n = v.slot.section;
    let a = |s: &str| format!("aaa.{n}.{s}");
    let security = str_of(w, "security").unwrap_or("open");
    let is_6e = r.band == "6e";
    let wpa3 = b(w, "wpa3_support");
    let transition = b(w, "wpa3_transition");
    let ssid = str_of(w, "name").unwrap_or_default();
    let id = text_of(w, "short_id").unwrap_or_default();
    let is_guest = b(w, "is_guest");

    let pmf = match str_of(w, "pmf_mode") {
        Some("optional") => 1,
        Some("required") => 2,
        _ => 0,
    };
    c.set(a("pmf.status"), on_off(pmf != 0));
    c.set(a("pmf.mode"), pmf);
    c.set(a("ft.status"), on_off(b(w, "fast_roaming_enabled")));
    if let Some(level) = int_of(w, "log_level").filter(|l| *l >= 0) {
        c.set(a("log_level"), level);
    }
    c.set(a("country_beacon"), on_off(b(w, "country_beacon")));
    c.set(a("11k.status"), on_off(b(w, "rrm_enabled")));
    let common_tail = |c: &mut Cfg| {
        c.set(a("p2p"), on_off(b(w, "p2p")));
        c.set(a("p2p_cross_connect"), on_off(b(w, "p2p_cross_connect")));
        c.set(a("proxy_arp"), on_off(b(w, "proxy_arp")));
        c.set(a("is_guest"), is_guest);
        c.set(a("tdls_prohibit"), on_off(b(w, "tdls_prohibit")));
        c.set(a("bss_transition"), on_off(flag(w, "bss_transition", true)));
    };
    let eap = matches!(security, "wpaeap" | "osen");
    if security == "open" || security == "wep" {
        c.set(a("br.devname"), bridge);
        c.set(a("devname"), v.dev());
        c.set(a("driver"), "madwifi");
        c.set(a("ssid"), ssid);
        c.set(a("status"), on_off(bit(ctx.caps.wifi, 13) && !r.disabled));
        c.set(a("id"), &id);
        c.set(a("verbose"), 2);
        common_tail(c);
        if security == "open" && wpa3 && !transition {
            // OWE transition pairs (an open VAP plus a hidden OWE companion) are not
            // implemented; a transition WLAN is deployed as its open half only.
            c.set(a("wpa.key.1.mgmt"), "OWE");
        }
        if security == "wep" {
            let (key, kind) = wep_key(w);
            let idx = int_of(w, "wep_idx").unwrap_or(1);
            c.set(a("security"), kind);
            c.set(a(&format!("security.{idx}.key")), key);
            c.set(a("security.default_key"), idx);
        }
    } else {
        let wpa_mode = str_of(w, "wpa_mode").unwrap_or("auto");
        c.set(a("br.devname"), bridge);
        c.set(a("devname"), v.dev());
        c.set(a("driver"), "madwifi");
        c.set(a("ssid"), ssid);
        c.set(a("status"), on_off(!r.disabled));
        c.set(a("verbose"), 2);
        c.set(
            a("wpa"),
            match wpa_mode {
                "wpa1" => 1,
                "wpa2" => 2,
                _ => 3,
            },
        );
        c.set(a("eapol_version"), if wpa_mode == "wpa1" { 1 } else { 2 });
        c.set(a("wpa.group_rekey"), int_of(w, "group_rekey").unwrap_or(3600));
        common_tail(c);
        c.set(a("id"), &id);
        if wpa3 || is_6e {
            c.set(a("wpa3.support"), "enabled");
            c.set(a("wpa3.transition"), on_off(transition));
        }
        let passphrase = str_of(w, "x_passphrase").unwrap_or("letmeinnow");
        if eap {
            if b(w, "wpa3_enhanced_192") {
                c.set(a("wpa3.enhanced_192"), "enabled");
            }
            c.set(a("wpa.key.1.mgmt"), if security == "osen" { "OSEN" } else { "WPA-EAP" });
            c.set(a("wpa.psk"), passphrase);
            c.set(a("auth_cache"), on_off(flag(w, "auth_cache", true)));
            radius_servers(c, ctx, w, &a);
            c.set(a("dynamic_vlan"), dynamic_vlan(ctx, w));
            c.set(a("hs20.status"), "disabled");
        } else {
            let sae = wpa3 || is_6e;
            if sae {
                let ft = if transition { b(w, "wpa3_fast_roaming") } else { b(w, "fast_roaming_enabled") };
                c.set(a("wpa3.ft.status"), on_off(ft));
                if let Some(x) = int_of(w, "sae_anti_clogging").filter(|x| *x > 0) {
                    c.set(a("sae.anti_clogging"), x);
                }
                if let Some(x) = int_of(w, "sae_sync").filter(|x| *x > 0) {
                    c.set(a("sae.sync"), x);
                }
                let groups = arr(w, "sae_groups");
                for (gi, g) in groups.iter().enumerate() {
                    c.set(a(&format!("sae.groups.{}.group", gi + 1)), g.to_string().trim_matches('"'));
                }
                if !groups.is_empty() {
                    c.set(a("sae.has_groups"), "enabled");
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
                    c.set(a("wpa.psk"), default_psk.unwrap_or(passphrase));
                } else if default_psk.is_none() {
                    k += 1;
                    c.set(a(&format!("sae.psk.{k}.psk")), passphrase);
                    c.set(a(&format!("sae.psk.{k}.mac")), "ff:ff:ff:ff:ff:ff");
                }
                for e in entries {
                    k += 1;
                    c.opt(a(&format!("sae.psk.{k}.psk")), str_of(e, "psk"));
                    c.opt(a(&format!("sae.psk.{k}.mac")), str_of(e, "mac"));
                    c.opt(a(&format!("sae.psk.{k}.vlan")), text_of(e, "vlan"));
                    c.opt(a(&format!("sae.psk.{k}.id")), str_of(e, "id"));
                }
                if entries.iter().any(|e| e.get("vlan").is_some()) {
                    c.set(a("dynamic_vlan"), if b(w, "sae_psk_vlan_required") { 2 } else { 1 });
                }
            }
            c.set(a("wpa.key.1.mgmt"), if sae { "SAE" } else { "WPA-PSK" });
            c.set(a("wpa.psk"), passphrase);
            if b(w, "private_preshared_keys_enabled") {
                c.set(a("dynamic_vlan"), 1);
                c.set(a("wpa.psk_file.status"), "enabled");
                for (pi, key) in arr(w, "private_preshared_keys").iter().enumerate() {
                    c.opt(a(&format!("wpa.psk_file.{}.psk", pi + 1)), str_of(key, "password"));
                    let vlan = network_vlan(ctx, str_of(key, "networkconf_id"));
                    if vlan != 1 {
                        c.set(a(&format!("wpa.psk_file.{}.vlanid", pi + 1)), vlan);
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
        c.set(a("wpa.1.pairwise"), pairwise);
        let cipher = match str_of(w, "pmf_cipher") {
            Some("bip-gmac-256") => "BIP-GMAC-256",
            _ => "AES-128-CMAC",
        };
        c.set(a("pmf.cipher"), cipher);
    }
    let mac_auth = b(w, "radius_mac_auth_enabled");
    if eap || mac_auth {
        nas_identifier(c, ctx, w, &a);
    }
    if mac_auth {
        c.set(a("radius.macacl.status"), "enabled");
        c.set(a("radius.macacl.emptypassword"), on_off(b(w, "radius_macacl_empty_password")));
        if !eap {
            radius_servers(c, ctx, w, &a);
        }
    } else {
        c.set(a("radius.macacl.status"), "disabled");
    }
    c.set(a("hide_ssid"), b(w, "hide_ssid"));
    render_wireless(c, ctx, radios, vaps, i);
    if flag(w, "iapp_enabled", true)
        && let Some(key) = str_of(w, "x_iapp_key").filter(|k| !k.is_empty())
    {
        c.set(a("iapp_key"), key);
    }
}

fn nas_identifier(c: &mut Cfg, ctx: &Ctx, w: &Value, a: &dyn Fn(&str) -> String) {
    let value = match str_of(w, "nas_identifier_type") {
        Some("ap_mac") => Some(ctx.mac.clone()),
        Some("ap_name") => str_of(ctx.device, "name").map(str::to_string),
        Some("site_name") => str_of(ctx.site, "desc").or(str_of(ctx.site, "name")).map(str::to_string),
        Some("custom") => str_of(w, "nas_identifier").map(str::to_string),
        _ => None,
    };
    if let Some(v) = value {
        c.set(a("nas_identifier"), v.chars().take(48).collect::<String>());
    }
}

/// Minimum data rate lines; `None` when the band has no minimum rate configured.
fn min_rate(w: &Value, band: &str) -> Option<i64> {
    match band {
        "ng" => Some(int_of(w, "minrate_ng_data_rate_kbps").unwrap_or(1000)),
        "na" if b(w, "minrate_na_enabled") => Some(int_of(w, "minrate_na_data_rate_kbps").unwrap_or(6000)),
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
    let w = &v.w;
    let n = v.slot.section;
    let k = |s: &str| format!("wireless.{n}.{s}");
    let security = str_of(w, "security").unwrap_or("open");
    let is_guest = b(w, "is_guest");
    let rate = min_rate(w, &r.band);
    let caps = ctx.caps;

    c.set(k("mode"), "master");
    c.set(k("devname"), v.dev());
    c.opt(k("id"), text_of(w, "short_id"));
    c.set(k("status"), on_off(!r.disabled));
    c.set(k("authmode"), if security == "open" { 0 } else { 1 });
    c.set(k("l2_isolation"), on_off(bool_of(w, "l2_isolation").unwrap_or(is_guest)));
    c.set(k("is_guest"), is_guest);
    if security == "wep" {
        let (key, kind) = wep_key(w);
        let idx = int_of(w, "wep_idx").unwrap_or(1);
        c.set(k("security"), kind);
        c.set(k(&format!("security.{idx}.key")), key);
        c.set(k("security.default_key"), idx);
    } else {
        c.set(k("security"), "none");
    }
    c.set(k("addmtikie"), "disabled");
    c.set(k("ssid"), str_of(w, "name").unwrap_or_default());
    c.set(k("hide_ssid"), b(w, "hide_ssid"));
    c.set(k("mac_acl.status"), "enabled");
    c.set(k("mac_acl.policy"), "deny");
    c.set(k("wmm"), "enabled");
    c.set(k("uapsd"), on_off(b(w, "uapsd_enabled")));
    c.set(k("parent"), &r.name);
    c.set(k("puren"), 0);
    c.set(k("pureg"), u8::from(!(r.band == "ng" && rate.is_none_or(allows_11b))));
    c.set(k("usage"), if is_guest { "guest" } else { "user" });
    c.set(k("wds"), "disabled");
    c.set(k("mcast.enhance"), u8::from(b(w, "mcastenhance_enabled")));
    c.set(k("multicast.inspect"), bit(caps.fw3, 7));
    c.set(k("autowds"), "disabled");
    c.set(k("vport"), "disabled");
    c.set(k("vwire"), "disabled");
    c.set(k("schedule_enabled"), on_off(!arr(w, "schedule_with_duration").is_empty()));
    let id = wlan_id(w);
    let has_5g_twin = vaps.iter().any(|o| wlan_id(&o.w) == id && radios[o.radio].band == "na");
    c.set(k("no2ghz_oui"), on_off(b(w, "no2ghz_oui") && r.band == "ng" && has_5g_twin));
    c.set(k("element_adopt"), on_off(b(w, "element_adopt")));
    if b(w, "enhanced_iot") {
        c.set(k("iot"), "enabled");
        c.set(k("qbssload"), "disabled");
    }
    if bit(caps.wifi2, 6) {
        c.set(k("advertise_ap_name"), on_off(b(w, "advertise_device_name_in_beacon")));
    }
    let suppressor = str_of(w, "multicast_suppressor_mode");
    let suppress_cap = bit(caps.wifi2, 22);
    if suppress_cap && matches!(suppressor, Some("conservative" | "aggressive")) {
        c.set(k("multicast.suppressor"), "enabled");
    }
    c.set(k("mcastrate"), text_of(w, "mcast_rate").unwrap_or_else(|| "auto".into()));
    if bit(caps.wifi, 6) {
        c.set(k("bga_filter"), "enabled");
    }
    let dtim = if r.band == "ng" && b(w, "iot_dtim_lock") {
        3
    } else if str_of(w, "dtim_mode") == Some("custom") {
        int_of(w, &format!("dtim_{}", r.band)).unwrap_or(if r.band == "ng" { 1 } else { 3 })
    } else if r.band == "ng" {
        1
    } else {
        3
    };
    c.set(k("dtim_period"), dtim);
    if let Some(rate) = rate {
        c.set(k("minrate_data"), rate);
        let beacon = if r.band == "ng" {
            match rate {
                6000 | 9000 => 11000,
                18000 | 36000 | 48000 | 54000 => 24000,
                x => x,
            }
        } else {
            rate
        };
        c.set(k("beacon_rate"), beacon);
        c.set(k("mgmt_rate"), beacon);
        if r.band == "ng" {
            c.set(k("minrate_cck_rates.status"), allows_11b(rate));
        }
        if b(w, &format!("minrate_{}_advertising_rates", r.band)) {
            c.set(k("minrate_below_disable"), "true");
        }
    }
    let aggressive = suppress_cap && suppressor == Some("aggressive");
    if b(w, "bc_filter_enabled") || aggressive {
        c.set(k("bcfilt.status"), "enabled");
        if aggressive {
            c.set(k("bcfilt.bypass_types"), "ARP|NSNA|DHCPV4|DHCPV6");
        }
        let mut macs: Vec<String> = str_list(w, "bc_filter_list").iter().map(|m| m.to_ascii_lowercase()).collect();
        macs.extend(gateway_macs(ctx));
        for (mi, mac) in hash_set_order(&macs).iter().enumerate() {
            c.set(k(&format!("bcfilt.{}.status", mi + 1)), "enabled");
            c.set(k(&format!("bcfilt.{}.mac", mi + 1)), mac);
        }
    }
    if bit(caps.wifi2, 5) {
        let (on, rssi) = match r.band.as_str() {
            "na" => (b(w, "roaming_assistant_na_enabled"), int_of(w, "roaming_assistant_na_rssi").unwrap_or(-75)),
            "6e" => (b(w, "roaming_assistant_6e_enabled"), int_of(w, "roaming_assistant_6e_rssi").unwrap_or(-88)),
            _ => (false, 0),
        };
        if on {
            c.set(k("btm_disassoc.status"), "enabled");
            c.set(k("btm_disassoc.threshold"), rssi);
        }
    }
    let dns_mode = str_of(w, "dns_assistance_mode").unwrap_or("off");
    if bit(caps.fw3, 3) && dns_mode != "off" {
        c.set(k("dns_cache.status"), "enabled");
        c.set(k("dns_bypass.status"), "enabled");
        if dns_mode == "manual" {
            c.set(k("dns_bypass.servers"), str_list(w, "dns_assistance_servers").join(","));
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
