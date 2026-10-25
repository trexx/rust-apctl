//! The readers apcfg exports for the controller, which must read the settings the way
//! the render does: checked on their own and against a render.

use apcfg::{
    Controller, DEFAULT_COUNTRY, Input, as_int, bool_of, capable_width, configured_width, country_code, flag, int_of, is_dfs_channel, override_of, radio_ai_na_dfs, radio_width, render, ssh_username,
    ssid_usergroup, ssid_vlan, usergroup_limits, wlan_bands,
};
use serde_json::{Value, json};

const MAC: &str = "02:00:00:00:00:01";

/// One site `s` with networks `tagged` (VLAN 20) and `lan` (untagged), user groups
/// `Default` (no limit) and `slow`, a RADIUS profile assigning VLANs, and one AP
/// with a 2.4 and a 5 GHz radio. Another site `t` has a group and a network too.
fn state(wlans: Value, radio_ai: Value) -> Value {
    json!({
        "sites": [{ "_id": "s", "name": "default" }, { "_id": "t", "name": "other" }],
        "networkconf": [
            { "_id": "tagged", "site_id": "s", "vlan_enabled": true, "vlan": "20" },
            { "_id": "lan", "site_id": "s", "vlan_enabled": false, "vlan": 30 },
            { "_id": "theirs", "site_id": "t", "vlan_enabled": true, "vlan": 40 },
        ],
        "usergroup": [
            { "_id": "default", "site_id": "s", "attr_hidden_id": "Default", "qos_rate_max_down": -1, "qos_rate_max_up": -1 },
            { "_id": "slow", "site_id": "s", "qos_rate_max_down": 2000.0, "qos_rate_max_up": "500" },
            { "_id": "their_slow", "site_id": "t", "qos_rate_max_down": 100, "qos_rate_max_up": 100 },
        ],
        "radiusprofile": [{ "_id": "dynamic", "site_id": "s", "vlan_wlan_mode": "optional" }],
        "apgroup": [{ "_id": "all", "site_id": "s", "attr_hidden_id": "default", "device_macs": [] }],
        "setting": [{ "key": "radio_ai", "site_id": "s", "radios_configuration": radio_ai }, { "key": "mgmt", "site_id": "s", "x_ssh_md5passwd": "$1$x$y" }],
        "wlanconf": wlans,
        "devices": [{
            "mac": MAC, "site_id": "s", "type": "uap", "name": "AP",
            "radio_table": [{ "name": "wifi0", "radio": "ng", "is_11ax": true }, { "name": "wifi1", "radio": "na", "is_11ax": true, "has_ht160": true }],
        }],
    })
}

fn wlan(name: &str, extra: Value) -> Value {
    let mut w = json!({ "_id": name, "site_id": "s", "name": name, "security": "wpapsk", "x_passphrase": "a passphrase", "ap_group_ids": ["all"] });
    w.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    w
}

fn system_cfg(state: &Value) -> String {
    let controller = Controller::default();
    render(&Input { state, device_mac: MAC, inform: None, cfgversion: "1", controller: &controller }).unwrap().system_cfg
}

/// The value of a config line.
fn line<'c>(cfg: &'c str, key: &str) -> Option<&'c str> {
    cfg.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
}

#[test]
fn readers_take_numbers_and_strings_as_the_render_does() {
    let v = json!({ "t": "true", "f": false, "n": "12", "x": 3.0, "bad": "yes" });
    assert_eq!((bool_of(&v, "t"), bool_of(&v, "f"), bool_of(&v, "bad"), bool_of(&v, "none")), (Some(true), Some(false), None, None));
    assert!(flag(&v, "none", true) && !flag(&v, "bad", false));
    assert_eq!((int_of(&v, "n"), int_of(&v, "x"), int_of(&v, "t")), (Some(12), Some(3), None));
    assert_eq!([as_int(&json!(80.0)), as_int(&json!(" 20 ")), as_int(&json!(1.5)), as_int(&json!(true)), as_int(&json!(null))], [Some(80), Some(20), None, None, None]);
    let device = json!({ "on": "on", "off": "off", "default": "default" });
    assert!(override_of(&device, "on", false) && !override_of(&device, "off", true));
    assert!(override_of(&device, "default", true) && !override_of(&device, "none", false), "anything else follows the site");
    assert_eq!([ssh_username(&json!({ "x_ssh_username": "admin" })), ssh_username(&json!({})), ssh_username(&json!({ "x_ssh_username": 7 }))], ["admin", "ubnt", "ubnt"]);
    assert_eq!(ssh_username(&json!({ "x_ssh_username": "" })), "", "an empty name is sent as stored");
}

#[test]
fn a_radios_capable_width_follows_its_flags() {
    let width = |r: Value| capable_width(&r);
    assert_eq!(width(json!({ "has_eht320": true, "has_eht240": true, "has_ht160": true })), 320);
    assert_eq!((width(json!({ "has_eht240": "true" })), width(json!({ "has_ht160": true, "is_11ac": true }))), (240, 160));
    assert_eq!((width(json!({ "is_11ax": true })), width(json!({ "is_11ac": true })), width(json!({ "has_eht320": false }))), (80, 80, 40));
}

#[test]
fn an_ssids_vlan_is_its_networks_else_its_own() {
    let s = state(json!([]), json!([]));
    let vlan = |w: Value| ssid_vlan(&s, "s", &w);
    assert_eq!(vlan(json!({ "networkconf_id": "tagged" })), Some(20));
    assert_eq!(vlan(json!({ "networkconf_id": "tagged", "vlan_enabled": true, "vlan": 99 })), Some(20), "the network's VLAN wins");
    assert_eq!(vlan(json!({ "networkconf_id": "lan" })), None);
    assert_eq!(vlan(json!({ "networkconf_id": "lan", "vlan_enabled": "true", "vlan": "99" })), Some(99), "the legacy VLAN of the WLAN");
    assert_eq!(vlan(json!({ "networkconf_id": "lan", "vlan_enabled": true, "vlan": 1 })), None, "VLAN 1 is untagged");
    assert_eq!(vlan(json!({ "networkconf_id": "theirs" })), None, "another site's network");
    assert_eq!(vlan(json!({ "networkconf_id": "tagged", "security": "wpaeap", "radiusprofile_id": "dynamic" })), None, "RADIUS assigns the VLAN");
    assert_eq!(vlan(json!({ "networkconf_id": "tagged", "security": "wpapsk", "radiusprofile_id": "dynamic" })), Some(20));
}

#[test]
fn a_radios_width_is_its_own_else_radio_ai_else_the_bands_default() {
    let s = state(json!([]), json!([{ "radio": "na", "channel_width": "40" }]));
    let width = |r: Value| configured_width(&s, "s", &r);
    assert_eq!((width(json!({ "radio": "na", "ht": "160" })), width(json!({ "radio": "na", "ht": 20 }))), (160, 20));
    assert_eq!(width(json!({ "radio": "na" })), 40, "radio_ai's width for the band");
    assert_eq!((width(json!({ "radio": "ng" })), width(json!({ "radio": "6e" })), width(json!({}))), (20, 160, 20));
    let s = state(json!([]), json!([]));
    assert_eq!(configured_width(&s, "s", &json!({ "radio": "na" })), 80);
    assert_eq!(configured_width(&s, "t", &json!({ "radio": "na" })), 80, "another site's radio_ai does not apply");
}

#[test]
fn an_ssids_user_group_falls_back_to_the_default_group() {
    let s = state(json!([]), json!([]));
    let group = |w: Value| ssid_usergroup(&s, "s", &w).and_then(apcfg::oid);
    assert_eq!(group(json!({ "usergroup_id": "slow" })), Some("slow"));
    for w in [json!({}), json!({ "usergroup_id": "" }), json!({ "usergroup_id": "gone" }), json!({ "usergroup_id": "their_slow" })] {
        assert_eq!(group(w.clone()), Some("default"), "{w}");
    }
    assert_eq!(ssid_usergroup(&s, "t", &json!({})), None, "a site without a Default group");
    assert_eq!(usergroup_limits(&s["usergroup"][1]), (2000, 500));
    assert_eq!(usergroup_limits(&json!({ "qos_rate_max_down": "fast" })), (-1, -1));
}

/// The exports read what the render then sends: the VAP's bridge, its speed limit and
/// the radio's width.
#[test]
fn the_render_agrees_with_the_exports() {
    let wlans = json!([wlan("Home", json!({ "networkconf_id": "tagged", "usergroup_id": "slow" }))]);
    let s = state(wlans, json!([{ "radio": "na", "channel_width": 40 }]));
    let cfg = system_cfg(&s);
    let w = &s["wlanconf"][0];
    assert_eq!(line(&cfg, "aaa.1.br.devname"), Some(format!("br0.{}", ssid_vlan(&s, "s", w).unwrap()).as_str()));
    let (down, up) = usergroup_limits(ssid_usergroup(&s, "s", w).unwrap());
    assert_eq!((line(&cfg, "qos.vap.1.dwnlink.maxspeed"), line(&cfg, "qos.vap.1.uplink.1.maxspeed")), (Some(down.to_string().as_str()), Some(up.to_string().as_str())));
    let radios = s["devices"][0]["radio_table"].as_array().unwrap();
    assert_eq!(line(&cfg, "radio.1.ieee_mode"), Some(format!("11nght{}", radio_width(&s, "s", &radios[0])).as_str()));
    assert_eq!(line(&cfg, "radio.2.ieee_mode"), Some(format!("11naht{}", radio_width(&s, "s", &radios[1])).as_str()));
    assert_eq!((configured_width(&s, "s", &radios[1]), radio_width(&s, "s", &radios[1])), (40, 40));
    assert_eq!(line(&cfg, "users.1.name"), Some(ssh_username(&s["setting"][1])));
    assert_eq!(line(&cfg, "radio.1.countrycode"), Some(DEFAULT_COUNTRY.to_string().as_str()), "a site without a country setting");
}

/// The render caps a radio's width by what it can do and by its band, as
/// [`radio_width`] does: an 11ax radio set to 160 MHz without `has_ht160` gets 80, a
/// 2.4 GHz radio set to 80 gets 40; and the user's own name is the SSH account.
#[test]
fn the_render_caps_widths_and_names_the_ssh_user_as_the_exports_do() {
    let mut s = state(json!([wlan("Home", json!({}))]), json!([]));
    s["devices"][0]["radio_table"][0]["ht"] = json!(80);
    s["devices"][0]["radio_table"][1] = json!({ "name": "wifi1", "radio": "na", "is_11ax": true, "ht": 160 });
    s["setting"][1]["x_ssh_username"] = json!("admin");
    let cfg = system_cfg(&s);
    let radios = s["devices"][0]["radio_table"].as_array().unwrap();
    assert_eq!([configured_width(&s, "s", &radios[0]), configured_width(&s, "s", &radios[1])], [80, 160], "what is set");
    assert_eq!([radio_width(&s, "s", &radios[0]), radio_width(&s, "s", &radios[1])], [40, 80], "what runs");
    assert_eq!(capable_width(&radios[1]), 80);
    assert_eq!(line(&cfg, "radio.1.ieee_mode"), Some(format!("11nght{}", radio_width(&s, "s", &radios[0])).as_str()));
    assert_eq!(line(&cfg, "radio.2.ieee_mode"), Some(format!("11naht{}", radio_width(&s, "s", &radios[1])).as_str()));
    assert_eq!(line(&cfg, "radio.2.ieee_mode"), Some("11naht80"));
    assert_eq!(line(&cfg, "users.1.name"), Some("admin"));
}

/// The bands an SSID goes on: those its `wlan_bands` names, else 2.4 and 5 GHz, as the
/// render deploys it.
#[test]
fn the_render_deploys_ssids_on_the_bands_the_export_names() {
    let cases = [("Both", json!({})), ("Empty", json!({ "wlan_bands": [] })), ("Unknown", json!({ "wlan_bands": ["7g", 5] })), ("Five", json!({ "wlan_bands": ["5g", "7g"] }))];
    let s = state(Value::Array(cases.iter().map(|(name, extra)| wlan(name, extra.clone())).collect()), json!([]));
    let cfg = system_cfg(&s);
    // The radios (`wifi0`, `wifi1`) an SSID's `wireless.N` sections are on.
    let on = |ssid: &str| -> Vec<&str> {
        let sections = cfg.lines().filter_map(|l| l.strip_prefix("wireless.")?.strip_suffix(&format!(".ssid={ssid}")));
        sections.map(|n| line(&cfg, &format!("wireless.{n}.parent")).unwrap()).collect()
    };
    for (i, (name, _)) in cases.iter().enumerate() {
        let radios: Vec<&str> = wlan_bands(&s["wlanconf"][i]).iter().map(|b| if *b == "2g" { "wifi0" } else { "wifi1" }).collect();
        assert_eq!(on(name), radios, "{name}");
    }
    assert_eq!(wlan_bands(&s["wlanconf"][0]), ["2g", "5g"]);
    assert_eq!(wlan_bands(&s["wlanconf"][2]), ["2g", "5g"], "names no band it knows");
    assert_eq!(wlan_bands(&s["wlanconf"][3]), ["5g"]);
    assert_eq!(wlan_bands(&json!({ "wlan_bands": ["6g", "2g"] })), ["6g", "2g"]);
}

/// The site's country is a number however it is stored, as [`country_code`] reads it
/// for the controller's channel rules: the APs get it as one (the US for a code that is
/// no number), and the US and Canada get the FCC DFS reset.
#[test]
fn the_country_is_read_as_a_number() {
    let mut s = state(json!([wlan("Home", json!({}))]), json!([]));
    s["devices"][0]["radio_table"][1] = json!({ "name": "wifi1", "radio": "na", "is_11ax": true, "has_fccdfs": true, "channel": 100 });
    let country = |s: &mut Value, code: Value| {
        s["setting"].as_array_mut().unwrap().retain(|d| d["key"] != "country");
        s["setting"].as_array_mut().unwrap().push(json!({ "key": "country", "site_id": "s", "code": code }));
        let cfg = system_cfg(s);
        let dfs_reset = cfg.lines().any(|l| l.ends_with(".cmd=syswrapper.sh dfs-reset"));
        (line(&cfg, "radio.countrycode").map(str::to_string), line(&cfg, "radio.2.countrycode").map(str::to_string), dfs_reset)
    };
    let code = |c: &str, dfs| (Some(c.to_string()), Some(c.to_string()), dfs);
    for stored in [json!("840"), json!(840), json!(840.0), json!(" 840"), json!("0840"), json!("x"), json!(true), json!("124.0"), Value::Null] {
        assert_eq!(country(&mut s, stored.clone()), code("840", true), "{stored}");
        assert_eq!(country_code(&stored), DEFAULT_COUNTRY, "{stored}");
    }
    assert_eq!(country(&mut s, json!(124.0)), code("124", true));
    assert_eq!(country(&mut s, json!("276")), code("276", false), "a radio with only FCC DFS");
    assert_eq!((country_code(&json!(124.0)), country_code(&json!("276"))), (124, 276));
}

/// What the render does with DFS, as the exports read it: 5 GHz automatic channel
/// selection may use DFS channels (`acsdfs`) when radio_ai's `na` entry allows it, and
/// a radio fixed to a DFS channel gets the nightly DFS reset.
#[test]
fn the_render_treats_dfs_as_the_exports_do() {
    let allowed = [
        (json!([{ "radio": "na", "dfs": true }]), true),
        (json!([{ "radio": "na", "dfs": "true" }]), true),
        (json!([{ "radio": "na", "dfs": false }]), false),
        (json!([{ "radio": "na", "dfs": "yes" }]), false),
        (json!([{ "radio": "na" }]), false),
        (json!([{ "radio": "ng", "dfs": true }]), false),
        (json!([]), false),
    ];
    for (radios_configuration, on) in allowed {
        let mut s = state(json!([wlan("Home", json!({}))]), radios_configuration.clone());
        // The bit (wifi_caps2 bit 4) of APs whose channel selection can be told about DFS.
        s["devices"][0]["wifi_caps2"] = json!(1 << 4);
        assert_eq!(radio_ai_na_dfs(&s["setting"][0]), on, "{radios_configuration}");
        assert_eq!(line(&system_cfg(&s), "radio.2.acsdfs"), Some(if on { "enabled" } else { "disabled" }), "{radios_configuration}");
    }
    assert!(!radio_ai_na_dfs(&Value::Null), "a site without a radio_ai setting");

    let mut s = state(json!([wlan("Home", json!({}))]), json!([]));
    for ch in [36, 48, 52, 100, 144, 149, 165] {
        s["devices"][0]["radio_table"][1] = json!({ "name": "wifi1", "radio": "na", "is_11ax": true, "has_fccdfs": true, "channel": ch });
        let dfs_reset = system_cfg(&s).lines().any(|l| l.ends_with(".cmd=syswrapper.sh dfs-reset"));
        assert_eq!(dfs_reset, is_dfs_channel(ch), "channel {ch}");
    }
    assert_eq!([36, 48, 52, 100, 144, 149, 165].map(is_dfs_channel), [false, false, true, true, true, false, false]);
}
