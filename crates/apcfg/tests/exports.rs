//! The readers apcfg exports for the controller, which must read the settings the way
//! the render does: checked on their own and against a render.

use apcfg::{Controller, Input, bool_of, configured_width, flag, int_of, render, ssid_usergroup, ssid_vlan, usergroup_limits};
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
    assert_eq!(line(&cfg, "radio.1.ieee_mode"), Some(format!("11nght{}", configured_width(&s, "s", &radios[0])).as_str()));
    assert_eq!(line(&cfg, "radio.2.ieee_mode"), Some(format!("11naht{}", configured_width(&s, "s", &radios[1])).as_str()));
}
