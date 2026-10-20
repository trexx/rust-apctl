//! Replays the capture session's settings changes (see the capture README and
//! `manifest.json`) on the final state, rendering both APs after every step:
//!
//! * each render must equal the push captured for that step (up to `common::normalise`);
//! * the diff between consecutive renders must have exactly the keys (or counts) the
//!   manifest records for that step;
//! * the `config_meta` from each render is stored before the next one, as the official
//!   controller does, so section numbers and VAP names evolve like they did live.
//!
//! The session started from the final state minus the test SSID, and the test SSID's
//! document is not in the snapshot (it was deleted in step 10). `test_wlan` reconstructs
//! it from what the step-1 push says about it.

#![recursion_limit = "256"]

mod common;

use common::{AP_B, AP_U, EXPECTED_PUSHES, assert_matches, check_expectation, load, manifest, render, state, store_meta};
use serde_json::{Value, json};
use wire::cfgdiff;

const SITE: &str = "00000000000000000000001e";
const TEST_WLAN_ID: &str = "0000000000000000000000f1";
const VLAN_NET_ID: &str = "0000000000000000000000f2";

/// The SSID created in step 1: WPA2-PSK on 2.4 + 5 GHz for "All APs", otherwise the
/// UI's defaults for a new WLAN. Values follow the step-1 push (e.g. `group_rekey=0`,
/// `pmf.mode=0`, `uapsd=disabled`, `no2ghz_oui=enabled`).
fn test_wlan() -> Value {
    json!({
        "_id": {"$oid": TEST_WLAN_ID},
        "site_id": SITE,
        "name": "ssid-8",
        "x_passphrase": "secret-8",
        "x_iapp_key": "secret-9",
        "short_id": 4,
        "enabled": true,
        "security": "wpapsk",
        "wpa_mode": "wpa2",
        "wpa_enc": "ccmp",
        "pmf_mode": "disabled",
        "wpa3_support": false,
        "wpa3_transition": false,
        "wpa3_fast_roaming": false,
        "sae_anti_clogging": 5,
        "sae_sync": 5,
        "group_rekey": 0,
        "wlan_bands": ["2g", "5g"],
        "ap_group_ids": ["00000000000000000000003c"],
        "networkconf_id": "00000000000000000000003b",
        "hide_ssid": false,
        "is_guest": false,
        "l2_isolation": false,
        "fast_roaming_enabled": false,
        "bss_transition": true,
        "uapsd_enabled": false,
        "mcastenhance_enabled": false,
        "no2ghz_oui": true,
        "proxy_arp": false,
        "country_beacon": false,
        "iapp_enabled": true,
        "minrate_ng_enabled": true,
        "minrate_ng_data_rate_kbps": 1000,
        "minrate_na_enabled": false,
        "minrate_na_data_rate_kbps": 6000,
        "dtim_mode": "default",
        "mac_filter_enabled": false,
        "bc_filter_enabled": false,
        "mdns_proxy_mode": "off",
        "dns_assistance_mode": "off",
        "multicast_suppressor_mode": "disabled",
        "roaming_assistant_na_enabled": false
    })
}

fn wlan_mut(state: &mut Value) -> &mut Value {
    state["wlanconf"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|w| w["_id"]["$oid"] == TEST_WLAN_ID)
        .expect("test WLAN present")
}

fn radio_mut<'a>(state: &'a mut Value, mac: &str, name: &str) -> &'a mut Value {
    let dev = state["devices"].as_array_mut().unwrap().iter_mut().find(|d| d["mac"] == mac).unwrap();
    dev["radio_table"].as_array_mut().unwrap().iter_mut().find(|r| r["name"] == name).unwrap()
}

/// The settings change of each manifest step.
fn apply(step: u64, s: &mut Value) {
    match step {
        1 => s["wlanconf"].as_array_mut().unwrap().push(test_wlan()),
        2 => {
            let w = wlan_mut(s);
            w["wpa3_support"] = json!(true);
            w["wpa3_transition"] = json!(true);
            // The UI turns on optional PMF with WPA3 transition.
            w["pmf_mode"] = json!("optional");
        }
        3 => wlan_mut(s)["hide_ssid"] = json!(true),
        4 => wlan_mut(s)["wlan_bands"] = json!(["5g"]),
        5 => {
            s["networkconf"].as_array_mut().unwrap().push(json!({
                "_id": {"$oid": VLAN_NET_ID},
                "site_id": SITE,
                "name": "vlan-2",
                "purpose": "vlan-only",
                "vlan_enabled": true,
                "vlan": 2,
                "enabled": true
            }));
            wlan_mut(s)["networkconf_id"] = json!(VLAN_NET_ID);
        }
        6 => wlan_mut(s)["fast_roaming_enabled"] = json!(true),
        7 => wlan_mut(s)["l2_isolation"] = json!(true),
        8 => {
            let w = wlan_mut(s);
            w["minrate_na_enabled"] = json!(true);
            w["minrate_na_data_rate_kbps"] = json!(12000);
        }
        9 => {
            let w = wlan_mut(s);
            w["mcastenhance_enabled"] = json!(true);
            w["group_rekey"] = json!(3600);
        }
        10 => {
            s["wlanconf"].as_array_mut().unwrap().retain(|w| w["_id"]["$oid"] != TEST_WLAN_ID);
            s["networkconf"].as_array_mut().unwrap().retain(|n| n["_id"]["$oid"] != VLAN_NET_ID);
        }
        12 => radio_mut(s, AP_U, "wifi1")["tx_power_mode"] = json!("medium"),
        13 => radio_mut(s, AP_U, "wifi1")["channel"] = json!(36),
        14 => radio_mut(s, AP_U, "wifi1")["ht"] = json!(40),
        15 => {
            let r = radio_mut(s, AP_U, "wifi1");
            r["tx_power_mode"] = json!("custom");
            r["channel"] = json!(44);
            r["ht"] = json!(80);
        }
        _ => panic!("no change modelled for step {step}"),
    }
}

fn mac_of(ap: &str) -> &'static str {
    if ap == "B" { AP_B } else { AP_U }
}

fn names<'a>(v: &[(&'a str, std::borrow::Cow<str>)]) -> Vec<&'a str> {
    v.iter().map(|(k, _)| *k).collect()
}

#[test]
fn every_step_renders_like_the_capture() {
    let Some(_) = common::fixtures() else { return };
    let mut s = state();
    // The session started before the test SSID existed: start from the final state
    // (step 10 deleted the SSID again, steps 12-15 only touch AP U's 5 GHz radio, and
    // step 15 restored it). Renders of that state are the "previous" configs of step 1.
    let mut previous: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for ap in ["B", "U"] {
        previous.insert(ap.to_string(), render(&s, mac_of(ap), "0").rendered.system_cfg);
    }
    let mut checked = 0;
    for step in manifest()["steps"].as_array().unwrap() {
        let n = step["step"].as_u64().unwrap();
        apply(n, &mut s);
        for push in step["pushes"].as_array().unwrap() {
            let ap = push["ap"].as_str().unwrap();
            let mac = mac_of(ap);
            let captured = load(push["file"].as_str().unwrap());
            let out = render(&s, mac, captured["cfgversion"].as_str().unwrap());
            let ctx = format!("step {n} ({}) on AP {ap}", step["label"].as_str().unwrap());
            assert_matches(&ctx, &out.rendered.system_cfg, captured["system_cfg"].as_str().unwrap());
            assert_eq!(out.rendered.mgmt_cfg.trim_end(), captured["mgmt_cfg"].as_str().unwrap().trim_end(), "{ctx}");
            if let Some(expect) = push.get("expect") {
                let d = cfgdiff::diff(&previous[ap], &out.rendered.system_cfg);
                check_expectation(&ctx, expect, &d);
                checked += 1;
            }
            store_meta(&mut s, mac, out.config_meta);
            previous.insert(ap.to_string(), out.rendered.system_cfg);
        }
    }
    assert_eq!(checked, EXPECTED_PUSHES, "every push after the two baselines is checked");
}

/// Step 1's baseline has no manifest expectation; check the size of what the test SSID
/// adds instead (the README's "baseline" line counts are whole-config sizes).
#[test]
fn step_one_adds_the_test_ssid_on_both_bands() {
    let Some(_) = common::fixtures() else { return };
    let mut s = state();
    let before = render(&s, AP_B, "0").rendered.system_cfg;
    apply(1, &mut s);
    let after = render(&s, AP_B, "0").rendered.system_cfg;
    let d = cfgdiff::diff(&before, &after);
    assert!(d.removed.is_empty() && d.changed.is_empty(), "{}", d.render("", false));
    let added = names(&d.added);
    assert!(added.contains(&"aaa.3.ssid") && added.contains(&"aaa.4.ssid"));
    assert!(added.contains(&"radio.1.virtual.1.devname"));
    let push = load("2026-10-12T184539.445Z_000026_020000000001_reply-setparam.json");
    assert_eq!(after.lines().count(), push["system_cfg"].as_str().unwrap().lines().count());
    assert_eq!(after.lines().count(), 593);
}

/// SNMP (written from the official logic; no capture uses it): its lines sit between
/// `sshd` and `ntpclient`, with no header, and v3 needs the firmware's capability bit.
#[test]
fn snmp_lines_follow_sshd() {
    let Some(_) = common::fixtures() else { return };
    let mut s = state();
    let before = render(&s, AP_B, "0").rendered.system_cfg;
    s["setting"].as_array_mut().unwrap().push(json!({
        "key": "snmp", "site_id": SITE, "enabled": true, "enabledV3": true, "community": "c0mmunity", "username": "mon", "x_password": "v3-secret",
    }));
    let dev = s["devices"].as_array_mut().unwrap().iter_mut().find(|d| d["mac"] == AP_B).unwrap();
    dev["snmp_location"] = json!("Garage");
    let after = render(&s, AP_B, "0").rendered.system_cfg;
    let d = cfgdiff::diff(&before, &after);
    assert!(d.removed.is_empty() && d.changed.is_empty(), "{}", d.render("", false));
    assert_eq!(
        names(&d.added),
        ["snmp.community", "snmp.location", "snmp.status", "snmp.user.1.name", "snmp.user.1.password", "snmp.version"]
    );
    let lines: Vec<&str> = after.lines().collect();
    let at = |p: &str| lines.iter().position(|l| l.starts_with(p)).unwrap();
    let order = ["sshd.", "snmp.status", "snmp.version", "snmp.location", "snmp.community", "snmp.user.1.name", "snmp.user.1.password", "# ntpclient"];
    assert!(order.windows(2).all(|w| at(w[0]) < at(w[1])), "snmp lines out of order");
    assert!(after.contains("snmp.version=all\n"));
}

/// mDNS "auto" filters the SSID's VLAN for every predefined service type, and a
/// custom rule scoped to specific APs applies only on those (written from the
/// decompile; the capture only has custom rules for all APs).
#[test]
fn mdns_auto_list_and_ap_scope() {
    let Some(_) = common::fixtures() else { return };
    let mut s = state();
    let main = s["wlanconf"].as_array_mut().unwrap().iter_mut().find(|w| w["mdns_proxy_mode"] == "custom" && w["mdns_proxy_custom"][0]["services_mode"] == "specific").unwrap();
    main["mdns_proxy_mode"] = json!("auto");
    let cfg = render(&s, AP_B, "0").rendered.system_cfg;
    let expected: usize = apcfg::MDNS_SERVICES.iter().map(|(_, _, t)| t.len()).sum();
    let filter = cfg.lines().filter(|l| l.contains(".service.") && l.starts_with("mdns_sd.filter.")).map(|l| l.split('.').nth(2).unwrap().to_string()).collect::<Vec<_>>();
    let first = filter.first().cloned().unwrap();
    assert_eq!(filter.iter().filter(|f| **f == first).count(), expected, "one service line per type, duplicates kept");
    assert!(cfg.contains(&format!("mdns_sd.filter.{first}.service.1.name=_amazonecho-remote._tcp\n")), "sorted within a code, codes in table order");

    let mut s = state();
    for w in s["wlanconf"].as_array_mut().unwrap() {
        for e in w["mdns_proxy_custom"].as_array_mut().into_iter().flatten() {
            e["ap_scope_mode"] = json!("specific");
            e["ap_macs"] = json!([AP_U]);
        }
    }
    let on_b = render(&s, AP_B, "0").rendered.system_cfg;
    let on_u = render(&s, AP_U, "0").rendered.system_cfg;
    // With no rule applying the official controller still writes the SSID's own merged
    // filter, just without services.
    let services = |cfg: &str| cfg.lines().filter(|l| l.starts_with("mdns_sd.filter.") && l.contains(".service.")).count();
    assert!(on_b.contains("mdns_sd.filter.1.vlan") && services(&on_b) == 0, "nothing proxied on AP B");
    assert_eq!(services(&on_u), 3, "Chromecast (2 types) and Spotify on AP U");
}

/// Deleting a radio's first SSID while another stays on that radio (the captures only
/// delete a virtual VAP): the one that stays keeps its VAP name and on-radio index but
/// takes over the radio's main `devname`/`status` lines. A WLAN added later at on-radio
/// index 0 takes them back, so the radio never has two main VAPs or none.
#[test]
fn deleting_a_radios_first_ssid_moves_its_main_lines() {
    let Some(_) = common::fixtures() else { return };
    // AP B's 2.4 GHz radio (`radio.1`) carries only ssid-6, at on-radio index 0.
    const FIRST_2G: &str = "00000000000000000000003d";
    let main_lines = |cfg: &str| cfg.lines().filter(|l| l.starts_with("radio.1.devname=") || l.starts_with("radio.1.status=")).count();
    let virtual_devs = |cfg: &str| cfg.lines().filter(|l| l.starts_with("radio.1.virtual.") && l.contains(".devname=")).map(str::to_string).collect::<Vec<_>>();
    let first_2g = |meta: &Value| -> Vec<(String, u64, bool)> {
        meta["wireless"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["radio_name"] == "wifi0")
            .map(|w| (w["id_or_name"].as_str().unwrap().to_string(), w["vap_index_on_radio"].as_u64().unwrap(), w["first_on_radio"].as_bool().unwrap()))
            .collect()
    };

    let mut s = state();
    apply(1, &mut s);
    let out = render(&s, AP_B, "0");
    assert_eq!(first_2g(&out.config_meta), [(FIRST_2G.to_string(), 0, true), (TEST_WLAN_ID.to_string(), 1, false)]);
    store_meta(&mut s, AP_B, out.config_meta);

    s["wlanconf"].as_array_mut().unwrap().retain(|w| w["_id"]["$oid"] != FIRST_2G);
    let out = render(&s, AP_B, "0");
    let cfg = &out.rendered.system_cfg;
    assert_eq!(first_2g(&out.config_meta), [(TEST_WLAN_ID.to_string(), 1, true)]);
    assert_eq!(main_lines(cfg), 2, "{cfg}");
    assert!(virtual_devs(cfg).is_empty(), "{:?}", virtual_devs(cfg));
    store_meta(&mut s, AP_B, out.config_meta);

    let mut new = test_wlan();
    new["_id"] = json!({"$oid": "0000000000000000000000f3"});
    new["name"] = json!("ssid-9");
    new["wlan_bands"] = json!(["2g"]);
    s["wlanconf"].as_array_mut().unwrap().push(new);
    let out = render(&s, AP_B, "0");
    let cfg = &out.rendered.system_cfg;
    assert_eq!(first_2g(&out.config_meta), [(TEST_WLAN_ID.to_string(), 1, false), ("0000000000000000000000f3".to_string(), 0, true)]);
    assert_eq!(main_lines(cfg), 2, "{cfg}");
    assert_eq!(virtual_devs(cfg).len(), 1, "{:?}", virtual_devs(cfg));
    assert!(virtual_devs(cfg)[0].starts_with("radio.1.virtual.1.devname="));
}
