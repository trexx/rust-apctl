//! `render()` against the last captured push to each AP (step 10 for B, step 15 for U),
//! whose inputs are exactly the final `controller-state.json`.

mod common;

use common::{AP_B, AP_U, assert_matches, load, render, state};
use serde_json::Value;

fn last_push(ap: &str) -> Value {
    load(match ap {
        AP_B => "2026-10-12T190003.026Z_000374_020000000001_reply-setparam.json",
        _ => "2026-10-12T190934.236Z_000676_020000000002_reply-setparam.json",
    })
}

fn golden(ap: &str) {
    let push = last_push(ap);
    let state = state();
    let cfgversion = push["cfgversion"].as_str().unwrap();
    let out = render(&state, ap, cfgversion);
    let (same, total) = assert_matches(&format!("{ap} system_cfg"), &out.rendered.system_cfg, push["system_cfg"].as_str().unwrap());
    eprintln!("{ap}: {same}/{total} system_cfg lines identical before normalising");
    // mgmt_cfg has nothing sanitised beyond the controller's host name, which is
    // consistently `name-15` in both the state and the push: an exact match.
    assert_eq!(out.rendered.mgmt_cfg.trim_end(), push["mgmt_cfg"].as_str().unwrap().trim_end(), "{ap} mgmt_cfg");
}

#[test]
fn ap_b_matches_the_last_push() {
    let Some(_) = common::fixtures() else { return };
    golden(AP_B);
}

#[test]
fn ap_u_matches_the_last_push() {
    let Some(_) = common::fixtures() else { return };
    golden(AP_U);
}

/// With nothing changed, the allocation written back equals the stored `config_meta`.
#[test]
fn config_meta_round_trips() {
    let Some(_) = common::fixtures() else { return };
    let state = state();
    for ap in [AP_B, AP_U] {
        let out = render(&state, ap, "0");
        let stored = state["config_meta"].as_array().unwrap().iter().find(|m| m["mac"] == ap).unwrap();
        let sorted = |v: &Value, k: &str| {
            let mut items: Vec<String> = v[k].as_array().unwrap().iter().map(Value::to_string).collect();
            items.sort();
            items
        };
        for k in ["wireless", "netconf", "bridge_index", "bridge_port"] {
            assert_eq!(sorted(&out.config_meta, k), sorted(stored, k), "{ap} {k}");
        }
        assert_eq!(out.config_meta["flags"], stored["flags"]);
        assert_eq!(out.config_meta["_id"], stored["_id"]);
    }
}

#[test]
fn blocked_sta_lists_blocked_clients() {
    let Some(_) = common::fixtures() else { return };
    let mut state = state();
    assert_eq!(apcfg::blocked_sta(&state, "00000000000000000000001e"), "");
    // The import does not export the `blocked` flag; the captured `blocked_sta` says
    // which known client has it.
    let client = state["clients"].as_array_mut().unwrap().iter_mut().find(|c| c["mac"] == "02:00:00:00:00:25").unwrap();
    client["blocked"] = serde_json::json!(true);
    let push = last_push(AP_B);
    assert_eq!(apcfg::blocked_sta(&state, "00000000000000000000001e"), push["blocked_sta"].as_str().unwrap());
}

/// The `mgmt_cfg` alone is the full render's, with the key the AP informs with
/// supplied or stored, and settings only `system_cfg` reads cannot stop it.
#[test]
fn mgmt_cfg_alone_matches_the_full_render() {
    let Some(_) = common::fixtures() else { return };
    let controller = common::controller();
    let mut state = state();
    for ap in [AP_B, AP_U] {
        let inform = common::inform(ap);
        let input = apcfg::Input { state: &state, device_mac: ap, inform: Some(&inform), cfgversion: "x", controller: &controller };
        assert_eq!(apcfg::render_mgmt(&input, None).unwrap(), render(&state, ap, "x").rendered.mgmt_cfg, "{ap}");
    }
    // As when adopting: the AP informs with another key than its own, so it is sent its own.
    let factory = "0123456789abcdef0123456789abcdef";
    let mut adopting = state.clone();
    adopting["devices"].as_array_mut().unwrap().iter_mut().find(|d| d["mac"] == AP_B).unwrap()["x_inform_authkey"] = factory.into();
    let expected = render(&adopting, AP_B, "x").rendered.mgmt_cfg;
    assert!(expected.contains("\nauthkey="), "{expected}");
    let inform = common::inform(AP_B);
    let input = apcfg::Input { state: &state, device_mac: AP_B, inform: Some(&inform), cfgversion: "x", controller: &controller };
    assert_eq!(apcfg::render_mgmt(&input, Some(factory)).unwrap(), expected);
    // Without the SSH password hash system_cfg cannot be rendered; mgmt_cfg still can.
    for s in state["setting"].as_array_mut().unwrap().iter_mut().filter(|s| s["key"] == "mgmt") {
        let s = s.as_object_mut().unwrap();
        s.remove("x_ssh_md5passwd");
        s.remove("x_ssh_sha512passwd");
    }
    let input = apcfg::Input { state: &state, device_mac: AP_B, inform: Some(&inform), cfgversion: "x", controller: &controller };
    assert!(apcfg::render(&input).is_err());
    assert_eq!(apcfg::render_mgmt(&input, Some(factory)).unwrap(), expected);
}

#[test]
fn missing_device_is_an_error() {
    let Some(_) = common::fixtures() else { return };
    let state = state();
    let controller = common::controller();
    let input = apcfg::Input { state: &state, device_mac: "02:00:00:00:99:99", inform: None, cfgversion: "x", controller: &controller };
    assert!(apcfg::render(&input).is_err());
}

/// Neither feature is in the captures, so these check the shape of the lines
/// (as the official controller writes them), not a byte-for-byte golden copy.
#[test]
fn speed_limits_shape_each_vap_to_its_wlans_group() {
    let Some(_) = common::fixtures() else { return };
    let mut state = state();
    let unlimited = render(&state, AP_B, "x").rendered.system_cfg;
    assert!(unlimited.contains("qos.status=disabled"));
    let site = state["wlanconf"][0]["site_id"].clone();
    state["usergroup"] = serde_json::json!([
        { "_id": "g-default", "name": "Default", "attr_hidden_id": "Default", "qos_rate_max_down": -1, "qos_rate_max_up": -1, "site_id": site },
        { "_id": "g-slow", "name": "Slow", "qos_rate_max_down": 5000, "qos_rate_max_up": 1000, "site_id": site },
    ]);
    // Only defined: QoS is on (any group limits), but no VAP uses the slow group yet.
    let cfg = render(&state, AP_B, "x").rendered.system_cfg;
    assert!(cfg.contains("qos.status=enabled\nqos.mode=1\n"));
    assert!(cfg.contains("qos.if.1.type=uplink"));
    assert!(!cfg.contains("maxspeed"), "nobody is limited yet");
    for w in state["wlanconf"].as_array_mut().unwrap() {
        w["usergroup_id"] = serde_json::json!("g-slow");
    }
    let cfg = render(&state, AP_B, "x").rendered.system_cfg;
    assert!(cfg.contains("qos.vap.1.dwnlink.maxspeed=5000"), "{cfg}");
    assert!(cfg.contains("qos.vap.1.uplink.1.maxspeed=1000"));
}

#[test]
fn schedules_reach_the_vaps() {
    let Some(_) = common::fixtures() else { return };
    let mut state = state();
    for w in state["wlanconf"].as_array_mut().unwrap() {
        w["schedule_with_duration"] = serde_json::json!([{ "start_days_of_week": ["mon"], "start_hour": 1, "start_minute": 0, "duration_minutes": 300 }]);
    }
    let cfg = render(&state, AP_B, "x").rendered.system_cfg;
    assert!(cfg.contains(".schedule_enabled=enabled"));
    assert!(cfg.contains("syswrapper.sh schedule-action"));
    // The fixture APs report both capabilities: inverted blocks, one key per block.
    assert!(cfg.contains(".schedule_invert=enabled"), "{cfg}");
    assert!(cfg.contains(".schedule_mon.0=0100-0600"));
}
