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
    golden(AP_B);
}

#[test]
fn ap_u_matches_the_last_push() {
    golden(AP_U);
}

/// With nothing changed, the allocation written back equals the stored `config_meta`.
#[test]
fn config_meta_round_trips() {
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
    let mut state = state();
    assert_eq!(apcfg::blocked_sta(&state, "00000000000000000000001e"), "");
    // The import does not export the `blocked` flag; the captured `blocked_sta` says
    // which known client has it.
    let client = state["clients"].as_array_mut().unwrap().iter_mut().find(|c| c["mac"] == "02:00:00:00:00:25").unwrap();
    client["blocked"] = serde_json::json!(true);
    let push = last_push(AP_B);
    assert_eq!(apcfg::blocked_sta(&state, "00000000000000000000001e"), push["blocked_sta"].as_str().unwrap());
}

#[test]
fn missing_device_is_an_error() {
    let state = state();
    let controller = common::controller();
    let input = apcfg::Input { state: &state, device_mac: "02:00:00:00:99:99", inform: None, cfgversion: "x", controller: &controller };
    assert!(apcfg::render(&input).is_err());
}
