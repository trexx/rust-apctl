//! Shared fixtures for the capture-based tests.
//!
//! The expected configs are real pushes from the official controller, sanitised by
//! `informdump sanitize`. A few differences between our output and the captures are
//! artefacts of that sanitising, not of rendering; `normalise` removes exactly those, and
//! every rule there says why it is needed.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use apcfg::{Controller, Input, Output};
use serde_json::{Value, json};

/// The capture fixtures (sanitised real captures, kept outside the repository), a JSON
/// file of them, and their manifest. Tests that need them skip without them.
#[allow(unused_imports)]
pub use wire::capture::sample::{EXPECTED_PUSHES, check_expectation, fixtures, load, manifest};

pub const AP_B: &str = "02:00:00:00:00:01";
pub const AP_U: &str = "02:00:00:00:00:02";

/// The AP's captured inform, read the first time a test asks for it.
pub fn inform(mac: &str) -> &'static Value {
    static B: OnceLock<Value> = OnceLock::new();
    static U: OnceLock<Value> = OnceLock::new();
    match mac {
        AP_B => B.get_or_init(|| load("2026-10-12T184427.182Z_000001_020000000001_inform.json")),
        _ => U.get_or_init(|| load("2026-10-12T184434.812Z_000003_020000000002_inform.json")),
    }
}

pub fn controller() -> Controller {
    Controller {
        host: "unifi.example.net".into(),
        version: "10.6.106".into(),
        // Not part of the settings snapshot (the official controller keeps it in its
        // system.properties); this is the sanitised value from the captures.
        reporter_uuid: "00000000-0000-4000-8000-000000000004".into(),
        ..Default::default()
    }
}

/// Clients pinned to AP B ("lock to AP"). The fixture snapshot predates the import
/// keeping the `user` fields `fixed_ap_enabled`/`fixed_ap_mac` (acf5fe0), but every push
/// to AP U denies exactly these ten MACs as `lock2ap`, and no push to AP B does, so they
/// are locked to B.
const LOCKED_TO_B: [&str; 10] = ["11", "0e", "10", "13", "22", "12", "0f", "21", "14", "15"];

/// `controller-state.json` plus the lock-to-AP flags it is missing: a copy of it, read
/// the first time a test asks for it, for the test to change.
pub fn state() -> Value {
    static STATE: OnceLock<Value> = OnceLock::new();
    STATE
        .get_or_init(|| {
            let mut state = load("controller-state.json");
            for client in state["clients"].as_array_mut().unwrap() {
                let mac = client["mac"].as_str().unwrap().to_string();
                if LOCKED_TO_B.iter().any(|m| mac == format!("02:00:00:00:00:{m}")) {
                    client["fixed_ap_enabled"] = json!(true);
                    client["fixed_ap_mac"] = json!(AP_B);
                }
            }
            state
        })
        .clone()
}

pub fn render(state: &Value, mac: &str, cfgversion: &str) -> Output {
    let controller = controller();
    let input = Input { state, device_mac: mac, inform: Some(inform(mac)), cfgversion, controller: &controller };
    apcfg::render_with_meta(&input).unwrap_or_else(|e| panic!("render {mac}: {e:#}"))
}

/// Stores a render's `config_meta` in the state, as a controller would after pushing.
pub fn store_meta(state: &mut Value, mac: &str, meta: Value) {
    let metas = state["config_meta"].as_array_mut().unwrap();
    metas.retain(|m| m["mac"] != mac);
    metas.push(meta);
}

/// Sanitiser artefacts: (key, value we render, value in the capture, reason).
const SANITISED: &[(&str, &str, &str, &str)] = &[
    ("users.2.name", "nobody", "secret-4", "every users.N.name is masked as a secret"),
    ("users.2.password", "x", "secret-5", "every *password* value is masked as a secret"),
    (
        "mesh.essid",
        "secret-16",
        "ssid-9",
        "the same mesh ESSID became a secret-N in the state (x_ prefix) but an ssid-N in the config (essid key)",
    ),
    (
        "resolv.host.1.name",
        "GarageAP",
        "name-1",
        "the hostname, learned from the inform, is replaced inside config values; the device name in the state is kept",
    ),
    ("resolv.host.1.name", "UpstairsAP", "name-11", "as above, for AP U"),
];

fn line_kv(line: &str) -> (&str, &str) {
    line.split_once('=').unwrap_or((line, ""))
}

/// Puts the values of the given line indices into sorted order, keeping the positions.
fn sort_values(lines: &mut [String], idx: &[usize]) {
    let mut vals: Vec<String> = idx.iter().map(|&i| line_kv(&lines[i]).1.to_string()).collect();
    vals.sort();
    for (&i, v) in idx.iter().zip(vals) {
        let key = line_kv(&lines[i]).0.to_string();
        lines[i] = format!("{key}={v}");
    }
}

/// Lines with the documented differences removed:
/// * our values for sanitised keys are replaced by the capture's fakes (`SANITISED`);
/// * MAC lists the official controller writes in Java `HashSet` order
///   (`wireless.N.bcfilt.K.mac`, and the `lock2ap` entries of `macacl.K`) are sorted:
///   that order depends on the real MACs' hash codes, which the fake MACs do not keep.
///   (We do write `HashSet` order; the channel `blklst` proves it on unsanitised values.)
pub fn normalise(cfg: &str, ours: bool) -> Vec<String> {
    let mut lines: Vec<String> = cfg.lines().map(str::to_string).collect();
    if ours {
        for line in &mut lines {
            let (k, v) = line_kv(line);
            if let Some((_, _, fake, _)) = SANITISED.iter().find(|(sk, ov, _, _)| *sk == k && *ov == v) {
                *line = format!("{k}={fake}");
            }
        }
    }
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let all: HashSet<&str> = lines.iter().map(String::as_str).collect();
    for (i, line) in lines.iter().enumerate() {
        let key = line_kv(line).0;
        let parts: Vec<&str> = key.split('.').collect();
        if let ["wireless", n, "bcfilt", _, "mac"] = parts[..] {
            groups.entry(format!("bcfilt {n}")).or_default().push(i);
        }
        if let ["macacl", k, "acl", j, "mac"] = parts[..] {
            let type_key = format!("macacl.{k}.acl.{j}.type=lock2ap");
            if all.contains(type_key.as_str()) {
                groups.entry(format!("macacl {k}")).or_default().push(i);
            }
        }
    }
    for idx in groups.values() {
        sort_values(&mut lines, idx);
    }
    lines
}

/// Asserts that our render matches the captured push up to `normalise`, with a readable
/// diff on failure. Returns (identical raw lines, total captured lines).
pub fn assert_matches(what: &str, ours: &str, captured: &str) -> (usize, usize) {
    let raw_ours: Vec<&str> = ours.lines().collect();
    let raw_cap: Vec<&str> = captured.lines().collect();
    let identical = raw_ours.iter().zip(&raw_cap).filter(|(a, b)| a == b).count();
    let (a, b) = (normalise(ours, true), normalise(captured, false));
    if a != b {
        let mut report = String::new();
        let n = a.len().max(b.len());
        for i in 0..n {
            let (x, y) = (a.get(i).map_or("<none>", String::as_str), b.get(i).map_or("<none>", String::as_str));
            if x != y {
                report.push_str(&format!("line {}: ours `{x}` / captured `{y}`\n", i + 1));
            }
        }
        panic!("{what}: {} vs {} lines, differences:\n{report}", a.len(), b.len());
    }
    assert!(ours.ends_with('\n'), "{what}: trailing newline");
    (identical, raw_cap.len())
}

/// The keys `SANITISED` covers, for checking no stale allow-list entry hides a change.
pub fn sanitised_keys() -> Vec<&'static str> {
    SANITISED.iter().map(|(k, ..)| *k).collect()
}
