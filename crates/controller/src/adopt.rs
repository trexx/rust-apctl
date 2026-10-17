//! Adopting and forgetting APs (active mode).
//!
//! As the official controller does it:
//!
//! - An AP apctl doesn't manage informs with the well-known factory key. It is
//!   answered 404 and listed as pending (also an AP apctl knows that was reset
//!   and uses the factory key again: "adoption required").
//! - Adopt creates the AP's record in the settings with a fresh per-AP key.
//!   Its next inform (still with the factory key) gets a `setparam` with only
//!   `mgmt_cfg`, which carries `authkey=<new key>`; from then on it informs with
//!   its own key and gets its full config like any other AP.
//! - An AP that informs elsewhere can be adopted over SSH: `syswrapper.sh
//!   set-adopt <inform url> <key>` points it here with its key (see `ssh`).
//! - Forget removes the AP from the settings. An AP still reporting gets
//!   `{"_type":"setdefault"}` with its next inform and resets itself.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use inform::Mac;
use serde::Serialize;
use serde_json::{Value, json};
use wire::keys::KeyStore;

use crate::api::{ApiError, AppState};
use crate::engine::{Event, EventKind, Input, Live};
use crate::model::Ts;
use crate::clock;

/// How long an AP has to come back with its new key.
pub const ADOPT_TIMEOUT: Ts = 300;
/// How long a forgotten AP has to report once more (and reset itself).
pub const FORGET_TIMEOUT: Ts = 90;
/// At most this many pending APs are listed (the official controller's default).
const MAX_PENDING: usize = 100;
/// At most this many of them from one address (an IPv6 /64): anyone can send
/// informs with the factory key, under any MAC.
const MAX_PENDING_PER_SOURCE: usize = 4;
/// A pending AP not heard from for this long is no longer listed.
const PENDING_TIMEOUT: Ts = 600;
/// The longest string kept of a pending AP's inform (its model, hostname...).
const MAX_PENDING_TEXT: usize = 64;

/// An AP waiting to be adopted.
#[derive(Clone, Debug, Serialize)]
pub struct Pending {
    pub mac: Mac,
    pub ip: Option<String>,
    pub model: Option<String>,
    pub model_display: Option<String>,
    pub version: Option<String>,
    pub hostname: Option<String>,
    pub serial: Option<String>,
    /// apctl had this AP before: it was reset (or lost its key).
    pub known: bool,
    pub first_seen: Ts,
    pub last_seen: Ts,
    /// Where its informs come from (see `source_of`).
    #[serde(skip)]
    pub source: IpAddr,
    /// Its last inform, to build its record from.
    #[serde(skip)]
    pub payload: Arc<Value>,
}

/// The APs apctl is adopting or forgetting, and the pending ones.
#[derive(Default, Debug)]
pub struct Adoption {
    pub pending: BTreeMap<Mac, Pending>,
    /// Adopt pressed at: the AP should come back with its own key.
    pub adopting: HashMap<Mac, Ts>,
    /// Forget pressed at: the AP gets `setdefault` with its next inform.
    pub forgetting: HashMap<Mac, Ts>,
}

/// Whether a record's `mac` is this one (`aa:bb:..`, any case), without
/// making a string for each record compared.
fn is_mac(v: &Value, mac: &Mac) -> bool {
    v.as_str().is_some_and(|s| s.len() == 17 && s.as_bytes()[2] == b':' && s.parse::<Mac>().is_ok_and(|m| m == *mac))
}

/// The AP's record in the settings.
pub fn device_doc<'a>(state: &'a Value, mac: &Mac) -> Option<&'a Value> {
    state["devices"].as_array()?.iter().find(|d| is_mac(&d["mac"], mac))
}

/// The AP's record in the settings, to change it.
pub fn device_doc_mut<'a>(state: &'a mut Value, mac: &Mac) -> Option<&'a mut Value> {
    state["devices"].as_array_mut()?.iter_mut().find(|d| is_mac(&d["mac"], mac))
}

fn parse_key<const N: usize>(hex_key: &str) -> Option<[u8; N]> {
    let b = hex::decode(hex_key).ok()?;
    b.try_into().ok()
}

/// The key an AP apctl manages informs with: its record's `x_authkey`, else
/// the key file (keys exported from the other controller). `None` when apctl
/// doesn't manage it; before any settings are imported, the key file decides.
pub fn device_key(state: Option<&Value>, keys: &KeyStore, mac: &Mac) -> Option<[u8; 16]> {
    match state {
        Some(state) => {
            let d = device_doc(state, mac)?;
            d["x_authkey"].as_str().and_then(parse_key).or_else(|| keys.get(mac).copied())
        }
        None => keys.get(mac).copied(),
    }
}

/// Every syslog key known, the settings' before the key file's (an AP
/// encrypts with its record's `syslog_key`, which apctl makes at adoption).
pub fn syslog_keys(state: Option<&Value>, keys: &KeyStore) -> Vec<(Mac, [u8; 32])> {
    let devices = state.and_then(|s| s["devices"].as_array()).into_iter().flatten();
    let stored = devices.filter_map(|d| Some((d["mac"].as_str()?.parse().ok()?, parse_key(d["syslog_key"].as_str()?)?)));
    stored.chain(keys.syslog_keys().map(|(m, k)| (*m, *k))).collect()
}

/// What adoption reads of a pending AP's inform (`new_device`, `radio_table`,
/// the listing): kept instead of the whole inform, which anyone can send.
/// Only short strings, numbers and flags.
pub fn pending_inform(payload: &Value) -> Value {
    let small = |v: &Value| match v {
        Value::String(s) => Some(Value::String(s[..s.floor_char_boundary(MAX_PENDING_TEXT)].to_string())),
        Value::Number(_) | Value::Bool(_) => Some(v.clone()),
        _ => None,
    };
    let pick = |v: &Value, keys: &[&str]| Value::Object(keys.iter().filter_map(|&k| Some((k.to_string(), small(v.get(k)?)?))).collect());
    let mut out = pick(payload, &["mac", "model", "model_display", "version", "serial", "ip", "hostname"]);
    if let Some(radios) = payload["radio_table"].as_array() {
        out["radio_table"] = radios.iter().take(8).map(|r| pick(r, &RADIO_KEYS)).collect();
    }
    out
}

/// The address pending APs are counted by: an IPv6 sender may use any
/// address of its /64.
fn source_of(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
        v4 => v4,
    }
}

/// Records an inform from an AP waiting for adoption (see `pending_inform`),
/// sent from `source`; true the first time. A new AP makes room, if needed,
/// by dropping the one heard from longest ago: of its source's, else of all.
pub fn note_pending(live: &mut Live, payload: Value, known: bool, now: Ts, source: IpAddr) -> bool {
    let Some(mac) = payload["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else { return false };
    let s = |k: &str| payload[k].as_str().map(str::to_string);
    let source = source_of(source);
    let pending = &mut live.adoption.pending;
    let new = !pending.contains_key(&mac);
    if new {
        let stalest = |of_source: bool| pending.values().filter(|p| !of_source || p.source == source).min_by_key(|p| p.last_seen).map(|p| p.mac);
        let full = if pending.values().filter(|p| p.source == source).count() >= MAX_PENDING_PER_SOURCE {
            stalest(true)
        } else if pending.len() >= MAX_PENDING {
            stalest(false)
        } else {
            None
        };
        if let Some(m) = full {
            pending.remove(&m);
        }
    }
    let first_seen = pending.get(&mac).map_or(now, |p| p.first_seen);
    pending.insert(
        mac,
        Pending {
            mac,
            ip: s("ip"),
            model: s("model"),
            model_display: s("model_display"),
            version: s("version"),
            hostname: s("hostname"),
            serial: s("serial"),
            known,
            first_seen,
            last_seen: now,
            source,
            payload: Arc::new(payload),
        },
    );
    new
}

/// Forgets pending APs not heard from for a while, and adoptions that timed
/// out. Forgets that timed out are finished by [`spawn`].
pub fn expire(live: &mut Live, now: Ts) {
    live.adoption.pending.retain(|_, p| now - p.last_seen < PENDING_TIMEOUT);
    live.adoption.adopting.retain(|_, t| now - *t < ADOPT_TIMEOUT);
}

/// What `radio_table` reads of each radio in an inform's `radio_table`.
const RADIO_KEYS: [&str; 14] = [
    "name", "radio", "radio_caps", "radio_caps2", "has_dfs", "has_fccdfs", "has_ht160", "is_11ac", "is_11ax", "nss", "min_txpower", "max_txpower", "builtin_antenna",
    "builtin_ant_gain",
];

/// The radio settings of a new AP, from the radios its inform lists: auto
/// channel, the site's default width, auto power.
pub fn radio_table(state: &Value, payload: &Value) -> Vec<Value> {
    let width = |band: &str| {
        crate::settings::setting(state, "radio_ai")["radios_configuration"]
            .as_array()
            .and_then(|l| l.iter().find(|c| c["radio"].as_str() == Some(band))?["channel_width"].as_i64())
            .unwrap_or(if band == "ng" { 20 } else { 80 })
    };
    payload["radio_table"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let band = r["radio"].as_str()?;
            let mut v = json!({
                "name": r["name"], "radio": band, "channel": "auto", "ht": width(band), "tx_power_mode": "auto",
                "min_rssi_enabled": false, "hard_noise_floor_enabled": false, "antenna_gain": r["builtin_ant_gain"],
            });
            // The rest of what it reports, as it reports it.
            for k in RADIO_KEYS.iter().filter(|k| !matches!(**k, "name" | "radio")) {
                if !r[k].is_null() {
                    v[k] = r[k].clone();
                }
            }
            Some(v)
        })
        .collect()
}

/// A new AP's record (but for its `site_id`): its details from its inform, a
/// fresh key (32 hex characters) and syslog key (64), a cfgversion, and its radios.
pub fn new_device(state: &Value, payload: &Value, mac: &Mac) -> Value {
    let other = &state["devices"][0];
    let mut d = json!({
        "mac": mac.to_string(), "adopted": true, "type": "uap", "x_authkey": crate::random_hex(16), "syslog_key": crate::random_hex(32),
        "cfgversion": crate::random_hex(8), "config_network": { "type": "dhcp" }, "adopted_at": clock::now_ts(),
        "radio_table": radio_table(state, payload),
    });
    for k in ["model", "version", "serial", "ip"] {
        if !payload[k].is_null() {
            d[k] = payload[k].clone();
        }
    }
    if let Some(n) = payload["hostname"].as_str() {
        d["name"] = json!(n);
    }
    // The management network and WLAN groups of the other APs.
    for k in ["mgmt_network_id", "wlangroup_id_ng", "wlangroup_id_na"] {
        if !other[k].is_null() {
            d[k] = other[k].clone();
        }
    }
    d
}

/// Adds a pending AP to the settings, from its inform. An AP apctl knew
/// keeps its record, with new keys: the adoption hands the AP its key sealed
/// with the public factory key, so whoever saw that would otherwise read what
/// was sent to the AP under the old one (its Wi-Fi passwords).
pub fn adopt_device(state: &mut Value, mac: &Mac, payload: &Value) -> Result<String, String> {
    if let Some(d) = device_doc_mut(state, mac) {
        d["x_authkey"] = json!(crate::random_hex(16));
        d["syslog_key"] = json!(crate::random_hex(32));
        // The key it informed with, which is not this one any more.
        if let Some(o) = d.as_object_mut() {
            o.remove("x_inform_authkey");
        }
        let name = d["name"].as_str().map_or_else(|| mac.to_string(), |n| format!("{n} ({mac})"));
        return Ok(format!("re-adopting AP {name} with new keys"));
    }
    let d = new_device(state, payload, mac);
    crate::settings::push_doc(state, "devices", d);
    Ok(format!("adopted AP {} ({mac})", payload["hostname"].as_str().or(payload["model"].as_str()).unwrap_or("new")))
}

/// Removes an AP from the settings and everything that names it.
pub fn remove_device(state: &mut Value, mac: &Mac) -> Result<String, String> {
    let same = |v: &Value| v.as_str().is_some_and(|m| m.parse::<Mac>().ok() == Some(*mac));
    let devices = state["devices"].as_array_mut().ok_or("the settings have no APs")?;
    let before = devices.len();
    let name = devices.iter().find(|d| same(&d["mac"])).and_then(|d| d["name"].as_str()).map_or_else(|| mac.to_string(), |n| format!("{n} ({mac})"));
    devices.retain(|d| !same(&d["mac"]));
    if devices.len() == before {
        return Err("this AP is not in the settings".into());
    }
    if let Some(m) = state["config_meta"].as_array_mut() {
        m.retain(|d| !same(&d["mac"]));
    }
    for g in state["apgroup"].as_array_mut().into_iter().flatten() {
        if let Some(l) = g["device_macs"].as_array_mut() {
            l.retain(|m| !same(m));
        }
    }
    for w in state["wlanconf"].as_array_mut().into_iter().flatten() {
        if let Some(l) = w["broadcasting_aps"].as_array_mut() {
            l.retain(|m| !same(m));
        }
        // An mDNS rule left with no AP applies nowhere, as it did; the editor
        // asks for its APs when the SSID is edited next.
        for r in w["mdns_proxy_custom"].as_array_mut().into_iter().flatten() {
            if let Some(l) = r.get_mut("ap_macs").and_then(Value::as_array_mut) {
                l.retain(|m| !same(m));
            }
        }
    }
    for c in state["clients"].as_array_mut().into_iter().flatten() {
        if same(&c["fixed_ap_mac"]) {
            c["fixed_ap_enabled"] = json!(false);
        }
    }
    for s in state["setting"].as_array_mut().into_iter().flatten() {
        if let Some(l) = s["exclude_devices"].as_array_mut() {
            l.retain(|m| !same(m));
        }
    }
    Ok(format!("forgot AP {name}"))
}

/// Finishes forgets of APs that didn't report again in time (active mode).
pub fn spawn(s: AppState) {
    if !s.active {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let now = clock::now_ts();
            // Taken out of `forgetting` here, so an inform arriving meanwhile
            // doesn't finish the same forget a second time.
            let overdue: Vec<Mac> = {
                let mut live = s.live.write().unwrap();
                expire(&mut live, now);
                let overdue: Vec<Mac> = live.adoption.forgetting.iter().filter(|(_, t)| now - **t >= FORGET_TIMEOUT).map(|(m, _)| *m).collect();
                for m in &overdue {
                    live.adoption.forgetting.remove(m);
                }
                overdue
            };
            for mac in overdue {
                tracing::info!("{mac}: forgotten without reporting again");
                finish_forget(&s.engine, mac, false).await;
            }
        }
    });
}

// ---- API ------------------------------------------------------------------

/// GET /api/devices/pending
pub async fn pending(State(s): State<AppState>) -> Json<Value> {
    // Before taking the lock below: it reads the settings too.
    let ssh = crate::ssh::available(&s);
    let now = clock::now_ts();
    // What `expire` would drop is left out (it runs every ten seconds), and
    // the lists are serialised after the lock is released.
    let (pending, adopting, forgetting) = {
        let live = s.live.read().unwrap();
        let a = &live.adoption;
        let pending: Vec<Pending> = a.pending.values().filter(|p| now - p.last_seen < PENDING_TIMEOUT).cloned().collect();
        let adopting: Vec<(Mac, Ts)> = a.adopting.iter().filter(|(_, t)| now - **t < ADOPT_TIMEOUT).map(|(m, t)| (*m, *t)).collect();
        let forgetting: Vec<(Mac, Ts)> = a.forgetting.iter().map(|(m, t)| (*m, *t)).collect();
        (pending, adopting, forgetting)
    };
    let since = |l: Vec<(Mac, Ts)>| l.into_iter().map(|(m, t)| json!({ "mac": m, "since": t })).collect::<Vec<_>>();
    Json(json!({ "active": s.active, "pending": pending, "adopting": since(adopting), "forgetting": since(forgetting), "ssh": ssh }))
}

/// POST /api/devices/{mac}/adopt: adopt a pending AP.
pub async fn adopt(State(s): State<AppState>, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "adoption needs")?;
    let mac = crate::api::parse_mac(&mac)?;
    let payload = s.live.read().unwrap().adoption.pending.get(&mac).map(|p| p.payload.clone()).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "this AP is not waiting for adoption".into()))?;
    let inform = payload.clone();
    crate::actions::apply_edit(&s, Box::new(move |state: &mut Value| adopt_device(state, &mac, &inform))).await?;
    {
        let mut live = s.live.write().unwrap();
        live.adoption.adopting.insert(mac, clock::now_ts());
        live.adoption.pending.remove(&mac);
    }
    s.note(Event::device(clock::now_ts(), EventKind::ApAdopting, mac, json!({ "model": payload["model"], "ip": payload["ip"] }))).await;
    Ok(Json(json!({ "adopting": true })))
}

/// POST /api/devices/{mac}/forget: remove an AP; if it reports again it resets itself.
pub async fn forget(State(s): State<AppState>, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "adoption needs")?;
    let mac = crate::api::parse_mac(&mac)?;
    let online = {
        let live = s.live.read().unwrap();
        if live.state.as_deref().and_then(|st| device_doc(st, &mac)).is_none() {
            return Err(ApiError(StatusCode::NOT_FOUND, "this AP is not in the settings".into()));
        }
        live.devices.get(&mac).is_some_and(|d| d.online)
    };
    if online {
        // Removed when it reports (and is told to reset), or after the timeout.
        s.live.write().unwrap().adoption.forgetting.insert(mac, clock::now_ts());
        crate::stun::poke(&s.live.read().unwrap(), &mac);
        return Ok(Json(json!({ "forgetting": true })));
    }
    finish_forget(&s.engine, mac, false).await;
    Ok(Json(json!({ "forgotten": true })))
}

/// Removes a forgotten AP from the settings and apctl's records.
pub async fn finish_forget(engine: &tokio::sync::mpsc::Sender<Input>, mac: Mac, reset: bool) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let edit: crate::engine::StateEdit = Box::new(move |state: &mut Value| remove_device(state, &mac));
    let _ = engine.send(Input::EditState { ts: clock::now_ts(), edit, done: tx }).await;
    let _ = rx.await;
    let _ = engine.send(Input::Forget { ts: clock::now_ts(), mac }).await;
    let _ = engine.send(Input::Note(Event::device(clock::now_ts(), EventKind::ApForgotten, mac, json!({ "reset": reset })))).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Value {
        json!({
            "devices": [{ "mac": "02:00:00:00:00:01", "site_id": "s1", "x_authkey": "000102030405060708090a0b0c0d0e0f", "mgmt_network_id": "n1" }],
            "setting": [{ "key": "radio_ai", "site_id": "s1", "radios_configuration": [{ "radio": "na", "channel_width": 40 }] }],
            "apgroup": [{ "_id": "g1", "for_wlanconf": true, "device_macs": ["02:00:00:00:00:01", "02:00:00:00:00:02"] }],
            "wlanconf": [{ "name": "Home", "broadcasting_aps": ["02:00:00:00:00:01"] }],
            "clients": [{ "mac": "aa:bb:cc:00:00:01", "fixed_ap_enabled": true, "fixed_ap_mac": "02:00:00:00:00:01" }],
            "config_meta": [{ "mac": "02:00:00:00:00:01" }],
        })
    }

    fn inform() -> Value {
        json!({
            "mac": "02:00:00:00:00:09", "model": "U6M", "version": "8.8.11", "ip": "192.0.2.9", "hostname": "U6-Mesh", "default": true,
            "radio_table": [
                { "name": "wifi0", "radio": "ng", "nss": 2, "max_txpower": 22, "min_txpower": 6, "radio_caps": 16404, "builtin_ant_gain": 3 },
                { "name": "wifi1", "radio": "na", "nss": 4, "has_ht160": true, "is_11ax": true, "builtin_ant_gain": 5 },
            ],
        })
    }

    #[test]
    fn keys_come_from_the_settings_then_the_key_file() {
        let s = state();
        let keys = KeyStore::default();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        assert_eq!(device_key(Some(&s), &keys, &ap), Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]));
        assert_eq!(device_key(Some(&s), &keys, &"02:00:00:00:00:09".parse().unwrap()), None, "not in the settings: not ours");
        let mut file = KeyStore::default();
        file.insert("02:00:00:00:00:09", "ffffffffffffffffffffffffffffffff").unwrap();
        assert!(device_key(Some(&s), &file, &"02:00:00:00:00:09".parse().unwrap()).is_none(), "a key alone does not make an AP ours");
        assert!(device_key(None, &file, &"02:00:00:00:00:09".parse().unwrap()).is_some(), "before an import, the key file decides");
    }

    #[test]
    fn adopting_creates_a_record_with_a_new_key_and_radios() {
        let mut s = state();
        adopt_device(&mut s, &"02:00:00:00:00:09".parse().unwrap(), &inform()).unwrap();
        let d = device_doc(&s, &"02:00:00:00:00:09".parse().unwrap()).unwrap().clone();
        assert_eq!(d["x_authkey"].as_str().unwrap().len(), 32);
        assert_ne!(d["x_authkey"], s["devices"][0]["x_authkey"]);
        assert_eq!(d["syslog_key"].as_str().unwrap().len(), 64);
        assert_eq!((d["site_id"].as_str(), d["mgmt_network_id"].as_str(), d["name"].as_str()), (Some("s1"), Some("n1"), Some("U6-Mesh")));
        assert_eq!(d["radio_table"][1]["ht"], 40, "the site's default width");
        assert_eq!((d["radio_table"][0]["channel"].as_str(), d["radio_table"][1]["has_ht160"].as_bool()), (Some("auto"), Some(true)));
        // Adopting again keeps the record, with new keys (the old one went out under the factory key).
        let mac: Mac = "02:00:00:00:00:09".parse().unwrap();
        device_doc_mut(&mut s, &mac).unwrap()["x_inform_authkey"] = d["x_authkey"].clone();
        adopt_device(&mut s, &mac, &inform()).unwrap();
        assert_eq!(s["devices"].as_array().unwrap().len(), 2);
        let again = device_doc(&s, &mac).unwrap();
        assert_eq!((again["name"].as_str(), again["x_authkey"].as_str().unwrap().len()), (Some("U6-Mesh"), 32));
        assert!(again["x_authkey"] != d["x_authkey"] && again["syslog_key"] != d["syslog_key"]);
        assert!(again.get("x_inform_authkey").is_none(), "the AP has yet to inform with it");
    }

    #[test]
    fn forgetting_removes_every_mention() {
        let mut s = state();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        s["devices"][0]["name"] = json!("Hall");
        s["wlanconf"][0]["mdns_proxy_custom"] = json!([{ "ap_scope_mode": "specific", "ap_macs": ["02:00:00:00:00:01", "02:00:00:00:00:02"] }, { "ap_scope_mode": "all" }]);
        assert_eq!(remove_device(&mut s, &ap).unwrap(), "forgot AP Hall (02:00:00:00:00:01)");
        assert!(s["devices"].as_array().unwrap().is_empty());
        assert_eq!(s["apgroup"][0]["device_macs"], json!(["02:00:00:00:00:02"]));
        assert_eq!(s["wlanconf"][0]["broadcasting_aps"], json!([]));
        assert_eq!(s["wlanconf"][0]["mdns_proxy_custom"][0]["ap_macs"], json!(["02:00:00:00:00:02"]));
        assert!(s["wlanconf"][0]["mdns_proxy_custom"][1].get("ap_macs").is_none());
        assert_eq!(s["clients"][0]["fixed_ap_enabled"], false);
        assert!(s["config_meta"].as_array().unwrap().is_empty());
        assert!(remove_device(&mut s, &ap).is_err());
        assert!(device_doc_mut(&mut state(), &ap).is_some());
        assert_eq!(remove_device(&mut state(), &ap).unwrap(), "forgot AP 02:00:00:00:00:01", "no name: the MAC");
    }

    #[test]
    fn pending_aps_are_listed_and_expire() {
        let mut live = Live::default();
        let mut big = inform();
        big["sys_stats"] = json!({ "loadavg_1": "0.1" });
        big["radio_table"][0]["scan_table"] = json!([{ "bssid": "x" }]);
        assert!(note_pending(&mut live, pending_inform(&big), false, 100, SRC));
        assert!(!note_pending(&mut live, pending_inform(&big), false, 110, SRC), "only new the first time");
        let p = &live.adoption.pending[&"02:00:00:00:00:09".parse().unwrap()];
        assert_eq!((p.first_seen, p.last_seen, p.model.as_deref()), (100, 110, Some("U6M")));
        // Only what adoption reads is kept, and a record built from it is the same.
        assert!(p.payload.get("sys_stats").is_none() && p.payload["radio_table"][0].get("scan_table").is_none());
        let mac = "02:00:00:00:00:09".parse().unwrap();
        let (mut a, mut b) = (new_device(&state(), &p.payload, &mac), new_device(&state(), &inform(), &mac));
        for d in [&mut a, &mut b] {
            for k in ["x_authkey", "syslog_key", "cfgversion", "adopted_at"] {
                d[k] = Value::Null;
            }
        }
        assert_eq!(a, b);
        expire(&mut live, 110 + 600);
        assert!(live.adoption.pending.is_empty());
    }

    const SRC: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9));

    #[test]
    fn only_short_values_of_a_pending_inform_are_kept() {
        let mut big = inform();
        big["model"] = json!("é".repeat(100));
        big["hostname"] = json!({ "nested": "x".repeat(1000) });
        big["serial"] = json!(["a", "b"]);
        big["radio_table"][0]["name"] = json!(vec![0; 1000]);
        let p = pending_inform(&big);
        assert_eq!(p["model"].as_str().unwrap(), "é".repeat(32), "cut at 64 bytes, between characters");
        assert!(p.get("hostname").is_none() && p.get("serial").is_none() && p["radio_table"][0].get("name").is_none());
        assert_eq!((p["radio_table"][1]["has_ht160"].as_bool(), p["radio_table"][0]["nss"].as_i64()), (Some(true), Some(2)));
    }

    #[test]
    fn one_address_cannot_fill_the_pending_list() {
        let mut live = Live::default();
        let ap = |n: usize| {
            let mut p = inform();
            p["mac"] = json!(format!("02:00:00:00:{:02x}:{:02x}", n / 256, n % 256));
            pending_inform(&p)
        };
        let v6 = |last: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last));
        // Each address of a /64 counts as the same sender: it keeps its latest few.
        for n in 0..10 {
            assert!(note_pending(&mut live, ap(n), false, n as Ts, v6(n as u16)));
        }
        let macs: Vec<String> = live.adoption.pending.keys().map(Mac::to_string).collect();
        assert_eq!(macs, ["02:00:00:00:00:06", "02:00:00:00:00:07", "02:00:00:00:00:08", "02:00:00:00:00:09"]);
        // A full list makes room by dropping the one heard from longest ago.
        let mut live = Live::default();
        for n in 0..MAX_PENDING {
            note_pending(&mut live, ap(n), false, 1000 + n as Ts, IpAddr::V4(std::net::Ipv4Addr::from(n as u32)));
        }
        assert!(note_pending(&mut live, ap(MAX_PENDING), false, 5000, SRC));
        assert_eq!(live.adoption.pending.len(), MAX_PENDING);
        assert!(!live.adoption.pending.contains_key(&"02:00:00:00:00:00".parse().unwrap()));
    }
}
