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
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use inform::Mac;
use serde::Serialize;
use serde_json::{Value, json};
use wire::keys::KeyStore;

use crate::api::{ApiError, AppState};
use crate::engine::{Event, Input, Live};
use crate::model::Ts;
use crate::settings::random_hex;
use crate::store;

/// How long an AP has to come back with its new key.
pub const ADOPT_TIMEOUT: Ts = 300;
/// How long a forgotten AP has to report once more (and reset itself).
pub const FORGET_TIMEOUT: Ts = 90;
/// At most this many pending APs are listed (the official controller's default).
const MAX_PENDING: usize = 100;

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
pub fn pending_inform(payload: &Value) -> Value {
    let pick = |v: &Value, keys: &[&str]| Value::Object(keys.iter().filter_map(|&k| Some((k.to_string(), v.get(k).filter(|x| !x.is_null())?.clone()))).collect());
    let mut out = pick(payload, &["mac", "model", "model_display", "version", "serial", "ip", "hostname"]);
    if let Some(radios) = payload["radio_table"].as_array() {
        out["radio_table"] = radios.iter().take(8).map(|r| pick(r, &RADIO_KEYS)).collect();
    }
    out
}

/// Records an inform from an AP waiting for adoption (see `pending_inform`);
/// true the first time.
pub fn note_pending(live: &mut Live, payload: Value, known: bool, now: Ts) -> bool {
    let Some(mac) = payload["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else { return false };
    let s = |k: &str| payload[k].as_str().map(str::to_string);
    let new = !live.adoption.pending.contains_key(&mac);
    if new && live.adoption.pending.len() >= MAX_PENDING {
        return false;
    }
    let first_seen = live.adoption.pending.get(&mac).map_or(now, |p| p.first_seen);
    live.adoption.pending.insert(
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
            payload: Arc::new(payload),
        },
    );
    new
}

/// Forgets pending APs not heard from for a while, and adoptions or forgets that timed out.
pub fn expire(live: &mut Live, now: Ts) {
    live.adoption.pending.retain(|_, p| now - p.last_seen < 600);
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
            for k in &RADIO_KEYS[2..] {
                if !r[k].is_null() {
                    v[k] = r[k].clone();
                }
            }
            Some(v)
        })
        .collect()
}

/// A new AP's record: its details from its inform, a fresh key (32 hex
/// characters) and syslog key (64), a cfgversion, and its radios.
pub fn new_device(state: &Value, payload: &Value, mac: &Mac) -> Value {
    let site = crate::settings::site_id(state);
    let other = state["devices"].as_array().and_then(|d| d.first()).cloned().unwrap_or(Value::Null);
    let mut d = json!({
        "mac": mac.to_string(), "adopted": true, "type": "uap", "x_authkey": random_hex(16), "syslog_key": random_hex(32),
        "cfgversion": random_hex(8), "config_network": { "type": "dhcp" }, "adopted_at": store::now_ts(),
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
    if let Some(s) = site {
        d["site_id"] = json!(s);
    }
    // The management network and WLAN groups of the other APs.
    for k in ["mgmt_network_id", "wlangroup_id_ng", "wlangroup_id_na"] {
        if !other[k].is_null() {
            d[k] = other[k].clone();
        }
    }
    d
}

/// Adds a pending AP to the settings, from its inform (or, for an AP apctl
/// knew, keeps its record).
pub fn adopt_device(state: &mut Value, mac: &Mac, payload: &Value) -> Result<String, String> {
    if device_doc(state, mac).is_some() {
        return Ok(format!("re-adopting {mac}"));
    }
    let d = new_device(state, payload, mac);
    crate::settings::array_mut(state, "devices").push(d);
    Ok(format!("adopted AP {} ({mac})", payload["hostname"].as_str().or(payload["model"].as_str()).unwrap_or("new")))
}

/// Removes an AP from the settings and everything that names it.
pub fn remove_device(state: &mut Value, mac: &Mac) -> Result<String, String> {
    let mac = mac.to_string();
    let same = |v: &Value| v.as_str().is_some_and(|m| m.eq_ignore_ascii_case(&mac));
    let devices = state["devices"].as_array_mut().ok_or("the settings have no APs")?;
    let before = devices.len();
    let name = devices.iter().find(|d| same(&d["mac"])).and_then(|d| d["name"].as_str().map(str::to_string)).unwrap_or_else(|| mac.clone());
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
            let now = store::now_ts();
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
    let mut live = s.live.write().unwrap();
    expire(&mut live, store::now_ts());
    let adopting: Vec<Value> = live.adoption.adopting.iter().map(|(m, t)| json!({ "mac": m, "since": t })).collect();
    let forgetting: Vec<Value> = live.adoption.forgetting.iter().map(|(m, t)| json!({ "mac": m, "since": t })).collect();
    Json(json!({
        "active": s.active, "pending": live.adoption.pending.values().collect::<Vec<_>>(), "adopting": adopting, "forgetting": forgetting,
        "ssh": ssh,
    }))
}

/// POST /api/devices/{mac}/adopt: adopt a pending AP.
pub async fn adopt(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    crate::api::require_active(&s, "adoption needs")?;
    let mac = crate::api::parse_mac(&mac)?;
    let payload = s.live.read().unwrap().adoption.pending.get(&mac).map(|p| p.payload.clone()).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "this AP is not waiting for adoption".into()))?;
    let inform = payload.clone();
    crate::actions::edit_settings(&s, format!("adopting {mac}"), move |state| adopt_device(state, &mac, &inform).map(|_| ())).await?;
    {
        let mut live = s.live.write().unwrap();
        live.adoption.adopting.insert(mac, store::now_ts());
        live.adoption.pending.remove(&mac);
    }
    let _ = s.engine.send(Input::Note(Event::device(store::now_ts(), "ap_adopting", mac, json!({ "model": payload["model"], "ip": payload["ip"] })))).await;
    Ok(Json(json!({ "adopting": true })))
}

/// POST /api/devices/{mac}/forget: remove an AP; if it reports again it resets itself.
pub async fn forget(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
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
        s.live.write().unwrap().adoption.forgetting.insert(mac, store::now_ts());
        crate::stun::poke(&s.live.read().unwrap(), &mac);
        return Ok(Json(json!({ "forgetting": true })));
    }
    finish_forget(&s.engine, mac, false).await;
    Ok(Json(json!({ "forgotten": true })))
}

/// Removes a forgotten AP from the settings and apctl's records.
pub async fn finish_forget(engine: &tokio::sync::mpsc::Sender<Input>, mac: Mac, reset: bool) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let edit: crate::engine::StateEdit = Box::new(move |state: &mut Value| remove_device(state, &mac).map(|_| ()));
    let _ = engine.send(Input::EditState { ts: store::now_ts(), what: format!("forgot AP {mac}"), edit, done: tx }).await;
    let _ = rx.await;
    let _ = engine.send(Input::Forget { ts: store::now_ts(), mac }).await;
    let _ = engine.send(Input::Note(Event::device(store::now_ts(), "ap_forgotten", mac, json!({ "reset": reset })))).await;
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
        // Adopting again keeps the record (and key).
        adopt_device(&mut s, &"02:00:00:00:00:09".parse().unwrap(), &inform()).unwrap();
        assert_eq!(s["devices"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn forgetting_removes_every_mention() {
        let mut s = state();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        remove_device(&mut s, &ap).unwrap();
        assert!(s["devices"].as_array().unwrap().is_empty());
        assert_eq!(s["apgroup"][0]["device_macs"], json!(["02:00:00:00:00:02"]));
        assert_eq!(s["wlanconf"][0]["broadcasting_aps"], json!([]));
        assert_eq!(s["clients"][0]["fixed_ap_enabled"], false);
        assert!(s["config_meta"].as_array().unwrap().is_empty());
        assert!(remove_device(&mut s, &ap).is_err());
        assert!(device_doc_mut(&mut state(), &ap).is_some());
    }

    #[test]
    fn pending_aps_are_listed_and_expire() {
        let mut live = Live::default();
        let mut big = inform();
        big["sys_stats"] = json!({ "loadavg_1": "0.1" });
        big["radio_table"][0]["scan_table"] = json!([{ "bssid": "x" }]);
        assert!(note_pending(&mut live, pending_inform(&big), false, 100));
        assert!(!note_pending(&mut live, pending_inform(&big), false, 110), "only new the first time");
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
}
