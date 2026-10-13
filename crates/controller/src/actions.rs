//! Device and client actions, as the official controller performs them:
//!
//! - restart: the AP's next inform is answered `{"_type":"reboot","reboot_type":"soft"}`;
//! - locate: `{"_type":"cmd","cmd":"set-locate"}` (flash the LED) until `unset-locate`;
//! - re-send config ("force provision"): the AP gets its config again with a new version;
//! - reconnect a client: `{"_type":"cmd","cmd":"kick-sta","mac"}` to the AP it is on;
//! - block / unblock: the client's `blocked` flag in the settings (so every AP's
//!   config carries it in `blocked_sta`), plus `block-sta` / `unblock-sta` to every AP;
//! - lock to an AP: `fixed_ap_enabled` / `fixed_ap_mac` in the client's settings, which
//!   the config generator turns into MAC filters on the other APs.
//!
//! Commands are queued per AP and sent one per inform, before any config push.
//! All of this needs active mode: in shadow mode apctl never answers the APs,
//! and changing settings there would only diverge from the other controller.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use inform::Mac;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};
use crate::engine::{Input, Live};
use crate::store;

/// Commands waiting for an AP's next inform.
pub fn queue(live: &mut Live, mac: Mac, cmd: Value) {
    let q = live.commands.entry(mac).or_default();
    // The same command twice in a row (e.g. a double click) is sent once.
    if q.back() != Some(&cmd) {
        q.push_back(cmd);
    }
}

/// The next queued command for an AP, if any.
pub fn next(live: &mut Live, mac: &Mac) -> Option<Value> {
    let q = live.commands.get_mut(mac)?;
    let cmd = q.pop_front();
    if q.is_empty() {
        live.commands.remove(mac);
    }
    cmd
}

/// Sets fields on a client's entry in the settings, creating it if needed.
pub fn edit_client(state: &mut Value, mac: &str, fields: &[(&str, Value)]) -> Result<(), String> {
    let site = state["devices"].as_array().and_then(|d| d.iter().find_map(|d| d["site_id"].as_str().map(str::to_string)));
    if !state["clients"].is_array() {
        state["clients"] = json!([]);
    }
    let list = state["clients"].as_array_mut().ok_or("settings have no client list")?;
    let entry = match list.iter().position(|c| same_mac(c, mac)) {
        Some(i) => &mut list[i],
        None => {
            let mut c = json!({ "mac": mac });
            if let Some(s) = site {
                c["site_id"] = json!(s);
            }
            list.push(c);
            list.last_mut().expect("just pushed")
        }
    };
    for (k, v) in fields {
        entry[*k] = v.clone();
    }
    Ok(())
}

fn same_mac(c: &Value, mac: &str) -> bool {
    c["mac"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(mac))
}

/// Adds a client's `blocked`, `locked_to` and own speed limit (`usergroup_id`)
/// from the settings to its view.
pub fn add_controls(v: &mut Value, state: Option<&Value>, mac: &str) {
    let entry = state.and_then(|s| s["clients"].as_array()).and_then(|l| l.iter().find(|c| same_mac(c, mac)));
    let blocked = entry.and_then(|c| c["blocked"].as_bool()).unwrap_or(false);
    let locked_to = entry.filter(|c| c["fixed_ap_enabled"].as_bool() == Some(true)).and_then(|c| c["fixed_ap_mac"].as_str());
    v["blocked"] = json!(blocked);
    v["locked_to"] = json!(locked_to.map(str::to_ascii_lowercase));
    v["usergroup_id"] = entry.map_or(Value::Null, |c| c["usergroup_id"].clone());
}

fn require_active(s: &AppState) -> Result<(), ApiError> {
    if s.active {
        Ok(())
    } else {
        Err(ApiError(StatusCode::CONFLICT, "this needs active mode: in shadow mode apctl never talks to the APs".into()))
    }
}

fn parse(mac: &str) -> Result<Mac, ApiError> {
    mac.parse().map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid MAC address".into()))
}

fn known_ap(s: &AppState, mac: &Mac) -> Result<(), ApiError> {
    if s.live.read().unwrap().devices.contains_key(mac) {
        Ok(())
    } else {
        Err(ApiError(StatusCode::NOT_FOUND, "unknown AP (or it hasn't reported since apctl started)".into()))
    }
}

async fn note(s: &AppState, kind: &'static str, mac: Mac, data: Value) {
    let _ = s.engine.send(Input::Note { ts: store::now_ts(), kind, mac, data }).await;
}

/// POST /api/devices/{mac}/restart
pub async fn restart(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    require_active(&s)?;
    let mac = parse(&mac)?;
    known_ap(&s, &mac)?;
    queue(&mut s.live.write().unwrap(), mac, json!({ "_type": "reboot", "reboot_type": "soft" }));
    note(&s, "ap_restart_requested", mac, json!({})).await;
    Ok(Json(json!({ "queued": true })))
}

#[derive(Deserialize)]
pub struct LocateBody {
    on: bool,
}

/// POST /api/devices/{mac}/locate {on}
pub async fn locate(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>, Json(b): Json<LocateBody>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    require_active(&s)?;
    let mac = parse(&mac)?;
    known_ap(&s, &mac)?;
    let mut live = s.live.write().unwrap();
    queue(&mut live, mac, json!({ "_type": "cmd", "cmd": if b.on { "set-locate" } else { "unset-locate" } }));
    if b.on {
        live.locating.insert(mac);
    } else {
        live.locating.remove(&mac);
    }
    Ok(Json(json!({ "locating": b.on })))
}

/// POST /api/devices/{mac}/provision: send the AP its config again.
pub async fn provision(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    require_active(&s)?;
    let mac = parse(&mac)?;
    known_ap(&s, &mac)?;
    s.live.write().unwrap().reprovision.insert(mac);
    note(&s, "ap_provision_requested", mac, json!({})).await;
    Ok(Json(json!({ "queued": true })))
}

/// POST /api/clients/{mac}/kick: disconnect the client so it reconnects.
pub async fn kick(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    require_active(&s)?;
    let client = parse(&mac)?;
    let ap = {
        let mut live = s.live.write().unwrap();
        let ap = live
            .clients
            .get(&client)
            .filter(|c| c.connected)
            .map(|c| c.sample.ap_mac)
            .ok_or_else(|| ApiError(StatusCode::CONFLICT, "the client is not connected".into()))?;
        queue(&mut live, ap, json!({ "_type": "cmd", "cmd": "kick-sta", "mac": client.to_string() }));
        ap
    };
    let _ = s.engine.send(Input::ClientNote { ts: store::now_ts(), kind: "client_reconnect_requested", client, data: json!({ "ap": ap }) }).await;
    Ok(Json(json!({ "queued": true, "ap": ap })))
}

#[derive(Deserialize)]
pub struct BlockBody {
    blocked: bool,
}

/// POST /api/clients/{mac}/block {blocked}
pub async fn block(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>, Json(b): Json<BlockBody>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    require_active(&s)?;
    let client = parse(&mac)?;
    let m = client.to_string();
    let blocked = b.blocked;
    let what = if blocked { format!("blocked client {m}") } else { format!("unblocked client {m}") };
    edit_settings(&s, what, move |state| edit_client(state, &m, &[("blocked", json!(blocked))])).await?;
    {
        let mut live = s.live.write().unwrap();
        let aps: Vec<Mac> = live.devices.keys().copied().collect();
        for ap in aps {
            queue(&mut live, ap, json!({ "_type": "cmd", "cmd": if blocked { "block-sta" } else { "unblock-sta" }, "mac": client.to_string() }));
        }
    }
    let kind = if blocked { "client_blocked" } else { "client_unblocked" };
    let _ = s.engine.send(Input::ClientNote { ts: store::now_ts(), kind, client, data: json!({}) }).await;
    Ok(Json(json!({ "blocked": blocked })))
}

#[derive(Deserialize)]
pub struct LockBody {
    /// The AP to lock the client to; null unlocks.
    ap: Option<String>,
}

/// POST /api/clients/{mac}/lock {ap}
pub async fn lock(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>, Json(b): Json<LockBody>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    require_active(&s)?;
    let client = parse(&mac)?;
    let ap = match &b.ap {
        Some(a) => {
            let a = parse(a)?;
            known_ap(&s, &a)?;
            Some(a.to_string())
        }
        None => None,
    };
    let m = client.to_string();
    let what = match &ap {
        Some(a) => format!("locked client {m} to AP {a}"),
        None => format!("unlocked client {m}"),
    };
    let fields = vec![("fixed_ap_enabled", json!(ap.is_some())), ("fixed_ap_mac", ap.clone().map_or(Value::Null, Value::String))];
    edit_settings(&s, what, move |state| edit_client(state, &m, &fields)).await?;
    Ok(Json(json!({ "locked_to": ap })))
}

/// Applies a change to the settings through the engine (which stores it and
/// records it in the config history); the next informs push the new config.
pub async fn edit_settings(s: &AppState, what: String, edit: impl FnOnce(&mut Value) -> Result<(), String> + Send + 'static) -> Result<(), ApiError> {
    if s.live.read().unwrap().state.is_none() {
        return Err(ApiError(StatusCode::CONFLICT, "no settings imported yet".into()));
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    s.engine
        .send(Input::EditState { ts: store::now_ts(), what, edit: Box::new(edit), done: tx })
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "engine stopped".into()))?;
    rx.await.map_err(|_| ApiError::internal("engine stopped"))?.map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_queue_in_order_without_double_clicks() {
        let mut live = Live::default();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        queue(&mut live, ap, json!({ "_type": "cmd", "cmd": "set-locate" }));
        queue(&mut live, ap, json!({ "_type": "cmd", "cmd": "set-locate" }));
        queue(&mut live, ap, json!({ "_type": "reboot", "reboot_type": "soft" }));
        assert_eq!(next(&mut live, &ap).unwrap()["cmd"], "set-locate");
        assert_eq!(next(&mut live, &ap).unwrap()["_type"], "reboot");
        assert!(next(&mut live, &ap).is_none());
        assert!(live.commands.is_empty());
    }

    #[test]
    fn client_settings_are_edited_or_created() {
        let mut state = json!({ "devices": [{ "mac": "02:00:00:00:00:01", "site_id": "s1" }], "clients": [{ "mac": "AA:BB:CC:00:00:01", "name": "tv" }] });
        edit_client(&mut state, "aa:bb:cc:00:00:01", &[("blocked", json!(true))]).unwrap();
        assert_eq!(state["clients"][0]["blocked"], true);
        assert_eq!(state["clients"][0]["name"], "tv", "other fields kept");
        edit_client(&mut state, "aa:bb:cc:00:00:02", &[("fixed_ap_enabled", json!(true)), ("fixed_ap_mac", json!("02:00:00:00:00:01"))]).unwrap();
        assert_eq!(state["clients"][1]["site_id"], "s1");
        assert_eq!(apcfg::blocked_sta(&state, "s1"), "aa:bb:cc:00:00:01");

        let mut v = json!({});
        add_controls(&mut v, Some(&state), "AA:BB:CC:00:00:02");
        assert_eq!((v["blocked"].as_bool(), v["locked_to"].as_str()), (Some(false), Some("02:00:00:00:00:01")));
    }
}
