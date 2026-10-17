//! Device and client actions, as the official controller performs them:
//!
//! - restart: the AP's next inform is answered `{"_type":"reboot","reboot_type":"soft"}`;
//! - locate: `{"_type":"cmd","cmd":"set-locate"}` (flash the LED) until `unset-locate`;
//! - re-send config ("force provision"): the AP gets its config again with a new version;
//! - reconnect a client: `{"_type":"cmd","cmd":"kick-sta","mac"}` to the AP it is on;
//! - block / unblock: the client's `blocked` flag in the settings (so every AP's
//!   config carries it in `blocked_sta`), plus `block-sta` / `unblock-sta` to every
//!   AP online (one that is away gets the flag with its config when it is back);
//! - lock to an AP: `fixed_ap_enabled` / `fixed_ap_mac` in the client's settings, which
//!   the config generator turns into MAC filters on the other APs.
//!
//! Commands are queued per AP and sent one per inform, before any config push;
//! restart, locate and reconnect need the AP online (it would otherwise run
//! them whenever it is back).
//! All of this needs active mode: in shadow mode apctl never answers the APs,
//! and changing settings there would only diverge from the other controller.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use inform::Mac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};
use crate::engine::{Event, EventKind, Input, Live};
use crate::store;

/// Commands waiting for an AP's next inform.
pub fn queue(live: &mut Live, mac: Mac, cmd: Value) {
    let q = live.commands.entry(mac).or_default();
    // A command undone before it was sent is dropped, and one already waiting
    // (e.g. after a double click) is sent once: toggling does not grow the queue.
    if let Some(undo) = opposite(&cmd) {
        q.retain(|c| *c != undo);
    }
    if !q.contains(&cmd) {
        q.push_back(cmd);
    }
    crate::stun::poke(live, &mac);
}

/// The command that undoes this one, if any.
fn opposite(cmd: &Value) -> Option<Value> {
    let undo = match cmd["cmd"].as_str()? {
        "set-locate" => "unset-locate",
        "unset-locate" => "set-locate",
        "block-sta" => "unblock-sta",
        "unblock-sta" => "block-sta",
        _ => return None,
    };
    let mut o = cmd.clone();
    o["cmd"] = json!(undo);
    Some(o)
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
pub fn edit_client(state: &mut Value, mac: &str, fields: &[(&str, Value)]) {
    let site = crate::settings::site_id(state).map(str::to_string);
    let list = crate::settings::array_mut(state, "clients");
    // Matched as `controls` reads them, whichever way the entry writes its MAC.
    let parsed = mac.parse::<Mac>().ok();
    let entry = match list.iter().position(|c| parsed.map_or_else(|| same_mac(c, mac), |m| entry_mac(c) == Some(m))) {
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
}

fn same_mac(c: &Value, mac: &str) -> bool {
    c["mac"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(mac))
}

/// A client's `blocked`, `locked_to` and own speed limit (`usergroup_id`) from
/// the settings, as its view shows them.
#[derive(Debug, Serialize, PartialEq)]
pub struct Controls<'a> {
    pub blocked: bool,
    pub locked_to: Option<String>,
    pub usergroup_id: Option<&'a Value>,
}

impl<'a> Controls<'a> {
    fn of(entry: Option<&'a Value>) -> Self {
        let locked_to = entry.filter(|c| c["fixed_ap_enabled"].as_bool() == Some(true)).and_then(|c| c["fixed_ap_mac"].as_str());
        Controls {
            blocked: entry.and_then(|c| c["blocked"].as_bool()).unwrap_or(false),
            locked_to: locked_to.map(str::to_ascii_lowercase),
            usergroup_id: entry.map(|c| &c["usergroup_id"]),
        }
    }
}

/// One client's controls. For many clients, `ClientControls` looks each one
/// up without scanning the settings' client list every time.
pub fn controls<'a>(state: Option<&'a Value>, mac: &Mac) -> Controls<'a> {
    Controls::of(state.and_then(|s| s["clients"].as_array()).and_then(|l| l.iter().find(|c| entry_mac(c) == Some(*mac))))
}

fn entry_mac(c: &Value) -> Option<Mac> {
    c["mac"].as_str()?.parse().ok()
}

/// The settings' client entries by MAC, built once for a list of clients.
pub struct ClientControls<'a>(HashMap<Mac, &'a Value>);

impl<'a> ClientControls<'a> {
    pub fn new(state: Option<&'a Value>) -> Self {
        let list = state.and_then(|s| s["clients"].as_array()).map(Vec::as_slice).unwrap_or_default();
        let mut map = HashMap::with_capacity(list.len());
        for c in list {
            // The first entry for a MAC wins, as with a scan of the list.
            if let Some(m) = entry_mac(c) {
                map.entry(m).or_insert(c);
            }
        }
        ClientControls(map)
    }

    /// `controls` for one client.
    pub fn get(&self, mac: &Mac) -> Controls<'a> {
        Controls::of(self.0.get(mac).copied())
    }
}

/// The AP a device action is for: active mode, and an AP apctl has heard from.
fn target_ap(s: &AppState, mac: &str) -> Result<Mac, ApiError> {
    crate::api::require_active(s, "this needs")?;
    let mac = crate::api::parse_mac(mac)?;
    known_ap(s, &mac)?;
    Ok(mac)
}

fn known_ap(s: &AppState, mac: &Mac) -> Result<(), ApiError> {
    if s.live.read().unwrap().devices.contains_key(mac) {
        Ok(())
    } else {
        Err(ApiError(StatusCode::NOT_FOUND, "unknown AP (or it hasn't reported since apctl started)".into()))
    }
}

/// Whether an AP is online: a command queued for one that is away would run
/// whenever it is back (a restart days later).
fn is_online(live: &Live, mac: &Mac) -> bool {
    live.devices.get(mac).is_some_and(|d| d.online)
}

fn offline() -> ApiError {
    ApiError(StatusCode::CONFLICT, "the AP is offline".into())
}

/// POST /api/devices/{mac}/restart
pub async fn restart(State(s): State<AppState>, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    let mac = target_ap(&s, &mac)?;
    {
        let mut live = s.live.write().unwrap();
        if !is_online(&live, &mac) {
            return Err(offline());
        }
        queue(&mut live, mac, json!({ "_type": "reboot", "reboot_type": "soft" }));
    }
    s.note(Event::device(store::now_ts(), EventKind::ApRestartRequested, mac, json!({}))).await;
    Ok(Json(json!({ "queued": true })))
}

#[derive(Deserialize)]
pub struct LocateBody {
    on: bool,
}

/// POST /api/devices/{mac}/locate {on}
pub async fn locate(State(s): State<AppState>, Path(mac): Path<String>, Json(b): Json<LocateBody>) -> Result<Json<Value>, ApiError> {
    let mac = target_ap(&s, &mac)?;
    let mut live = s.live.write().unwrap();
    // Turning it off can wait for an AP that is away: it is harmless when it comes.
    if b.on && !is_online(&live, &mac) {
        return Err(offline());
    }
    queue(&mut live, mac, json!({ "_type": "cmd", "cmd": if b.on { "set-locate" } else { "unset-locate" } }));
    if b.on {
        live.locating.insert(mac);
    } else {
        live.locating.remove(&mac);
    }
    Ok(Json(json!({ "locating": b.on })))
}

/// POST /api/devices/{mac}/provision: send the AP its config again.
pub async fn provision(State(s): State<AppState>, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    let mac = target_ap(&s, &mac)?;
    s.live.write().unwrap().reprovision.insert(mac);
    s.note(Event::device(store::now_ts(), EventKind::ApProvisionRequested, mac, json!({}))).await;
    Ok(Json(json!({ "queued": true })))
}

/// POST /api/clients/{mac}/kick: disconnect the client so it reconnects.
pub async fn kick(State(s): State<AppState>, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    let client = crate::api::parse_mac(&mac)?;
    let ap = {
        let mut live = s.live.write().unwrap();
        let ap = live
            .clients
            .get(&client)
            .filter(|c| c.connected)
            .map(|c| c.sample.ap_mac)
            .ok_or_else(|| ApiError(StatusCode::CONFLICT, "the client is not connected".into()))?;
        if !is_online(&live, &ap) {
            return Err(ApiError(StatusCode::CONFLICT, "the client's AP is offline".into()));
        }
        queue(&mut live, ap, json!({ "_type": "cmd", "cmd": "kick-sta", "mac": client.to_string() }));
        ap
    };
    s.note(Event::client(store::now_ts(), EventKind::ClientReconnectRequested, client, json!({ "ap": ap }))).await;
    Ok(Json(json!({ "queued": true, "ap": ap })))
}

#[derive(Deserialize)]
pub struct BlockBody {
    blocked: bool,
}

/// POST /api/clients/{mac}/block {blocked}
pub async fn block(State(s): State<AppState>, Path(mac): Path<String>, Json(b): Json<BlockBody>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    let client = crate::api::parse_mac(&mac)?;
    let m = client.to_string();
    let blocked = b.blocked;
    let what = if blocked { format!("blocked client {m}") } else { format!("unblocked client {m}") };
    edit_settings(&s, what, move |state| {
        edit_client(state, &m, &[("blocked", json!(blocked))]);
        Ok(())
    })
    .await?;
    {
        let mut live = s.live.write().unwrap();
        let aps: Vec<Mac> = live.devices.iter().filter(|(_, d)| d.online).map(|(m, _)| *m).collect();
        for ap in aps {
            queue(&mut live, ap, json!({ "_type": "cmd", "cmd": if blocked { "block-sta" } else { "unblock-sta" }, "mac": client.to_string() }));
        }
    }
    let kind = if blocked { EventKind::ClientBlocked } else { EventKind::ClientUnblocked };
    s.note(Event::client(store::now_ts(), kind, client, json!({}))).await;
    Ok(Json(json!({ "blocked": blocked })))
}

#[derive(Deserialize)]
pub struct LockBody {
    /// The AP to lock the client to; null unlocks.
    ap: Option<String>,
}

/// POST /api/clients/{mac}/lock {ap}
pub async fn lock(State(s): State<AppState>, Path(mac): Path<String>, Json(b): Json<LockBody>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    let client = crate::api::parse_mac(&mac)?;
    let ap = match &b.ap {
        Some(a) => {
            let a = crate::api::parse_mac(a)?;
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
    edit_settings(&s, what, move |state| {
        edit_client(state, &m, &fields);
        Ok(())
    })
    .await?;
    Ok(Json(json!({ "locked_to": ap })))
}

/// Applies a change to the settings through the engine (which stores it and
/// records it in the config history); the next informs push the new config.
pub async fn edit_settings(s: &AppState, what: String, edit: impl FnOnce(&mut Value) -> Result<(), String> + Send + 'static) -> Result<(), ApiError> {
    apply_edit(s, Box::new(move |state| edit(state).map(|()| what))).await.map(|_| ())
}

/// `edit_settings` for an edit that itself says what it changed (worked out
/// on the settings as the engine has them); returns that.
pub async fn apply_edit(s: &AppState, edit: crate::engine::StateEdit) -> Result<String, ApiError> {
    crate::api::current_state(s)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    s.ask(Input::EditState { ts: store::now_ts(), edit, done: tx }, rx).await?.map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))
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
    fn toggling_does_not_grow_the_queue() {
        let mut live = Live::default();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let cmd = |c: &str, mac: Option<&str>| {
            let mut v = json!({ "_type": "cmd", "cmd": c });
            if let Some(m) = mac {
                v["mac"] = json!(m);
            }
            v
        };
        for _ in 0..10 {
            for c in ["set-locate", "unset-locate"] {
                queue(&mut live, ap, cmd(c, None));
            }
            for c in ["block-sta", "unblock-sta"] {
                queue(&mut live, ap, cmd(c, Some("aa:bb:cc:00:00:01")));
            }
            queue(&mut live, ap, cmd("block-sta", Some("aa:bb:cc:00:00:02")));
            queue(&mut live, ap, cmd("kick-sta", Some("aa:bb:cc:00:00:03")));
        }
        let cmds: Vec<String> = std::iter::from_fn(|| next(&mut live, &ap)).map(|c| format!("{} {}", c["cmd"].as_str().unwrap(), c["mac"].as_str().unwrap_or(""))).collect();
        assert_eq!(cmds, ["block-sta aa:bb:cc:00:00:02", "kick-sta aa:bb:cc:00:00:03", "unset-locate ", "unblock-sta aa:bb:cc:00:00:01"]);
    }

    #[test]
    fn client_settings_are_edited_or_created() {
        let mut state = json!({ "devices": [{ "mac": "02:00:00:00:00:01", "site_id": "s1" }], "clients": [{ "mac": "AA:BB:CC:00:00:01", "name": "tv" }] });
        edit_client(&mut state, "aa:bb:cc:00:00:01", &[("blocked", json!(true))]);
        assert_eq!(state["clients"][0]["blocked"], true);
        assert_eq!(state["clients"][0]["name"], "tv", "other fields kept");
        edit_client(&mut state, "aa:bb:cc:00:00:02", &[("fixed_ap_enabled", json!(true)), ("fixed_ap_mac", json!("02:00:00:00:00:01"))]);
        assert_eq!(state["clients"][1]["site_id"], "s1");
        assert_eq!(apcfg::blocked_sta(&state, "s1"), "aa:bb:cc:00:00:01");

        let mac = |s: &str| s.parse::<Mac>().unwrap();
        let c = controls(Some(&state), &mac("AA:BB:CC:00:00:02"));
        assert_eq!((c.blocked, c.locked_to.as_deref()), (false, Some("02:00:00:00:00:01")));
        assert_eq!(serde_json::to_value(controls(Some(&state), &mac("aa:bb:cc:00:00:01"))).unwrap(), json!({ "blocked": true, "locked_to": null, "usergroup_id": null }));
        let all = ClientControls::new(Some(&state));
        for m in ["aa:bb:cc:00:00:01", "AA:BB:CC:00:00:02", "aa:bb:cc:00:00:03"] {
            assert_eq!(controls(Some(&state), &mac(m)), all.get(&mac(m)), "{m}");
        }
        // An entry that writes its MAC another way is the one edited, as the one shown.
        let mut state = json!({ "clients": [{ "mac": "AA-BB-CC-00-00-04" }, { "mac": "aabbcc000005" }] });
        edit_client(&mut state, "aa:bb:cc:00:00:04", &[("blocked", json!(true))]);
        edit_client(&mut state, "aa:bb:cc:00:00:05", &[("blocked", json!(true))]);
        assert_eq!(state["clients"].as_array().unwrap().len(), 2, "no duplicate");
        assert!(controls(Some(&state), &mac("aa:bb:cc:00:00:04")).blocked && controls(Some(&state), &mac("aa:bb:cc:00:00:05")).blocked);
    }
}
