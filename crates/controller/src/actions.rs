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

use axum::extract::State;
use inform::Mac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState, Json, MacPath};
use crate::clock;
use crate::engine::{Event, EventKind, Input, Live};
use crate::settings::doc_mac;

/// Commands waiting for an AP's next inform.
pub fn queue(live: &mut Live, mac: Mac, cmd: Value) {
    let q = live.commands.entry(mac).or_default();
    // A command undone before it was sent is dropped, and one already waiting
    // (e.g. after a double click) is sent once: toggling does not grow the queue.
    if let Some(undo) = opposite(&cmd) {
        q.retain(|c| *c != undo);
    }
    // A client's newer speed limit replaces one still waiting.
    if cmd["cmd"] == "rate-update" {
        q.retain(|c| c["cmd"] != "rate-update" || c["mac"] != cmd["mac"]);
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

/// Sets fields on a client's entry in the site's settings, creating it (with
/// the MAC as `aa:bb:..`) if needed. Clearing (every field null or false) a
/// client with no entry creates none: it reads as cleared already.
pub fn edit_client(state: &mut Value, mac: Mac, fields: &[(&str, Value)]) {
    // Matched as `controls` reads them, whichever way the entry writes its MAC.
    let found = crate::settings::docs(state, "clients").position(|c| doc_mac(&c["mac"]) == Some(mac));
    let entry = match found {
        Some(i) => crate::settings::docs_mut(state, "clients").nth(i).expect("found above"),
        None if fields.iter().all(|(_, v)| v.is_null() || *v == Value::Bool(false)) => return,
        None => crate::settings::push_doc(state, "clients", json!({ "mac": mac.to_string() })),
    };
    for (k, v) in fields {
        entry[*k] = v.clone();
    }
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
        let locked_to = entry.filter(|c| c["fixed_ap_enabled"].as_bool() == Some(true)).and_then(|c| doc_mac(&c["fixed_ap_mac"]));
        Controls {
            blocked: entry.and_then(|c| c["blocked"].as_bool()).unwrap_or(false),
            locked_to: locked_to.map(|m| m.to_string()),
            usergroup_id: entry.map(|c| &c["usergroup_id"]),
        }
    }
}

/// One client's controls, from the site's entry. For many clients,
/// `ClientControls` looks each one up without scanning the settings' client
/// list every time.
pub fn controls<'a>(state: Option<&'a Value>, mac: &Mac) -> Controls<'a> {
    Controls::of(state.and_then(|s| crate::settings::docs(s, "clients").find(|c| doc_mac(&c["mac"]) == Some(*mac))))
}

/// The settings' client entries by MAC, built once for a list of clients.
pub struct ClientControls<'a>(HashMap<Mac, &'a Value>);

impl<'a> ClientControls<'a> {
    pub fn new(state: Option<&'a Value>) -> Self {
        let mut map = HashMap::new();
        for c in state.into_iter().flat_map(|s| crate::settings::docs(s, "clients")) {
            // The first entry for a MAC wins, as with a scan of the list.
            if let Some(m) = doc_mac(&c["mac"]) {
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

/// Whether a device action can be done: active mode, and an AP apctl has heard from.
fn target_ap(s: &AppState, mac: &Mac) -> Result<(), ApiError> {
    crate::api::require_active(s, "this needs")?;
    known_ap(s, mac)
}

fn known_ap(s: &AppState, mac: &Mac) -> Result<(), ApiError> {
    if s.live.read().unwrap().devices.contains_key(mac) {
        Ok(())
    } else {
        Err(ApiError::not_found("unknown AP (or it hasn't reported since apctl started)"))
    }
}

/// Whether an AP is online: a command queued for one that is away would run
/// whenever it is back (a restart days later).
fn is_online(live: &Live, mac: &Mac) -> bool {
    live.devices.get(mac).is_some_and(|d| d.online)
}

/// POST /api/devices/{mac}/restart
pub async fn restart(State(s): State<AppState>, MacPath(mac): MacPath) -> Result<Json<Value>, ApiError> {
    target_ap(&s, &mac)?;
    {
        let mut live = s.live.write().unwrap();
        if !is_online(&live, &mac) {
            return Err(ApiError::ap_offline());
        }
        queue(&mut live, mac, json!({ "_type": "reboot", "reboot_type": "soft" }));
    }
    s.note(Event::device(clock::now_ts(), EventKind::ApRestartRequested, mac, json!({}))).await;
    Ok(Json(json!({ "queued": true })))
}

#[derive(Deserialize)]
pub struct LocateBody {
    on: bool,
}

/// POST /api/devices/{mac}/locate {on}
pub async fn locate(State(s): State<AppState>, MacPath(mac): MacPath, Json(b): Json<LocateBody>) -> Result<Json<Value>, ApiError> {
    target_ap(&s, &mac)?;
    let mut live = s.live.write().unwrap();
    // Turning it off can wait for an AP that is away: it is harmless when it comes.
    if b.on && !is_online(&live, &mac) {
        return Err(ApiError::ap_offline());
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
pub async fn provision(State(s): State<AppState>, MacPath(mac): MacPath) -> Result<Json<Value>, ApiError> {
    target_ap(&s, &mac)?;
    {
        let mut live = s.live.write().unwrap();
        live.reprovision.insert(mac);
        // As for a queued command: the AP is asked to inform now.
        crate::stun::poke(&live, &mac);
    }
    s.note(Event::device(clock::now_ts(), EventKind::ApProvisionRequested, mac, json!({}))).await;
    Ok(Json(json!({ "queued": true })))
}

/// POST /api/clients/{mac}/kick: disconnect the client so it reconnects.
pub async fn kick(State(s): State<AppState>, MacPath(client): MacPath) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    let ap = {
        let mut live = s.live.write().unwrap();
        let ap = live
            .clients
            .get(&client)
            .filter(|c| c.connected)
            .map(|c| c.sample.ap_mac)
            .ok_or_else(|| ApiError::conflict("the client is not connected"))?;
        if !is_online(&live, &ap) {
            return Err(ApiError::conflict("the client's AP is offline"));
        }
        queue(&mut live, ap, json!({ "_type": "cmd", "cmd": "kick-sta", "mac": client.to_string() }));
        ap
    };
    s.note(Event::client(clock::now_ts(), EventKind::ClientReconnectRequested, client, json!({ "ap": ap }))).await;
    Ok(Json(json!({ "queued": true, "ap": ap })))
}

#[derive(Deserialize)]
pub struct BlockBody {
    blocked: bool,
}

/// POST /api/clients/{mac}/block {blocked}
pub async fn block(State(s): State<AppState>, MacPath(client): MacPath, Json(b): Json<BlockBody>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    let blocked = b.blocked;
    let what = if blocked { format!("blocked client {client}") } else { format!("unblocked client {client}") };
    edit_settings(&s, what, move |state| {
        edit_client(state, client, &[("blocked", json!(blocked))]);
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
    s.note(Event::client(clock::now_ts(), kind, client, json!({}))).await;
    Ok(Json(json!({ "blocked": blocked })))
}

#[derive(Deserialize)]
pub struct LockBody {
    /// The AP to lock the client to; null unlocks.
    ap: Option<String>,
}

/// POST /api/clients/{mac}/lock {ap}
pub async fn lock(State(s): State<AppState>, MacPath(client): MacPath, Json(b): Json<LockBody>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    let ap = match &b.ap {
        Some(a) => {
            let a = crate::api::parse_mac(a)?;
            known_ap(&s, &a)?;
            Some(a.to_string())
        }
        None => None,
    };
    let what = match &ap {
        Some(a) => format!("locked client {client} to AP {a}"),
        None => format!("unlocked client {client}"),
    };
    let fields = vec![("fixed_ap_enabled", json!(ap.is_some())), ("fixed_ap_mac", ap.clone().map_or(Value::Null, Value::String))];
    edit_settings(&s, what, move |state| {
        edit_client(state, client, &fields);
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
    s.ask(Input::EditState { ts: clock::now_ts(), edit, done: tx }, rx).await?.map_err(ApiError::bad)
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
    fn a_newer_speed_limit_replaces_one_still_waiting() {
        let mut live = Live::default();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let limit = |client: &str, down: i64| json!({ "_type": "cmd", "cmd": "rate-update", "mac": client, "dl_max": down, "dl_min": 64, "ul_max": -1, "ul_min": 64 });
        queue(&mut live, ap, limit("aa:bb:cc:00:00:01", 2000));
        queue(&mut live, ap, limit("aa:bb:cc:00:00:02", 1000));
        queue(&mut live, ap, limit("aa:bb:cc:00:00:01", -1));
        let cmds: Vec<(String, i64)> = std::iter::from_fn(|| next(&mut live, &ap)).map(|c| (c["mac"].as_str().unwrap().to_string(), c["dl_max"].as_i64().unwrap())).collect();
        assert_eq!(cmds, [("aa:bb:cc:00:00:02".to_string(), 1000), ("aa:bb:cc:00:00:01".to_string(), -1)], "one command per client, the latest");
    }

    #[test]
    fn client_settings_are_edited_or_created() {
        let mut state = json!({ "devices": [{ "mac": "02:00:00:00:00:01", "site_id": "s1" }], "clients": [{ "mac": "AA:BB:CC:00:00:01", "name": "tv" }] });
        let mac = |s: &str| s.parse::<Mac>().unwrap();
        edit_client(&mut state, mac("aa:bb:cc:00:00:01"), &[("blocked", json!(true))]);
        assert_eq!(state["clients"][0]["blocked"], true);
        assert_eq!(state["clients"][0]["name"], "tv", "other fields kept");
        edit_client(&mut state, mac("AA-BB-CC-00-00-02"), &[("fixed_ap_enabled", json!(true)), ("fixed_ap_mac", json!("02:00:00:00:00:01"))]);
        assert_eq!((state["clients"][1]["site_id"].as_str(), state["clients"][1]["mac"].as_str()), (Some("s1"), Some("aa:bb:cc:00:00:02")), "a new entry's MAC is canonical");
        assert_eq!(apcfg::blocked_sta(&state, "s1"), "aa:bb:cc:00:00:01");
        let c = controls(Some(&state), &mac("AA:BB:CC:00:00:02"));
        assert_eq!((c.blocked, c.locked_to.as_deref()), (false, Some("02:00:00:00:00:01")));
        assert_eq!(serde_json::to_value(controls(Some(&state), &mac("aa:bb:cc:00:00:01"))).unwrap(), json!({ "blocked": true, "locked_to": null, "usergroup_id": null }));
        let all = ClientControls::new(Some(&state));
        for m in ["aa:bb:cc:00:00:01", "AA:BB:CC:00:00:02", "aa:bb:cc:00:00:03"] {
            assert_eq!(controls(Some(&state), &mac(m)), all.get(&mac(m)), "{m}");
        }
        // An entry that writes its MAC another way is the one edited, as the one shown.
        let mut state = json!({ "clients": [{ "mac": "AA-BB-CC-00-00-04" }, { "mac": "aabbcc000005" }] });
        edit_client(&mut state, mac("aa:bb:cc:00:00:04"), &[("blocked", json!(true))]);
        edit_client(&mut state, mac("aabbcc000005"), &[("blocked", json!(true))]);
        assert_eq!(state["clients"].as_array().unwrap().len(), 2, "no duplicate");
        // Unblocking, unlocking or dropping the speed limit of a client without an entry adds none.
        edit_client(&mut state, mac("aa:bb:cc:00:00:06"), &[("blocked", json!(false))]);
        edit_client(&mut state, mac("aa:bb:cc:00:00:06"), &[("fixed_ap_enabled", json!(false)), ("fixed_ap_mac", Value::Null)]);
        edit_client(&mut state, mac("aa:bb:cc:00:00:06"), &[("usergroup_id", Value::Null)]);
        assert_eq!(state["clients"].as_array().unwrap().len(), 2);
        assert!(controls(Some(&state), &mac("aa:bb:cc:00:00:04")).blocked && controls(Some(&state), &mac("aa:bb:cc:00:00:05")).blocked);
    }
}
