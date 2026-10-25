//! Speed limits (user groups): the site's default group, the groups the
//! SSIDs and clients point at, and their editor. Changes go through
//! [`crate::settings::change`], so they can be previewed like SSID and AP edits.

use std::collections::HashMap;

use apcfg::{flag, oid};
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, AppState, Json, MacPath, Path, Query};
use crate::settings::{Patch, PreviewQuery, change, client_label, doc_by_id, doc_by_id_mut, docs, hidden_doc_id, id_of, new_id, num, push_doc, remove_doc, str_field};

/// The default user group, created when the settings have none (imports made
/// before apctl read user groups). It keeps the id the SSIDs already point at.
pub fn ensure_default_usergroup(state: &mut Value) -> String {
    if let Some(id) = default_usergroup(state) {
        return id;
    }
    let doc = new_default_usergroup(state);
    let id = id_of(&doc).unwrap_or_default();
    push_doc(state, "usergroup", doc);
    id
}

/// The default user group as [`ensure_default_usergroup`] adds it (but for
/// its `site_id`): with the id SSIDs point at ([`orphan_usergroup_id`]), else a new one.
fn new_default_usergroup(state: &Value) -> Value {
    default_usergroup_doc(&orphan_usergroup_id(state).map_or_else(new_id, str::to_string))
}

/// The default user group's document, with this id.
fn default_usergroup_doc(id: &str) -> Value {
    json!({ "_id": id, "name": "Default", "attr_hidden_id": "Default", "attr_no_delete": true, "qos_rate_max_down": -1, "qos_rate_max_up": -1 })
}

/// The id a default user group made now keeps: the one most SSIDs point at
/// (the first of a tie) that no group has (an id a group has is a speed limit,
/// not the default). `None` when no SSID points at a missing group.
fn orphan_usergroup_id(state: &Value) -> Option<&str> {
    let mut uses: Vec<(&str, usize)> = Vec::new();
    for g in docs(state, "wlanconf").filter_map(|w| w["usergroup_id"].as_str()).filter(|g| !g.is_empty() && doc_by_id(state, "usergroup", g).is_none()) {
        match uses.iter_mut().find(|(id, _)| *id == g) {
            Some((_, n)) => *n += 1,
            None => uses.push((g, 1)),
        }
    }
    // max_by_key keeps the last of equals: reversed, that is the first seen.
    uses.into_iter().rev().max_by_key(|(_, n)| *n).map(|(id, _)| id)
}

/// The id of the site's default user group (no speed limit).
pub fn default_usergroup(state: &Value) -> Option<String> {
    hidden_doc_id(state, "usergroup", "Default")
}

/// A limit in kbps: -1 (none) or 2 to 100000, as the official controller allows.
fn rate(v: &Value, what: &str) -> Result<i64, String> {
    match num(v) {
        Some(-1) => Ok(-1),
        Some(n) if (2..=100_000).contains(&n) => Ok(n),
        _ => Err(format!("the {what} limit must be 2 to 100000 kbps, or -1 for none")),
    }
}

/// What uses a user group: its id, and "SSID x" / "client y" (SSIDs first).
fn group_uses(state: &Value) -> impl Iterator<Item = (&str, String)> {
    let ssids = docs(state, "wlanconf").filter_map(|w| Some((w["usergroup_id"].as_str()?, format!("SSID {}", w["name"].as_str().unwrap_or("?")))));
    let clients = docs(state, "clients").filter_map(|c| Some((c["usergroup_id"].as_str()?, format!("client {}", client_label(c)))));
    ssids.chain(clients)
}

/// Who uses each user group (by id), read in one pass.
fn group_users(state: &Value) -> HashMap<&str, Vec<String>> {
    let mut out: HashMap<&str, Vec<String>> = HashMap::new();
    for (id, user) in group_uses(state) {
        out.entry(id).or_default().push(user);
    }
    out
}

/// A new user group (its fields), or an edit to one (its id and the fields to change).
pub enum GroupEdit {
    Create(Value),
    Edit(String, Value),
}

/// Deletes a user group no SSID or client uses; the default one stays.
pub fn remove_usergroup(state: &mut Value, id: &str) -> Result<String, String> {
    let g = doc_by_id(state, "usergroup", id).ok_or("unknown speed limit")?;
    if flag(g, "attr_no_delete", false) {
        return Err("the default speed limit cannot be deleted".into());
    }
    let what = format!("deleted speed limit \"{}\"", g["name"].as_str().unwrap_or("?"));
    let users: Vec<String> = group_uses(state).filter(|(g, _)| *g == id).map(|(_, user)| user).collect();
    if !users.is_empty() {
        return Err(format!("still used by {}", users.join(", ")));
    }
    remove_doc(state, "usergroup", id);
    Ok(what)
}

/// Creates or edits a user group.
pub fn apply_usergroup(state: &mut Value, e: &GroupEdit) -> Result<String, String> {
    ensure_default_usergroup(state);
    let (id, p) = match e {
        GroupEdit::Create(p) => (None, p),
        GroupEdit::Edit(id, p) => (Some(id.as_str()), p),
    };
    let name = str_field(p, "name")?.map(str::trim);
    if name.is_some_and(|n| n.is_empty() || n.chars().count() > 128) {
        return Err("the name must be 1 to 128 characters".into());
    }
    let down = if p["qos_rate_max_down"].is_null() { None } else { Some(rate(&p["qos_rate_max_down"], "download")?) };
    let up = if p["qos_rate_max_up"].is_null() { None } else { Some(rate(&p["qos_rate_max_up"], "upload")?) };
    if let Some(n) = name
        && docs(state, "usergroup").any(|g| g["name"].as_str() == Some(n) && oid(g) != id)
    {
        return Err(format!("another speed limit is called \"{n}\""));
    }
    let (g, created) = match id {
        Some(id) => (doc_by_id_mut(state, "usergroup", id).ok_or("unknown speed limit")?, false),
        None => {
            let n = name.ok_or("the new speed limit needs a name")?;
            (push_doc(state, "usergroup", json!({ "_id": new_id(), "name": n, "qos_rate_max_down": -1, "qos_rate_max_up": -1 })), true)
        }
    };
    if let Some(n) = name {
        g["name"] = json!(n);
    }
    if let Some(d) = down {
        g["qos_rate_max_down"] = json!(d);
    }
    if let Some(u) = up {
        g["qos_rate_max_up"] = json!(u);
    }
    let show = |v: &Value| match num(v) {
        Some(n) if n > 0 => format!("{} Mbps", n as f64 / 1000.0),
        _ => "none".into(),
    };
    Ok(format!(
        "{} speed limit \"{}\": down {}, up {}",
        if created { "added" } else { "changed" },
        g["name"].as_str().unwrap_or("?"),
        show(&g["qos_rate_max_down"]),
        show(&g["qos_rate_max_up"])
    ))
}

/// A client and the speed limit (user group) of its own it gets: none (or
/// empty) removes it, so the SSID's applies.
pub struct ClientGroup {
    pub mac: inform::Mac,
    pub usergroup_id: Option<String>,
}

/// Sets a client's own speed limit.
pub fn apply_client_group(state: &mut Value, e: &ClientGroup) -> Result<String, String> {
    let mac = e.mac;
    let (value, what) = match e.usergroup_id.as_deref().filter(|g| !g.is_empty()) {
        Some(g) => {
            let name = doc_by_id(state, "usergroup", g).ok_or("unknown speed limit")?["name"].as_str().unwrap_or("?");
            (json!(g), format!("client {mac}: speed limit \"{name}\""))
        }
        None => (Value::Null, format!("client {mac}: no own speed limit")),
    };
    crate::actions::edit_client(state, mac, &[("usergroup_id", value)]);
    Ok(what)
}

/// GET /api/settings/usergroups
pub async fn usergroups(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let state = crate::api::current_state(&s)?;
    Ok(Json(json!({ "active": s.active, "groups": usergroup_list(&state) })))
}

/// The site's user groups as the editors show them, with what uses each.
fn usergroup_list(state: &Value) -> Vec<Value> {
    let users = group_users(state);
    let group = |g: &Value| {
        let id = id_of(g).unwrap_or_default();
        let used_by = users.get(id.as_str()).map(Vec::as_slice).unwrap_or_default();
        json!({
            "id": id, "name": g["name"], "default": g["attr_hidden_id"].as_str() == Some("Default"),
            "qos_rate_max_down": g["qos_rate_max_down"], "qos_rate_max_up": g["qos_rate_max_up"], "used_by": used_by,
        })
    };
    let mut groups: Vec<Value> = docs(state, "usergroup").map(group).collect();
    // Settings without a default group get it on their first save; shown as it will be, with
    // the id it will keep, else "" (the editors' name for the default group while it isn't made).
    if default_usergroup(state).is_none() {
        groups.push(group(&default_usergroup_doc(orphan_usergroup_id(state).unwrap_or(""))));
    }
    groups
}

/// POST /api/settings/usergroups {patch}
pub async fn post_usergroup(State(s): State<AppState>, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    change(&s, &q, apply_usergroup, GroupEdit::Create(b.patch)).await
}

/// PUT /api/settings/usergroups/{id} {patch}
pub async fn put_usergroup(State(s): State<AppState>, Path(id): Path<String>, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    change(&s, &q, apply_usergroup, GroupEdit::Edit(id, b.patch)).await
}

/// DELETE /api/settings/usergroups/{id}
pub async fn delete_usergroup(State(s): State<AppState>, Path(id): Path<String>, Query(q): Query<PreviewQuery>) -> Result<Json<Value>, ApiError> {
    change(&s, &q, |state: &mut Value, id: &String| remove_usergroup(state, id), id).await
}

#[derive(Deserialize)]
pub struct ClientGroupBody {
    usergroup_id: Option<String>,
}

/// PUT /api/clients/{mac}/speed-limit {usergroup_id}
pub async fn put_client_group(State(s): State<AppState>, MacPath(mac): MacPath, Query(q): Query<PreviewQuery>, Json(b): Json<ClientGroupBody>) -> Result<Json<Value>, ApiError> {
    change(&s, &q, apply_client_group, ClientGroup { mac, usergroup_id: b.usergroup_id }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{WlanEdit, apply_wlan};

    fn state() -> Value {
        json!({
            "devices": [{ "mac": "02:00:00:00:00:01", "site_id": "s1", "radio_table": [] }],
            "apgroup": [{ "_id": "g0", "attr_hidden_id": "default", "site_id": "s1" }],
            "wlanconf": [{ "_id": "w1", "site_id": "s1", "name": "Home", "security": "open", "wlan_bands": ["5g"], "ap_group_ids": ["g0"], "usergroup_id": "ug-imported" }],
            "clients": [{ "mac": "aa:bb:cc:00:00:01", "name": "tv" }],
        })
    }

    #[test]
    fn the_default_group_keeps_the_id_the_ssids_use() {
        let mut s = state();
        assert_eq!(ensure_default_usergroup(&mut s), "ug-imported");
        assert_eq!(ensure_default_usergroup(&mut s), "ug-imported", "made once");
        assert_eq!(s["usergroup"].as_array().unwrap().len(), 1);
        // An id a group already has is that group's (a speed limit), never the
        // default's; of the others the one most SSIDs use wins.
        let mut s = state();
        let ssid = |id: &str, g: &str| json!({ "_id": id, "site_id": "s1", "name": id, "security": "open", "usergroup_id": g });
        s["wlanconf"] = json!([ssid("w1", "ug-slow"), ssid("w2", "ug-a"), ssid("w3", "ug-b"), ssid("w4", "ug-b")]);
        s["usergroup"] = json!([{ "_id": "ug-slow", "name": "Slow", "site_id": "s1", "qos_rate_max_down": 1000 }]);
        assert_eq!(ensure_default_usergroup(&mut s), "ug-b");
        s["wlanconf"] = json!([ssid("w1", "ug-slow")]);
        s["usergroup"].as_array_mut().unwrap().truncate(1);
        let id = ensure_default_usergroup(&mut s);
        assert!(id != "ug-slow" && s["usergroup"].as_array().unwrap().len() == 2, "{id}");
        // A tie goes to the first SSID's.
        let mut s = state();
        s["wlanconf"] = json!([ssid("w1", "ug-a"), ssid("w2", "ug-b")]);
        assert_eq!(ensure_default_usergroup(&mut s), "ug-a");
        // Shown before it is made: with the id it will keep, else "" (not a new random one each time).
        let shown = |s: &Value| usergroup_list(s).into_iter().find(|g| g["default"] == true).map(|g| g["id"].clone());
        assert_eq!(shown(&state()), Some(json!("ug-imported")));
        let mut s = state();
        s["wlanconf"][0].as_object_mut().unwrap().remove("usergroup_id");
        assert_eq!((shown(&s), shown(&s)), (Some(json!("")), Some(json!(""))));
    }

    #[test]
    fn speed_limits_are_checked_and_not_deleted_while_used() {
        let mut s = state();
        let group = |id: Option<&str>, patch: Value| match id {
            Some(id) => GroupEdit::Edit(id.into(), patch),
            None => GroupEdit::Create(patch),
        };
        let client = |mac: &str, g: Option<&str>| ClientGroup { mac: mac.parse().unwrap(), usergroup_id: g.map(str::to_string) };
        let what = apply_usergroup(&mut s, &group(None, json!({ "name": "Kids", "qos_rate_max_down": 5000, "qos_rate_max_up": -1 }))).unwrap();
        assert!(what.contains("down 5 Mbps, up none"), "{what}");
        let id = id_of(s["usergroup"].as_array().unwrap().iter().find(|g| g["name"] == "Kids").unwrap()).unwrap();
        assert!(apply_usergroup(&mut s, &group(Some(&id), json!({ "qos_rate_max_down": 1 }))).is_err(), "0 and 1 kbps are not allowed");
        apply_usergroup(&mut s, &group(Some(&id), json!({ "qos_rate_max_down": "6000" }))).unwrap();
        // A rate stored as text (an import) is told as the number it is.
        let kids = s["usergroup"].as_array_mut().unwrap().iter_mut().find(|g| g["name"] == "Kids").unwrap();
        kids["qos_rate_max_up"] = json!("2500");
        let what = apply_usergroup(&mut s, &group(Some(&id), json!({ "name": "Kids" }))).unwrap();
        assert!(what.contains("down 6 Mbps, up 2.5 Mbps"), "{what}");
        assert!(apply_usergroup(&mut s, &group(None, json!({ "name": "Kids" }))).is_err(), "names are unique");
        apply_client_group(&mut s, &client("AA-BB-CC-00-00-01", Some(&id))).unwrap();
        assert_eq!((s["clients"].as_array().unwrap().len(), s["clients"][0]["usergroup_id"].as_str()), (1, Some(id.as_str())), "the entry, however the MAC is written");
        let err = remove_usergroup(&mut s, &id).unwrap_err();
        assert!(err.contains("client tv"), "{err}");
        apply_client_group(&mut s, &client("aabbcc000001", None)).unwrap();
        remove_usergroup(&mut s, &id).unwrap();
        assert!(remove_usergroup(&mut s, "ug-imported").is_err(), "the default stays");
        // An SSID back to "no limit" points at the default group.
        apply_wlan(&mut s, &WlanEdit { id: "w1".into(), patch: json!({ "usergroup_id": "" }) }).unwrap();
        assert_eq!(s["wlanconf"][0]["usergroup_id"], "ug-imported");
        assert!(apply_wlan(&mut s, &WlanEdit { id: "w1".into(), patch: json!({ "usergroup_id": "nope" }) }).is_err());
    }
}
