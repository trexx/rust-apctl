//! Speed limits (user groups): the site's default group, the groups the
//! SSIDs and clients point at, and their editor. Changes go through
//! [`crate::settings::change`], so they can be previewed like SSID and AP edits.

use std::collections::HashMap;

use apcfg::{flag, oid};
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, AppState, Json, MacPath, Path, Query};
use crate::settings::{ClientNames, Patch, PreviewQuery, change, client_label, client_names, doc_by_id, doc_by_id_mut, docs, hidden_doc_id, id_of, most_named, new_id, num, push_doc, remove_doc, str_field};

/// The default user group, created when the settings have none (imports made
/// before apctl read user groups). It keeps the id the SSIDs already point at.
pub fn ensure_default_usergroup(state: &mut Value) -> String {
    if let Some(id) = default_usergroup(state) {
        return id;
    }
    // With the id SSIDs point at, else a new one.
    let id = orphan_usergroup_id(state).map_or_else(new_id, str::to_string);
    push_doc(state, "usergroup", default_usergroup_doc(&id));
    id
}

/// The default user group's document, with this id.
fn default_usergroup_doc(id: &str) -> Value {
    json!({ "_id": id, "name": "Default", "attr_hidden_id": "Default", "attr_no_delete": true, "qos_rate_max_down": -1, "qos_rate_max_up": -1 })
}

/// The id a default user group made now keeps: the one most SSIDs point at
/// (the first of a tie) that no group has (an id a group has is a speed limit,
/// not the default). `None` when no SSID points at a missing group.
fn orphan_usergroup_id(state: &Value) -> Option<&str> {
    most_named(docs(state, "wlanconf").filter_map(|w| w["usergroup_id"].as_str()).filter(|g| !g.is_empty() && doc_by_id(state, "usergroup", g).is_none()))
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

/// A limit in kbps as the page shows it: kbps under 1000, else Mbps to two
/// decimals (a half hundredth rounded up) without trailing zeros; "none" for no limit.
fn rate_label(kbps: i64) -> String {
    match kbps {
        ..=0 => "none".into(),
        1..1000 => format!("{kbps} kbps"),
        _ => {
            let hundredths = (kbps + 5) / 10;
            let (whole, frac) = (hundredths / 100, hundredths % 100);
            match frac {
                0 => format!("{whole} Mbps"),
                f if f % 10 == 0 => format!("{whole}.{} Mbps", f / 10),
                f => format!("{whole}.{f:02} Mbps"),
            }
        }
    }
}

/// What uses a user group: its id, and "SSID x" / "client y" (SSIDs first),
/// a client named by [`client_label`]. An SSID uses the group the render gives
/// its clients ([`apcfg::ssid_usergroup`]: one with no group, an empty id or a
/// stale one gets the default), or, while the settings have no default group,
/// the one shown in its place ([`usergroup_list`]). A client with no group of
/// its own (none, or an empty id) uses none: its SSID's applies.
fn group_uses<'a>(state: &'a Value, names: &'a ClientNames) -> impl Iterator<Item = (&'a str, String)> {
    let site = crate::settings::site_id(state).unwrap_or_default();
    let unmade = orphan_usergroup_id(state).unwrap_or("");
    let ssids = docs(state, "wlanconf").map(move |w| (apcfg::ssid_usergroup(state, site, w).and_then(oid).unwrap_or(unmade), format!("SSID {}", w["name"].as_str().unwrap_or("?"))));
    let clients = docs(state, "clients").filter_map(|c| Some((c["usergroup_id"].as_str().filter(|g| !g.is_empty())?, format!("client {}", client_label(c, names)))));
    ssids.chain(clients)
}

/// Who uses each user group (by id), read in one pass.
fn group_users<'a>(state: &'a Value, names: &'a ClientNames) -> HashMap<&'a str, Vec<String>> {
    let mut out: HashMap<&str, Vec<String>> = HashMap::new();
    for (id, user) in group_uses(state, names) {
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
pub fn remove_usergroup(state: &mut Value, id: &str, names: &ClientNames) -> Result<String, String> {
    let g = doc_by_id(state, "usergroup", id).ok_or("unknown speed limit")?;
    if flag(g, "attr_no_delete", false) {
        return Err("the default speed limit cannot be deleted".into());
    }
    let what = format!("deleted speed limit \"{}\"", g["name"].as_str().unwrap_or("?"));
    let users: Vec<String> = group_uses(state, names).filter(|(g, _)| *g == id).map(|(_, user)| user).collect();
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
    // Told as the render reads the limits.
    let (down, up) = apcfg::usergroup_limits(g);
    Ok(format!("{} speed limit \"{}\": down {}, up {}", if created { "added" } else { "changed" }, g["name"].as_str().unwrap_or("?"), rate_label(down), rate_label(up)))
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
    Ok(Json(json!({ "groups": usergroup_list(&state, &client_names(&s)) })))
}

/// The site's user groups as the editors show them, with what uses each and
/// their limits as the render reads them (kbps, -1 for none).
fn usergroup_list(state: &Value, names: &ClientNames) -> Vec<Value> {
    let users = group_users(state, names);
    let group = |g: &Value| {
        let id = id_of(g).unwrap_or_default();
        let used_by = users.get(id.as_str()).map(Vec::as_slice).unwrap_or_default();
        let (down, up) = apcfg::usergroup_limits(g);
        json!({
            "id": id, "name": g["name"], "default": g["attr_hidden_id"].as_str() == Some("Default"),
            "qos_rate_max_down": down, "qos_rate_max_up": up, "used_by": used_by,
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
    let names = client_names(&s);
    change(&s, &q, |state: &mut Value, (id, names): &(String, ClientNames)| remove_usergroup(state, id, names), (id, names)).await
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
        let shown = |s: &Value| usergroup_list(s, &ClientNames::new()).into_iter().find(|g| g["default"] == true).map(|g| g["id"].clone());
        assert_eq!(shown(&state()), Some(json!("ug-imported")));
        let mut s = state();
        s["wlanconf"][0].as_object_mut().unwrap().remove("usergroup_id");
        assert_eq!((shown(&s), shown(&s)), (Some(json!("")), Some(json!(""))));
    }

    #[test]
    fn the_default_row_lists_what_has_no_limit_as_the_aps_are_told() {
        let used_by = |s: &Value, default: bool| usergroup_list(s, &ClientNames::new()).into_iter().find(|g| g["default"] == default).map(|g| g["used_by"].clone());
        // Not made yet: shown with the id the SSIDs point at, and what points at it.
        let mut s = state();
        s["clients"][0]["usergroup_id"] = json!("");
        assert_eq!(used_by(&s, true), Some(json!(["SSID Home"])), "a client with an empty group has none of its own");
        // No group at all: the SSID has no limit, and the client still none of its own.
        s["wlanconf"][0].as_object_mut().unwrap().remove("usergroup_id");
        assert_eq!(used_by(&s, true), Some(json!(["SSID Home"])));
        // Made: an SSID with no id, an empty one or a stale one gets the default, as in the config.
        ensure_default_usergroup(&mut s);
        let ssid = |id: &str, g: Value| json!({ "_id": id, "site_id": "s1", "name": id, "security": "open", "usergroup_id": g });
        s["usergroup"].as_array_mut().unwrap().push(json!({ "_id": "ug-slow", "name": "Slow", "site_id": "s1", "qos_rate_max_down": 1000 }));
        s["wlanconf"] = json!([ssid("A", json!("")), ssid("B", json!("gone")), ssid("C", Value::Null), ssid("D", json!("ug-slow"))]);
        assert_eq!(used_by(&s, true), Some(json!(["SSID A", "SSID B", "SSID C"])));
        assert_eq!(used_by(&s, false), Some(json!(["SSID D"])));
    }

    #[test]
    fn limits_are_sent_as_the_render_reads_them() {
        let mut s = state();
        s["usergroup"] = json!([
            { "_id": "a", "name": "Text", "site_id": "s1", "qos_rate_max_down": "2500", "qos_rate_max_up": 1000 },
            { "_id": "b", "name": "Unreadable", "site_id": "s1", "qos_rate_max_down": "2500.0", "qos_rate_max_up": 1.5 },
        ]);
        let rates = |name: &str| {
            let g = usergroup_list(&s, &ClientNames::new()).into_iter().find(|g| g["name"] == name).unwrap();
            (g["qos_rate_max_down"].clone(), g["qos_rate_max_up"].clone())
        };
        assert_eq!(rates("Text"), (json!(2500), json!(1000)));
        assert_eq!(rates("Unreadable"), (json!(-1), json!(-1)), "the APs get no limit from these");
        assert_eq!(rates("Default"), (json!(-1), json!(-1)));
        let what = apply_usergroup(&mut s, &GroupEdit::Edit("b".into(), json!({ "name": "Unreadable" }))).unwrap();
        assert!(what.ends_with("down none, up none"), "{what}");
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
        // As the page shows a limit (format.ts `speed`), a half hundredth rounded up (1005, 2675).
        let labels = [-1, 2, 500, 999, 1000, 1005, 1234, 1235, 1500, 1999, 2675, 100_000].map(rate_label);
        assert_eq!(labels, ["none", "2 kbps", "500 kbps", "999 kbps", "1 Mbps", "1.01 Mbps", "1.23 Mbps", "1.24 Mbps", "1.5 Mbps", "2 Mbps", "2.68 Mbps", "100 Mbps"]);
        apply_client_group(&mut s, &client("AA-BB-CC-00-00-01", Some(&id))).unwrap();
        assert_eq!((s["clients"].as_array().unwrap().len(), s["clients"][0]["usergroup_id"].as_str()), (1, Some(id.as_str())), "the entry, however the MAC is written");
        let none = ClientNames::new();
        let err = remove_usergroup(&mut s, &id, &none).unwrap_err();
        assert!(err.contains("client tv"), "{err}");
        // A client is named as the pages name it: by its alias in apctl first.
        let names = ClientNames::from([("aa:bb:cc:00:00:01".parse().unwrap(), "Living room TV".to_string())]);
        let err = remove_usergroup(&mut s, &id, &names).unwrap_err();
        assert!(err.ends_with("client Living room TV"), "{err}");
        assert_eq!(usergroup_list(&s, &names).iter().find(|g| g["name"] == "Kids").unwrap()["used_by"], json!(["client Living room TV"]));
        apply_client_group(&mut s, &client("aabbcc000001", None)).unwrap();
        remove_usergroup(&mut s, &id, &none).unwrap();
        assert!(remove_usergroup(&mut s, "ug-imported", &none).is_err(), "the default stays");
        // An SSID back to "no limit" points at the default group.
        apply_wlan(&mut s, &WlanEdit { id: "w1".into(), patch: json!({ "usergroup_id": "" }) }).unwrap();
        assert_eq!(s["wlanconf"][0]["usergroup_id"], "ug-imported");
        assert!(apply_wlan(&mut s, &WlanEdit { id: "w1".into(), patch: json!({ "usergroup_id": "nope" }) }).is_err());
    }
}
