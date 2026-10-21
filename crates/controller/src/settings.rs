//! The settings editor: changes to SSIDs (`wlanconf`) and APs (`devices`) in
//! apctl's copy of the controller settings.
//!
//! Every change can be previewed first (`?preview=true`): the config each AP
//! would get is rendered with and without it and the difference returned, the
//! same shape as a config push in the history. Previews work in shadow mode
//! too; saving needs active mode, since in shadow mode the settings belong to
//! the other controller (the next import would replace them).

use axum::extract::State;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use serde::Deserialize;
use serde_json::{Value, json};

use apcfg::oid;

use crate::api::{ApiError, AppState, Json, MacPath, Path, Query};
use crate::random_hex;

#[derive(Deserialize, Default)]
pub struct PreviewQuery {
    #[serde(default)]
    pub preview: bool,
}

/// A change to the settings: applied to a copy for a preview, or through the
/// engine to save it. `B` is what the handler took from the request.
pub type Apply<B> = fn(&mut Value, &B) -> Result<String, String>;

/// Previews or saves `apply(state, body)`. `apply` validates, edits, and
/// returns what changed in words (for the event and the config history).
pub(crate) async fn change<B: Send + 'static>(s: &AppState, q: &PreviewQuery, apply: Apply<B>, body: B) -> Result<Json<Value>, ApiError> {
    if q.preview {
        let current = crate::api::current_state(s)?;
        return Ok(Json(preview(s, current, move |state| apply(state, &body)).await?));
    }
    if !s.active {
        return Err(ApiError::conflict("saving needs active mode: in shadow mode the settings belong to the other controller"));
    }
    // Applied once, inside the engine, to the settings as they are then; what
    // changed is what that run says.
    let what = crate::actions::apply_edit(s, Box::new(move |state| apply(state, &body))).await?;
    Ok(Json(json!({ "saved": true, "what": what })))
}

/// What `edit` changes in words, and what each reporting AP's config would
/// become, as config-push summaries. What rendering needs is copied out of
/// `live` first; copying the settings, the edit (some hash passwords) and the
/// rendering (twice per AP) run off the async workers without the lock.
async fn preview(s: &AppState, before: Arc<Value>, edit: impl FnOnce(&mut Value) -> Result<String, String> + Send + 'static) -> Result<Value, ApiError> {
    let render = s.renderer.clone();
    let aps: Vec<_> = {
        let live = s.live.read().unwrap();
        live.devices
            .iter()
            .map(|(mac, d)| (*mac, live.raw_informs.get(mac).cloned(), d.snapshot.ap.cfgversion.clone().unwrap_or_default(), d.snapshot.ap.hostname.clone(), d.snapshot.radios.clone()))
            .collect()
    };
    let work = move || {
        let mut after = (*before).clone();
        let what = edit(&mut after).map_err(ApiError::bad)?;
        let mut out = Vec::new();
        for (mac, inform, cfgversion, name, radios) in &aps {
            let mac_s = mac.to_string();
            let req = |state| crate::dryrun::RenderRequest { state, device_mac: &mac_s, inform: inform.as_deref(), cfgversion, previous_system_cfg: None };
            match (render(&req(&before)), render(&req(&after))) {
                (Ok(old), Ok(new)) => {
                    let summary = |o: &str, n: &str| wire::cfgdiff::diff(o, n).summary();
                    let mut labels = crate::engine::section_labels(&old.1, radios);
                    labels.extend(crate::engine::section_labels(&new.1, radios));
                    out.push(json!({
                        "mac": mac, "name": name,
                        "mgmt_cfg": summary(&old.0, &new.0), "system_cfg": summary(&old.1, &new.1), "labels": labels,
                    }));
                }
                // The edit makes a config that did not render render: nothing to compare it with.
                (Err(e), Ok(_)) => out.push(json!({ "mac": mac, "name": name, "fixes": format!("{e:#}") })),
                (_, Err(e)) => out.push(json!({ "mac": mac, "name": name, "error": format!("{e:#}") })),
            }
        }
        Ok(json!({ "what": what, "aps": out }))
    };
    tokio::task::spawn_blocking(work).await?
}

/// Fields of an SSID the editor shows and edits (secrets are never listed).
const WLAN_FIELDS: &[&str] = &[
    "name", "enabled", "hide_ssid", "security", "wpa_mode", "wpa3_support", "wpa3_transition", "pmf_mode", "wlan_bands", "ap_group_mode",
    "fast_roaming_enabled", "bss_transition", "roaming_assistant_na_enabled", "roaming_assistant_na_rssi", "uapsd_enabled", "proxy_arp",
    "mcastenhance_enabled", "multicast_suppressor_mode", "bc_filter_enabled", "bc_filter_list", "l2_isolation", "minrate_setting_preference",
    "minrate_ng_enabled", "minrate_ng_data_rate_kbps", "minrate_na_enabled", "minrate_na_data_rate_kbps", "dtim_mode", "dtim_ng", "dtim_na",
    "group_rekey", "mac_filter_enabled", "mac_filter_policy", "mac_filter_list", "is_guest", "networkconf_id", "country_beacon",
    "usergroup_id", "schedule_with_duration", "dns_assistance_mode", "dns_assistance_servers", "no2ghz_oui", "advertise_device_name_in_beacon",
    "enhanced_iot", "iot_channel_lock", "iot_dtim_lock", "wpa3_fast_roaming", "sae_anti_clogging", "sae_sync", "rrm_enabled", "tdls_prohibit", "p2p",
    "p2p_cross_connect", "log_level", "mdns_proxy_mode", "mdns_proxy_custom",
];

/// The id of a settings document (plain or `{"$oid": ...}`).
pub fn id_of(v: &Value) -> Option<String> {
    oid(v).map(str::to_string)
}

/// The MAC a settings field holds (an AP record's `mac`, an entry of an AP
/// group's `device_macs`...), in whichever form it is written: `aa:bb:..`,
/// `AA-BB-..` or bare hex. Every lookup by MAC in the controller goes through
/// this, so its editors find a record however it writes its MAC. The render
/// (apcfg) compares the text, ignoring case only: the controller writes
/// `aa:bb:..`, so only an uploaded or hand-made state can differ.
pub(crate) fn doc_mac(v: &Value) -> Option<inform::Mac> {
    v.as_str()?.parse().ok()
}

/// The site apctl manages: the one its APs belong to.
///
/// apctl manages one site. An import may hold several (`informdump import`
/// reads every site), and each AP's config is rendered from its own site's
/// documents, but the editors read and change this site's documents only:
/// every lookup in a collection goes through [`docs`] / [`docs_mut`] (or
/// [`setting`] / [`setting_mut`]), and new documents go in with [`push_doc`].
/// The one exception is an AP's record looked up by its MAC
/// ([`crate::adopt::device_doc`]): keys, adoption and forgetting go by the
/// AP's own record, whatever site holds it. The AP editor edits the site's
/// APs only ([`site_device`]): its rules are this site's.
pub fn site_id(state: &Value) -> Option<&str> {
    state["devices"].as_array()?.iter().find_map(|d| d["site_id"].as_str())
}

/// Whether a settings document belongs to the site (documents without a site do).
fn in_site(site: Option<&str>, d: &Value) -> bool {
    site.is_none() || d["site_id"].as_str().is_none_or(|s| Some(s) == site)
}

/// The site's documents of a collection.
pub(crate) fn docs<'a>(state: &'a Value, collection: &str) -> impl Iterator<Item = &'a Value> {
    let site = site_id(state);
    state[collection].as_array().into_iter().flatten().filter(move |d| in_site(site, d))
}

/// The site's documents of a collection, to change.
pub(crate) fn docs_mut<'a>(state: &'a mut Value, collection: &str) -> impl Iterator<Item = &'a mut Value> {
    let site = site_id(state).map(str::to_string);
    state.get_mut(collection).and_then(Value::as_array_mut).into_iter().flatten().filter(move |d| in_site(site.as_deref(), d))
}

/// The site's document of a collection with this id.
fn doc_by_id<'a>(state: &'a Value, collection: &str, id: &str) -> Option<&'a Value> {
    docs(state, collection).find(|d| oid(d) == Some(id))
}

/// [`doc_by_id`], to change.
fn doc_by_id_mut<'a>(state: &'a mut Value, collection: &str, id: &str) -> Option<&'a mut Value> {
    docs_mut(state, collection).find(|d| oid(d) == Some(id))
}

/// Removes the site's document of a collection with this id (another site's
/// with the same id stays).
fn remove_doc(state: &mut Value, collection: &str, id: &str) {
    let site = site_id(state).map(str::to_string);
    if let Some(list) = state.get_mut(collection).and_then(Value::as_array_mut) {
        list.retain(|d| !in_site(site.as_deref(), d) || oid(d) != Some(id));
    }
}

/// The id of the site's document of a collection the official controller
/// marks with this `attr_hidden_id` (the default AP group, user group, LAN).
fn hidden_doc_id(state: &Value, collection: &str, hidden: &str) -> Option<String> {
    docs(state, collection).find(|d| d["attr_hidden_id"].as_str() == Some(hidden)).and_then(id_of)
}

/// The site's AP with this MAC. An AP of another site (of a multi-site import)
/// is refused: its country, outdoor default and neighbours are its own site's.
fn site_device<'a>(state: &'a Value, mac: &inform::Mac) -> Result<&'a Value, &'static str> {
    match docs(state, "devices").find(|d| doc_mac(&d["mac"]) == Some(*mac)) {
        Some(d) => Ok(d),
        None if crate::adopt::device_doc(state, mac).is_some() => Err("this AP belongs to another site"),
        None => Err("this AP is not in the settings"),
    }
}

/// The site's setting document with this key (`Null` when there is none).
pub(crate) fn setting<'a>(state: &'a Value, key: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    docs(state, "setting").find(|s| s["key"].as_str() == Some(key)).unwrap_or(&NULL)
}

/// The site's setting document with this key, created when missing.
pub(crate) fn setting_mut<'a>(state: &'a mut Value, key: &str) -> &'a mut Value {
    let site = site_id(state);
    match state["setting"].as_array().and_then(|l| l.iter().position(|s| s["key"].as_str() == Some(key) && in_site(site, s))) {
        Some(i) => &mut state["setting"][i],
        None => push_doc(state, "setting", json!({ "key": key })),
    }
}

/// Adds a document to a collection of the settings, in the site when the
/// settings have one (a document without `site_id` belongs to every site, as
/// one with `"site_id": null` does), and returns it.
pub(crate) fn push_doc<'a>(state: &'a mut Value, collection: &str, mut doc: Value) -> &'a mut Value {
    if let Some(site) = site_id(state) {
        doc["site_id"] = json!(site);
    }
    let list = array_mut(state, collection);
    list.push(doc);
    list.last_mut().expect("just pushed")
}

/// A list in the settings (a collection), created empty when missing.
pub(crate) fn array_mut<'a>(state: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    let v = &mut state[key];
    if !v.is_array() {
        *v = Value::Array(Vec::new());
    }
    match v {
        Value::Array(list) => list,
        _ => unreachable!("made a list above"),
    }
}

/// An inform's (or an AP record's) entry for one band in its `radio_table`.
pub(crate) fn inform_radio<'a>(inform: &'a Value, band: &str) -> Option<&'a Value> {
    inform["radio_table"].as_array()?.iter().find(|r| r["radio"].as_str() == Some(band))
}

/// [`inform_radio`], to change.
pub(crate) fn inform_radio_mut<'a>(inform: &'a mut Value, band: &str) -> Option<&'a mut Value> {
    inform.get_mut("radio_table")?.as_array_mut()?.iter_mut().find(|r| r["radio"].as_str() == Some(band))
}

/// An AP as messages name it: its name, else its MAC.
pub(crate) fn device_label(d: &Value, mac: impl std::fmt::Display) -> String {
    d["name"].as_str().filter(|n| !n.trim().is_empty()).map_or_else(|| mac.to_string(), str::to_string)
}

/// A client as messages name it: its name, else its host name, else its MAC.
fn client_label(c: &Value) -> &str {
    c["name"].as_str().or(c["hostname"].as_str()).or(c["mac"].as_str()).unwrap_or("?")
}

/// [`device_label`] from the AP's record alone: its MAC written `aa:bb:..`
/// (however the record writes it), else `fallback`.
pub(crate) fn record_label(d: &Value, fallback: &str) -> String {
    match doc_mac(&d["mac"]) {
        Some(m) => device_label(d, m),
        None => device_label(d, fallback),
    }
}

/// A flag of the site's `mgmt` setting (outdoor mode, advanced features...).
pub(crate) fn mgmt_flag(state: &Value, key: &str) -> bool {
    setting(state, "mgmt")[key].as_bool() == Some(true)
}

/// The site's time zone (Olson name), from the `locale` setting.
pub(crate) fn timezone(state: &Value) -> Option<&str> {
    setting(state, "locale")["timezone"].as_str()
}

/// A number the settings may hold as a number or as a string (imports keep
/// e.g. `"ht": "20"`, `"code": "276"`).
pub(crate) fn num(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str()?.parse().ok())
}

/// Some fields of a document, as they are (`null` for one it lacks).
pub(crate) fn pick(v: &Value, keys: &[&str]) -> serde_json::Map<String, Value> {
    keys.iter().map(|k| (k.to_string(), v[*k].clone())).collect()
}

/// The site's APs' MACs (however their records write them).
pub(crate) fn device_macs(state: &Value) -> Vec<inform::Mac> {
    docs(state, "devices").filter_map(|d| doc_mac(&d["mac"])).collect()
}

/// Drops repeated entries, keeping the first of each in place.
pub(crate) fn dedup_in_order<T: Eq + std::hash::Hash + Clone>(v: &mut Vec<T>) {
    let mut seen = HashSet::new();
    v.retain(|x| seen.insert(x.clone()));
}

/// A band's name for people.
pub(crate) fn band_name(band: &str) -> &str {
    match band {
        "ng" => "2.4 GHz",
        "na" => "5 GHz",
        "6e" => "6 GHz",
        b => b,
    }
}

/// The `radio_caps` bit of a radio with the "interference blocker" (hard noise floor).
const INTERFERENCE_BLOCKER: i64 = 131072;

/// Whether an AP record's radio has the interference blocker.
fn has_blocker(radio: &Value) -> bool {
    radio["radio_caps"].as_i64().is_some_and(|c| c & INTERFERENCE_BLOCKER != 0)
}

/// The APs an SSID is broadcast from, sorted: `None` for all of them (its
/// groups hold the site's default one). One with no groups is broadcast from
/// none, as the AP config has it.
fn wlan_aps(state: &Value, w: &Value) -> Option<Vec<inform::Mac>> {
    let groups: Vec<&str> = w["ap_group_ids"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut macs = Vec::new();
    for g in docs(state, "apgroup").filter(|g| oid(g).is_some_and(|id| groups.contains(&id))) {
        if g["attr_hidden_id"].as_str() == Some("default") {
            return None;
        }
        macs.extend(g["device_macs"].as_array().into_iter().flatten().filter_map(doc_mac));
    }
    macs.sort();
    macs.dedup();
    Some(macs)
}

/// GET /api/settings/wlans
pub async fn wlans(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    // Only the informs of the site's APs are copied out under the lock.
    let (state, informs) = {
        let live = s.live.read().unwrap();
        let informs: HashMap<inform::Mac, Arc<Value>> = live.state.as_deref().map_or_else(HashMap::new, |st| {
            docs(st, "devices").filter_map(|d| doc_mac(&d["mac"])).filter_map(|m| Some((m, live.raw_informs.get(&m)?.clone()))).collect()
        });
        (live.state.clone(), informs)
    };
    Ok(Json(wlans_view(state.as_deref().unwrap_or(&Value::Null), &informs, s.active)))
}

/// The SSIDs as the editor shows them, with what it offers for them. Without
/// settings (nothing imported yet) every list is empty.
fn wlans_view(state: &Value, informs: &HashMap<inform::Mac, Arc<Value>>, active: bool) -> Value {
    let list: Vec<Value> = docs(state, "wlanconf")
        // The hidden "element" SSID belongs to the official controller's own adoption feature.
        .filter(|w| w["attr_hidden_id"].as_str().is_none())
        .map(|w| {
            let mut v = json!({
                "id": id_of(w), "aps": wlan_aps(state, w), "protection": protection_of(w).map(|p| p.name), "editable": w["attr_no_edit"].as_bool() != Some(true),
                "has_passphrase": w["x_passphrase"].as_str().is_some_and(|p| !p.is_empty()),
            });
            if let Value::Object(o) = &mut v {
                o.extend(pick(w, WLAN_FIELDS));
            }
            v
        })
        .collect();
    let networks: Vec<Value> = docs(state, "networkconf").map(|n| json!({ "id": id_of(n), "name": n["name"], "vlan": n["vlan"], "purpose": n["purpose"] })).collect();
    let aps: Vec<Value> = docs(state, "devices").map(|d| json!({ "mac": doc_mac(&d["mac"]), "name": d["name"] })).collect();
    let (unsupported, unknown) = feature_support(state, informs);
    let mdns: Vec<Value> = apcfg::MDNS_SERVICES.iter().map(|(code, name, _)| json!({ "code": code, "name": name })).collect();
    json!({ "active": active, "wlans": list, "networks": networks, "aps": aps, "unsupported": unsupported, "unknown": unknown, "mdns_services": mdns })
}

/// For each optional SSID feature, the APs that would broadcast the SSID
/// without it; and the APs whose support is not known yet (no inform).
fn feature_support(state: &Value, informs: &HashMap<inform::Mac, Arc<Value>>) -> (BTreeMap<&'static str, Vec<inform::Mac>>, Vec<inform::Mac>) {
    let mut unsupported: BTreeMap<&str, Vec<inform::Mac>> = apcfg::SSID_FEATURES.iter().map(|f| (*f, Vec::new())).collect();
    let mut unknown = Vec::new();
    for d in docs(state, "devices") {
        let Some(mac) = doc_mac(&d["mac"]) else { continue };
        match apcfg::ssid_feature_support(d, informs.get(&mac).map(|v| v.as_ref())) {
            None => unknown.push(mac),
            Some(list) => {
                for (f, ok) in list {
                    if !ok {
                        unsupported.entry(f).or_default().push(mac);
                    }
                }
            }
        }
    }
    (unsupported, unknown)
}

/// GET /api/settings/wlans/{id}/passphrase: shown on request only.
pub async fn passphrase(State(s): State<AppState>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let state = crate::api::current_state(&s)?;
    let w = wlan(&state, &id).ok_or_else(|| ApiError::not_found("unknown SSID"))?;
    Ok(Json(json!({ "passphrase": w["x_passphrase"] })))
}

/// Fields of an AP radio the editor shows and edits.
const RADIO_FIELDS: &[&str] = &[
    "radio", "name", "channel", "ht", "tx_power_mode", "tx_power", "min_rssi_enabled", "min_rssi", "hard_noise_floor_enabled", "sens_level_enabled", "sens_level",
    "antenna_gain", "antenna_id", "vwire_enabled", "loadbalance_enabled", "maxsta",
];

/// Fields of an AP the editor shows and edits, besides its radios.
const DEVICE_FIELDS: &[&str] = &[
    "name", "led_override", "led_override_color", "led_override_color_brightness", "outdoor_mode_override", "bandsteering_mode", "atf_enabled",
    "green_ap_enabled", "resetbtn_enabled", "jumboframe_enabled", "config_network", "snmp_location", "snmp_contact",
];

/// What the AP itself reports about a radio: power range, widths, channels.
fn radio_caps(inform: Option<&Value>, band: &str) -> Value {
    let Some(r) = inform.and_then(|p| inform_radio(p, band)) else { return Value::Null };
    json!({
        "min_txpower": r["min_txpower"], "max_txpower": r["max_txpower"], "has_ht160": r["has_ht160"], "has_dfs": r["has_dfs"],
        "is_11ax": r["is_11ax"], "nss": r["nss"],
    })
}

/// What the AP reports about a radio that an edit is checked against.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadioCaps {
    /// The power range, dBm.
    pub min_txpower: i64,
    pub max_txpower: i64,
    pub has_ht160: bool,
}

impl Default for RadioCaps {
    /// A radio that reports nothing: 1 to 30 dBm, no 160 MHz.
    fn default() -> Self {
        RadioCaps { min_txpower: 1, max_txpower: 30, has_ht160: false }
    }
}

impl RadioCaps {
    /// Each band's caps from an inform's `radio_table` (the first entry of a
    /// band, as [`inform_radio`] finds it); none without an inform.
    pub fn of_inform(inform: Option<&Value>) -> HashMap<String, RadioCaps> {
        let mut out = HashMap::new();
        for r in inform.and_then(|p| p["radio_table"].as_array()).into_iter().flatten() {
            let Some(band) = r["radio"].as_str() else { continue };
            let d = RadioCaps::default();
            out.entry(band.to_string()).or_insert(RadioCaps {
                min_txpower: r["min_txpower"].as_i64().unwrap_or(d.min_txpower),
                max_txpower: r["max_txpower"].as_i64().unwrap_or(d.max_txpower),
                has_ht160: r["has_ht160"].as_bool() == Some(true),
            });
        }
        out
    }
}

/// GET /api/settings/devices/{mac}
pub async fn device(State(s): State<AppState>, MacPath(mac): MacPath) -> Result<Json<Value>, ApiError> {
    let (state, inform) = {
        let live = s.live.read().unwrap();
        (live.state.clone(), live.raw_informs.get(&mac).cloned())
    };
    let state = state.ok_or_else(ApiError::no_state)?;
    let d = site_device(&state, &mac).map_err(ApiError::not_found)?;
    let radios: Vec<Value> = d["radio_table"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let mut v = Value::Object(pick(r, RADIO_FIELDS));
            let band = r["radio"].as_str().unwrap_or("");
            v["caps"] = radio_caps(inform.as_deref(), band);
            v["channels"] = channels(&state, band, false);
            v["channels_outdoor"] = channels(&state, band, true);
            // The "interference blocker" exists only on radios reporting this capability.
            v["has_blocker"] = json!(has_blocker(r));
            v
        })
        .collect();
    let supported: Vec<&str> = apcfg::device_feature_support(d, inform.as_deref()).map_or_else(|| apcfg::DEVICE_FEATURES.to_vec(), |l| l.into_iter().filter(|(_, ok)| *ok).map(|(f, _)| f).collect());
    let site_outdoor = mgmt_flag(&state, "outdoor_mode_enabled");
    let advanced = mgmt_flag(&state, "advanced_feature_enabled");
    let antennas: Vec<Value> = inform.as_deref().and_then(|p| p["antenna_table"].as_array().cloned()).unwrap_or_default();
    let mut out = json!({
        "active": s.active, "mac": mac.to_string(), "model": d["model"], "radios": radios, "features": supported,
        "reported": inform.is_some(), "site_outdoor": site_outdoor, "advanced_features": advanced, "antennas": antennas,
        "ports": d["ethernet_table"].as_array().map_or(0, |t| t.iter().filter_map(|e| e["num_port"].as_i64()).sum::<i64>()),
    });
    if let Value::Object(o) = &mut out {
        o.extend(pick(d, DEVICE_FIELDS));
    }
    Ok(Json(out))
}

// ---- Channels -------------------------------------------------------------

/// The channel rules a country follows.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Rules {
    /// European (ETSI): EU and EEA members, the UK and Switzerland.
    Etsi,
    /// US (FCC).
    Fcc,
}

/// A country apctl has channel rules for: its ISO 3166 numeric code, its name
/// (for the site settings) and its rules.
pub(crate) struct Country {
    pub code: i64,
    pub name: &'static str,
    pub rules: Rules,
}

/// The countries apctl has channel rules for; the site's country must be one.
pub(crate) const COUNTRIES: &[Country] = {
    use Rules::{Etsi, Fcc};
    const fn c(code: i64, name: &'static str, rules: Rules) -> Country {
        Country { code, name, rules }
    }
    &[
        c(40, "Austria", Etsi), c(56, "Belgium", Etsi), c(100, "Bulgaria", Etsi), c(124, "Canada", Fcc), c(191, "Croatia", Etsi), c(196, "Cyprus", Etsi),
        c(203, "Czechia", Etsi), c(208, "Denmark", Etsi), c(233, "Estonia", Etsi), c(246, "Finland", Etsi), c(250, "France", Etsi), c(276, "Germany", Etsi),
        c(300, "Greece", Etsi), c(348, "Hungary", Etsi), c(352, "Iceland", Etsi), c(372, "Ireland", Etsi), c(380, "Italy", Etsi), c(428, "Latvia", Etsi),
        c(438, "Liechtenstein", Etsi), c(440, "Lithuania", Etsi), c(442, "Luxembourg", Etsi), c(470, "Malta", Etsi), c(528, "Netherlands", Etsi),
        c(578, "Norway", Etsi), c(616, "Poland", Etsi), c(620, "Portugal", Etsi), c(642, "Romania", Etsi), c(703, "Slovakia", Etsi), c(705, "Slovenia", Etsi),
        c(724, "Spain", Etsi), c(752, "Sweden", Etsi), c(756, "Switzerland", Etsi), c(826, "United Kingdom", Etsi), c(840, "United States", Fcc),
    ]
};

/// The rules of a country, if apctl has them.
fn rules_of(country: Option<i64>) -> Option<Rules> {
    let code = country?;
    COUNTRIES.iter().find(|c| c.code == code).map(|c| c.rules)
}

/// The site's country (ISO 3166 numeric), from the `country` setting.
pub(crate) fn country(state: &Value) -> Option<i64> {
    num(&setting(state, "country")["code"])
}

/// Legal primary channels for a band and width in the site's country (indoor,
/// or outdoor when `outdoor`). `None` when apctl has no rules for the country
/// or the band (6 GHz): nothing is restricted then, the AP's own regulatory
/// domain decides.
pub fn legal_channels(country: Option<i64>, band: &str, width: i64, outdoor: bool) -> Option<Vec<i64>> {
    Some(channel_blocks(rules_of(country)?, band, width, outdoor)?.into_iter().flatten().copied().collect())
}

/// [`legal_channels`] for one channel, without building the list: `None` when
/// apctl has no rules for the country or the band.
pub fn is_legal(country: Option<i64>, band: &str, width: i64, outdoor: bool, ch: i64) -> Option<bool> {
    Some(channel_blocks(rules_of(country)?, band, width, outdoor)?.into_iter().any(|b| b.contains(&ch)))
}

/// Whether an AP may be fixed on a channel at a width: by the country's rules
/// (indoor or outdoor), or where apctl has none, when the band has the channel
/// at that width. A band apctl has no channels for is not checked.
pub(crate) fn fixed_channel_ok(country: Option<i64>, band: &str, width: i64, outdoor: bool, ch: i64) -> bool {
    is_legal(country, band, width, outdoor, ch).unwrap_or_else(|| {
        let all = band_channels(band, width);
        all.is_empty() || all.contains(&ch)
    })
}

/// The legal channels of a band at a width: [`legal_channels`], or where apctl
/// has no rules, [`band_channels`].
pub(crate) fn allowed_channels(country: Option<i64>, band: &str, width: i64, outdoor: bool) -> Vec<i64> {
    legal_channels(country, band, width, outdoor).unwrap_or_else(|| band_channels(band, width))
}

/// A fixed channel of an AP's `radio_table` entry that [`fixed_channel_ok`] refuses at its width.
pub(crate) fn illegal_fixed_channel(country: Option<i64>, radio: &Value, outdoor: bool) -> Option<i64> {
    let ch = num(&radio["channel"])?;
    let width = num(&radio["ht"]).unwrap_or(20);
    (!fixed_channel_ok(country, radio["radio"].as_str().unwrap_or(""), width, outdoor, ch)).then_some(ch)
}

/// The legal channels of [`legal_channels`], as up to three runs of a table.
fn channel_blocks(rules: Rules, band: &str, width: i64, outdoor: bool) -> Option<[&'static [i64]; 3]> {
    const NG: [i64; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    const NA_LOW: &[i64] = &[36, 40, 44, 48, 52, 56, 60, 64];
    const NA_MID: &[i64] = &[100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140];
    const FCC_HIGH: &[i64] = &[144, 149, 153, 157, 161, 165];
    Some(match (band, rules) {
        ("ng", Rules::Etsi) => [&NG, &[], &[]],
        ("ng", Rules::Fcc) => [&NG[..11], &[], &[]],
        // 140 has no partner for 40 MHz; 132-140 make no 80 MHz block.
        ("na", Rules::Etsi) => [if outdoor { &[] } else { NA_LOW }, &NA_MID[..if width == 20 { 11 } else if width == 40 { 10 } else { 8 }], &[]],
        // 132-161 make no 160 MHz block; 165 is 20 MHz only.
        ("na", Rules::Fcc) => [NA_LOW, &NA_MID[..if width <= 80 { 11 } else { 8 }], &FCC_HIGH[..if width == 20 { 6 } else if width <= 80 { 5 } else { 0 }]],
        _ => return None,
    })
}

/// Every primary channel of a band at a width, where [`legal_channels`] has no
/// rules: the choices the editor offers, and what Channel AI starts from.
pub(crate) fn band_channels(band: &str, width: i64) -> Vec<i64> {
    match band {
        "ng" => (1..=13).collect(),
        // The US list holds every channel the European one does.
        "na" => channel_blocks(Rules::Fcc, "na", width, false).map(|b| b.into_iter().flatten().copied().collect()).unwrap_or_default(),
        // 1 to 233 in steps of 4; 233 has no partner for 40 MHz, 225-233 make no 80 MHz block.
        "6e" => (1..=233).step_by(4).filter(|c| width <= 20 || *c <= if width == 40 { 229 } else { 221 }).collect(),
        _ => Vec::new(),
    }
}

/// Whether outdoor channel rules apply to an AP (its own override, else the site's).
pub(crate) fn outdoor(state: &Value, d: &Value) -> bool {
    outdoor_with(d, mgmt_flag(state, "outdoor_mode_enabled"))
}

/// [`outdoor`] with the site's default given.
pub(crate) fn outdoor_with(d: &Value, site_default: bool) -> bool {
    match d["outdoor_mode_override"].as_str() {
        Some("on") => true,
        Some("off") => false,
        _ => site_default,
    }
}

/// Channel choices per width for the editor.
fn channels(state: &Value, band: &str, o: bool) -> Value {
    let c = country(state);
    let widths: &[i64] = if band == "ng" { &[20, 40] } else { &[20, 40, 80, 160] };
    let mut out = serde_json::Map::new();
    for w in widths {
        out.insert(w.to_string(), json!(allowed_channels(c, band, *w, o)));
    }
    Value::Object(out)
}

// ---- Validation helpers ---------------------------------------------------

/// A new settings document's id.
fn new_id() -> String {
    random_hex::<12>()
}

pub(crate) fn is_mac(s: &str) -> bool {
    s.parse::<inform::Mac>().is_ok()
}

fn bool_field(patch: &Value, key: &str) -> Result<Option<bool>, String> {
    match &patch[key] {
        Value::Null => Ok(None),
        Value::Bool(b) => Ok(Some(*b)),
        _ => Err(format!("{key} must be true or false")),
    }
}

fn int_field(patch: &Value, key: &str, lo: i64, hi: i64) -> Result<Option<i64>, String> {
    match &patch[key] {
        Value::Null => Ok(None),
        v => match num(v) {
            Some(n) if (lo..=hi).contains(&n) => Ok(Some(n)),
            _ => Err(format!("{key} must be a whole number from {lo} to {hi}")),
        },
    }
}

fn enum_field<'a>(patch: &'a Value, key: &str, allowed: &[&str]) -> Result<Option<&'a str>, String> {
    match &patch[key] {
        Value::Null => Ok(None),
        Value::String(s) if allowed.contains(&s.as_str()) => Ok(Some(s)),
        _ => Err(format!("{key} must be one of {}", allowed.join(", "))),
    }
}

/// A text field of a patch: `None` when absent; anything but a string is
/// refused, and so is text with control characters (tab, line breaks): the AP
/// config can't hold them, so what is saved would differ from what the AP gets.
pub(crate) fn str_field<'a>(patch: &'a Value, key: &str) -> Result<Option<&'a str>, String> {
    match &patch[key] {
        Value::Null => Ok(None),
        Value::String(s) if s.contains(char::is_control) => Err(format!("{key} must not hold control characters (tabs, line breaks)")),
        Value::String(s) => Ok(Some(s)),
        _ => Err(format!("{key} must be text")),
    }
}

/// A list of text (`key` names it in errors): `None` when absent; anything but
/// a list, or an element that is not a string, is refused.
pub(crate) fn str_list<'a>(v: &'a Value, key: &str) -> Result<Option<Vec<&'a str>>, String> {
    match v {
        Value::Null => Ok(None),
        Value::Array(a) => a.iter().map(|x| x.as_str().ok_or_else(|| format!("{key}: {x} is not text"))).collect::<Result<_, _>>().map(Some),
        _ => Err(format!("{key} must be a list of text")),
    }
}

/// A list of objects (`key` names it in errors): empty when absent; anything but a list is refused.
fn obj_list<'a>(v: &'a Value, key: &str) -> Result<&'a [Value], String> {
    match v {
        Value::Null => Ok(&[]),
        Value::Array(a) => Ok(a),
        _ => Err(format!("{key} must be a list")),
    }
}

fn mac_list(patch: &Value, key: &str) -> Result<Option<Vec<inform::Mac>>, String> {
    mac_list_value(&patch[key], key)
}

/// [`mac_list`] for the value itself (`key` names it in errors). Any form
/// `Mac` reads (`aa-bb-..`, bare hex, any case) is taken, and saved as
/// `aa:bb:..` (a `Mac` serialises so).
pub(crate) fn mac_list_value(v: &Value, key: &str) -> Result<Option<Vec<inform::Mac>>, String> {
    match v {
        Value::Null => Ok(None),
        Value::Array(a) => {
            let mut out = Vec::new();
            for m in a {
                let mac = m.as_str().and_then(|s| s.trim().parse::<inform::Mac>().ok()).ok_or_else(|| format!("{key}: {m} is not a MAC address"))?;
                out.push(mac);
            }
            dedup_in_order(&mut out);
            Ok(Some(out))
        }
        _ => Err(format!("{key} must be a list of MAC addresses")),
    }
}

// ---- SSIDs ----------------------------------------------------------------

/// A security choice as the official UI offers it, the fields it sets (each
/// with `wpa_mode` "wpa2") and how it reads for people.
struct Protection {
    name: &'static str,
    label: &'static str,
    security: &'static str,
    wpa3_support: bool,
    wpa3_transition: bool,
}

const PROTECTION: &[Protection] = &[
    Protection { name: "wpa2", label: "WPA2 Personal", security: "wpapsk", wpa3_support: false, wpa3_transition: false },
    Protection { name: "wpa2_wpa3", label: "WPA2/WPA3 Personal", security: "wpapsk", wpa3_support: true, wpa3_transition: true },
    Protection { name: "wpa3", label: "WPA3 Personal", security: "wpapsk", wpa3_support: true, wpa3_transition: false },
    Protection { name: "open", label: "Open", security: "open", wpa3_support: false, wpa3_transition: false },
];

/// An SSID's protection as the editor's rules read it: (WPA Personal, WPA3,
/// WPA2/WPA3 transition). The transition flag means nothing without WPA3.
fn psk_wpa3(w: &Value) -> (bool, bool, bool) {
    let wpa3 = w["wpa3_support"].as_bool().unwrap_or(false);
    (w["security"].as_str() == Some("wpapsk"), wpa3, wpa3 && w["wpa3_transition"].as_bool().unwrap_or(false))
}

/// The protection choice of a stored SSID, if it is one the editor offers.
/// An open SSID's `wpa_mode` means nothing.
fn protection_of(w: &Value) -> Option<&'static Protection> {
    let security = w["security"].as_str()?;
    if security != "open" && w["wpa_mode"].as_str().is_some_and(|m| m != "wpa2") {
        return None;
    }
    let (_, wpa3, transition) = psk_wpa3(w);
    PROTECTION.iter().find(|p| (p.security, p.wpa3_support, p.wpa3_transition) == (security, wpa3, transition))
}

/// How an SSID's security reads for people: the editor's choices by their
/// label, anything else from its fields.
pub(crate) fn security_label(w: &Value) -> String {
    if let Some(p) = protection_of(w) {
        return p.label.into();
    }
    match w["security"].as_str() {
        Some("open") => "Open".into(),
        Some("wpapsk") => format!("{} Personal", w["wpa_mode"].as_str().unwrap_or("wpa2").to_uppercase()),
        Some("wpaeap") => "WPA Enterprise".into(),
        Some(o) => o.to_string(),
        None => "?".into(),
    }
}

const MINRATE_NG: &[i64] = &[1000, 2000, 5500, 6000, 9000, 11000, 12000, 18000, 24000, 36000, 48000, 54000];
const MINRATE_NA: &[i64] = &[6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000];

fn find_wlan<'a>(state: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    doc_by_id_mut(state, "wlanconf", id)
}

fn wlan<'a>(state: &'a Value, id: &str) -> Option<&'a Value> {
    doc_by_id(state, "wlanconf", id)
}

fn default_group(state: &Value) -> Option<String> {
    hidden_doc_id(state, "apgroup", "default")
}

/// Sets which APs broadcast an SSID: all, or a list (kept in a hidden AP group
/// of its own, as the official controller does). The caller removes groups
/// left unused ([`prune_groups`]).
fn set_wlan_aps(state: &mut Value, id: &str, aps: Option<Vec<inform::Mac>>) -> Result<(), String> {
    let own = {
        let current: Vec<&str> = wlan(state, id).and_then(|w| w["ap_group_ids"].as_array()).into_iter().flatten().filter_map(Value::as_str).collect();
        docs(state, "apgroup").find(|g| g["for_wlanconf"].as_bool() == Some(true) && oid(g).is_some_and(|i| current.contains(&i))).and_then(id_of)
    };
    match aps {
        None => {
            let all = default_group(state).ok_or("the settings have no default AP group")?;
            let w = find_wlan(state, id).ok_or("unknown SSID")?;
            w["ap_group_mode"] = json!("all");
            w["ap_group_ids"] = json!([all]);
            w["broadcasting_aps"] = json!([]);
        }
        Some(macs) => {
            if macs.is_empty() {
                return Err("choose at least one AP, or broadcast from all of them".into());
            }
            let known = device_macs(state);
            if let Some(m) = macs.iter().find(|m| !known.contains(m)) {
                return Err(format!("{m} is not one of the APs"));
            }
            let gid = match own {
                Some(g) => {
                    if let Some(d) = doc_by_id_mut(state, "apgroup", &g) {
                        d["device_macs"] = json!(macs);
                    }
                    g
                }
                None => {
                    let g = new_id();
                    push_doc(state, "apgroup", json!({ "_id": g, "name": "devices_ap_group", "for_wlanconf": true, "attr_no_delete": false, "device_macs": macs }));
                    g
                }
            };
            let w = find_wlan(state, id).ok_or("unknown SSID")?;
            w["ap_group_mode"] = json!("devices");
            w["ap_group_ids"] = json!([gid]);
            w["broadcasting_aps"] = json!(macs);
        }
    }
    Ok(())
}

/// Removes the site's per-SSID AP groups no SSID uses any more, as its AP
/// group or as where one of its mDNS rules applies.
fn prune_groups(state: &mut Value) {
    let site = site_id(state).map(str::to_string);
    let ids = |v: &Value| v["ap_group_ids"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>();
    let used: Vec<String> = docs(state, "wlanconf").flat_map(|w| ids(w).into_iter().chain(w["mdns_proxy_custom"].as_array().into_iter().flatten().flat_map(ids))).collect();
    if let Some(groups) = state["apgroup"].as_array_mut() {
        groups.retain(|g| !in_site(site.as_deref(), g) || g["for_wlanconf"].as_bool() != Some(true) || oid(g).is_some_and(|i| used.iter().any(|u| u == i)));
    }
}

/// The APs an SSID is deployed to.
fn deployed_to(state: &Value, w: &Value) -> Vec<inform::Mac> {
    wlan_aps(state, w).unwrap_or_else(|| device_macs(state))
}

/// mDNS proxy rules: where each applies (all APs, specific ones, AP groups),
/// which services pass (all, chosen ones, none), and the networks it bridges.
fn check_mdns_rules(state: &Value, v: &Value) -> Result<Vec<Value>, String> {
    let rules = v.as_array().ok_or("mdns_proxy_custom must be a list")?;
    if rules.len() > 16 {
        return Err("at most 16 mDNS rules".into());
    }
    let aps = device_macs(state);
    let groups: Vec<&str> = docs(state, "apgroup").filter_map(oid).collect();
    let networks: Vec<&str> = docs(state, "networkconf").filter_map(oid).collect();
    let mut out = Vec::new();
    for (i, r) in rules.iter().enumerate() {
        let n = i + 1;
        let scope = enum_field(r, "ap_scope_mode", &["all", "specific", "group"])?.unwrap_or("all");
        let services = enum_field(r, "services_mode", &["all", "specific", "none"])?.unwrap_or("all");
        let mut rule = json!({ "ap_scope_mode": scope, "services_mode": services, "isolation_enabled": bool_field(r, "isolation_enabled")?.unwrap_or(false) });
        let ids = |key: &str| -> Result<Vec<&str>, String> { Ok(str_list(&r[key], &format!("mDNS rule {n}: {key}"))?.unwrap_or_default()) };
        let nets = ids("networkconf_ids")?;
        if let Some(bad) = nets.iter().find(|x| !networks.contains(x)) {
            return Err(format!("mDNS rule {n}: {bad} is not a network"));
        }
        rule["networkconf_ids"] = json!(nets);
        match scope {
            "specific" => {
                let macs = mac_list_value(&r["ap_macs"], &format!("mDNS rule {n}: ap_macs"))?.unwrap_or_default();
                if macs.is_empty() || macs.iter().any(|m| !aps.contains(m)) {
                    return Err(format!("mDNS rule {n}: choose the APs it applies on"));
                }
                rule["ap_macs"] = json!(macs);
            }
            "group" => {
                let g = ids("ap_group_ids")?;
                if g.is_empty() || g.iter().any(|x| !groups.contains(x)) {
                    return Err(format!("mDNS rule {n}: choose the AP groups it applies on"));
                }
                rule["ap_group_ids"] = json!(g);
            }
            _ => {}
        }
        if services == "specific" {
            let mut codes: Vec<&str> = Vec::new();
            for c in obj_list(&r["predefined_services"], &format!("mDNS rule {n}: predefined_services"))? {
                let code = c["code"].as_str().or(c.as_str()).unwrap_or("");
                if !apcfg::MDNS_SERVICES.iter().any(|(k, _, _)| *k == code) {
                    return Err(format!("mDNS rule {n}: {code} is not a known service"));
                }
                codes.push(code);
            }
            dedup_in_order(&mut codes);
            let custom_list = obj_list(&r["custom_services"], &format!("mDNS rule {n}: custom_services"))?;
            // apctl's own bound (the official controller sets none), as for the rules.
            if custom_list.len() > 32 {
                return Err(format!("mDNS rule {n}: at most 32 custom services"));
            }
            let mut custom = Vec::new();
            for c in custom_list {
                let address = c["address"].as_str().unwrap_or("").trim();
                let parts: Vec<&str> = address.split('.').collect();
                let ok = parts.len() == 3
                    && parts[0].len() > 1
                    && parts[0].len() <= 64
                    && parts[0].starts_with('_')
                    && parts[0][1..].chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                    && matches!(parts[1], "_tcp" | "_udp")
                    && parts[2] == "local";
                if !ok {
                    return Err(format!("mDNS rule {n}: {address} is not a service like _service._tcp.local"));
                }
                let name = c["name"].as_str().map(str::trim).filter(|x| !x.is_empty()).unwrap_or(address);
                custom.push(json!({ "address": address, "name": name.chars().take(64).collect::<String>() }));
            }
            if codes.is_empty() && custom.is_empty() {
                return Err(format!("mDNS rule {n}: choose at least one service"));
            }
            rule["predefined_services"] = json!(codes.iter().map(|c| json!({ "code": c })).collect::<Vec<_>>());
            rule["custom_services"] = json!(custom);
        }
        out.push(rule);
    }
    Ok(out)
}

/// A count the settings have over its limit: what is counted (an AP's band,
/// the broadcast-filter addresses, the MAC filters sharing an AP group), how
/// many, and the error that says so.
struct Over {
    what: String,
    count: usize,
    err: String,
}

/// Every count the settings have over its limit ([`wlan_limits`], [`list_limits`]).
fn over_limits(state: &Value) -> Vec<Over> {
    let mut out = wlan_limits(state);
    out.extend(list_limits(state));
    out
}

/// Refuses settings with a count over its limit that `before` (the
/// [`over_limits`] before the edit) did not have that high: an edit may not
/// go over a limit, but settings imported over one can still be edited
/// otherwise, and brought back under it a step at a time.
fn check_limits(before: &[Over], state: &Value) -> Result<(), String> {
    match over_limits(state).into_iter().find(|o| !before.iter().any(|b| b.what == o.what && b.count >= o.count)) {
        Some(o) => Err(o.err),
        None => Ok(()),
    }
}

/// The official limit of SSIDs per radio band on an AP: 4 when wireless
/// meshing is on (the radios keep slots for it), else 8 (7 with element
/// adoption). Disabled SSIDs count too. Returns the radios over it.
fn wlan_limits(state: &Value) -> Vec<Over> {
    let mut out = Vec::new();
    let setting_on = |key: &str, default: bool| setting(state, key)["enabled"].as_bool().unwrap_or(default);
    let (meshing, element_adopt) = (setting_on("connectivity", true), setting_on("element_adopt", false));
    // Each SSID's bands and the APs it goes to (`None`: all, sorted otherwise), worked out once.
    let wlans: Vec<(Vec<&str>, Option<Vec<inform::Mac>>)> =
        docs(state, "wlanconf").map(|w| (w["wlan_bands"].as_array().into_iter().flatten().filter_map(Value::as_str).collect(), wlan_aps(state, w))).collect();
    for d in docs(state, "devices") {
        let Some(mac) = doc_mac(&d["mac"]) else { continue };
        let name = device_label(d, mac);
        for (band, wb) in [("ng", "2g"), ("na", "5g"), ("6e", "6g")] {
            let radios: Vec<&Value> = d["radio_table"].as_array().into_iter().flatten().filter(|r| r["radio"].as_str() == Some(band)).collect();
            if radios.is_empty() {
                continue;
            }
            let limit = if meshing && radios.iter().all(|r| r["vwire_enabled"].as_bool() != Some(false)) {
                4
            } else if element_adopt {
                7
            } else {
                8
            };
            let count = wlans.iter().filter(|(bands, aps)| bands.contains(&wb) && aps.as_ref().is_none_or(|a| a.binary_search(&mac).is_ok())).count();
            if count > limit {
                out.push(Over { what: format!("{mac} {band}"), count, err: format!("{name} would have {count} SSIDs on its {} radio; it supports {limit}", band_name(band)) });
            }
        }
    }
    out
}

/// What Force Wi-Fi 4 (`enhanced_iot`) holds an SSID to, with each field's
/// name for errors: the official controller's IoT template, plus the features
/// its UI clears and its validation refuses alongside it.
static IOT_TEMPLATE: LazyLock<Vec<(&str, Value, &str)>> = LazyLock::new(|| {
    vec![
        ("wlan_bands", json!(["2g"]), "a band other than 2.4 GHz"),
        ("wpa3_support", json!(false), "WPA3"),
        ("wpa3_transition", json!(false), "WPA3"),
        ("wpa3_enhanced_192", json!(false), "WPA3"),
        ("wpa3_fast_roaming", json!(false), "WPA3 fast roaming"),
        ("pmf_mode", json!("disabled"), "PMF"),
        ("fast_roaming_enabled", json!(false), "fast roaming"),
        ("bss_transition", json!(false), "BSS transition"),
        ("proxy_arp", json!(false), "proxy ARP"),
        ("no2ghz_oui", json!(false), "band steering"),
        ("group_rekey", json!(0), "group rekey"),
        ("dtim_mode", json!("default"), "a custom DTIM period"),
        ("hotspot2conf_enabled", json!(false), "Hotspot 2.0"),
        ("mlo_enabled", json!(false), "MLO"),
        ("advertise_device_name_in_beacon", json!(false), "the AP name in beacons"),
        ("dns_assistance_mode", json!("off"), "DNS Assistance"),
        ("roaming_assistant_na_enabled", json!(false), "the roaming assistant"),
    ]
});

/// How a plain field of a patch is checked before it is copied.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Bool,
    Int(i64, i64),
    Enum(&'static [&'static str]),
}

use Kind::{Bool, Enum, Int};

/// Copies the fields of `fields` the patch sets into `doc`, each checked by its
/// kind. Fields with rules of their own are handled by hand around this.
pub(crate) fn copy_fields(p: &Value, doc: &mut Value, fields: &[(&str, Kind)]) -> Result<(), String> {
    for (key, kind) in fields {
        let v = match kind {
            Bool => bool_field(p, key)?.map(Value::from),
            Int(lo, hi) => int_field(p, key, *lo, *hi)?.map(Value::from),
            Enum(allowed) => enum_field(p, key, allowed)?.map(Value::from),
        };
        if let Some(v) = v {
            doc[*key] = v;
        }
    }
    Ok(())
}

/// An edit to one SSID: its id and the fields to change.
pub struct WlanEdit {
    pub id: String,
    pub patch: Value,
}

/// Applies an edit to one SSID, with the official controller's rules for each
/// field and the fields it derives on save.
pub fn apply_wlan(state: &mut Value, e: &WlanEdit) -> Result<String, String> {
    let over = over_limits(state);
    let (what, channels) = edit_wlan(state, e, &over)?;
    Ok(with_notes(what, &channels))
}

/// `what`, followed by the notes (each AP's channel moves), `; `-separated.
fn with_notes(what: String, notes: &[String]) -> String {
    if notes.is_empty() { what } else { format!("{what}; {}", notes.join("; ")) }
}

/// [`apply_wlan`], with the counts over their limits before the edit (see [`check_limits`]).
/// Returns what changed on the SSID and, apart, the channel moves the edit made on its APs.
fn edit_wlan(state: &mut Value, e: &WlanEdit, over: &[Over]) -> Result<(String, Vec<String>), String> {
    let (id, p) = (e.id.as_str(), &e.patch);
    let before = find_wlan(state, id).ok_or("unknown SSID")?.clone();
    if before["attr_no_edit"].as_bool() == Some(true) {
        return Err("this SSID cannot be edited".into());
    }
    let mut w = before.clone();
    let mut changed: Vec<&str> = Vec::new();

    if let Some(name) = str_field(p, "name")?.map(str::trim) {
        if name.is_empty() || name.len() > 32 {
            return Err("the network name (SSID) must be 1 to 32 bytes".into());
        }
        if docs(state, "wlanconf").any(|o| oid(o) != Some(id) && o["name"].as_str() == Some(name)) {
            return Err(format!("another SSID is already called \"{name}\""));
        }
        w["name"] = json!(name);
    }

    // Force Wi-Fi 4: turning it on clears what it can't be combined with, as the
    // official UI does; the edit is then checked against it at the end.
    let was_iot = before["enhanced_iot"].as_bool() == Some(true);
    copy_fields(p, &mut w, &[("enhanced_iot", Bool)])?;
    let iot = w["enhanced_iot"].as_bool() == Some(true);
    if iot && !was_iot {
        for (k, v, _) in IOT_TEMPLATE.iter() {
            w[*k] = v.clone();
        }
    }
    // What the edit's own fields are told apart from, below: the held fields as they are now.
    let iot_base: Option<Vec<Value>> = iot.then(|| IOT_TEMPLATE.iter().map(|(k, _, _)| w[*k].clone()).collect());

    copy_fields(
        p,
        &mut w,
        &[
            ("enabled", Bool), ("hide_ssid", Bool), ("is_guest", Bool), ("proxy_arp", Bool), ("l2_isolation", Bool), ("uapsd_enabled", Bool),
            ("bss_transition", Bool), ("mcastenhance_enabled", Bool), ("fast_roaming_enabled", Bool), ("country_beacon", Bool),
        ],
    )?;
    wlan_security(p, &mut w)?;
    let bands = wlan_bands(p, &mut w)?;
    wlan_roaming(p, &mut w, &bands)?;
    // Sent as they are; the official UI keeps but never shows the last three.
    // `log_level` is hostapd's level for this SSID; -1 leaves the AP's default.
    copy_fields(
        p,
        &mut w,
        &[("advertise_device_name_in_beacon", Bool), ("rrm_enabled", Bool), ("tdls_prohibit", Bool), ("p2p", Bool), ("p2p_cross_connect", Bool), ("log_level", Int(-1, 4))],
    )?;
    wlan_dns_and_mdns(state, p, &mut w)?;
    wlan_rates(p, &mut w)?;
    wlan_power_saving(p, &mut w)?;

    // MAC filter.
    copy_fields(p, &mut w, &[("mac_filter_enabled", Bool), ("mac_filter_policy", Enum(&["allow", "deny"]))])?;
    if let Some(list) = mac_list(p, "mac_filter_list")? {
        w["mac_filter_list"] = json!(list);
    }
    wlan_links(state, p, &mut w)?;

    if let Some(iot_base) = &iot_base {
        for ((k, v, what), base) in IOT_TEMPLATE.iter().zip(iot_base) {
            if w[*k] != *v {
                // The edit asked for it: refuse. Otherwise the stored value just goes.
                if w[*k] != *base {
                    return Err(format!("{what} is not available with Force Wi-Fi 4"));
                }
                w[*k] = v.clone();
            }
        }
        w["wlan_band"] = json!("2g");
    }
    wlan_password(p, &before, &mut w, &mut changed)?;

    let locked_aps_before = if before["iot_channel_lock"].as_bool() == Some(true) { deployed_to(state, &before) } else { Vec::new() };
    *find_wlan(state, id).ok_or("unknown SSID")? = w;
    // "aps": null means all APs; no "aps" leaves them as they are.
    if p.get("aps").is_some() {
        let aps = match &p["aps"] {
            Value::Null => None,
            v => mac_list_value(v, "aps")?,
        };
        set_wlan_aps(state, id, aps)?;
    }
    // A group can go with a change of APs or of the mDNS rules.
    prune_groups(state);
    check_limits(over, state)?;
    let channels = apply_channel_locks(state, &locked_aps_before, None);

    let after = wlan(state, id).ok_or("unknown SSID")?;
    let mut keys: Vec<&str> = after.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
    keys.retain(|k| *k != "x_passphrase" && before[*k] != after[*k]);
    changed.extend(keys);
    let name = after["name"].as_str().unwrap_or("?");
    let what = if changed.is_empty() { format!("SSID \"{name}\": nothing changed") } else { format!("SSID \"{name}\": {}", changed.join(", ")) };
    Ok((what, channels))
}

/// Protection, PMF and the WPA3 timers.
fn wlan_security(p: &Value, w: &mut Value) -> Result<(), String> {
    if !p["protection"].is_null() {
        let x = PROTECTION.iter().find(|x| p["protection"].as_str() == Some(x.name)).ok_or_else(|| {
            format!("protection must be one of {}", PROTECTION.iter().map(|x| x.name).collect::<Vec<_>>().join(", "))
        })?;
        w["security"] = json!(x.security);
        w["wpa_mode"] = json!("wpa2");
        w["wpa3_support"] = json!(x.wpa3_support);
        w["wpa3_transition"] = json!(x.wpa3_transition);
        if x.security == "wpapsk" {
            w["wpa_enc"] = json!("ccmp");
        }
        // The protection decides PMF unless the edit sets it too.
        if p["pmf_mode"].is_null() {
            w["pmf_mode"] = json!(match (x.wpa3_support, x.wpa3_transition) {
                (true, true) => "optional",
                (true, false) => "required",
                (false, _) => "disabled",
            });
        }
    }
    copy_fields(p, w, &[("pmf_mode", Enum(&["disabled", "optional", "required"]))])?;
    let (psk, wpa3, transition) = psk_wpa3(w);
    match (psk && wpa3, transition, w["pmf_mode"].as_str().unwrap_or("disabled")) {
        (true, false, m) if m != "required" => return Err("WPA3 needs protected management frames (PMF) set to required".into()),
        (true, true, "disabled") => return Err("WPA2/WPA3 needs protected management frames (PMF) optional or required".into()),
        _ => {}
    }
    // SAE timers (WPA3), seconds; the official UI starts both at 5.
    if wpa3 && !p["protection"].is_null() {
        for key in ["sae_anti_clogging", "sae_sync"] {
            if w[key].is_null() {
                w[key] = json!(5);
            }
        }
    }
    // `wpa3_fast_roaming`: fast roaming for WPA3 clients of a WPA2/WPA3 SSID (the official UI never sets it).
    copy_fields(p, w, &[("sae_anti_clogging", Int(1, 60)), ("sae_sync", Int(1, 60)), ("wpa3_fast_roaming", Bool)])?;
    Ok(())
}

/// The password, checked against the protection the SSID ends up with (`w`,
/// once Force Wi-Fi 4 has had its say).
fn wlan_password(p: &Value, before: &Value, w: &mut Value, changed: &mut Vec<&str>) -> Result<(), String> {
    let (psk, wpa3, transition) = psk_wpa3(w);
    let given = str_field(p, "passphrase")?;
    if psk && given.is_none() && w["x_passphrase"].as_str().is_none_or(str::is_empty) {
        return Err("a password is needed for WPA2/WPA3".into());
    }
    // A kept password is checked against the new protection too, however it
    // came about (Force Wi-Fi 4 turns WPA3 off): WPA3 allows up to 255
    // characters, and a longer one kept for WPA2 would reach the APs as a key
    // they cannot use.
    if given.is_some() || psk && (!p["protection"].is_null() || psk_wpa3(before) != psk_wpa3(w)) {
        let pass = given.or(w["x_passphrase"].as_str()).unwrap_or_default();
        let printable = pass.chars().all(|c| (' '..='~').contains(&c));
        let hex64 = pass.len() == 64 && pass.chars().all(|c| c.is_ascii_hexdigit());
        let wpa3_only = wpa3 && !transition;
        let ok = if wpa3_only { printable && (8..=255).contains(&pass.len()) } else { hex64 || printable && (8..=63).contains(&pass.len()) };
        if !ok {
            let rule = if wpa3_only { "the password must be 8 to 255 printable ASCII characters" } else { "the password must be 8 to 63 printable ASCII characters (or 64 hex digits)" };
            return Err(if given.is_some() { rule.into() } else { format!("{rule}: enter a new one for this protection") });
        }
    }
    if let Some(pass) = given {
        w["x_passphrase"] = json!(pass);
        changed.push("password");
    }
    Ok(())
}

/// The bands an SSID is broadcast on.
struct Bands {
    g2: bool,
    g5: bool,
    g6: bool,
}

/// The bands, and the `wlan_band` derived from them. Returns the bands.
fn wlan_bands(p: &Value, w: &mut Value) -> Result<Bands, String> {
    if !p["wlan_bands"].is_null() {
        let bands: Option<Vec<&str>> = p["wlan_bands"].as_array().ok_or("wlan_bands must be a list")?.iter().map(Value::as_str).collect();
        let mut bands = bands.filter(|b| !b.is_empty() && b.iter().all(|b| ["2g", "5g", "6g"].contains(b))).ok_or("choose at least one band: 2g, 5g or 6g")?;
        dedup_in_order(&mut bands);
        w["wlan_bands"] = json!(bands);
    }
    let on = |b: &str| w["wlan_bands"].as_array().into_iter().flatten().any(|x| x.as_str() == Some(b));
    let bands = Bands { g2: on("2g"), g5: on("5g"), g6: on("6g") };
    if bands.g6 && !(w["wpa3_support"].as_bool() == Some(true) || w["security"].as_str() == Some("open")) {
        return Err("6 GHz needs WPA3 (or an open network)".into());
    }
    w["wlan_band"] = json!(match bands {
        Bands { g2: true, g5: true, .. } => "both",
        Bands { g5: true, .. } => "5g",
        Bands { g2: false, g6: true, .. } => "6g",
        _ => "2g",
    });
    Ok(bands)
}

/// The roaming assistant, band steering and the IoT locks, which depend on the bands.
fn wlan_roaming(p: &Value, w: &mut Value, bands: &Bands) -> Result<(), String> {
    // Force Wi-Fi 4 holds the roaming assistant off (IOT_TEMPLATE).
    copy_fields(p, w, &[("roaming_assistant_na_enabled", Bool), ("roaming_assistant_na_rssi", Int(-80, -60))])?;

    // Band steering: dual-band clients the AP has seen on 5 GHz are kept off 2.4 GHz.
    let dual = bands.g2 && bands.g5;
    if let Some(b) = bool_field(p, "no2ghz_oui")? {
        if b && !dual {
            return Err("band steering needs both 2.4 and 5 GHz".into());
        }
        w["no2ghz_oui"] = json!(b);
    }
    if !dual && w["no2ghz_oui"].as_bool() == Some(true) {
        w["no2ghz_oui"] = json!(false);
    }

    // IoT locks: 2.4 GHz on channel 6 on every AP of the SSID, and a DTIM of 3
    // there. Both need 2.4 GHz and go when it does.
    for key in ["iot_channel_lock", "iot_dtim_lock"] {
        if let Some(b) = bool_field(p, key)? {
            if b && !bands.g2 {
                return Err("the IoT locks need 2.4 GHz".into());
            }
            w[key] = json!(b);
        }
        if !bands.g2 && w[key].as_bool() == Some(true) {
            w[key] = json!(false);
        }
    }
    Ok(())
}

/// DNS Assistance and the mDNS proxy.
fn wlan_dns_and_mdns(state: &Value, p: &Value, w: &mut Value) -> Result<(), String> {
    // DNS Assistance: the AP caches DNS and, when the network's server is slow
    // or fails, sends queries to fallback servers (its own choice, or these).
    copy_fields(p, w, &[("dns_assistance_mode", Enum(&["off", "auto", "manual"]))])?;
    if let Some(list) = str_list(&p["dns_assistance_servers"], "dns_assistance_servers")? {
        let mut servers: Vec<String> = Vec::new();
        for v in list {
            let ip = Some(v.trim()).filter(|s| !s.is_empty());
            match ip.map(|s| (s, s.parse::<std::net::Ipv4Addr>())) {
                None => {}
                Some((s, Ok(_))) => servers.push(s.to_string()),
                Some((s, Err(_))) => return Err(format!("DNS server {s} is not an IPv4 address")),
            }
        }
        dedup_in_order(&mut servers);
        if servers.len() > 2 {
            return Err("DNS Assistance takes at most 2 servers".into());
        }
        w["dns_assistance_servers"] = json!(servers);
    }
    if w["dns_assistance_mode"].as_str() == Some("manual") && w["dns_assistance_servers"].as_array().is_none_or(Vec::is_empty) {
        return Err("DNS Assistance set to manual needs at least one server".into());
    }

    // mDNS proxy: off, auto (the standard services within the SSID's own VLAN) or
    // custom rules.
    copy_fields(p, w, &[("mdns_proxy_mode", Enum(&["off", "auto", "custom"]))])?;
    if !p["mdns_proxy_custom"].is_null() {
        w["mdns_proxy_custom"] = json!(check_mdns_rules(state, &p["mdns_proxy_custom"])?);
    }
    if w["mdns_proxy_mode"].as_str() == Some("custom") && w["mdns_proxy_custom"].as_array().is_none_or(Vec::is_empty) {
        return Err("custom mDNS needs at least one rule".into());
    }
    Ok(())
}

/// Multicast and broadcast suppression, and the minimum data rates.
fn wlan_rates(p: &Value, w: &mut Value) -> Result<(), String> {
    // The suppression mode decides the broadcast filter.
    if let Some(m) = enum_field(p, "multicast_suppressor_mode", &["off", "conservative", "aggressive"])? {
        w["multicast_suppressor_mode"] = json!(m);
        w["bc_filter_enabled"] = json!(m == "aggressive");
        if m != "aggressive" {
            w["bc_filter_list"] = json!([]);
        }
    }
    if let Some(list) = mac_list(p, "bc_filter_list")? {
        w["bc_filter_list"] = json!(list);
    }

    copy_fields(p, w, &[("minrate_setting_preference", Enum(&["auto", "manual"]))])?;
    if let Some(r) = int_field(p, "minrate_ng_data_rate_kbps", 1000, 54000)? {
        if !MINRATE_NG.contains(&r) {
            return Err(format!("{r} kbps is not a 2.4 GHz rate"));
        }
        w["minrate_ng_data_rate_kbps"] = json!(r);
    }
    copy_fields(p, w, &[("minrate_na_enabled", Bool)])?;
    if let Some(r) = int_field(p, "minrate_na_data_rate_kbps", 6000, 54000)? {
        if !MINRATE_NA.contains(&r) {
            return Err(format!("{r} kbps is not a 5 GHz rate"));
        }
        w["minrate_na_data_rate_kbps"] = json!(r);
    }
    w["minrate_ng_enabled"] = json!(true);
    if w["minrate_setting_preference"].as_str() == Some("auto") {
        w["minrate_na_enabled"] = json!(false);
        w["minrate_na_data_rate_kbps"] = json!(6000);
        w["minrate_ng_data_rate_kbps"] = json!(1000);
    } else {
        w["minrate_setting_preference"] = json!("manual");
    }
    Ok(())
}

/// Power saving (DTIM) and group rekeying.
fn wlan_power_saving(p: &Value, w: &mut Value) -> Result<(), String> {
    copy_fields(p, w, &[("dtim_mode", Enum(&["default", "custom"])), ("dtim_ng", Int(1, 255)), ("dtim_na", Int(1, 255))])?;
    if w["dtim_mode"].as_str() != Some("custom") {
        w["dtim_ng"] = json!(1);
        w["dtim_na"] = json!(3);
        w["dtim_6e"] = json!(3);
    }
    if w["iot_dtim_lock"].as_bool() == Some(true) {
        if num(&p["dtim_ng"]).is_some_and(|n| n != 3) {
            return Err("the DTIM lock holds 2.4 GHz at 3".into());
        }
        w["dtim_ng"] = json!(3);
    }
    if let Some(n) = int_field(p, "group_rekey", 0, 86400)? {
        if n != 0 && n < 60 {
            return Err("group rekey must be off (0) or 60 to 86400 seconds".into());
        }
        w["group_rekey"] = json!(n);
    }
    Ok(())
}

/// What the SSID points at: its speed limit, blackout schedule and network.
fn wlan_links(state: &mut Value, p: &Value, w: &mut Value) -> Result<(), String> {
    // Speed limit: a user group; empty means the default group (no limit).
    if let Some(g) = str_field(p, "usergroup_id")? {
        let id = if g.is_empty() { ensure_default_usergroup(state) } else { g.to_string() };
        if doc_by_id(state, "usergroup", &id).is_none() {
            return Err("unknown speed limit".into());
        }
        w["usergroup_id"] = json!(id);
    }
    // Blackout schedule: periods the SSID is off.
    if !p["schedule_with_duration"].is_null() {
        w["schedule_with_duration"] = json!(check_schedule(&p["schedule_with_duration"])?);
    }
    if let Some(n) = str_field(p, "networkconf_id")? {
        let net = doc_by_id(state, "networkconf", n).ok_or("unknown network")?;
        // A network stored already (an import's, say) stays, whatever it is.
        if w["networkconf_id"].as_str() != Some(n) {
            ssid_network(net)?;
        }
        w["networkconf_id"] = json!(n);
    }
    Ok(())
}

/// Whether an SSID may be put on a network, as the official UI offers them: a
/// LAN one (corporate, guest or VLAN-only; one without a purpose is taken
/// too), not a WAN or VPN one, nor the inter-VLAN routing network (VLAN 4040).
fn ssid_network(net: &Value) -> Result<(), String> {
    let name = net["name"].as_str().unwrap_or("?");
    match net["purpose"].as_str().filter(|p| !p.is_empty()) {
        None | Some("corporate" | "guest" | "vlan-only") => {}
        Some(purpose) => return Err(format!("network \"{name}\" ({purpose}) cannot carry an SSID")),
    }
    if num(&net["vlan"]) == Some(4040) {
        return Err(format!("network \"{name}\" is the inter-VLAN routing network (VLAN 4040), which cannot carry an SSID"));
    }
    Ok(())
}

/// APs broadcasting an SSID with the IoT channel lock.
pub(crate) fn channel_locked_macs(state: &Value) -> Vec<inform::Mac> {
    let mut out: Vec<inform::Mac> = docs(state, "wlanconf").filter(|w| w["iot_channel_lock"].as_bool() == Some(true)).flat_map(|w| deployed_to(state, w)).collect();
    out.sort();
    out.dedup();
    out
}

/// Keeps the 2.4 GHz channel of APs in line with the SSIDs' channel locks, as
/// the official controller does when a lock changes: channel 6 on every AP an
/// SSID with the lock is broadcast from, and back to auto on an AP in
/// `released` (it had a locked SSID before the change) that has none left.
/// With `only`, that AP alone: a newly adopted one (see `adopt_device`).
/// Returns what changed, in words.
pub(crate) fn apply_channel_locks(state: &mut Value, released: &[inform::Mac], only: Option<&inform::Mac>) -> Vec<String> {
    let locked = channel_locked_macs(state);
    let mut out = Vec::new();
    for d in docs_mut(state, "devices") {
        let Some(mac) = doc_mac(&d["mac"]).filter(|m| only.is_none_or(|o| o == m)) else { continue };
        let target = if locked.contains(&mac) {
            json!("6")
        } else if released.contains(&mac) {
            json!("auto")
        } else {
            continue;
        };
        let name = device_label(d, mac);
        let Some(r) = inform_radio_mut(d, "ng") else { continue };
        if !same_channel(&r["channel"], &target) {
            r["channel"] = target.clone();
            out.push(format!("AP {name}: 2.4 GHz channel {}", target.as_str().unwrap_or_default()));
        }
    }
    out
}

/// Whether two radio `channel` values are the same channel: "auto", or a
/// number the settings may hold as a number or as a string.
fn same_channel(a: &Value, b: &Value) -> bool {
    match (num(a), num(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

const DAY_NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// Checks blackout periods: days `sun`..`sat`, a start time, and a duration of
/// at least a minute (apctl caps it at a week; the official controller has no cap).
fn check_schedule(v: &Value) -> Result<Vec<Value>, String> {
    let list = v.as_array().ok_or("the schedule must be a list")?;
    if list.len() > 50 {
        return Err("at most 50 blackout periods".into());
    }
    let mut out = Vec::new();
    for e in list {
        let days: Vec<String> = str_list(&e["start_days_of_week"], "start_days_of_week")?.unwrap_or_default().into_iter().map(str::to_ascii_lowercase).collect();
        if days.is_empty() || days.iter().any(|d| !DAY_NAMES.contains(&d.as_str())) {
            return Err("each blackout period needs its days (sun to sat)".into());
        }
        let hour = int_field(e, "start_hour", 0, 23)?.ok_or("each blackout period needs a start hour")?;
        let minute = int_field(e, "start_minute", 0, 59)?.unwrap_or(0);
        let duration = int_field(e, "duration_minutes", 1, 7 * 1440)?.ok_or("each blackout period needs a duration")?;
        let mut entry = json!({ "start_days_of_week": days, "start_hour": hour, "start_minute": minute, "duration_minutes": duration });
        if let Some(n) = e["name"].as_str().filter(|n| !n.is_empty()) {
            entry["name"] = json!(n.chars().take(64).collect::<String>());
        }
        out.push(entry);
    }
    Ok(out)
}

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
/// its `site_id`). Its id is the one most SSIDs point at (the first of a tie)
/// that no group has: an id a group has is a speed limit, not the default.
fn new_default_usergroup(state: &Value) -> Value {
    let mut uses: Vec<(&str, usize)> = Vec::new();
    for g in docs(state, "wlanconf").filter_map(|w| w["usergroup_id"].as_str()).filter(|g| !g.is_empty() && doc_by_id(state, "usergroup", g).is_none()) {
        match uses.iter_mut().find(|(id, _)| *id == g) {
            Some((_, n)) => *n += 1,
            None => uses.push((g, 1)),
        }
    }
    // max_by_key keeps the last of equals: reversed, that is the first seen.
    let id = uses.into_iter().rev().max_by_key(|(_, n)| *n).map_or_else(new_id, |(id, _)| id.to_string());
    json!({ "_id": id, "name": "Default", "attr_hidden_id": "Default", "attr_no_delete": true, "qos_rate_max_down": -1, "qos_rate_max_up": -1 })
}

/// The id of the site's default user group (no speed limit).
pub fn default_usergroup(state: &Value) -> Option<String> {
    hidden_doc_id(state, "usergroup", "Default")
}

/// Site-wide list limits: 256 broadcast-filter addresses in all, 512 MAC-filter
/// addresses over the SSIDs sharing an AP group. Returns the lists over them.
fn list_limits(state: &Value) -> Vec<Over> {
    let mut out = Vec::new();
    let len = |w: &Value, k: &str| w[k].as_array().map_or(0, Vec::len);
    let bc: usize = docs(state, "wlanconf").filter(|w| w["bc_filter_enabled"].as_bool() == Some(true)).map(|w| len(w, "bc_filter_list")).sum();
    if bc > 256 {
        out.push(Over { what: "bcfilter".into(), count: bc, err: format!("{bc} broadcast-filter addresses in all; the limit is 256") });
    }
    // As the official controller counts: the SSIDs sharing an AP group with
    // one (the default group counts as a group like any other).
    let wlans: Vec<(Vec<&str>, usize)> = docs(state, "wlanconf")
        .filter(|w| w["mac_filter_enabled"].as_bool() == Some(true))
        .map(|w| (w["ap_group_ids"].as_array().into_iter().flatten().filter_map(Value::as_str).collect(), len(w, "mac_filter_list")))
        .collect();
    for (g, _) in &wlans {
        let total: usize = wlans.iter().filter(|(o, _)| o.iter().any(|x| g.contains(x))).map(|(_, n)| n).sum();
        if total > 512 {
            out.push(Over { what: format!("macfilter {}", g.join(",")), count: total, err: format!("{total} MAC-filter addresses on SSIDs sharing an AP group; the limit is 512") });
        }
    }
    out
}

/// Creates an SSID (`patch` holds at least a name and, unless open, a
/// password) with the official controller's defaults for everything else.
/// A refused SSID leaves `state` half-changed: callers work on a copy (the
/// preview's, or the engine's, which is dropped on an error).
pub fn create_wlan(state: &mut Value, patch: &Value) -> Result<String, String> {
    // Counted before the new SSID is there: it adds to every count it is in.
    let over = over_limits(state);
    let site = site_id(state).ok_or("the settings have no APs")?.to_string();
    let all = default_group(state).ok_or("the settings have no default AP group")?;
    // The default network, when the patch names none (a named one is checked as an edit's is):
    // the hidden LAN one, else the first that may carry an SSID.
    let network = match str_field(patch, "networkconf_id")? {
        Some(_) => None,
        None => hidden_doc_id(state, "networkconf", "LAN").or_else(|| docs(state, "networkconf").find(|n| ssid_network(n).is_ok()).and_then(id_of)),
    };
    let usergroup = ensure_default_usergroup(state);
    let short_id = docs(state, "wlanconf").filter_map(|w| w["short_id"].as_i64()).max().unwrap_or(0) + 1;
    let id = new_id();
    let doc = json!({
        "_id": id, "site_id": site, "name": "", "enabled": true, "hide_ssid": false, "is_guest": false,
        "security": "wpapsk", "wpa_mode": "wpa2", "wpa_enc": "ccmp", "wpa3_support": false, "wpa3_transition": false, "pmf_mode": "disabled",
        "wlan_bands": ["2g", "5g"], "wlan_band": "both", "ap_group_mode": "all", "ap_group_ids": [all], "broadcasting_aps": [],
        "networkconf_id": network, "usergroup_id": usergroup, "iapp_enabled": true, "x_iapp_key": random_hex::<16>(), "short_id": short_id,
    });
    let rest = json!({
        "setting_preference": "manual", "bss_transition": true, "fast_roaming_enabled": false, "uapsd_enabled": false, "proxy_arp": false,
        "l2_isolation": false, "mcastenhance_enabled": false, "multicast_suppressor_mode": "off", "bc_filter_enabled": false, "bc_filter_list": [],
        "minrate_setting_preference": "auto", "dtim_mode": "default", "group_rekey": 0, "mac_filter_enabled": false, "mac_filter_policy": "allow",
        "mac_filter_list": [], "mdns_proxy_mode": "off", "roaming_assistant_na_enabled": false, "schedule_with_duration": [], "no2ghz_oui": true,
        "passphrase_autogenerated": false,
    });
    let mut doc = doc;
    if let (Some(d), Value::Object(r)) = (doc.as_object_mut(), rest) {
        d.extend(r);
    }
    let mut patch = patch.clone();
    if patch["name"].as_str().is_none_or(|n| n.trim().is_empty()) {
        return Err("the new SSID needs a name".into());
    }
    if patch["protection"].is_null() {
        patch["protection"] = json!("wpa2");
    }
    let name = patch["name"].as_str().unwrap_or_default().trim().to_string();
    array_mut(state, "wlanconf").push(doc);
    let (_, channels) = edit_wlan(state, &WlanEdit { id, patch }, &over)?;
    Ok(with_notes(format!("added SSID \"{name}\""), &channels))
}

/// Deletes an SSID and its own AP group.
pub fn delete_wlan(state: &mut Value, id: &str) -> Result<String, String> {
    let w = wlan(state, id).ok_or("unknown SSID")?;
    if w["attr_no_delete"].as_bool() == Some(true) {
        return Err("this SSID cannot be deleted".into());
    }
    let released = if w["iot_channel_lock"].as_bool() == Some(true) { deployed_to(state, w) } else { Vec::new() };
    let what = format!("deleted SSID \"{}\"", w["name"].as_str().unwrap_or("?"));
    remove_doc(state, "wlanconf", id);
    prune_groups(state);
    let channels = apply_channel_locks(state, &released, None);
    Ok(with_notes(what, &channels))
}

// ---- APs ------------------------------------------------------------------

/// An edit to one AP: name, LED, ..., and `radios` by band in `patch`.
pub struct DeviceEdit {
    pub mac: inform::Mac,
    pub patch: Value,
    /// What the AP reports about its radios, by band (power range, 160 MHz support).
    pub caps: HashMap<String, RadioCaps>,
    /// The band of the radio carrying the AP's wireless (mesh) uplink.
    pub wireless_uplink: Option<String>,
    /// The antennas the AP reports (`antenna_table`).
    pub antennas: Value,
}

/// Applies an edit to one AP, with the official controller's rules.
pub fn apply_device(state: &mut Value, e: &DeviceEdit) -> Result<String, String> {
    let m = e.mac;
    let p = &e.patch;
    let before = site_device(state, &m)?.clone();
    let mut d = before.clone();

    device_fields(state, e, &before, &mut d)?;
    // Outdoor mode changes which channels are legal.
    let o = outdoor(state, &d);
    // SSIDs locking this AP's 2.4 GHz channel for IoT devices.
    let iot_lock = channel_locked_macs(state).contains(&m);
    let radio_edits = obj_list(&p["radios"], "radios")?;
    for rp in radio_edits {
        radio_edit(e, rp, &before, &mut d, iot_lock)?;
    }

    // A fixed channel must be legal for its (possibly new) width, on the radios
    // edited, or on all of them when outdoor mode changed.
    let outdoor_changed = o != outdoor(state, &before);
    let c = country(state);
    for r in d["radio_table"].as_array().into_iter().flatten() {
        let band = r["radio"].as_str().unwrap_or("");
        let edited = radio_edits.iter().any(|rp| rp["radio"].as_str() == Some(band));
        if !edited && !outdoor_changed {
            continue;
        }
        if let Some(ch) = illegal_fixed_channel(c, r, o) {
            let label = band_name(band);
            return Err(if edited {
                format!("{label}: channel {ch} is not allowed at {} MHz here", num(&r["ht"]).unwrap_or(20))
            } else {
                format!("{label}: channel {ch} is not allowed {} here; pick another first", if o { "outdoors" } else { "indoors" })
            });
        }
    }
    let name = device_label(&d, m);
    let mut changed: Vec<String> = Vec::new();
    for k in DEVICE_FIELDS {
        if before[*k] != d[*k] {
            changed.push(k.replace('_', " "));
        }
    }
    fn radios(v: &Value) -> &[Value] {
        v["radio_table"].as_array().map_or(&[], Vec::as_slice)
    }
    for (b, a) in radios(&before).iter().zip(radios(&d)) {
        let keys: Vec<&str> = RADIO_FIELDS.iter().copied().filter(|k| b[*k] != a[*k]).collect();
        if !keys.is_empty() {
            changed.push(format!("{} radio: {}", band_name(a["radio"].as_str().unwrap_or("")), keys.join(", ")));
        }
    }
    *docs_mut(state, "devices").find(|d| doc_mac(&d["mac"]) == Some(m)).expect("found above") = d;
    Ok(if changed.is_empty() { format!("AP {name}: nothing changed") } else { format!("AP {name}: {}", changed.join("; ")) })
}

/// The AP-wide fields: name, LED, modes, SNMP, antenna and its own address.
fn device_fields(state: &Value, e: &DeviceEdit, before: &Value, d: &mut Value) -> Result<(), String> {
    let p = &e.patch;
    if let Some(name) = str_field(p, "name")? {
        let name = name.trim();
        if name.chars().count() > 128 {
            return Err("the name can be at most 128 characters".into());
        }
        d["name"] = json!(name);
    }
    copy_fields(p, d, &[("led_override", Enum(&["default", "on", "off"])), ("led_override_color_brightness", Int(0, 100))])?;
    if let Some(c) = str_field(p, "led_override_color")? {
        d["led_override_color"] = json!(led_color(c)?);
    }
    copy_fields(
        p,
        d,
        &[
            ("outdoor_mode_override", Enum(&["default", "on", "off"])), ("bandsteering_mode", Enum(&["off", "equal", "prefer_5g"])),
            ("resetbtn_enabled", Enum(&["on", "off"])),
        ],
    )?;
    for key in ["snmp_location", "snmp_contact"] {
        if let Some(v) = str_field(p, key)?.map(str::trim) {
            if v.chars().count() > 255 {
                return Err(format!("{} can be at most 255 characters", key.replace('_', " ")));
            }
            d[key] = json!(v);
        }
    }
    copy_fields(p, d, &[("atf_enabled", Bool), ("green_ap_enabled", Bool), ("jumboframe_enabled", Bool)])?;
    // The antenna, from those the AP reports; each radio's gain follows it, as in
    // the official UI (which offers the choice only with two or more antennas).
    if let Some(a) = int_field(p, "antenna_id", 0, 9)? {
        let entry = e.antennas.as_array().into_iter().flatten().find(|x| x["id"].as_i64() == Some(a)).ok_or_else(|| format!("this AP has no antenna {a}"))?;
        for r in d["radio_table"].as_array_mut().into_iter().flatten() {
            let gain = r["name"].as_str().and_then(|n| entry[format!("{n}_gain")].as_i64()).unwrap_or(6);
            r["antenna_id"] = json!(a);
            r["antenna_gain"] = json!(gain);
        }
    }
    if !p["config_network"].is_null() {
        let cn = check_config_network(&p["config_network"], &before["config_network"])?;
        if let Some(ip) = cn["ip"].as_str() {
            check_ip_free(state, &e.mac, ip)?;
        }
        d["config_network"] = cn;
    }
    Ok(())
}

/// An edit to one of the AP's radios (`rp`, by band): width, channel, power and
/// the rest, checked against what the radio reports ([`apply_device`] then checks a fixed channel against the country).
fn radio_edit(e: &DeviceEdit, rp: &Value, before: &Value, d: &mut Value, iot_lock: bool) -> Result<(), String> {
    let band = rp["radio"].as_str().ok_or("each radio needs its band (radio)")?;
    let caps = e.caps.get(band).copied().unwrap_or_default();
    let label = band_name(band);
    let r = inform_radio_mut(d, band).ok_or_else(|| format!("this AP has no {label} radio"))?;
    if let Some(ht) = int_field(rp, "ht", 20, 320)? {
        let ok = match band {
            "ng" => [20, 40].contains(&ht),
            "na" | "6e" => [20, 40, 80].contains(&ht) || ht == 160 && caps.has_ht160,
            _ => false,
        };
        if !ok {
            return Err(format!("{label}: {ht} MHz is not available on this radio"));
        }
        r["ht"] = json!(ht);
    }
    match &rp["channel"] {
        Value::Null => {}
        Value::String(a) if a == "auto" => r["channel"] = json!("auto"),
        v => {
            let ch = num(v).ok_or_else(|| format!("{label}: channel must be auto or a number"))?;
            // Whatever the country, it must be one of the band's channels (those the editor offers).
            if !band_channels(band, 20).contains(&ch) {
                return Err(format!("{label}: {ch} is not a channel of this band"));
            }
            r["channel"] = json!(ch);
        }
    }
    // The official controller refuses any change here, which strands an AP
    // that came under the lock on another channel (one adopted after the lock
    // was switched on stays on auto there); a change to the lock's channel is
    // let through, so such an AP can join it.
    if band == "ng" && iot_lock && !same_channel(&r["channel"], inform_radio(before, band).map_or(&Value::Null, |x| &x["channel"])) && !same_channel(&r["channel"], &json!(6)) {
        return Err("the 2.4 GHz channel is locked by an SSID's IoT setting: it can only go to 6".into());
    }
    copy_fields(rp, r, &[("tx_power_mode", Enum(&["auto", "high", "medium", "low", "custom", "disabled"]))])?;
    let (lo, hi) = (caps.min_txpower, caps.max_txpower);
    if let Some(tx) = int_field(rp, "tx_power", lo, hi).map_err(|_| format!("{label}: power must be {lo} to {hi} dBm"))? {
        r["tx_power"] = json!(tx);
    }
    copy_fields(rp, r, &[("min_rssi_enabled", Bool), ("min_rssi", Int(-90, -67))])?;
    if let Some(b) = bool_field(rp, "hard_noise_floor_enabled")? {
        if b && !has_blocker(r) {
            return Err(format!("{label}: this radio has no interference blocker"));
        }
        r["hard_noise_floor_enabled"] = json!(b);
    }
    copy_fields(
        rp,
        r,
        &[("vwire_enabled", Bool), ("sens_level_enabled", Bool), ("loadbalance_enabled", Bool), ("sens_level", Int(-90, -50)), ("maxsta", Int(1, 200))],
    )?;
    if r["tx_power_mode"].as_str() == Some("disabled") && e.wireless_uplink.as_deref() == Some(band) {
        return Err(format!("{label}: this radio carries the AP's wireless uplink, so it cannot be turned off"));
    }
    Ok(())
}

/// The AP's own address: DHCP, or static with an address, netmask, a gateway
/// on that subnet, a DNS server (a second one and a search domain optional).
fn check_config_network(p: &Value, before: &Value) -> Result<Value, String> {
    use std::net::Ipv4Addr;
    let ip = |key: &str| -> Result<Option<Ipv4Addr>, String> {
        match str_field(p, key)?.map(str::trim).filter(|s| !s.is_empty()) {
            None => Ok(None),
            Some(s) => s.parse().map(Some).map_err(|_| format!("{key}: {s} is not an IPv4 address")),
        }
    };
    let req_ip = |key: &str| ip(key)?.ok_or_else(|| format!("a static address needs {key}"));
    let mut out = json!({ "type": "dhcp" });
    if let Some(b) = before["bonding_enabled"].as_bool() {
        out["bonding_enabled"] = json!(b);
    }
    match p["type"].as_str() {
        Some("dhcp") => return Ok(out),
        Some("static") => {}
        _ => return Err("config_network.type must be dhcp or static".into()),
    }
    let addr = req_ip("ip")?;
    let mask = req_ip("netmask")?;
    let m = u32::from(mask);
    if m == 0 || m.leading_ones() + m.trailing_zeros() != 32 || m.trailing_zeros() < 2 {
        return Err(format!("{mask} is not a usable netmask"));
    }
    let net = u32::from(addr) & m;
    if u32::from(addr) == net || u32::from(addr) == net | !m {
        return Err(format!("{addr} is the network or broadcast address of its subnet"));
    }
    out["type"] = json!("static");
    out["ip"] = json!(addr.to_string());
    out["netmask"] = json!(mask.to_string());
    // The official UI also needs a gateway and a DNS server; the subnet check is ours.
    let gw = req_ip("gateway")?;
    if u32::from(gw) & m != net || gw == addr {
        return Err(format!("the gateway {gw} must be another address on {}/{}", Ipv4Addr::from(net), m.leading_ones()));
    }
    out["gateway"] = json!(gw.to_string());
    out["dns1"] = json!(req_ip("dns1")?.to_string());
    if let Some(d) = ip("dns2")? {
        out["dns2"] = json!(d.to_string());
    }
    if let Some(suffix) = str_field(p, "dnssuffix")?.map(str::trim).filter(|s| !s.is_empty()) {
        if !crate::site::is_domain_name(suffix) {
            return Err(format!("{suffix} is not a domain name"));
        }
        out["dnssuffix"] = json!(suffix);
    }
    Ok(out)
}

/// A static address must not be another AP's, or one reserved for a client.
fn check_ip_free(state: &Value, mac: &inform::Mac, ip: &str) -> Result<(), String> {
    if let Some(o) = docs(state, "devices").find(|o| doc_mac(&o["mac"]) != Some(*mac) && o["config_network"]["type"].as_str() == Some("static") && o["config_network"]["ip"].as_str() == Some(ip)) {
        return Err(format!("{ip} is already {}'s address", record_label(o, "another AP")));
    }
    if let Some(c) = docs(state, "clients").find(|c| c["use_fixedip"].as_bool() == Some(true) && c["fixed_ip"].as_str() == Some(ip)) {
        return Err(format!("{ip} is reserved for the client {}", client_label(c)));
    }
    Ok(())
}

/// An LED colour as `#rrggbb` (the AP config takes six hex digits).
fn led_color(c: &str) -> Result<String, String> {
    let hex = c.trim().trim_start_matches('#');
    let full: String = match hex.len() {
        3 => hex.chars().flat_map(|x| [x, x]).collect(),
        6 => hex.to_string(),
        _ => String::new(),
    };
    if full.is_empty() || !full.chars().all(|x| x.is_ascii_hexdigit()) {
        return Err(format!("{c} is not a colour like #0000ff"));
    }
    Ok(format!("#{}", full.to_ascii_lowercase()))
}

// ---- Handlers -------------------------------------------------------------

#[derive(Deserialize)]
pub struct Patch {
    #[serde(default)]
    pub(crate) patch: Value,
}

/// PUT /api/settings/wlans/{id} {patch} (`?preview=true` to see the effect)
pub async fn put_wlan(State(s): State<AppState>, Path(id): Path<String>, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    change(&s, &q, apply_wlan, WlanEdit { id, patch: b.patch }).await
}

/// POST /api/settings/wlans {patch}
pub async fn post_wlan(State(s): State<AppState>, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    change(&s, &q, create_wlan, b.patch).await
}

/// DELETE /api/settings/wlans/{id}
pub async fn delete_wlan_route(State(s): State<AppState>, Path(id): Path<String>, Query(q): Query<PreviewQuery>) -> Result<Json<Value>, ApiError> {
    change(&s, &q, |state: &mut Value, id: &String| delete_wlan(state, id), id).await
}

/// PUT /api/settings/devices/{mac} {patch}
pub async fn put_device(State(s): State<AppState>, MacPath(mac): MacPath, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    let inform = s.live.read().unwrap().raw_informs.get(&mac).cloned();
    let caps = RadioCaps::of_inform(inform.as_deref());
    // A mesh AP's uplink radio must stay on.
    let wireless_uplink = match inform.as_deref().map(uplink) {
        Some(Uplink::Wireless(band)) => band,
        _ => None,
    };
    let antennas = inform.as_deref().map_or(Value::Null, |p| p["antenna_table"].clone());
    change(&s, &q, apply_device, DeviceEdit { mac, patch: b.patch, caps, wireless_uplink, antennas }).await
}

/// How an AP reaches the network.
#[derive(Debug, PartialEq)]
pub(crate) enum Uplink {
    Wired,
    /// Over Wi-Fi (mesh), with the band of the radio it runs on when known.
    Wireless(Option<String>),
}

impl Uplink {
    pub fn is_wireless(&self) -> bool {
        matches!(self, Uplink::Wireless(_))
    }
}

/// How an AP reaches the network, from its (full) inform. `uplink` names the
/// uplink interface: missing, empty or `eth...` when wired; else the AP's own
/// station VAP, which `vap_table` lists by `name` (`mld_name` for a
/// multi-link one) with its band in `radio`, as the official controller reads
/// it. An AP that lost its mesh uplink (isolated) names a placeholder that is
/// no VAP: still wireless, on an unknown band.
pub(crate) fn uplink(p: &Value) -> Uplink {
    let Some(up) = p["uplink"].as_str().filter(|u| !u.is_empty() && !u.starts_with("eth")) else { return Uplink::Wired };
    let vap = p["vap_table"].as_array().into_iter().flatten().find(|v| v["name"].as_str() == Some(up) || v["mld_name"].as_str() == Some(up));
    Uplink::Wireless(vap.and_then(|v| v["radio"].as_str()).map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP1: &str = "02:00:00:00:00:01";
    const AP2: &str = "02:00:00:00:00:02";

    fn state() -> Value {
        let radio = |band: &str, ch: Value, ht: i64| json!({ "name": if band == "ng" { "wifi0" } else { "wifi1" }, "radio": band, "channel": ch, "ht": ht, "tx_power_mode": "auto", "radio_caps": 131072 });
        json!({
            "devices": [
                { "mac": AP1, "name": "Hall", "site_id": "s1", "radio_table": [radio("ng", json!(1), 20), radio("na", json!(44), 80)] },
                { "mac": AP2, "name": "Attic", "site_id": "s1", "radio_table": [radio("ng", json!("auto"), 20), radio("na", json!(48), 80)] },
            ],
            "apgroup": [{ "_id": { "$oid": "g0" }, "name": "All APs", "attr_hidden_id": "default", "site_id": "s1" }],
            "networkconf": [{ "_id": "n1", "name": "LAN", "attr_hidden_id": "LAN", "site_id": "s1" }],
            "setting": [{ "key": "country", "code": "276", "site_id": "s1" }, { "key": "connectivity", "enabled": false, "site_id": "s1" }],
            "wlanconf": [{
                "_id": { "$oid": "w1" }, "site_id": "s1", "name": "Home", "enabled": true, "security": "wpapsk", "wpa_mode": "wpa2", "wpa3_support": false,
                "wpa3_transition": false, "pmf_mode": "disabled", "x_passphrase": "correct horse", "wlan_bands": ["2g", "5g"], "ap_group_mode": "all",
                "ap_group_ids": ["g0"], "short_id": 2, "minrate_setting_preference": "manual", "minrate_ng_data_rate_kbps": 6000,
            }],
        })
    }

    fn edit(s: &mut Value, patch: Value) -> Result<String, String> {
        apply_wlan(s, &WlanEdit { id: "w1".into(), patch })
    }

    #[test]
    fn protection_sets_wpa3_and_pmf_as_the_official_ui_does() {
        let mut s = state();
        edit(&mut s, json!({ "protection": "wpa2_wpa3" })).unwrap();
        let w = &s["wlanconf"][0];
        assert_eq!((w["wpa3_support"].as_bool(), w["wpa3_transition"].as_bool(), w["pmf_mode"].as_str()), (Some(true), Some(true), Some("optional")));
        assert_eq!(protection_of(w).map(|p| p.name), Some("wpa2_wpa3"));
        assert!(edit(&mut s, json!({ "pmf_mode": "disabled" })).unwrap_err().contains("PMF"));
        edit(&mut s, json!({ "protection": "wpa3" })).unwrap();
        assert_eq!(s["wlanconf"][0]["pmf_mode"], "required");
        assert!(edit(&mut s, json!({ "pmf_mode": "optional" })).is_err(), "WPA3 alone needs PMF required");
        // Each choice reads by its label; anything else from its fields.
        let label = |w: Value| security_label(&w);
        assert_eq!(label(s["wlanconf"][0].clone()), "WPA3 Personal");
        assert_eq!(label(json!({ "security": "wpapsk", "wpa_mode": "wpa2", "wpa3_support": true, "wpa3_transition": true })), "WPA2/WPA3 Personal");
        assert_eq!(label(json!({ "security": "wpapsk", "wpa_mode": "wpa1" })), "WPA1 Personal");
        assert_eq!((label(json!({ "security": "open", "wpa3_support": true })), label(json!({ "security": "wpaeap" }))), ("Open".into(), "WPA Enterprise".into()));
    }

    #[test]
    fn dns_assistance_needs_ipv4_servers_when_manual() {
        let mut s = state();
        assert!(edit(&mut s, json!({ "dns_assistance_mode": "manual" })).unwrap_err().contains("at least one server"));
        assert!(edit(&mut s, json!({ "dns_assistance_mode": "manual", "dns_assistance_servers": ["fd00::1"] })).is_err(), "IPv4 only");
        edit(&mut s, json!({ "dns_assistance_mode": "manual", "dns_assistance_servers": [" 192.168.1.1", "", "9.9.9.9"] })).unwrap();
        assert_eq!(s["wlanconf"][0]["dns_assistance_servers"], json!(["192.168.1.1", "9.9.9.9"]));
        // The list is kept for later when the mode changes.
        edit(&mut s, json!({ "dns_assistance_mode": "auto" })).unwrap();
        assert_eq!(s["wlanconf"][0]["dns_assistance_servers"][1], "9.9.9.9");
        assert!(edit(&mut s, json!({ "dns_assistance_mode": "fallback" })).is_err());
    }

    #[test]
    fn text_fields_refuse_anything_but_text() {
        let mut s = state();
        for (k, v) in [("passphrase", json!(12345678)), ("name", json!(5)), ("usergroup_id", json!(3)), ("networkconf_id", json!(false))] {
            assert_eq!(edit(&mut s, json!({ k: v })).unwrap_err(), format!("{k} must be text"));
        }
        for (k, v) in [("name", json!(5)), ("led_override_color", json!(255)), ("snmp_location", json!(["x"]))] {
            assert_eq!(dev(&mut s, json!({ k: v })).unwrap_err(), format!("{k} must be text"));
        }
        assert!(dev(&mut s, json!({ "config_network": { "type": "static", "ip": "192.168.1.20", "netmask": "255.255.255.0", "gateway": "192.168.1.1", "dns1": "192.168.1.1", "dns2": 9 } })).unwrap_err().contains("dns2"));
        assert_eq!(s["wlanconf"][0]["x_passphrase"], "correct horse");
        assert_eq!(edit(&mut s, json!({ "dns_assistance_servers": [5] })).unwrap_err(), "dns_assistance_servers: 5 is not text");
        assert_eq!(edit(&mut s, json!({ "dns_assistance_servers": "1.1.1.1" })).unwrap_err(), "dns_assistance_servers must be a list of text");
        // Control characters would be dropped from the AP's config: refused.
        assert!(edit(&mut s, json!({ "name": "Ho\tme" })).unwrap_err().contains("control characters"));
        for (k, v) in [("name", "Hall\n"), ("snmp_location", "attic\u{7}")] {
            assert_eq!(dev(&mut s, json!({ k: v })).unwrap_err(), format!("{k} must not hold control characters (tabs, line breaks)"));
        }
    }

    #[test]
    fn band_steering_needs_both_bands_and_hidden_toggles_are_kept() {
        let mut s = state();
        edit(&mut s, json!({ "no2ghz_oui": true, "rrm_enabled": true, "tdls_prohibit": true, "log_level": 2 })).unwrap();
        assert!(edit(&mut s, json!({ "log_level": 7 })).is_err());
        // Dropping a band turns band steering off; enabling it then is refused.
        let what = edit(&mut s, json!({ "wlan_bands": ["5g"] })).unwrap();
        assert!(what.contains("no2ghz_oui"), "{what}");
        assert!(edit(&mut s, json!({ "no2ghz_oui": true })).unwrap_err().contains("both"));
        let w = &s["wlanconf"][0];
        assert_eq!((w["rrm_enabled"].as_bool(), w["tdls_prohibit"].as_bool(), w["log_level"].as_i64()), (Some(true), Some(true), Some(2)));
        // Each band once; anything but a band's name is refused.
        assert!(edit(&mut s, json!({ "wlan_bands": ["5g", 2] })).is_err());
        edit(&mut s, json!({ "wlan_bands": ["2g", "5g", "2g"] })).unwrap();
        assert_eq!((&s["wlanconf"][0]["wlan_bands"], s["wlanconf"][0]["wlan_band"].as_str()), (&json!(["2g", "5g"]), Some("both")));
    }

    #[test]
    fn force_wifi4_clears_and_then_holds_the_newer_features() {
        let mut s = state();
        edit(&mut s, json!({ "protection": "wpa2_wpa3", "proxy_arp": true, "dns_assistance_mode": "auto", "no2ghz_oui": true })).unwrap();
        edit(&mut s, json!({ "enhanced_iot": true })).unwrap();
        let w = &s["wlanconf"][0];
        assert_eq!(w["wlan_bands"], json!(["2g"]));
        assert_eq!((w["wpa3_support"].as_bool(), w["pmf_mode"].as_str(), w["proxy_arp"].as_bool()), (Some(false), Some("disabled"), Some(false)));
        assert_eq!((w["dns_assistance_mode"].as_str(), w["no2ghz_oui"].as_bool()), (Some("off"), Some(false)));
        assert_eq!(protection_of(w).map(|p| p.name), Some("wpa2"));
        // While it is on, asking for one of them is refused.
        assert!(edit(&mut s, json!({ "dns_assistance_mode": "auto" })).unwrap_err().contains("Force Wi-Fi 4"));
        assert!(edit(&mut s, json!({ "wlan_bands": ["2g", "5g"] })).is_err());
        assert!(edit(&mut s, json!({ "protection": "wpa3" })).is_err());
        edit(&mut s, json!({ "enhanced_iot": false, "wlan_bands": ["2g", "5g"] })).unwrap();
    }

    #[test]
    fn an_imported_force_wifi4_ssid_with_the_roaming_assistant_can_be_edited() {
        let mut s = state();
        let w = &mut s["wlanconf"][0];
        (w["enhanced_iot"], w["wlan_bands"], w["roaming_assistant_na_enabled"]) = (json!(true), json!(["2g"]), json!(true));
        // The stored value goes with the save; asking for it is refused.
        let what = edit(&mut s, json!({ "name": "Things" })).unwrap();
        assert!(what.contains("roaming_assistant_na_enabled"), "{what}");
        assert_eq!((s["wlanconf"][0]["name"].as_str(), s["wlanconf"][0]["roaming_assistant_na_enabled"].as_bool()), (Some("Things"), Some(false)));
        assert!(edit(&mut s, json!({ "roaming_assistant_na_enabled": true })).unwrap_err().contains("roaming assistant"));
    }

    #[test]
    fn force_wifi4_checks_a_kept_wpa3_password() {
        let mut s = state();
        edit(&mut s, json!({ "protection": "wpa3", "wlan_bands": ["2g"], "passphrase": "p".repeat(100) })).unwrap();
        // Turning WPA3 off this way leaves WPA2, where 100 characters are no key.
        assert!(edit(&mut s, json!({ "enhanced_iot": true })).unwrap_err().contains("enter a new one"));
        edit(&mut s, json!({ "enhanced_iot": true, "passphrase": "short enough" })).unwrap();
        assert_eq!(protection_of(&s["wlanconf"][0]).map(|p| p.name), Some("wpa2"));
        // A kept password that fits passes as before.
        let mut s = state();
        edit(&mut s, json!({ "protection": "wpa2_wpa3" })).unwrap();
        edit(&mut s, json!({ "enhanced_iot": true })).unwrap();
    }

    #[test]
    fn the_channel_lock_moves_its_aps_to_6_and_back() {
        let mut s = state();
        let what = edit(&mut s, json!({ "iot_channel_lock": true })).unwrap();
        assert!(what.contains("Hall: 2.4 GHz channel 6") && what.contains("Attic"), "{what}");
        assert_eq!(s["devices"][0]["radio_table"][0]["channel"], "6");
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "ng", "channel": 1 }] })).is_err());
        // Narrowed to one AP: the other is released.
        edit(&mut s, json!({ "aps": [AP1] })).unwrap();
        assert_eq!((s["devices"][0]["radio_table"][0]["channel"].as_str(), s["devices"][1]["radio_table"][0]["channel"].as_str()), (Some("6"), Some("auto")));
        // Dropping 2.4 GHz ends the lock.
        edit(&mut s, json!({ "wlan_bands": ["5g"] })).unwrap();
        assert_eq!(s["wlanconf"][0]["iot_channel_lock"], false);
        assert_eq!(s["devices"][0]["radio_table"][0]["channel"], "auto");
        assert!(edit(&mut s, json!({ "iot_dtim_lock": true })).is_err());
        // A new SSID with the lock reports its APs' moves too.
        let what = create_wlan(&mut s, &json!({ "name": "IoT", "passphrase": "password1", "iot_channel_lock": true })).unwrap();
        assert!(what.starts_with("added SSID \"IoT\"; ") && what.contains("Hall: 2.4 GHz channel 6"), "{what}");
    }

    #[test]
    fn dtim_lock_and_sae_timers() {
        let mut s = state();
        edit(&mut s, json!({ "iot_dtim_lock": true })).unwrap();
        assert_eq!(s["wlanconf"][0]["dtim_ng"], 3);
        assert!(edit(&mut s, json!({ "dtim_mode": "custom", "dtim_ng": 1 })).is_err());
        assert!(edit(&mut s, json!({ "dtim_mode": "custom", "dtim_ng": "1" })).is_err(), "a number as text is held to the lock too");
        edit(&mut s, json!({ "protection": "wpa3" })).unwrap();
        assert!(edit(&mut s, json!({ "passphrase": "short" })).unwrap_err().contains("8 to 255"));
        assert_eq!((s["wlanconf"][0]["sae_anti_clogging"].as_i64(), s["wlanconf"][0]["sae_sync"].as_i64()), (Some(5), Some(5)));
        assert!(edit(&mut s, json!({ "sae_sync": 61 })).is_err());
        edit(&mut s, json!({ "sae_sync": 10 })).unwrap();
        assert!(edit(&mut s, json!({ "dns_assistance_mode": "manual", "dns_assistance_servers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"] })).is_err());
    }

    #[test]
    fn mdns_rules_are_checked() {
        let mut s = state();
        assert!(edit(&mut s, json!({ "mdns_proxy_mode": "custom" })).unwrap_err().contains("at least one rule"));
        let rule = json!({ "ap_scope_mode": "specific", "ap_macs": [AP2.to_uppercase(), format!(" {AP2}")], "services_mode": "specific",
            "predefined_services": [{ "code": "apple_airPlay" }, { "code": "apple_airPlay" }], "custom_services": [{ "address": "_myapp._tcp.local" }] });
        edit(&mut s, json!({ "mdns_proxy_mode": "custom", "mdns_proxy_custom": [rule] })).unwrap();
        let r = &s["wlanconf"][0]["mdns_proxy_custom"][0];
        assert_eq!((&r["ap_macs"], r["predefined_services"].as_array().unwrap().len()), (&json!([AP2]), 1), "MACs trimmed, written alike and once");
        assert_eq!(r["custom_services"][0]["name"], "_myapp._tcp.local");
        let bad = |r: Value| edit(&mut state(), json!({ "mdns_proxy_mode": "custom", "mdns_proxy_custom": [r] })).is_err();
        assert!(bad(json!({ "services_mode": "specific", "predefined_services": [{ "code": "telnet" }] })));
        assert!(bad(json!({ "services_mode": "specific", "custom_services": [{ "address": "myapp.local" }] })));
        assert!(bad(json!({ "services_mode": "specific" })), "no services chosen");
        assert!(bad(json!({ "ap_scope_mode": "specific", "ap_macs": ["02:00:00:00:00:99"] })), "unknown AP");
        let many: Vec<Value> = (0..33).map(|i| json!({ "address": format!("_app{i}._tcp.local") })).collect();
        assert!(bad(json!({ "services_mode": "specific", "custom_services": many })), "33 custom services");
        // Lists of anything else are refused, not read as empty.
        assert!(bad(json!({ "networkconf_ids": [5] })) && bad(json!({ "networkconf_ids": "n1" })));
        assert!(bad(json!({ "services_mode": "specific", "predefined_services": [{ "code": "apple_airPlay" }], "custom_services": { "address": "_myapp._tcp.local" } })));
        edit(&mut s, json!({ "mdns_proxy_mode": "auto" })).unwrap();
    }

    #[test]
    fn passwords_and_names_follow_the_official_limits() {
        let mut s = state();
        assert!(edit(&mut s, json!({ "passphrase": "short" })).is_err());
        assert!(edit(&mut s, json!({ "passphrase": "x".repeat(64) })).is_err(), "64 characters must be hex");
        edit(&mut s, json!({ "passphrase": "a".repeat(64) })).unwrap();
        assert!(edit(&mut s, json!({ "passphrase": "pässword" })).is_err(), "printable ASCII only");
        assert!(edit(&mut s, json!({ "name": "x".repeat(33) })).is_err());
        assert!(edit(&mut s, json!({ "name": "ææææææææææææææææææ" })).is_err(), "32 bytes, not characters");
        let what = edit(&mut s, json!({ "passphrase": "another secret" })).unwrap();
        assert!(what.contains("password") && !what.contains("another secret"), "{what}");
        // A long WPA3 password is not kept when the protection becomes one that cannot use it.
        edit(&mut s, json!({ "protection": "wpa3", "passphrase": "p".repeat(100) })).unwrap();
        for protection in ["wpa2", "wpa2_wpa3"] {
            assert!(edit(&mut s, json!({ "protection": protection })).unwrap_err().contains("enter a new one"), "{protection}");
            edit(&mut s.clone(), json!({ "protection": protection, "passphrase": "short enough" })).unwrap();
        }
        assert_eq!(s["wlanconf"][0]["x_passphrase"].as_str().map(str::len), Some(100));
        edit(&mut s, json!({ "protection": "open" })).unwrap();
    }

    #[test]
    fn specific_aps_use_a_group_of_their_own_which_goes_when_unused() {
        let mut s = state();
        edit(&mut s, json!({ "aps": [AP2] })).unwrap();
        let w = &s["wlanconf"][0];
        assert_eq!((w["ap_group_mode"].as_str(), w["broadcasting_aps"][0].as_str()), (Some("devices"), Some(AP2)));
        let gid = w["ap_group_ids"][0].as_str().unwrap().to_string();
        let g = s["apgroup"].as_array().unwrap().iter().find(|g| oid(g) == Some(gid.as_str())).unwrap();
        assert_eq!((g["for_wlanconf"].as_bool(), g["device_macs"][0].as_str()), (Some(true), Some(AP2)));
        assert_eq!(wlan_aps(&s, &s["wlanconf"][0]), Some(vec![AP2.parse().unwrap()]));
        assert_eq!(wlan_aps(&s, &json!({ "name": "no groups" })), Some(vec![]), "broadcast from no AP, as the AP config has it");
        // The same group is reused, then removed when the SSID goes back to all APs.
        edit(&mut s, json!({ "aps": [AP1, AP2] })).unwrap();
        assert_eq!(s["wlanconf"][0]["ap_group_ids"][0].as_str(), Some(gid.as_str()));
        edit(&mut s, json!({ "aps": null })).unwrap();
        assert_eq!((s["wlanconf"][0]["ap_group_mode"].as_str(), s["apgroup"].as_array().unwrap().len()), (Some("all"), 1));
        assert!(edit(&mut s, json!({ "aps": ["02:00:00:00:00:99"] })).is_err());
        assert!(edit(&mut s, json!({ "aps": [] })).is_err());
        // A group an mDNS rule applies on stays while the rule does.
        edit(&mut s, json!({ "aps": [AP2] })).unwrap();
        let gid = s["wlanconf"][0]["ap_group_ids"][0].as_str().unwrap().to_string();
        edit(&mut s, json!({ "mdns_proxy_mode": "custom", "mdns_proxy_custom": [{ "ap_scope_mode": "group", "ap_group_ids": [gid] }] })).unwrap();
        edit(&mut s, json!({ "aps": null })).unwrap();
        assert_eq!(s["apgroup"].as_array().unwrap().len(), 2);
        edit(&mut s, json!({ "mdns_proxy_mode": "auto", "mdns_proxy_custom": [] })).unwrap();
        assert_eq!(s["apgroup"].as_array().unwrap().len(), 1, "gone once no rule names it");
    }

    #[test]
    fn ssids_per_radio_are_limited_like_the_official_controller() {
        let mut s = state();
        for i in 0..7 {
            create_wlan(&mut s, &json!({ "name": format!("N{i}"), "passphrase": "password1" })).unwrap();
        }
        let err = create_wlan(&mut s, &json!({ "name": "N8", "passphrase": "password1" })).unwrap_err();
        assert!(err.contains("supports 8"), "{err}");
        // With wireless meshing on, the radios keep slots for it: 4 per band.
        let mut s = state();
        s["setting"][1]["enabled"] = json!(true);
        for i in 0..3 {
            create_wlan(&mut s, &json!({ "name": format!("N{i}"), "passphrase": "password1" })).unwrap();
        }
        assert!(create_wlan(&mut s, &json!({ "name": "N4", "passphrase": "password1" })).unwrap_err().contains("supports 4"));
    }

    #[test]
    fn ssids_go_only_on_networks_the_official_ui_offers() {
        let mut s = state();
        s["networkconf"].as_array_mut().unwrap().extend([
            json!({ "_id": "wan", "name": "Internet", "purpose": "wan", "site_id": "s1" }),
            json!({ "_id": "ivr", "name": "Routing", "purpose": "corporate", "vlan": "4040", "site_id": "s1" }),
            json!({ "_id": "iot", "name": "IoT", "purpose": "vlan-only", "vlan": 30, "site_id": "s1" }),
        ]);
        assert_eq!(edit(&mut s, json!({ "networkconf_id": "wan" })).unwrap_err(), "network \"Internet\" (wan) cannot carry an SSID");
        assert!(edit(&mut s, json!({ "networkconf_id": "ivr" })).unwrap_err().contains("VLAN 4040"));
        assert!(create_wlan(&mut s.clone(), &json!({ "name": "Up", "passphrase": "password1", "networkconf_id": "wan" })).unwrap_err().contains("cannot carry"));
        edit(&mut s, json!({ "networkconf_id": "iot" })).unwrap();
        create_wlan(&mut s, &json!({ "name": "Things", "passphrase": "password1", "networkconf_id": "iot" })).unwrap();
        // Without a hidden LAN network, a new SSID goes on the first network that may carry one.
        let mut t = s.clone();
        t["networkconf"].as_array_mut().unwrap().retain(|n| n["_id"] != "n1");
        create_wlan(&mut t, &json!({ "name": "Default", "passphrase": "password1" })).unwrap();
        assert_eq!(t["wlanconf"].as_array().unwrap().last().unwrap()["networkconf_id"], "iot");
        // One stored already (an import's) is left alone: the SSID's other fields can be edited, and the network sent back as it is.
        s["wlanconf"][0]["networkconf_id"] = json!("wan");
        edit(&mut s, json!({ "hide_ssid": true, "networkconf_id": "wan" })).unwrap();
        assert_eq!((s["wlanconf"][0]["hide_ssid"].as_bool(), s["wlanconf"][0]["networkconf_id"].as_str()), (Some(true), Some("wan")));
    }

    #[test]
    fn settings_over_a_limit_can_still_be_edited() {
        let mut s = state();
        for i in 0..7 {
            create_wlan(&mut s, &json!({ "name": format!("N{i}"), "passphrase": "password1" })).unwrap();
        }
        // A ninth SSID, as an import may have it: every radio is over its limit of 8.
        let mut ninth = s["wlanconf"][1].clone();
        (ninth["_id"], ninth["name"]) = (json!("w9"), json!("N9"));
        s["wlanconf"].as_array_mut().unwrap().push(ninth);
        edit(&mut s, json!({ "name": "Home again" })).unwrap();
        assert!(create_wlan(&mut s.clone(), &json!({ "name": "N10", "passphrase": "password1" })).unwrap_err().contains("would have 10"));
        // Back under the limit on 2.4 GHz (5 GHz stays at 9), then over it again: refused.
        edit(&mut s, json!({ "wlan_bands": ["5g"] })).unwrap();
        assert!(edit(&mut s, json!({ "wlan_bands": ["2g", "5g"] })).unwrap_err().contains("9 SSIDs on its 2.4 GHz radio"));
        // The same for the list limits.
        let list: Vec<String> = (0..300).map(|i| format!("02:00:00:00:{:02x}:{:02x}", i / 256, i % 256)).collect();
        (s["wlanconf"][1]["bc_filter_enabled"], s["wlanconf"][1]["bc_filter_list"]) = (json!(true), json!(list));
        edit(&mut s, json!({ "hide_ssid": true })).unwrap();
        let more = json!({ "multicast_suppressor_mode": "aggressive", "bc_filter_list": ["02:00:00:00:ff:01"] });
        assert!(edit(&mut s, more).unwrap_err().contains("301 broadcast-filter"));
    }

    #[test]
    fn new_ssids_get_defaults_and_deleting_cleans_up() {
        let mut s = state();
        // A refused SSID leaves its copy of the settings half-changed (the callers drop it).
        assert!(create_wlan(&mut s.clone(), &json!({ "name": "Guest" })).unwrap_err().contains("password"));
        assert!(create_wlan(&mut s.clone(), &json!({ "name": "Home", "passphrase": "password1" })).unwrap_err().contains("already"));
        create_wlan(&mut s, &json!({ "name": "Guest", "passphrase": "password1", "aps": [AP1] })).unwrap();
        let w = s["wlanconf"][1].clone();
        assert_eq!((w["short_id"].as_i64(), w["networkconf_id"].as_str(), w["x_iapp_key"].as_str().map(str::len)), (Some(3), Some("n1"), Some(32)));
        assert_eq!((w["minrate_ng_enabled"].as_bool(), w["wlan_band"].as_str(), w["dtim_na"].as_i64()), (Some(true), Some("both"), Some(3)));
        assert_eq!(s["apgroup"].as_array().unwrap().len(), 2);
        delete_wlan(&mut s, &id_of(&w).unwrap()).unwrap();
        assert_eq!((s["wlanconf"].as_array().unwrap().len(), s["apgroup"].as_array().unwrap().len()), (1, 1));
        s["wlanconf"][0]["attr_no_delete"] = json!(true);
        assert!(delete_wlan(&mut s, "w1").is_err());
    }

    #[test]
    fn rates_and_suppression_derive_their_companion_fields() {
        let mut s = state();
        assert!(edit(&mut s, json!({ "minrate_ng_data_rate_kbps": 7000 })).is_err());
        edit(&mut s, json!({ "minrate_ng_data_rate_kbps": 12000, "minrate_na_enabled": true, "minrate_na_data_rate_kbps": 24000 })).unwrap();
        assert_eq!(s["wlanconf"][0]["minrate_na_data_rate_kbps"], 24000);
        edit(&mut s, json!({ "minrate_setting_preference": "auto" })).unwrap();
        let w = &s["wlanconf"][0];
        assert_eq!((w["minrate_ng_data_rate_kbps"].as_i64(), w["minrate_na_enabled"].as_bool()), (Some(1000), Some(false)));
        edit(&mut s, json!({ "multicast_suppressor_mode": "aggressive", "bc_filter_list": ["AA:BB:CC:00:00:01"] })).unwrap();
        assert_eq!((s["wlanconf"][0]["bc_filter_enabled"].as_bool(), s["wlanconf"][0]["bc_filter_list"][0].as_str()), (Some(true), Some("aa:bb:cc:00:00:01")));
        edit(&mut s, json!({ "multicast_suppressor_mode": "off" })).unwrap();
        assert_eq!(s["wlanconf"][0]["bc_filter_list"], json!([]));
        assert!(edit(&mut s, json!({ "roaming_assistant_na_rssi": -85 })).is_err());
        assert!(edit(&mut s, json!({ "group_rekey": 30 })).is_err());
    }

    #[test]
    fn channels_follow_the_country_and_width() {
        let eu = |band, width, outdoor| legal_channels(Some(276), band, width, outdoor).unwrap();
        assert_eq!(eu("ng", 20, false), (1..=13).collect::<Vec<_>>());
        assert!(eu("na", 20, false).contains(&140) && !eu("na", 40, false).contains(&140));
        assert!(!eu("na", 80, false).contains(&132) && !eu("na", 20, false).contains(&149));
        assert!(!eu("na", 20, true).contains(&36), "outdoors only 100-140 in Europe");
        assert!(legal_channels(Some(840), "na", 20, false).unwrap().contains(&165));
        assert_eq!(legal_channels(Some(840), "ng", 20, false).unwrap().len(), 11);
        // No rules for the country or the band: nothing is restricted.
        assert_eq!((legal_channels(None, "ng", 20, false), legal_channels(Some(392), "na", 80, false), legal_channels(Some(276), "6e", 20, false)), (None, None, None));
        assert_eq!(band_channels("6e", 20).len(), 59);
        assert_eq!((band_channels("6e", 160).last(), band_channels("na", 20).last()), (Some(&221), Some(&165)));
        assert_eq!(legal_channels(Some(840), "na", 160, false).unwrap().last(), Some(&128));
        assert_eq!(legal_channels(Some(840), "na", 80, false).unwrap().last(), Some(&161));
        // One channel is checked against the same rules.
        for (c, band, width, o) in [(Some(276), "ng", 20, false), (Some(840), "ng", 40, false), (Some(276), "na", 40, true), (Some(276), "na", 80, false), (Some(840), "na", 20, false), (Some(840), "na", 160, false), (None, "na", 20, false), (Some(276), "6e", 20, false)] {
            let list = legal_channels(c, band, width, o);
            for ch in 1..=233 {
                assert_eq!(is_legal(c, band, width, o, ch), list.as_ref().map(|l| l.contains(&ch)), "{c:?} {band} {width} {o} {ch}");
            }
        }
        assert_eq!(illegal_fixed_channel(Some(276), &json!({ "radio": "na", "ht": "40", "channel": "140" }), false), Some(140));
        assert_eq!(illegal_fixed_channel(Some(276), &json!({ "radio": "na", "ht": 20, "channel": 140 }), false), None);
        assert_eq!(illegal_fixed_channel(Some(276), &json!({ "radio": "na", "channel": "auto" }), true), None);
    }

    fn dev(s: &mut Value, patch: Value) -> Result<String, String> {
        let caps = RadioCaps::of_inform(Some(&json!({ "radio_table": [{ "radio": "na", "min_txpower": 6, "max_txpower": 26, "has_ht160": false }, { "radio": "ng", "min_txpower": 6, "max_txpower": 22 }] })));
        apply_device(s, &DeviceEdit { mac: AP1.parse().unwrap(), patch, caps, wireless_uplink: None, antennas: Value::Null })
    }

    #[test]
    fn ap_edits_are_checked_against_the_radio_and_country() {
        let mut s = state();
        let what = dev(&mut s, json!({ "name": "Hallway", "led_override": "off", "radios": [{ "radio": "na", "channel": 100, "tx_power_mode": "custom", "tx_power": 12 }] })).unwrap();
        assert!(what.contains("5 GHz radio: channel, tx_power_mode, tx_power"), "{what}");
        assert_eq!((s["devices"][0]["name"].as_str(), s["devices"][0]["radio_table"][1]["channel"].as_i64()), (Some("Hallway"), Some(100)));
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "na", "channel": 149 }] })).is_err(), "not in Germany");
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "na", "ht": 160 }] })).is_err(), "no 160 MHz on this radio");
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "ng", "ht": 80 }] })).is_err());
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "na", "tx_power": 30 }] })).is_err());
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "na", "min_rssi": -60 }] })).is_err());
        dev(&mut s, json!({ "radios": [{ "radio": "na", "min_rssi_enabled": true, "min_rssi": -75, "hard_noise_floor_enabled": true }] })).unwrap();
        // Narrowing the width keeps a channel legal; 140 only works at 20 MHz.
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "na", "channel": 140 }] })).is_err());
        dev(&mut s, json!({ "radios": [{ "radio": "na", "channel": 140, "ht": 20 }] })).unwrap();
        // An IoT channel lock on an SSID here freezes the 2.4 GHz channel, but
        // for a move onto the lock's channel 6 (from 1 here, set before the lock).
        s["wlanconf"][0]["iot_channel_lock"] = json!(true);
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "ng", "channel": 11 }] })).unwrap_err().contains("IoT"));
        dev(&mut s, json!({ "radios": [{ "radio": "ng", "tx_power_mode": "low" }] })).unwrap();
        dev(&mut s.clone(), json!({ "radios": [{ "radio": "ng", "channel": 6 }] })).unwrap();
        s["devices"][0]["radio_table"][0]["channel"] = json!("auto");
        dev(&mut s.clone(), json!({ "radios": [{ "radio": "ng", "channel": "6" }] })).unwrap();
        // The lock keeps channel 6 as "6": asking for 6 again is no change.
        s["devices"][0]["radio_table"][0]["channel"] = json!("6");
        dev(&mut s, json!({ "radios": [{ "radio": "ng", "channel": 6 }] })).unwrap();
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "ng", "channel": 1 }] })).unwrap_err().contains("IoT"));
    }

    #[test]
    fn ap_wide_settings_and_its_address() {
        let mut s = state();
        let what = dev(&mut s, json!({ "led_override_color": "#0F0", "bandsteering_mode": "prefer_5g", "resetbtn_enabled": "off" })).unwrap();
        assert!(what.contains("bandsteering mode") && what.contains("resetbtn enabled"), "{what}");
        assert_eq!(s["devices"][0]["led_override_color"], "#00ff00", "three digits become six");
        assert!(dev(&mut s, json!({ "led_override_color": "green" })).is_err());
        assert!(dev(&mut s, json!({ "bandsteering_mode": "always" })).is_err());
        // Outdoors in Europe 5 GHz is 100-140 only, so channel 44 has to go first.
        assert!(dev(&mut s, json!({ "outdoor_mode_override": "on" })).unwrap_err().contains("channel 44"));
        dev(&mut s, json!({ "outdoor_mode_override": "on", "radios": [{ "radio": "na", "channel": 100 }] })).unwrap();

        let static_ip = |ip: &str, gw: &str| json!({ "config_network": { "type": "static", "ip": ip, "netmask": "255.255.255.0", "gateway": gw, "dns1": "192.168.1.1" } });
        s["devices"][1]["config_network"] = json!({ "type": "static", "ip": "192.168.1.21" });
        s["clients"] = json!([{ "mac": "02:00:00:00:00:99", "name": "NAS", "use_fixedip": true, "fixed_ip": "192.168.1.22", "site_id": "s1" }]);
        assert!(dev(&mut s, static_ip("192.168.1.21", "192.168.1.1")).unwrap_err().contains("Attic"));
        assert!(dev(&mut s, static_ip("192.168.1.22", "192.168.1.1")).unwrap_err().contains("NAS"));
        assert!(dev(&mut s, json!({ "config_network": { "type": "static", "ip": "192.168.1.20", "netmask": "255.255.255.0", "gateway": "192.168.1.1" } })).unwrap_err().contains("dns1"));
        dev(&mut s, static_ip("192.168.1.20", "192.168.1.1")).unwrap();
        assert_eq!(s["devices"][0]["config_network"]["ip"], "192.168.1.20");
        assert!(dev(&mut s, static_ip("192.168.1.20", "10.0.0.1")).unwrap_err().contains("gateway"));
        assert!(dev(&mut s, static_ip("192.168.1.255", "192.168.1.1")).is_err(), "broadcast address");
        assert!(dev(&mut s, json!({ "config_network": { "type": "static", "ip": "192.168.1.20" } })).is_err(), "netmask needed");
        let with_suffix = |d: &str| json!({ "config_network": { "type": "static", "ip": "192.168.1.20", "netmask": "255.255.255.0", "gateway": "192.168.1.1", "dns1": "192.168.1.1", "dnssuffix": d } });
        dev(&mut s.clone(), with_suffix("home-1.lan")).unwrap();
        for bad in ["-home.lan", "home-.lan", "home..lan", "home_1.lan"] {
            assert!(dev(&mut s.clone(), with_suffix(bad)).unwrap_err().contains("not a domain name"), "{bad}");
        }
        dev(&mut s, json!({ "config_network": { "type": "dhcp", "ip": "192.168.1.20" } })).unwrap();
        assert_eq!(s["devices"][0]["config_network"], json!({ "type": "dhcp" }));
    }

    #[test]
    fn widths_stored_as_strings_and_6ghz_radios() {
        let mut s = state();
        // Imports keep "ht" as a string: 140 is legal at 20 MHz, not at 80.
        s["devices"][0]["radio_table"][1]["ht"] = json!("20");
        dev(&mut s, json!({ "radios": [{ "radio": "na", "channel": 140 }] })).unwrap();
        s["devices"][0]["radio_table"][1]["ht"] = json!("80");
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "na", "channel": 100 }] })).is_ok());
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "na", "channel": 140 }] })).is_err());
        // apctl has no 6 GHz rules: a fixed channel and width are the AP's to judge.
        s["devices"][0]["radio_table"].as_array_mut().unwrap().push(json!({ "name": "wifi2", "radio": "6e", "channel": "auto", "ht": 160 }));
        dev(&mut s, json!({ "radios": [{ "radio": "6e", "channel": 37, "ht": 80 }] })).unwrap();
        assert_eq!(s["devices"][0]["radio_table"][2]["channel"], 37);
        // Nor for a country outside its tables.
        s["setting"][0]["code"] = json!("392");
        dev(&mut s, json!({ "radios": [{ "radio": "na", "channel": 149, "ht": 80 }] })).unwrap();
        // Without rules a channel must still be one of the band's.
        for ch in [999, 0, -4, 38] {
            assert!(dev(&mut s, json!({ "radios": [{ "radio": "6e", "channel": ch }] })).unwrap_err().contains("not a channel"), "6 GHz {ch}");
        }
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "na", "channel": 999 }] })).unwrap_err().contains("not a channel"));
        assert_eq!(s["devices"][0]["radio_table"][2]["channel"], 37);
        // Nor one the band has, but not at the width: the editor never offers these.
        let mut wide = s.clone();
        wide["devices"][0]["radio_table"][2]["ht"] = json!("160");
        assert!(dev(&mut wide, json!({ "radios": [{ "radio": "6e", "channel": 233 }] })).unwrap_err().contains("not allowed at 160 MHz"));
        assert!(dev(&mut s.clone(), json!({ "radios": [{ "radio": "na", "channel": 165, "ht": 80 }] })).unwrap_err().contains("not allowed at 80 MHz"));
        assert!(dev(&mut s.clone(), json!({ "radios": { "radio": "na", "channel": 36 } })).unwrap_err().contains("radios must be a list"));
        // A width change that the kept channel does not fit is refused too.
        s["devices"][0]["radio_table"][2]["channel"] = json!(233);
        s["devices"][0]["radio_table"][2]["ht"] = json!(20);
        assert!(dev(&mut s.clone(), json!({ "radios": [{ "radio": "6e", "ht": 40 }] })).unwrap_err().contains("channel 233"));
    }

    #[test]
    fn a_mesh_uplink_is_found_by_its_vap() {
        let inform = |uplink: &str| json!({ "uplink": uplink, "vap_table": [{ "name": "wifi1ap0", "radio": "na" }, { "name": "wifi1sta0", "radio": "na", "usage": "uplink" }] });
        assert_eq!(uplink(&inform("wifi1sta0")), Uplink::Wireless(Some("na".into())));
        assert_eq!(uplink(&inform("eth0")), Uplink::Wired);
        assert_eq!(uplink(&inform("")), Uplink::Wired);
        assert_eq!(uplink(&json!({ "vap_table": [] })), Uplink::Wired, "no uplink named: wired");
        assert_eq!(uplink(&inform("ath0")), Uplink::Wireless(None), "a placeholder names no VAP: wireless, band unknown");
        let mut s = state();
        let e = DeviceEdit { mac: AP1.parse().unwrap(), patch: json!({ "radios": [{ "radio": "na", "tx_power_mode": "disabled" }] }), caps: HashMap::new(), wireless_uplink: Some("na".into()), antennas: Value::Null };
        assert!(apply_device(&mut s, &e).unwrap_err().contains("uplink"));
    }

    #[test]
    fn ssids_per_radio_are_limited() {
        let wlan = |i: usize, bands: Value, groups: Value| json!({ "_id": format!("w{i}"), "name": format!("N{i}"), "wlan_bands": bands, "ap_group_ids": groups });
        let mut s = json!({
            "devices": [{ "mac": AP1, "name": "Hall", "radio_table": [{ "radio": "ng" }, { "radio": "na" }] }, { "mac": AP2, "radio_table": [{ "radio": "na" }] }],
            "apgroup": [{ "_id": "all", "attr_hidden_id": "default" }, { "_id": "one", "device_macs": [AP2] }],
            "setting": [{ "key": "connectivity", "enabled": false }],
            "wlanconf": (0..8).map(|i| wlan(i, json!(["2g", "5g"]), json!(["all"]))).collect::<Vec<_>>(),
        });
        let check = |s: &Value| check_limits(&[], s);
        assert!(check(&s).is_ok(), "eight per radio");
        // A ninth on 5 GHz for the second AP only: the first is still fine.
        s["wlanconf"].as_array_mut().unwrap().push(wlan(8, json!(["5g"]), json!(["one"])));
        assert!(check(&s).unwrap_err().starts_with(&format!("{AP2} would have 9 SSIDs on its 5 GHz radio")));
        // Wireless meshing on: four per radio.
        s["wlanconf"].as_array_mut().unwrap().truncate(5);
        s["setting"][0]["enabled"] = json!(true);
        assert_eq!(check(&s).unwrap_err(), "Hall would have 5 SSIDs on its 2.4 GHz radio; it supports 4");
        // Element adoption on: seven per radio.
        s["setting"] = json!([{ "key": "connectivity", "enabled": false }, { "key": "element_adopt", "enabled": true }]);
        s["wlanconf"] = json!((0..8).map(|i| wlan(i, json!(["2g"]), json!(["all"]))).collect::<Vec<_>>());
        assert_eq!(check(&s).unwrap_err(), "Hall would have 8 SSIDs on its 2.4 GHz radio; it supports 7");
        s["wlanconf"].as_array_mut().unwrap().truncate(7);
        check(&s).unwrap();
    }

    /// Every `setting` document the controller reads (by key) is one an import
    /// keeps (`apcfg::SETTING_KEYS`): a key missing there is gone after a re-import.
    #[test]
    fn setting_keys_cover_every_setting_the_controller_reads() {
        const SOURCES: &[&str] = &[include_str!("settings.rs"), include_str!("site.rs"), include_str!("channelai.rs"), include_str!("adopt.rs"), include_str!("ssh.rs")];
        let mut read: Vec<String> = Vec::new();
        for src in SOURCES {
            // Test modules (each runs to the next `}` at the start of a line) are left out.
            let mut rest: &str = src;
            let mut code = String::new();
            while let Some(at) = rest.find("#[cfg(test)]") {
                code.push_str(&rest[..at]);
                rest = rest[at..].find("\n}\n").map_or("", |end| &rest[at + end..]);
            }
            code.push_str(rest);
            for pattern in ["setting(", "setting_mut(", "setting_on("] {
                for (at, _) in code.match_indices(pattern) {
                    let args = &code[at + pattern.len()..];
                    let args = &args[..args.find(')').unwrap()];
                    // `setting(state, "key")`, `setting_on("key", ..)`: the first quoted argument.
                    if let Some(q) = args.find('"') {
                        read.push(args[q + 1..q + 1 + args[q + 1..].find('"').unwrap()].to_string());
                    }
                }
            }
        }
        for key in ["mgmt", "country", "element_adopt", "radio_ai", "ntp"] {
            assert!(read.iter().any(|r| r == key), "the patterns still find the reads of {key}: {read:?}");
        }
        for key in &read {
            assert!(apcfg::SETTING_KEYS.contains(&key.as_str()), "setting `{key}` is read but missing from apcfg::SETTING_KEYS");
        }
    }

    #[test]
    fn mac_filter_addresses_add_up_over_ssids_sharing_an_ap_group() {
        let list = |n: usize| (0..n).map(|i| format!("02:00:00:00:{:02x}:{:02x}", i / 256, i % 256)).collect::<Vec<_>>();
        let wlan = |groups: &[&str], n: usize| json!({ "mac_filter_enabled": true, "ap_group_ids": groups, "mac_filter_list": list(n) });
        let s = json!({ "wlanconf": [wlan(&["a", "b"], 300), wlan(&["b"], 300)] });
        assert!(check_limits(&[], &s).unwrap_err().contains("600 MAC-filter"));
        let s = json!({ "wlanconf": [wlan(&["a"], 300), wlan(&["c"], 300), wlan(&["c"], 212)] });
        check_limits(&[], &s).unwrap();
    }

    #[test]
    fn macs_are_saved_in_one_form_whichever_way_they_are_written() {
        let mut s = state();
        edit(&mut s, json!({ "mac_filter_list": ["02-00-00-00-00-0A", "02000000000b", "02:00:00:00:00:0a"], "bc_filter_list": ["AABBCC000001"] })).unwrap();
        assert_eq!(s["wlanconf"][0]["mac_filter_list"], json!(["02:00:00:00:00:0a", "02:00:00:00:00:0b"]), "one entry per address");
        assert_eq!(s["wlanconf"][0]["bc_filter_list"], json!(["aa:bb:cc:00:00:01"]));
        assert!(edit(&mut s, json!({ "mac_filter_list": ["02-00:00:00:00:0a"] })).is_err(), "one separator throughout");
        edit(&mut s, json!({ "aps": ["02-00-00-00-00-02"] })).unwrap();
        assert_eq!(s["wlanconf"][0]["broadcasting_aps"], json!([AP2]));
        let rule = json!({ "ap_scope_mode": "specific", "ap_macs": ["020000000001"] });
        edit(&mut s, json!({ "mdns_proxy_mode": "custom", "mdns_proxy_custom": [rule] })).unwrap();
        assert_eq!(s["wlanconf"][0]["mdns_proxy_custom"][0]["ap_macs"], json!([AP1]));
        // An AP named another way is still the one an SSID's channel lock holds.
        let mut s = state();
        edit(&mut s, json!({ "iot_channel_lock": true })).unwrap();
        let e = DeviceEdit { mac: "02-00-00-00-00-01".parse().unwrap(), patch: json!({ "radios": [{ "radio": "ng", "channel": 1 }] }), caps: HashMap::new(), wireless_uplink: None, antennas: Value::Null };
        assert!(apply_device(&mut s, &e).unwrap_err().contains("IoT"));
        // A record that writes its MAC another way is found, and listed as `aa:bb:..`.
        let mut s = state();
        s["devices"][1]["mac"] = json!("02-00-00-00-00-02");
        assert_eq!(device_macs(&s), [AP1, AP2].map(|m| m.parse::<inform::Mac>().unwrap()));
        assert!(crate::adopt::device_doc(&s, &AP2.parse().unwrap()).is_some());
        edit(&mut s, json!({ "aps": [AP2] })).unwrap();
    }

    #[test]
    fn the_ssid_list_has_its_full_shape_before_anything_is_imported() {
        let v = wlans_view(&Value::Null, &HashMap::new(), true);
        assert_eq!((&v["wlans"], &v["aps"], &v["unknown"]), (&json!([]), &json!([]), &json!([])));
        assert!(v["unsupported"].is_object() && !v["mdns_services"].as_array().unwrap().is_empty());
        let v = wlans_view(&state(), &HashMap::new(), true);
        assert_eq!((v["aps"].as_array().unwrap().len(), &v["unknown"][0]), (2, &json!(AP1)), "no inform yet: support unknown");
    }

    #[test]
    fn new_documents_are_put_in_the_site() {
        let mut s = state();
        setting_mut(&mut s, "ntp")["setting_preference"] = json!("auto");
        assert_eq!(setting(&s, "ntp")["site_id"], "s1");
        // Without a site, none is written (a null one meant the same: every site).
        let mut s = json!({ "setting": [{ "key": "ntp", "site_id": null, "x": 1 }] });
        assert_eq!(setting_mut(&mut s, "ntp")["x"], 1, "a null site_id is in the site");
        setting_mut(&mut s, "mgmt");
        assert_eq!(s["setting"][1], json!({ "key": "mgmt" }));
    }

    #[test]
    fn the_editors_change_the_aps_site_only() {
        let mut s = state();
        s["wlanconf"].as_array_mut().unwrap().push(json!({ "_id": "w2", "site_id": "s2", "name": "Elsewhere", "ap_group_ids": ["g9"] }));
        s["apgroup"].as_array_mut().unwrap().push(json!({ "_id": "g9", "site_id": "s2", "for_wlanconf": true }));
        s["usergroup"] = json!([{ "_id": "u2", "site_id": "s2", "name": "Theirs" }]);
        s["clients"] = json!([{ "mac": "aa:bb:cc:00:00:01", "site_id": "s2", "blocked": true }]);
        assert_eq!(apply_wlan(&mut s.clone(), &WlanEdit { id: "w2".into(), patch: json!({ "name": "Mine" }) }).unwrap_err(), "unknown SSID");
        assert!(delete_wlan(&mut s.clone(), "w2").is_err());
        assert!(apply_usergroup(&mut s.clone(), &GroupEdit::Edit("u2".into(), json!({ "name": "Mine" }))).is_err());
        // An AP of the other site is judged by its own site's rules: not edited here.
        let mut t = s.clone();
        t["devices"].as_array_mut().unwrap().push(json!({ "mac": "02:00:00:00:00:09", "name": "Far", "site_id": "s2", "radio_table": [] }));
        let far = DeviceEdit { mac: "02:00:00:00:00:09".parse().unwrap(), patch: json!({ "name": "Near" }), caps: HashMap::new(), wireless_uplink: None, antennas: Value::Null };
        assert_eq!(apply_device(&mut t, &far).unwrap_err(), "this AP belongs to another site");
        // Pruning this site's per-SSID groups leaves another site's alone.
        edit(&mut s, json!({ "aps": [AP1] })).unwrap();
        edit(&mut s, json!({ "aps": null })).unwrap();
        assert_eq!(s["apgroup"].as_array().unwrap().iter().filter_map(oid).collect::<Vec<_>>(), ["g0", "g9"]);
        // Deleting this site's SSID leaves another site's with the same id.
        let mut t = s.clone();
        t["wlanconf"].as_array_mut().unwrap().push(json!({ "_id": "w1", "site_id": "s2", "name": "Twin" }));
        delete_wlan(&mut t, "w1").unwrap();
        assert_eq!(t["wlanconf"].as_array().unwrap().iter().filter_map(|w| w["name"].as_str()).collect::<Vec<_>>(), ["Elsewhere", "Twin"]);
        // A client's entry in another site is not this site's.
        let c1: inform::Mac = "aa:bb:cc:00:00:01".parse().unwrap();
        assert!(!crate::actions::controls(Some(&s), &c1).blocked);
        crate::actions::edit_client(&mut s, c1, &[("usergroup_id", json!("u1"))]);
        assert_eq!((s["clients"][0]["blocked"].as_bool(), s["clients"][1]["site_id"].as_str()), (Some(true), Some("s1")));
        assert!(!crate::actions::controls(Some(&s), &c1).blocked);
    }

    #[test]
    fn repeated_entries_go_wherever_they_are() {
        let mut s = state();
        edit(&mut s, json!({ "mac_filter_list": ["02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0A"] })).unwrap();
        assert_eq!(s["wlanconf"][0]["mac_filter_list"], json!(["02:00:00:00:00:0a", "02:00:00:00:00:0b"]));
        edit(&mut s, json!({ "dns_assistance_mode": "manual", "dns_assistance_servers": ["1.1.1.1", "8.8.8.8", "1.1.1.1"] })).unwrap();
        assert_eq!(s["wlanconf"][0]["dns_assistance_servers"], json!(["1.1.1.1", "8.8.8.8"]));
    }

    #[test]
    fn radio_extras_are_range_checked() {
        let mut s = state();
        let antennas = json!([{ "id": 4, "name": "Combined", "wifi0_gain": 3, "wifi1_gain": 5 }, { "id": 5, "name": "External" }]);
        let caps = RadioCaps::of_inform(Some(&json!({ "radio_table": [{ "radio": "na", "min_txpower": 6, "max_txpower": 26 }, { "radio": "ng", "min_txpower": 6, "max_txpower": 22 }] })));
        let any = |s: &mut Value, patch: Value| apply_device(s, &DeviceEdit { mac: AP1.parse().unwrap(), patch, caps: caps.clone(), wireless_uplink: None, antennas: antennas.clone() });
        let edit = |s: &mut Value, r: Value| any(s, json!({ "radios": [r] }));
        edit(&mut s, json!({ "radio": "na", "loadbalance_enabled": true, "maxsta": 40, "sens_level_enabled": true, "sens_level": -80 })).unwrap();
        let r = &s["devices"][0]["radio_table"][1];
        assert_eq!((r["maxsta"].as_i64(), r["sens_level"].as_i64()), (Some(40), Some(-80)));
        // The antenna sets each radio's gain from the AP's table (6 when it has none).
        any(&mut s, json!({ "antenna_id": 4 })).unwrap();
        let gains = |s: &Value| s["devices"][0]["radio_table"].as_array().unwrap().iter().map(|r| r["antenna_gain"].as_i64().unwrap()).collect::<Vec<_>>();
        assert_eq!(gains(&s), [3, 5]);
        any(&mut s, json!({ "antenna_id": 5 })).unwrap();
        assert_eq!(gains(&s), [6, 6]);
        assert!(any(&mut s, json!({ "antenna_id": 2 })).is_err());
        assert!(edit(&mut s, json!({ "radio": "na", "maxsta": 500 })).is_err());
        assert!(edit(&mut s, json!({ "radio": "na", "sens_level": -40 })).is_err());
    }
}

// ---- Speed limits (user groups) -----------------------------------------------

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
    if g["attr_no_delete"].as_bool() == Some(true) {
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
    let show = |v: &Value| match v.as_i64() {
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
    let users = group_users(&state);
    let group = |g: &Value| {
        let id = id_of(g).unwrap_or_default();
        let used_by = users.get(id.as_str()).map(Vec::as_slice).unwrap_or_default();
        json!({
            "id": id, "name": g["name"], "default": g["attr_hidden_id"].as_str() == Some("Default"),
            "qos_rate_max_down": g["qos_rate_max_down"], "qos_rate_max_up": g["qos_rate_max_up"], "used_by": used_by,
        })
    };
    let mut groups: Vec<Value> = docs(&state, "usergroup").map(group).collect();
    // Settings without a default group get it on their first save; shown as it will be.
    if default_usergroup(&state).is_none() {
        groups.push(group(&new_default_usergroup(&state)));
    }
    Ok(Json(json!({ "active": s.active, "groups": groups })))
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
mod speed_and_schedule_tests {
    use super::*;

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

    #[test]
    fn blackout_schedules_are_checked() {
        let mut s = state();
        let ok = json!([{ "start_days_of_week": ["Mon", "tue"], "start_hour": 22, "start_minute": 30, "duration_minutes": 480, "name": "night" }]);
        apply_wlan(&mut s, &WlanEdit { id: "w1".into(), patch: json!({ "schedule_with_duration": ok }) }).unwrap();
        assert_eq!(s["wlanconf"][0]["schedule_with_duration"][0]["start_days_of_week"], json!(["mon", "tue"]));
        for bad in [
            json!([{ "start_days_of_week": [], "start_hour": 1, "duration_minutes": 10 }]),
            json!([{ "start_days_of_week": ["mon"], "start_hour": 24, "duration_minutes": 10 }]),
            json!([{ "start_days_of_week": ["mon"], "start_hour": 1, "duration_minutes": 0 }]),
            json!([{ "start_days_of_week": ["funday"], "start_hour": 1, "duration_minutes": 10 }]),
            json!([{ "start_days_of_week": ["mon", 1], "start_hour": 1, "duration_minutes": 10 }]),
        ] {
            assert!(apply_wlan(&mut s, &WlanEdit { id: "w1".into(), patch: json!({ "schedule_with_duration": bad }) }).is_err(), "{bad}");
        }
        apply_wlan(&mut s, &WlanEdit { id: "w1".into(), patch: json!({ "schedule_with_duration": [] }) }).unwrap();
        assert_eq!(s["wlanconf"][0]["schedule_with_duration"], json!([]));
    }
}
