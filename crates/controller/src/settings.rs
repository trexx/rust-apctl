//! The settings editor: changes to SSIDs (`wlanconf`) and APs (`devices`) in
//! apctl's copy of the controller settings.
//!
//! Every change can be previewed first (`?preview=true`): the config each AP
//! would get is rendered with and without it and the difference returned, the
//! same shape as a config push in the history. Previews work in shadow mode
//! too; saving needs active mode, since in shadow mode the settings belong to
//! the other controller (the next import would replace them).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};

#[derive(Deserialize, Default)]
pub struct PreviewQuery {
    #[serde(default)]
    pub preview: bool,
}

/// A change to the settings: applied to a copy for a preview, or through the
/// engine to save it.
pub type Apply = fn(&mut Value, &Value) -> Result<String, String>;

/// Previews or saves `apply(state, body)`. `apply` validates, edits, and
/// returns what changed in words (for the event and the config history).
pub(crate) async fn change(s: &AppState, headers: &HeaderMap, q: &PreviewQuery, apply: Apply, body: Value) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(headers)?;
    let current = s.live.read().unwrap().state.clone().ok_or_else(|| ApiError(StatusCode::CONFLICT, "no settings imported yet".into()))?;
    let mut edited = (*current).clone();
    let what = apply(&mut edited, &body).map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    if q.preview {
        return Ok(Json(json!({ "what": what, "aps": preview(s, &current, &edited) })));
    }
    if !s.active {
        return Err(ApiError(StatusCode::CONFLICT, "saving needs active mode: in shadow mode the settings belong to the other controller".into()));
    }
    // Applied again inside the engine, to the settings as they are then.
    crate::actions::edit_settings(s, what.clone(), move |state| apply(state, &body).map(|_| ())).await?;
    Ok(Json(json!({ "saved": true, "what": what })))
}

/// What each reporting AP's config would become, as config-push summaries.
fn preview(s: &AppState, before: &Value, after: &Value) -> Vec<Value> {
    let Some(render) = &s.renderer else { return Vec::new() };
    let live = s.live.read().unwrap();
    let mut out = Vec::new();
    for (mac, d) in &live.devices {
        let inform = live.raw_informs.get(mac).map(|v| v.as_ref());
        let cfgversion = d.snapshot.ap.cfgversion.clone().unwrap_or_default();
        let mac_s = mac.to_string();
        let req = |state| crate::dryrun::RenderRequest { state, device_mac: &mac_s, inform, cfgversion: &cfgversion, previous_system_cfg: None };
        let name = d.snapshot.ap.hostname.clone();
        match (render(&req(before)), render(&req(after))) {
            (Ok(old), Ok(new)) => {
                let summary = |o: &str, n: &str| {
                    let d = wire::cfgdiff::diff(o, n);
                    json!({ "added": d.added.len(), "removed": d.removed.len(), "changed": d.changed.len(), "diff": d.render("", true) })
                };
                let mut labels = crate::engine::section_labels(&old.1, &d.snapshot.radios);
                labels.extend(crate::engine::section_labels(&new.1, &d.snapshot.radios));
                out.push(json!({
                    "mac": mac, "name": name,
                    "mgmt_cfg": summary(&old.0, &new.0), "system_cfg": summary(&old.1, &new.1), "labels": labels,
                }));
            }
            (_, Err(e)) | (Err(e), _) => out.push(json!({ "mac": mac, "name": name, "error": format!("{e:#}") })),
        }
    }
    out
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
    match &v["_id"] {
        Value::String(s) => Some(s.clone()),
        o => o["$oid"].as_str().map(str::to_string),
    }
}

/// The site the APs belong to (apctl manages one).
pub fn site_id(state: &Value) -> Option<String> {
    state["devices"].as_array()?.iter().find_map(|d| d["site_id"].as_str().map(str::to_string))
}

pub(crate) fn docs<'a>(state: &'a Value, collection: &str) -> impl Iterator<Item = &'a Value> {
    let site = site_id(state);
    state[collection].as_array().into_iter().flatten().filter(move |d| site.is_none() || d["site_id"].as_str().is_none_or(|s| Some(s) == site.as_deref()))
}

/// The APs an SSID is broadcast from: `None` for all of them.
fn wlan_aps(state: &Value, w: &Value) -> Option<Vec<String>> {
    let groups: Vec<&str> = w["ap_group_ids"].as_array()?.iter().filter_map(Value::as_str).collect();
    let mut macs = Vec::new();
    for g in docs(state, "apgroup").filter(|g| id_of(g).is_some_and(|id| groups.contains(&id.as_str()))) {
        if g["attr_hidden_id"].as_str() == Some("default") {
            return None;
        }
        macs.extend(g["device_macs"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_ascii_lowercase));
    }
    macs.sort();
    macs.dedup();
    Some(macs)
}

/// GET /api/settings/wlans
pub async fn wlans(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (state, informs) = {
        let live = s.live.read().unwrap();
        (live.state.clone(), live.raw_informs.clone())
    };
    let Some(state) = state else { return Ok(Json(json!({ "active": s.active, "wlans": [], "networks": [] }))) };
    let list: Vec<Value> = docs(&state, "wlanconf")
        // The hidden "element" SSID belongs to the official controller's own adoption feature.
        .filter(|w| w["attr_hidden_id"].as_str().is_none())
        .map(|w| {
            let mut v = json!({
                "id": id_of(w), "aps": wlan_aps(&state, w), "protection": protection_of(w), "editable": w["attr_no_edit"].as_bool() != Some(true),
                "has_passphrase": w["x_passphrase"].as_str().is_some_and(|p| !p.is_empty()),
            });
            for f in WLAN_FIELDS {
                v[*f] = w[*f].clone();
            }
            v
        })
        .collect();
    let networks: Vec<Value> = docs(&state, "networkconf").map(|n| json!({ "id": id_of(n), "name": n["name"], "vlan": n["vlan"], "purpose": n["purpose"] })).collect();
    let aps: Vec<Value> = docs(&state, "devices").map(|d| json!({ "mac": d["mac"].as_str().map(str::to_ascii_lowercase), "name": d["name"] })).collect();
    let (unsupported, unknown) = feature_support(&state, &informs);
    let mdns: Vec<Value> = apcfg::MDNS_SERVICES.iter().map(|(code, name, _)| json!({ "code": code, "name": name })).collect();
    Ok(Json(json!({ "active": s.active, "wlans": list, "networks": networks, "aps": aps, "unsupported": unsupported, "unknown": unknown, "mdns_services": mdns })))
}

/// For each optional SSID feature, the APs that would broadcast the SSID
/// without it; and the APs whose support is not known yet (no inform).
fn feature_support(state: &Value, informs: &std::collections::HashMap<inform::Mac, std::sync::Arc<Value>>) -> (Value, Vec<String>) {
    let mut unsupported: serde_json::Map<String, Value> = apcfg::SSID_FEATURES.iter().map(|f| (f.to_string(), json!([]))).collect();
    let mut unknown = Vec::new();
    for d in docs(state, "devices") {
        let Some(mac) = d["mac"].as_str().map(str::to_ascii_lowercase) else { continue };
        let inform = mac.parse::<inform::Mac>().ok().and_then(|m| informs.get(&m));
        match apcfg::ssid_feature_support(d, inform.map(|v| v.as_ref())) {
            None => unknown.push(mac),
            Some(list) => {
                for (f, ok) in list {
                    if !ok {
                        unsupported[f].as_array_mut().unwrap().push(json!(mac));
                    }
                }
            }
        }
    }
    (Value::Object(unsupported), unknown)
}

/// GET /api/settings/wlans/{id}/passphrase: shown on request only.
pub async fn passphrase(State(s): State<AppState>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let state = s.live.read().unwrap().state.clone().ok_or_else(|| ApiError(StatusCode::CONFLICT, "no settings imported yet".into()))?;
    let w = docs(&state, "wlanconf").find(|w| id_of(w).as_deref() == Some(id.as_str())).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown SSID".into()))?;
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
    let Some(r) = inform.and_then(|p| p["radio_table"].as_array()?.iter().find(|r| r["radio"].as_str() == Some(band))) else { return Value::Null };
    json!({
        "min_txpower": r["min_txpower"], "max_txpower": r["max_txpower"], "has_ht160": r["has_ht160"], "has_dfs": r["has_dfs"],
        "is_11ax": r["is_11ax"], "nss": r["nss"],
    })
}

/// GET /api/settings/devices/{mac}
pub async fn device(State(s): State<AppState>, Path(mac): Path<String>) -> Result<Json<Value>, ApiError> {
    let (state, inform) = {
        let live = s.live.read().unwrap();
        let inform = mac.parse().ok().and_then(|m| live.raw_informs.get(&m).cloned());
        (live.state.clone(), inform)
    };
    let state = state.ok_or_else(|| ApiError(StatusCode::CONFLICT, "no settings imported yet".into()))?;
    let d = docs(&state, "devices")
        .find(|d| d["mac"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(&mac)))
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "this AP is not in the settings".into()))?;
    let radios: Vec<Value> = d["radio_table"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let mut v = json!({});
            for f in RADIO_FIELDS {
                v[*f] = r[*f].clone();
            }
            let band = r["radio"].as_str().unwrap_or("");
            v["caps"] = radio_caps(inform.as_deref(), band);
            v["channels"] = channels(&state, band, false);
            v["channels_outdoor"] = channels(&state, band, true);
            // The "interference blocker" exists only on radios reporting this capability.
            v["has_blocker"] = json!(r["radio_caps"].as_i64().is_some_and(|c| c & 131072 != 0));
            v
        })
        .collect();
    let supported: Vec<&str> = apcfg::device_feature_support(d, inform.as_deref()).map_or_else(|| apcfg::DEVICE_FEATURES.to_vec(), |l| l.into_iter().filter(|(_, ok)| *ok).map(|(f, _)| f).collect());
    let site_outdoor = docs(&state, "setting").any(|s| s["key"].as_str() == Some("mgmt") && s["outdoor_mode_enabled"].as_bool() == Some(true));
    let advanced = docs(&state, "setting").any(|s| s["key"].as_str() == Some("mgmt") && s["advanced_feature_enabled"].as_bool() == Some(true));
    let antennas: Vec<Value> = inform.as_deref().and_then(|p| p["antenna_table"].as_array().cloned()).unwrap_or_default();
    let mut out = json!({
        "active": s.active, "mac": mac.to_ascii_lowercase(), "model": d["model"], "radios": radios, "features": supported,
        "reported": inform.is_some(), "site_outdoor": site_outdoor, "advanced_features": advanced, "antennas": antennas,
        "ports": d["ethernet_table"].as_array().map_or(0, |t| t.iter().filter_map(|e| e["num_port"].as_i64()).sum::<i64>()),
    });
    for f in DEVICE_FIELDS {
        out[*f] = d[*f].clone();
    }
    Ok(Json(out))
}

// ---- Channels -------------------------------------------------------------

/// Countries using the European (ETSI) rules, by ISO 3166 numeric code: EU and
/// EEA members, the UK and Switzerland.
const ETSI: &[i64] = &[
    40, 56, 100, 191, 196, 203, 208, 233, 246, 250, 276, 300, 348, 352, 372, 380, 428, 438, 440, 442, 470, 528, 578, 616, 620, 642, 703, 705, 724, 752,
    756, 826,
];
/// Countries using the US (FCC) rules.
const FCC: &[i64] = &[840, 124];

/// Names of the countries the channel tables above cover, for the site settings.
pub(crate) const COUNTRY_NAMES: &[(i64, &str)] = &[
    (40, "Austria"), (56, "Belgium"), (100, "Bulgaria"), (124, "Canada"), (191, "Croatia"), (196, "Cyprus"), (203, "Czechia"), (208, "Denmark"),
    (233, "Estonia"), (246, "Finland"), (250, "France"), (276, "Germany"), (300, "Greece"), (348, "Hungary"), (352, "Iceland"), (372, "Ireland"),
    (380, "Italy"), (428, "Latvia"), (438, "Liechtenstein"), (440, "Lithuania"), (442, "Luxembourg"), (470, "Malta"), (528, "Netherlands"), (578, "Norway"),
    (616, "Poland"), (620, "Portugal"), (642, "Romania"), (703, "Slovakia"), (705, "Slovenia"), (724, "Spain"), (752, "Sweden"), (756, "Switzerland"),
    (826, "United Kingdom"), (840, "United States"),
];

/// The site's country (ISO 3166 numeric), from the `country` setting.
pub(crate) fn country(state: &Value) -> Option<i64> {
    let c = docs(state, "setting").find(|s| s["key"].as_str() == Some("country"))?;
    c["code"].as_i64().or_else(|| c["code"].as_str()?.parse().ok())
}

/// Legal primary channels for a band and width in the site's country (indoor,
/// or outdoor when `outdoor`). Unknown countries get the channels allowed
/// almost everywhere.
pub fn legal_channels(country: Option<i64>, band: &str, width: i64, outdoor: bool) -> Vec<i64> {
    let etsi = country.is_some_and(|c| ETSI.contains(&c));
    let fcc = country.is_some_and(|c| FCC.contains(&c));
    match band {
        "ng" if etsi => (1..=13).collect(),
        "ng" => (1..=11).collect(),
        "na" if etsi => {
            let low: Vec<i64> = if outdoor { vec![] } else { vec![36, 40, 44, 48, 52, 56, 60, 64] };
            // 140 has no partner for 40 MHz; 132-140 make no 80 MHz block.
            let high: &[i64] = match width {
                20 => &[100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140],
                40 => &[100, 104, 108, 112, 116, 120, 124, 128, 132, 136],
                _ => &[100, 104, 108, 112, 116, 120, 124, 128],
            };
            low.into_iter().chain(high.iter().copied()).collect()
        }
        "na" if fcc => {
            let mut c = vec![36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128];
            if width <= 80 {
                c.extend([132, 136, 140, 144, 149, 153, 157, 161]);
            }
            if width == 20 {
                c.push(165);
            }
            c
        }
        "na" => vec![36, 40, 44, 48],
        _ => Vec::new(),
    }
}

/// Whether outdoor channel rules apply to an AP (its own override, else the site's).
pub(crate) fn outdoor(state: &Value, d: &Value) -> bool {
    match d["outdoor_mode_override"].as_str() {
        Some("on") => true,
        Some("off") => false,
        _ => docs(state, "setting").any(|s| s["key"].as_str() == Some("mgmt") && s["outdoor_mode_enabled"].as_bool() == Some(true)),
    }
}

/// Channel choices per width for the editor.
fn channels(state: &Value, band: &str, o: bool) -> Value {
    let c = country(state);
    let widths: &[i64] = if band == "ng" { &[20, 40] } else { &[20, 40, 80, 160] };
    let mut out = serde_json::Map::new();
    for w in widths {
        out.insert(w.to_string(), json!(legal_channels(c, band, *w, o)));
    }
    Value::Object(out)
}

// ---- Validation helpers ---------------------------------------------------

fn new_id() -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).expect("system random source");
    hex::encode(b)
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
        v => match v.as_i64().or_else(|| v.as_str()?.parse().ok()) {
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

fn mac_list(patch: &Value, key: &str) -> Result<Option<Vec<String>>, String> {
    match &patch[key] {
        Value::Null => Ok(None),
        Value::Array(a) => {
            let mut out = Vec::new();
            for m in a {
                match m.as_str().map(str::trim) {
                    Some(m) if is_mac(m) => out.push(m.to_ascii_lowercase()),
                    _ => return Err(format!("{key}: {m} is not a MAC address")),
                }
            }
            out.dedup();
            Ok(Some(out))
        }
        _ => Err(format!("{key} must be a list of MAC addresses")),
    }
}

// ---- SSIDs ----------------------------------------------------------------

/// Security choices as the official UI offers them, mapped to
/// `(security, wpa_mode, wpa3_support, wpa3_transition)`.
const PROTECTION: &[(&str, &str, &str, bool, bool)] = &[
    ("wpa2", "wpapsk", "wpa2", false, false),
    ("wpa2_wpa3", "wpapsk", "wpa2", true, true),
    ("wpa3", "wpapsk", "wpa2", true, false),
    ("open", "open", "wpa2", false, false),
];

/// The protection choice of a stored SSID, if it is one the editor offers.
fn protection_of(w: &Value) -> Option<&'static str> {
    let wpa3 = w["wpa3_support"].as_bool().unwrap_or(false);
    let transition = w["wpa3_transition"].as_bool().unwrap_or(false);
    PROTECTION
        .iter()
        .find(|p| w["security"].as_str() == Some(p.1) && (p.1 == "open" && !wpa3 || p.1 != "open" && w["wpa_mode"].as_str().unwrap_or("wpa2") == p.2 && wpa3 == p.3 && (!wpa3 || transition == p.4)))
        .map(|p| p.0)
}

const MINRATE_NG: &[i64] = &[1000, 2000, 5500, 6000, 9000, 11000, 12000, 18000, 24000, 36000, 48000, 54000];
const MINRATE_NA: &[i64] = &[6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000];

fn find_wlan<'a>(state: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    state["wlanconf"].as_array_mut()?.iter_mut().find(|w| id_of(w).as_deref() == Some(id))
}

fn default_group(state: &Value) -> Option<String> {
    docs(state, "apgroup").find(|g| g["attr_hidden_id"].as_str() == Some("default")).and_then(id_of)
}

/// Sets which APs broadcast an SSID: all, or a list (kept in a hidden AP group
/// of its own, as the official controller does). Groups left unused are removed.
fn set_wlan_aps(state: &mut Value, id: &str, aps: Option<Vec<String>>) -> Result<(), String> {
    let site = site_id(state);
    let known: Vec<String> = docs(state, "devices").filter_map(|d| d["mac"].as_str().map(str::to_ascii_lowercase)).collect();
    let current: Vec<String> = find_wlan(state, id).and_then(|w| w["ap_group_ids"].as_array().cloned()).unwrap_or_default().iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let own = docs(state, "apgroup").find(|g| g["for_wlanconf"].as_bool() == Some(true) && id_of(g).is_some_and(|i| current.contains(&i))).and_then(id_of);
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
            if let Some(m) = macs.iter().find(|m| !known.contains(m)) {
                return Err(format!("{m} is not one of the APs"));
            }
            let gid = match &own {
                Some(g) => g.clone(),
                None => {
                    let g = new_id();
                    let mut doc = json!({ "_id": g, "name": "devices_ap_group", "for_wlanconf": true, "attr_no_delete": false, "device_macs": [] });
                    if let Some(s) = &site {
                        doc["site_id"] = json!(s);
                    }
                    if !state["apgroup"].is_array() {
                        state["apgroup"] = json!([]);
                    }
                    state["apgroup"].as_array_mut().unwrap().push(doc);
                    g
                }
            };
            if let Some(g) = state["apgroup"].as_array_mut().and_then(|l| l.iter_mut().find(|g| id_of(g).as_deref() == Some(gid.as_str()))) {
                g["device_macs"] = json!(macs);
            }
            let w = find_wlan(state, id).ok_or("unknown SSID")?;
            w["ap_group_mode"] = json!("devices");
            w["ap_group_ids"] = json!([gid]);
            w["broadcasting_aps"] = json!(macs);
        }
    }
    prune_groups(state);
    Ok(())
}

/// Removes per-SSID AP groups no SSID uses any more.
fn prune_groups(state: &mut Value) {
    let used: Vec<String> = state["wlanconf"].as_array().into_iter().flatten().flat_map(|w| w["ap_group_ids"].as_array().cloned().unwrap_or_default()).filter_map(|v| v.as_str().map(str::to_string)).collect();
    if let Some(groups) = state["apgroup"].as_array_mut() {
        groups.retain(|g| g["for_wlanconf"].as_bool() != Some(true) || id_of(g).is_some_and(|i| used.contains(&i)));
    }
}

/// The APs (lowercase MACs) an SSID is deployed to.
fn deployed_to(state: &Value, w: &Value) -> Vec<String> {
    let all: Vec<String> = docs(state, "devices").filter_map(|d| d["mac"].as_str().map(str::to_ascii_lowercase)).collect();
    match wlan_aps(state, w) {
        None if w["ap_group_ids"].as_array().is_some_and(|a| !a.is_empty()) => all,
        None => Vec::new(),
        Some(macs) => macs,
    }
}

/// mDNS proxy rules: where each applies (all APs, specific ones, AP groups),
/// which services pass (all, chosen ones, none), and the networks it bridges.
fn check_mdns_rules(state: &Value, v: &Value) -> Result<Vec<Value>, String> {
    let rules = v.as_array().ok_or("mdns_proxy_custom must be a list")?;
    if rules.len() > 16 {
        return Err("at most 16 mDNS rules".into());
    }
    let aps: Vec<String> = docs(state, "devices").filter_map(|d| d["mac"].as_str().map(str::to_ascii_lowercase)).collect();
    let groups: Vec<String> = docs(state, "apgroup").filter_map(id_of).collect();
    let networks: Vec<String> = docs(state, "networkconf").filter_map(id_of).collect();
    let mut out = Vec::new();
    for (i, r) in rules.iter().enumerate() {
        let n = i + 1;
        let scope = enum_field(r, "ap_scope_mode", &["all", "specific", "group"])?.unwrap_or("all");
        let services = enum_field(r, "services_mode", &["all", "specific", "none"])?.unwrap_or("all");
        let mut rule = json!({ "ap_scope_mode": scope, "services_mode": services, "isolation_enabled": bool_field(r, "isolation_enabled")?.unwrap_or(false) });
        let ids = |key: &str| -> Vec<String> { r[key].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(str::to_string)).collect() };
        let nets = ids("networkconf_ids");
        if let Some(bad) = nets.iter().find(|x| !networks.contains(x)) {
            return Err(format!("mDNS rule {n}: {bad} is not a network"));
        }
        rule["networkconf_ids"] = json!(nets);
        match scope {
            "specific" => {
                let macs: Vec<String> = ids("ap_macs").iter().map(|m| m.to_ascii_lowercase()).collect();
                if macs.is_empty() || macs.iter().any(|m| !aps.contains(m)) {
                    return Err(format!("mDNS rule {n}: choose the APs it applies on"));
                }
                rule["ap_macs"] = json!(macs);
            }
            "group" => {
                let g = ids("ap_group_ids");
                if g.is_empty() || g.iter().any(|x| !groups.contains(x)) {
                    return Err(format!("mDNS rule {n}: choose the AP groups it applies on"));
                }
                rule["ap_group_ids"] = json!(g);
            }
            _ => {}
        }
        if services == "specific" {
            let mut codes: Vec<String> = Vec::new();
            for c in r["predefined_services"].as_array().into_iter().flatten() {
                let code = c["code"].as_str().or(c.as_str()).unwrap_or("");
                if !apcfg::MDNS_SERVICES.iter().any(|(k, _, _)| *k == code) {
                    return Err(format!("mDNS rule {n}: {code} is not a known service"));
                }
                if !codes.iter().any(|x| x == code) {
                    codes.push(code.to_string());
                }
            }
            let mut custom = Vec::new();
            for c in r["custom_services"].as_array().into_iter().flatten() {
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

/// The official limit of SSIDs per radio band on an AP: 4 when wireless
/// meshing is on (the radios keep slots for it), else 8 (7 with element
/// adoption). Disabled SSIDs count too.
fn check_wlan_limits(state: &Value) -> Result<(), String> {
    let setting_on = |key: &str, default: bool| docs(state, "setting").find(|s| s["key"].as_str() == Some(key)).and_then(|s| s["enabled"].as_bool()).unwrap_or(default);
    let wlans: Vec<&Value> = docs(state, "wlanconf").collect();
    for d in docs(state, "devices") {
        let mac = d["mac"].as_str().unwrap_or_default().to_ascii_lowercase();
        let name = d["name"].as_str().unwrap_or(&mac);
        for (band, wb) in [("ng", "2g"), ("na", "5g"), ("6e", "6g")] {
            let radios: Vec<&Value> = d["radio_table"].as_array().into_iter().flatten().filter(|r| r["radio"].as_str() == Some(band)).collect();
            if radios.is_empty() {
                continue;
            }
            let limit = if setting_on("connectivity", true) && radios.iter().all(|r| r["vwire_enabled"].as_bool() != Some(false)) {
                4
            } else if setting_on("element_adopt", false) {
                7
            } else {
                8
            };
            let count = wlans
                .iter()
                .filter(|w| w["wlan_bands"].as_array().is_some_and(|b| b.iter().any(|x| x.as_str() == Some(wb))))
                .filter(|w| deployed_to(state, w).contains(&mac))
                .count();
            if count > limit {
                return Err(format!("{name} would have {count} SSIDs on its {} radio; it supports {limit}", band_name(band)));
            }
        }
    }
    Ok(())
}

fn band_name(band: &str) -> &'static str {
    match band {
        "ng" => "2.4 GHz",
        "na" => "5 GHz",
        _ => "6 GHz",
    }
}

/// What Force Wi-Fi 4 (`enhanced_iot`) holds an SSID to, with each field's
/// name for errors: the official controller's IoT template, plus the features
/// its UI clears and its validation refuses alongside it.
fn iot_template() -> Vec<(&'static str, Value, &'static str)> {
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
}

/// Applies an edit to one SSID (`body.id`, `body.patch`), with the official
/// controller's rules for each field and the fields it derives on save.
pub fn apply_wlan(state: &mut Value, body: &Value) -> Result<String, String> {
    let id = body["id"].as_str().ok_or("which SSID?")?.to_string();
    let p = &body["patch"];
    let before = find_wlan(state, &id).ok_or("unknown SSID")?.clone();
    if before["attr_no_edit"].as_bool() == Some(true) {
        return Err("this SSID cannot be edited".into());
    }
    let mut w = before.clone();
    let mut changed: Vec<&str> = Vec::new();

    if let Some(name) = p["name"].as_str().map(str::trim) {
        if name.is_empty() || name.len() > 32 {
            return Err("the network name (SSID) must be 1 to 32 bytes".into());
        }
        if docs(state, "wlanconf").any(|o| id_of(o).as_deref() != Some(id.as_str()) && o["name"].as_str() == Some(name)) {
            return Err(format!("another SSID is already called \"{name}\""));
        }
        w["name"] = json!(name);
    }

    // Force Wi-Fi 4: turning it on clears what it can't be combined with, as the
    // official UI does; the edit is then checked against it at the end.
    let was_iot = before["enhanced_iot"].as_bool() == Some(true);
    if let Some(b) = bool_field(p, "enhanced_iot")? {
        w["enhanced_iot"] = json!(b);
    }
    let iot = w["enhanced_iot"].as_bool() == Some(true);
    if iot && !was_iot {
        for (k, v, _) in iot_template() {
            w[k] = v;
        }
    }
    let iot_base = w.clone();

    for key in [
        "enabled", "hide_ssid", "is_guest", "proxy_arp", "l2_isolation", "uapsd_enabled", "bss_transition", "mcastenhance_enabled", "fast_roaming_enabled", "country_beacon",
    ] {
        if let Some(b) = bool_field(p, key)? {
            w[key] = json!(b);
        }
    }

    // Security.
    if let Some(choice) = enum_field(p, "protection", &PROTECTION.iter().map(|x| x.0).collect::<Vec<_>>())? {
        let (_, security, mode, wpa3, transition) = PROTECTION.iter().find(|x| x.0 == choice).copied().unwrap();
        w["security"] = json!(security);
        w["wpa_mode"] = json!(mode);
        w["wpa3_support"] = json!(wpa3);
        w["wpa3_transition"] = json!(transition);
        if security == "wpapsk" {
            w["wpa_enc"] = json!("ccmp");
        }
        // The protection decides PMF unless the edit sets it too.
        if p["pmf_mode"].is_null() {
            w["pmf_mode"] = json!(if wpa3 && transition { "optional" } else if wpa3 { "required" } else { "disabled" });
        }
    }
    if let Some(m) = enum_field(p, "pmf_mode", &["disabled", "optional", "required"])? {
        w["pmf_mode"] = json!(m);
    }
    let wpa3 = w["wpa3_support"].as_bool().unwrap_or(false);
    let transition = w["wpa3_transition"].as_bool().unwrap_or(false);
    let psk = w["security"].as_str() == Some("wpapsk");
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
    for key in ["sae_anti_clogging", "sae_sync"] {
        if let Some(n) = int_field(p, key, 1, 60)? {
            w[key] = json!(n);
        }
    }
    // Fast roaming for WPA3 clients of a WPA2/WPA3 SSID (the official UI never sets it).
    if let Some(b) = bool_field(p, "wpa3_fast_roaming")? {
        w["wpa3_fast_roaming"] = json!(b);
    }

    if let Some(pass) = p["passphrase"].as_str() {
        let printable = pass.chars().all(|c| (' '..='~').contains(&c));
        let hex64 = pass.len() == 64 && pass.chars().all(|c| c.is_ascii_hexdigit());
        let ok = if wpa3 && !transition { printable && (8..=255).contains(&pass.len()) } else { hex64 || printable && (8..=63).contains(&pass.len()) };
        if !ok {
            return Err("the password must be 8 to 63 printable ASCII characters (or 64 hex digits)".into());
        }
        w["x_passphrase"] = json!(pass);
        changed.push("password");
    }
    if psk && w["x_passphrase"].as_str().is_none_or(str::is_empty) {
        return Err("a password is needed for WPA2/WPA3".into());
    }

    // Bands.
    if !p["wlan_bands"].is_null() {
        let bands: Vec<String> = p["wlan_bands"].as_array().ok_or("wlan_bands must be a list")?.iter().filter_map(|b| b.as_str().map(str::to_string)).collect();
        if bands.is_empty() || bands.iter().any(|b| !["2g", "5g", "6g"].contains(&b.as_str())) {
            return Err("choose at least one band: 2g, 5g or 6g".into());
        }
        w["wlan_bands"] = json!(bands);
    }
    let bands: Vec<String> = w["wlan_bands"].as_array().into_iter().flatten().filter_map(|b| b.as_str().map(str::to_string)).collect();
    if bands.iter().any(|b| b == "6g") && !(wpa3 || w["security"].as_str() == Some("open")) {
        return Err("6 GHz needs WPA3 (or an open network)".into());
    }
    let has = |b: &str| bands.iter().any(|x| x == b);
    w["wlan_band"] = json!(if has("2g") && has("5g") { "both" } else if has("5g") { "5g" } else if has("6g") && bands.len() == 1 { "6g" } else { "2g" });

    // Roaming.
    if let Some(b) = bool_field(p, "roaming_assistant_na_enabled")? {
        w["roaming_assistant_na_enabled"] = json!(b);
    }
    if let Some(rssi) = int_field(p, "roaming_assistant_na_rssi", -80, -60)? {
        w["roaming_assistant_na_rssi"] = json!(rssi);
    }
    if w["roaming_assistant_na_enabled"].as_bool() == Some(true) && w["enhanced_iot"].as_bool() == Some(true) {
        return Err("the roaming assistant is not available with Force Wi-Fi 4".into());
    }

    // Band steering: dual-band clients the AP has seen on 5 GHz are kept off 2.4 GHz.
    let dual = bands.iter().any(|b| b == "2g") && bands.iter().any(|b| b == "5g");
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
            if b && !has("2g") {
                return Err("the IoT locks need 2.4 GHz".into());
            }
            w[key] = json!(b);
        }
        if !has("2g") && w[key].as_bool() == Some(true) {
            w[key] = json!(false);
        }
    }

    // Sent as they are; the official UI keeps but never shows the last three.
    for key in ["advertise_device_name_in_beacon", "rrm_enabled", "tdls_prohibit", "p2p", "p2p_cross_connect"] {
        if let Some(b) = bool_field(p, key)? {
            w[key] = json!(b);
        }
    }
    // hostapd's level for this SSID; -1 leaves the AP's default.
    if let Some(n) = int_field(p, "log_level", -1, 4)? {
        w["log_level"] = json!(n);
    }

    // DNS Assistance: the AP caches DNS and, when the network's server is slow
    // or fails, sends queries to fallback servers (its own choice, or these).
    if let Some(m) = enum_field(p, "dns_assistance_mode", &["off", "auto", "manual"])? {
        w["dns_assistance_mode"] = json!(m);
    }
    if !p["dns_assistance_servers"].is_null() {
        let list = p["dns_assistance_servers"].as_array().ok_or("dns_assistance_servers must be a list")?;
        let mut servers: Vec<String> = Vec::new();
        for v in list {
            let ip = v.as_str().map(str::trim).filter(|s| !s.is_empty());
            match ip.map(|s| (s, s.parse::<std::net::Ipv4Addr>())) {
                None => {}
                Some((s, Ok(_))) => servers.push(s.to_string()),
                Some((s, Err(_))) => return Err(format!("DNS server {s} is not an IPv4 address")),
            }
        }
        servers.dedup();
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
    if let Some(m) = enum_field(p, "mdns_proxy_mode", &["off", "auto", "custom"])? {
        w["mdns_proxy_mode"] = json!(m);
    }
    if !p["mdns_proxy_custom"].is_null() {
        w["mdns_proxy_custom"] = json!(check_mdns_rules(state, &p["mdns_proxy_custom"])?);
    }
    if w["mdns_proxy_mode"].as_str() == Some("custom") && w["mdns_proxy_custom"].as_array().is_none_or(Vec::is_empty) {
        return Err("custom mDNS needs at least one rule".into());
    }

    // Multicast and broadcast. The suppression mode decides the broadcast filter.
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

    // Data rates.
    if let Some(pref) = enum_field(p, "minrate_setting_preference", &["auto", "manual"])? {
        w["minrate_setting_preference"] = json!(pref);
    }
    if let Some(r) = int_field(p, "minrate_ng_data_rate_kbps", 1000, 54000)? {
        if !MINRATE_NG.contains(&r) {
            return Err(format!("{r} kbps is not a 2.4 GHz rate"));
        }
        w["minrate_ng_data_rate_kbps"] = json!(r);
    }
    if let Some(b) = bool_field(p, "minrate_na_enabled")? {
        w["minrate_na_enabled"] = json!(b);
    }
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

    // Power saving and rekeying.
    if let Some(m) = enum_field(p, "dtim_mode", &["default", "custom"])? {
        w["dtim_mode"] = json!(m);
    }
    for key in ["dtim_ng", "dtim_na"] {
        if let Some(n) = int_field(p, key, 1, 255)? {
            w[key] = json!(n);
        }
    }
    if w["dtim_mode"].as_str() != Some("custom") {
        w["dtim_ng"] = json!(1);
        w["dtim_na"] = json!(3);
        w["dtim_6e"] = json!(3);
    }
    if w["iot_dtim_lock"].as_bool() == Some(true) {
        if p["dtim_ng"].as_i64().is_some_and(|n| n != 3) {
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

    // MAC filter.
    if let Some(b) = bool_field(p, "mac_filter_enabled")? {
        w["mac_filter_enabled"] = json!(b);
    }
    if let Some(m) = enum_field(p, "mac_filter_policy", &["allow", "deny"])? {
        w["mac_filter_policy"] = json!(m);
    }
    if let Some(list) = mac_list(p, "mac_filter_list")? {
        w["mac_filter_list"] = json!(list);
    }

    // Speed limit: a user group; empty means the default group (no limit).
    if let Some(g) = p["usergroup_id"].as_str() {
        let id = if g.is_empty() { ensure_default_usergroup(state) } else { g.to_string() };
        if !docs(state, "usergroup").any(|x| id_of(x).as_deref() == Some(id.as_str())) {
            return Err("unknown speed limit".into());
        }
        w["usergroup_id"] = json!(id);
    }
    // Blackout schedule: periods the SSID is off.
    if !p["schedule_with_duration"].is_null() {
        w["schedule_with_duration"] = json!(check_schedule(&p["schedule_with_duration"])?);
    }

    // Network.
    if let Some(n) = p["networkconf_id"].as_str() {
        if !docs(state, "networkconf").any(|x| id_of(x).as_deref() == Some(n)) {
            return Err("unknown network".into());
        }
        w["networkconf_id"] = json!(n);
    }

    if iot {
        for (k, v, what) in iot_template() {
            if w[k] != v {
                // The edit asked for it: refuse. Otherwise the stored value just goes.
                if w[k] != iot_base[k] {
                    return Err(format!("{what} is not available with Force Wi-Fi 4"));
                }
                w[k] = v;
            }
        }
        w["wlan_band"] = json!("2g");
    }

    let locked_aps_before = if before["iot_channel_lock"].as_bool() == Some(true) { deployed_to(state, &before) } else { Vec::new() };
    *find_wlan(state, &id).ok_or("unknown SSID")? = w.clone();
    // "aps": null means all APs; no "aps" leaves them as they are.
    if p.get("aps").is_some() {
        let aps = match &p["aps"] {
            Value::Null => None,
            v => Some(mac_list(&json!({ "aps": v }), "aps")?.unwrap_or_default()),
        };
        set_wlan_aps(state, &id, aps)?;
    }
    check_wlan_limits(state)?;
    check_list_limits(state)?;
    let channels = apply_channel_locks(state, &locked_aps_before);

    let after = find_wlan(state, &id).ok_or("unknown SSID")?.clone();
    let mut keys: Vec<&str> = after.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
    keys.retain(|k| *k != "x_passphrase" && before[*k] != after[*k]);
    changed.extend(keys);
    let name = after["name"].as_str().unwrap_or("?");
    let mut what = if changed.is_empty() { format!("SSID \"{name}\": nothing changed") } else { format!("SSID \"{name}\": {}", changed.join(", ")) };
    if !channels.is_empty() {
        what.push_str(&format!("; {}", channels.join("; ")));
    }
    Ok(what)
}

/// APs (lowercase MACs) broadcasting an SSID with the IoT channel lock.
pub fn channel_locked_aps(state: &Value) -> Vec<String> {
    let mut out: Vec<String> = docs(state, "wlanconf").filter(|w| w["iot_channel_lock"].as_bool() == Some(true)).flat_map(|w| deployed_to(state, w)).collect();
    out.sort();
    out.dedup();
    out
}

/// Keeps the 2.4 GHz channel of APs in line with the SSIDs' channel locks, as
/// the official controller does when a lock changes: channel 6 on every AP an
/// SSID with the lock is broadcast from, and back to auto on an AP in
/// `released` (it had a locked SSID before the change) that has none left.
/// Returns what changed, in words.
fn apply_channel_locks(state: &mut Value, released: &[String]) -> Vec<String> {
    let locked = channel_locked_aps(state);
    let mut out = Vec::new();
    for d in state["devices"].as_array_mut().into_iter().flatten() {
        let Some(mac) = d["mac"].as_str().map(str::to_ascii_lowercase) else { continue };
        let target = if locked.contains(&mac) {
            json!("6")
        } else if released.contains(&mac) {
            json!("auto")
        } else {
            continue;
        };
        let name = d["name"].as_str().unwrap_or(&mac).to_string();
        let Some(r) = d["radio_table"].as_array_mut().and_then(|t| t.iter_mut().find(|r| r["radio"].as_str() == Some("ng"))) else { continue };
        let same = r["channel"] == target || r["channel"].as_i64().is_some_and(|c| c.to_string() == target.as_str().unwrap_or_default());
        if !same {
            r["channel"] = target.clone();
            out.push(format!("AP {name}: 2.4 GHz channel {}", target.as_str().unwrap_or_default()));
        }
    }
    out
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
        let days: Vec<String> = e["start_days_of_week"].as_array().into_iter().flatten().filter_map(|d| d.as_str().map(str::to_ascii_lowercase)).collect();
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
    let id = docs(state, "wlanconf").find_map(|w| w["usergroup_id"].as_str().filter(|g| !g.is_empty()).map(str::to_string)).unwrap_or_else(new_id);
    let mut doc = json!({ "_id": id, "name": "Default", "attr_hidden_id": "Default", "attr_no_delete": true, "qos_rate_max_down": -1, "qos_rate_max_up": -1 });
    if let Some(site) = site_id(state) {
        doc["site_id"] = json!(site);
    }
    if !state["usergroup"].is_array() {
        state["usergroup"] = json!([]);
    }
    state["usergroup"].as_array_mut().unwrap().push(doc);
    id
}

/// The id of the site's default user group (no speed limit).
pub fn default_usergroup(state: &Value) -> Option<String> {
    docs(state, "usergroup").find(|g| g["attr_hidden_id"].as_str() == Some("Default")).and_then(id_of)
}

/// Site-wide list limits: 256 broadcast-filter addresses in all, 512 MAC-filter
/// addresses over SSIDs on the same APs.
fn check_list_limits(state: &Value) -> Result<(), String> {
    let len = |w: &Value, k: &str| w[k].as_array().map_or(0, Vec::len);
    let bc: usize = docs(state, "wlanconf").filter(|w| w["bc_filter_enabled"].as_bool() == Some(true)).map(|w| len(w, "bc_filter_list")).sum();
    if bc > 256 {
        return Err(format!("{bc} broadcast-filter addresses in all; the limit is 256"));
    }
    let wlans: Vec<&Value> = docs(state, "wlanconf").filter(|w| w["mac_filter_enabled"].as_bool() == Some(true)).collect();
    for w in &wlans {
        let total: usize = wlans.iter().filter(|o| o["ap_group_ids"] == w["ap_group_ids"]).map(|o| len(o, "mac_filter_list")).sum();
        if total > 512 {
            return Err(format!("{total} MAC-filter addresses on the same APs; the limit is 512"));
        }
    }
    Ok(())
}

/// Creates an SSID (`body.patch` holds at least a name and, unless open, a
/// password) with the official controller's defaults for everything else.
pub fn create_wlan(state: &mut Value, body: &Value) -> Result<String, String> {
    let site = site_id(state).ok_or("the settings have no APs")?;
    let all = default_group(state).ok_or("the settings have no default AP group")?;
    let network = docs(state, "networkconf").find(|n| n["attr_hidden_id"].as_str() == Some("LAN")).or_else(|| docs(state, "networkconf").next()).and_then(id_of);
    let usergroup = ensure_default_usergroup(state);
    let short_id = docs(state, "wlanconf").filter_map(|w| w["short_id"].as_i64()).max().unwrap_or(0) + 1;
    let id = new_id();
    let mut iapp = [0u8; 16];
    getrandom::fill(&mut iapp).expect("system random source");
    let doc = json!({
        "_id": id, "site_id": site, "name": "", "enabled": true, "hide_ssid": false, "is_guest": false,
        "security": "wpapsk", "wpa_mode": "wpa2", "wpa_enc": "ccmp", "wpa3_support": false, "wpa3_transition": false, "pmf_mode": "disabled",
        "wlan_bands": ["2g", "5g"], "wlan_band": "both", "ap_group_mode": "all", "ap_group_ids": [all], "broadcasting_aps": [],
        "networkconf_id": network, "usergroup_id": usergroup, "iapp_enabled": true, "x_iapp_key": hex::encode(iapp), "short_id": short_id,
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
    let mut patch = body["patch"].clone();
    if patch["name"].as_str().is_none_or(|n| n.trim().is_empty()) {
        return Err("the new SSID needs a name".into());
    }
    if patch["protection"].is_null() {
        patch["protection"] = json!("wpa2");
    }
    let name = patch["name"].as_str().unwrap_or_default().trim().to_string();
    // Built on a copy, so a refused SSID leaves nothing behind.
    let mut next = state.clone();
    if !next["wlanconf"].is_array() {
        next["wlanconf"] = json!([]);
    }
    next["wlanconf"].as_array_mut().unwrap().push(doc);
    apply_wlan(&mut next, &json!({ "id": id, "patch": patch }))?;
    *state = next;
    Ok(format!("added SSID \"{name}\""))
}

/// Deletes an SSID (`body.id`) and its own AP group.
pub fn delete_wlan(state: &mut Value, body: &Value) -> Result<String, String> {
    let id = body["id"].as_str().ok_or("which SSID?")?;
    let w = find_wlan(state, id).ok_or("unknown SSID")?.clone();
    if w["attr_no_delete"].as_bool() == Some(true) {
        return Err("this SSID cannot be deleted".into());
    }
    let released = if w["iot_channel_lock"].as_bool() == Some(true) { deployed_to(state, &w) } else { Vec::new() };
    state["wlanconf"].as_array_mut().unwrap().retain(|x| id_of(x).as_deref() != Some(id));
    prune_groups(state);
    let channels = apply_channel_locks(state, &released);
    let mut what = format!("deleted SSID \"{}\"", w["name"].as_str().unwrap_or("?"));
    if !channels.is_empty() {
        what.push_str(&format!("; {}", channels.join("; ")));
    }
    Ok(what)
}

// ---- APs ------------------------------------------------------------------

/// Applies an edit to one AP (`body.mac`, `body.patch`: name, LED, and
/// `radios` by band), with the official controller's rules. `body.caps` holds
/// what the AP reports about its radios (power range, 160 MHz support).
pub fn apply_device(state: &mut Value, body: &Value) -> Result<String, String> {
    let mac = body["mac"].as_str().ok_or("which AP?")?.to_ascii_lowercase();
    let p = &body["patch"];
    let c = country(state);
    let devices = state["devices"].as_array().ok_or("the settings have no APs")?;
    let i = devices.iter().position(|d| d["mac"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(&mac))).ok_or("this AP is not in the settings")?;
    let before = devices[i].clone();
    // SSIDs locking this AP's 2.4 GHz channel for IoT devices.
    let iot_lock = docs(state, "wlanconf").any(|w| w["iot_channel_lock"].as_bool() == Some(true) && deployed_to(state, w).contains(&mac));
    let mut d = before.clone();

    if let Some(name) = p["name"].as_str() {
        let name = name.trim();
        if name.chars().count() > 128 {
            return Err("the name can be at most 128 characters".into());
        }
        d["name"] = json!(name);
    }
    if let Some(led) = enum_field(p, "led_override", &["default", "on", "off"])? {
        d["led_override"] = json!(led);
    }
    if let Some(b) = int_field(p, "led_override_color_brightness", 0, 100)? {
        d["led_override_color_brightness"] = json!(b);
    }
    if let Some(c) = p["led_override_color"].as_str() {
        d["led_override_color"] = json!(led_color(c)?);
    }
    for (key, allowed) in [("outdoor_mode_override", &["default", "on", "off"][..]), ("bandsteering_mode", &["off", "equal", "prefer_5g"]), ("resetbtn_enabled", &["on", "off"])] {
        if let Some(v) = enum_field(p, key, allowed)? {
            d[key] = json!(v);
        }
    }
    for key in ["snmp_location", "snmp_contact"] {
        if let Some(v) = p[key].as_str().map(str::trim) {
            if v.chars().count() > 255 {
                return Err(format!("{} can be at most 255 characters", key.replace('_', " ")));
            }
            d[key] = json!(v);
        }
    }
    for key in ["atf_enabled", "green_ap_enabled", "jumboframe_enabled"] {
        if let Some(b) = bool_field(p, key)? {
            d[key] = json!(b);
        }
    }
    // The antenna, from those the AP reports; each radio's gain follows it, as in
    // the official UI (which offers the choice only with two or more antennas).
    if let Some(a) = int_field(p, "antenna_id", 0, 9)? {
        let entry = body["antennas"].as_array().into_iter().flatten().find(|x| x["id"].as_i64() == Some(a)).ok_or_else(|| format!("this AP has no antenna {a}"))?;
        for r in d["radio_table"].as_array_mut().into_iter().flatten() {
            let gain = r["name"].as_str().and_then(|n| entry[format!("{n}_gain")].as_i64()).unwrap_or(6);
            r["antenna_id"] = json!(a);
            r["antenna_gain"] = json!(gain);
        }
    }
    if !p["config_network"].is_null() {
        let cn = check_config_network(&p["config_network"], &before["config_network"])?;
        if let Some(ip) = cn["ip"].as_str() {
            check_ip_free(state, &mac, ip)?;
        }
        d["config_network"] = cn;
    }
    // Outdoor mode changes which channels are legal.
    let o = outdoor(state, &d);

    for rp in p["radios"].as_array().into_iter().flatten() {
        let band = rp["radio"].as_str().ok_or("each radio needs its band (radio)")?;
        let caps = &body["caps"][band];
        let r = d["radio_table"].as_array_mut().and_then(|t| t.iter_mut().find(|r| r["radio"].as_str() == Some(band))).ok_or_else(|| format!("this AP has no {} radio", band_name(band)))?;
        let label = band_name(band);
        if !rp["ht"].is_null() {
            let ht = int_field(rp, "ht", 20, 320)?.unwrap_or(20);
            let ok = match band {
                "ng" => [20, 40].contains(&ht),
                "na" => [20, 40, 80].contains(&ht) || ht == 160 && caps["has_ht160"].as_bool() == Some(true),
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
                let ch = v.as_i64().or_else(|| v.as_str()?.parse().ok()).ok_or_else(|| format!("{label}: channel must be auto or a number"))?;
                r["channel"] = json!(ch);
            }
        }
        // A fixed channel must be legal for the (possibly new) width.
        if let Some(ch) = r["channel"].as_i64() {
            let width = r["ht"].as_i64().unwrap_or(20);
            if !legal_channels(c, band, width, o).contains(&ch) {
                return Err(format!("{label}: channel {ch} is not allowed at {width} MHz here"));
            }
        }
        if band == "ng" && iot_lock && r["channel"] != before["radio_table"].as_array().and_then(|t| t.iter().find(|x| x["radio"].as_str() == Some(band))).map_or(Value::Null, |x| x["channel"].clone()) {
            return Err("the 2.4 GHz channel is locked by an SSID's IoT setting".into());
        }
        if let Some(m) = enum_field(rp, "tx_power_mode", &["auto", "high", "medium", "low", "custom", "disabled"])? {
            r["tx_power_mode"] = json!(m);
        }
        if !rp["tx_power"].is_null() {
            let lo = caps["min_txpower"].as_i64().unwrap_or(1);
            let hi = caps["max_txpower"].as_i64().unwrap_or(30);
            let tx = int_field(rp, "tx_power", lo, hi).map_err(|_| format!("{label}: power must be {lo} to {hi} dBm"))?.unwrap_or(lo);
            r["tx_power"] = json!(tx);
        }
        if let Some(b) = bool_field(rp, "min_rssi_enabled")? {
            r["min_rssi_enabled"] = json!(b);
        }
        if let Some(v) = int_field(rp, "min_rssi", -90, -67)? {
            r["min_rssi"] = json!(v);
        }
        if let Some(b) = bool_field(rp, "hard_noise_floor_enabled")? {
            let capable = r["radio_caps"].as_i64().is_some_and(|c| c & 131072 != 0);
            if b && !capable {
                return Err(format!("{label}: this radio has no interference blocker"));
            }
            r["hard_noise_floor_enabled"] = json!(b);
        }
        for key in ["vwire_enabled", "sens_level_enabled", "loadbalance_enabled"] {
            if let Some(b) = bool_field(rp, key)? {
                r[key] = json!(b);
            }
        }
        if let Some(v) = int_field(rp, "sens_level", -90, -50)? {
            r["sens_level"] = json!(v);
        }
        if let Some(n) = int_field(rp, "maxsta", 1, 200)? {
            r["maxsta"] = json!(n);
        }
        if r["tx_power_mode"].as_str() == Some("disabled") && body["wireless_uplink"].as_str() == Some(band) {
            return Err(format!("{label}: this radio carries the AP's wireless uplink, so it cannot be turned off"));
        }
    }

    // Outdoor mode may have made a radio's fixed channel illegal.
    if o != outdoor(state, &before) {
        for r in d["radio_table"].as_array().into_iter().flatten() {
            let (band, width) = (r["radio"].as_str().unwrap_or(""), r["ht"].as_i64().unwrap_or(20));
            if let Some(ch) = r["channel"].as_i64().or_else(|| r["channel"].as_str()?.parse().ok())
                && !legal_channels(c, band, width, o).contains(&ch)
            {
                return Err(format!("{}: channel {ch} is not allowed {} here; pick another first", band_name(band), if o { "outdoors" } else { "indoors" }));
            }
        }
    }
    state["devices"].as_array_mut().unwrap()[i] = d.clone();
    let name = d["name"].as_str().unwrap_or(&mac).to_string();
    let mut changed: Vec<String> = Vec::new();
    for k in DEVICE_FIELDS {
        if before[*k] != d[*k] {
            changed.push(k.replace('_', " "));
        }
    }
    let radios = |v: &Value| v["radio_table"].as_array().cloned().unwrap_or_default();
    for (b, a) in radios(&before).iter().zip(radios(&d).iter()) {
        let keys: Vec<&str> = RADIO_FIELDS.iter().copied().filter(|k| b[*k] != a[*k]).collect();
        if !keys.is_empty() {
            changed.push(format!("{} radio: {}", band_name(a["radio"].as_str().unwrap_or("")), keys.join(", ")));
        }
    }
    Ok(if changed.is_empty() { format!("AP {name}: nothing changed") } else { format!("AP {name}: {}", changed.join("; ")) })
}

/// The AP's own address: DHCP, or static with an address, netmask, a gateway
/// on that subnet, a DNS server (a second one and a search domain optional).
fn check_config_network(p: &Value, before: &Value) -> Result<Value, String> {
    use std::net::Ipv4Addr;
    let ip = |key: &str, required: bool| -> Result<Option<Ipv4Addr>, String> {
        match p[key].as_str().map(str::trim).filter(|s| !s.is_empty()) {
            None if required => Err(format!("a static address needs {key}")),
            None => Ok(None),
            Some(s) => s.parse().map(Some).map_err(|_| format!("{key}: {s} is not an IPv4 address")),
        }
    };
    let mut out = json!({ "type": "dhcp" });
    if let Some(b) = before["bonding_enabled"].as_bool() {
        out["bonding_enabled"] = json!(b);
    }
    match p["type"].as_str() {
        Some("dhcp") => return Ok(out),
        Some("static") => {}
        _ => return Err("config_network.type must be dhcp or static".into()),
    }
    let addr = ip("ip", true)?.unwrap();
    let mask = ip("netmask", true)?.unwrap();
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
    let gw = ip("gateway", true)?.unwrap();
    if u32::from(gw) & m != net || gw == addr {
        return Err(format!("the gateway {gw} must be another address on {}/{}", Ipv4Addr::from(net), m.leading_ones()));
    }
    out["gateway"] = json!(gw.to_string());
    for (key, required) in [("dns1", true), ("dns2", false)] {
        if let Some(d) = ip(key, required)? {
            out[key] = json!(d.to_string());
        }
    }
    if let Some(suffix) = p["dnssuffix"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        if suffix.len() > 253 || !suffix.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')) {
            return Err(format!("{suffix} is not a domain name"));
        }
        out["dnssuffix"] = json!(suffix);
    }
    Ok(out)
}

/// A static address must not be another AP's, or one reserved for a client.
fn check_ip_free(state: &Value, mac: &str, ip: &str) -> Result<(), String> {
    if let Some(o) = docs(state, "devices").find(|o| o["mac"].as_str().is_some_and(|m| !m.eq_ignore_ascii_case(mac)) && o["config_network"]["type"].as_str() == Some("static") && o["config_network"]["ip"].as_str() == Some(ip)) {
        return Err(format!("{ip} is already {}'s address", o["name"].as_str().or(o["mac"].as_str()).unwrap_or("another AP")));
    }
    if let Some(c) = docs(state, "clients").find(|c| c["use_fixedip"].as_bool() == Some(true) && c["fixed_ip"].as_str() == Some(ip)) {
        return Err(format!("{ip} is reserved for the client {}", c["name"].as_str().or(c["hostname"].as_str()).or(c["mac"].as_str()).unwrap_or("?")));
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
    patch: Value,
}

/// PUT /api/settings/wlans/{id} {patch} (`?preview=true` to see the effect)
pub async fn put_wlan(State(s): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    change(&s, &headers, &q, apply_wlan, json!({ "id": id, "patch": b.patch })).await
}

/// POST /api/settings/wlans {patch}
pub async fn post_wlan(State(s): State<AppState>, headers: HeaderMap, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    change(&s, &headers, &q, create_wlan, json!({ "patch": b.patch })).await
}

/// DELETE /api/settings/wlans/{id}
pub async fn delete_wlan_route(State(s): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<PreviewQuery>) -> Result<Json<Value>, ApiError> {
    change(&s, &headers, &q, delete_wlan, json!({ "id": id })).await
}

/// PUT /api/settings/devices/{mac} {patch}
pub async fn put_device(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    let inform = mac.parse::<inform::Mac>().ok().and_then(|m| s.live.read().unwrap().raw_informs.get(&m).cloned());
    let caps = json!({ "ng": radio_caps(inform.as_deref(), "ng"), "na": radio_caps(inform.as_deref(), "na"), "6e": radio_caps(inform.as_deref(), "6e") });
    // A mesh AP's uplink radio must stay on.
    let uplink = inform.as_deref().filter(|p| p["uplink"]["type"].as_str() == Some("wireless")).and_then(|p| p["uplink"]["radio"].as_str().map(str::to_string));
    let antennas = inform.as_deref().map_or(Value::Null, |p| p["antenna_table"].clone());
    change(&s, &headers, &q, apply_device, json!({ "mac": mac, "patch": b.patch, "caps": caps, "wireless_uplink": uplink, "antennas": antennas })).await
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
        apply_wlan(s, &json!({ "id": "w1", "patch": patch }))
    }

    #[test]
    fn protection_sets_wpa3_and_pmf_as_the_official_ui_does() {
        let mut s = state();
        edit(&mut s, json!({ "protection": "wpa2_wpa3" })).unwrap();
        let w = &s["wlanconf"][0];
        assert_eq!((w["wpa3_support"].as_bool(), w["wpa3_transition"].as_bool(), w["pmf_mode"].as_str()), (Some(true), Some(true), Some("optional")));
        assert_eq!(protection_of(w), Some("wpa2_wpa3"));
        assert!(edit(&mut s, json!({ "pmf_mode": "disabled" })).unwrap_err().contains("PMF"));
        edit(&mut s, json!({ "protection": "wpa3" })).unwrap();
        assert_eq!(s["wlanconf"][0]["pmf_mode"], "required");
        assert!(edit(&mut s, json!({ "pmf_mode": "optional" })).is_err(), "WPA3 alone needs PMF required");
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
        assert_eq!(protection_of(w), Some("wpa2"));
        // While it is on, asking for one of them is refused.
        assert!(edit(&mut s, json!({ "dns_assistance_mode": "auto" })).unwrap_err().contains("Force Wi-Fi 4"));
        assert!(edit(&mut s, json!({ "wlan_bands": ["2g", "5g"] })).is_err());
        assert!(edit(&mut s, json!({ "protection": "wpa3" })).is_err());
        edit(&mut s, json!({ "enhanced_iot": false, "wlan_bands": ["2g", "5g"] })).unwrap();
    }

    #[test]
    fn the_channel_lock_moves_its_aps_to_6_and_back() {
        let mut s = state();
        let what = edit(&mut s, json!({ "iot_channel_lock": true })).unwrap();
        assert!(what.contains("Hall: 2.4 GHz channel 6") && what.contains("Attic"), "{what}");
        assert_eq!(s["devices"][0]["radio_table"][0]["channel"], "6");
        assert!(apply_device(&mut s, &json!({ "mac": AP1, "patch": { "radios": [{ "radio": "ng", "channel": 1 }] } })).is_err());
        // Narrowed to one AP: the other is released.
        edit(&mut s, json!({ "aps": [AP1] })).unwrap();
        assert_eq!((s["devices"][0]["radio_table"][0]["channel"].as_str(), s["devices"][1]["radio_table"][0]["channel"].as_str()), (Some("6"), Some("auto")));
        // Dropping 2.4 GHz ends the lock.
        edit(&mut s, json!({ "wlan_bands": ["5g"] })).unwrap();
        assert_eq!(s["wlanconf"][0]["iot_channel_lock"], false);
        assert_eq!(s["devices"][0]["radio_table"][0]["channel"], "auto");
        assert!(edit(&mut s, json!({ "iot_dtim_lock": true })).is_err());
    }

    #[test]
    fn dtim_lock_and_sae_timers() {
        let mut s = state();
        edit(&mut s, json!({ "iot_dtim_lock": true })).unwrap();
        assert_eq!(s["wlanconf"][0]["dtim_ng"], 3);
        assert!(edit(&mut s, json!({ "dtim_mode": "custom", "dtim_ng": 1 })).is_err());
        edit(&mut s, json!({ "protection": "wpa3" })).unwrap();
        assert_eq!((s["wlanconf"][0]["sae_anti_clogging"].as_i64(), s["wlanconf"][0]["sae_sync"].as_i64()), (Some(5), Some(5)));
        assert!(edit(&mut s, json!({ "sae_sync": 61 })).is_err());
        edit(&mut s, json!({ "sae_sync": 10 })).unwrap();
        assert!(edit(&mut s, json!({ "dns_assistance_mode": "manual", "dns_assistance_servers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"] })).is_err());
    }

    #[test]
    fn mdns_rules_are_checked() {
        let mut s = state();
        assert!(edit(&mut s, json!({ "mdns_proxy_mode": "custom" })).unwrap_err().contains("at least one rule"));
        let rule = json!({ "ap_scope_mode": "specific", "ap_macs": [AP2.to_uppercase()], "services_mode": "specific",
            "predefined_services": [{ "code": "apple_airPlay" }, { "code": "apple_airPlay" }], "custom_services": [{ "address": "_myapp._tcp.local" }] });
        edit(&mut s, json!({ "mdns_proxy_mode": "custom", "mdns_proxy_custom": [rule] })).unwrap();
        let r = &s["wlanconf"][0]["mdns_proxy_custom"][0];
        assert_eq!((r["ap_macs"][0].as_str(), r["predefined_services"].as_array().unwrap().len()), (Some(AP2), 1));
        assert_eq!(r["custom_services"][0]["name"], "_myapp._tcp.local");
        let bad = |r: Value| edit(&mut state(), json!({ "mdns_proxy_mode": "custom", "mdns_proxy_custom": [r] })).is_err();
        assert!(bad(json!({ "services_mode": "specific", "predefined_services": [{ "code": "telnet" }] })));
        assert!(bad(json!({ "services_mode": "specific", "custom_services": [{ "address": "myapp.local" }] })));
        assert!(bad(json!({ "services_mode": "specific" })), "no services chosen");
        assert!(bad(json!({ "ap_scope_mode": "specific", "ap_macs": ["02:00:00:00:00:99"] })), "unknown AP");
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
    }

    #[test]
    fn specific_aps_use_a_group_of_their_own_which_goes_when_unused() {
        let mut s = state();
        edit(&mut s, json!({ "aps": [AP2] })).unwrap();
        let w = &s["wlanconf"][0];
        assert_eq!((w["ap_group_mode"].as_str(), w["broadcasting_aps"][0].as_str()), (Some("devices"), Some(AP2)));
        let gid = w["ap_group_ids"][0].as_str().unwrap().to_string();
        let g = s["apgroup"].as_array().unwrap().iter().find(|g| id_of(g).as_deref() == Some(gid.as_str())).unwrap();
        assert_eq!((g["for_wlanconf"].as_bool(), g["device_macs"][0].as_str()), (Some(true), Some(AP2)));
        assert_eq!(wlan_aps(&s, &s["wlanconf"][0]), Some(vec![AP2.to_string()]));
        // The same group is reused, then removed when the SSID goes back to all APs.
        edit(&mut s, json!({ "aps": [AP1, AP2] })).unwrap();
        assert_eq!(s["wlanconf"][0]["ap_group_ids"][0].as_str(), Some(gid.as_str()));
        edit(&mut s, json!({ "aps": null })).unwrap();
        assert_eq!((s["wlanconf"][0]["ap_group_mode"].as_str(), s["apgroup"].as_array().unwrap().len()), (Some("all"), 1));
        assert!(edit(&mut s, json!({ "aps": ["02:00:00:00:00:99"] })).is_err());
        assert!(edit(&mut s, json!({ "aps": [] })).is_err());
    }

    #[test]
    fn ssids_per_radio_are_limited_like_the_official_controller() {
        let mut s = state();
        for i in 0..7 {
            create_wlan(&mut s, &json!({ "patch": { "name": format!("N{i}"), "passphrase": "password1" } })).unwrap();
        }
        let err = create_wlan(&mut s, &json!({ "patch": { "name": "N8", "passphrase": "password1" } })).unwrap_err();
        assert!(err.contains("supports 8"), "{err}");
        // With wireless meshing on, the radios keep slots for it: 4 per band.
        let mut s = state();
        s["setting"][1]["enabled"] = json!(true);
        for i in 0..3 {
            create_wlan(&mut s, &json!({ "patch": { "name": format!("N{i}"), "passphrase": "password1" } })).unwrap();
        }
        assert!(create_wlan(&mut s, &json!({ "patch": { "name": "N4", "passphrase": "password1" } })).unwrap_err().contains("supports 4"));
    }

    #[test]
    fn new_ssids_get_defaults_and_deleting_cleans_up() {
        let mut s = state();
        assert!(create_wlan(&mut s, &json!({ "patch": { "name": "Guest" } })).unwrap_err().contains("password"));
        assert!(create_wlan(&mut s, &json!({ "patch": { "name": "Home", "passphrase": "password1" } })).unwrap_err().contains("already"));
        create_wlan(&mut s, &json!({ "patch": { "name": "Guest", "passphrase": "password1", "aps": [AP1] } })).unwrap();
        let w = s["wlanconf"][1].clone();
        assert_eq!((w["short_id"].as_i64(), w["networkconf_id"].as_str(), w["x_iapp_key"].as_str().map(str::len)), (Some(3), Some("n1"), Some(32)));
        assert_eq!((w["minrate_ng_enabled"].as_bool(), w["wlan_band"].as_str(), w["dtim_na"].as_i64()), (Some(true), Some("both"), Some(3)));
        assert_eq!(s["apgroup"].as_array().unwrap().len(), 2);
        delete_wlan(&mut s, &json!({ "id": id_of(&w) })).unwrap();
        assert_eq!((s["wlanconf"].as_array().unwrap().len(), s["apgroup"].as_array().unwrap().len()), (1, 1));
        s["wlanconf"][0]["attr_no_delete"] = json!(true);
        assert!(delete_wlan(&mut s, &json!({ "id": "w1" })).is_err());
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
        let eu = Some(276);
        assert_eq!(legal_channels(eu, "ng", 20, false), (1..=13).collect::<Vec<_>>());
        assert!(legal_channels(eu, "na", 20, false).contains(&140) && !legal_channels(eu, "na", 40, false).contains(&140));
        assert!(!legal_channels(eu, "na", 80, false).contains(&132) && !legal_channels(eu, "na", 20, false).contains(&149));
        assert!(!legal_channels(eu, "na", 20, true).contains(&36), "outdoors only 100-140 in Europe");
        assert!(legal_channels(Some(840), "na", 20, false).contains(&165));
        assert_eq!(legal_channels(None, "ng", 20, false).len(), 11);
    }

    fn dev(s: &mut Value, patch: Value) -> Result<String, String> {
        let caps = json!({ "na": { "min_txpower": 6, "max_txpower": 26, "has_ht160": false }, "ng": { "min_txpower": 6, "max_txpower": 22 } });
        apply_device(s, &json!({ "mac": AP1, "patch": patch, "caps": caps }))
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
        // An IoT channel lock on an SSID here freezes the 2.4 GHz channel.
        s["wlanconf"][0]["iot_channel_lock"] = json!(true);
        assert!(dev(&mut s, json!({ "radios": [{ "radio": "ng", "channel": 6 }] })).unwrap_err().contains("IoT"));
        dev(&mut s, json!({ "radios": [{ "radio": "ng", "tx_power_mode": "low" }] })).unwrap();
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
        dev(&mut s, json!({ "config_network": { "type": "dhcp", "ip": "192.168.1.20" } })).unwrap();
        assert_eq!(s["devices"][0]["config_network"], json!({ "type": "dhcp" }));
    }

    #[test]
    fn radio_extras_are_range_checked() {
        let mut s = state();
        let antennas = json!([{ "id": 4, "name": "Combined", "wifi0_gain": 3, "wifi1_gain": 5 }, { "id": 5, "name": "External" }]);
        let caps = json!({ "na": { "min_txpower": 6, "max_txpower": 26 }, "ng": { "min_txpower": 6, "max_txpower": 22 } });
        let any = |s: &mut Value, p: Value| apply_device(s, &json!({ "mac": AP1, "patch": p, "caps": caps, "antennas": antennas }));
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
    match v.as_i64() {
        Some(-1) => Ok(-1),
        Some(n) if (2..=100_000).contains(&n) => Ok(n),
        _ => Err(format!("the {what} limit must be 2 to 100000 kbps, or -1 for none")),
    }
}

/// Who uses a user group: SSID and client names.
fn group_users(state: &Value, id: &str) -> Vec<String> {
    let mut out: Vec<String> = docs(state, "wlanconf").filter(|w| w["usergroup_id"].as_str() == Some(id)).map(|w| format!("SSID {}", w["name"].as_str().unwrap_or("?"))).collect();
    out.extend(
        state["clients"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["usergroup_id"].as_str() == Some(id))
            .map(|c| format!("client {}", c["name"].as_str().or(c["hostname"].as_str()).or(c["mac"].as_str()).unwrap_or("?"))),
    );
    out
}

/// Creates (`body.id` null), edits or deletes (`body.delete`) a user group.
pub fn apply_usergroup(state: &mut Value, body: &Value) -> Result<String, String> {
    ensure_default_usergroup(state);
    let id = body["id"].as_str().map(str::to_string);
    if body["delete"].as_bool() == Some(true) {
        let id = id.ok_or("which speed limit?")?;
        let g = docs(state, "usergroup").find(|g| id_of(g).as_deref() == Some(id.as_str())).ok_or("unknown speed limit")?.clone();
        if g["attr_no_delete"].as_bool() == Some(true) {
            return Err("the default speed limit cannot be deleted".into());
        }
        let users = group_users(state, &id);
        if !users.is_empty() {
            return Err(format!("still used by {}", users.join(", ")));
        }
        state["usergroup"].as_array_mut().unwrap().retain(|x| id_of(x).as_deref() != Some(id.as_str()));
        return Ok(format!("deleted speed limit \"{}\"", g["name"].as_str().unwrap_or("?")));
    }
    let p = &body["patch"];
    let name = p["name"].as_str().map(str::trim);
    if name.is_some_and(|n| n.is_empty() || n.chars().count() > 128) {
        return Err("the name must be 1 to 128 characters".into());
    }
    let down = if p["qos_rate_max_down"].is_null() { None } else { Some(rate(&p["qos_rate_max_down"], "download")?) };
    let up = if p["qos_rate_max_up"].is_null() { None } else { Some(rate(&p["qos_rate_max_up"], "upload")?) };
    if let Some(n) = name
        && docs(state, "usergroup").any(|g| g["name"].as_str() == Some(n) && id_of(g) != id)
    {
        return Err(format!("another speed limit is called \"{n}\""));
    }
    let site = site_id(state);
    let list = state["usergroup"].as_array_mut().unwrap();
    let (g, created) = match &id {
        Some(id) => (list.iter_mut().find(|g| id_of(g).as_deref() == Some(id.as_str())).ok_or("unknown speed limit")?, false),
        None => {
            let n = name.ok_or("the new speed limit needs a name")?;
            let mut doc = json!({ "_id": new_id(), "name": n, "qos_rate_max_down": -1, "qos_rate_max_up": -1 });
            if let Some(s) = site {
                doc["site_id"] = json!(s);
            }
            list.push(doc);
            (list.last_mut().unwrap(), true)
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

/// Sets a client's own speed limit (`body.mac`, `body.usergroup_id`; null or
/// empty removes it, so the SSID's applies).
pub fn apply_client_group(state: &mut Value, body: &Value) -> Result<String, String> {
    let mac = body["mac"].as_str().ok_or("which client?")?.to_ascii_lowercase();
    if !is_mac(&mac) {
        return Err("invalid MAC address".into());
    }
    let group = body["usergroup_id"].as_str().filter(|g| !g.is_empty()).map(str::to_string);
    let name = match &group {
        Some(g) => docs(state, "usergroup").find(|x| id_of(x).as_deref() == Some(g.as_str())).ok_or("unknown speed limit")?["name"].as_str().unwrap_or("?").to_string(),
        None => String::new(),
    };
    crate::actions::edit_client(state, &mac, &[("usergroup_id", group.clone().map_or(Value::Null, Value::String))])?;
    Ok(match group {
        Some(_) => format!("client {mac}: speed limit \"{name}\""),
        None => format!("client {mac}: no own speed limit"),
    })
}

/// GET /api/settings/usergroups
pub async fn usergroups(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let state = s.live.read().unwrap().state.clone();
    let Some(state) = state else { return Ok(Json(json!({ "active": s.active, "groups": [] }))) };
    let mut with_default = (*state).clone();
    ensure_default_usergroup(&mut with_default);
    let groups: Vec<Value> = docs(&with_default, "usergroup")
        .map(|g| {
            let id = id_of(g).unwrap_or_default();
            json!({
                "id": id, "name": g["name"], "default": g["attr_hidden_id"].as_str() == Some("Default"),
                "qos_rate_max_down": g["qos_rate_max_down"], "qos_rate_max_up": g["qos_rate_max_up"], "used_by": group_users(&with_default, &id),
            })
        })
        .collect();
    Ok(Json(json!({ "active": s.active, "groups": groups })))
}

/// POST /api/settings/usergroups {patch}
pub async fn post_usergroup(State(s): State<AppState>, headers: HeaderMap, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    change(&s, &headers, &q, apply_usergroup, json!({ "patch": b.patch })).await
}

/// PUT /api/settings/usergroups/{id} {patch}
pub async fn put_usergroup(State(s): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    change(&s, &headers, &q, apply_usergroup, json!({ "id": id, "patch": b.patch })).await
}

/// DELETE /api/settings/usergroups/{id}
pub async fn delete_usergroup(State(s): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<PreviewQuery>) -> Result<Json<Value>, ApiError> {
    change(&s, &headers, &q, apply_usergroup, json!({ "id": id, "delete": true })).await
}

#[derive(Deserialize)]
pub struct ClientGroupBody {
    usergroup_id: Option<String>,
}

/// PUT /api/clients/{mac}/speed-limit {usergroup_id}
pub async fn put_client_group(State(s): State<AppState>, headers: HeaderMap, Path(mac): Path<String>, Query(q): Query<PreviewQuery>, Json(b): Json<ClientGroupBody>) -> Result<Json<Value>, ApiError> {
    change(&s, &headers, &q, apply_client_group, json!({ "mac": mac, "usergroup_id": b.usergroup_id })).await
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
    }

    #[test]
    fn speed_limits_are_checked_and_not_deleted_while_used() {
        let mut s = state();
        let what = apply_usergroup(&mut s, &json!({ "patch": { "name": "Kids", "qos_rate_max_down": 5000, "qos_rate_max_up": -1 } })).unwrap();
        assert!(what.contains("down 5 Mbps, up none"), "{what}");
        let id = id_of(s["usergroup"].as_array().unwrap().iter().find(|g| g["name"] == "Kids").unwrap()).unwrap();
        assert!(apply_usergroup(&mut s, &json!({ "id": id, "patch": { "qos_rate_max_down": 1 } })).is_err(), "0 and 1 kbps are not allowed");
        assert!(apply_usergroup(&mut s, &json!({ "patch": { "name": "Kids" } })).is_err(), "names are unique");
        apply_client_group(&mut s, &json!({ "mac": "AA:BB:CC:00:00:01", "usergroup_id": id })).unwrap();
        let err = apply_usergroup(&mut s, &json!({ "id": id, "delete": true })).unwrap_err();
        assert!(err.contains("client tv"), "{err}");
        apply_client_group(&mut s, &json!({ "mac": "aa:bb:cc:00:00:01", "usergroup_id": null })).unwrap();
        apply_usergroup(&mut s, &json!({ "id": id, "delete": true })).unwrap();
        assert!(apply_usergroup(&mut s, &json!({ "id": "ug-imported", "delete": true })).is_err(), "the default stays");
        // An SSID back to "no limit" points at the default group.
        apply_wlan(&mut s, &json!({ "id": "w1", "patch": { "usergroup_id": "" } })).unwrap();
        assert_eq!(s["wlanconf"][0]["usergroup_id"], "ug-imported");
        assert!(apply_wlan(&mut s, &json!({ "id": "w1", "patch": { "usergroup_id": "nope" } })).is_err());
    }

    #[test]
    fn blackout_schedules_are_checked() {
        let mut s = state();
        let ok = json!([{ "start_days_of_week": ["Mon", "tue"], "start_hour": 22, "start_minute": 30, "duration_minutes": 480, "name": "night" }]);
        apply_wlan(&mut s, &json!({ "id": "w1", "patch": { "schedule_with_duration": ok } })).unwrap();
        assert_eq!(s["wlanconf"][0]["schedule_with_duration"][0]["start_days_of_week"], json!(["mon", "tue"]));
        for bad in [
            json!([{ "start_days_of_week": [], "start_hour": 1, "duration_minutes": 10 }]),
            json!([{ "start_days_of_week": ["mon"], "start_hour": 24, "duration_minutes": 10 }]),
            json!([{ "start_days_of_week": ["mon"], "start_hour": 1, "duration_minutes": 0 }]),
            json!([{ "start_days_of_week": ["funday"], "start_hour": 1, "duration_minutes": 10 }]),
        ] {
            assert!(apply_wlan(&mut s, &json!({ "id": "w1", "patch": { "schedule_with_duration": bad } })).is_err(), "{bad}");
        }
        apply_wlan(&mut s, &json!({ "id": "w1", "patch": { "schedule_with_duration": [] } })).unwrap();
        assert_eq!(s["wlanconf"][0]["schedule_with_duration"], json!([]));
    }
}
