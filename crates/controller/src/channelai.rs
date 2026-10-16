//! Channel AI: scans the RF environment and moves APs to better channels,
//! nightly at the hour set in the site's `radio_ai` setting, or on request.
//!
//! As the official controller does it: every AP with the band first runs a
//! "quick scan" (`{"_type":"cmd","cmd":"quick-scan","scan-band","scan-bw"}`, its
//! utilisation and interference per channel come back in `spectrum_table`),
//! then a plan is made at each radio's current width from the channels the
//! setting allows. It is applied only when clearly better (by more than 10%)
//! or when an AP sits on a channel no longer allowed, by writing fixed
//! channels into the APs' radio settings, which go out as a normal config.
//! APs on a wireless uplink keep their channel, as do excluded ones (the
//! official controller keeps the exclusion list but no longer reads it;
//! apctl honours it). The plan itself is apctl's own (see `insights`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use inform::Mac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};
use crate::engine::{Event, Input, Live};
use crate::model::Ts;
use crate::adopt::{device_doc, device_doc_mut};
use crate::settings::{band_channels, country, device_macs, inform_radio, is_legal, legal_channels, num, setting, setting_mut, uplink};
use crate::store;

/// Bands Channel AI handles (6 GHz needs hardware apctl has not seen).
const BANDS: &[&str] = &["ng", "na"];
/// Longest wait for one AP's quick scan.
const SCAN_TIMEOUT: Ts = 120;

/// A quick scan in progress on one AP.
#[derive(Clone, Debug, Serialize)]
pub struct Scan {
    pub band: String,
    pub started: Ts,
    /// The AP has reported `quickscan_scanning: true` since.
    #[serde(skip)]
    seen_scanning: bool,
}

/// The `radio_ai` setting, as Channel AI uses it.
#[derive(Debug, Serialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    pub hour: i64,
    pub minute: i64,
    pub radios: Vec<String>,
    pub dfs: bool,
    pub exclude_devices: Vec<String>,
}

fn radio_ai(state: &Value) -> Option<&Value> {
    Some(setting(state, "radio_ai")).filter(|r| !r.is_null())
}

/// `M H * * *` (the only form the official UI writes); 03:00 otherwise, its default.
fn parse_cron(expr: &str) -> (i64, i64) {
    let f: Vec<&str> = expr.split_whitespace().collect();
    match f.as_slice() {
        [m, h, "*", "*", "*"] => match (m.parse::<i64>(), h.parse::<i64>()) {
            (Ok(m), Ok(h)) if (0..60).contains(&m) && (0..24).contains(&h) => (h, m),
            _ => (3, 0),
        },
        _ => (3, 0),
    }
}

pub fn settings(state: Option<&Value>) -> Settings {
    let r = state.and_then(radio_ai);
    let (hour, minute) = parse_cron(r.and_then(|r| r["cron_expr"].as_str()).unwrap_or("0 3 * * *"));
    let list = |k: &str| -> Vec<String> { r.and_then(|r| r[k].as_array()).into_iter().flatten().filter_map(|v| v.as_str().map(str::to_ascii_lowercase)).collect() };
    let radios = r.map_or_else(|| BANDS.iter().map(|b| b.to_string()).collect(), |_| list("radios"));
    let dfs = r.and_then(|r| r["radios_configuration"].as_array()?.iter().find(|c| c["radio"].as_str() == Some("na"))?["dfs"].as_bool()).unwrap_or(false);
    Settings { enabled: r.and_then(|r| r["enabled"].as_bool()).unwrap_or(false), hour, minute, radios, dfs, exclude_devices: list("exclude_devices") }
}

/// Whether a 5 GHz channel is a DFS one (radar can force the AP off it).
pub(crate) fn is_dfs(ch: i64) -> bool {
    (52..=144).contains(&ch)
}

/// The channels a plan may use on a band: the setting's list (kept by the
/// official controller as the country's channels minus the blacklist, and
/// minus DFS unless allowed), within what is legal here. `with_dfs` adds the
/// legal DFS channels (to try a plan with them). `None` without a setting.
/// In a country apctl has no rules for, the list is taken as it is.
pub fn allowed(state: Option<&Value>, band: &str, with_dfs: bool) -> Option<Vec<i64>> {
    let state = state?;
    let r = radio_ai(state)?;
    let legal = legal_channels(country(state), band, 20, false);
    let mut list: Vec<i64> = r[format!("channels_{band}")].as_array()?.iter().filter_map(num).filter(|c| legal.as_ref().is_none_or(|l| l.contains(c))).collect();
    if with_dfs && band == "na" {
        let all = legal.unwrap_or_else(|| band_channels(band, 20));
        let extra: Vec<i64> = all.into_iter().filter(|c| is_dfs(*c) && !list.contains(c)).collect();
        list.extend(extra);
    }
    list.sort();
    Some(list)
}

/// APs whose channel on `band` a plan must not change: excluded in the
/// setting, on a wireless uplink (moving them would cut them off), being
/// upgraded, or (2.4 GHz) held on channel 6 by an SSID's IoT channel lock.
pub fn pinned(live: &Live, band: &str) -> Vec<String> {
    let mut out = settings(live.state.as_deref()).exclude_devices;
    if band == "ng" {
        out.extend(live.state.as_deref().map(crate::settings::channel_locked_aps).unwrap_or_default());
    }
    out.extend(live.raw_informs.iter().filter(|(_, p)| uplink(p).is_wireless()).map(|(mac, _)| mac.to_string()));
    if let Some(j) = &live.firmware.current {
        out.push(j.mac.to_string());
    }
    out
}

fn band_index(band: &str) -> i64 {
    match band {
        "ng" => 0,
        "na" => 1,
        _ => 2,
    }
}

/// How old (seconds) the AP's spectrum table for a band is: `spectrum_table_time`
/// counts up from the last scan with every report.
fn spectrum_age(inform: &Value, band: &str) -> Option<i64> {
    inform_radio(inform, band)?["spectrum_table_time"].as_i64()
}

/// Asks every AP that can to scan a band; returns the APs asked. Scans go out
/// with each AP's next inform (see `actions`).
pub fn start_scans(live: &mut Live, band: &str, now: Ts) -> Vec<Mac> {
    let width = match band {
        "ng" => 20,
        "na" => 80,
        _ => 160,
    };
    let eligible: Vec<Mac> = live
        .devices
        .iter()
        .filter(|(_, d)| d.online)
        .filter_map(|(mac, _)| {
            let p = live.raw_informs.get(mac)?;
            let caps = p["wifi_caps2"].as_u64().unwrap_or(0);
            (caps & 128 != 0 && !uplink(p).is_wireless() && inform_radio(p, band).is_some()).then_some(*mac)
        })
        .collect();
    for mac in &eligible {
        crate::actions::queue(live, *mac, json!({ "_type": "cmd", "cmd": "quick-scan", "scan-band": band_index(band), "scan-bw": width }));
        live.scans.insert(*mac, Scan { band: band.to_string(), started: now, seen_scanning: false });
    }
    eligible
}

/// Marks finished scans: the AP reported scanning and then stopped, its
/// spectrum table for the band is younger than the request, it went offline,
/// or it timed out.
pub fn check_scans(live: &mut Live, now: Ts) {
    let Live { scans, raw_informs, devices, .. } = live;
    scans.retain(|mac, s| {
        let Some(p) = raw_informs.get(mac) else { return false };
        match p["quickscan_scanning"].as_bool() {
            Some(true) => s.seen_scanning = true,
            Some(false) if s.seen_scanning => return false,
            _ => {}
        }
        let renewed = spectrum_age(p, &s.band).is_some_and(|age| age < now - s.started);
        let offline = devices.get(mac).is_some_and(|d| !d.online);
        !renewed && !offline && now - s.started < SCAN_TIMEOUT
    });
}

/// Waits (up to the timeout) until no scan is running.
async fn wait_for_scans(s: &AppState) {
    for _ in 0..(SCAN_TIMEOUT / 2 + 5) {
        {
            let mut live = s.live.write().unwrap();
            check_scans(&mut live, store::now_ts());
            if live.scans.is_empty() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Writes fixed channels into the APs' radio settings (`changes`: AP, band,
/// channel), checking each is legal at the radio's width and allowed.
pub fn set_channels(state: &mut Value, changes: &[(String, String, i64)]) -> Result<(), String> {
    let c = country(state);
    let locked = crate::settings::channel_locked_aps(state);
    for (mac, band, ch) in changes {
        if band == "ng" && locked.contains(&mac.to_ascii_lowercase()) {
            return Err(format!("{mac}: the 2.4 GHz channel is locked by an SSID's IoT setting"));
        }
        let allowed_here = allowed(Some(state), band, true);
        if !state["devices"].is_array() {
            return Err("the settings have no APs".into());
        }
        let m: Mac = mac.parse().map_err(|_| format!("{mac} is not in the settings"))?;
        let d = device_doc(state, &m).ok_or_else(|| format!("{mac} is not in the settings"))?;
        let outdoor = crate::settings::outdoor(state, d);
        let d = device_doc_mut(state, &m).expect("found above");
        let r = d["radio_table"].as_array_mut().and_then(|t| t.iter_mut().find(|r| r["radio"].as_str() == Some(band))).ok_or_else(|| format!("{mac} has no {band} radio"))?;
        let width = num(&r["ht"]).unwrap_or(20);
        if is_legal(c, band, width, outdoor, *ch) == Some(false) {
            return Err(format!("channel {ch} is not allowed at {width} MHz here"));
        }
        if allowed_here.is_some_and(|a| !a.contains(ch)) {
            return Err(format!("channel {ch} is not one of the channels Channel AI may use"));
        }
        r["channel"] = json!(ch);
        r["ht"] = json!(width);
    }
    Ok(())
}

/// One Channel AI run already going (nightly or asked for).
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Holds [`RUNNING`] for one run and lets it go however the run ends (a
/// panic included), so Channel AI is never left "already running".
struct RunGuard;

impl RunGuard {
    fn take() -> Option<RunGuard> {
        (!RUNNING.swap(true, Ordering::SeqCst)).then_some(RunGuard)
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

/// A channel move of one AP, as a plan lists it and the API takes it back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub mac: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub from: Option<i64>,
    #[serde(alias = "channel")]
    pub to: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<i64>,
}

/// Scans, plans and (when worth it) applies, band by band.
pub async fn run(s: AppState, bands: Vec<String>, trigger: &'static str) {
    let Some(_running) = RunGuard::take() else {
        tracing::info!("channel AI: a run is already going");
        return;
    };
    for band in bands.iter().filter(|b| BANDS.contains(&b.as_str())) {
        let scanned = start_scans(&mut s.live.write().unwrap(), band, store::now_ts());
        tracing::info!("channel AI ({trigger}): {} APs scanning {band}", scanned.len());
        wait_for_scans(&s).await;
        // The engine queues an AP's scan results before it shows the scan as
        // done: once they are committed, the plan reads them.
        let w = s.writer.clone();
        if !tokio::task::spawn_blocking(move || w.flush(Duration::from_secs(10))).await.unwrap_or(false) {
            tracing::warn!("channel AI: the scan results were not stored in time; planning {band} with what is there");
        }
        let (allowed, pinned) = {
            let live = s.live.read().unwrap();
            (allowed(live.state.as_deref(), band, false), pinned(&live, band))
        };
        let plan = match crate::insights::compute_plan(&s, band.clone(), false, allowed, pinned).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("channel AI: no plan for {band}: {}", e.1);
                continue;
            }
        };
        let changes: Vec<Change> = plan
            .plan
            .iter()
            .filter(|p| p.change)
            .filter_map(|p| Some(Change { mac: p.mac.clone(), name: p.name.clone(), from: p.current_channel, to: p.suggested_channel?, width: Some(p.width) }))
            .collect();
        let mut data = json!({
            "band": band, "trigger": trigger, "scanned": scanned.len(), "changes": changes,
            "current_total": plan.current_total, "suggested_total": plan.suggested_total, "applied": false,
        });
        if !changes.is_empty() {
            match apply(&s, band, &changes, trigger).await {
                Ok(()) => data["applied"] = json!(true),
                Err(e) => data["error"] = json!(e.1),
            }
        }
        let _ = s.engine.send(Input::Note(Event::site(store::now_ts(), "channel_plan", data))).await;
    }
}

async fn apply(s: &AppState, band: &str, changes: &[Change], trigger: &str) -> Result<(), ApiError> {
    let list: Vec<(String, String, i64)> = changes.iter().map(|c| (c.mac.clone(), band.to_string(), c.to)).collect();
    let show = |c: &Change| format!("{} {} → {}", c.name.as_deref().unwrap_or(&c.mac), c.from.map_or_else(|| "null".to_string(), |f| f.to_string()), c.to);
    let what = format!("channel AI ({trigger}): {}", changes.iter().map(show).collect::<Vec<_>>().join(", "));
    crate::actions::edit_settings(s, what, move |state| set_channels(state, &list)).await
}

/// Runs Channel AI nightly at the setting's hour, in the site's time zone
/// (active mode only: in shadow mode the other controller does this).
pub fn schedule(s: AppState) {
    if !s.active {
        return;
    }
    tokio::spawn(async move {
        let mut last_day = None;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let (cfg, tz) = {
                let live = s.live.read().unwrap();
                let st = live.state.as_deref();
                let tz = st.and_then(crate::settings::timezone).map(str::to_string);
                (settings(st), tz)
            };
            let (day, minute) = crate::clock::local(tz.as_deref(), store::now_ts());
            if cfg.enabled && minute == cfg.hour * 60 + cfg.minute && last_day != Some(day) {
                last_day = Some(day);
                run(s.clone(), cfg.radios.clone(), "nightly").await;
            }
        }
    });
}

/// The next nightly run (UTC), if enabled: the first minute after now at the
/// setting's local time, today or on one of the next days (a time skipped by
/// a summer-time change is skipped that day, as the scheduler skips it).
fn next_run(cfg: &Settings, tz: Option<&str>, now: Ts) -> Option<Ts> {
    if !cfg.enabled {
        return None;
    }
    let target = cfg.hour * 60 + cfg.minute;
    // The zone's rule, looked up once; unknown zones are UTC (as in `clock::local`).
    let rule = tz.and_then(apcfg::tz::posix);
    let offset = |t: Ts| rule.and_then(|r| crate::clock::utc_offset(r, t)).unwrap_or(0);
    let local = |t: Ts| (t + offset(t)).rem_euclid(86400) / 60;
    let first = now - now % 60 + 60;
    let today = (first + offset(first)).div_euclid(86400);
    (0..3).find_map(|day| {
        let wall = (today + day) * 86400 + target * 60;
        // The UTC time of that wall-clock time, under the offset before or after a change.
        [wall - offset(wall), wall - offset(wall - offset(wall))].into_iter().filter(|t| *t >= first && local(*t) == target).min()
    })
}

// ---- API ------------------------------------------------------------------

/// GET /api/rf/channel-ai
pub async fn status(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    // Finished scans are cleared under the write lock; the rest needs only a copy.
    let (state, scans) = {
        let mut live = s.live.write().unwrap();
        check_scans(&mut live, store::now_ts());
        let scans: Vec<Value> = live.scans.iter().map(|(m, sc)| json!({ "mac": m, "band": sc.band, "started": sc.started })).collect();
        (live.state.clone(), scans)
    };
    let st = state.as_deref();
    let tz = st.and_then(crate::settings::timezone);
    let cfg = settings(st);
    Ok(Json(json!({
        "active": s.active, "has_settings": st.and_then(radio_ai).is_some(), "timezone": tz,
        "next_run": next_run(&cfg, tz, store::now_ts()), "running": RUNNING.load(Ordering::SeqCst), "scans": scans,
        "allowed": { "ng": allowed(st, "ng", false), "na": allowed(st, "na", false) }, "settings": cfg,
    })))
}

#[derive(Deserialize)]
pub struct BandBody {
    band: String,
}

/// POST /api/rf/scan {band}
pub async fn scan(State(s): State<AppState>, Json(b): Json<BandBody>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    if !BANDS.contains(&b.band.as_str()) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "band must be ng or na".into()));
    }
    let asked = start_scans(&mut s.live.write().unwrap(), &b.band, store::now_ts());
    if asked.is_empty() {
        return Err(ApiError(StatusCode::CONFLICT, "no online AP can scan this band".into()));
    }
    Ok(Json(json!({ "scanning": asked })))
}

#[derive(Deserialize)]
pub struct RunBody {
    bands: Option<Vec<String>>,
}

/// POST /api/rf/channel-ai/run {bands?}: scan, plan and apply now.
pub async fn run_now(State(s): State<AppState>, Json(b): Json<RunBody>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    if RUNNING.load(Ordering::SeqCst) {
        return Err(ApiError(StatusCode::CONFLICT, "Channel AI is already running".into()));
    }
    let bands = b.bands.unwrap_or_else(|| settings(s.live.read().unwrap().state.as_deref()).radios);
    tokio::spawn(run(s.clone(), bands, "manual"));
    Ok(Json(json!({ "started": true })))
}

#[derive(Deserialize)]
pub struct ApplyBody {
    band: String,
    /// `{mac, name, from, to}` as the plan listed them.
    changes: Vec<Change>,
}

/// POST /api/rf/channel-plan/apply {band, changes}: apply a plan as shown.
/// Every change must be complete (a malformed one refuses the whole plan).
pub async fn apply_plan(State(s): State<AppState>, Json(b): Json<Value>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "this needs")?;
    let b: ApplyBody = serde_json::from_value(b).map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("not a plan: {e}")))?;
    if !BANDS.contains(&b.band.as_str()) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "band must be ng or na".into()));
    }
    if b.changes.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "the plan changes nothing".into()));
    }
    if let Some(c) = b.changes.iter().find(|c| !crate::settings::is_mac(&c.mac)) {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("{} is not a MAC address", c.mac)));
    }
    apply(&s, &b.band, &b.changes, "manual").await?;
    let data = json!({ "band": b.band, "trigger": "manual", "changes": b.changes, "applied": true });
    let _ = s.engine.send(Input::Note(Event::site(store::now_ts(), "channel_plan", data))).await;
    Ok(Json(json!({ "applied": b.changes.len() })))
}

/// Edits the `radio_ai` setting (`patch`: enabled, hour, radios, dfs,
/// exclude_devices), creating it with the official defaults when missing. The
/// channel lists are recomputed as the official controller does: the
/// country's channels minus the blacklist, minus DFS unless allowed (every
/// channel of the band in a country apctl has no rules for).
pub fn apply_settings(state: &mut Value, p: &Value) -> Result<String, String> {
    let c = country(state);
    let known = device_macs(state);
    let missing = radio_ai(state).is_none();
    let r = setting_mut(state, "radio_ai");
    if missing {
        let blacklist: Vec<Value> = [2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 14].iter().map(|c| json!({ "radio": "ng", "channel": c.to_string(), "channel_width": "20" })).collect();
        let defaults = json!({
            "enabled": false, "cron_expr": "0 3 * * *", "radios": ["ng", "na"], "channels_blacklist": blacklist,
            "radios_configuration": [{ "radio": "ng", "channel_width": 20, "dfs": false }, { "radio": "na", "channel_width": 40, "dfs": false }],
            "exclude_devices": [],
        });
        if let (Some(r), Value::Object(d)) = (r.as_object_mut(), defaults) {
            r.extend(d);
        }
    }
    let before = r.clone();
    if let Some(b) = p["enabled"].as_bool() {
        r["enabled"] = json!(b);
    }
    if !p["hour"].is_null() {
        let h = p["hour"].as_i64().filter(|h| (0..24).contains(h)).ok_or("the hour must be 0 to 23")?;
        r["cron_expr"] = json!(format!("0 {h} * * *"));
    }
    if !p["radios"].is_null() {
        let radios: Vec<String> = p["radios"].as_array().ok_or("radios must be a list")?.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        if radios.iter().any(|b| !BANDS.contains(&b.as_str())) {
            return Err("radios can be ng and na".into());
        }
        r["radios"] = json!(radios);
    }
    if let Some(dfs) = p["dfs"].as_bool() {
        let mut confs = r["radios_configuration"].as_array().cloned().unwrap_or_default();
        match confs.iter_mut().find(|c| c["radio"].as_str() == Some("na")) {
            Some(c) => c["dfs"] = json!(dfs),
            None => confs.push(json!({ "radio": "na", "channel_width": 40, "dfs": dfs })),
        }
        r["radios_configuration"] = json!(confs);
    }
    if !p["exclude_devices"].is_null() {
        let macs: Vec<String> = p["exclude_devices"].as_array().ok_or("exclude_devices must be a list")?.iter().filter_map(|v| v.as_str().map(str::to_ascii_lowercase)).collect();
        if let Some(m) = macs.iter().find(|m| !known.contains(m)) {
            return Err(format!("{m} is not one of the APs"));
        }
        r["exclude_devices"] = json!(macs);
    }
    // The allowed channels follow the country, blacklist and DFS choice.
    let blacklist = r["channels_blacklist"].as_array().cloned().unwrap_or_default();
    let blacklisted = |band: &str, ch: i64| {
        blacklist.iter().any(|b| {
            b["radio"].as_str() == Some(band) && num(&b["channel"]) == Some(ch) && b["channel_width"].as_str().is_none_or(|w| w == "20")
        })
    };
    let dfs = r["radios_configuration"].as_array().and_then(|l| l.iter().find(|c| c["radio"].as_str() == Some("na"))).and_then(|c| c["dfs"].as_bool()).unwrap_or(false);
    for band in BANDS {
        let chans: Vec<String> = legal_channels(c, band, 20, false).unwrap_or_else(|| band_channels(band, 20)).into_iter().filter(|ch| !blacklisted(band, *ch) && (dfs || !is_dfs(*ch))).map(|ch| ch.to_string()).collect();
        r[format!("channels_{band}")] = json!(chans);
    }
    let changed: Vec<&str> = ["enabled", "cron_expr", "radios", "radios_configuration", "exclude_devices", "channels_ng", "channels_na"].into_iter().filter(|k| before[*k] != r[*k]).collect();
    Ok(if changed.is_empty() { "Channel AI: nothing changed".into() } else { format!("Channel AI settings: {}", changed.join(", ")) })
}

/// PUT /api/rf/channel-ai {patch} (`?preview=true` to see the effect)
pub async fn put_settings(State(s): State<AppState>, Query(q): Query<crate::settings::PreviewQuery>, Json(b): Json<Value>) -> Result<Json<Value>, ApiError> {
    crate::settings::change(&s, &q, apply_settings, b["patch"].clone()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Value {
        json!({
            "devices": [{ "mac": "02:00:00:00:00:01", "site_id": "s1", "radio_table": [{ "radio": "na", "channel": 44, "ht": 80 }, { "radio": "ng", "channel": "auto", "ht": 20 }] }],
            "setting": [
                { "key": "country", "code": "276", "site_id": "s1" },
                { "key": "locale", "timezone": "Europe/Berlin", "site_id": "s1" },
                { "key": "radio_ai", "site_id": "s1", "enabled": true, "cron_expr": "0 5 * * *", "radios": ["ng", "na"], "channels_ng": ["1", "6", "11"],
                  "channels_na": ["36", "40", "44", "48"], "radios_configuration": [{ "radio": "na", "dfs": false, "channel_width": 40 }], "exclude_devices": [],
                  "channels_blacklist": [{ "radio": "ng", "channel": "2", "channel_width": "20" }, { "radio": "ng", "channel": "13", "channel_width": "20" }] },
            ],
        })
    }

    #[test]
    fn settings_come_from_the_radio_ai_setting() {
        let s = state();
        let cfg = settings(Some(&s));
        assert_eq!((cfg.enabled, cfg.hour, cfg.minute, cfg.dfs), (true, 5, 0, false));
        assert_eq!(allowed(Some(&s), "na", false), Some(vec![36, 40, 44, 48]));
        assert_eq!(allowed(Some(&s), "na", true).unwrap().len(), 4 + 15, "plus the legal DFS channels");
        assert_eq!(allowed(Some(&s), "ng", false), Some(vec![1, 6, 11]));
        assert_eq!(parse_cron("*/5 * * * *"), (3, 0));
        assert!(allowed(None, "na", false).is_none());
    }

    #[test]
    fn editing_settings_recomputes_the_channels() {
        let mut s = state();
        apply_settings(&mut s, &json!({ "dfs": true, "hour": 4 })).unwrap();
        let r = radio_ai(&s).unwrap();
        assert_eq!(r["cron_expr"], "0 4 * * *");
        assert!(r["channels_na"].as_array().unwrap().iter().any(|c| c == "100"));
        // ng: Germany's 1-13 minus the blacklist (2 and 13 here).
        assert_eq!(r["channels_ng"].as_array().unwrap().len(), 11);
        assert!(apply_settings(&mut s, &json!({ "hour": 24 })).is_err());
        assert!(apply_settings(&mut s, &json!({ "exclude_devices": ["02:00:00:00:00:99"] })).is_err());
        apply_settings(&mut s, &json!({ "exclude_devices": ["02:00:00:00:00:01"] })).unwrap();
        assert_eq!(settings(Some(&s)).exclude_devices, vec!["02:00:00:00:00:01"]);
    }

    #[test]
    fn plans_are_written_as_fixed_channels_when_legal() {
        let mut s = state();
        set_channels(&mut s, &[("02:00:00:00:00:01".into(), "ng".into(), 6)]).unwrap();
        assert_eq!(s["devices"][0]["radio_table"][1]["channel"], 6, "an auto radio is pinned");
        assert!(set_channels(&mut s, &[("02:00:00:00:00:01".into(), "na".into(), 140)]).is_err(), "not at 80 MHz");
        assert!(set_channels(&mut s, &[("02:00:00:00:00:01".into(), "ng".into(), 3)]).is_err(), "not in the allowed list");
        set_channels(&mut s, &[("02:00:00:00:00:01".into(), "na".into(), 36)]).unwrap();
    }

    #[test]
    fn scans_finish_when_the_spectrum_table_is_newer_than_the_request() {
        let mut live = Live::default();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let inform = |age: i64, scanning: Option<bool>| {
            let mut p = json!({ "wifi_caps2": 128, "uplink": "eth0", "radio_table": [{ "radio": "na", "spectrum_table_time": age }] });
            if let Some(b) = scanning {
                p["quickscan_scanning"] = json!(b);
            }
            std::sync::Arc::new(p)
        };
        live.raw_informs.insert(ap, inform(56_000, None));
        // (Asked for directly: start_scans only asks APs that are online.)
        crate::actions::queue(&mut live, ap, json!({ "_type": "cmd", "cmd": "quick-scan" }));
        live.scans.insert(ap, Scan { band: "na".into(), started: 1000, seen_scanning: false });
        assert_eq!(crate::actions::next(&mut live, &ap).unwrap()["cmd"], "quick-scan");
        check_scans(&mut live, 1010);
        assert_eq!(live.scans.len(), 1, "the old table does not count");
        live.raw_informs.insert(ap, inform(56_011, Some(true)));
        check_scans(&mut live, 1020);
        assert_eq!(live.scans.len(), 1);
        live.raw_informs.insert(ap, inform(3, None));
        check_scans(&mut live, 1040);
        assert!(live.scans.is_empty(), "a table 3 s old is from this scan");
        // Without an answer, a scan gives up after two minutes.
        live.scans.insert(ap, Scan { band: "na".into(), started: 2000, seen_scanning: false });
        live.raw_informs.insert(ap, inform(56_000, None));
        check_scans(&mut live, 2000 + SCAN_TIMEOUT);
        assert!(live.scans.is_empty());
    }

    #[test]
    fn the_next_run_is_at_the_local_hour() {
        let s = state();
        let cfg = settings(Some(&s));
        // 2026-07-01 00:00 UTC: 05:00 in Berlin (summer) is 03:00 UTC.
        let now = 1_782_864_000;
        assert_eq!(next_run(&cfg, Some("Europe/Berlin"), now), Some(now + 3 * 3600));
        // Just past it: tomorrow; in winter 05:00 in Berlin is 04:00 UTC; no zone is UTC.
        assert_eq!(next_run(&cfg, Some("Europe/Berlin"), now + 3 * 3600), Some(now + 27 * 3600));
        let winter = 1_796_083_200; // 2026-12-01 00:00 UTC
        assert_eq!(next_run(&cfg, Some("Europe/Berlin"), winter), Some(winter + 4 * 3600));
        assert_eq!(next_run(&cfg, None, winter), Some(winter + 5 * 3600));
        // 02:30 does not exist on 2026-03-29 in Berlin: the next run is the day after.
        let cfg = Settings { hour: 2, minute: 30, ..settings(Some(&s)) };
        let before = 1_774_742_400; // 2026-03-29 00:00 UTC
        assert_eq!(next_run(&cfg, Some("Europe/Berlin"), before), Some(before + 86400 + 30 * 60));
    }

    #[test]
    fn a_run_that_panics_lets_go_of_the_flag() {
        let r = std::panic::catch_unwind(|| {
            let _g = RunGuard::take().unwrap();
            assert!(RunGuard::take().is_none(), "one run at a time");
            panic!("plan failed");
        });
        assert!(r.is_err());
        assert!(!RUNNING.load(Ordering::SeqCst));
    }

    #[test]
    fn plan_changes_must_be_complete() {
        let ok: ApplyBody = serde_json::from_value(json!({ "band": "na", "changes": [{ "mac": "02:00:00:00:00:01", "name": null, "from": 44, "to": 36 }] })).unwrap();
        assert_eq!((ok.changes[0].to, ok.changes[0].from), (36, Some(44)));
        assert!(serde_json::from_value::<ApplyBody>(json!({ "band": "na", "changes": [{ "mac": "02:00:00:00:00:01", "to": null }] })).is_err());
        assert!(serde_json::from_value::<ApplyBody>(json!({ "band": "na", "changes": [{ "to": 36 }] })).is_err());
    }
}
