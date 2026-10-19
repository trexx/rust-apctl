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
//! apctl honours it). The plan itself is apctl's own (see `channelplan`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::extract::State;
use inform::Mac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState, Json, Query};
use crate::clock;
use crate::engine::{Event, EventKind, Live};
use crate::model::Ts;
use crate::adopt::{device_doc, device_doc_mut};
use crate::settings::{band_channels, country, dedup_in_order, device_macs, inform_radio, is_legal, legal_channels, mac_list_value, num, setting, setting_mut, uplink};

/// A band Channel AI handles, and how its quick scan is asked for.
pub struct Band {
    pub radio: &'static str,
    /// `scan-band` in the quick-scan command.
    scan_band: i64,
    /// `scan-bw`: the width scanned (MHz).
    scan_width: i64,
}

/// Bands Channel AI handles (6 GHz needs hardware apctl has not seen).
const BANDS: &[Band] = &[Band { radio: "ng", scan_band: 0, scan_width: 20 }, Band { radio: "na", scan_band: 1, scan_width: 80 }];

impl Band {
    /// The band with this radio name, if Channel AI handles it.
    pub fn named(radio: &str) -> Option<&'static Band> {
        BANDS.iter().find(|b| b.radio == radio)
    }
}

/// `wifi_caps2` bit: the AP can run a quick scan.
const CAP_QUICK_SCAN: u64 = 128;
/// The schedule when the setting has none: 03:00, the official default.
const DEFAULT_CRON: &str = "0 3 * * *";

/// Longest wait for one AP's quick scan.
const SCAN_TIMEOUT: Ts = 120;

/// A quick scan in progress on one AP.
#[derive(Clone, Debug)]
pub struct Scan {
    /// The band's radio name, as in [`BANDS`].
    pub band: &'static str,
    pub started: Ts,
    /// The AP has reported `quickscan_scanning: true` since.
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

/// Whether the `radio_ai` setting allows DFS channels on 5 GHz.
fn na_dfs(r: &Value) -> bool {
    r["radios_configuration"].as_array().and_then(|l| l.iter().find(|c| c["radio"].as_str() == Some("na"))).and_then(|c| c["dfs"].as_bool()).unwrap_or(false)
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
    let (hour, minute) = parse_cron(r.and_then(|r| r["cron_expr"].as_str()).unwrap_or(DEFAULT_CRON));
    let list = |k: &str| -> Vec<String> { r.and_then(|r| r[k].as_array()).into_iter().flatten().filter_map(|v| v.as_str().map(str::to_ascii_lowercase)).collect() };
    let radios = r.map_or_else(|| BANDS.iter().map(|b| b.radio.to_string()).collect(), |_| list("radios"));
    let dfs = r.is_some_and(na_dfs);
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

/// How old (seconds) the AP's spectrum table for a band is: `spectrum_table_time`
/// counts up from the last scan with every report.
fn spectrum_age(inform: &Value, band: &str) -> Option<i64> {
    inform_radio(inform, band)?["spectrum_table_time"].as_i64()
}

/// Asks every AP that can to scan a band; returns the APs asked. Scans go out
/// with each AP's next inform (see `actions`).
pub fn start_scans(live: &mut Live, band: &Band, now: Ts) -> Vec<Mac> {
    let eligible: Vec<Mac> = live
        .devices
        .iter()
        .filter(|(_, d)| d.online)
        .filter_map(|(mac, _)| {
            let p = live.raw_informs.get(mac)?;
            let caps = p["wifi_caps2"].as_u64().unwrap_or(0);
            (caps & CAP_QUICK_SCAN != 0 && !uplink(p).is_wireless() && inform_radio(p, band.radio).is_some()).then_some(*mac)
        })
        .collect();
    for mac in &eligible {
        crate::actions::queue(live, *mac, json!({ "_type": "cmd", "cmd": "quick-scan", "scan-band": band.scan_band, "scan-bw": band.scan_width }));
        live.scans.insert(*mac, Scan { band: band.radio, started: now, seen_scanning: false });
    }
    eligible
}

/// Marks finished scans: the AP reported scanning and then stopped, its
/// spectrum table for the band was made after the request, it went offline,
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
        // The table's age is as of the full inform that holds it, not now.
        let d = devices.get(mac);
        let renewed = d.zip(spectrum_age(p, s.band)).is_some_and(|(d, age)| d.last_full_inform - age > s.started);
        let offline = d.is_some_and(|d| !d.online);
        !renewed && !offline && now - s.started < SCAN_TIMEOUT
    });
}

/// Waits (up to the timeout) until no scan is running.
async fn wait_for_scans(s: &AppState) {
    for _ in 0..(SCAN_TIMEOUT / 2 + 5) {
        {
            let mut live = s.live.write().unwrap();
            check_scans(&mut live, clock::now_ts());
            if live.scans.is_empty() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Writes fixed channels on `band` into the APs' radio settings (`changes`:
/// AP, channel), checking each is legal at the radio's width and allowed, and
/// that the AP is not one whose channel a plan must keep (`held`: see [`pinned`]).
pub fn set_channels(state: &mut Value, band: &str, changes: &[(String, i64)], held: &[Mac]) -> Result<(), String> {
    if !state["devices"].is_array() {
        return Err("the settings have no APs".into());
    }
    let c = country(state);
    let locked = if band == "ng" { crate::settings::channel_locked_aps(state) } else { vec![] };
    let allowed_here = allowed(Some(state), band, true);
    for (mac, ch) in changes {
        // The locks list MACs as aa:bb:..; the plan's is compared in that form, however it is written.
        let m: Mac = mac.parse().map_err(|_| format!("{mac} is not in the settings"))?;
        if locked.contains(&m.to_string()) {
            return Err(format!("{mac}: the 2.4 GHz channel is locked by an SSID's IoT setting"));
        }
        // A plan made earlier, or sent as it is: the AP may have been excluded, or gone on a wireless uplink, since.
        if held.contains(&m) {
            return Err(format!("{mac}: Channel AI keeps this AP's channel (excluded, on a wireless uplink or being upgraded)"));
        }
        let d = device_doc(state, &m).ok_or_else(|| format!("{mac} is not in the settings"))?;
        let outdoor = crate::settings::outdoor(state, d);
        let d = device_doc_mut(state, &m).expect("found above");
        let r = crate::settings::inform_radio_mut(d, band).ok_or_else(|| format!("{mac} has no {band} radio"))?;
        let width = num(&r["ht"]).unwrap_or(20);
        if is_legal(c, band, width, outdoor, *ch) == Some(false) {
            return Err(format!("channel {ch} is not allowed at {width} MHz here"));
        }
        if allowed_here.as_ref().is_some_and(|a| !a.contains(ch)) {
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

/// Scans, plans and (when worth it) applies, band by band, holding the run
/// flag (`_running`) until done.
async fn run(s: AppState, bands: Vec<String>, trigger: &'static str, _running: RunGuard) {
    for (band, b) in bands.iter().filter_map(|n| Some((n, Band::named(n)?))) {
        let scanned = start_scans(&mut s.live.write().unwrap(), b, clock::now_ts());
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
        let plan = match crate::channelplan::compute_plan(&s, band.clone(), false, allowed, pinned).await {
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
            .map(|p| Change { mac: p.mac.clone(), name: p.name.clone(), from: Some(p.current_channel), to: p.suggested_channel, width: Some(p.width) })
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
        s.note(Event::site(clock::now_ts(), EventKind::ChannelPlan, data)).await;
    }
}

async fn apply(s: &AppState, band: &str, changes: &[Change], trigger: &str) -> Result<(), ApiError> {
    let list: Vec<(String, i64)> = changes.iter().map(|c| (c.mac.clone(), c.to)).collect();
    let show = |c: &Change| format!("{} {} → {}", c.name.as_deref().unwrap_or(&c.mac), c.from.map_or_else(|| "auto".to_string(), |f| f.to_string()), c.to);
    let what = format!("channel AI ({trigger}): {}", changes.iter().map(show).collect::<Vec<_>>().join(", "));
    let held: Vec<Mac> = pinned(&s.live.read().unwrap(), band).iter().filter_map(|m| m.parse().ok()).collect();
    let band = band.to_string();
    crate::actions::edit_settings(s, what, move |state| set_channels(state, &band, &list, &held)).await
}

/// Runs Channel AI nightly at the setting's hour, in the site's time zone
/// (active mode only: in shadow mode the other controller does this).
pub fn schedule(s: AppState) {
    if !s.active {
        return;
    }
    tokio::spawn(async move {
        let mut nightly = Nightly::default();
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let (cfg, tz) = {
                let live = s.live.read().unwrap();
                let st = live.state.as_deref();
                let tz = st.and_then(crate::settings::timezone).map(str::to_string);
                (settings(st), tz)
            };
            let (day, minute) = crate::clock::local(tz.as_deref(), clock::now_ts());
            if !nightly.due(&cfg, day, minute) {
                continue;
            }
            match RunGuard::take() {
                Some(guard) => {
                    nightly.started(day);
                    run(s.clone(), cfg.radios.clone(), "nightly", guard).await;
                }
                None if minute == cfg.hour * 60 + cfg.minute => tracing::info!("channel AI: a run is already going; the nightly run follows it"),
                None => {}
            }
        }
    });
}

/// When the nightly run is due: from the setting's minute until it has
/// started that day, so that a run going at that minute only delays it.
#[derive(Debug, Default)]
struct Nightly {
    /// The day the nightly run last started.
    done: Option<i64>,
    /// The day whose run is due and has not started yet.
    waiting: Option<i64>,
}

impl Nightly {
    /// Whether the nightly run should start now (`day`, `minute`: the local
    /// day and minute of the day). A wait does not carry over into the next day.
    fn due(&mut self, cfg: &Settings, day: i64, minute: i64) -> bool {
        if cfg.enabled && minute == cfg.hour * 60 + cfg.minute && self.done != Some(day) {
            self.waiting = Some(day);
        }
        cfg.enabled && self.waiting == Some(day)
    }

    fn started(&mut self, day: i64) {
        self.done = Some(day);
        self.waiting = None;
    }
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
        check_scans(&mut live, clock::now_ts());
        let scans: Vec<Value> = live.scans.iter().map(|(m, sc)| json!({ "mac": m, "band": sc.band, "started": sc.started })).collect();
        (live.state.clone(), scans)
    };
    let st = state.as_deref();
    let tz = st.and_then(crate::settings::timezone);
    let cfg = settings(st);
    Ok(Json(json!({
        "active": s.active, "has_settings": st.and_then(radio_ai).is_some(), "timezone": tz,
        "next_run": next_run(&cfg, tz, clock::now_ts()), "running": RUNNING.load(Ordering::SeqCst), "scans": scans,
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
    let band = Band::named(&b.band).ok_or_else(|| ApiError::bad("band must be ng or na"))?;
    let asked = start_scans(&mut s.live.write().unwrap(), band, clock::now_ts());
    if asked.is_empty() {
        return Err(ApiError::conflict("no online AP can scan this band"));
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
    // Taken here, so that of two requests at once only one is told it started.
    let guard = RunGuard::take().ok_or_else(|| ApiError::conflict("Channel AI is already running"))?;
    let bands = b.bands.unwrap_or_else(|| settings(s.live.read().unwrap().state.as_deref()).radios);
    tokio::spawn(run(s.clone(), bands, "manual", guard));
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
    let b: ApplyBody = serde_json::from_value(b).map_err(|e| ApiError::bad(format!("not a plan: {e}")))?;
    if Band::named(&b.band).is_none() {
        return Err(ApiError::bad("band must be ng or na"));
    }
    if b.changes.is_empty() {
        return Err(ApiError::bad("the plan changes nothing"));
    }
    if let Some(c) = b.changes.iter().find(|c| !crate::settings::is_mac(&c.mac)) {
        return Err(ApiError::bad(format!("{} is not a MAC address", c.mac)));
    }
    apply(&s, &b.band, &b.changes, "manual").await?;
    let data = json!({ "band": b.band, "trigger": "manual", "changes": b.changes, "applied": true });
    s.note(Event::site(clock::now_ts(), EventKind::ChannelPlan, data)).await;
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
            "enabled": false, "cron_expr": DEFAULT_CRON, "radios": ["ng", "na"], "channels_blacklist": blacklist,
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
        // The minute stays (an imported setting may have one).
        let (_, m) = parse_cron(r["cron_expr"].as_str().unwrap_or(DEFAULT_CRON));
        r["cron_expr"] = json!(format!("{m} {h} * * *"));
    }
    if !p["radios"].is_null() {
        let list = p["radios"].as_array().ok_or("radios must be a list")?;
        let mut radios: Vec<&str> = list.iter().map(|v| Some(Band::named(v.as_str()?)?.radio)).collect::<Option<_>>().ok_or("radios can be ng and na")?;
        dedup_in_order(&mut radios);
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
        let macs = mac_list_value(&p["exclude_devices"], "exclude_devices")?.unwrap_or_default();
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
    let dfs = na_dfs(r);
    for band in BANDS.iter().map(|b| b.radio) {
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
        // Each band once; anything but a band's name is refused.
        apply_settings(&mut s, &json!({ "radios": ["na", "na"] })).unwrap();
        assert_eq!(settings(Some(&s)).radios, ["na"]);
        assert!(apply_settings(&mut s, &json!({ "radios": ["ng", 5] })).is_err());
        assert!(apply_settings(&mut s, &json!({ "radios": ["6e"] })).is_err());
        // An imported minute is kept when only the hour changes.
        setting_mut(&mut s, "radio_ai")["cron_expr"] = json!("30 2 * * *");
        apply_settings(&mut s, &json!({ "hour": 6 })).unwrap();
        assert_eq!((settings(Some(&s)).hour, settings(Some(&s)).minute), (6, 30));
        assert!(apply_settings(&mut s, &json!({ "exclude_devices": ["02:00:00:00:00:99"] })).is_err());
        assert!(apply_settings(&mut s, &json!({ "exclude_devices": [1] })).is_err());
        // Any form of the MAC, saved as aa:bb:.. and once.
        apply_settings(&mut s, &json!({ "exclude_devices": ["02-00-00-00-00-01", "020000000001"] })).unwrap();
        assert_eq!(settings(Some(&s)).exclude_devices, vec!["02:00:00:00:00:01"]);
    }

    #[test]
    fn plans_are_written_as_fixed_channels_when_legal() {
        let mut s = state();
        set_channels(&mut s, "ng", &[("02:00:00:00:00:01".into(), 6)], &[]).unwrap();
        assert_eq!(s["devices"][0]["radio_table"][1]["channel"], 6, "an auto radio is pinned");
        assert!(set_channels(&mut s, "na", &[("02:00:00:00:00:01".into(), 140)], &[]).is_err(), "not at 80 MHz");
        assert!(set_channels(&mut s, "ng", &[("02:00:00:00:00:01".into(), 3)], &[]).is_err(), "not in the allowed list");
        set_channels(&mut s, "na", &[("02:00:00:00:00:01".into(), 36)], &[]).unwrap();
        assert!(set_channels(&mut s, "na", &[("02:00:00:00:00:02".into(), 36)], &[]).is_err(), "not one of the APs");
        // Nor an AP a plan must leave where it is, however the plan came.
        let held = ["02:00:00:00:00:01".parse().unwrap()];
        assert!(set_channels(&mut s, "na", &[("02-00-00-00-00-01".into(), 36)], &held).unwrap_err().contains("keeps this AP's channel"));
    }

    #[test]
    fn a_channel_locked_ap_is_refused_however_its_mac_is_written() {
        let mut s = state();
        s["apgroup"] = json!([{ "_id": "g1", "attr_hidden_id": "default", "device_macs": ["02:00:00:00:00:01"], "site_id": "s1" }]);
        s["wlanconf"] = json!([{ "_id": "w1", "name": "Things", "iot_channel_lock": true, "ap_group_ids": ["g1"], "site_id": "s1" }]);
        for mac in ["02:00:00:00:00:01", "02-00-00-00-00-01", "02:00:00:00:00:01".to_uppercase().as_str()] {
            assert!(set_channels(&mut s, "ng", &[(mac.into(), 11)], &[]).unwrap_err().contains("IoT"), "{mac}");
        }
        set_channels(&mut s, "na", &[("02-00-00-00-00-01".into(), 36)], &[]).unwrap();
    }

    #[test]
    fn scans_finish_when_the_spectrum_table_is_newer_than_the_request() {
        let mut live = Live::default();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let inform = |age: i64, scanning: Option<bool>| {
            let mut p = json!({ "mac": ap.to_string(), "wifi_caps2": 128, "uplink": "eth0", "vap_table": [], "radio_table": [{ "radio": "na", "spectrum_table_time": age }] });
            if let Some(b) = scanning {
                p["quickscan_scanning"] = json!(b);
            }
            std::sync::Arc::new(p)
        };
        // The AP's last full inform arrived at `at`.
        let heard = |live: &mut Live, at: Ts| {
            let snapshot = crate::model::parse(at, &inform(0, None)).unwrap();
            let d = crate::engine::DeviceView { snapshot, online: true, first_seen: 0, last_seen: at, peer: String::new(), interval: 10, last_full_inform: at, last_config_push: None };
            live.devices.insert(ap, d);
        };
        heard(&mut live, 995);
        live.raw_informs.insert(ap, inform(56_000, None));
        // (Asked for directly: start_scans only asks APs that are online.)
        crate::actions::queue(&mut live, ap, json!({ "_type": "cmd", "cmd": "quick-scan" }));
        live.scans.insert(ap, Scan { band: "na", started: 1000, seen_scanning: false });
        assert_eq!(crate::actions::next(&mut live, &ap).unwrap()["cmd"], "quick-scan");
        check_scans(&mut live, 1010);
        assert_eq!(live.scans.len(), 1, "the old table does not count");
        heard(&mut live, 1011);
        live.raw_informs.insert(ap, inform(56_011, Some(true)));
        check_scans(&mut live, 1020);
        assert_eq!(live.scans.len(), 1);
        heard(&mut live, 1040);
        live.raw_informs.insert(ap, inform(3, None));
        check_scans(&mut live, 1040);
        assert!(live.scans.is_empty(), "a table 3 s old is from this scan");
        // A table from just before the request, reported before it, is not this
        // scan's however long ago that report came.
        live.scans.insert(ap, Scan { band: "na", started: 1100, seen_scanning: false });
        heard(&mut live, 1098);
        live.raw_informs.insert(ap, inform(5, None));
        check_scans(&mut live, 1130);
        assert_eq!(live.scans.len(), 1, "made at 1093, before the request at 1100");
        heard(&mut live, 1130);
        live.raw_informs.insert(ap, inform(10, None));
        check_scans(&mut live, 1130);
        assert!(live.scans.is_empty(), "made at 1120");
        // Without an answer, a scan gives up after two minutes.
        live.scans.insert(ap, Scan { band: "na", started: 2000, seen_scanning: false });
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
    fn a_nightly_run_held_up_by_another_starts_after_it() {
        let cfg = Settings { enabled: true, hour: 3, minute: 15, radios: vec![], dfs: false, exclude_devices: vec![] };
        let mut n = Nightly::default();
        assert!(!n.due(&cfg, 1, 3 * 60 + 14));
        // Due at its minute; another run is going, so it waits, and is still due after.
        assert!(n.due(&cfg, 1, 3 * 60 + 15));
        assert!(n.due(&cfg, 1, 3 * 60 + 17));
        n.started(1);
        assert!(!n.due(&cfg, 1, 3 * 60 + 15), "once a day");
        assert!(!n.due(&cfg, 2, 3 * 60 + 16), "not before its minute");
        assert!(n.due(&cfg, 2, 3 * 60 + 15));
        // A run that never got to start is not carried into the next day.
        assert!(!n.due(&cfg, 3, 3 * 60 + 14));
        assert!(!n.due(&Settings { enabled: false, ..cfg }, 2, 3 * 60 + 15));
    }

    #[test]
    fn plan_changes_must_be_complete() {
        let ok: ApplyBody = serde_json::from_value(json!({ "band": "na", "changes": [{ "mac": "02:00:00:00:00:01", "name": null, "from": 44, "to": 36 }] })).unwrap();
        assert_eq!((ok.changes[0].to, ok.changes[0].from), (36, Some(44)));
        assert!(serde_json::from_value::<ApplyBody>(json!({ "band": "na", "changes": [{ "mac": "02:00:00:00:00:01", "to": null }] })).is_err());
        assert!(serde_json::from_value::<ApplyBody>(json!({ "band": "na", "changes": [{ "to": 36 }] })).is_err());
    }
}
