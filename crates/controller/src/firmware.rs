//! AP firmware: what is available, and upgrades one AP at a time.
//!
//! Like the official controller, apctl reads Ubiquiti's public firmware feed
//! (`fw-update.ubnt.com`, product `unifi-firmware`, channel `release`) once a
//! day, keyed by platform (the AP's model code, e.g. `U6M`). Unlike it, an
//! update is only offered when the release is *newer* than what the AP runs:
//! the official controller offers any different version, which would downgrade
//! APs on early-access firmware.
//!
//! Upgrades need active mode: the command is the reply to the AP's next inform,
//! `{"_type":"upgrade","version","url","md5sum","sha256sum"}` (sha256 only when
//! the AP's `fw_caps` has bit 0x04000000), and the AP downloads the file
//! itself. Progress comes back as notifications (`event_string` "Upgrade":
//! downloading, writing, or an error with its reason), success as the new
//! version in an inform. apctl upgrades strictly one AP at a time, mesh
//! children before the APs they hang off, and stops the queue on a failure.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use rusqlite::{Connection, OptionalExtension};
use rusqlite::types::Value as Sql;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use inform::Mac;

use crate::api::{ApiError, AppState, Json};
use crate::clock;
use crate::engine::Live;
use crate::model::Ts;
use crate::store::{Db, Writer};

pub const FEED: &str = "https://fw-update.ubnt.com/api/firmware-newest?filter=eq~~product~~unifi-firmware&filter=eq~~channel~~release";
/// `fw_caps` bit: the AP verifies SHA-256 checksums.
const CAP_SHA256: i64 = 0x0400_0000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Release {
    pub platform: String,
    /// `major.minor.patch.build`, as APs report their version.
    pub version: String,
    pub url: String,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub size: Option<i64>,
    pub created: Option<String>,
}

/// The newest release per platform from the feed, in the order the platforms
/// first appear. Entries without a version or a download link are skipped.
pub fn parse_feed(feed: &Value) -> Vec<Release> {
    let s = |v: &Value| v.as_str().filter(|x| !x.is_empty()).map(str::to_string);
    let all = feed["_embedded"]["firmware"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| {
            let (maj, min, pat) = (f["version_major"].as_i64()?, f["version_minor"].as_i64()?, f["version_patch"].as_i64()?);
            let url = s(&f["_links"]["data"]["href"])?;
            let build = s(&f["version_build"]).or_else(|| f["version_build"].as_i64().map(|b| b.to_string()));
            let pre = s(&f["version_prerelease"]);
            let mut version = format!("{maj}.{min}.{pat}");
            if let Some(p) = pre {
                let _ = write!(version, "-{p}");
            }
            if let Some(b) = build {
                let _ = write!(version, ".{b}");
            }
            Some(Release { platform: s(&f["platform"])?, version, url, md5: s(&f["md5"]), sha256: s(&f["sha256"]), size: f["file_size"].as_i64(), created: s(&f["created"]) })
        });
    let mut out: Vec<Release> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for r in all {
        match at.get(&r.platform) {
            Some(&i) if compare(&r.version, &out[i].version).is_gt() => out[i] = r,
            Some(_) => {}
            None => {
                at.insert(r.platform.clone(), out.len());
                out.push(r);
            }
        }
    }
    out
}

/// The feed's platform key for an AP model code (a few differ in case).
pub fn platform_for(model: &str) -> String {
    match model {
        "U7EV2" => "U7Ev2".into(),
        "UALR6V2" => "UALR6v2".into(),
        "UALR6V3" => "UALR6v3".into(),
        "U2LV2" => "U2Lv2".into(),
        "U2SV2" => "U2Sv2".into(),
        m => m.into(),
    }
}

/// Compares firmware versions numerically, segment by segment (`.` and `-`
/// separate segments; a `+build` suffix is ignored). On a tie, a version with
/// a pre-release part is older than the plain one.
pub fn compare(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |v: &str| -> Vec<u64> {
        let v = v.trim_start_matches('v');
        let v = v.split('+').next().unwrap_or(v);
        // A segment's leading digits; none (as in `rc`) is 0.
        v.split(['.', '-']).map(|x| x[..x.find(|c: char| !c.is_ascii_digit()).unwrap_or(x.len())].parse().unwrap_or(0)).collect()
    };
    let (pa, pb) = (parts(a), parts(b));
    let n = pa.len().min(pb.len());
    match pa[..n].cmp(&pb[..n]) {
        std::cmp::Ordering::Equal if a.contains('-') || b.contains('-') => pb.len().cmp(&pa.len()),
        o => o,
    }
}

/// Where an AP stands against the release feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    UpdateAvailable,
    UpToDate,
    /// Newer than the release (early access).
    Ahead,
    Unknown,
}

/// Why an AP asked to be upgraded was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Skip {
    UpToDate,
    Ahead,
    /// No release to offer (none for its model, or below what it needs).
    Unknown,
    Offline,
    /// Not an AP apctl knows (or not a MAC at all).
    NotFound,
}

pub fn status(current: Option<&str>, release: Option<&Release>, required: Option<&str>) -> Status {
    let (Some(cur), Some(rel)) = (current, release) else { return Status::Unknown };
    match compare(&rel.version, cur) {
        std::cmp::Ordering::Greater if required.is_none_or(|r| compare(&rel.version, r).is_ge()) => Status::UpdateAvailable,
        std::cmp::Ordering::Greater => Status::Unknown,
        std::cmp::Ordering::Equal => Status::UpToDate,
        std::cmp::Ordering::Less => Status::Ahead,
    }
}

/// Where an upgrade is: queued, sent with an inform reply, then the AP's own steps.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Queued,
    Sent,
    Preparing,
    Downloading,
    Writing,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Job {
    pub mac: Mac,
    pub name: Option<String>,
    pub from: Option<String>,
    /// The version to install, or "custom" for a firmware URL.
    pub target: String,
    pub url: String,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub custom: bool,
    pub state: JobState,
    pub sent_at: Option<Ts>,
    pub expires: Option<Ts>,
}

impl Job {
    /// A queued upgrade of `a` to `target`, a release version or "custom" for a firmware URL.
    fn new(a: ApInfo, target: String, url: String, md5: Option<String>, sha256: Option<String>, custom: bool) -> Job {
        Job { mac: a.mac, name: a.name, from: a.version, target, url, md5, sha256, custom, state: JobState::Queued, sent_at: None, expires: None }
    }
}

/// How long a sent upgrade has at least, and each of the AP's steps after it,
/// before it fails: the official controller's minimum for U6 APs.
pub const STEP_DEADLINE: Ts = 450;
/// The most the AP's own upgrade + reboot estimate can give a sent upgrade.
const MAX_DEADLINE: Ts = 86_400;
/// How long the upgrade at the head of the queue waits for its AP's turn (an
/// inform with its settings current) before it fails.
const TURN_WAIT: Ts = 600;
/// Why a sent upgrade failed when out of time.
const TIMED_OUT: &str = "it did not come back with the new firmware in time";
/// Why an upgrade whose AP never took its turn failed.
const NOT_TAKEN: &str = "it was not ready for the upgrade in time (offline, or its settings not applied)";

/// The upgrade queue: one AP at a time.
#[derive(Debug, Default, Serialize)]
pub struct Jobs {
    pub current: Option<Job>,
    pub queue: VecDeque<Job>,
    /// Why the queue stopped, after a failure.
    pub stopped: Option<String>,
}

impl Jobs {
    /// Queues upgrades (an AP already queued or upgrading is not queued again);
    /// how many were queued. A queue stopped by a failure stays stopped until
    /// it is resumed.
    pub fn enqueue(&mut self, jobs: Vec<Job>) -> usize {
        let mut n = 0;
        for j in jobs {
            let busy = self.current.as_ref().is_some_and(|c| c.mac == j.mac) || self.queue.iter().any(|q| q.mac == j.mac);
            if !busy {
                self.queue.push_back(j);
                n += 1;
            }
        }
        self.next();
        n
    }

    /// Starts a queue a failure stopped again; whether it was stopped.
    pub fn resume(&mut self) -> bool {
        let stopped = self.stopped.take().is_some();
        self.next();
        stopped
    }

    fn next(&mut self) {
        if self.current.is_none() && self.stopped.is_none() {
            self.current = self.queue.pop_front();
        }
    }

    pub fn current_for(&mut self, mac: &Mac) -> Option<&mut Job> {
        self.current.as_mut().filter(|j| j.mac == *mac)
    }

    /// The AP's current job once its command is sent. What the AP reports of
    /// an upgrade before then is not about this job (an upgrade started
    /// elsewhere, or a late notice from an earlier one).
    fn sent_for(&mut self, mac: &Mac) -> Option<&mut Job> {
        self.current_for(mac).filter(|j| j.state != JobState::Queued)
    }

    /// The AP reports a step of its upgrade: the deadline is re-armed, as the
    /// official controller does on each step.
    pub fn progress(&mut self, mac: &Mac, state: JobState, now: Ts) {
        if let Some(j) = self.sent_for(mac) {
            j.state = state;
            j.expires = Some(now + STEP_DEADLINE);
        }
    }

    /// The AP reports that its upgrade failed: [`Jobs::failed`] for a job
    /// whose command was sent.
    pub fn upgrade_error(&mut self, mac: &Mac, why: &str) -> Option<Job> {
        self.sent_for(mac)?;
        self.failed(mac, why)
    }

    /// The AP reports its version: the job succeeded if it was upgrading and
    /// the version changed. When the version it started from is not known, the
    /// first one it reports after the upgrade was sent is taken as that.
    pub fn version_seen(&mut self, mac: &Mac, version: &str) -> Option<Job> {
        let j = self.current.as_mut().filter(|j| j.mac == *mac && j.state != JobState::Queued)?;
        match &j.from {
            None => {
                j.from = Some(version.to_string());
                return None;
            }
            Some(f) if f == version => return None,
            Some(_) => {}
        }
        let j = self.current.take();
        self.next();
        j
    }

    /// The current job failed: stop the queue so a problem is not repeated on every AP.
    pub fn failed(&mut self, mac: &Mac, why: &str) -> Option<Job> {
        let j = self.current.take_if(|j| j.mac == *mac)?;
        if !self.queue.is_empty() {
            self.stopped = Some(format!("{} failed: {why}", j.name.clone().unwrap_or_else(|| j.mac.to_string())));
        }
        Some(j)
    }

    /// The current upgrade if it is out of time, with why: sent and not
    /// finished, or still waiting for its AP to take its turn (offline, or its
    /// settings not applied), which it is given [`TURN_WAIT`] for from the
    /// first call that finds it at the head of the queue.
    pub fn expired(&mut self, now: Ts) -> Option<(Mac, &'static str)> {
        let j = self.current.as_mut()?;
        if j.state == JobState::Queued && j.expires.is_none() {
            j.expires = Some(now + TURN_WAIT);
        }
        let why = if j.state == JobState::Queued { NOT_TAKEN } else { TIMED_OUT };
        j.expires.is_some_and(|e| now > e).then_some((j.mac, why))
    }

    pub fn cancel_queued(&mut self) -> usize {
        let n = self.queue.len() + usize::from(self.current.take_if(|j| j.state == JobState::Queued).is_some());
        self.queue.clear();
        self.stopped = None;
        n
    }

    /// Drops a forgotten AP's job, queued or current; the next one starts.
    pub fn remove(&mut self, mac: &Mac) {
        self.queue.retain(|j| j.mac != *mac);
        if self.current.take_if(|j| j.mac == *mac).is_some() {
            self.next();
        }
    }
}

/// A change to the queue asked for from the UI, made by the engine.
#[derive(Debug)]
pub enum Op {
    Enqueue(Vec<Job>),
    CancelQueued,
    /// Starts a queue stopped by a failure again.
    Resume,
}

impl Op {
    /// Makes the change; how many upgrades it queued or cancelled (resuming: 1 if the queue was stopped).
    pub fn apply(self, jobs: &mut Jobs) -> usize {
        match self {
            Op::Enqueue(new) => {
                let n = jobs.enqueue(new);
                tracing::info!("firmware: {n} upgrade(s) queued");
                n
            }
            Op::CancelQueued => {
                let n = jobs.cancel_queued();
                tracing::info!("firmware: {n} queued upgrade(s) cancelled");
                n
            }
            Op::Resume => {
                let resumed = jobs.resume();
                if resumed {
                    tracing::info!("firmware: the upgrade queue resumed");
                }
                usize::from(resumed)
            }
        }
    }
}

/// Has the engine change the queue.
async fn change_queue(s: &AppState, op: Op) -> Result<usize, ApiError> {
    let (done, rx) = tokio::sync::oneshot::channel();
    s.ask(crate::engine::Input::Firmware { op, done }, rx).await
}

/// The upgrade command for an AP's inform reply, if its turn has come. Marks
/// the job sent and sets its deadline: the AP's own upgrade + reboot estimate,
/// but at least [`STEP_DEADLINE`] and at most a day.
pub fn command(jobs: &mut Jobs, mac: &Mac, inform: &Value, now: Ts) -> Option<Result<Value, &'static str>> {
    let j = jobs.current_for(mac).filter(|j| j.state == JobState::Queued)?;
    if !j.custom && inform["internet"].as_bool() == Some(false) {
        return Some(Err("the AP has no internet access to download the firmware"));
    }
    let estimate = inform["upgrade_duration"].as_i64().unwrap_or(0).saturating_add(inform["reboot_duration"].as_i64().unwrap_or(0));
    j.state = JobState::Sent;
    j.sent_at = Some(now);
    j.expires = Some(now + estimate.clamp(STEP_DEADLINE, MAX_DEADLINE));
    // What it runs now, so that only a different version counts as the upgrade landing.
    if j.from.is_none() {
        j.from = inform["version"].as_str().map(str::to_string);
    }
    // For a firmware URL the official controller expects (and sends) "unknown".
    let version = if j.custom { "unknown" } else { j.target.as_str() };
    let mut cmd = json!({ "_type": "upgrade", "version": version, "url": j.url, "server_time_in_utc": crate::active::server_time(now) });
    if let Some(m) = &j.md5 {
        cmd["md5sum"] = json!(m);
    }
    if let Some(s) = &j.sha256
        && inform["fw_caps"].as_i64().unwrap_or(0) & CAP_SHA256 != 0
    {
        cmd["sha256sum"] = json!(s);
    }
    Some(Ok(cmd))
}

// ---------------------------------------------------------------- checking

/// Fetches the release feed and stores the newest release per platform.
pub fn check(writer: &Writer) -> anyhow::Result<usize> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(30))).build().into();
    let result = (|| -> anyhow::Result<Vec<Release>> {
        let text = agent.get(FEED).header("User-Agent", concat!("apctl/", env!("CARGO_PKG_VERSION"))).call()?.body_mut().read_to_string()?;
        let feed: Value = serde_json::from_str(&text)?;
        let releases = parse_feed(&feed);
        if releases.is_empty() {
            anyhow::bail!("the firmware feed listed nothing");
        }
        Ok(releases)
    })();
    let now = clock::now_ts();
    match result {
        Ok(releases) => {
            store_releases(writer, &releases, now);
            Ok(releases.len())
        }
        Err(e) => {
            writer.exec(Db::Config, "INSERT OR REPLACE INTO firmware_check (id, ts, error) VALUES (1, ?1, ?2)", vec![Sql::Integer(now), Sql::Text(format!("{e:#}"))]);
            Err(e)
        }
    }
}

/// Stores what the feed listed, checked at `now`, in place of what it listed before.
fn store_releases(writer: &Writer, releases: &[Release], now: Ts) {
    for r in releases {
        writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO firmware_releases (platform, version, url, md5, sha256, size, created, checked) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            vec![
                Sql::Text(r.platform.clone()),
                Sql::Text(r.version.clone()),
                Sql::Text(r.url.clone()),
                r.md5.clone().map_or(Sql::Null, Sql::Text),
                r.sha256.clone().map_or(Sql::Null, Sql::Text),
                r.size.map_or(Sql::Null, Sql::Integer),
                r.created.clone().map_or(Sql::Null, Sql::Text),
                Sql::Integer(now),
            ],
        );
    }
    // Platforms the feed no longer lists, by name rather than by date:
    // after the clock steps back, rows checked "later" are as old.
    let listed = serde_json::to_string(&releases.iter().map(|r| &r.platform).collect::<Vec<_>>()).expect("a list of strings");
    writer.exec(Db::Config, "DELETE FROM firmware_releases WHERE platform NOT IN (SELECT value FROM json_each(?1))", vec![Sql::Text(listed)]);
    writer.exec(Db::Config, "INSERT OR REPLACE INTO firmware_check (id, ts, error) VALUES (1, ?1, NULL)", vec![Sql::Integer(now)]);
}

/// Checks a minute after start, then daily.
pub fn schedule(writer: Writer) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let mut every = tokio::time::interval(Duration::from_secs(86400));
        loop {
            every.tick().await;
            let w = writer.clone();
            match tokio::task::spawn_blocking(move || check(&w)).await {
                Ok(Ok(n)) => tracing::info!("firmware feed: {n} platforms"),
                Ok(Err(e)) => tracing::warn!("firmware check failed: {e:#}"),
                Err(e) => tracing::warn!("firmware check failed: {e}"),
            }
        }
    });
}

/// The newest release for each platform.
type Releases = HashMap<String, Release>;

/// The stored releases, and when the feed was last checked (with its error, if it failed).
fn releases(c: &Connection) -> anyhow::Result<(Releases, Option<Ts>, Option<String>)> {
    let list = c
        .prepare("SELECT platform, version, url, md5, sha256, size, created FROM firmware_releases")?
        .query_map([], |r| {
            Ok(Release { platform: r.get(0)?, version: r.get(1)?, url: r.get(2)?, md5: r.get(3)?, sha256: r.get(4)?, size: r.get(5)?, created: r.get(6)? })
        })?
        .map(|r| r.map(|r| (r.platform.clone(), r)))
        .collect::<rusqlite::Result<HashMap<_, _>>>()?;
    let (ts, err) = c.query_row("SELECT ts, error FROM firmware_check WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?.unwrap_or((None, None));
    Ok((list, ts, err))
}

/// An AP model's feed platform, and the release for it.
fn release_for<'a>(rels: &'a Releases, model: Option<&str>) -> (Option<String>, Option<&'a Release>) {
    let platform = model.map(platform_for);
    let rel = platform.as_ref().and_then(|p| rels.get(p));
    (platform, rel)
}

// ---------------------------------------------------------------- API

struct ApInfo {
    mac: Mac,
    name: Option<String>,
    model: Option<String>,
    version: Option<String>,
    required: Option<String>,
    online: bool,
    /// Uplinked over Wi-Fi (mesh): upgraded before wired APs.
    mesh: bool,
}

fn aps(live: &Live) -> Vec<ApInfo> {
    live.devices
        .iter()
        .map(|(mac, d)| {
            let raw = live.raw_informs.get(mac);
            ApInfo {
                mac: *mac,
                name: d.snapshot.ap.hostname.clone(),
                model: d.snapshot.ap.model.clone(),
                version: d.snapshot.ap.version.clone(),
                required: raw.and_then(|r| r["required_version"].as_str().map(str::to_string)),
                online: d.online,
                mesh: raw.is_some_and(|r| crate::settings::uplink(r).is_wireless()),
            }
        })
        .collect()
}

/// GET /api/firmware
pub async fn index(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (rels, checked, error) = crate::api::read(&s.store, Db::Config, releases).await?;
    let (aps, jobs) = {
        let live = s.live.read().unwrap();
        (aps(&live), serde_json::to_value(&live.firmware).map_err(anyhow::Error::from)?)
    };
    let list: Vec<Value> = aps
        .into_iter()
        .map(|a| {
            let (platform, rel) = release_for(&rels, a.model.as_deref());
            json!({
                "mac": a.mac, "name": a.name, "model": a.model, "platform": platform, "version": a.version, "online": a.online,
                "release": rel, "status": status(a.version.as_deref(), rel, a.required.as_deref()),
            })
        })
        .collect();
    Ok(Json(json!({ "checked": checked, "error": error, "channel": "release", "active": s.active, "aps": list, "jobs": jobs })))
}

/// POST /api/firmware/check
pub async fn check_now(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let w = s.writer.clone();
    let n = tokio::task::spawn_blocking(move || check(&w))
        .await?
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("the firmware feed could not be read: {e:#}")))?;
    // The writer commits about once a second: have it commit this check now (waiting
    // a few seconds at most), so that the page's next read shows the new releases.
    let w = s.writer.clone();
    if !tokio::task::spawn_blocking(move || w.flush(Duration::from_secs(5))).await? {
        tracing::warn!("the firmware check was not stored within five seconds");
    }
    Ok(Json(json!({ "ok": true, "platforms": n })))
}

#[derive(Deserialize)]
pub struct UpgradeBody {
    macs: Vec<String>,
}

/// POST /api/firmware/upgrade: queue release upgrades, one AP at a time.
pub async fn upgrade(State(s): State<AppState>, Json(b): Json<UpgradeBody>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "upgrades need")?;
    let (rels, ..) = crate::api::read(&s.store, Db::Config, releases).await?;
    let known = aps(&s.live.read().unwrap());
    let mut skipped = Vec::new();
    let mut wanted: Vec<Mac> = Vec::new();
    for m in &b.macs {
        match m.parse::<Mac>() {
            Ok(mac) if known.iter().any(|a| a.mac == mac) => wanted.push(mac),
            _ => skipped.push(json!({ "mac": m, "why": Skip::NotFound })),
        }
    }
    let mut chosen: Vec<ApInfo> = known.into_iter().filter(|a| wanted.contains(&a.mac)).collect();
    // Mesh APs first: an AP with mesh children must not restart before them.
    chosen.sort_by_key(|a| (!a.mesh, a.mac));
    let mut jobs = Vec::new();
    for a in chosen {
        let (_, rel) = release_for(&rels, a.model.as_deref());
        match (status(a.version.as_deref(), rel, a.required.as_deref()), rel, a.online) {
            (Status::UpdateAvailable, Some(r), true) => jobs.push(Job::new(a, r.version.clone(), r.url.clone(), r.md5.clone(), r.sha256.clone(), false)),
            (st, _, online) => {
                let why = match st {
                    _ if !online => Skip::Offline,
                    Status::UpToDate => Skip::UpToDate,
                    Status::Ahead => Skip::Ahead,
                    Status::UpdateAvailable | Status::Unknown => Skip::Unknown,
                };
                skipped.push(json!({ "mac": a.mac, "why": why }));
            }
        }
    }
    let n = change_queue(&s, Op::Enqueue(jobs)).await?;
    Ok(Json(json!({ "queued": n, "skipped": skipped })))
}

#[derive(Deserialize)]
pub struct UrlBody {
    mac: String,
    url: String,
}

/// Whether a firmware URL looks like one an AP can fetch, as the official
/// controller's custom-update form expects: http(s) or ftp, ending .bin or .tar.
pub fn valid_firmware_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    ["http://", "https://", "ftp://"].iter().any(|p| lower.starts_with(p))
        && (lower.ends_with(".bin") || lower.ends_with(".tar"))
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
        && url.len() < 2048
}

/// POST /api/firmware/upgrade-url: install a specific firmware file (e.g. an early-access build).
pub async fn upgrade_url(State(s): State<AppState>, Json(b): Json<UrlBody>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "upgrades need")?;
    if !valid_firmware_url(&b.url) {
        return Err(ApiError::bad("use an http(s) or ftp URL ending in .bin or .tar"));
    }
    let mac = crate::api::parse_mac(&b.mac)?;
    let a = aps(&s.live.read().unwrap()).into_iter().find(|a| a.mac == mac).ok_or_else(|| ApiError::not_found("unknown AP"))?;
    if !a.online {
        return Err(ApiError::ap_offline());
    }
    let job = Job::new(a, "custom".into(), b.url, None, None, true);
    let n = change_queue(&s, Op::Enqueue(vec![job])).await?;
    Ok(Json(json!({ "queued": n })))
}

/// POST /api/firmware/cancel: drop queued upgrades (one already sent cannot be stopped).
pub async fn cancel(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let n = change_queue(&s, Op::CancelQueued).await?;
    Ok(Json(json!({ "cancelled": n })))
}

/// POST /api/firmware/resume: start a queue a failed upgrade stopped again.
pub async fn resume(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "upgrades need")?;
    let n = change_queue(&s, Op::Resume).await?;
    Ok(Json(json!({ "resumed": n > 0 })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;
    use crate::model::tests::flushed;

    #[test]
    fn reads_the_release_feed() {
        // The shape of a real entry (U6M, release channel).
        let feed = json!({ "_embedded": { "firmware": [
            { "platform": "U6M", "version": "v6.8.2+15592", "version_major": 6, "version_minor": 8, "version_patch": 2, "version_build": "15592",
              "version_prerelease": null, "md5": "0fec04452cadd2d025777d36ab2974ea", "sha256": null, "file_size": 22586927, "created": "2026-02-11T20:10:35Z",
              "_links": { "data": { "href": "https://fw-download.ubnt.com/data/unifi-firmware/51ba-U6M-6.8.2.bin" } } },
            { "platform": "BROKEN", "version_major": 1 },
        ] } });
        let r = parse_feed(&feed);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].platform.as_str(), r[0].version.as_str(), r[0].size), ("U6M", "6.8.2.15592", Some(22586927)));
        assert_eq!(r[0].md5.as_deref(), Some("0fec04452cadd2d025777d36ab2974ea"));
        assert_eq!(r[0].sha256, None);
        // Two entries for a platform: the newer, wherever it is listed.
        let entry = |platform: &str, patch: i64| json!({ "platform": platform, "version_major": 6, "version_minor": 8, "version_patch": patch, "version_build": "1", "_links": { "data": { "href": "u" } } });
        for list in [[entry("U6M", 10), entry("U6M", 9), entry("U7P", 1)], [entry("U6M", 9), entry("U6M", 10), entry("U7P", 1)]] {
            let r = parse_feed(&json!({ "_embedded": { "firmware": list } }));
            assert_eq!(r.iter().map(|r| (r.platform.as_str(), r.version.as_str())).collect::<Vec<_>>(), [("U6M", "6.8.10.1"), ("U7P", "6.8.1.1")]);
        }
    }

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(compare("8.8.11.20161", "6.8.2.15592"), Greater);
        assert_eq!(compare("6.8.10.1", "6.8.9.1"), Greater, "numbers, not text");
        assert_eq!(compare("v6.8.2+15592", "6.8.2"), Equal);
        assert_eq!(compare("6.8.2-rc.1", "6.8.2"), Less, "a pre-release is older than the release");
        assert_eq!(compare("6.8.2-rc1.1", "6.8.2-rc.1"), Equal, "a segment counts by its leading digits");
        assert_eq!(compare("6.10b.1", "6.9.1"), Greater);
    }

    #[test]
    fn never_offers_a_downgrade() {
        let rel = Release { platform: "U6M".into(), version: "6.8.2.15592".into(), url: "u".into(), md5: None, sha256: None, size: None, created: None };
        // The user's APs run early-access 8.8.11: ahead of release, nothing offered.
        assert_eq!(status(Some("8.8.11.20161"), Some(&rel), Some("6.2.49")), Status::Ahead);
        assert_eq!(status(Some("6.8.2.15592"), Some(&rel), None), Status::UpToDate);
        assert_eq!(status(Some("6.7.0.1"), Some(&rel), None), Status::UpdateAvailable);
        // A release below what the AP needs is not offered.
        assert_eq!(status(Some("6.7.0.1"), Some(&rel), Some("7.0.0")), Status::Unknown);
        assert_eq!(status(Some("6.7.0.1"), None, None), Status::Unknown);
        assert_eq!((json!(Status::UpdateAvailable), json!(Skip::NotFound)), (json!("update_available"), json!("not_found")), "named as the UI expects");
    }

    /// A test AP's MAC, by a one-hex-digit name.
    fn m(name: &str) -> Mac {
        format!("02:00:00:00:00:0{name}").parse().unwrap()
    }

    fn job(mac: &str) -> Job {
        Job {
            mac: m(mac),
            name: Some(mac.into()),
            from: Some("6.7.0.1".into()),
            target: "6.8.2.15592".into(),
            url: "https://x/fw.bin".into(),
            md5: Some("m".into()),
            sha256: Some("s".into()),
            custom: false,
            state: JobState::Queued,
            sent_at: None,
            expires: None,
        }
    }

    #[test]
    fn one_at_a_time_and_stop_on_failure() {
        let mut j = Jobs::default();
        j.enqueue(vec![job("a"), job("b"), job("c")]);
        assert_eq!(j.current.as_ref().map(|c| c.mac), Some(m("a")));
        // Not a's turn to be told yet for b.
        assert!(command(&mut j, &m("b"), &json!({}), 100).is_none());
        // a informs: it gets the command (sha256 only with the capability bit).
        let cmd = command(&mut j, &m("a"), &json!({ "fw_caps": CAP_SHA256, "upgrade_duration": 120, "reboot_duration": 60 }), 100).unwrap().unwrap();
        assert_eq!((cmd["_type"].as_str(), cmd["version"].as_str(), cmd["md5sum"].as_str(), cmd["sha256sum"].as_str()), (Some("upgrade"), Some("6.8.2.15592"), Some("m"), Some("s")));
        assert_eq!(j.current.as_ref().and_then(|c| c.expires), Some(100 + 450), "at least 450 s");
        assert!(command(&mut j, &m("a"), &json!({}), 110).is_none(), "sent once");
        assert!(j.version_seen(&m("b"), "6.8.2.15592").is_none(), "not b's turn");
        // The same version again is not success; the new one is.
        assert!(j.version_seen(&m("a"), "6.7.0.1").is_none());
        assert!(j.version_seen(&m("a"), "6.8.2.15592").is_some());
        assert_eq!(j.current.as_ref().map(|c| c.mac), Some(m("b")));
        // b has no internet: refused, and the queue stops before c.
        assert_eq!(command(&mut j, &m("b"), &json!({ "internet": false }), 200).unwrap().unwrap_err(), "the AP has no internet access to download the firmware");
        j.failed(&m("b"), "no internet");
        assert!(j.current.is_none() && j.stopped.is_some() && j.queue.len() == 1);
        // Queuing more does not start a stopped queue; resuming does, once.
        j.enqueue(vec![job("d")]);
        assert!(j.current.is_none() && j.stopped.is_some() && j.queue.len() == 2);
        assert_eq!(Op::Resume.apply(&mut j), 1);
        assert_eq!(j.current.as_ref().map(|c| c.mac), Some(m("c")));
        assert_eq!(Op::Resume.apply(&mut j), 0, "not stopped");
    }

    #[test]
    fn success_needs_a_version_change_when_the_start_is_unknown() {
        let mut j = Jobs::default();
        j.enqueue(vec![Job { from: None, ..job("a") }]);
        assert!(j.version_seen(&m("a"), "6.7.0.1").is_none(), "not sent yet");
        // The version in the inform the command goes out with is where it started.
        command(&mut j, &m("a"), &json!({ "version": "6.7.0.1" }), 0).unwrap().unwrap();
        assert!(j.version_seen(&m("a"), "6.7.0.1").is_none(), "the next inform, still downloading");
        assert_eq!(j.version_seen(&m("a"), "6.8.2.15592").and_then(|x| x.from).as_deref(), Some("6.7.0.1"));
        // An inform without a version: the first one reported afterwards is the start.
        j.enqueue(vec![Job { from: None, ..job("b") }]);
        command(&mut j, &m("b"), &json!({}), 0).unwrap().unwrap();
        assert!(j.version_seen(&m("b"), "6.7.0.1").is_none());
        assert!(j.version_seen(&m("b"), "6.7.0.1").is_none());
        assert!(j.version_seen(&m("b"), "6.8.2.15592").is_some());
    }

    #[test]
    fn deadlines_and_cancelling() {
        let mut j = Jobs::default();
        j.enqueue(vec![job("a"), job("b")]);
        command(&mut j, &m("a"), &json!({ "upgrade_duration": 600, "reboot_duration": 100 }), 0).unwrap().unwrap();
        assert_eq!(j.expired(700), None);
        assert_eq!(j.expired(701), Some((m("a"), TIMED_OUT)));
        // Each step the AP reports gives it the step's time again.
        j.progress(&m("a"), JobState::Downloading, 650);
        assert_eq!(j.current.as_ref().map(|c| (c.state, c.expires)), Some((JobState::Downloading, Some(650 + STEP_DEADLINE))));
        assert_eq!(j.cancel_queued(), 1, "only b; a is already upgrading");
        assert!(j.current.is_some());
        // As the engine makes the changes the UI asks for.
        assert_eq!(Op::Enqueue(vec![job("c"), job("d")]).apply(&mut j), 2);
        assert_eq!(Op::Enqueue(vec![job("a"), job("c"), job("e")]).apply(&mut j), 1, "a is upgrading and c queued already");
        assert_eq!(Op::CancelQueued.apply(&mut j), 3);
    }

    #[test]
    fn a_firmware_url_is_sent_as_version_unknown() {
        let mut j = Jobs::default();
        j.enqueue(vec![Job { target: "custom".into(), custom: true, md5: None, sha256: None, ..job("a") }]);
        let cmd = command(&mut j, &m("a"), &json!({ "internet": false }), 0).unwrap().unwrap();
        assert_eq!((cmd["version"].as_str(), cmd["url"].as_str()), (Some("unknown"), Some("https://x/fw.bin")));
        assert_eq!(j.current.as_ref().map(|c| c.target.as_str()), Some("custom"), "the UI's label stays");
    }

    #[test]
    fn notices_before_the_command_is_sent_leave_the_job_alone() {
        let mut j = Jobs::default();
        j.enqueue(vec![job("a"), job("b")]);
        // An upgrade started elsewhere, or a late notice of an earlier one.
        j.progress(&m("a"), JobState::Downloading, 100);
        assert!(j.upgrade_error(&m("a"), "download failed").is_none());
        assert_eq!(j.current.as_ref().map(|c| (c.mac, c.state, c.expires)), Some((m("a"), JobState::Queued, None)));
        // Its turn still sends the command; after that the notices count.
        command(&mut j, &m("a"), &json!({}), 110).unwrap().unwrap();
        j.progress(&m("a"), JobState::Downloading, 120);
        assert_eq!(j.current.as_ref().map(|c| c.state), Some(JobState::Downloading));
        assert_eq!(j.upgrade_error(&m("a"), "download failed").map(|f| f.mac), Some(m("a")));
        assert!(j.current.is_none() && j.stopped.is_some());
    }

    #[test]
    fn the_aps_estimate_is_kept_within_bounds() {
        for (estimate, expires) in [((i64::MAX, i64::MAX), MAX_DEADLINE), ((-1_000_000, 0), STEP_DEADLINE)] {
            let mut j = Jobs::default();
            j.enqueue(vec![job("a")]);
            command(&mut j, &m("a"), &json!({ "upgrade_duration": estimate.0, "reboot_duration": estimate.1 }), 100).unwrap().unwrap();
            assert_eq!(j.current.as_ref().and_then(|c| c.expires), Some(100 + expires));
        }
    }

    #[test]
    fn an_upgrade_whose_ap_never_takes_its_turn_fails() {
        let mut j = Jobs::default();
        j.enqueue(vec![job("a"), job("b")]);
        // Its wait starts when it is first found at the head of the queue.
        assert_eq!(j.expired(1000), None);
        assert_eq!(j.current.as_ref().and_then(|c| c.expires), Some(1000 + TURN_WAIT));
        assert_eq!(j.expired(1000 + TURN_WAIT), None);
        let (mac, why) = j.expired(1001 + TURN_WAIT).unwrap();
        assert_eq!((mac, why), (m("a"), NOT_TAKEN));
        // As a sent one out of time: it fails and the queue stops before b.
        j.failed(&mac, why);
        assert!(j.current.is_none() && j.queue.len() == 1);
        assert_eq!(j.stopped.as_deref(), Some(format!("a failed: {NOT_TAKEN}").as_str()));
        // Resumed, b gets a wait of its own; taking its turn in time sets the sent deadline.
        j.resume();
        assert_eq!(j.expired(5000), None);
        command(&mut j, &m("b"), &json!({}), 5100).unwrap().unwrap();
        assert_eq!(j.current.as_ref().and_then(|c| c.expires), Some(5100 + 450));
        assert_eq!(j.expired(5551), Some((m("b"), TIMED_OUT)), "then it is out of time as a sent one");
    }

    #[test]
    fn a_check_replaces_what_the_last_one_listed_whatever_the_clock() {
        let dir = crate::model::tests::TestDir::new("firmware-releases");
        let (store, writer) = crate::store::Store::open(&dir).unwrap();
        let rel = |p: &str| Release { platform: p.into(), version: "6.8.2.15592".into(), url: "u".into(), md5: None, sha256: None, size: None, created: None };
        store_releases(&writer, &[rel("U6M"), rel("U7P")], 2_000_000_000);
        // The clock steps back before the next check, which no longer lists U7P.
        store_releases(&writer, &[rel("U6M"), rel("UAL6")], 1_000_000_000);
        flushed(&writer);
        let (rels, checked, error) = store.read(Db::Config, releases).unwrap();
        let mut platforms: Vec<&str> = rels.keys().map(String::as_str).collect();
        platforms.sort_unstable();
        assert_eq!((platforms, checked, error), (vec!["U6M", "UAL6"], Some(1_000_000_000), None));
    }

    #[test]
    fn firmware_urls() {
        assert!(valid_firmware_url("https://dl.ui.com/unifi/firmware/U6M/8.8.12/BZ.mt7621.v8.8.12.bin"));
        assert!(valid_firmware_url("http://192.168.1.10/fw.tar"));
        assert!(!valid_firmware_url("file:///etc/passwd.bin"));
        assert!(!valid_firmware_url("https://example.com/fw.exe"));
        assert!(!valid_firmware_url("https://example.com/a b.bin"));
    }
}
