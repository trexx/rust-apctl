//! HTTP API and live WebSocket for the web UI.

use std::sync::Arc;

use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use inform::Mac;
use rusqlite::types::Value as Sql;
use rusqlite::params_from_iter;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::engine::{AliasEdit, LiveMsg, SharedLive};
use crate::model::Ts;
use crate::store::{self, Db, Store};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    /// Manufacturer names by MAC prefix (IEEE registry).
    pub vendors: Arc<crate::vendor::Vendors>,
    /// The config generator (for on-demand dry runs and settings previews).
    pub renderer: crate::dryrun::RenderFn,
    pub auth: crate::auth::SharedAuth,
    /// Commands for the engine (e.g. setting aliases).
    pub engine: tokio::sync::mpsc::Sender<crate::engine::Input>,
    pub live: SharedLive,
    /// The live messages as JSON text, for the UI's sockets (see `live_json`).
    pub tx: broadcast::Sender<Utf8Bytes>,
    pub started: Ts,
    pub source: String,
    pub backups: crate::backup::Backups,
    /// Active mode: apctl answers the APs (and can upgrade them).
    pub active: bool,
    pub writer: crate::store::Writer,
}

pub fn router(state: AppState) -> Router {
    let public = Router::new()
        // For Kubernetes probes: no login, no data.
        .route("/healthz", get(healthz))
        .route("/api/login", axum::routing::post(crate::auth::login))
        .route("/api/logout", axum::routing::post(crate::auth::logout))
        .route("/api/me", get(crate::auth::me));
    let protected = Router::new()
        .route("/api/status", get(status))
        .route("/api/devices", get(devices))
        .route("/api/devices/{mac}", get(device))
        .route("/api/clients", get(clients))
        .route("/api/clients/{mac}", get(client))
        .route("/api/clients/{mac}/alias", axum::routing::put(set_alias))
        .route("/api/clients/aliases", axum::routing::post(import_aliases))
        .route("/api/devices/pending", get(crate::adopt::pending))
        .route("/api/devices/adopt-ssh", axum::routing::post(crate::ssh::adopt))
        .route("/api/devices/{mac}/adopt", axum::routing::post(crate::adopt::adopt))
        .route("/api/devices/{mac}/forget", axum::routing::post(crate::adopt::forget))
        .route("/api/devices/{mac}/restart", axum::routing::post(crate::actions::restart))
        .route("/api/devices/{mac}/locate", axum::routing::post(crate::actions::locate))
        .route("/api/devices/{mac}/provision", axum::routing::post(crate::actions::provision))
        .route("/api/clients/{mac}/kick", axum::routing::post(crate::actions::kick))
        .route("/api/clients/{mac}/block", axum::routing::post(crate::actions::block))
        .route("/api/clients/{mac}/lock", axum::routing::post(crate::actions::lock))
        .route(
            "/api/settings/state",
            get(state_summary).post(import_state).layer(axum::extract::DefaultBodyLimit::max(8 << 20)),
        )
        .route("/api/settings/site", get(crate::site::get_site).put(crate::site::put_site))
        .route("/api/settings/wlans", get(crate::settings::wlans).post(crate::settings::post_wlan))
        .route("/api/settings/wlans/{id}", axum::routing::put(crate::settings::put_wlan).delete(crate::settings::delete_wlan_route))
        .route("/api/settings/wlans/{id}/passphrase", get(crate::settings::passphrase))
        .route("/api/settings/devices/{mac}", get(crate::settings::device).put(crate::settings::put_device))
        .route("/api/settings/usergroups", get(crate::settings::usergroups).post(crate::settings::post_usergroup))
        .route("/api/settings/usergroups/{id}", axum::routing::put(crate::settings::put_usergroup).delete(crate::settings::delete_usergroup))
        .route("/api/clients/{mac}/speed-limit", axum::routing::put(crate::settings::put_client_group))
        .route("/api/dryrun", get(dryrun))
        .route("/api/site/activity", get(crate::insights::activity))
        .route("/api/site/top", get(crate::insights::top))
        .route("/api/site/connectivity", get(crate::connections::connectivity))
        .route("/api/connections", get(crate::connections::list))
        .route("/api/firmware", get(crate::firmware::index))
        .route("/api/firmware/check", axum::routing::post(crate::firmware::check_now))
        .route("/api/firmware/upgrade", axum::routing::post(crate::firmware::upgrade))
        .route("/api/firmware/upgrade-url", axum::routing::post(crate::firmware::upgrade_url))
        .route("/api/firmware/cancel", axum::routing::post(crate::firmware::cancel))
        .route("/api/backups", get(crate::backup::index).post(crate::backup::create_now))
        .route("/api/backups/settings", axum::routing::put(crate::backup::put_settings))
        .route("/api/backups/file/{name}", get(crate::backup::download).delete(crate::backup::delete))
        .route("/api/backups/upload", axum::routing::post(crate::backup::upload))
        .route("/api/backups/restore", axum::routing::post(crate::backup::restore))
        .route("/api/alerts", get(crate::alerts::list))
        .route("/api/alerts/read", axum::routing::post(crate::alerts::mark_read))
        .route("/api/wlans", get(crate::insights::wlans))
        .route("/api/roaming", get(crate::connections::roaming))
        .route("/api/site/density", get(crate::insights::density))
        .route("/api/site/retries", get(crate::insights::retries))
        .route("/api/site/multicast", get(crate::insights::multicast))
        .route("/api/rf/radios", get(crate::insights::radios))
        .route("/api/rf/neighbors", get(crate::insights::neighbors))
        .route("/api/rf/channel-plan", get(crate::insights::channel_plan))
        .route("/api/rf/channel-plan/apply", axum::routing::post(crate::channelai::apply_plan))
        .route("/api/rf/channel-ai", get(crate::channelai::status).put(crate::channelai::put_settings))
        .route("/api/rf/channel-ai/run", axum::routing::post(crate::channelai::run_now))
        .route("/api/rf/scan", axum::routing::post(crate::channelai::scan))
        .route("/api/rf/threats", get(crate::threats::list))
        .route("/api/rf/threats/ack", axum::routing::put(crate::threats::ack))
        .route("/api/series/{table}", get(series))
        .route("/api/events", get(events))
        .route("/api/logs", get(logs))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), crate::auth::require_login));
    // The live socket is added after compression, which must not touch an upgrade.
    let socket = Router::new().route("/api/ws", get(ws)).route_layer(axum::middleware::from_fn_with_state(state.clone(), crate::auth::require_login));
    // JSON and the UI's scripts and styles compress well (gzip only; images are left alone).
    public.merge(protected).fallback(crate::web::handler).layer(tower_http::compression::CompressionLayer::new().compress_when(compressible())).merge(socket).with_state(state)
}

/// What is worth compressing: the defaults (nothing tiny, no images), and no
/// octet-stream, which apctl only sends for backups, already compressed or
/// encrypted (compressing them again costs CPU and loses their length).
fn compressible() -> impl tower_http::compression::Predicate {
    use tower_http::compression::predicate::{DefaultPredicate, NotForContentType, Predicate};
    DefaultPredicate::new().and(NotForContentType::const_new("application/octet-stream"))
}

/// 409 unless apctl is the active controller. `what` says what needs it ("upgrades need").
pub fn require_active(s: &AppState, what: &str) -> Result<(), ApiError> {
    if s.active { Ok(()) } else { Err(ApiError(StatusCode::CONFLICT, format!("{what} active mode: in shadow mode apctl never talks to the APs"))) }
}

/// The imported settings, as they are now.
pub fn current_state(s: &AppState) -> Result<Arc<Value>, ApiError> {
    s.live.read().unwrap().state.clone().ok_or_else(ApiError::no_state)
}

pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn internal(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }

    /// Nothing to work on: no settings were imported yet.
    pub fn no_state() -> Self {
        ApiError(StatusCode::CONFLICT, "no settings imported yet".into())
    }

    /// The engine thread is gone (it ended, or panicked).
    pub fn engine_stopped() -> Self {
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "engine stopped".into())
    }
}

impl AppState {
    /// Hands the engine an input.
    pub async fn send(&self, input: crate::engine::Input) -> Result<(), ApiError> {
        self.engine.send(input).await.map_err(|_| ApiError::engine_stopped())
    }

    /// Hands the engine an input that answers on `rx`, and waits for the answer.
    pub async fn ask<T>(&self, input: crate::engine::Input, rx: tokio::sync::oneshot::Receiver<T>) -> Result<T, ApiError> {
        self.send(input).await?;
        rx.await.map_err(|_| ApiError::engine_stopped())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

/// An unexpected failure: the details (paths, SQL) go to the log, not to the browser.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("request failed: {e:#}");
        ApiError::internal(INTERNAL)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::from(anyhow::Error::from(e))
    }
}

const INTERNAL: &str = "internal error (the details are in apctl's log)";

/// A blocking task that panicked or was cancelled: logged, and as unexpected
/// as any other failure to the browser (a panic message can name paths or data).
impl From<tokio::task::JoinError> for ApiError {
    fn from(e: tokio::task::JoinError) -> Self {
        ApiError::from(anyhow::Error::from(e))
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

/// A MAC address from the URL or body; 400 when it isn't one.
pub fn parse_mac(s: &str) -> Result<Mac, ApiError> {
    s.parse().map_err(|_| bad(format!("invalid MAC {s}")))
}

/// Runs a read query on the blocking pool.
pub async fn read<T: Send + 'static>(
    store: &Arc<Store>,
    db: Db,
    f: impl FnOnce(&rusqlite::Connection) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || store.read(db, f)).await?.map_err(ApiError::from)
}

async fn status(State(s): State<AppState>) -> ApiResult {
    let live = s.live.read().unwrap();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if s.active { "active" } else { "shadow" },
        "source": s.source,
        "started": s.started,
        "now": store::now_ts(),
        "counters": &*live.counters,
        "devices": live.devices.len(),
        "devices_online": live.devices.values().filter(|d| d.online).count(),
        "clients_connected": live.clients.values().filter(|c| c.connected).count(),
    })))
}

/// For Kubernetes probes. Fails once nothing can be stored or processed any more.
async fn healthz(State(s): State<AppState>) -> Response {
    if s.writer.stopped() {
        return (StatusCode::SERVICE_UNAVAILABLE, "database writer stopped").into_response();
    }
    // The engine thread drops its end of the queue however it ends, a panic
    // included; a panic under the live view's lock poisons it for every reader.
    if s.engine.is_closed() || s.live.is_poisoned() {
        return (StatusCode::SERVICE_UNAVAILABLE, "engine stopped").into_response();
    }
    "ok".into_response()
}

/// An AP as the database remembers it: shown after a restart until it reports again.
struct StoredDevice {
    mac: String,
    /// The name given in apctl, else the AP's hostname.
    name: Option<String>,
    model: Option<String>,
    model_display: Option<String>,
    version: Option<String>,
    ip: Option<String>,
    serial: Option<String>,
    first_seen: Ts,
    last_seen: Ts,
}

impl StoredDevice {
    /// Shaped like a live device view, but offline.
    fn view(&self) -> Value {
        json!({
            "snapshot": {
                "ap": {
                    "mac": self.mac, "hostname": self.name, "model": self.model, "model_display": self.model_display, "version": self.version,
                    "ip": self.ip, "serial": self.serial, "uptime": null, "cpu": null, "mem": null, "load1": null, "load5": null,
                    "load15": null, "mem_total": null, "mem_used": null, "satisfaction": null,
                },
                "uplink": null, "radios": [], "vaps": [], "clients": [], "has_vap_table": false,
            },
            "online": false, "first_seen": self.first_seen, "last_seen": self.last_seen,
            "peer": "", "interval": 0, "reconfiguring": false, "last_config_push": null, "stored_only": true,
        })
    }

    /// Its row in the device list.
    fn row(self) -> DeviceRow {
        DeviceRow {
            mac: self.mac, name: self.name, model: self.model, model_display: self.model_display, version: self.version, ip: self.ip,
            online: false, reconfiguring: false, first_seen: self.first_seen, last_seen: self.last_seen, uptime: None, cpu: None, mem: None,
            load1: None, satisfaction: None, clients: 0, uplink: None, radios: vec![], last_config_push: None, locating: None, stored_only: true,
        }
    }
}

/// An AP in the device list.
#[derive(Serialize)]
struct DeviceRow {
    mac: String,
    name: Option<String>,
    model: Option<String>,
    model_display: Option<String>,
    version: Option<String>,
    ip: Option<String>,
    online: bool,
    reconfiguring: bool,
    first_seen: Ts,
    last_seen: Ts,
    uptime: Option<i64>,
    cpu: Option<f64>,
    mem: Option<f64>,
    load1: Option<f64>,
    satisfaction: Option<i64>,
    clients: usize,
    uplink: Option<UplinkRow>,
    radios: Vec<RadioRow>,
    last_config_push: Option<Ts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locating: Option<bool>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stored_only: bool,
}

#[derive(Serialize)]
struct UplinkRow {
    speed: Option<i64>,
    up: Option<bool>,
    full_duplex: Option<bool>,
}

#[derive(Serialize)]
struct RadioRow {
    radio: String,
    channel: Option<i64>,
    bw: Option<i64>,
    tx_power: Option<i64>,
    cu_total: Option<i64>,
    noise_floor: Option<i64>,
    clients: i64,
}

/// APs in the database (all, or `only` this one).
async fn stored_devices(store: &Arc<Store>, only: Option<String>) -> Result<Vec<StoredDevice>, ApiError> {
    read(store, Db::Config, move |c| {
        let mut stmt = c.prepare(
            "SELECT mac, COALESCE(name, hostname), model, model_display, version, ip, serial, first_seen, last_seen FROM devices WHERE ?1 IS NULL OR mac = ?1",
        )?;
        let rows = stmt
            .query_map([only.as_deref()], |r| {
                Ok(StoredDevice {
                    mac: r.get(0)?, name: r.get(1)?, model: r.get(2)?, model_display: r.get(3)?, version: r.get(4)?, ip: r.get(5)?, serial: r.get(6)?,
                    first_seen: r.get::<_, Option<i64>>(7)?.unwrap_or(0), last_seen: r.get::<_, Option<i64>>(8)?.unwrap_or(0),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await
}

async fn devices(State(s): State<AppState>) -> Result<Json<Vec<DeviceRow>>, ApiError> {
    let stored = stored_devices(&s.store, None).await?;
    // The rows are copied out under the lock (a few short strings each) and
    // serialised after it.
    let list = {
        let live = s.live.read().unwrap();
        // Connected clients per AP, counted in one pass.
        let mut per_ap: std::collections::HashMap<Mac, usize> = std::collections::HashMap::new();
        for c in live.clients.values().filter(|c| c.connected) {
            *per_ap.entry(c.sample.ap_mac).or_default() += 1;
        }
        let mut list: Vec<DeviceRow> = live
            .devices
            .iter()
            .map(|(mac, d)| {
                let a = &d.snapshot.ap;
                DeviceRow {
                    mac: mac.to_string(), name: a.hostname.clone(), model: a.model.clone(), model_display: a.model_display.clone(),
                    version: a.version.clone(), ip: a.ip.clone(), online: d.online, reconfiguring: d.reconfiguring,
                    first_seen: d.first_seen, last_seen: d.last_seen, uptime: a.uptime, cpu: a.cpu, mem: a.mem, load1: a.load1,
                    satisfaction: a.satisfaction, clients: per_ap.get(mac).copied().unwrap_or(0),
                    uplink: d.snapshot.uplink.as_ref().map(|u| UplinkRow { speed: u.speed, up: u.up, full_duplex: u.full_duplex }),
                    radios: d.snapshot.radios.iter().map(|r| RadioRow {
                        radio: r.radio.clone(), channel: r.channel, bw: r.bw, tx_power: r.tx_power, cu_total: r.cu_total,
                        noise_floor: r.noise_floor, clients: r.num_sta,
                    }).collect(),
                    last_config_push: d.last_config_push,
                    locating: Some(live.locating.contains(mac)),
                    stored_only: false,
                }
            })
            .collect();
        list.extend(stored.into_iter().filter(|d| !d.mac.parse().is_ok_and(|m: Mac| live.devices.contains_key(&m))).map(StoredDevice::row));
        list
    };
    Ok(Json(list))
}

async fn device(State(s): State<AppState>, Path(mac): Path<String>) -> ApiResult {
    let mac = parse_mac(&mac)?;
    let found = {
        let live = s.live.read().unwrap();
        live.devices.get(&mac).map(|d| {
            // The clients are copied out (shared samples) and serialised after the lock.
            let clients: Vec<_> = live.clients.values().filter(|c| c.connected && c.sample.ap_mac == mac).cloned().collect();
            (serde_json::to_value(d).unwrap_or_default(), clients, live.locating.contains(&mac))
        })
    };
    if let Some((device, clients, locating)) = found {
        return Ok(Json(json!({ "device": device, "clients": clients, "locating": locating })));
    }
    // Known but not reporting since apctl started: offline, with what we stored.
    let stored = stored_devices(&s.store, Some(mac.to_string())).await?;
    let d = stored.into_iter().next().ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown device".into()))?;
    Ok(Json(json!({ "device": d.view(), "clients": [] })))
}

/// Every client: the ones seen in this run and the ones restored from the
/// database at start (`Engine::restore` loads them all, so the live view is
/// the whole list).
/// A client as the client list and page show it: its view, plus its name,
/// manufacturer and controls.
#[derive(Serialize)]
struct ClientRow<'a> {
    #[serde(flatten)]
    view: &'a crate::engine::ClientView,
    #[serde(skip_serializing_if = "Option::is_none")]
    ap_name: Option<Option<&'a str>>,
    alias: Option<&'a str>,
    note: Option<&'a str>,
    vendor: Option<&'a str>,
    #[serde(flatten)]
    controls: crate::actions::Controls<'a>,
}

type ClientCopy = (Mac, crate::engine::ClientView, Option<String>, Option<crate::engine::Alias>);

async fn clients(State(s): State<AppState>) -> Response {
    // What each client's entry needs, copied under the lock (the samples are
    // shared, the rest is small); the serialising happens after it.
    let (state, list) = {
        let live = s.live.read().unwrap();
        let list: Vec<ClientCopy> = live
            .clients
            .iter()
            .map(|(mac, c)| {
                let ap_name = live.devices.get(&c.sample.ap_mac).and_then(|d| d.snapshot.ap.hostname.clone());
                (*mac, c.clone(), ap_name, live.aliases.get(mac).cloned())
            })
            .collect();
        (live.state.clone(), list)
    };
    let controls = crate::actions::ClientControls::new(state.as_deref());
    let rows: Vec<ClientRow> = list
        .iter()
        .map(|(mac, view, ap_name, alias)| ClientRow {
            view,
            ap_name: Some(ap_name.as_deref()),
            alias: alias.as_ref().and_then(|a| a.alias.as_deref()),
            note: alias.as_ref().and_then(|a| a.note.as_deref()),
            vendor: s.vendors.lookup(mac),
            controls: controls.get(mac),
        })
        .collect();
    Json(rows).into_response()
}

async fn client(State(s): State<AppState>, Path(mac): Path<String>) -> Result<Response, ApiError> {
    let mac = parse_mac(&mac)?;
    let (view, alias, state) = {
        let live = s.live.read().unwrap();
        let view = live.clients.get(&mac).cloned().ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown client".into()))?;
        (view, live.aliases.get(&mac).cloned().unwrap_or_default(), live.state.clone())
    };
    let row = ClientRow {
        view: &view,
        ap_name: None,
        alias: alias.alias.as_deref(),
        note: alias.note.as_deref(),
        vendor: s.vendors.lookup(&mac),
        controls: crate::actions::controls(state.as_deref(), &mac),
    };
    Ok(Json(row).into_response())
}

async fn state_summary(State(s): State<AppState>) -> ApiResult {
    let live = s.live.read().unwrap();
    Ok(Json(json!({
        "imported_at": live.state_imported_at,
        "summary": live.state.as_deref().map(crate::dryrun::summarize_state),
    })))
}

/// Replaces the imported controller settings with an `informdump import` snapshot.
async fn import_state(State(s): State<AppState>, Json(state): Json<Value>) -> ApiResult {
    crate::dryrun::validate_state(&state).map_err(|e| bad(format!("{e:#}")))?;
    let summary = crate::dryrun::summarize_state(&state);
    s.send(crate::engine::Input::SetState { ts: store::now_ts(), state }).await?;
    Ok(Json(json!({ "ok": true, "summary": summary })))
}

/// Dry-run status: for each AP, what apctl would push now compared with the last
/// config the other controller pushed; plus the comparisons made at each push.
async fn dryrun(State(s): State<AppState>) -> ApiResult {
    // What each AP's render needs, copied under a short lock: the unredacted
    // config seen in this run when there is one. Only full configs count: a
    // management-only push says nothing about system_cfg.
    let (state, imported_at, aps) = {
        let live = s.live.read().unwrap();
        let aps: Vec<_> = live
            .devices
            .iter()
            .map(|(mac, d)| {
                let seen = live.last_config.get(mac).filter(|c| !c.system_cfg.is_empty()).cloned();
                (*mac, d.snapshot.ap.hostname.clone(), d.snapshot.ap.cfgversion.clone(), seen, live.raw_informs.get(mac).cloned())
            })
            .collect();
        (live.state.clone(), live.state_imported_at, aps)
    };
    // Then from the database, in one go: the stored redacted copy for APs not
    // pushed to since start, and the comparisons made at each push.
    let need: Vec<Mac> = aps.iter().filter(|a| a.3.is_none()).map(|a| a.0).collect();
    let (stored, history) = read(&s.store, Db::Config, move |c| {
        let mut stored = std::collections::HashMap::new();
        for mac in need {
            if let Some(p) = crate::engine::stored_push(c, &mac)?.filter(|p| !p.system_cfg.is_empty()) {
                stored.insert(mac, Arc::new(p));
            }
        }
        let mut stmt = c.prepare("SELECT ts, mac, cfgversion, matches, comparison FROM dryrun_results ORDER BY ts DESC LIMIT 100")?;
        let history = stmt
            .query_map([], |r| {
                let comparison: String = r.get(4)?;
                Ok(json!({
                    "ts": r.get::<_, i64>(0)?, "mac": r.get::<_, String>(1)?, "cfgversion": r.get::<_, Option<String>>(2)?,
                    "matches": r.get::<_, i64>(3)? != 0,
                    "comparison": serde_json::from_str::<Value>(&comparison).unwrap_or(Value::Null),
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((stored, history))
    })
    .await?;

    // The renders run on the blocking pool.
    let renderer = s.renderer.clone();
    let devices = tokio::task::spawn_blocking(move || {
        // The settings' AP records by MAC, looked up once (the first for a MAC counts).
        let mut docs: std::collections::HashMap<Mac, &Value> = std::collections::HashMap::new();
        for d in state.as_deref().and_then(|st| st["devices"].as_array()).into_iter().flatten() {
            if let Some(mac) = d["mac"].as_str().and_then(|m| m.parse().ok()) {
                docs.entry(mac).or_insert(d);
            }
        }
        let mut stored = stored;
        let mut devices = Vec::new();
        for (mac, name, running_version, seen, inform) in aps {
            let actual = seen.map(|c| (c, false)).or_else(|| stored.remove(&mac).map(|c| (c, true)));
            // The snapshot records the cfgversion the other controller expected for
            // each AP at import time. If the AP now runs another one, that controller
            // has pushed new config since: the settings are probably out of date.
            let snapshot_version = docs.get(&mac).and_then(|d| d["cfgversion"].as_str());
            let settings_stale = matches!((snapshot_version, &running_version), (Some(a), Some(b)) if a != b);
            let entry = |status: &str, extra: Value| {
                let mut v = json!({ "mac": mac, "name": name, "status": status, "settings_stale": settings_stale });
                if let Value::Object(m) = extra {
                    v.as_object_mut().unwrap().extend(m);
                }
                v
            };
            let Some(state) = state.as_deref() else {
                devices.push(entry("no_settings", json!({})));
                continue;
            };
            let Some((actual, redacted)) = actual else {
                devices.push(entry("no_config_seen", json!({})));
                continue;
            };
            let req = crate::dryrun::RenderRequest {
                state,
                device_mac: &mac.to_string(),
                inform: inform.as_deref(),
                cfgversion: actual.cfgversion.as_deref().unwrap_or(""),
                previous_system_cfg: Some(&actual.system_cfg),
            };
            match renderer(&req) {
                Ok(ours) => {
                    let c = crate::dryrun::compare(&ours, &actual.mgmt_cfg, &actual.system_cfg, redacted);
                    let status = if c.mgmt_cfg.identical && c.system_cfg.identical {
                        "match"
                    } else if c.matches() {
                        "equivalent"
                    } else {
                        "differs"
                    };
                    devices.push(entry(status, json!({ "comparison": c, "against_redacted": redacted })));
                }
                Err(e) => devices.push(entry("error", json!({ "error": format!("{e:#}") }))),
            }
        }
        devices
    })
    .await?;
    Ok(Json(json!({
        "settings_imported_at": imported_at,
        "devices": devices,
        "history": history,
    })))
}

#[derive(Deserialize)]
struct AliasBody {
    alias: Option<String>,
    note: Option<String>,
}

const MAX_ALIAS: usize = 64;
const MAX_NOTE: usize = 500;

fn validate(alias: &Option<String>, note: &Option<String>) -> Result<(), ApiError> {
    if alias.as_ref().is_some_and(|a| a.chars().count() > MAX_ALIAS) {
        return Err(bad(format!("alias longer than {MAX_ALIAS} characters")));
    }
    if note.as_ref().is_some_and(|n| n.chars().count() > MAX_NOTE) {
        return Err(bad(format!("note longer than {MAX_NOTE} characters")));
    }
    Ok(())
}

/// Sets (or, with empty values, clears) a client's alias and note.
async fn set_alias(
    State(s): State<AppState>,
    Path(mac): Path<String>,
    Json(body): Json<AliasBody>,
) -> ApiResult {
    let mac = parse_mac(&mac)?;
    validate(&body.alias, &body.note)?;
    let entries = vec![AliasEdit { mac, alias: body.alias, note: body.note }];
    let input = crate::engine::Input::SetAliases { ts: store::now_ts(), entries, only_if_unset: false };
    s.send(input).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct ImportEntry {
    mac: String,
    alias: Option<String>,
    note: Option<String>,
}

#[derive(Deserialize)]
struct ImportQuery {
    #[serde(default)]
    overwrite: bool,
}

/// Bulk-sets aliases (e.g. names from another controller). By default an
/// alias already set in apctl is kept.
async fn import_aliases(
    State(s): State<AppState>,
    Query(q): Query<ImportQuery>,
    Json(entries): Json<Vec<ImportEntry>>,
) -> ApiResult {
    let mut parsed = Vec::with_capacity(entries.len());
    for e in entries {
        validate(&e.alias, &e.note)?;
        parsed.push(AliasEdit { mac: parse_mac(&e.mac)?, alias: e.alias, note: e.note });
    }
    let n = parsed.len();
    // All in one message: one pass of the engine, one client-list update.
    let input = crate::engine::Input::SetAliases { ts: store::now_ts(), entries: parsed, only_if_unset: !q.overwrite };
    s.send(input).await?;
    Ok(Json(json!({ "submitted": n })))
}

#[derive(Deserialize)]
struct SeriesQuery {
    /// Key values in the table's key order, comma-separated (e.g. `mac,radio`).
    key: String,
    from: Option<Ts>,
    to: Option<Ts>,
}

async fn series(State(s): State<AppState>, Path(table): Path<String>, Query(q): Query<SeriesQuery>) -> Result<Json<store::Series>, ApiError> {
    let t = store::table(&table).ok_or_else(|| bad(format!("unknown series {table}")))?;
    let keys: Vec<String> = q.key.split(',').map(str::to_string).collect();
    if keys.len() != t.keys.len() {
        return Err(bad(format!("{table} needs key {}", t.keys.join(","))));
    }
    let now = store::now_ts();
    let to = q.to.unwrap_or(now);
    let from = q.from.unwrap_or(to.saturating_sub(3600));
    let (from, to) = (from.min(to), from.max(to));
    let tier = store::tier_for(from, to, now);
    Ok(Json(read(&s.store, Db::Metrics, move |c| store::series(c, t, &keys, from, to, tier)).await?))
}

/// A WHERE clause made of optional filters, with numbered parameters.
#[derive(Default)]
struct Where {
    cond: Vec<String>,
    params: Vec<Sql>,
}

impl Where {
    /// Adds a condition; its `?` stands for `value`.
    fn and(&mut self, sql: &str, value: Sql) {
        self.params.push(value);
        self.cond.push(sql.replace('?', &format!("?{}", self.params.len())));
    }

    fn sql(&self) -> String {
        if self.cond.is_empty() { "1 = 1".into() } else { self.cond.join(" AND ") }
    }
}

#[derive(Deserialize)]
struct EventQuery {
    device: Option<String>,
    client: Option<String>,
    kind: Option<String>,
    limit: Option<i64>,
}

/// The event kinds starting with `prefix`, read from the kind index one kind
/// at a time (a handful of lookups, however many events there are).
fn kinds_with_prefix(c: &rusqlite::Connection, prefix: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = c.prepare_cached(
        "WITH RECURSIVE k(kind) AS (
            SELECT (SELECT MIN(kind) FROM events WHERE kind >= ?1 AND kind < ?2)
            UNION ALL SELECT (SELECT MIN(kind) FROM events WHERE kind > k.kind AND kind < ?2) FROM k WHERE k.kind IS NOT NULL)
         SELECT kind FROM k WHERE kind IS NOT NULL",
    )?;
    stmt.query_map((prefix, format!("{prefix}{}", char::MAX)), |r| r.get(0))?.collect()
}

async fn events(State(s): State<AppState>, Query(q): Query<EventQuery>) -> ApiResult {
    let mut w = Where::default();
    if let Some(d) = &q.device {
        w.and("device_mac = ?", Sql::Text(parse_mac(d)?.to_string()));
    }
    if let Some(c) = &q.client {
        w.and("client_mac = ?", Sql::Text(parse_mac(c)?.to_string()));
    }
    // Prefix match, so `client` selects all client events; several kinds
    // can be given separated by commas.
    let prefixes: Vec<String> = q.kind.iter().flat_map(|k| k.split(',')).map(|k| k.trim().to_ascii_lowercase()).filter(|k| !k.is_empty()).take(10).collect();
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    const COLUMNS: &str = "ts, kind, device_mac, client_mac, data, id";
    let rows = read(&s.store, Db::Config, move |c| {
        let sql = if prefixes.is_empty() {
            format!("SELECT {COLUMNS} FROM events WHERE {} ORDER BY ts DESC, id DESC LIMIT {limit}", w.sql())
        } else {
            // The newest of each matching kind from the (kind, ts) index, then
            // the newest of those: a rare kind is found without walking every
            // event, and a common one reads no more than the limit.
            let mut kinds: Vec<String> = Vec::new();
            for p in &prefixes {
                kinds.extend(kinds_with_prefix(c, p)?);
            }
            kinds.sort();
            kinds.dedup();
            if kinds.is_empty() {
                return Ok(vec![]);
            }
            let filters = w.sql();
            let parts: Vec<String> = kinds
                .into_iter()
                .map(|k| {
                    w.params.push(Sql::Text(k));
                    format!("SELECT * FROM (SELECT {COLUMNS} FROM events WHERE {filters} AND kind = ?{} ORDER BY ts DESC, id DESC LIMIT {limit})", w.params.len())
                })
                .collect();
            format!("{} ORDER BY ts DESC, id DESC LIMIT {limit}", parts.join(" UNION ALL "))
        };
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(w.params), |r| {
                let data: Option<String> = r.get(4)?;
                Ok(json!({
                    "id": r.get::<_, i64>(5)?, "ts": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?,
                    "device_mac": r.get::<_, Option<String>>(2)?, "client_mac": r.get::<_, Option<String>>(3)?,
                    "data": data.and_then(|d| serde_json::from_str::<Value>(&d).ok()),
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
struct LogQuery {
    device: Option<String>,
    /// Full-text query (SQLite FTS5 syntax).
    q: Option<String>,
    limit: Option<i64>,
}

async fn logs(State(s): State<AppState>, Query(q): Query<LogQuery>) -> ApiResult {
    let mut w = Where::default();
    if let Some(d) = &q.device {
        w.and("l.device_mac = ?", Sql::Text(parse_mac(d)?.to_string()));
    }
    if let Some(text) = q.q.as_deref().filter(|t| !t.trim().is_empty()) {
        // Quote each word so user input cannot break FTS syntax; words are ANDed.
        let fts: Vec<String> = text.split_whitespace().map(|w| format!("\"{}\"", w.replace('"', "\"\""))).collect();
        w.and("l.id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?)", Sql::Text(fts.join(" ")));
    }
    let limit = q.limit.unwrap_or(500).clamp(1, 5000);
    let sql = format!(
        "SELECT l.ts, l.device_mac, l.src_ip, l.facility, l.severity, l.program, l.msg, l.id FROM logs l WHERE {} ORDER BY l.ts DESC, l.id DESC LIMIT {limit}",
        w.sql()
    );
    let rows = read(&s.store, Db::Logs, move |c| {
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(w.params), |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(7)?, "ts": r.get::<_, i64>(0)?, "device_mac": r.get::<_, Option<String>>(1)?, "src_ip": r.get::<_, Option<String>>(2)?,
                    "facility": r.get::<_, Option<i64>>(3)?, "severity": r.get::<_, Option<i64>>(4)?,
                    "program": r.get::<_, Option<String>>(5)?, "msg": r.get::<_, String>(6)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    Ok(Json(Value::Array(rows)))
}

async fn ws(State(s): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    let rx = s.tx.subscribe();
    upgrade.on_upgrade(move |socket| live_socket(socket, rx))
}

/// Tells a client that missed messages to refetch rather than dropping it.
const RESYNC: &str = r#"{"type":"resync"}"#;

/// Serialises each live message once, whatever the number of sockets: a task
/// forwards the engine's messages as JSON text to the channel they read.
/// Messages the task itself misses become a resync.
pub fn live_json(typed: &broadcast::Sender<LiveMsg>) -> broadcast::Sender<Utf8Bytes> {
    let (tx, _) = broadcast::channel(4096);
    let mut rx = typed.subscribe();
    let out = tx.clone();
    tokio::spawn(async move {
        loop {
            let text = match rx.recv().await {
                Ok(_) if out.receiver_count() == 0 => continue, // no socket open
                Ok(m) => Utf8Bytes::from(serde_json::to_string(&m).unwrap_or_default()),
                Err(broadcast::error::RecvError::Lagged(_)) => Utf8Bytes::from_static(RESYNC),
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let _ = out.send(text);
        }
    });
    tx
}

async fn live_socket(mut socket: WebSocket, mut rx: broadcast::Receiver<Utf8Bytes>) {
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                // Shared text: sending it copies nothing.
                Ok(text) => {
                    if socket.send(Message::Text(text)).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if socket.send(Message::Text(Utf8Bytes::from_static(RESYNC))).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

    /// The app's state, and the engine's end of its queue (dropping it stops the "engine").
    fn state() -> (AppState, tokio::sync::mpsc::Receiver<crate::engine::Input>) {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("apctl-api-{}-{nanos}", std::process::id()));
        let (store, writer) = Store::open(&dir).unwrap();
        let auth = Arc::new(crate::auth::Auth::new(Default::default(), &store, writer.clone(), Default::default()).unwrap());
        let (engine, engine_rx) = tokio::sync::mpsc::channel(1);
        let (tx, _) = broadcast::channel(1);
        let state = AppState {
            backups: crate::backup::Backups::new(dir, None),
            store, vendors: Default::default(), renderer: crate::dryrun::apcfg_renderer(crate::EMULATE_VERSION.into()), auth, engine, live: Default::default(), tx, started: 0, source: "none".into(),
            active: false, writer,
        };
        (state, engine_rx)
    }

    fn app() -> (Router, tokio::sync::mpsc::Receiver<crate::engine::Input>) {
        let (state, engine) = state();
        (router(state), engine)
    }

    async fn get_json(app: &Router, path: &str) -> Value {
        let res = app.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn device_and_client_lists() {
        let (s, _engine) = state();
        // One AP reporting with a client, one only in the database.
        let (tx, _) = broadcast::channel(16);
        let mut engine = crate::engine::Engine::new(s.writer.clone(), Default::default(), s.live.clone(), tx);
        let payload = json!({ "mac": "02:00:00:00:00:01", "hostname": "Hall", "uptime": 100, "vap_table": [
            { "bssid": "b1", "essid": "Home", "radio": "na", "channel": 36, "usage": "user", "sta_table": [{ "mac": "02:00:00:00:01:01", "hostname": "phone" }] },
        ] });
        let header = inform::Header { packet_version: 0, mac: Mac([0; 6]), flags: inform::Flags(0), iv: [0; 16], payload_version: 1, payload_len: 0 };
        let decoded = wire::decode::Decoded { header, key: wire::decode::KeyUsed::Device, payload };
        engine.handle(crate::engine::Input::Inform { ts: 50, peer: "x".into(), decoded });
        s.writer.exec(Db::Config, "INSERT INTO devices (mac, name, model, first_seen, last_seen) VALUES ('02:00:00:00:00:02', 'Attic', 'U6', 10, 20)", vec![]);
        assert!(s.writer.flush(std::time::Duration::from_secs(5)));
        let app = router(s);

        let list = get_json(&app, "/api/devices").await;
        assert_eq!((list[0]["name"].as_str(), list[0]["clients"].as_i64(), list[0]["online"].as_bool()), (Some("Hall"), Some(1), Some(true)));
        assert_eq!(list[1], json!({
            "mac": "02:00:00:00:00:02", "name": "Attic", "model": "U6", "model_display": null, "version": null, "ip": null, "online": false,
            "reconfiguring": false, "first_seen": 10, "last_seen": 20, "uptime": null, "cpu": null, "mem": null, "load1": null, "satisfaction": null,
            "clients": 0, "uplink": null, "radios": [], "last_config_push": null, "stored_only": true,
        }));
        let one = get_json(&app, "/api/devices/02:00:00:00:00:01").await;
        assert_eq!((one["clients"][0]["sample"]["hostname"].as_str(), one["locating"].as_bool()), (Some("phone"), Some(false)));
        let stored = get_json(&app, "/api/devices/02:00:00:00:00:02").await;
        assert_eq!((stored["device"]["snapshot"]["ap"]["hostname"].as_str(), stored["device"]["stored_only"].as_bool()), (Some("Attic"), Some(true)));
        let clients = get_json(&app, "/api/clients").await;
        assert_eq!((clients[0]["ap_name"].as_str(), clients[0]["connected"].as_bool(), clients[0]["sample"]["essid"].as_str()), (Some("Hall"), Some(true), Some("Home")));
        assert!(clients[0]["alias"].is_null() && clients[0].get("blocked").is_some(), "{}", clients[0]);
        let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>().join(",");
        assert_eq!(keys(&clients[0]), "alias,ap_name,blocked,connected,first_seen,last_seen,locked_to,note,sample,usergroup_id,vendor");
        let one = get_json(&app, "/api/clients/02:00:00:00:01:01").await;
        assert_eq!(keys(&one), "alias,blocked,connected,first_seen,last_seen,locked_to,note,sample,usergroup_id,vendor", "no ap_name, as before");
        assert_eq!(one["sample"], clients[0]["sample"]);
    }

    async fn get(app: &Router, path: &str) -> Response {
        let req = Request::get(path).header(header::ACCEPT_ENCODING, "gzip").body(Body::empty()).unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn json_is_gzipped_and_the_live_socket_is_not() {
        let (app, _engine) = app();
        let res = get(&app, "/api/status").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::CONTENT_ENCODING).map(|v| v.to_str().unwrap()), Some("gzip"));
        // Not an upgrade request, so refused; but never compressed either.
        let res = get(&app, "/api/ws").await;
        assert!(res.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(get(&app, "/healthz").await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn live_messages_are_serialised_once_for_the_sockets() {
        let (typed, _) = broadcast::channel(16);
        let json = live_json(&typed);
        let mut socket = json.subscribe();
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        typed.send(LiveMsg::Log { device_mac: Some(ap) }).unwrap();
        typed.send(LiveMsg::Device { mac: ap }).unwrap();
        assert_eq!(socket.recv().await.unwrap().as_str(), r#"{"type":"log","device_mac":"02:00:00:00:00:01"}"#);
        assert_eq!(socket.recv().await.unwrap().as_str(), r#"{"type":"device","mac":"02:00:00:00:00:01"}"#);
    }

    #[tokio::test]
    async fn dry_run_reads_stored_pushes_and_history() {
        let (s, _engine) = state();
        let (tx, _) = broadcast::channel(16);
        let mut engine = crate::engine::Engine::new(s.writer.clone(), Default::default(), s.live.clone(), tx);
        let header = inform::Header { packet_version: 0, mac: Mac([0; 6]), flags: inform::Flags(0), iv: [0; 16], payload_version: 1, payload_len: 0 };
        let payload = json!({ "mac": "02:00:00:00:00:01", "hostname": "Hall", "uptime": 100 });
        engine.handle(crate::engine::Input::Inform { ts: 50, peer: "x".into(), decoded: wire::decode::Decoded { header, key: wire::decode::KeyUsed::Device, payload } });
        s.writer.exec(Db::Config, "INSERT INTO device_config (mac, ts, mgmt_cfg, system_cfg) VALUES ('02:00:00:00:00:01', 1, 'a=1', 'b=2')", vec![]);
        s.writer.exec(Db::Config, "INSERT INTO dryrun_results (ts, mac, matches, comparison) VALUES (7, '02:00:00:00:00:01', 1, '{}')", vec![]);
        assert!(s.writer.flush(std::time::Duration::from_secs(5)));
        let app = router(s);
        let d = get_json(&app, "/api/dryrun").await;
        assert_eq!((d["devices"][0]["status"].as_str(), d["history"][0]["ts"].as_i64()), (Some("no_settings"), Some(7)));
    }

    #[tokio::test]
    async fn events_by_kind_prefix_newest_first() {
        let (s, _engine) = state();
        let rows = [
            (1, "client_connected", Some("02:00:00:00:00:01")), (2, "ap_online", Some("02:00:00:00:00:01")), (3, "client_roamed", Some("02:00:00:00:00:02")),
            (4, "client_connected", Some("02:00:00:00:00:02")), (5, "config_pushed", Some("02:00:00:00:00:01")), (6, "client_connected", None),
        ];
        for (ts, kind, dev) in rows {
            s.writer.exec(Db::Config, "INSERT INTO events (ts, kind, device_mac, data) VALUES (?1, ?2, ?3, '{}')", vec![Sql::Integer(ts), Sql::Text(kind.into()), dev.map_or(Sql::Null, |d| Sql::Text(d.into()))]);
        }
        assert!(s.writer.flush(std::time::Duration::from_secs(5)));
        let app = router(s);
        let ts = |v: Value| v.as_array().unwrap().iter().map(|e| e["ts"].as_i64().unwrap()).collect::<Vec<_>>();
        assert_eq!(ts(get_json(&app, "/api/events?kind=client").await), vec![6, 4, 3, 1]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=client&limit=2").await), vec![6, 4]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=CLIENT_CONN,config").await), vec![6, 5, 4, 1], "any case, several prefixes");
        assert_eq!(ts(get_json(&app, "/api/events?kind=client&device=02:00:00:00:00:02").await), vec![4, 3]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=nothing").await), Vec::<i64>::new());
        assert_eq!(ts(get_json(&app, "/api/events?limit=3").await), vec![6, 5, 4]);
    }

    #[tokio::test]
    async fn read_only_mode_keeps_secrets() {
        // No users: read-only, without a login.
        let (app, _engine) = app();
        assert_eq!(get(&app, "/api/status").await.status(), StatusCode::OK);
        assert_eq!(get(&app, "/api/settings/wlans/w1/passphrase").await.status(), StatusCode::FORBIDDEN);
        assert_eq!(get(&app, "/api/backups/file/apctl-0.1.0-20260101-000000.apb").await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn changes_need_the_csrf_header() {
        let (mut state, _engine) = state();
        let file = state.backups.data_dir.join("users");
        std::fs::write(&file, format!("admin:{}\n", crate::auth::hash_password("x").unwrap())).unwrap();
        let users = crate::auth::Users::load(&file).unwrap();
        state.auth = Arc::new(crate::auth::Auth::new(users, &state.store, state.writer.clone(), Default::default()).unwrap());
        let cookie = format!("{}={}", crate::auth::COOKIE, state.auth.create("admin").unwrap());
        let app = router(state);
        let post = |csrf: bool| {
            let mut req = Request::post("/api/alerts/read").header(header::COOKIE, &cookie);
            if csrf {
                req = req.header("x-requested-with", "apctl");
            }
            app.clone().oneshot(req.body(Body::empty()).unwrap())
        };
        assert_eq!(post(false).await.unwrap().status(), StatusCode::FORBIDDEN);
        assert_eq!(post(true).await.unwrap().status(), StatusCode::OK);
        // Reads need no header.
        let req = Request::get("/api/status").header(header::COOKIE, &cookie).body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    /// The app's state with one user, and that user's session cookie.
    fn logged_in() -> (AppState, tokio::sync::mpsc::Receiver<crate::engine::Input>, String) {
        let (mut state, engine) = state();
        let file = state.backups.data_dir.join("users");
        std::fs::write(&file, format!("admin:{}\n", crate::auth::hash_password("x").unwrap())).unwrap();
        state.auth = Arc::new(crate::auth::Auth::new(crate::auth::Users::load(&file).unwrap(), &state.store, state.writer.clone(), Default::default()).unwrap());
        let cookie = format!("{}={}", crate::auth::COOKIE, state.auth.create("admin").unwrap());
        (state, engine, cookie)
    }

    #[tokio::test]
    async fn saved_backup_settings_are_in_effect_at_once() {
        let (state, _engine, cookie) = logged_in();
        let app = router(state);
        let body = json!({ "enabled": false, "frequency": "weekly", "minute_utc": 60, "weekday": 2, "monthday": 1, "keep": 5, "days": 7 });
        let req = Request::put("/api/backups/settings")
            .header(header::COOKIE, &cookie)
            .header("x-requested-with", "apctl")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
        // Read back straight away, before the writer has committed anything.
        let req = Request::get("/api/backups").header(header::COOKIE, &cookie).body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let index: Value = serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap();
        assert_eq!(index["settings"], body);
        assert!(index["next_run"].is_null(), "automatic backups are off");
    }

    #[tokio::test]
    async fn backups_download_with_their_length_and_uncompressed() {
        let (state, _engine, cookie) = logged_in();
        let m = crate::backup::create(&state.backups, &state.backups.data_dir, crate::backup::Kind::Manual, 0).unwrap();
        let raw = std::fs::read(state.backups.dir().join(&m.name)).unwrap();
        let app = router(state);
        let req = Request::get(format!("/api/backups/file/{}", m.name)).header(header::COOKIE, &cookie).header(header::ACCEPT_ENCODING, "gzip").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(res.headers().get(header::CONTENT_LENGTH).map(|v| v.to_str().unwrap().to_string()), Some(raw.len().to_string()));
        assert_eq!(axum::body::to_bytes(res.into_body(), 1 << 24).await.unwrap(), raw);
    }

    #[tokio::test]
    async fn a_panicked_task_is_an_internal_error_without_detail() {
        let e = tokio::task::spawn_blocking(|| panic!("reading /data/config.db")).await.unwrap_err();
        let ApiError(status, msg) = ApiError::from(e);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(msg, INTERNAL);
    }

    #[tokio::test]
    async fn healthz_fails_once_the_engine_has_stopped() {
        let (app, engine) = app();
        assert_eq!(get(&app, "/healthz").await.status(), StatusCode::OK);
        drop(engine); // as when the engine thread panics
        assert_eq!(get(&app, "/healthz").await.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
