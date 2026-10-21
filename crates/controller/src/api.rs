//! HTTP API and live WebSocket for the web UI.

use std::sync::Arc;

use axum::Router;
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use inform::Mac;
use rusqlite::types::Value as Sql;
use rusqlite::params_from_iter;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::clock;
use crate::connections::WEAK_SIGNAL;
use crate::engine::{AliasEdit, ClientView, DeviceView, KnownDevice, Live, LiveMsg, SharedLive};
use crate::model::{ClientSample, Ts};
use crate::series::client_name;
use crate::store::{self, Db, Store};

/// What the handlers share. Cloned for every request (and by some handlers
/// again), so it is one `Arc`: a clone is a single count, and what is kept
/// for the whole process (the insights memo) needs no `Arc` of its own.
#[derive(Clone)]
pub struct AppState(Arc<AppStateInner>);

impl std::ops::Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &AppStateInner {
        &self.0
    }
}

impl AppState {
    pub fn new(inner: AppStateInner) -> Self {
        AppState(Arc::new(inner))
    }

    /// To change a test's state before it is handed out.
    #[cfg(test)]
    pub fn get_mut(&mut self) -> &mut AppStateInner {
        Arc::get_mut(&mut self.0).expect("the state is not shared yet")
    }
}

pub struct AppStateInner {
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
    /// `--inform-url` in active mode (see `ssh::inform_url`).
    pub inform_url: Option<String>,
    /// What the insights views read lately (see `series::memo_read`).
    pub memo: crate::series::Memo,
    /// What the threat checks keep between runs, shared with `threats::watch`.
    pub threats: Arc<crate::threats::ThreatState>,
}

pub fn router(state: AppState) -> Router {
    let public = Router::new()
        // For Kubernetes probes: no login, no data.
        .route("/healthz", get(healthz))
        .route("/api/login", axum::routing::post(crate::auth::login))
        .route("/api/logout", axum::routing::post(crate::auth::logout))
        .route("/api/me", get(crate::auth::me));
    // Routes that hand out secrets: withheld in read-only mode.
    let secret = axum::middleware::from_fn_with_state(state.clone(), crate::auth::withhold_in_read_only);
    let protected = Router::new()
        .route("/api/status", get(status))
        .route("/api/devices", get(devices))
        .route("/api/devices/{mac}", get(device))
        .route("/api/clients", get(clients))
        .route("/api/clients/names", get(client_names))
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
        .route("/api/settings/wlans/{id}/passphrase", get(crate::settings::passphrase).route_layer(secret.clone()))
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
        .route("/api/firmware/resume", axum::routing::post(crate::firmware::resume))
        .route("/api/backups", get(crate::backup::index).post(crate::backup::create_now))
        .route("/api/backups/settings", axum::routing::put(crate::backup::put_settings))
        .route("/api/backups/file/{name}", get(crate::backup::download).delete(crate::backup::delete).route_layer(secret.clone()))
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
        .route("/api/rf/channel-plan", get(crate::channelplan::channel_plan))
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
    let app = public.merge(protected).fallback(crate::web::handler).layer(tower_http::compression::CompressionLayer::new().compress_when(compressible())).merge(socket);
    with_security_headers(app).with_state(state)
}

/// On every answer, the UI's and the API's: no page of another site may frame
/// apctl's (a sibling subdomain gets the session cookie, see `Auth::same_origin`), and no
/// browser guesses a type other than the one sent.
fn with_security_headers(app: Router<AppState>) -> Router<AppState> {
    use axum::http::{HeaderValue, header};
    use tower_http::set_header::SetResponseHeaderLayer;
    let set = |name, value| SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value));
    app.layer(set(header::X_FRAME_OPTIONS, "DENY"))
        .layer(set(header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"))
        .layer(set(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
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
    if s.active { Ok(()) } else { Err(ApiError::conflict(format!("{what} active mode: in shadow mode apctl never talks to the APs"))) }
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

    /// A request that can't be done as asked (400), saying what is wrong with it.
    pub fn bad(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.into())
    }

    /// What the request names isn't there (404).
    pub fn not_found(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::NOT_FOUND, msg.into())
    }

    /// The request clashes with the current state (409): shadow mode, an AP that is away, a run already going.
    pub fn conflict(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::CONFLICT, msg.into())
    }

    /// Not allowed, whoever asks (403).
    pub fn forbidden(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::FORBIDDEN, msg.into())
    }

    /// Needs a (valid) login (401).
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::UNAUTHORIZED, msg.into())
    }

    /// The AP a command is for is offline: queued, it would run whenever the AP is back.
    pub fn ap_offline() -> Self {
        Self::conflict("the AP is offline")
    }

    /// Nothing to work on: no settings were imported yet.
    pub fn no_state() -> Self {
        Self::conflict("no settings imported yet")
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

    /// Records an event. Nothing to tell the caller if the engine has stopped:
    /// the action it describes is done either way.
    pub async fn note(&self, event: crate::engine::Event) {
        let _ = self.engine.send(crate::engine::Input::Note(event)).await;
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

/// A MAC address from the URL or body; 400 when it isn't one.
pub fn parse_mac(s: &str) -> Result<Mac, ApiError> {
    s.parse().map_err(|_| ApiError::bad(format!("invalid MAC {s}")))
}

// axum's extractors answer a malformed request in plain text. These wrap them
// so the UI gets `{"error": ...}` like any other failure, with the same status
// and text. `Json` also stands in for axum's as a response.

/// A JSON request body (and response).
pub struct Json<T>(pub T);

/// A query string.
pub struct Query<T>(pub T);

/// A path parameter.
pub struct Path<T>(pub T);

/// A MAC address path parameter; 400 when it isn't one.
pub struct MacPath(pub Mac);

macro_rules! rejection_to_api_error {
    ($($rejection:ty),*) => {$(
        impl From<$rejection> for ApiError {
            fn from(r: $rejection) -> Self {
                ApiError(r.status(), r.body_text())
            }
        }
    )*};
}

rejection_to_api_error!(JsonRejection, QueryRejection, PathRejection);

impl<T: serde::de::DeserializeOwned, S: Send + Sync> FromRequest<S> for Json<T> {
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, ApiError> {
        Ok(Json(axum::Json::<T>::from_request(req, state).await?.0))
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

impl<T: serde::de::DeserializeOwned, S: Send + Sync> FromRequestParts<S> for Query<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Ok(Query(axum::extract::Query::<T>::from_request_parts(parts, state).await?.0))
    }
}

impl<T: serde::de::DeserializeOwned + Send, S: Send + Sync> FromRequestParts<S> for Path<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Ok(Path(axum::extract::Path::<T>::from_request_parts(parts, state).await?.0))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for MacPath {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let Path(text) = Path::<String>::from_request_parts(parts, state).await?;
        parse_mac(&text).map(MacPath)
    }
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
    // Counted under the lock, serialised after it (the counters are atomics, read as they are then).
    let (counters, devices, devices_online, connected, weak, by_band) = {
        let live = s.live.read().unwrap();
        // The overview's client counters, so that it needs no client list: the
        // connected clients by radio, and how many of them have a weak signal.
        let (mut connected, mut weak, mut by_band) = (0, 0, std::collections::BTreeMap::<&str, usize>::new());
        for (_, c) in live.connected_clients() {
            connected += 1;
            weak += usize::from(c.sample.signal.is_some_and(|s| s < WEAK_SIGNAL));
            if let Some(radio) = c.sample.radio.as_deref() {
                *by_band.entry(radio).or_default() += 1;
            }
        }
        // With the APs known from the database only, as the device list has them.
        let devices = live.devices.len() + stored_only(&live).count();
        let by_band: std::collections::BTreeMap<String, usize> = by_band.into_iter().map(|(radio, n)| (radio.to_string(), n)).collect();
        (live.counters.clone(), devices, live.devices.values().filter(|d| d.online).count(), connected, weak, by_band)
    };
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if s.active { "active" } else { "shadow" },
        "source": s.source,
        "started": s.started,
        "now": clock::now_ts(),
        "counters": &*counters,
        "devices": devices,
        "devices_online": devices_online,
        "clients_connected": connected,
        "clients_by_band": by_band,
        "clients_weak": weak,
        "weak_signal_dbm": WEAK_SIGNAL,
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

/// The APs known from the database only: not reporting since apctl started.
fn stored_only(live: &Live) -> impl Iterator<Item = (&Mac, &KnownDevice)> {
    live.known_devices.iter().filter(|(mac, _)| !live.devices.contains_key(mac))
}

/// An AP known from the database only (see `Live::known_devices`), as a live
/// device view of it, offline: what was not stored is empty.
fn stored_view(mac: Mac, k: &KnownDevice) -> DeviceView {
    let ap = crate::model::ApSample {
        mac, ts: k.last_seen, hostname: k.hostname.clone(), model: k.model.clone(), model_display: k.model_display.clone(), version: k.version.clone(),
        ip: k.ip.clone(), serial: k.serial.clone(), hash_id: None, cfgversion: None, uptime: None, cpu: None, mem: None, load1: None, load5: None,
        load15: None, mem_total: None, mem_used: None, satisfaction: None, num_sta: None,
    };
    DeviceView {
        snapshot: crate::model::Snapshot {
            ap, uplink: None, radios: vec![], vaps: vec![], clients: vec![], has_vap_table: false,
        },
        online: false, first_seen: k.first_seen, last_seen: k.last_seen, peer: None, interval: 0, last_full_inform: 0,
        last_config_push: None,
    }
}

/// Where a device row comes from: an AP reporting in this run, with whether it
/// is blinking to be found, or one known from the database only (`stored_view`).
enum RowSource {
    Live { locating: bool },
    Stored,
}

/// An AP's row in the device list, with `clients` connected to it.
fn device_row(mac: Mac, d: &DeviceView, clients: usize, source: RowSource) -> DeviceRow {
    let (locating, stored_only) = match source {
        RowSource::Live { locating } => (Some(locating), false),
        RowSource::Stored => (None, true),
    };
    let a = &d.snapshot.ap;
    DeviceRow {
        mac, name: a.hostname.clone(), model: a.model.clone(), model_display: a.model_display.clone(), version: a.version.clone(), ip: a.ip.clone(),
        online: d.online, first_seen: d.first_seen, last_seen: d.last_seen, uptime: a.uptime, cpu: a.cpu, mem: a.mem, load1: a.load1,
        satisfaction: a.satisfaction, clients,
        uplink: d.snapshot.uplink.as_ref().map(|u| UplinkRow { speed: u.speed, up: u.up, full_duplex: u.full_duplex }),
        radios: d.snapshot.radios.iter().map(|r| RadioRow {
            radio: r.radio.clone(), channel: r.channel, bw: r.bw, tx_power: r.tx_power, cu_total: r.cu_total, noise_floor: r.noise_floor, clients: r.num_sta,
        }).collect(),
        last_config_push: d.last_config_push, locating, stored_only,
    }
}

/// An AP in the device list.
#[derive(Serialize)]
struct DeviceRow {
    mac: Mac,
    name: Option<String>,
    model: Option<String>,
    model_display: Option<String>,
    version: Option<String>,
    ip: Option<String>,
    online: bool,
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

async fn devices(State(s): State<AppState>) -> Json<Vec<DeviceRow>> {
    // The rows are copied out under the lock (a few short strings each) and
    // serialised after it.
    let list = {
        let live = s.live.read().unwrap();
        // Connected clients per AP, counted in one pass.
        let mut per_ap: std::collections::HashMap<Mac, usize> = std::collections::HashMap::new();
        for (_, c) in live.connected_clients() {
            *per_ap.entry(c.sample.ap_mac).or_default() += 1;
        }
        let mut list: Vec<DeviceRow> =
            live.devices.iter().map(|(mac, d)| device_row(*mac, d, per_ap.get(mac).copied().unwrap_or(0), RowSource::Live { locating: live.locating.contains(mac) })).collect();
        // Then the APs not reporting since apctl started, by MAC as the others.
        let mut stored: Vec<DeviceRow> = stored_only(&live).map(|(mac, k)| device_row(*mac, &stored_view(*mac, k), 0, RowSource::Stored)).collect();
        stored.sort_unstable_by_key(|d| d.mac);
        list.append(&mut stored);
        list
    };
    Json(list)
}

/// An AP's page: its view, its connected clients (without their multicast tables,
/// as the client list sends them), and whether it is blinking to be found.
#[derive(Serialize)]
struct DeviceDetail<'a> {
    device: DeviceOut<'a>,
    clients: Vec<ListedView<'a>>,
    locating: bool,
}

#[derive(Serialize)]
struct DeviceOut<'a> {
    #[serde(flatten)]
    view: &'a DeviceView,
    /// Known from the database only: it has not reported since apctl started.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stored_only: bool,
}

async fn device(State(s): State<AppState>, MacPath(mac): MacPath) -> Result<Response, ApiError> {
    // Copied out under the lock (the clients' samples are shared), and serialised after it.
    let (view, clients, locating, stored_only) = {
        let live = s.live.read().unwrap();
        match (live.devices.get(&mac), live.known_devices.get(&mac)) {
            (Some(d), _) => {
                let clients: Vec<_> = live.connected_clients().map(|(_, c)| c).filter(|c| c.sample.ap_mac == mac).cloned().collect();
                (d.clone(), clients, live.locating.contains(&mac), false)
            }
            // Known but not reporting since apctl started: offline, with what was stored.
            (None, Some(k)) => (stored_view(mac, k), Vec::new(), false, true),
            (None, None) => return Err(ApiError::not_found("unknown device")),
        }
    };
    let clients = clients.iter().map(ListedView::new).collect();
    Ok(Json(DeviceDetail { device: DeviceOut { view: &view, stored_only }, clients, locating }).into_response())
}

/// A client as its page shows it: its view, plus its name, manufacturer and controls.
/// The list sends a smaller view (`ListedView`).
#[derive(Serialize)]
struct ClientRow<'a, V = &'a ClientView> {
    #[serde(flatten)]
    view: V,
    alias: Option<&'a str>,
    note: Option<&'a str>,
    vendor: Option<&'a str>,
    #[serde(flatten)]
    controls: crate::actions::Controls<'a>,
}

/// A client in the client list: as on its page, without the multicast tables, plus the
/// name of the AP it is on.
#[derive(Serialize)]
struct ListedClient<'a> {
    #[serde(flatten)]
    client: ClientRow<'a, ListedView<'a>>,
    /// Null when that AP has no name (see `series::ap_name_of`), or was forgotten.
    ap_name: Option<&'a str>,
}

/// A client's view as the list (and an AP's page) sends it: the sample without its multicast
/// tables, which only the client's own page shows (with the peers in its groups), and without
/// the packet counters, which no list shows, so the list of every client of the past year
/// doesn't carry them.
#[derive(Serialize)]
struct ListedView<'a> {
    sample: ListedSample<'a>,
    connected: bool,
    first_seen: Ts,
    last_seen: Ts,
}

impl<'a> ListedView<'a> {
    fn new(view: &'a ClientView) -> ListedView<'a> {
        // In full, so that a field added to the view is a compile error here rather than missing from the list.
        let ClientView { sample, connected, first_seen, last_seen } = view;
        ListedView { sample: ListedSample(sample), connected: *connected, first_seen: *first_seen, last_seen: *last_seen }
    }
}

/// A sample, serialised as it is without `multicast`, `tx_packets` and `rx_packets`.
struct ListedSample<'a>(&'a ClientSample);

impl Serialize for ListedSample<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // Destructured in full, as above: a new field must be added here too, or left out by name.
        macro_rules! all_but {
            ($($f:ident),*) => {{
                let ClientSample { $($f,)* multicast: _, tx_packets: _, rx_packets: _ } = self.0;
                let mut st = s.serialize_struct("ClientSample", [$(stringify!($f)),*].len())?;
                $(st.serialize_field(stringify!($f), $f)?;)*
                st.end()
            }};
        }
        all_but!(
            mac, ap_mac, bssid, essid, radio, channel, hostname, ip, rssi, signal, noise, tx_rate, rx_rate, tx_bytes, rx_bytes, tx_retries,
            idletime, uptime, satisfaction, anomalies, nss, wifi_gen, vlan_id, latency_avg, is_11r
        )
    }
}

type ClientCopy = (Mac, ClientView, Option<crate::engine::Alias>);

/// Every client: the ones seen in this run and the ones restored from the
/// database at start (`Engine::restore` loads them all, so the live view is
/// the whole list).
async fn clients(State(s): State<AppState>) -> Response {
    // What each client's entry needs, copied under the lock (the samples are
    // shared, the rest is small); the serialising happens after it.
    // The APs' names once each, rather than once per client.
    let (state, list, ap_names) = {
        let live = s.live.read().unwrap();
        let list: Vec<ClientCopy> = live.clients.iter().map(|(mac, c)| (*mac, c.clone(), live.aliases.get(mac).cloned())).collect();
        let aps = live.devices.keys().chain(live.known_devices.keys());
        let ap_names: std::collections::HashMap<Mac, String> = aps.filter_map(|m| Some((*m, crate::series::ap_name_of(&live, m)?))).collect();
        (live.state.clone(), list, ap_names)
    };
    let controls = crate::actions::ClientControls::new(state.as_deref());
    let rows: Vec<ListedClient> = list
        .iter()
        .map(|(mac, view, alias)| ListedClient {
            client: ClientRow {
                view: ListedView::new(view),
                alias: alias.as_ref().and_then(|a| a.alias.as_deref()),
                note: alias.as_ref().and_then(|a| a.note.as_deref()),
                vendor: s.vendors.lookup(mac),
                controls: controls.get(mac),
            },
            ap_name: ap_names.get(&view.sample.ap_mac).map(String::as_str),
        })
        .collect();
    Json(rows).into_response()
}

/// Each named client's display name (its alias, else its hostname) by MAC:
/// what event lists and links show, without the client list's samples.
async fn client_names(State(s): State<AppState>) -> Json<std::collections::HashMap<String, String>> {
    let live = s.live.read().unwrap();
    let names = live
        .clients
        .keys()
        .filter_map(|mac| Some((mac.to_string(), client_name(&live, Some(*mac))?.to_string())))
        .collect();
    Json(names)
}

/// A client's page: its view (with the multicast tables), plus the peers in its multicast groups.
#[derive(Serialize)]
struct ClientPage<'a> {
    #[serde(flatten)]
    client: ClientRow<'a>,
    /// For each group it joined, the other connected clients that joined it too (groups without any are left out).
    peers: std::collections::BTreeMap<String, Vec<Peer>>,
}

/// Another client in a multicast group, by its display name (else its MAC).
#[derive(Serialize)]
struct Peer {
    mac: Mac,
    name: String,
}

/// The other connected clients in each of `groups`, sorted by name: a scan of the connected clients,
/// made only for a client that joined some.
fn multicast_peers(live: &Live, mac: &Mac, groups: &[String]) -> std::collections::BTreeMap<String, Vec<Peer>> {
    let mut by: std::collections::BTreeMap<String, Vec<Peer>> = std::collections::BTreeMap::new();
    if groups.is_empty() {
        return by;
    }
    for (m, c) in live.connected_clients().filter(|(m, _)| *m != mac) {
        let Some(joined) = c.sample.multicast.as_ref().map(|x| &x.memberships) else { continue };
        let mut shared = joined.iter().filter(|g| groups.contains(g)).peekable();
        if shared.peek().is_none() {
            continue;
        }
        let name = client_name(live, Some(*m)).map_or_else(|| m.to_string(), str::to_string);
        for g in shared {
            by.entry(g.clone()).or_default().push(Peer { mac: *m, name: name.clone() });
        }
    }
    for peers in by.values_mut() {
        peers.sort_by_cached_key(|p| p.name.to_lowercase());
    }
    by
}

async fn client(State(s): State<AppState>, MacPath(mac): MacPath) -> Result<Response, ApiError> {
    let (view, alias, state, peers) = {
        let live = s.live.read().unwrap();
        let view = live.clients.get(&mac).cloned().ok_or_else(|| ApiError::not_found("unknown client"))?;
        let peers = multicast_peers(&live, &mac, view.sample.multicast.as_ref().map_or(&[], |m| &m.memberships));
        (view, live.aliases.get(&mac).cloned().unwrap_or_default(), live.state.clone(), peers)
    };
    let row = ClientRow {
        view: &view,
        alias: alias.alias.as_deref(),
        note: alias.note.as_deref(),
        vendor: s.vendors.lookup(&mac),
        controls: crate::actions::controls(state.as_deref(), &mac),
    };
    Ok(Json(ClientPage { client: row, peers }).into_response())
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
    crate::dryrun::validate_state(&state).map_err(|e| ApiError::bad(format!("{e:#}")))?;
    let summary = crate::dryrun::summarize_state(&state);
    s.send(crate::engine::Input::SetState { ts: clock::now_ts(), state }).await?;
    Ok(Json(json!({ "ok": true, "summary": summary })))
}

/// Dry-run status: for each AP, what apctl would push now compared with the last
/// config the other controller pushed; plus the comparisons made at each push.
async fn dryrun(State(s): State<AppState>) -> Result<Json<DryRunStatus>, ApiError> {
    // What each AP's render needs, copied under a short lock: the unredacted
    // config seen in this run when there is one. Only full configs count: a
    // management-only push says nothing about system_cfg (nor, after a restart,
    // one without mgmt_cfg about mgmt_cfg).
    let (state, imported_at, aps) = {
        let live = s.live.read().unwrap();
        let aps: Vec<_> = live
            .devices
            .iter()
            .map(|(mac, d)| {
                let seen = live.last_config.get(mac).filter(|c| c.complete()).cloned();
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
            if let Some(p) = crate::store::stored_push(c, &mac)?.filter(|p| !p.system_cfg.is_empty()) {
                stored.insert(mac, Arc::new(p));
            }
        }
        // Without the diffs' text, which older rows have and the history never shows (only the counts); text that isn't JSON becomes null.
        let mut stmt = c.prepare_cached(
            "SELECT id, ts, mac, cfgversion, matches, CASE WHEN json_valid(comparison) THEN json_remove(comparison, '$.mgmt_cfg.diff', '$.system_cfg.diff') END
             FROM dryrun_results ORDER BY ts DESC LIMIT 100",
        )?;
        let history = stmt
            .query_map([], |r| {
                Ok(DryRunHistory { id: r.get(0)?, ts: r.get(1)?, mac: r.get(2)?, cfgversion: r.get(3)?, matches: r.get(4)?, comparison: raw_json(r.get(5)?) })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((stored, history))
    })
    .await?;

    // The renders run on the blocking pool.
    let renderer = s.renderer.clone();
    let active = s.active;
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
            let settings_stale = settings_stale(active, docs.get(&mac).and_then(|d| d["cfgversion"].as_str()), running_version.as_deref());
            let entry = |status| DryRunDevice { mac, name: name.clone(), status, settings_stale, comparison: None, against_redacted: None, error: None };
            let Some(state) = state.as_deref() else {
                devices.push(entry(DryRunState::NoSettings));
                continue;
            };
            let Some((actual, redacted)) = actual else {
                devices.push(entry(DryRunState::NoConfigSeen));
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
                    let c = crate::dryrun::compare(&ours, &actual.mgmt_cfg, &actual.system_cfg, redacted, true);
                    let status = if c.mgmt_cfg.identical && c.system_cfg.identical {
                        DryRunState::Match
                    } else if c.matches() {
                        DryRunState::Equivalent
                    } else {
                        DryRunState::Differs
                    };
                    devices.push(DryRunDevice { comparison: Some(c), against_redacted: Some(redacted), ..entry(status) });
                }
                Err(e) => devices.push(DryRunDevice { error: Some(format!("{e:#}")), ..entry(DryRunState::Error) }),
            }
        }
        devices
    })
    .await?;
    Ok(Json(DryRunStatus { settings_imported_at: imported_at, devices, history }))
}

/// A comparison made at a push, as stored.
#[derive(Serialize)]
struct DryRunHistory {
    /// The row's id: what the page keys the comparisons by.
    id: i64,
    ts: Ts,
    mac: String,
    cfgversion: Option<String>,
    matches: bool,
    comparison: Option<Box<RawValue>>,
}

#[derive(Serialize)]
struct DryRunStatus {
    settings_imported_at: Option<Ts>,
    devices: Vec<DryRunDevice>,
    history: Vec<DryRunHistory>,
}

/// An AP's dry run now: how what apctl would push compares with what it runs.
/// The imported settings record the cfgversion the other controller expected
/// for each AP at import time. If the AP now runs another one, that controller
/// has pushed new config since: the settings are probably out of date. Never in
/// active mode, where the version an AP runs is apctl's own (see
/// `active::decide_version`) and a re-import would undo apctl's edits.
fn settings_stale(active: bool, imported: Option<&str>, running: Option<&str>) -> bool {
    !active && matches!((imported, running), (Some(a), Some(b)) if a != b)
}

#[derive(Serialize)]
struct DryRunDevice {
    mac: Mac,
    name: Option<String>,
    status: DryRunState,
    /// The AP runs another cfgversion than the imported settings expect.
    settings_stale: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<crate::dryrun::Comparison>,
    /// Compared with the stored copy, whose secrets are masked.
    #[serde(skip_serializing_if = "Option::is_none")]
    against_redacted: Option<bool>,
    /// Why the render failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum DryRunState {
    /// Nothing to render from: no settings imported.
    NoSettings,
    /// No full config pushed to the AP seen yet.
    NoConfigSeen,
    /// Identical configs.
    Match,
    /// The same settings, in other words (see `dryrun::compare`).
    Equivalent,
    Differs,
    Error,
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
        return Err(ApiError::bad(format!("alias longer than {MAX_ALIAS} characters")));
    }
    if note.as_ref().is_some_and(|n| n.chars().count() > MAX_NOTE) {
        return Err(ApiError::bad(format!("note longer than {MAX_NOTE} characters")));
    }
    Ok(())
}

/// Sets (or, with empty values, clears) a client's alias and note.
async fn set_alias(
    State(s): State<AppState>,
    MacPath(mac): MacPath,
    Json(body): Json<AliasBody>,
) -> ApiResult {
    validate(&body.alias, &body.note)?;
    let entries = vec![AliasEdit { mac, alias: body.alias, note: body.note }];
    let input = crate::engine::Input::SetAliases { ts: clock::now_ts(), entries, only_if_unset: false };
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
    let input = crate::engine::Input::SetAliases { ts: clock::now_ts(), entries: parsed, only_if_unset: !q.overwrite };
    s.send(input).await?;
    Ok(Json(json!({ "submitted": n })))
}

#[derive(Deserialize)]
struct SeriesQuery {
    /// Key values in the table's key order, comma-separated (e.g. `mac,radio`).
    key: String,
    /// The numbers wanted, comma-separated (e.g. `cpu,mem`): every one if not given.
    fields: Option<String>,
    from: Option<Ts>,
    to: Option<Ts>,
}

async fn series(State(s): State<AppState>, Path(table): Path<String>, Query(q): Query<SeriesQuery>) -> Result<Json<store::Series>, ApiError> {
    let t = store::table(&table).ok_or_else(|| ApiError::bad(format!("unknown series {table}")))?;
    // A MAC (or BSSID) in any form it is written in is looked up as stored.
    let keys: Vec<String> = q.key.split(',').map(|k| k.parse::<Mac>().map_or_else(|_| k.to_string(), |m| m.to_string())).collect();
    if keys.len() != t.keys.len() {
        return Err(ApiError::bad(format!("{table} needs key {}", t.keys.join(","))));
    }
    let only = q.fields.as_deref().map(|f| t.numbers_named(f)).transpose().map_err(|f| ApiError::bad(format!("{table} has no field {f}")))?;
    // An hour by default. No shortest window: a live chart asks for what is newer than its last sample.
    let (from, to, tier) = crate::series::bounded(q.from, q.to, 3600);
    Ok(Json(read(&s.store, Db::Metrics, move |c| store::series(c, t, &keys, only.as_deref(), from, to, tier)).await?))
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
        let mark = self.param(value);
        self.cond.push(sql.replace('?', &mark));
    }

    /// Adds a parameter, and returns its placeholder (`?N`) for SQL written outside the conditions.
    fn param(&mut self, value: Sql) -> String {
        self.params.push(value);
        format!("?{}", self.params.len())
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
    /// Only the events stored after the one with this id (a list catching up).
    after: Option<i64>,
}

/// A stored JSON column, passed on as stored; text that isn't JSON becomes null.
fn raw_json(text: Option<String>) -> Option<Box<RawValue>> {
    text.and_then(|t| RawValue::from_string(t).ok())
}

#[derive(Serialize)]
struct EventRow {
    id: i64,
    ts: Ts,
    kind: String,
    device_mac: Option<String>,
    client_mac: Option<String>,
    data: Option<Box<RawValue>>,
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

/// A list catching up over at most this many rows (by id) reads them all by id.
const CATCH_UP_SCAN: i64 = 10_000;

/// Whether a list catching up on the rows of `table` stored after `after`
/// reads them by id (the rowid), which visits every row stored since: when
/// there are few. An index on the filters would walk back through every older
/// row when fewer than the limit are new; but over many rows (a list filtered
/// to something rare, whose newest row is old) it serves better, as without
/// `after`, which then only drops the older rows.
fn catch_up_by_id(c: &rusqlite::Connection, table: &str, after: Option<i64>) -> rusqlite::Result<bool> {
    let Some(after) = after else { return Ok(false) };
    let newest: i64 = c.prepare_cached(&format!("SELECT coalesce(max(id), 0) FROM {table}"))?.query_row([], |r| r.get(0))?;
    // Saturating: `after` comes from the client, and i64::MIN would wrap to "few".
    Ok(newest.saturating_sub(after) <= CATCH_UP_SCAN)
}

async fn events(State(s): State<AppState>, Query(q): Query<EventQuery>) -> Result<Json<Vec<EventRow>>, ApiError> {
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
    let after = q.after;
    const COLUMNS: &str = "ts, kind, device_mac, client_mac, data, id";
    let rows = read(&s.store, Db::Config, move |c| {
        let mut kinds: Vec<String> = Vec::new();
        for p in &prefixes {
            kinds.extend(kinds_with_prefix(c, p)?);
        }
        kinds.sort();
        kinds.dedup();
        if !prefixes.is_empty() && kinds.is_empty() {
            return Ok(vec![]);
        }
        let by_id = catch_up_by_id(c, "events", after)?;
        // Bound, as every value is, so that each shape of query is compiled once per connection.
        let limit = w.param(Sql::Integer(limit));
        if let Some(after) = after.filter(|_| !by_id) {
            // Unary plus: not by the rowid range, which would visit every event since.
            w.and("+id > ?", Sql::Integer(after));
        }
        let sql = if let Some(after) = after.filter(|_| by_id) {
            w.and("id > ?", Sql::Integer(after));
            if !kinds.is_empty() {
                let marks: Vec<String> = kinds.into_iter().map(|k| w.param(Sql::Text(k))).collect();
                w.cond.push(format!("kind IN ({})", marks.join(", ")));
            }
            format!("SELECT {COLUMNS} FROM events NOT INDEXED WHERE {} ORDER BY ts DESC, id DESC LIMIT {limit}", w.sql())
        } else if kinds.is_empty() {
            format!("SELECT {COLUMNS} FROM events WHERE {} ORDER BY ts DESC, id DESC LIMIT {limit}", w.sql())
        } else {
            // The newest of each matching kind from the (kind, ts) index, then
            // the newest of those: a rare kind is found without walking every
            // event, and a common one reads no more than the limit.
            let filters = w.sql();
            let parts: Vec<String> = kinds
                .into_iter()
                .map(|k| format!("SELECT * FROM (SELECT {COLUMNS} FROM events WHERE {filters} AND kind = {} ORDER BY ts DESC, id DESC LIMIT {limit})", w.param(Sql::Text(k))))
                .collect();
            format!("{} ORDER BY ts DESC, id DESC LIMIT {limit}", parts.join(" UNION ALL "))
        };
        let mut stmt = c.prepare_cached(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(w.params), |r| {
                Ok(EventRow { id: r.get(5)?, ts: r.get(0)?, kind: r.get(1)?, device_mac: r.get(2)?, client_mac: r.get(3)?, data: raw_json(r.get(4)?) })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct LogQuery {
    device: Option<String>,
    /// Full-text query (SQLite FTS5 syntax).
    q: Option<String>,
    limit: Option<i64>,
    /// Only the lines stored after the one with this id (a list catching up).
    after: Option<i64>,
}

/// The SQL for a log query, newest first; `by_id` as `catch_up_by_id` decides.
fn logs_sql(w: &mut Where, device: Option<Mac>, search: Option<&str>, after: Option<i64>, by_id: bool, limit: i64) -> String {
    const COLUMNS: &str = "l.ts, l.device_mac, l.src_ip, l.facility, l.severity, l.program, l.msg, l.id";
    // Bound, as every value is, so that each shape of query is compiled once per connection.
    let limit = w.param(Sql::Integer(limit));
    if let Some(text) = search {
        // Quote each word so user input cannot break FTS syntax; words are ANDed.
        let fts: Vec<String> = text.split_whitespace().map(|w| format!("\"{}\"", w.replace('"', "\"\""))).collect();
        w.and("logs_fts MATCH ?", Sql::Text(fts.join(" ")));
    }
    if let Some(d) = device {
        w.and("l.device_mac = ?", Sql::Text(d.to_string()));
    }
    if search.is_some() {
        // The newest matches straight from the full-text index, which can
        // stop at the limit (a line's id is its rowid there, and ids rise
        // with time); then in time order, as without a search.
        if let Some(after) = after {
            w.and("logs_fts.rowid > ?", Sql::Integer(after));
        }
        return format!(
            "SELECT * FROM (SELECT {COLUMNS} FROM logs_fts CROSS JOIN logs l ON l.id = logs_fts.rowid WHERE {} ORDER BY logs_fts.rowid DESC LIMIT {limit}) ORDER BY ts DESC, id DESC",
            w.sql()
        );
    }
    // Catching up over few lines, they are read by id (see `catch_up_by_id`);
    // over many, from an index (the unary plus keeps the rowid range out).
    let from = match after {
        Some(after) if by_id => {
            w.and("l.id > ?", Sql::Integer(after));
            "logs l NOT INDEXED"
        }
        Some(after) => {
            w.and("+l.id > ?", Sql::Integer(after));
            "logs l"
        }
        None => "logs l",
    };
    format!("SELECT {COLUMNS} FROM {from} WHERE {} ORDER BY l.ts DESC, l.id DESC LIMIT {limit}", w.sql())
}

/// A stored syslog line.
#[derive(Serialize)]
struct LogRow {
    id: i64,
    ts: Ts,
    device_mac: Option<String>,
    src_ip: Option<String>,
    facility: Option<i64>,
    severity: Option<i64>,
    program: Option<String>,
    msg: String,
}

async fn logs(State(s): State<AppState>, Query(q): Query<LogQuery>) -> Result<Json<Vec<LogRow>>, ApiError> {
    let device = q.device.as_deref().map(parse_mac).transpose()?;
    let search = q.q.as_deref().filter(|t| !t.trim().is_empty());
    let limit = q.limit.unwrap_or(500).clamp(1, 5000);
    let (search, after) = (search.map(str::to_string), q.after);
    let rows = read(&s.store, Db::Logs, move |c| {
        let by_id = search.is_none() && catch_up_by_id(c, "logs", after)?;
        let mut w = Where::default();
        let sql = logs_sql(&mut w, device, search.as_deref(), after, by_id, limit);
        let mut stmt = c.prepare_cached(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(w.params), |r| {
                Ok(LogRow {
                    id: r.get(7)?, ts: r.get(0)?, device_mac: r.get(1)?, src_ip: r.get(2)?, facility: r.get(3)?, severity: r.get(4)?, program: r.get(5)?,
                    msg: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    Ok(Json(rows))
}

async fn ws(
    State(s): State<AppState>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !s.auth.same_origin(&headers, peer.map(|p| p.0.0.ip()), uri.authority().map(|a| a.as_str())) {
        return ApiError::forbidden("the live socket is only for pages of this server").into_response();
    }
    let rx = s.tx.subscribe();
    let (auth, session) = (s.auth.clone(), s.auth.session_of(&headers));
    upgrade.on_upgrade(move |socket| live_socket(socket, rx, auth, session))
}

/// How often an open socket checks that its session is still there.
const SESSION_RECHECK: std::time::Duration = std::time::Duration::from_secs(30);

/// Tells a client that missed messages to refetch rather than dropping it.
const RESYNC: &str = r#"{"type":"resync"}"#;

/// Serialises each live message once, whatever the number of sockets: a task
/// forwards the engine's messages as JSON text to the channel they read.
/// Messages the task itself misses, or fails to serialise, become a resync.
pub fn live_json(typed: &broadcast::Sender<LiveMsg>) -> broadcast::Sender<Utf8Bytes> {
    let (tx, _) = broadcast::channel(4096);
    let mut rx = typed.subscribe();
    let out = tx.clone();
    tokio::spawn(async move {
        loop {
            let text = match rx.recv().await {
                Ok(_) if out.receiver_count() == 0 => continue, // no socket open
                Ok(m) => match serde_json::to_string(&m) {
                    Ok(text) => Utf8Bytes::from(text),
                    // A resync in its place, as for a missed one (an empty frame is no JSON to the page).
                    Err(e) => {
                        tracing::error!("live message not sent: {e}");
                        Utf8Bytes::from_static(RESYNC)
                    }
                },
                Err(broadcast::error::RecvError::Lagged(_)) => Utf8Bytes::from_static(RESYNC),
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let _ = out.send(text);
        }
    });
    tx
}

/// Streams the live messages until the client goes, or its session does:
/// the login is checked at the upgrade, then at every logout and now and
/// then (for expiry). Read-only mode has no sessions to check.
async fn live_socket(mut socket: WebSocket, mut rx: broadcast::Receiver<Utf8Bytes>, auth: crate::auth::SharedAuth, session: Option<String>) {
    let mut recheck = tokio::time::interval_at(tokio::time::Instant::now() + SESSION_RECHECK, SESSION_RECHECK);
    let mut logouts = auth.logouts();
    loop {
        // (The logouts' sender lives in `auth`, which this holds: it never closes.)
        let due = async {
            tokio::select! {
                _ = recheck.tick() => {}
                _ = logouts.changed() => {}
            }
        };
        tokio::select! {
            _ = due, if session.is_some() => {
                if !session.as_deref().is_some_and(|h| auth.alive(h)) {
                    let close = axum::extract::ws::CloseFrame { code: axum::extract::ws::close_code::POLICY, reason: Utf8Bytes::from_static("logged out") };
                    let _ = socket.send(Message::Close(Some(close))).await;
                    return;
                }
            }
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
    use crate::model::tests::{TestDir, flushed};
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

    /// The app's state, the engine's end of its queue (dropping it stops the
    /// "engine"), and the data directory.
    fn state() -> (AppState, tokio::sync::mpsc::Receiver<crate::engine::Input>, TestDir) {
        let dir = TestDir::new("api");
        let (store, writer) = Store::open(&dir).unwrap();
        let auth = Arc::new(crate::auth::Auth::new(Default::default(), &store, writer.clone(), Default::default()).unwrap());
        let (engine, engine_rx) = tokio::sync::mpsc::channel(1);
        let (tx, _) = broadcast::channel(1);
        let state = AppState::new(AppStateInner {
            backups: crate::backup::Backups::new(dir.to_path_buf(), None),
            store, vendors: Default::default(), renderer: crate::dryrun::apcfg_renderer(crate::EMULATE_VERSION.into()), auth, engine, live: Default::default(), tx, started: 0, source: "none".into(),
            active: false, writer, inform_url: None, memo: Default::default(), threats: Default::default(),
        });
        (state, engine_rx, dir)
    }

    fn app() -> (Router, tokio::sync::mpsc::Receiver<crate::engine::Input>, TestDir) {
        let (state, engine, dir) = state();
        (router(state), engine, dir)
    }

    /// An AP's report, decoded, as the engine gets it at time 50.
    fn report(payload: Value) -> crate::engine::Input {
        let header = inform::Header { packet_version: 0, mac: Mac([0; 6]), flags: inform::Flags::NONE, iv: [0; 16], payload_version: 1, payload_len: 0 };
        crate::engine::Input::Inform { ts: 50, peer: [10, 0, 0, 1].into(), decoded: wire::decode::Decoded { header, key: wire::decode::KeyUsed::Device, payload } }
    }

    async fn get_json(app: &Router, path: &str) -> Value {
        let res = app.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn device_and_client_lists() {
        let (s, _engine, _dir) = state();
        // One AP reporting with a client, one only in the database.
        let (tx, _) = broadcast::channel(16);
        let mut engine = crate::engine::Engine::new(s.writer.clone(), Default::default(), s.live.clone(), tx);
        let payload = json!({ "mac": "02:00:00:00:00:01", "hostname": "Hall", "uptime": 100, "vap_table": [
            { "bssid": "b1", "essid": "Home", "radio": "na", "channel": 36, "usage": "user", "sta_table": [{ "mac": "02:00:00:00:01:01", "hostname": "phone" }] },
        ] });
        // The one in the database is restored as at start, before any inform.
        s.writer.exec(Db::Config, "INSERT INTO devices (mac, hostname, model, first_seen, last_seen) VALUES ('02:00:00:00:00:02', 'Attic', 'U6', 10, 20)", vec![]);
        s.writer.exec(Db::Config, "INSERT INTO clients (mac, first_seen, last_seen, ap_mac, bssid) VALUES ('02:00:00:00:01:02', 10, 20, '02:00:00:00:00:02', 'b2')", vec![]);
        flushed(&s.writer);
        engine.restore(&s.store).unwrap();
        engine.handle(report(payload));
        let app = router(s);

        let list = get_json(&app, "/api/devices").await;
        assert_eq!((list[0]["name"].as_str(), list[0]["clients"].as_i64(), list[0]["online"].as_bool()), (Some("Hall"), Some(1), Some(true)));
        assert_eq!(list[1], json!({
            "mac": "02:00:00:00:00:02", "name": "Attic", "model": "U6", "model_display": null, "version": null, "ip": null, "online": false,
            "first_seen": 10, "last_seen": 20, "uptime": null, "cpu": null, "mem": null, "load1": null, "satisfaction": null,
            "clients": 0, "uplink": null, "radios": [], "last_config_push": null, "stored_only": true,
        }));
        let status = get_json(&app, "/api/status").await;
        assert_eq!((status["devices"].as_i64(), status["devices_online"].as_i64()), (Some(2), Some(1)), "the stored AP counted, offline");
        let one = get_json(&app, "/api/devices/02:00:00:00:00:01").await;
        assert_eq!((one["clients"][0]["sample"]["hostname"].as_str(), one["locating"].as_bool()), (Some("phone"), Some(false)));
        let stored = get_json(&app, "/api/devices/02:00:00:00:00:02").await;
        assert_eq!((stored["device"]["snapshot"]["ap"]["hostname"].as_str(), stored["device"]["stored_only"].as_bool()), (Some("Attic"), Some(true)));
        // A stored AP is shaped like a live one, with only stored_only added.
        let sorted = |v: &Value| {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        for path in ["", "/device", "/device/snapshot", "/device/snapshot/ap"] {
            let mut live = sorted(one.pointer(path).unwrap());
            if path == "/device" {
                live.push("stored_only".into());
                live.sort();
            }
            assert_eq!(sorted(stored.pointer(path).unwrap()), live, "{path}");
        }
        assert_eq!(stored["device"]["snapshot"]["ap"]["mac"], "02:00:00:00:00:02");
        // The snapshot's clients come beside it; its neighbours and spectrum are the RF pages'.
        assert_eq!(sorted(&one["device"]["snapshot"]), ["ap", "has_vap_table", "radios", "uplink", "vaps"]);
        let clients = get_json(&app, "/api/clients").await;
        assert_eq!((clients[0]["ap_name"].as_str(), clients[0]["connected"].as_bool(), clients[0]["sample"]["essid"].as_str()), (Some("Hall"), Some(true), Some("Home")));
        assert!(clients[0]["alias"].is_null() && clients[0].get("blocked").is_some(), "{}", clients[0]);
        // A client of the AP not reporting since the start: the AP by its stored name.
        assert_eq!((clients[1]["ap_name"].as_str(), clients[1]["connected"].as_bool()), (Some("Attic"), Some(false)));
        let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>().join(",");
        assert_eq!(keys(&clients[0]), "alias,ap_name,blocked,connected,first_seen,last_seen,locked_to,note,sample,usergroup_id,vendor");
        let one = get_json(&app, "/api/clients/02:00:00:00:01:01").await;
        assert_eq!(keys(&one), "alias,blocked,connected,first_seen,last_seen,locked_to,note,peers,sample,usergroup_id,vendor", "no ap_name, as before");
        // The list's sample is the page's without the multicast tables and the packet counters.
        let mut page_sample = one["sample"].clone();
        for k in ["multicast", "tx_packets", "rx_packets"] {
            assert!(page_sample.as_object_mut().unwrap().remove(k).is_some(), "{k}");
        }
        assert_eq!(page_sample, clients[0]["sample"]);
        assert_eq!(one["peers"], json!({}));
        assert_eq!(get_json(&app, "/api/clients/names").await, json!({ "02:00:00:00:01:01": "phone" }));
        let status = get_json(&app, "/api/status").await;
        assert_eq!((&status["clients_connected"], &status["clients_by_band"], &status["clients_weak"]), (&json!(1), &json!({ "na": 1 }), &json!(0)));
        assert_eq!(status["weak_signal_dbm"], -75, "the threshold the count uses, for its label");
    }

    #[tokio::test]
    async fn a_clients_page_lists_its_multicast_peers_and_the_lists_have_no_multicast() {
        let (s, _engine, _dir) = state();
        let (tx, _) = broadcast::channel(16);
        let mut engine = crate::engine::Engine::new(s.writer.clone(), Default::default(), s.live.clone(), tx);
        let joined = |groups: &[&str]| json!({ "types": {}, "memberships": groups.iter().map(|g| json!({ "group_ip": g })).collect::<Vec<_>>() });
        let (ssdp, mdns) = ("239.255.255.250", "224.0.0.251");
        let payload = json!({ "mac": "02:00:00:00:00:01", "hostname": "Hall", "uptime": 100, "vap_table": [
            { "bssid": "b1", "essid": "Home", "radio": "na", "channel": 36, "usage": "user", "sta_table": [
                { "mac": "02:00:00:00:01:01", "hostname": "tv", "multicast": joined(&[ssdp, mdns]) },
                { "mac": "02:00:00:00:01:02", "hostname": "Speaker", "multicast": joined(&[ssdp]) },
                { "mac": "02:00:00:00:01:03", "hostname": "amp", "multicast": joined(&[ssdp]) },
                { "mac": "02:00:00:00:01:04", "multicast": joined(&[mdns]) },
                { "mac": "02:00:00:00:01:05", "hostname": "gone", "multicast": joined(&[ssdp, mdns]) },
                { "mac": "02:00:00:00:01:06", "hostname": "laptop" },
            ] },
        ] });
        engine.handle(report(payload));
        s.live.write().unwrap().clients.get_mut(&"02:00:00:00:01:05".parse().unwrap()).unwrap().connected = false;
        let app = router(s);

        let list = get_json(&app, "/api/clients").await;
        assert_eq!(list.as_array().unwrap().len(), 6);
        assert!(list.as_array().unwrap().iter().all(|c| c["sample"].get("multicast").is_none() && c["sample"]["essid"] == "Home"), "{list}");
        // Nor does the AP's page list its clients with them.
        let ap = get_json(&app, "/api/devices/02:00:00:00:00:01").await["clients"].clone();
        assert_eq!(ap.as_array().unwrap().len(), 5, "the connected ones");
        assert!(ap.as_array().unwrap().iter().all(|c| c["sample"].get("multicast").is_none() && c["sample"]["essid"] == "Home" && c["connected"] == true), "{ap}");
        // The other connected clients in each group, by name (else MAC); not the client itself, nor one that left.
        let tv = get_json(&app, "/api/clients/02:00:00:00:01:01").await;
        assert_eq!(tv["sample"]["multicast"]["memberships"], json!([ssdp, mdns]));
        assert_eq!(tv["peers"], json!({
            mdns: [{ "mac": "02:00:00:00:01:04", "name": "02:00:00:00:01:04" }],
            ssdp: [{ "mac": "02:00:00:00:01:03", "name": "amp" }, { "mac": "02:00:00:00:01:02", "name": "Speaker" }],
        }));
        let speaker = get_json(&app, "/api/clients/02:00:00:00:01:02").await;
        assert_eq!(speaker["peers"], json!({ ssdp: [{ "mac": "02:00:00:00:01:03", "name": "amp" }, { "mac": "02:00:00:00:01:01", "name": "tv" }] }));
        // A client that joined no group has no peers, and one that left still sees who is in its groups.
        assert_eq!(get_json(&app, "/api/clients/02:00:00:00:01:06").await["peers"], json!({}));
        let gone = get_json(&app, "/api/clients/02:00:00:00:01:05").await;
        assert_eq!(gone["peers"][mdns], json!([{ "mac": "02:00:00:00:01:04", "name": "02:00:00:00:01:04" }, { "mac": "02:00:00:00:01:01", "name": "tv" }]));
    }

    async fn get(app: &Router, path: &str) -> Response {
        let req = Request::get(path).header(header::ACCEPT_ENCODING, "gzip").body(Body::empty()).unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn json_is_gzipped_and_the_live_socket_is_not() {
        let (app, _engine, _dir) = app();
        let res = get(&app, "/api/status").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::CONTENT_ENCODING).map(|v| v.to_str().unwrap()), Some("gzip"));
        // Not an upgrade request, so refused; but never compressed either.
        let res = get(&app, "/api/ws").await;
        assert!(res.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(get(&app, "/healthz").await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn no_answer_can_be_framed_or_sniffed() {
        let (app, _engine, _dir) = app();
        // The API, an API error, the UI (or its 404 when unbuilt), the live socket's refusal.
        for path in ["/api/status", "/api/nope", "/", "/clients", "/api/ws", "/healthz"] {
            let res = get(&app, path).await;
            let h = |name| res.headers().get(name).map(|v: &axum::http::HeaderValue| v.to_str().unwrap().to_string());
            assert_eq!(h(header::X_FRAME_OPTIONS).as_deref(), Some("DENY"), "{path}");
            assert_eq!(h(header::CONTENT_SECURITY_POLICY).as_deref(), Some("frame-ancestors 'none'"), "{path}");
            assert_eq!(h(header::X_CONTENT_TYPE_OPTIONS).as_deref(), Some("nosniff"), "{path}");
        }
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
        let (s, _engine, _dir) = state();
        let (tx, _) = broadcast::channel(16);
        let mut engine = crate::engine::Engine::new(s.writer.clone(), Default::default(), s.live.clone(), tx);
        engine.handle(report(json!({ "mac": "02:00:00:00:00:01", "hostname": "Hall", "uptime": 100 })));
        s.writer.exec(Db::Config, "INSERT INTO device_config (mac, ts, mgmt_cfg, system_cfg) VALUES ('02:00:00:00:00:01', 1, 'a=1', 'b=2')", vec![]);
        let stored = r#"{"mgmt_cfg":{"added":0,"diff":"- a=1"},"system_cfg":{"added":1,"removed":0,"changed":0,"identical":false,"diff":"+ c=3"}}"#;
        s.writer.exec(Db::Config, "INSERT INTO dryrun_results (ts, mac, matches, comparison) VALUES (7, '02:00:00:00:00:01', 0, ?1)", vec![Sql::Text(stored.into())]);
        s.writer.exec(Db::Config, "INSERT INTO dryrun_results (ts, mac, matches, comparison) VALUES (6, '02:00:00:00:00:01', 0, 'not json')", vec![]);
        flushed(&s.writer);
        let app = router(s);
        let d = get_json(&app, "/api/dryrun").await;
        assert_eq!((d["devices"][0]["status"].as_str(), d["history"][0]["ts"].as_i64(), d["history"][0]["id"].as_i64()), (Some("no_settings"), Some(7), Some(1)));
        // The history's comparisons come without the diffs' text.
        assert_eq!(d["history"][0]["comparison"], json!({ "mgmt_cfg": { "added": 0 }, "system_cfg": { "added": 1, "removed": 0, "changed": 0, "identical": false } }));
        assert_eq!(d["history"][1]["comparison"], Value::Null);
        assert_eq!(d["devices"][0], json!({ "mac": "02:00:00:00:00:01", "name": "Hall", "status": "no_settings", "settings_stale": false }));
    }

    #[test]
    fn imported_settings_are_stale_only_in_shadow_mode() {
        assert!(settings_stale(false, Some("a"), Some("b")));
        assert!(!settings_stale(false, Some("a"), Some("a")) && !settings_stale(false, None, Some("b")) && !settings_stale(false, Some("a"), None));
        assert!(!settings_stale(true, Some("a"), Some("b")), "in active mode the AP runs apctl's version");
    }

    #[tokio::test]
    async fn a_series_key_matches_any_form_of_a_mac() {
        let (s, _engine, _dir) = state();
        let at = clock::now_ts() - 60;
        s.writer.exec(Db::Metrics, "INSERT INTO radio_stats (mac, radio, ts, cu_total) VALUES ('02:00:00:00:00:0a', 'na', ?1, 40)", vec![Sql::Integer(at)]);
        flushed(&s.writer);
        let app = router(s);
        for key in ["02:00:00:00:00:0a", "02-00-00-00-00-0A", "02000000000A"] {
            let got = get_json(&app, &format!("/api/series/radio_stats?key={key},na&fields=cu_total")).await;
            assert_eq!(got["ts"], json!([at]), "{key}");
        }
    }

    #[tokio::test]
    async fn events_by_kind_prefix_newest_first() {
        let (s, _engine, _dir) = state();
        let rows = [
            (1, "client_connected", Some("02:00:00:00:00:01")), (2, "ap_online", Some("02:00:00:00:00:01")), (3, "client_roamed", Some("02:00:00:00:00:02")),
            (4, "client_connected", Some("02:00:00:00:00:02")), (5, "config_pushed", Some("02:00:00:00:00:01")), (6, "client_connected", None),
        ];
        for (ts, kind, dev) in rows {
            s.writer.exec(Db::Config, "INSERT INTO events (ts, kind, device_mac, data) VALUES (?1, ?2, ?3, '{}')", vec![Sql::Integer(ts), Sql::Text(kind.into()), dev.map_or(Sql::Null, |d| Sql::Text(d.into()))]);
        }
        flushed(&s.writer);
        let writer = s.writer.clone();
        let app = router(s);
        let ts = |v: Value| v.as_array().unwrap().iter().map(|e| e["ts"].as_i64().unwrap()).collect::<Vec<_>>();
        assert_eq!(ts(get_json(&app, "/api/events?kind=client").await), vec![6, 4, 3, 1]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=client&limit=2").await), vec![6, 4]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=CLIENT_CONN,config").await), vec![6, 5, 4, 1], "any case, several prefixes");
        assert_eq!(ts(get_json(&app, "/api/events?kind=client&device=02:00:00:00:00:02").await), vec![4, 3]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=nothing").await), Vec::<i64>::new());
        assert_eq!(ts(get_json(&app, "/api/events?limit=3").await), vec![6, 5, 4]);
        // Catching up: only what was stored after a given event (here the ids follow the times).
        assert_eq!(ts(get_json(&app, "/api/events?after=4").await), vec![6, 5]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=client&after=3").await), vec![6, 4]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=client&device=02:00:00:00:00:02&after=1").await), vec![4, 3]);
        assert_eq!(ts(get_json(&app, "/api/events?after=6").await), Vec::<i64>::new());
        assert_eq!(ts(get_json(&app, &format!("/api/events?after={}&limit=2", i64::MIN)).await), vec![6, 5], "the oldest id there is: everything");
        // Catching up over more rows than are read by id: from the filters' indexes, the same rows.
        writer.exec(Db::Config, "INSERT INTO events (id, ts, kind, device_mac, data) VALUES (?1, 7, 'client_connected', '02:00:00:00:00:02', '{}')", vec![Sql::Integer(CATCH_UP_SCAN + 10)]);
        flushed(&writer);
        assert_eq!(ts(get_json(&app, "/api/events?after=4").await), vec![7, 6, 5]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=client&after=3").await), vec![7, 6, 4]);
        assert_eq!(ts(get_json(&app, "/api/events?device=02:00:00:00:00:02&after=3").await), vec![7, 4]);
        assert_eq!(ts(get_json(&app, "/api/events?kind=client&device=02:00:00:00:00:02&after=1").await), vec![7, 4, 3]);
        assert_eq!(get_json(&app, "/api/events?limit=1").await[0]["data"], json!({}), "the stored payload, as stored");
    }

    #[tokio::test]
    async fn logs_search_and_catch_up() {
        let (s, _engine, _dir) = state();
        let lines = [(1, "02:00:00:00:00:01", "hostapd", "wlan0: STA joined"), (2, "02:00:00:00:00:02", "kernel", "eth0 link up"), (3, "02:00:00:00:00:01", "hostapd", "wlan1: STA left")];
        for (ts, mac, program, msg) in lines {
            let sql = "INSERT INTO logs (ts, device_mac, program, msg) VALUES (?1, ?2, ?3, ?4)";
            s.writer.exec(Db::Logs, sql, vec![Sql::Integer(ts), Sql::Text(mac.into()), Sql::Text(program.into()), Sql::Text(msg.into())]);
        }
        flushed(&s.writer);
        // A search is read from the full-text index, newest first, and stops at the limit.
        let mut w = Where::default();
        let sql = logs_sql(&mut w, None, Some("sta"), None, false, 10);
        assert!(sql.contains("LIMIT ?1)") && w.params[0] == Sql::Integer(10), "the limit is bound, as every value: {sql}");
        let plan: Vec<String> = s
            .store
            .read(Db::Logs, |c| Ok(c.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?.query_map(params_from_iter(w.params), |r| r.get(3))?.collect::<rusqlite::Result<_>>()?))
            .unwrap();
        assert!(plan.iter().any(|p| p.starts_with("SCAN logs_fts VIRTUAL TABLE")) && plan.iter().any(|p| p.starts_with("SEARCH l USING INTEGER PRIMARY KEY")), "{plan:?}");
        // Only the limited rows are sorted by time, after the index's own order.
        assert_eq!(plan.iter().filter(|p| p.contains("TEMP B-TREE")).count(), 1, "{plan:?}");
        assert!(plan.last().is_some_and(|p| p == "USE TEMP B-TREE FOR ORDER BY") && plan.iter().any(|p| p.starts_with("SCAN (subquery")), "{plan:?}");
        // Catching up a device's lines over many rows: from its index, not every line since.
        let plan = |by_id| {
            let mut w = Where::default();
            let sql = logs_sql(&mut w, Some("02:00:00:00:00:02".parse().unwrap()), None, Some(1), by_id, 10);
            s.store.read(Db::Logs, |c| Ok(c.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?.query_map(params_from_iter(w.params), |r| r.get::<_, String>(3))?.collect::<rusqlite::Result<Vec<_>>>()?)).unwrap()
        };
        assert_eq!(plan(false), ["SEARCH l USING INDEX logs_device (device_mac=?)"]);
        assert!(plan(true)[0].starts_with("SEARCH l USING INTEGER PRIMARY KEY (rowid>?)"), "{:?}", plan(true));
        let (writer, s_store) = (s.writer.clone(), s.store.clone());
        let app = router(s);
        let ts = |v: Value| v.as_array().unwrap().iter().map(|e| e["ts"].as_i64().unwrap()).collect::<Vec<_>>();
        assert_eq!(ts(get_json(&app, "/api/logs").await), vec![3, 2, 1]);
        assert_eq!(ts(get_json(&app, "/api/logs?q=sta").await), vec![3, 1]);
        assert_eq!(ts(get_json(&app, "/api/logs?q=sta&limit=1").await), vec![3]);
        assert_eq!(ts(get_json(&app, "/api/logs?q=STA%20joined").await), vec![1], "words are ANDed");
        assert_eq!(ts(get_json(&app, "/api/logs?q=sta&after=1").await), vec![3]);
        assert_eq!(ts(get_json(&app, "/api/logs?after=1").await), vec![3, 2]);
        assert_eq!(ts(get_json(&app, "/api/logs?after=1&device=02:00:00:00:00:02").await), vec![2]);
        assert_eq!(ts(get_json(&app, "/api/logs?q=link&device=02:00:00:00:00:01").await), Vec::<i64>::new());
        let line = json!({
            "id": 3, "ts": 3, "device_mac": "02:00:00:00:00:01", "src_ip": null, "facility": null, "severity": null, "program": "hostapd", "msg": "wlan1: STA left",
        });
        assert_eq!(get_json(&app, "/api/logs?limit=1").await, json!([line]));
        // Catching up over more rows than are read by id: from the indexes, the same lines.
        writer.exec(Db::Logs, "INSERT INTO logs (id, ts, device_mac, msg) VALUES (?1, 4, '02:00:00:00:00:02', 'eth0 link down')", vec![Sql::Integer(CATCH_UP_SCAN + 10)]);
        flushed(&writer);
        assert_eq!(ts(get_json(&app, "/api/logs?after=1&device=02:00:00:00:00:02").await), vec![4, 2]);
        assert_eq!(ts(get_json(&app, "/api/logs?after=2").await), vec![4, 3]);
        assert_eq!(ts(get_json(&app, &format!("/api/logs?after={}&limit=2", i64::MIN)).await), vec![4, 3]);
        // Far behind: from the indexes, not by id.
        let by_id = |after| s_store.read(Db::Logs, move |c| Ok(catch_up_by_id(c, "logs", Some(after))?)).unwrap();
        assert_eq!((by_id(i64::MIN), by_id(-1), by_id(CATCH_UP_SCAN + 9), by_id(i64::MAX)), (false, false, true, true));
    }

    #[tokio::test]
    async fn read_only_mode_keeps_secrets() {
        // No users: read-only, without a login.
        let (app, _engine, _dir) = app();
        assert_eq!(get(&app, "/api/status").await.status(), StatusCode::OK);
        assert_eq!(get(&app, "/api/settings/wlans/w1/passphrase").await.status(), StatusCode::FORBIDDEN);
        assert_eq!(get(&app, "/api/backups/file/apctl-0.1.0-20260101-000000.apb").await.status(), StatusCode::FORBIDDEN);
        // With a login they are served (here: there are no settings yet).
        let (state, _engine, cookie, _dir) = logged_in();
        let req = Request::get("/api/settings/wlans/w1/passphrase").header(header::COOKIE, cookie).body(Body::empty()).unwrap();
        assert_eq!(router(state).oneshot(req).await.unwrap().status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn changes_need_the_csrf_header() {
        let (state, _engine, cookie, _dir) = logged_in();
        let app = router(state);
        let post = |csrf: bool| {
            let mut req = Request::post("/api/alerts/read").header(header::COOKIE, &cookie);
            if csrf {
                req = req.header("x-requested-with", "apctl");
            }
            app.clone().oneshot(req.body(Body::empty()).unwrap())
        };
        let refused = post(false).await.unwrap();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let body: Value = serde_json::from_slice(&axum::body::to_bytes(refused.into_body(), 1 << 16).await.unwrap()).unwrap();
        assert_eq!(body, json!({ "error": "missing X-Requested-With: apctl header" }));
        assert_eq!(post(true).await.unwrap().status(), StatusCode::OK);
        // Reads need no header.
        let req = Request::get("/api/status").header(header::COOKIE, &cookie).body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_malformed_request_is_answered_in_json() {
        let (state, _engine, cookie, _dir) = logged_in();
        let app = router(state);
        let error = |res: Response| async move {
            let status = res.status();
            let body: Value = serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 16).await.unwrap()).unwrap();
            (status, body["error"].as_str().unwrap_or_else(|| panic!("no error in {body}")).to_string())
        };
        let get = |path: &str| app.clone().oneshot(Request::get(path).header(header::COOKIE, &cookie).body(Body::empty()).unwrap());
        assert_eq!(error(get("/api/devices/nope").await.unwrap()).await, (StatusCode::BAD_REQUEST, "invalid MAC nope".into()));
        let (status, msg) = error(get("/api/series/clients?from=soon").await.unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.starts_with("Failed to deserialize query string"), "{msg}");
        let (status, msg) = error(get("/api/series/ap_stats?key=02:00:00:00:00:01&fields=cpu,nope").await.unwrap()).await;
        assert_eq!((status, msg.as_str()), (StatusCode::BAD_REQUEST, "ap_stats has no field nope"));
        let (status, msg) = error(get("/api/site/activity?mac=02:00:00:00:00").await.unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "not an empty chart: {msg}");
        let put = |content_type: &str, body: &'static str| {
            let req = Request::put("/api/clients/02:00:00:00:01:01/alias").header(header::COOKIE, &cookie).header("x-requested-with", "apctl").header(header::CONTENT_TYPE, content_type);
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };
        let (status, msg) = error(put("application/json", "{\"alias\":").await.unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.starts_with("Failed to parse the request body as JSON"), "{msg}");
        let (status, msg) = error(put("text/plain", "{}").await.unwrap()).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "the rejection's own status: {msg}");
        let (status, _) = error(put("application/json", "{\"alias\": 5}").await.unwrap()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// The app's state with one user, that user's session cookie, and the data directory.
    fn logged_in() -> (AppState, tokio::sync::mpsc::Receiver<crate::engine::Input>, String, TestDir) {
        logged_in_behind(&[])
    }

    /// As `logged_in`, with these trusted proxies.
    fn logged_in_behind(proxies: &[&str]) -> (AppState, tokio::sync::mpsc::Receiver<crate::engine::Input>, String, TestDir) {
        let (mut state, engine, dir) = state();
        let file = state.backups.data_dir.join("users");
        std::fs::write(&file, format!("admin:{}\n", crate::auth::hash_password("x").unwrap())).unwrap();
        let proxies = Arc::new(crate::auth::Proxies::parse(&proxies.iter().map(|p| p.to_string()).collect::<Vec<_>>()).unwrap());
        state.get_mut().auth = Arc::new(crate::auth::Auth::new(crate::auth::Users::load(&file).unwrap(), &state.store, state.writer.clone(), proxies).unwrap());
        let cookie = format!("{}={}", crate::auth::COOKIE, state.auth.create("admin"));
        (state, engine, cookie, dir)
    }

    #[tokio::test]
    async fn saved_backup_settings_are_in_effect_at_once() {
        let (state, _engine, cookie, _dir) = logged_in();
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
        let (state, _engine, cookie, _dir) = logged_in();
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
    async fn the_live_socket_checks_the_origin_and_closes_at_logout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (state, _engine, cookie, _dir) = logged_in();
        let app = router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = app.clone().into_make_service_with_connect_info::<std::net::SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
        // A handshake by hand: the status line, and the open connection.
        let open = |origin: Option<String>| {
            let cookie = cookie.clone();
            async move {
                let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
                let origin = origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default();
                let req = format!(
                    "GET /api/ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCookie: {cookie}\r\n{origin}\r\n"
                );
                tcp.write_all(req.as_bytes()).await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    tcp.read_exact(&mut b).await.unwrap();
                    head.push(b[0]);
                }
                let status = String::from_utf8(head).unwrap().split(' ').nth(1).unwrap().to_string();
                (status, tcp)
            }
        };
        assert_eq!(open(Some("http://evil.example".into())).await.0, "403");
        assert_eq!(open(None).await.0, "101", "no Origin: not a browser page");
        let (status, mut tcp) = open(Some(format!("http://{addr}"))).await;
        assert_eq!(status, "101");
        let logout = |csrf: bool| {
            let req = Request::post("/api/logout").header(header::COOKIE, &cookie);
            app.clone().oneshot(if csrf { req.header("x-requested-with", "apctl") } else { req }.body(Body::empty()).unwrap())
        };
        // Another site cannot log the visitor out.
        assert_eq!(logout(false).await.unwrap().status(), StatusCode::FORBIDDEN);
        assert_eq!(open(None).await.0, "101", "still logged in");
        assert_eq!(logout(true).await.unwrap().status(), StatusCode::OK);
        let mut frame = [0u8; 2];
        tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_exact(&mut frame)).await.expect("closed at the logout").unwrap();
        assert_eq!(frame[0], 0x88, "a close frame");
    }

    #[tokio::test]
    async fn a_session_cookie_planted_before_ours_does_not_lock_the_user_out() {
        let (state, _engine, cookie, _dir) = logged_in();
        let app = router(state);
        // As a sibling subdomain can set it: for the parent domain, sent first.
        let both = format!("{}=planted; {cookie}", crate::auth::COOKIE);
        let send = |req: axum::http::request::Builder| app.clone().oneshot(req.header(header::COOKIE, &both).body(Body::empty()).unwrap());
        assert_eq!(send(Request::get("/api/status")).await.unwrap().status(), StatusCode::OK);
        let me = send(Request::get("/api/me")).await.unwrap();
        let me: Value = serde_json::from_slice(&axum::body::to_bytes(me.into_body(), 1 << 16).await.unwrap()).unwrap();
        assert_eq!(me["user"], "admin");
        // A logout ends the valid session among them.
        assert_eq!(send(Request::post("/api/logout").header("x-requested-with", "apctl")).await.unwrap().status(), StatusCode::OK);
        assert_eq!(send(Request::get("/api/status")).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_session_used_a_day_later_gets_its_cookie_again() {
        let (state, _engine, cookie, _dir) = logged_in_behind(&["10.42.0.0/16"]);
        let token = cookie.split_once('=').unwrap().1;
        let auth = state.auth.clone();
        let app = router(state);
        let from = |peer: &str, path: &'static str| {
            let peer = axum::extract::ConnectInfo(std::net::SocketAddr::new(peer.parse().unwrap(), 40000));
            let req = Request::get(path).header(header::COOKIE, &cookie).header("x-forwarded-proto", "https").extension(peer).body(Body::empty()).unwrap();
            let app = app.clone();
            async move {
                let res = app.oneshot(req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                res.headers().get(header::SET_COOKIE).map(|v| v.to_str().unwrap().to_string())
            }
        };
        const PROXY: &str = "10.42.0.3";
        assert_eq!(from(PROXY, "/api/status").await, None, "fresh from the login");
        for path in ["/api/status", "/api/me"] {
            auth.age_session(token, 2 * 86400);
            let c = from(PROXY, path).await.unwrap_or_else(|| panic!("{path}: no cookie"));
            assert!(c.starts_with(&format!("{}={token};", crate::auth::COOKIE)) && c.contains("Max-Age=2592000") && c.ends_with("; Secure"), "{c}");
            assert_eq!(from(PROXY, path).await, None, "{path}: once a day");
        }
        // X-Forwarded-Proto is believed only from a trusted proxy.
        auth.age_session(token, 2 * 86400);
        let c = from("192.168.1.20", "/api/status").await.unwrap();
        assert!(c.contains("Max-Age=2592000") && !c.contains("Secure"), "{c}");
    }

    #[tokio::test]
    async fn healthz_fails_once_the_engine_has_stopped() {
        let (app, engine, _dir) = app();
        assert_eq!(get(&app, "/healthz").await.status(), StatusCode::OK);
        drop(engine); // as when the engine thread panics
        assert_eq!(get(&app, "/healthz").await.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
