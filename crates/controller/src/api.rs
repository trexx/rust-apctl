//! HTTP API and live WebSocket for the web UI.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use inform::Mac;
use rusqlite::types::Value as Sql;
use rusqlite::params_from_iter;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::engine::{LiveMsg, SharedLive};
use crate::model::Ts;
use crate::store::{self, Db, Store};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    /// Manufacturer names by MAC prefix (IEEE registry).
    pub vendors: Arc<crate::vendor::Vendors>,
    /// The config generator, when available (for on-demand dry runs).
    pub renderer: Option<crate::dryrun::RenderFn>,
    pub auth: crate::auth::SharedAuth,
    /// Commands for the engine (e.g. setting aliases).
    pub engine: tokio::sync::mpsc::Sender<crate::engine::Input>,
    pub live: SharedLive,
    pub tx: broadcast::Sender<LiveMsg>,
    pub started: Ts,
    pub source: String,
    pub backups: Option<crate::backup::Backups>,
    /// Active mode: apctl answers the APs (and can upgrade them).
    pub active: bool,
    pub writer: Option<crate::store::Writer>,
}

pub fn router(state: AppState) -> Router {
    let public = Router::new()
        // For Kubernetes probes: no login, no data.
        .route("/healthz", get(|| async { "ok" }))
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
        .route("/api/settings/wlans", get(crate::settings::wlans).post(crate::settings::post_wlan))
        .route("/api/settings/wlans/{id}", axum::routing::put(crate::settings::put_wlan).delete(crate::settings::delete_wlan_route))
        .route("/api/settings/wlans/{id}/passphrase", get(crate::settings::passphrase))
        .route("/api/settings/devices/{mac}", get(crate::settings::device).put(crate::settings::put_device))
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
        .route("/api/backups/upload", axum::routing::post(crate::backup::upload).layer(axum::extract::DefaultBodyLimit::max(1 << 30)))
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
        .route("/api/ws", get(ws))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), crate::auth::require_login));
    public.merge(protected).fallback(crate::web::handler).with_state(state)
}

pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn internal(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn parse_mac(s: &str) -> Result<Mac, ApiError> {
    s.parse().map_err(|_| bad(format!("invalid MAC {s}")))
}

/// Runs a read query on the blocking pool.
async fn read<T: Send + 'static>(
    store: &Arc<Store>,
    db: Db,
    f: impl FnOnce(&rusqlite::Connection) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || store.read(db, f))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(ApiError::from)
}

async fn status(State(s): State<AppState>) -> ApiResult {
    let live = s.live.read().unwrap();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if s.active { "active" } else { "shadow" },
        "source": s.source,
        "started": s.started,
        "now": store::now_ts(),
        "counters": live.counters,
        "devices": live.devices.len(),
        "devices_online": live.devices.values().filter(|d| d.online).count(),
        "clients_connected": live.clients.values().filter(|c| c.connected).count(),
    })))
}

/// APs in the database, as views shaped like a live one but offline: shown
/// after a restart until each AP reports again.
async fn stored_devices(store: &Arc<Store>, only: Option<String>) -> Result<Vec<Value>, ApiError> {
    read(store, Db::Config, move |c| {
        let mut stmt = c.prepare(
            "SELECT mac, COALESCE(name, hostname), model, model_display, version, ip, serial, first_seen, last_seen, uptime FROM devices WHERE ?1 IS NULL OR mac = ?1",
        )?;
        let rows = stmt
            .query_map([only.as_deref()], |r| {
                Ok(json!({
                    "snapshot": {
                        "ap": {
                            "mac": r.get::<_, String>(0)?, "hostname": r.get::<_, Option<String>>(1)?, "model": r.get::<_, Option<String>>(2)?,
                            "model_display": r.get::<_, Option<String>>(3)?, "version": r.get::<_, Option<String>>(4)?, "ip": r.get::<_, Option<String>>(5)?,
                            "serial": r.get::<_, Option<String>>(6)?, "uptime": null, "cpu": null, "mem": null, "load1": null, "load5": null,
                            "load15": null, "mem_total": null, "mem_used": null, "satisfaction": null,
                        },
                        "uplink": null, "radios": [], "vaps": [], "clients": [], "has_vap_table": false,
                    },
                    "online": false, "first_seen": r.get::<_, Option<i64>>(7)?.unwrap_or(0), "last_seen": r.get::<_, Option<i64>>(8)?.unwrap_or(0),
                    "peer": "", "interval": 0, "reconfiguring": false, "last_config_push": null, "stored_only": true,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await
}

async fn devices(State(s): State<AppState>) -> ApiResult {
    let stored = stored_devices(&s.store, None).await?;
    let live = s.live.read().unwrap();
    let mut list: Vec<Value> = live
        .devices
        .iter()
        .map(|(mac, d)| {
            let a = &d.snapshot.ap;
            let clients = live.clients.values().filter(|c| c.connected && c.sample.ap_mac == *mac).count();
            json!({
                "mac": mac, "name": a.hostname, "model": a.model, "model_display": a.model_display,
                "version": a.version, "ip": a.ip, "online": d.online, "reconfiguring": d.reconfiguring,
                "first_seen": d.first_seen, "last_seen": d.last_seen, "uptime": a.uptime,
                "cpu": a.cpu, "mem": a.mem, "load1": a.load1, "satisfaction": a.satisfaction,
                "clients": clients,
                "uplink": d.snapshot.uplink.as_ref().map(|u| json!({ "speed": u.speed, "up": u.up, "full_duplex": u.full_duplex })),
                "radios": d.snapshot.radios.iter().map(|r| json!({
                    "radio": r.radio, "channel": r.channel, "bw": r.bw, "tx_power": r.tx_power,
                    "cu_total": r.cu_total, "noise_floor": r.noise_floor, "clients": r.num_sta,
                })).collect::<Vec<_>>(),
                "last_config_push": d.last_config_push,
                "locating": live.locating.contains(mac),
            })
        })
        .collect();
    for d in stored {
        let ap = &d["snapshot"]["ap"];
        if ap["mac"].as_str().and_then(|m| m.parse().ok()).is_some_and(|m| live.devices.contains_key(&m)) {
            continue;
        }
        list.push(json!({
            "mac": ap["mac"], "name": ap["hostname"], "model": ap["model"], "model_display": ap["model_display"], "version": ap["version"],
            "ip": ap["ip"], "online": false, "reconfiguring": false, "first_seen": d["first_seen"], "last_seen": d["last_seen"], "uptime": null,
            "cpu": null, "mem": null, "load1": null, "satisfaction": null, "clients": 0, "uplink": null, "radios": [], "last_config_push": null,
            "stored_only": true,
        }));
    }
    Ok(Json(Value::Array(list)))
}

async fn device(State(s): State<AppState>, Path(mac): Path<String>) -> ApiResult {
    let mac = parse_mac(&mac)?;
    {
        let live = s.live.read().unwrap();
        if let Some(d) = live.devices.get(&mac) {
            let clients: Vec<_> = live.clients.values().filter(|c| c.connected && c.sample.ap_mac == mac).collect();
            return Ok(Json(json!({ "device": d, "clients": clients, "locating": live.locating.contains(&mac) })));
        }
    }
    // Known but not reporting since apctl started: offline, with what we stored.
    let stored = stored_devices(&s.store, Some(mac.to_string())).await?;
    let d = stored.into_iter().next().ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown device".into()))?;
    Ok(Json(json!({ "device": d, "clients": [] })))
}

async fn clients(State(s): State<AppState>) -> ApiResult {
    #[allow(clippy::type_complexity)]
    let (live_clients, aliases, state): (BTreeMap<String, Value>, BTreeMap<String, Value>, Option<Arc<Value>>) = {
        let live = s.live.read().unwrap();
        let clients = live
            .clients
            .iter()
            .map(|(mac, c)| {
                let ap_name = live.devices.get(&c.sample.ap_mac).and_then(|d| d.snapshot.ap.hostname.clone());
                let mut v = serde_json::to_value(c).unwrap_or_default();
                v["ap_name"] = json!(ap_name);
                let a = live.aliases.get(mac).cloned().unwrap_or_default();
                v["alias"] = json!(a.alias);
                v["note"] = json!(a.note);
                v["vendor"] = json!(s.vendors.lookup(mac));
                crate::actions::add_controls(&mut v, live.state.as_deref(), &mac.to_string());
                (mac.to_string(), v)
            })
            .collect();
        let aliases = live.aliases.iter().map(|(m, a)| (m.to_string(), serde_json::to_value(a).unwrap_or_default())).collect();
        (clients, aliases, live.state.clone())
    };
    // Clients known from before this process started, not yet seen again.
    let known: Vec<Value> = read(&s.store, Db::Config, |c| {
        let mut stmt = c.prepare("SELECT mac, hostname, ip, first_seen, last_seen, ap_mac, essid, radio FROM clients ORDER BY last_seen DESC LIMIT 2000")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(json!({
                    "mac": r.get::<_, String>(0)?, "hostname": r.get::<_, Option<String>>(1)?, "ip": r.get::<_, Option<String>>(2)?,
                    "first_seen": r.get::<_, Option<i64>>(3)?, "last_seen": r.get::<_, Option<i64>>(4)?,
                    "ap_mac": r.get::<_, Option<String>>(5)?, "essid": r.get::<_, Option<String>>(6)?, "radio": r.get::<_, Option<String>>(7)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    let mut out: Vec<Value> = live_clients.values().cloned().collect();
    for k in known {
        let mac = k["mac"].as_str().unwrap_or("").to_string();
        if !live_clients.contains_key(&mac) {
            let a = aliases.get(&mac).cloned().unwrap_or_default();
            let mut v = json!({
                "connected": false, "first_seen": k["first_seen"], "last_seen": k["last_seen"], "sample": k,
                "alias": a["alias"], "note": a["note"], "vendor": s.vendors.lookup_str(&mac),
            });
            crate::actions::add_controls(&mut v, state.as_deref(), &mac);
            out.push(v);
        }
    }
    Ok(Json(Value::Array(out)))
}

async fn client(State(s): State<AppState>, Path(mac): Path<String>) -> ApiResult {
    let mac = parse_mac(&mac)?;
    let found = {
        let live = s.live.read().unwrap();
        let a = live.aliases.get(&mac).cloned().unwrap_or_default();
        live.clients.get(&mac).map(|c| {
            let mut v = serde_json::to_value(c).unwrap_or_default();
            v["alias"] = json!(a.alias);
            v["note"] = json!(a.note);
            v["vendor"] = json!(s.vendors.lookup(&mac));
            crate::actions::add_controls(&mut v, live.state.as_deref(), &mac.to_string());
            v
        })
    };
    match found {
        Some(v) => Ok(Json(v)),
        None => Err(ApiError(StatusCode::NOT_FOUND, "unknown client".into())),
    }
}

async fn state_summary(State(s): State<AppState>) -> ApiResult {
    let live = s.live.read().unwrap();
    Ok(Json(json!({
        "imported_at": live.state_imported_at,
        "summary": live.state.as_deref().map(crate::dryrun::summarize_state),
    })))
}

/// Replaces the imported controller settings with an `informdump import` snapshot.
async fn import_state(State(s): State<AppState>, headers: axum::http::HeaderMap, Json(state): Json<Value>) -> ApiResult {
    check_csrf(&headers)?;
    crate::dryrun::validate_state(&state).map_err(|e| bad(format!("{e:#}")))?;
    let summary = crate::dryrun::summarize_state(&state);
    s.engine
        .send(crate::engine::Input::SetState { ts: store::now_ts(), state })
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "engine stopped".into()))?;
    Ok(Json(json!({ "ok": true, "summary": summary })))
}

/// Dry-run status: for each AP, what apctl would push now compared with the last
/// config the other controller pushed; plus the comparisons made at each push.
async fn dryrun(State(s): State<AppState>) -> ApiResult {
    // Redacted last configs from the database, for APs not pushed to since start.
    let stored: BTreeMap<String, (String, String, Option<String>)> = read(&s.store, Db::Config, |c| {
        let mut stmt = c.prepare("SELECT mac, mgmt_cfg, system_cfg, cfgversion FROM device_config")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    (r.get::<_, Option<String>>(1)?.unwrap_or_default(), r.get::<_, Option<String>>(2)?.unwrap_or_default(), r.get(3)?),
                ))
            })?
            .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
        Ok(rows)
    })
    .await?;
    let history: Vec<Value> = read(&s.store, Db::Config, |c| {
        let mut stmt = c.prepare("SELECT ts, mac, cfgversion, matches, comparison FROM dryrun_results ORDER BY ts DESC LIMIT 100")?;
        let rows = stmt
            .query_map([], |r| {
                let comparison: String = r.get(4)?;
                Ok(json!({
                    "ts": r.get::<_, i64>(0)?, "mac": r.get::<_, String>(1)?, "cfgversion": r.get::<_, Option<String>>(2)?,
                    "matches": r.get::<_, i64>(3)? != 0,
                    "comparison": serde_json::from_str::<Value>(&comparison).unwrap_or(Value::Null),
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;

    let live = s.live.read().unwrap();
    let mut devices = Vec::new();
    for (mac, d) in &live.devices {
        let name = d.snapshot.ap.hostname.clone();
        let entry = |status: &str, extra: Value| {
            let mut v = json!({ "mac": mac, "name": name, "status": status });
            if let Value::Object(m) = extra {
                v.as_object_mut().unwrap().extend(m);
            }
            v
        };
        // The snapshot records the cfgversion the other controller expected for
        // each AP at import time. If the AP now runs another one, that controller
        // has pushed new config since: the settings are probably out of date.
        let snapshot_version = live.state.as_deref().and_then(|st| {
            st["devices"].as_array()?.iter().find(|x| x["mac"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(&mac.to_string())))?["cfgversion"]
                .as_str()
                .map(str::to_string)
        });
        let running_version = d.snapshot.ap.cfgversion.clone();
        let settings_stale = matches!((&snapshot_version, &running_version), (Some(a), Some(b)) if a != b);
        let entry = |status: &str, extra: Value| {
            let mut v = entry(status, extra);
            v["settings_stale"] = json!(settings_stale);
            v
        };
        let (Some(render), Some(state)) = (&s.renderer, live.state.as_deref()) else {
            devices.push(entry(if s.renderer.is_none() { "no_generator" } else { "no_settings" }, json!({})));
            continue;
        };
        // Prefer the unredacted config seen in this run; fall back to the stored redacted copy.
        // Only full configs count: a management-only push says nothing about system_cfg.
        let (actual, redacted) = match (live.last_config.get(mac).filter(|c| !c.1.is_empty()), stored.get(&mac.to_string()).filter(|c| !c.1.is_empty())) {
            (Some(c), _) => (c.clone(), false),
            (None, Some(c)) => (c.clone(), true),
            (None, None) => {
                devices.push(entry("no_config_seen", json!({})));
                continue;
            }
        };
        let req = crate::dryrun::RenderRequest {
            state,
            device_mac: &mac.to_string(),
            inform: live.raw_informs.get(mac).map(|v| v.as_ref()),
            cfgversion: actual.2.as_deref().unwrap_or(""),
            previous_system_cfg: Some(&actual.1),
        };
        match render(&req) {
            Ok(ours) => {
                let c = crate::dryrun::compare(&ours, &actual.0, &actual.1, redacted);
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
    Ok(Json(json!({
        "generator": s.renderer.is_some(),
        "settings_imported_at": live.state_imported_at,
        "devices": devices,
        "history": history,
    })))
}

/// Mutations must carry this header. Browsers cannot add custom headers to
/// cross-site requests without a CORS preflight, which this server never
/// approves, so another website cannot make a visitor's browser change data.
pub fn check_csrf(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
    match headers.get("x-requested-with").and_then(|v| v.to_str().ok()) {
        Some("apctl") => Ok(()),
        _ => Err(ApiError(StatusCode::FORBIDDEN, "missing X-Requested-With: apctl header".into())),
    }
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
    headers: axum::http::HeaderMap,
    Json(body): Json<AliasBody>,
) -> ApiResult {
    check_csrf(&headers)?;
    let mac = parse_mac(&mac)?;
    validate(&body.alias, &body.note)?;
    let input = crate::engine::Input::SetAlias { ts: store::now_ts(), mac, alias: body.alias, note: body.note, only_if_unset: false };
    s.engine.send(input).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "engine stopped".into()))?;
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
    headers: axum::http::HeaderMap,
    Json(entries): Json<Vec<ImportEntry>>,
) -> ApiResult {
    check_csrf(&headers)?;
    let mut parsed = Vec::with_capacity(entries.len());
    for e in entries {
        validate(&e.alias, &e.note)?;
        parsed.push((parse_mac(&e.mac)?, e.alias, e.note));
    }
    let n = parsed.len();
    for (mac, alias, note) in parsed {
        let input = crate::engine::Input::SetAlias { ts: store::now_ts(), mac, alias, note, only_if_unset: !q.overwrite };
        s.engine.send(input).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "engine stopped".into()))?;
    }
    Ok(Json(json!({ "submitted": n })))
}

#[derive(Deserialize)]
struct SeriesQuery {
    /// Key values in the table's key order, comma-separated (e.g. `mac,radio`).
    key: String,
    from: Option<Ts>,
    to: Option<Ts>,
}

async fn series(State(s): State<AppState>, Path(table): Path<String>, Query(q): Query<SeriesQuery>) -> ApiResult {
    let t = store::table(&table).ok_or_else(|| bad(format!("unknown series {table}")))?;
    let keys: Vec<String> = q.key.split(',').map(str::to_string).collect();
    if keys.len() != t.keys.len() {
        return Err(bad(format!("{table} needs key {}", t.keys.join(","))));
    }
    let now = store::now_ts();
    let to = q.to.unwrap_or(now);
    let from = q.from.unwrap_or(to - 3600);
    let tier = store::tier_for(from, to, now);
    let result = read(&s.store, Db::Metrics, move |c| store::series(c, t, &keys, from, to, tier)).await?;
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
}

#[derive(Deserialize)]
struct EventQuery {
    device: Option<String>,
    client: Option<String>,
    kind: Option<String>,
    /// Only events strictly before this time (for paging backwards).
    before: Option<Ts>,
    limit: Option<i64>,
}

async fn events(State(s): State<AppState>, Query(q): Query<EventQuery>) -> ApiResult {
    let mut cond = vec!["1 = 1".to_string()];
    let mut params: Vec<Sql> = Vec::new();
    if let Some(d) = &q.device {
        params.push(Sql::Text(parse_mac(d)?.to_string()));
        cond.push(format!("device_mac = ?{}", params.len()));
    }
    if let Some(c) = &q.client {
        params.push(Sql::Text(parse_mac(c)?.to_string()));
        cond.push(format!("client_mac = ?{}", params.len()));
    }
    if let Some(k) = &q.kind {
        // Prefix match, so `client` selects all client events; several kinds
        // can be given separated by commas.
        let mut any = Vec::new();
        for k in k.split(',').map(str::trim).filter(|k| !k.is_empty()).take(10) {
            params.push(Sql::Text(format!("{k}%")));
            any.push(format!("kind LIKE ?{}", params.len()));
        }
        if !any.is_empty() {
            cond.push(format!("({})", any.join(" OR ")));
        }
    }
    if let Some(b) = q.before {
        params.push(Sql::Integer(b));
        cond.push(format!("ts < ?{}", params.len()));
    }
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    let sql = format!("SELECT ts, kind, device_mac, client_mac, data FROM events WHERE {} ORDER BY ts DESC, id DESC LIMIT {limit}", cond.join(" AND "));
    let rows = read(&s.store, Db::Config, move |c| {
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(params), |r| {
                let data: Option<String> = r.get(4)?;
                Ok(json!({
                    "ts": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?,
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
    before: Option<Ts>,
    limit: Option<i64>,
}

async fn logs(State(s): State<AppState>, Query(q): Query<LogQuery>) -> ApiResult {
    let mut cond = vec!["1 = 1".to_string()];
    let mut params: Vec<Sql> = Vec::new();
    if let Some(d) = &q.device {
        params.push(Sql::Text(parse_mac(d)?.to_string()));
        cond.push(format!("l.device_mac = ?{}", params.len()));
    }
    if let Some(text) = q.q.as_deref().filter(|t| !t.trim().is_empty()) {
        // Quote each word so user input cannot break FTS syntax; words are ANDed.
        let fts: Vec<String> = text.split_whitespace().map(|w| format!("\"{}\"", w.replace('"', "\"\""))).collect();
        params.push(Sql::Text(fts.join(" ")));
        cond.push(format!("l.id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?{})", params.len()));
    }
    if let Some(b) = q.before {
        params.push(Sql::Integer(b));
        cond.push(format!("l.ts < ?{}", params.len()));
    }
    let limit = q.limit.unwrap_or(500).clamp(1, 5000);
    let sql = format!(
        "SELECT l.ts, l.device_mac, l.src_ip, l.facility, l.severity, l.program, l.msg FROM logs l WHERE {} ORDER BY l.ts DESC, l.id DESC LIMIT {limit}",
        cond.join(" AND ")
    );
    let rows = read(&s.store, Db::Logs, move |c| {
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(params), |r| {
                Ok(json!({
                    "ts": r.get::<_, i64>(0)?, "device_mac": r.get::<_, Option<String>>(1)?, "src_ip": r.get::<_, Option<String>>(2)?,
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

async fn live_socket(mut socket: WebSocket, mut rx: broadcast::Receiver<LiveMsg>) {
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(m) => {
                    let text = serde_json::to_string(&m).unwrap_or_default();
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        return;
                    }
                }
                // A slow client missed messages: tell it to refetch rather than dropping it.
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if socket.send(Message::Text(r#"{"type":"resync"}"#.into())).await.is_err() {
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
