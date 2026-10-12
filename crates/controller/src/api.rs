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
    pub live: SharedLive,
    pub tx: broadcast::Sender<LiveMsg>,
    pub started: Ts,
    pub source: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/devices", get(devices))
        .route("/api/devices/{mac}", get(device))
        .route("/api/clients", get(clients))
        .route("/api/clients/{mac}", get(client))
        .route("/api/series/{table}", get(series))
        .route("/api/events", get(events))
        .route("/api/logs", get(logs))
        .route("/api/ws", get(ws))
        .fallback(crate::web::handler)
        .with_state(state)
}

pub struct ApiError(StatusCode, String);

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
        "mode": "shadow",
        "source": s.source,
        "started": s.started,
        "now": store::now_ts(),
        "counters": live.counters,
        "devices": live.devices.len(),
        "devices_online": live.devices.values().filter(|d| d.online).count(),
        "clients_connected": live.clients.values().filter(|c| c.connected).count(),
    })))
}

async fn devices(State(s): State<AppState>) -> ApiResult {
    let live = s.live.read().unwrap();
    let list: Vec<Value> = live
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
            })
        })
        .collect();
    Ok(Json(Value::Array(list)))
}

async fn device(State(s): State<AppState>, Path(mac): Path<String>) -> ApiResult {
    let mac = parse_mac(&mac)?;
    let live = s.live.read().unwrap();
    let d = live.devices.get(&mac).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown device".into()))?;
    let clients: Vec<_> = live.clients.values().filter(|c| c.connected && c.sample.ap_mac == mac).collect();
    Ok(Json(json!({ "device": d, "clients": clients })))
}

async fn clients(State(s): State<AppState>) -> ApiResult {
    let live_clients: BTreeMap<String, Value> = {
        let live = s.live.read().unwrap();
        live.clients
            .iter()
            .map(|(mac, c)| {
                let ap_name = live.devices.get(&c.sample.ap_mac).and_then(|d| d.snapshot.ap.hostname.clone());
                let mut v = serde_json::to_value(c).unwrap_or_default();
                v["ap_name"] = json!(ap_name);
                (mac.to_string(), v)
            })
            .collect()
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
        if !live_clients.contains_key(k["mac"].as_str().unwrap_or("")) {
            out.push(json!({ "connected": false, "first_seen": k["first_seen"], "last_seen": k["last_seen"], "sample": k }));
        }
    }
    Ok(Json(Value::Array(out)))
}

async fn client(State(s): State<AppState>, Path(mac): Path<String>) -> ApiResult {
    let mac = parse_mac(&mac)?;
    let live = s.live.read().unwrap();
    match live.clients.get(&mac) {
        Some(c) => Ok(Json(serde_json::to_value(c).unwrap_or_default())),
        None => Err(ApiError(StatusCode::NOT_FOUND, "unknown client".into())),
    }
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
        // Prefix match, so `client` selects all client events.
        params.push(Sql::Text(format!("{k}%")));
        cond.push(format!("kind LIKE ?{}", params.len()));
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
