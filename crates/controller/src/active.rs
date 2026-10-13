//! Active mode: apctl answers the APs' informs itself.
//!
//! Off unless `--active` is given. For each inform:
//!
//! 1. The packet is decrypted with the AP's own key, then the factory key.
//!    Unknown APs (factory key only) get 404, like an unadopted device would
//!    from the official controller. An AP that has used AES-GCM may not fall
//!    back to CBC. The MAC in the header must match the payload's.
//! 2. The inform feeds the engine exactly as in shadow mode (metrics, events).
//! 3. apctl renders the AP's config from the settings. If the AP reports a
//!    different `cfgversion`, the reply is a full `setparam`; otherwise a `noop`
//!    with the next inform interval.
//! 4. The reply uses the request's encryption mode, is never compressed, and
//!    has a fresh random IV.
//!
//! At cutover the APs already run the config apctl would render (the dry run
//! checks this), so apctl adopts the `cfgversion` they report instead of
//! pushing the same config again under a new token.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use inform::{DEFAULT_KEY, Flags, Mac, Packet};
use rusqlite::types::Value as Sql;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use wire::decode::{Decoded, KeyUsed};
use wire::keys::KeyStore;

use crate::engine::{Input, SharedLive};
use crate::model::Ts;
use crate::store::{self, Db, Store, Writer};

/// What apctl remembers about an AP it manages.
#[derive(Debug, Clone, Default)]
struct Managed {
    /// The cfgversion of the config apctl considers current for this AP.
    cfgversion: Option<String>,
    /// The rendered config with a placeholder cfgversion, to detect changes.
    content: Option<String>,
    /// Set once the AP has used AES-GCM; CBC is refused after that.
    gcm: bool,
}

pub struct Active {
    live: SharedLive,
    keys: Arc<KeyStore>,
    engine: mpsc::Sender<Input>,
    writer: Writer,
    controller: apcfg::Controller,
    devices: Mutex<HashMap<Mac, Managed>>,
    /// The last push stored for each AP (secrets masked), for adopting the
    /// running config after a restart, when no unmasked push is in memory.
    stored_pushes: HashMap<Mac, (String, String, Option<String>)>,
}

const PLACEHOLDER: &str = "0000000000000000";

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system random source");
    b
}

fn new_cfgversion() -> String {
    hex::encode(random_bytes::<8>())
}

impl Active {
    pub fn new(
        store: &Store,
        writer: Writer,
        live: SharedLive,
        keys: Arc<KeyStore>,
        engine: mpsc::Sender<Input>,
        controller: apcfg::Controller,
    ) -> anyhow::Result<Active> {
        let rows = store.read(Db::Config, |c| {
            let mut stmt = c.prepare("SELECT mac, cfgversion, content, gcm FROM managed_devices")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        Managed { cfgversion: r.get(1)?, content: r.get(2)?, gcm: r.get::<_, i64>(3)? != 0 },
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        let devices = rows.into_iter().filter_map(|(m, d)| m.parse().ok().map(|m| (m, d))).collect();
        let pushes = store.read(Db::Config, |c| {
            let mut stmt = c.prepare("SELECT mac, mgmt_cfg, system_cfg, cfgversion FROM device_config")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        (r.get::<_, Option<String>>(1)?.unwrap_or_default(), r.get::<_, Option<String>>(2)?.unwrap_or_default(), r.get(3)?),
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        let stored_pushes = pushes.into_iter().filter_map(|(m, p)| m.parse().ok().map(|m| (m, p))).collect();
        Ok(Active { live, keys, engine, writer, controller, devices: Mutex::new(devices), stored_pushes })
    }

    fn persist(&self, mac: Mac, d: &Managed) {
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO managed_devices (mac, cfgversion, content, gcm, updated) VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                Sql::Text(mac.to_string()),
                d.cfgversion.clone().map_or(Sql::Null, Sql::Text),
                d.content.clone().map_or(Sql::Null, Sql::Text),
                Sql::Integer(d.gcm as i64),
                Sql::Integer(store::now_ts()),
            ],
        );
    }

    /// Seconds until the AP's next inform. Matches the official controller for
    /// small sites: five seconds per AP plus jitter, at least ten.
    fn interval(&self) -> i64 {
        let n = self.live.read().unwrap().devices.len().max(1) as i64;
        if n < 18 { (n * 5 + (random_bytes::<1>()[0] % 5) as i64).max(10) } else { 60 + (random_bytes::<1>()[0] % 31) as i64 }
    }

    fn render(&self, state: &Value, mac: Mac, inform: &Value, cfgversion: &str) -> anyhow::Result<apcfg::Output> {
        let mac_s = mac.to_string();
        let input = apcfg::Input { state, device_mac: &mac_s, inform: Some(inform), cfgversion, controller: &self.controller };
        apcfg::render_with_meta(&input)
    }

    /// Decides the reply to an AP's inform.
    fn reply(&self, ts: Ts, mac: Mac, payload: &Value) -> Value {
        let server_time = (ts * 1000).to_string();
        let noop = |interval: i64| {
            json!({
                "_type": "noop", "interval": interval, "fingerprint": [], "live_update": false,
                "include_blocks": ["multicast", "pathmon"], "server_time_in_utc": server_time,
            })
        };
        let (state, last_push) = {
            let live = self.live.read().unwrap();
            (live.state.clone(), live.last_config.get(&mac).cloned())
        };
        let Some(state) = state else {
            tracing::warn!("{mac}: no settings imported, replying noop");
            return noop(self.interval());
        };
        let reported = payload["cfgversion"].as_str().unwrap_or("").to_string();

        // What would we push, ignoring the cfgversion token?
        let probe = match self.render(&state, mac, payload, PLACEHOLDER) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!("{mac}: cannot render config, replying noop: {e:#}");
                return noop(self.interval());
            }
        };
        let site_id = state["devices"]
            .as_array()
            .and_then(|d| d.iter().find(|d| d["mac"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(&mac.to_string()))))
            .and_then(|d| d["site_id"].as_str())
            .unwrap_or("")
            .to_string();
        let blocked = apcfg::blocked_sta(&state, &site_id);
        let content = format!("{}\n--\n{}\n--\n{}", probe.rendered.mgmt_cfg, probe.rendered.system_cfg, blocked);

        // The lock is never held while rendering, and never taken twice.
        let (current, changed) = {
            let devices = self.devices.lock().unwrap();
            let d = devices.get(&mac);
            (d.and_then(|d| d.cfgversion.clone()), d.and_then(|d| d.content.as_deref()) != Some(content.as_str()))
        };
        let cfgversion = if !changed {
            current.unwrap_or_default()
        } else {
            // First contact after cutover: if the AP already runs exactly this
            // config (the last push we saw from the other controller, rendered
            // with the AP's token), keep its token instead of re-pushing.
            // Prefer the unmasked push seen in this run; otherwise the stored copy,
            // where secrets are masked (they come from the same imported settings).
            let candidate = last_push.map(|p| (p, false)).or_else(|| self.stored_pushes.get(&mac).cloned().map(|p| (p, true)));
            let adopt = current.is_none()
                && candidate.as_ref().is_some_and(|((m, s, v), redacted)| {
                    v.as_deref() == Some(reported.as_str())
                        && self.render(&state, mac, payload, &reported).is_ok_and(|ours| {
                            crate::dryrun::compare(&(ours.rendered.mgmt_cfg, ours.rendered.system_cfg), m, s, *redacted).matches()
                        })
                });
            let version = if adopt { reported.clone() } else { new_cfgversion() };
            tracing::info!(
                "{mac}: config {} (cfgversion {version})",
                if adopt { "already in place, adopting the AP's version" } else { "changed" }
            );
            let snapshot = {
                let mut devices = self.devices.lock().unwrap();
                let d = devices.entry(mac).or_default();
                d.cfgversion = Some(version.clone());
                d.content = Some(content);
                d.clone()
            };
            self.persist(mac, &snapshot);
            version
        };

        if reported == cfgversion {
            return noop(self.interval());
        }
        match self.render(&state, mac, payload, &cfgversion) {
            Ok(out) => {
                // Keep the section numbering the render allocated.
                let _ = self.engine.try_send(Input::SetConfigMeta { mac, meta: out.config_meta });
                tracing::info!("{mac}: pushing config {cfgversion} (AP reports {reported:?})");
                json!({
                    "_type": "setparam",
                    "cfgversion": cfgversion,
                    "system_cfg": out.rendered.system_cfg,
                    "blocked_sta": blocked,
                    "mgmt_cfg": out.rendered.mgmt_cfg,
                    "server_time_in_utc": server_time,
                })
            }
            Err(e) => {
                tracing::error!("{mac}: cannot render config, replying noop: {e:#}");
                noop(self.interval())
            }
        }
    }
}

fn status(code: StatusCode) -> Response {
    code.into_response()
}

/// POST /inform
pub async fn inform(
    State(active): State<Arc<Active>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ts = store::now_ts();
    let Ok(pkt) = Packet::parse(&body) else { return status(StatusCode::BAD_REQUEST) };
    let mac = pkt.header.mac;
    let gcm = pkt.header.flags.has(Flags::GCM);

    // Which keys may this AP use?
    let device_key = active.keys.get(&mac).copied();
    let mut attempts: Vec<(KeyUsed, [u8; 16])> = Vec::new();
    if let Some(k) = device_key {
        attempts.push((KeyUsed::Device, k));
    }
    attempts.push((KeyUsed::Default, DEFAULT_KEY));
    let opened = attempts
        .iter()
        .find_map(|(used, key)| pkt.open(key).ok().and_then(|p| serde_json::from_slice::<Value>(&p).ok()).map(|v| (*used, *key, v)));
    let Some((used, key, payload)) = opened else {
        tracing::warn!("{mac}: inform from {} could not be decrypted", peer.ip());
        return status(StatusCode::BAD_REQUEST);
    };
    if device_key.is_none() {
        // Not adopted by us: the official controller answers 404 and lists the
        // device as pending. Adoption comes later.
        tracing::info!("{mac}: unadopted device informing from {}", peer.ip());
        return status(StatusCode::NOT_FOUND);
    }
    if payload["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) != Some(mac) {
        tracing::warn!("{mac}: header and payload MACs differ");
        return status(StatusCode::BAD_REQUEST);
    }
    {
        let mut devices = active.devices.lock().unwrap();
        let d = devices.entry(mac).or_default();
        if d.gcm && !gcm {
            tracing::warn!("{mac}: refusing a CBC inform from a device that uses AES-GCM");
            return status(StatusCode::BAD_REQUEST);
        }
        if gcm && !d.gcm {
            d.gcm = true;
            let snapshot = d.clone();
            drop(devices);
            active.persist(mac, &snapshot);
        }
    }

    let peer_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| peer.ip().to_string());
    let reply = active.reply(ts, mac, &payload);
    let decoded = Decoded { header: pkt.header.clone(), key: used, payload };
    if active.engine.send(Input::Inform { ts, peer: peer_ip, decoded }).await.is_err() {
        return status(StatusCode::SERVICE_UNAVAILABLE);
    }
    if reply["_type"] == "setparam" {
        let _ = active.engine.send(Input::ConfigPushed { ts, mac, payload: reply.clone() }).await;
    }

    let flags = Flags(Flags::ENCRYPTED | if gcm { Flags::GCM } else { 0 });
    let packet = inform::seal(mac, flags, random_bytes::<16>(), &key, reply.to_string().as_bytes());
    ([(header::CONTENT_TYPE, "application/x-binary")], packet).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    const AP: &str = "02:00:00:00:00:01";
    const KEY: [u8; 16] = [0x42; 16];

    fn fixture(part: &str) -> Value {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/captures/2026-10-12-u6m-8.8.11");
        let file = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).find(|p| p.to_string_lossy().contains(part)).unwrap();
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
    }

    struct Rig {
        app: axum::Router,
        live: SharedLive,
        _rx: mpsc::Receiver<Input>,
        active: Arc<Active>,
    }

    fn rig(with_state: bool, last_push: Option<(String, String, Option<String>)>) -> Rig {
        rig_with_stored(with_state, last_push, None)
    }

    /// `stored`: a push already in the database (as written in shadow mode, masked).
    fn rig_with_stored(with_state: bool, last_push: Option<(String, String, Option<String>)>, stored: Option<(String, String, String)>) -> Rig {
        let dir = std::env::temp_dir().join(format!("apctl-active-{}-{}", std::process::id(), hex::encode(random_bytes::<4>())));
        let (store, writer) = Store::open(&dir).unwrap();
        if let Some((mgmt, system, version)) = stored {
            writer.exec(
                Db::Config,
                "INSERT INTO device_config (mac, ts, cfgversion, mgmt_cfg, system_cfg) VALUES (?1, 0, ?2, ?3, ?4)",
                vec![Sql::Text(AP.into()), Sql::Text(version), Sql::Text(wire::cfgdiff::redact(&mgmt)), Sql::Text(wire::cfgdiff::redact(&system))],
            );
            std::thread::sleep(std::time::Duration::from_millis(1500)); // the writer commits about once a second
        }
        let live: SharedLive = Default::default();
        {
            let mut l = live.write().unwrap();
            if with_state {
                l.state = Some(Arc::new(fixture("controller-state.json")));
            }
            if let Some(p) = last_push {
                l.last_config.insert(AP.parse().unwrap(), p);
            }
        }
        let mut keys = KeyStore::default();
        keys.insert(AP, &hex::encode(KEY)).unwrap();
        let (tx, rx) = mpsc::channel(1000);
        let controller = apcfg::Controller {
            inform_url: "http://unifi.example.net:8080/inform".into(),
            mgmt_url: "https://unifi.example.net:8443".into(),
            stun_url: "stun://unifi.example.net:3478/".into(),
            syslog_ip: None,
            version: "10.6.106".into(),
            reporter_uuid: "00000000-0000-4000-8000-000000000004".into(),
        };
        let active = Arc::new(Active::new(&store, writer, live.clone(), Arc::new(keys), tx, controller).unwrap());
        let app = axum::Router::new().route("/inform", axum::routing::post(inform)).with_state(active.clone());
        Rig { app, live, _rx: rx, active }
    }

    /// The AP's own inform (sanitised capture), with a chosen cfgversion.
    fn ap_payload(cfgversion: &str) -> Value {
        let mut p = fixture("000001_020000000001_inform");
        p["cfgversion"] = json!(cfgversion);
        p
    }

    async fn send(rig: &Rig, packet: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let mut req = Request::post("/inform").header("content-type", "application/x-binary").body(Body::from(packet)).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([192, 168, 0, 6], 40000))));
        let res = rig.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec();
        (status, body)
    }

    /// Sends an inform the way the AP does (GCM + zlib unless `flags` says otherwise).
    async fn inform_as_ap(rig: &Rig, payload: &Value, key: [u8; 16], flags: u16) -> (StatusCode, Option<(Flags, Value)>) {
        let mac: Mac = payload["mac"].as_str().unwrap().parse().unwrap();
        let packet = inform::seal(mac, Flags(flags), random_bytes::<16>(), &key, payload.to_string().as_bytes());
        let (status, body) = send(rig, packet).await;
        if status != StatusCode::OK {
            return (status, None);
        }
        let pkt = Packet::parse(&body).unwrap();
        let reply: Value = serde_json::from_slice(&pkt.open(&key).expect("reply decrypts with the AP's key")).unwrap();
        (status, Some((pkt.header.flags, reply)))
    }

    const GCM_ZLIB: u16 = Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB;

    #[tokio::test]
    async fn provisions_once_then_heartbeats() {
        let rig = rig(true, None);
        let (status, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        assert_eq!(status, StatusCode::OK);
        let (flags, reply) = reply.unwrap();
        assert_eq!(flags, Flags(Flags::ENCRYPTED | Flags::GCM), "same mode as the request, never compressed");
        assert_eq!(reply["_type"], "setparam");
        let version = reply["cfgversion"].as_str().unwrap().to_string();
        assert_eq!(version.len(), 16);
        assert!(reply["mgmt_cfg"].as_str().unwrap().contains(&format!("cfgversion={version}")));
        assert!(reply["system_cfg"].as_str().unwrap().lines().count() > 300);
        assert!(reply["server_time_in_utc"].as_str().unwrap().len() >= 13);

        // The AP applies it and reports the new version: heartbeat only.
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        let (_, reply) = reply.unwrap();
        assert_eq!(reply["_type"], "noop");
        let interval = reply["interval"].as_i64().unwrap();
        assert!((10..=14).contains(&interval), "{interval}");
        assert_eq!(reply["include_blocks"], json!(["multicast", "pathmon"]));

        // Until it applies a push, an AP still reporting the old version gets it again.
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["cfgversion"], version.as_str());
    }

    #[tokio::test]
    async fn adopts_the_running_config_at_cutover_instead_of_repushing() {
        // The last push we saw from the other controller is exactly what we render
        // with the AP's token: render it once to get that push.
        let probe = rig(true, None);
        let payload = ap_payload("abcdefabcdefabcd");
        let out = probe.active.render(&probe.live.read().unwrap().state.clone().unwrap(), AP.parse().unwrap(), &payload, "abcdefabcdefabcd").unwrap();
        let same = rig(true, Some((out.rendered.mgmt_cfg, out.rendered.system_cfg, Some("abcdefabcdefabcd".into()))));
        let (_, reply) = inform_as_ap(&same, &payload, KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop", "no re-push of an identical config");

        // A different last push (another token): apctl takes over with its own version.
        let other = rig(true, Some(("x".into(), "y".into(), Some("abcdefabcdefabcd".into()))));
        let (_, reply) = inform_as_ap(&other, &payload, KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "setparam");
    }

    #[tokio::test]
    async fn adopts_from_the_stored_masked_push_after_a_restart() {
        let probe = rig(true, None);
        let payload = ap_payload("abcdefabcdefabcd");
        let out = probe.active.render(&probe.live.read().unwrap().state.clone().unwrap(), AP.parse().unwrap(), &payload, "abcdefabcdefabcd").unwrap();
        let rig = rig_with_stored(true, None, Some((out.rendered.mgmt_cfg, out.rendered.system_cfg, "abcdefabcdefabcd".into())));
        let (_, reply) = inform_as_ap(&rig, &payload, KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
    }

    #[tokio::test]
    async fn rejects_what_the_official_controller_rejects() {
        let rig = rig(true, None);
        // Wrong key.
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), [9; 16], GCM_ZLIB).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Header MAC differs from the payload's.
        let packet = inform::seal("02:00:00:00:00:01".parse().unwrap(), Flags(GCM_ZLIB), random_bytes::<16>(), &KEY, {
            let mut p = ap_payload("1");
            p["mac"] = json!("02:00:00:00:00:99");
            p.to_string()
        }.as_bytes());
        assert_eq!(send(&rig, packet).await.0, StatusCode::BAD_REQUEST);
        // Garbage.
        assert_eq!(send(&rig, b"not an inform".to_vec()).await.0, StatusCode::BAD_REQUEST);
        // An unadopted device (factory key, no key of ours): 404, like an unadopted AP.
        let mut stranger = ap_payload("1");
        stranger["mac"] = json!("02:00:00:00:00:77");
        let (status, _) = inform_as_ap(&rig, &stranger, DEFAULT_KEY, Flags::ENCRYPTED | Flags::GCM).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn no_cbc_after_gcm_and_cbc_replies_for_cbc_devices() {
        let rig = rig(true, None);
        // A CBC-only exchange is answered in CBC.
        let (status, reply) = inform_as_ap(&rig, &ap_payload("1"), KEY, Flags::ENCRYPTED).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reply.unwrap().0, Flags(Flags::ENCRYPTED));
        // Once the device has used GCM, CBC is refused.
        inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), KEY, Flags::ENCRYPTED).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn without_settings_it_only_heartbeats() {
        let rig = rig(false, None);
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop", "never push a config it cannot render");
    }
}
