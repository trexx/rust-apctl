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

use crate::engine::{Input, PushedConfig, SharedLive};
use crate::model::Ts;
use crate::store::{self, Db, Store, Writer};

/// What apctl remembers about an AP it manages.
#[derive(Clone, Default)]
struct Managed {
    /// The cfgversion of the config apctl considers current for this AP.
    cfgversion: Option<String>,
    /// The rendered config with a placeholder cfgversion, to detect changes.
    content: Option<String>,
    /// Set once the AP has used AES-GCM; CBC is refused after that.
    gcm: bool,
    /// The last render (memory only): reused while its inputs are unchanged.
    render: Option<Arc<Render>>,
}

/// A render of an AP's config with the placeholder cfgversion, and what it
/// was made from.
struct Render {
    /// The settings rendered from. Every change replaces their Arc; holding
    /// it keeps the address from being reused by another version.
    state: Arc<Value>,
    /// What the generator reads from the inform (`render_inputs`).
    inputs: Value,
    out: apcfg::Output,
    blocked: String,
    /// Both configs and the blocked clients, as compared with `Managed::content`.
    content: String,
}

/// The parts of an inform the config generator reads: the capability bits
/// (apcfg `Caps::read`), `has_eth1` and the names in `vap_table` (net.rs),
/// `inform_ip`, the `port_table` interface names and `uplink` (system.rs).
/// Informs that agree on these render the same config from the same settings,
/// so the rest (counters, uptime, clients) need not cause a render. Raw values
/// are compared, which is stricter than what apcfg parses from them. Keep in
/// step with apcfg when it reads more of the inform.
fn render_inputs(p: &Value) -> Value {
    let names = |table: &str, key: &str| p[table].as_array().map(|t| t.iter().map(|x| x[key].clone()).collect::<Vec<_>>());
    let caps = ["fw_caps", "fw2_caps", "fw3_caps", "wifi_caps", "wifi_caps2", "hw_caps"].map(|k| p[k].clone());
    json!({
        "caps": caps,
        "has_eth1": p["has_eth1"], "inform_ip": p["inform_ip"], "uplink": p["uplink"],
        "vap_table": names("vap_table", "name"), "port_table": names("port_table", "ifname"),
    })
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
    stored_pushes: HashMap<Mac, PushedConfig>,
    /// Reverse proxies whose X-Forwarded-For is believed for the AP's address.
    proxies: Arc<crate::auth::Proxies>,
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

/// Seconds until an AP's next inform, for a site of `n_devices` APs. Matches
/// the official controller for small sites: five seconds per AP plus jitter,
/// at least ten.
fn interval(n_devices: usize) -> i64 {
    let n = n_devices.max(1) as i64;
    if n < 18 { (n * 5 + (random_bytes::<1>()[0] % 5) as i64).max(10) } else { 60 + (random_bytes::<1>()[0] % 31) as i64 }
}

/// A `mgmt_cfg` rendered with the placeholder token, carrying `cfgversion`
/// instead. The token appears nowhere else in a render (apcfg sets it on this
/// one line of `mgmt_cfg`), so this equals rendering again with `cfgversion`.
fn with_cfgversion(mgmt: &str, cfgversion: &str) -> String {
    let line = format!("cfgversion={PLACEHOLDER}\n");
    let at = if mgmt.starts_with(&line) { Some(0) } else { mgmt.find(&format!("\n{line}")).map(|i| i + 1) };
    match at {
        Some(i) => format!("{}cfgversion={cfgversion}\n{}", &mgmt[..i], &mgmt[i + line.len()..]),
        None => mgmt.to_string(),
    }
}

impl Active {
    pub fn new(
        store: &Store,
        writer: Writer,
        live: SharedLive,
        keys: Arc<KeyStore>,
        engine: mpsc::Sender<Input>,
        controller: apcfg::Controller,
        proxies: Arc<crate::auth::Proxies>,
    ) -> anyhow::Result<Active> {
        let rows = store.read(Db::Config, |c| {
            let mut stmt = c.prepare("SELECT mac, cfgversion, content, gcm FROM managed_devices")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        Managed { cfgversion: r.get(1)?, content: r.get(2)?, gcm: r.get::<_, i64>(3)? != 0, render: None },
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        let devices = rows.into_iter().filter_map(|(m, d)| m.parse().ok().map(|m| (m, d))).collect();
        let stored_pushes = store.read(Db::Config, |c| Ok(crate::engine::stored_pushes(c)?))?;
        Ok(Active { live, keys, engine, writer, controller, devices: Mutex::new(devices), stored_pushes, proxies })
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

    fn render(&self, state: &Value, mac: Mac, inform: &Value, cfgversion: &str) -> anyhow::Result<apcfg::Output> {
        let mac_s = mac.to_string();
        let input = apcfg::Input { state, device_mac: &mac_s, inform: Some(inform), cfgversion, controller: &self.controller };
        apcfg::render_with_meta(&input)
    }

    /// The AP's config with the placeholder cfgversion: the last render while
    /// neither the settings nor what it read of the inform changed (most
    /// informs), else a new one. The lock is not held while rendering.
    fn placeholder_render(&self, state: &Arc<Value>, mac: Mac, payload: &Value) -> anyhow::Result<Arc<Render>> {
        let inputs = render_inputs(payload);
        let last = self.devices.lock().unwrap().get(&mac).and_then(|d| d.render.clone());
        if let Some(r) = last.filter(|r| Arc::ptr_eq(&r.state, state) && r.inputs == inputs) {
            return Ok(r);
        }
        let out = self.render(state, mac, payload, PLACEHOLDER)?;
        let site_id = crate::adopt::device_doc(state, &mac).and_then(|d| d["site_id"].as_str()).unwrap_or("");
        let blocked = apcfg::blocked_sta(state, site_id);
        let content = format!("{}\n--\n{}\n--\n{}", out.rendered.mgmt_cfg, out.rendered.system_cfg, blocked);
        let r = Arc::new(Render { state: state.clone(), inputs, out, blocked, content });
        self.devices.lock().unwrap().entry(mac).or_default().render = Some(r.clone());
        Ok(r)
    }

    /// The reply that adopts an AP: only `mgmt_cfg`, which carries its own key
    /// (it still informs with the factory key). Its full config follows once
    /// it informs with that key.
    fn adoption_reply(&self, ts: Ts, mac: Mac, payload: &Value) -> Value {
        let server_time = (ts * 1000).to_string();
        let (state, n_devices) = {
            let live = self.live.read().unwrap();
            (live.state.clone(), live.devices.len())
        };
        let Some(mut state) = state.as_deref().cloned() else {
            return json!({ "_type": "noop", "interval": interval(n_devices), "server_time_in_utc": server_time });
        };
        let mut cfgversion = new_cfgversion();
        if let Some(d) = crate::adopt::device_doc_mut(&mut state, &mac) {
            // The key it used, so mgmt_cfg includes `authkey`.
            d["x_inform_authkey"] = json!(hex::encode(DEFAULT_KEY));
            if let Some(v) = d["cfgversion"].as_str() {
                cfgversion = v.to_string();
            }
        }
        match self.render(&state, mac, payload, &cfgversion) {
            Ok(out) => json!({ "_type": "setparam", "mgmt_cfg": out.rendered.mgmt_cfg, "server_time_in_utc": server_time }),
            Err(e) => {
                tracing::error!("{mac}: cannot render the adoption config: {e:#}");
                json!({ "_type": "noop", "interval": interval(n_devices), "server_time_in_utc": server_time })
            }
        }
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
        // Notifications (config acknowledgements, events) get a bare noop: no
        // interval, and never a config push.
        if payload["inform_as_notif"].as_bool() == Some(true) {
            return json!({ "_type": "noop", "server_time_in_utc": server_time });
        }
        // One lock for what the reply needs: a queued command (restart, locate,
        // kick...) goes before anything else; a resend asked from the UI (the
        // flag stays until the push is built); the settings; the site's size.
        let (cmd, force, state, n_devices) = {
            let mut live = self.live.write().unwrap();
            let cmd = crate::actions::next(&mut live, &mac);
            (cmd, live.reprovision.contains(&mac), live.state.clone(), live.devices.len())
        };
        if let Some(mut cmd) = cmd {
            cmd["server_time_in_utc"] = json!(server_time);
            tracing::info!("{mac}: sending {} {}", cmd["_type"], cmd["cmd"]);
            return cmd;
        }
        let Some(state) = state else {
            tracing::warn!("{mac}: no settings imported, replying noop");
            return noop(interval(n_devices));
        };
        let device = crate::adopt::device_doc(&state, &mac);
        // An AP adopted over SSH has no radio settings yet: take them from this inform first.
        let has_radios = device.is_some_and(|d| d["radio_table"].as_array().is_some_and(|t| !t.is_empty()));
        if !has_radios && payload["radio_table"].is_array() {
            let (tx, _rx) = tokio::sync::oneshot::channel();
            let p = payload.clone();
            let edit: crate::engine::StateEdit = Box::new(move |st: &mut Value| {
                let table = crate::adopt::radio_table(st, &p);
                let d = crate::adopt::device_doc_mut(st, &mac).ok_or("no record")?;
                d["radio_table"] = json!(table);
                for k in ["model", "version", "serial", "ip"] {
                    if !p[k].is_null() {
                        d[k] = p[k].clone();
                    }
                }
                if d["name"].is_null() {
                    d["name"] = p["hostname"].clone();
                }
                Ok(())
            });
            let _ = self.engine.try_send(Input::EditState { ts, what: format!("radio settings for new AP {mac}"), edit, done: tx });
            return noop(interval(n_devices));
        }
        let reported = payload["cfgversion"].as_str().unwrap_or("").to_string();

        // What would we push, ignoring the cfgversion token? Rendered once: the
        // token is patched into mgmt_cfg where a version is needed.
        let render = match self.placeholder_render(&state, mac, payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("{mac}: cannot render config, replying noop: {e:#}");
                return noop(interval(n_devices));
            }
        };
        let out = &render.out;

        // The lock is never held while rendering.
        let (current, changed) = {
            let devices = self.devices.lock().unwrap();
            let d = devices.get(&mac);
            (d.and_then(|d| d.cfgversion.clone()), force || d.and_then(|d| d.content.as_deref()) != Some(render.content.as_str()))
        };
        let cfgversion = if !changed {
            current.unwrap_or_default()
        } else {
            // First contact after cutover: if the AP already runs exactly this
            // config (the last push we saw from the other controller, rendered
            // with the AP's token), keep its token instead of re-pushing.
            // Prefer the unmasked push seen in this run; otherwise the stored copy,
            // where secrets are masked (they come from the same imported settings).
            // A resend asked for is always a push.
            let adopt = !force && current.is_none() && {
                let last_push = self.live.read().unwrap().last_config.get(&mac).cloned();
                let candidate = last_push.map(|p| (p, false)).or_else(|| self.stored_pushes.get(&mac).cloned().map(|p| (p, true)));
                candidate.is_some_and(|(p, redacted)| {
                    let ours = (with_cfgversion(&out.rendered.mgmt_cfg, &reported), out.rendered.system_cfg.clone());
                    p.cfgversion.as_deref() == Some(reported.as_str()) && crate::dryrun::compare(&ours, &p.mgmt_cfg, &p.system_cfg, redacted).matches()
                })
            };
            let version = if adopt { reported.clone() } else { new_cfgversion() };
            tracing::info!(
                "{mac}: config {} (cfgversion {version})",
                if adopt { "already in place, adopting the AP's version" } else { "changed" }
            );
            let snapshot = {
                let mut devices = self.devices.lock().unwrap();
                let d = devices.entry(mac).or_default();
                d.cfgversion = Some(version.clone());
                d.content = Some(render.content.clone());
                d.clone()
            };
            self.persist(mac, &snapshot);
            version
        };

        if reported == cfgversion {
            // Config is current: is it this AP's turn for a firmware upgrade?
            // (One lock: an upgrade that cannot be sent fails at once.)
            let cmd = {
                let mut live = self.live.write().unwrap();
                match crate::firmware::command(&mut live.firmware, &mac, payload, ts) {
                    Some(Err(why)) => Some(Err((why, live.firmware.failed(&mac, why).is_some()))),
                    cmd => cmd.map(|c| c.map_err(|why| (why, false))),
                }
            };
            match cmd {
                Some(Ok(cmd)) => {
                    tracing::warn!("{mac}: sending firmware upgrade to {}", cmd["version"]);
                    let data = json!({ "target": cmd["version"], "url": cmd["url"] });
                    let _ = self.engine.try_send(Input::Note { ts, kind: "ap_upgrade_sent", mac, data });
                    return cmd;
                }
                Some(Err((why, true))) => {
                    let _ = self.engine.try_send(Input::Note { ts, kind: "ap_upgrade_failed", mac, data: json!({ "reason": "no internet", "detail": why }) });
                }
                Some(Err((_, false))) | None => {}
            }
            return noop(interval(n_devices));
        }
        if force {
            self.live.write().unwrap().reprovision.remove(&mac);
        }
        // Keep the section numbering the render allocated.
        let _ = self.engine.try_send(Input::SetConfigMeta { mac, meta: out.config_meta.clone() });
        tracing::info!("{mac}: pushing config {cfgversion} (AP reports {reported:?})");
        json!({
            "_type": "setparam",
            "cfgversion": cfgversion,
            "system_cfg": out.rendered.system_cfg,
            "blocked_sta": render.blocked,
            "mgmt_cfg": with_cfgversion(&out.rendered.mgmt_cfg, &cfgversion),
            "server_time_in_utc": server_time,
        })
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
    // An unencrypted packet "opens" with any key: it proves nothing.
    if !pkt.header.flags.has(Flags::ENCRYPTED) {
        tracing::warn!("{mac}: refusing an unencrypted inform from {}", peer.ip());
        return status(StatusCode::BAD_REQUEST);
    }

    // Which keys may this AP use? Its own if apctl manages it; the factory key always.
    let state = active.live.read().unwrap().state.clone();
    let device_key = crate::adopt::device_key(state.as_deref(), &active.keys, &mac);
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
    if payload["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) != Some(mac) {
        tracing::warn!("{mac}: header and payload MACs differ");
        return status(StatusCode::BAD_REQUEST);
    }
    if device_key.is_none() || used == KeyUsed::Default {
        let known = device_key.is_some();
        let adopting = active.live.read().unwrap().adoption.adopting.contains_key(&mac);
        if known && adopting {
            // Adopt pressed: hand the AP its own key (in mgmt_cfg), with the factory key.
            let a = active.clone();
            let Ok(reply) = tokio::task::spawn_blocking(move || a.adoption_reply(ts, mac, &payload)).await else {
                return status(StatusCode::INTERNAL_SERVER_ERROR);
            };
            tracing::info!("{mac}: adoption: sending its key");
            return sealed(mac, gcm, &key, &reply);
        }
        // Not ours, or ours but reset: answered 404 and listed for adoption.
        // Whatever apctl remembered about it (e.g. AES-GCM) no longer holds.
        active.devices.lock().unwrap().remove(&mac);
        let new = crate::adopt::note_pending(&mut active.live.write().unwrap(), &payload, known, ts);
        if new {
            tracing::info!("{mac}: {} informing from {}", if known { "reset AP (adoption required)" } else { "AP waiting for adoption" }, peer.ip());
            let data = json!({ "model": payload["model"], "ip": payload["ip"], "known": known });
            let _ = active.engine.send(Input::Note { ts, kind: "ap_pending", mac, data }).await;
        }
        return status(StatusCode::NOT_FOUND);
    }
    // Its own key: an adoption is complete; a forgotten AP is told to reset.
    let (was_adopting, forgetting) = {
        let mut live = active.live.write().unwrap();
        live.adoption.pending.remove(&mac);
        (live.adoption.adopting.remove(&mac).is_some(), live.adoption.forgetting.contains_key(&mac))
    };
    if was_adopting {
        let data = json!({ "model": payload["model"], "ip": payload["ip"], "version": payload["version"] });
        let _ = active.engine.send(Input::Note { ts, kind: "ap_adopted", mac, data }).await;
    }
    if forgetting {
        tracing::warn!("{mac}: forgotten: telling it to reset");
        let engine = active.engine.clone();
        tokio::spawn(async move { crate::adopt::finish_forget(&engine, mac, true).await });
        active.devices.lock().unwrap().remove(&mac);
        let reply = json!({ "_type": "setdefault", "server_time_in_utc": (ts * 1000).to_string() });
        return sealed(mac, gcm, &key, &reply);
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

    let peer_ip = active.proxies.client_ip(&headers, peer.ip()).to_string();
    // Rendering the config takes a while: off the async workers.
    let a = active.clone();
    let Ok((reply, payload)) = tokio::task::spawn_blocking(move || (a.reply(ts, mac, &payload), payload)).await else {
        return status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let decoded = Decoded { header: pkt.header.clone(), key: used, payload };
    if active.engine.send(Input::Inform { ts, peer: peer_ip, decoded }).await.is_err() {
        return status(StatusCode::SERVICE_UNAVAILABLE);
    }
    if reply["_type"] == "setparam" {
        let _ = active.engine.send(Input::ConfigPushed { ts, mac, payload: reply.clone() }).await;
    }

    sealed(mac, gcm, &key, &reply)
}

/// A reply in the request's encryption mode, never compressed, with a fresh IV.
fn sealed(mac: Mac, gcm: bool, key: &[u8; 16], reply: &Value) -> Response {
    let flags = Flags(Flags::ENCRYPTED | if gcm { Flags::GCM } else { 0 });
    let packet = inform::seal(mac, flags, random_bytes::<16>(), key, reply.to_string().as_bytes());
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

    use crate::model::tests::{fixture, fixtures};

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
            if let Some((mgmt_cfg, system_cfg, cfgversion)) = last_push {
                l.last_config.insert(AP.parse().unwrap(), PushedConfig { mgmt_cfg, system_cfg, cfgversion });
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
        let active = Arc::new(Active::new(&store, writer, live.clone(), Arc::new(keys), tx, controller, Default::default()).unwrap());
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
    async fn sends_a_queued_upgrade_once_the_config_is_current() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        let version = reply.unwrap().1["cfgversion"].as_str().unwrap().to_string();
        rig.live.write().unwrap().firmware.enqueue(vec![crate::firmware::Job {
            mac: AP.parse().unwrap(),
            name: None,
            from: Some("8.8.11.20161".into()),
            target: "8.8.12.20200".into(),
            url: "https://fw-download.example/U6M-8.8.12.bin".into(),
            md5: Some("abc".into()),
            sha256: None,
            custom: false,
            state: crate::firmware::JobState::Queued,
            sent_at: None,
            expires: None,
        }]);
        // An AP whose config is out of date gets the config first.
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "setparam");
        // Config current: now the upgrade.
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!((reply["_type"].as_str(), reply["version"].as_str(), reply["md5sum"].as_str()), (Some("upgrade"), Some("8.8.12.20200"), Some("abc")));
        assert_eq!(reply["url"], "https://fw-download.example/U6M-8.8.12.bin");
        // Sent once: the next inform is a heartbeat.
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
        assert_eq!(rig.live.read().unwrap().firmware.current.as_ref().map(|j| j.state), Some(crate::firmware::JobState::Sent));
    }

    #[tokio::test]
    async fn sends_queued_commands_one_per_inform_before_the_config() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let ap: Mac = AP.parse().unwrap();
        {
            let mut live = rig.live.write().unwrap();
            crate::actions::queue(&mut live, ap, json!({ "_type": "cmd", "cmd": "set-locate" }));
            crate::actions::queue(&mut live, ap, json!({ "_type": "reboot", "reboot_type": "soft" }));
        }
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!((reply["_type"].as_str(), reply["cmd"].as_str()), (Some("cmd"), Some("set-locate")));
        assert!(reply["server_time_in_utc"].is_string());
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["reboot_type"], "soft");
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "setparam");
    }

    #[tokio::test]
    async fn resends_the_config_when_asked() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        let version = reply.unwrap().1["cfgversion"].as_str().unwrap().to_string();
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
        rig.live.write().unwrap().reprovision.insert(AP.parse().unwrap());
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!(reply["_type"], "setparam");
        assert_ne!(reply["cfgversion"].as_str(), Some(version.as_str()), "a new version, so the AP applies it");
        assert!(rig.live.read().unwrap().reprovision.is_empty());
    }

    #[tokio::test]
    async fn blocking_a_client_changes_the_config() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        let version = reply.unwrap().1["cfgversion"].as_str().unwrap().to_string();
        {
            let mut live = rig.live.write().unwrap();
            let mut state = live.state.as_deref().cloned().unwrap();
            crate::actions::edit_client(&mut state, "aa:bb:cc:00:00:09", &[("blocked", json!(true))]).unwrap();
            live.state = Some(Arc::new(state));
        }
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!(reply["_type"], "setparam");
        assert!(reply["blocked_sta"].as_str().unwrap().split('\n').any(|m| m == "aa:bb:cc:00:00:09"));
    }

    #[tokio::test]
    async fn provisions_once_then_heartbeats() {
        let Some(_) = fixtures() else { return };
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
        let Some(_) = fixtures() else { return };
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
        let Some(_) = fixtures() else { return };
        let probe = rig(true, None);
        let payload = ap_payload("abcdefabcdefabcd");
        let out = probe.active.render(&probe.live.read().unwrap().state.clone().unwrap(), AP.parse().unwrap(), &payload, "abcdefabcdefabcd").unwrap();
        let rig = rig_with_stored(true, None, Some((out.rendered.mgmt_cfg, out.rendered.system_cfg, "abcdefabcdefabcd".into())));
        let (_, reply) = inform_as_ap(&rig, &payload, KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
    }

    #[tokio::test]
    async fn refuses_unencrypted_informs() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        // Plain JSON under an adopted AP's MAC "opens" with its key: it must not count.
        for flags in [0, Flags::ZLIB, Flags::GCM, Flags::GCM | Flags::ZLIB] {
            let (status, _) = inform_as_ap(&rig, &ap_payload("1"), KEY, flags).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "flags {flags:#x}");
        }
        assert!(rig.active.devices.lock().unwrap().is_empty(), "nothing recorded");
    }

    #[tokio::test]
    async fn rejects_what_the_official_controller_rejects() {
        let Some(_) = fixtures() else { return };
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

    #[test]
    fn patching_the_cfgversion_equals_rendering_with_it() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let state = rig.live.read().unwrap().state.clone().unwrap();
        let payload = ap_payload("1");
        let probe = rig.active.render(&state, AP.parse().unwrap(), &payload, PLACEHOLDER).unwrap();
        let real = rig.active.render(&state, AP.parse().unwrap(), &payload, "0123456789abcdef").unwrap();
        assert_eq!(with_cfgversion(&probe.rendered.mgmt_cfg, "0123456789abcdef"), real.rendered.mgmt_cfg);
        assert_eq!(probe.rendered.system_cfg, real.rendered.system_cfg);
        assert_eq!(with_cfgversion("cfgversion=0000000000000000\nx=1\n", "ab"), "cfgversion=ab\nx=1\n");
    }

    #[test]
    fn renders_again_only_when_the_settings_or_what_it_reads_change() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let ap: Mac = AP.parse().unwrap();
        let state = rig.live.read().unwrap().state.clone().unwrap();
        let mut payload = ap_payload("1");
        let render = |state: &Arc<Value>, p: &Value| rig.active.placeholder_render(state, ap, p).unwrap();
        let first = render(&state, &payload);
        // What changes with every inform (uptime, counters, the reported version) is not read.
        payload["uptime"] = json!(987654);
        payload["bytes"] = json!(123);
        payload["cfgversion"] = json!("2");
        assert!(Arc::ptr_eq(&first, &render(&state, &payload)), "reused");
        // Each field the generator reads makes a new render, equal to one made from scratch.
        for (field, value) in [("inform_ip", json!("192.0.2.99")), ("has_eth1", json!(true)), ("wifi_caps", json!(0)), ("uplink", json!("eth1"))] {
            let before = render(&state, &payload);
            payload[field] = value;
            let after = render(&state, &payload);
            assert!(!Arc::ptr_eq(&before, &after), "{field} changed");
            let fresh = rig.active.render(&state, ap, &payload, PLACEHOLDER).unwrap();
            assert_eq!((&after.out.rendered.mgmt_cfg, &after.out.rendered.system_cfg), (&fresh.rendered.mgmt_cfg, &fresh.rendered.system_cfg));
        }
        // So does every change of the settings (a new Arc), even to an equal copy.
        let latest = render(&state, &payload);
        let copy = Arc::new((*state).clone());
        assert!(!Arc::ptr_eq(&latest, &render(&copy, &payload)));
    }

    #[tokio::test]
    async fn a_resend_survives_an_inform_that_cannot_push() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let ap: Mac = AP.parse().unwrap();
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        let version = reply.unwrap().1["cfgversion"].as_str().unwrap().to_string();
        let with_radios = rig.live.read().unwrap().state.clone().unwrap();
        {
            let mut live = rig.live.write().unwrap();
            live.reprovision.insert(ap);
            // As if adopted over SSH: no radio settings yet, so this inform only collects them.
            let mut state = (*with_radios).clone();
            state["devices"].as_array_mut().unwrap().iter_mut().find(|d| d["mac"] == AP).unwrap()["radio_table"] = json!([]);
            live.state = Some(Arc::new(state));
        }
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
        assert!(rig.live.read().unwrap().reprovision.contains(&ap), "the resend is still wanted");
        rig.live.write().unwrap().state = Some(with_radios);
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "setparam");
        assert!(rig.live.read().unwrap().reprovision.is_empty());
    }

    #[tokio::test]
    async fn adopts_a_new_ap_then_forgets_it() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let new: Mac = "02:00:00:00:00:09".parse().unwrap();
        let mut payload = ap_payload("1");
        payload["mac"] = json!(new.to_string());
        payload["default"] = json!(true);
        // Factory key, unknown AP: 404 and listed as pending.
        let (status, _) = inform_as_ap(&rig, &payload, DEFAULT_KEY, GCM_ZLIB).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(rig.live.read().unwrap().adoption.pending.get(&new).is_some_and(|p| !p.known));
        // Adopt: a record with its own key, and the AP is expected back.
        {
            let mut live = rig.live.write().unwrap();
            let mut state = live.state.as_deref().cloned().unwrap();
            crate::adopt::adopt_device(&mut state, &new, &payload).unwrap();
            live.state = Some(Arc::new(state));
            live.adoption.adopting.insert(new, 0);
        }
        let key_hex = crate::adopt::device_doc(rig.live.read().unwrap().state.as_deref().unwrap(), &new).unwrap()["x_authkey"].as_str().unwrap().to_string();
        let key: [u8; 16] = hex::decode(&key_hex).unwrap().try_into().unwrap();
        // Still on the factory key: only mgmt_cfg, carrying its key.
        let (_, reply) = inform_as_ap(&rig, &payload, DEFAULT_KEY, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!(reply["_type"], "setparam");
        assert!(reply["mgmt_cfg"].as_str().unwrap().contains(&format!("authkey={key_hex}")));
        assert!(reply["system_cfg"].is_null());
        // Back with its own key: adopted, and its full config follows.
        let (_, reply) = inform_as_ap(&rig, &payload, key, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!(reply["_type"], "setparam");
        assert!(reply["system_cfg"].as_str().unwrap().lines().count() > 100);
        assert!(!reply["mgmt_cfg"].as_str().unwrap().contains("authkey="), "no key once it uses its own");
        assert!(rig.live.read().unwrap().adoption.adopting.is_empty());
        // Forget: its next inform tells it to reset.
        rig.live.write().unwrap().adoption.forgetting.insert(new, 0);
        let (_, reply) = inform_as_ap(&rig, &payload, key, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "setdefault");
    }

    #[tokio::test]
    async fn a_reset_ap_is_listed_for_adoption_again() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        // AP is ours (it has a key), but informs with the factory key: it was reset.
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), DEFAULT_KEY, GCM_ZLIB).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(rig.live.read().unwrap().adoption.pending.get(&AP.parse().unwrap()).is_some_and(|p| p.known));
    }

    #[tokio::test]
    async fn no_cbc_after_gcm_and_cbc_replies_for_cbc_devices() {
        let Some(_) = fixtures() else { return };
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
    async fn notifications_get_a_bare_noop() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let mut p = ap_payload("1111111111111111"); // out of date, yet no push
        p["inform_as_notif"] = json!(true);
        p["notif_reason"] = json!("event");
        let (_, reply) = inform_as_ap(&rig, &p, KEY, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!(reply["_type"], "noop");
        assert!(reply.get("interval").is_none());
    }

    #[tokio::test]
    async fn without_settings_it_only_heartbeats() {
        let Some(_) = fixtures() else { return };
        let rig = rig(false, None);
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop", "never push a config it cannot render");
    }
}
