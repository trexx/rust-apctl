//! Active mode: apctl answers the APs' informs itself.
//!
//! Off unless `--active` is given. For each inform:
//!
//! 1. The packet is decrypted with the AP's own key, then the factory key
//!    (a few at a time, fewer with the factory key, which anyone can use; an
//!    inform that finds too many waiting already gets 503, and the AP tries
//!    again at its next interval). Unknown APs (factory key only) get 404,
//!    like an unadopted device would from the official controller. An AP that
//!    has used AES-GCM (or whose record says so, `x_aes_gcm`) may not fall
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
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use inform::{DEFAULT_KEY, Flags, Mac, Packet};
use rusqlite::types::Value as Sql;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, SemaphorePermit, mpsc};
use wire::decode::{Decoded, KeyUsed, open_with};
use wire::keys::KeyStore;

use crate::clock;
use crate::engine::{Event, EventKind, Input, SharedLive};
use crate::model::Ts;
use crate::random_bytes;
use crate::store::{Db, PushedConfig, Store, Writer};

/// What apctl remembers about an AP it manages.
#[derive(Clone, Default)]
struct Managed {
    /// The cfgversion of the config apctl considers current for this AP.
    cfgversion: Option<String>,
    /// The digest of the config that cfgversion stands for (`Render::digest`),
    /// to detect changes. Only the digest is stored: the config holds secrets.
    content: Option<[u8; 32]>,
    /// Set once the AP has used AES-GCM, or from its record's `x_aes_gcm`
    /// when apctl first hears from it; CBC is refused after that.
    gcm: bool,
    /// The last render (memory only): reused while its inputs are unchanged.
    render: Option<Arc<Render>>,
}

/// A render of an AP's config with the placeholder cfgversion, and what it
/// was made from.
struct Render {
    /// The settings rendered from, by address. Every change replaces their
    /// Arc; the Weak keeps the address from being reused by another version
    /// without keeping old settings alive for an AP that went quiet.
    state: Weak<Value>,
    /// What the generator reads from the inform (`apcfg::inform_inputs`).
    inputs: Value,
    out: apcfg::Output,
    blocked: String,
    /// The digest of both configs and the blocked clients (see `content_digest`),
    /// as compared with `Managed::content`.
    digest: [u8; 32],
}

/// SHA-256 of `mgmt_cfg`, `system_cfg` and `blocked_sta` joined by `\n--\n`:
/// the text `managed_devices.content` held before it held this digest.
fn content_digest(mgmt: &str, system: &str, blocked: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    for (i, part) in [mgmt, system, blocked].into_iter().enumerate() {
        if i > 0 {
            h.update(b"\n--\n");
        }
        h.update(part.as_bytes());
    }
    h.finalize().into()
}

/// A stored `managed_devices.content`: a digest in hex. A row from before
/// apctl stored digests holds the rendered text itself, whose digest equals
/// that of the same config rendered now, so an upgrade pushes nothing again;
/// true for such a row, to rewrite it with the digest.
fn stored_digest(content: &str) -> ([u8; 32], bool) {
    let mut digest = [0u8; 32];
    match hex::decode_to_slice(content, &mut digest) {
        Ok(()) => (digest, false),
        Err(_) => (Sha256::digest(content.as_bytes()).into(), true),
    }
}

pub struct Active {
    live: SharedLive,
    keys: Arc<KeyStore>,
    engine: mpsc::Sender<Input>,
    writer: Writer,
    controller: apcfg::Controller,
    /// Shared with the live view's `forget_managed`, which drops an AP's entry when it is forgotten.
    devices: Arc<Mutex<HashMap<Mac, Managed>>>,
    /// Read for the last push stored for an AP (secrets masked), to adopt its
    /// running config after a restart, when no unmasked push is in memory.
    store: Arc<Store>,
    /// The `mgmt_cfg` handed to each AP being adopted (see `adoption_cfg`).
    /// Shared with `forget_managed` too.
    adoption_cfgs: Arc<Mutex<HashMap<Mac, AdoptionCfg>>>,
    /// Informs opened with an AP's own key, a few at a time.
    work: Gate,
    /// Informs opened with the factory key, which anyone can use: fewer at a
    /// time, as a small zlib body can inflate to megabytes of JSON.
    strangers: Gate,
    /// Reverse proxies whose X-Forwarded-For is believed for the AP's address.
    proxies: Arc<crate::auth::Proxies>,
    /// Set once "no settings imported" has been logged as a warning.
    warned_no_state: AtomicBool,
}

/// A semaphore for informs that holds only so much waiting: an inform that
/// would take the bytes waiting for it past `max_waiting` is turned away
/// (503) instead of held in memory, and its AP tries again at its next
/// interval. Counted by bytes, so that the APs' small informs can all wait
/// out a burst (every AP informs at once after a settings change) while a
/// flood of large bodies cannot pile up.
struct Gate {
    permits: Semaphore,
    waiting: AtomicUsize,
    max_waiting: usize,
}

/// What a waiting inform holds besides its body (its task, its connection).
const WAIT_OVERHEAD: usize = 4 << 10;

/// The bytes counted as waiting for a gate while this lives (also when the
/// wait is cut short: the AP hung up).
struct Waiting<'a>(&'a AtomicUsize, usize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Ordering::Relaxed);
    }
}

impl Gate {
    fn new(permits: usize, max_waiting: usize) -> Gate {
        Gate { permits: Semaphore::new(permits), waiting: AtomicUsize::new(0), max_waiting }
    }

    /// A permit for an inform of `size` bytes: at once if one is free, else
    /// after the informs ahead of it; None when too much is waiting already.
    async fn enter(&self, size: usize) -> Option<SemaphorePermit<'_>> {
        if let Ok(p) = self.permits.try_acquire() {
            return Some(p);
        }
        let cost = size + WAIT_OVERHEAD;
        let waiting = Waiting(&self.waiting, cost);
        if self.waiting.fetch_add(cost, Ordering::Relaxed) + cost > self.max_waiting {
            return None;
        }
        let permit = self.permits.acquire().await.ok();
        drop(waiting);
        permit
    }
}

/// An opened inform: the key it was opened with, its payload, and the permit
/// held while it is handled.
type Opened<'a> = (KeyUsed, [u8; 16], Value, SemaphorePermit<'a>);

/// An adoption's `mgmt_cfg`, and the settings it was made from (by address,
/// as for `Render::state`).
type AdoptionCfg = (Weak<Value>, Arc<str>);

const PLACEHOLDER: &str = "0000000000000000";

fn new_cfgversion() -> String {
    crate::random_hex::<8>()
}

/// A reply's `server_time_in_utc`: milliseconds, as a string.
pub(crate) fn server_time(ts: Ts) -> String {
    (ts * 1000).to_string()
}

/// The longest inform interval apctl asks for (on sites of 18 APs or more).
/// The insights read this far back for the sample before a window.
pub const MAX_INFORM_INTERVAL: Ts = 90;

/// Seconds until an AP's next inform, for a site of `n_devices` APs. Matches
/// the official controller for small sites: five seconds per AP plus jitter,
/// at least ten. The jitter is the AP's own, from its MAC, so it spreads the
/// APs out as well while an AP is asked for the same interval every time:
/// the engine then has nothing to change for nearly every reply.
fn interval(mac: Mac, n_devices: usize) -> Ts {
    let n = n_devices.max(1) as i64;
    // The device-specific half of the MAC: the vendor half is the same for every AP.
    let jitter = i64::from(u32::from_be_bytes([0, mac.0[3], mac.0[4], mac.0[5]]));
    if n < 18 { (n * 5 + jitter % 5).max(10) } else { MAX_INFORM_INTERVAL - jitter % 31 }
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
        store: &Arc<Store>,
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
                    let content = r.get::<_, Option<String>>(2)?.map(|c| stored_digest(&c));
                    let managed = Managed { cfgversion: r.get(1)?, content: content.map(|c| c.0), gcm: r.get::<_, i64>(3)? != 0, render: None };
                    Ok((r.get::<_, String>(0)?, managed, content.is_some_and(|c| c.1)))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        let mut legacy = Vec::new();
        let mut devices = HashMap::new();
        for (m, d, old) in rows {
            let Ok(m) = m.parse::<Mac>() else { continue };
            if old {
                legacy.push((m, d.clone()));
            }
            devices.insert(m, d);
        }
        let devices = Arc::new(Mutex::new(devices));
        let adoption_cfgs: Arc<Mutex<HashMap<Mac, AdoptionCfg>>> = Default::default();
        // Whichever way an AP is forgotten (reporting or not), the engine drops what is kept here of it.
        let (forgotten, adoptions) = (Arc::downgrade(&devices), Arc::downgrade(&adoption_cfgs));
        live.write().unwrap().forget_managed = Some(Arc::new(move |mac: &Mac| {
            if let Some(devices) = forgotten.upgrade() {
                devices.lock().unwrap().remove(mac);
            }
            if let Some(cfgs) = adoptions.upgrade() {
                cfgs.lock().unwrap().remove(mac);
            }
        }));
        let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
        let active = Active {
            live, keys, engine, writer, controller, devices, store: store.clone(), adoption_cfgs,
            work: Gate::new(cpus, 64 << 20), strangers: Gate::new((cpus / 2).max(1), 8 << 20), proxies, warned_no_state: AtomicBool::new(false),
        };
        // Rows holding the rendered config (with its secrets) get its digest instead.
        if !legacy.is_empty() {
            tracing::info!("replacing the stored configs of {} managed APs with their digests", legacy.len());
        }
        for (m, d) in legacy {
            active.persist(m, &d);
        }
        Ok(active)
    }

    fn persist(&self, mac: Mac, d: &Managed) {
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO managed_devices (mac, cfgversion, content, gcm, updated) VALUES (?1, ?2, ?3, ?4, ?5)",
            vec![
                Sql::Text(mac.to_string()),
                d.cfgversion.clone().map_or(Sql::Null, Sql::Text),
                d.content.map_or(Sql::Null, |c| Sql::Text(hex::encode(c))),
                Sql::Integer(d.gcm as i64),
                Sql::Integer(clock::now_ts()),
            ],
        );
    }

    /// Drops what apctl remembers about an AP it no longer has, in memory and stored.
    fn unmanage(&self, mac: Mac) {
        if self.devices.lock().unwrap().remove(&mac).is_some() {
            self.writer.exec(Db::Config, "DELETE FROM managed_devices WHERE mac = ?1", vec![Sql::Text(mac.to_string())]);
        }
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
        let last = self.devices.lock().unwrap().get(&mac).and_then(|d| d.render.clone());
        if let Some(r) = last.filter(|r| std::ptr::eq(r.state.as_ptr(), Arc::as_ptr(state)) && apcfg::inform_inputs_match(&r.inputs, payload)) {
            return Ok(r);
        }
        let out = self.render(state, mac, payload, PLACEHOLDER)?;
        let site_id = crate::adopt::device_doc(state, &mac).and_then(|d| d["site_id"].as_str()).unwrap_or("");
        let blocked = apcfg::blocked_sta(state, site_id);
        let digest = content_digest(&out.rendered.mgmt_cfg, &out.rendered.system_cfg, &blocked);
        let r = Arc::new(Render { state: Arc::downgrade(state), inputs: apcfg::inform_inputs(payload), out, blocked, digest });
        self.devices.lock().unwrap().entry(mac).or_default().render = Some(r.clone());
        Ok(r)
    }

    /// The reply that adopts an AP: only `mgmt_cfg`, which carries its own key
    /// (it still informs with the factory key). Its full config follows once
    /// it informs with that key.
    fn adoption_reply(&self, ts: Ts, mac: Mac, payload: &Value) -> Value {
        let server_time = server_time(ts);
        let (state, n_devices) = {
            let live = self.live.read().unwrap();
            (live.state.clone(), live.devices.len())
        };
        let Some(state) = state else {
            return json!({ "_type": "noop", "interval": interval(mac, n_devices), "server_time_in_utc": server_time });
        };
        match self.adoption_cfg(&state, mac, payload) {
            Ok(mgmt_cfg) => json!({ "_type": "setparam", "mgmt_cfg": mgmt_cfg, "server_time_in_utc": server_time }),
            Err(e) => {
                tracing::error!("{mac}: cannot render the adoption config: {e:#}");
                json!({ "_type": "noop", "interval": interval(mac, n_devices), "server_time_in_utc": server_time })
            }
        }
    }

    /// The `mgmt_cfg` that adopts an AP, made once per version of the
    /// settings: every inform under the factory key while the adoption lasts
    /// (anyone can send them under its MAC) gets the same one. Only mgmt_cfg
    /// is rendered, so settings it does not read cannot hold up an adoption.
    /// Kept until the adoption ends (see `factory_key_inform`, `managed_inform`)
    /// or the AP is forgotten; one of settings since replaced, or of an
    /// adoption that timed out, goes when another is made.
    fn adoption_cfg(&self, state: &Arc<Value>, mac: Mac, payload: &Value) -> anyhow::Result<Arc<str>> {
        if let Some((from, cfg)) = self.adoption_cfgs.lock().unwrap().get(&mac)
            && std::ptr::eq(from.as_ptr(), Arc::as_ptr(state))
        {
            return Ok(cfg.clone());
        }
        // A new version, never the record's: an AP adopted again would report
        // that one, which a push stored for it may still carry. With the key
        // it used, so mgmt_cfg includes `authkey`.
        let (mac_s, cfgversion) = (mac.to_string(), new_cfgversion());
        let input = apcfg::Input { state, device_mac: &mac_s, inform: Some(payload), cfgversion: &cfgversion, controller: &self.controller };
        let cfg: Arc<str> = apcfg::render_mgmt(&input, Some(&hex::encode(DEFAULT_KEY)))?.into();
        let adopting: Vec<Mac> = self.live.read().unwrap().adoption.adopting.keys().copied().collect();
        let mut cfgs = self.adoption_cfgs.lock().unwrap();
        cfgs.retain(|m, (from, _)| from.strong_count() > 0 && adopting.contains(m));
        cfgs.insert(mac, (Arc::downgrade(state), cfg.clone()));
        Ok(cfg)
    }

    /// Decides the reply to an AP's inform. Runs off the async workers: it
    /// renders, and waits for room in the engine's queue rather than dropping
    /// what it tells the engine.
    fn reply(&self, ts: Ts, mac: Mac, payload: &Value) -> Value {
        let server_time = server_time(ts);
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
        // One read for what the reply needs: whether a command is queued; a
        // resend asked from the UI (the flag stays until the push is built);
        // the settings; the site's size. Writing only to take a command.
        let (queued, force, state, n_devices) = {
            let live = self.live.read().unwrap();
            (live.commands.contains_key(&mac), live.reprovision.contains(&mac), live.state.clone(), live.devices.len())
        };
        if queued && let Some(cmd) = self.queued_command(mac, &server_time) {
            return cmd;
        }
        let Some(state) = state else {
            if self.warned_no_state.swap(true, Ordering::Relaxed) {
                tracing::debug!("{mac}: no settings imported, replying noop");
            } else {
                tracing::warn!("{mac}: no settings imported, replying noop to every AP until some are");
            }
            return noop(interval(mac, n_devices));
        };
        if self.collect_radios(ts, mac, &state, payload) {
            return noop(interval(mac, n_devices));
        }
        let reported = payload["cfgversion"].as_str().unwrap_or("");

        // What would we push, ignoring the cfgversion token? Rendered once: the
        // token is patched into mgmt_cfg where a version is needed.
        let render = match self.placeholder_render(&state, mac, payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("{mac}: cannot render config, replying noop: {e:#}");
                return noop(interval(mac, n_devices));
            }
        };
        let cfgversion = self.decide_version(mac, reported, &render, force);
        if reported == cfgversion {
            return self.firmware_turn(ts, mac, payload).unwrap_or_else(|| noop(interval(mac, n_devices)));
        }
        if force {
            self.live.write().unwrap().reprovision.remove(&mac);
        }
        let out = &render.out;
        // Keep the section numbering the render allocated.
        let _ = self.engine.blocking_send(Input::SetConfigMeta { mac, meta: out.config_meta.clone() });
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

    /// The next queued command (restart, locate, kick...): it goes before anything else.
    fn queued_command(&self, mac: Mac, server_time: &str) -> Option<Value> {
        let mut cmd = crate::actions::next(&mut self.live.write().unwrap(), &mac)?;
        cmd["server_time_in_utc"] = json!(server_time);
        tracing::info!("{mac}: sending {} {}", cmd["_type"], cmd["cmd"]);
        Some(cmd)
    }

    /// An AP adopted over SSH has no radio settings yet: they are made from
    /// the radios its inform lists before any config is pushed. True until
    /// the AP has them (the reply is then a heartbeat).
    fn collect_radios(&self, ts: Ts, mac: Mac, state: &Value, payload: &Value) -> bool {
        let has_radios = |d: &Value| d["radio_table"].as_array().is_some_and(|t| !t.is_empty());
        if crate::adopt::device_doc(state, &mac).is_none_or(has_radios) {
            return false;
        }
        let table = crate::adopt::radio_table(state, payload);
        // None listed: no change to make (each one makes every AP render and
        // inform again), so wait for an inform that lists them.
        if table.is_empty() {
            return true;
        }
        // What the record takes from the inform, as for an AP adopted from the UI.
        let details = crate::adopt::pending_inform(payload);
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let edit: crate::engine::StateEdit = Box::new(move |st: &mut Value| {
            let d = crate::adopt::device_doc_mut(st, &mac).ok_or("no record")?;
            // An earlier inform's change got there first: nothing to write.
            if has_radios(d) {
                return Err(format!("{mac} has its radio settings already"));
            }
            d["radio_table"] = json!(table);
            crate::adopt::fill_from_inform(d, &details);
            // Its 2.4 GHz radio is known now: it joins the channel locks.
            Ok(crate::adopt::join_channel_locks(st, &mac, format!("radio settings for new AP {mac}")))
        });
        let _ = self.engine.blocking_send(Input::EditState { ts, edit, done: tx });
        true
    }

    /// The cfgversion the AP should run: the current one while the config is
    /// unchanged, else a new one, or at cutover the one the AP reports if it
    /// already runs this config (see `runs_already`).
    fn decide_version(&self, mac: Mac, reported: &str, render: &Render, force: bool) -> String {
        // The lock is never held while rendering.
        let (current, changed) = {
            let devices = self.devices.lock().unwrap();
            let d = devices.get(&mac);
            let same = d.and_then(|d| d.content) == Some(render.digest);
            (d.and_then(|d| d.cfgversion.clone()), force || !same)
        };
        if !changed {
            return current.unwrap_or_default();
        }
        // A resend asked for is always a push.
        let adopt = !force && current.is_none() && self.runs_already(mac, reported, &render.out);
        let version = if adopt { reported.to_string() } else { new_cfgversion() };
        tracing::info!("{mac}: config {} (cfgversion {version})", if adopt { "already in place, adopting the AP's version" } else { "changed" });
        let snapshot = {
            let mut devices = self.devices.lock().unwrap();
            let d = devices.entry(mac).or_default();
            d.cfgversion = Some(version.clone());
            d.content = Some(render.digest);
            d.clone()
        };
        self.persist(mac, &snapshot);
        version
    }

    /// First contact after cutover: whether the AP already runs exactly this
    /// config (the last push seen from the other controller, rendered with
    /// the AP's token), so that apctl keeps its token instead of pushing the
    /// same config again. The push seen in this run is compared in full;
    /// after a restart, the stored copy with its secrets masked.
    fn runs_already(&self, mac: Mac, reported: &str, out: &apcfg::Output) -> bool {
        let seen = self.live.read().unwrap().last_config.get(&mac).cloned();
        let stored;
        let (push, redacted) = match &seen {
            Some(p) => (&**p, false),
            None => {
                let Some(p) = self.stored_push(mac) else { return false };
                stored = p;
                (&stored, true)
            }
        };
        push.cfgversion.as_deref() == Some(reported)
            && crate::dryrun::equivalent(&with_cfgversion(&out.rendered.mgmt_cfg, reported), &push.mgmt_cfg, redacted)
            && crate::dryrun::equivalent(&out.rendered.system_cfg, &push.system_cfg, redacted)
    }

    /// The last push stored for an AP, its secrets masked. None if the
    /// settings were edited in apctl since it was recorded: a password changed
    /// there would not show in a masked comparison, and never reach the AP.
    fn stored_push(&self, mac: Mac) -> Option<PushedConfig> {
        let read = self.store.read(Db::Config, |c| {
            let Some((push, pushed)) = crate::store::stored_push_at(c, &mac)? else { return Ok(None) };
            let edited: Option<Ts> = c.query_row("SELECT MAX(ts) FROM events WHERE kind = ?1", [EventKind::SettingsChanged.as_str()], |r| r.get(0))?;
            if edited.is_some_and(|e| pushed.is_none_or(|p| p <= e)) {
                tracing::info!("{mac}: the settings were edited after its last stored push: not comparing with it");
                return Ok(None);
            }
            Ok(Some(push))
        });
        read.unwrap_or_else(|e| {
            tracing::warn!("{mac}: cannot read its last stored push: {e:#}");
            None
        })
    }

    /// Once the AP's config is current: the firmware upgrade, if it is its
    /// turn. An upgrade that cannot be sent fails at once.
    fn firmware_turn(&self, ts: Ts, mac: Mac, payload: &Value) -> Option<Value> {
        // A read for every inform; the write lock only when it is this AP's turn.
        let turn = self.live.read().unwrap().firmware.current.as_ref().is_some_and(|j| j.mac == mac && j.state == crate::firmware::JobState::Queued);
        if !turn {
            return None;
        }
        // The failed job's target, for the event.
        let (cmd, target) = {
            let mut live = self.live.write().unwrap();
            let cmd = crate::firmware::command(&mut live.firmware, &mac, payload, ts)?;
            let target = cmd.as_ref().err().and_then(|why| live.firmware.failed(&mac, why)).map(|j| j.target);
            (cmd, target)
        };
        match cmd {
            Ok(cmd) => {
                tracing::warn!("{mac}: sending firmware upgrade to {}", cmd["version"]);
                let data = json!({ "target": cmd["version"], "url": cmd["url"] });
                let _ = self.engine.blocking_send(Input::Note(Event::device(ts, EventKind::ApUpgradeSent, mac, data)));
                Some(cmd)
            }
            Err(why) => {
                tracing::warn!("{mac}: firmware upgrade not sent: {why}");
                let data = json!({ "reason": "not sent", "detail": why, "target": target });
                let _ = self.engine.blocking_send(Input::Note(Event::device(ts, EventKind::ApUpgradeFailed, mac, data)));
                None
            }
        }
    }

    /// Opens an inform: decrypting, inflating (up to 8 MB) and parsing, off
    /// the async workers. The AP's own key is tried first; the factory key,
    /// which anyone can use, gets fewer turns, so that a flood under it leaves
    /// room for the APs. The permit is held while the inform is handled.
    /// Else the status to answer: 503 when too many informs are waiting
    /// already (see `Gate`), 400 when no key opens it.
    async fn open(&self, body: Bytes, device_key: Option<[u8; 16]>) -> Result<Opened<'_>, StatusCode> {
        let decode = |body: Bytes, used: KeyUsed, key: [u8; 16]| {
            tokio::task::spawn_blocking(move || Packet::parse(&body).map_err(anyhow::Error::from).and_then(|pkt| open_with(&pkt, [(used, key)])))
        };
        if let Some(k) = device_key {
            let permit = self.work.enter(body.len()).await.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            if let Ok(Ok((used, key, payload))) = decode(body.clone(), KeyUsed::Device, k).await {
                return Ok((used, key, payload, permit));
            }
        }
        let permit = self.strangers.enter(body.len()).await.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        match decode(body, KeyUsed::Default, DEFAULT_KEY).await {
            Ok(Ok((used, key, payload))) => Ok((used, key, payload, permit)),
            _ => Err(StatusCode::BAD_REQUEST),
        }
    }
}

/// A managed AP that informed with its own key less than this long ago is not
/// taken for reset when a factory-key inform comes under its MAC (the official
/// controller has no such wait).
const RESET_QUIET_SECS: Ts = 600;

/// Who sent an inform, and the key it was opened with: what answering it needs.
#[derive(Clone, Copy)]
struct Caller {
    mac: Mac,
    gcm: bool,
    key: [u8; 16],
    /// The address the inform came from.
    peer: IpAddr,
    /// The AP's own address: `peer`, or behind a trusted proxy what it says.
    source: IpAddr,
}

impl Caller {
    /// A reply in the request's encryption mode, never compressed, with a
    /// fresh IV, serialised straight into the packet.
    fn seal(&self, reply: &Value) -> Response {
        let flags = Flags::ENCRYPTED | if self.gcm { Flags::GCM } else { Flags::NONE };
        let packet = inform::seal_with(self.mac, flags, random_bytes::<16>(), &self.key, |out| serde_json::to_writer(out, reply).expect("a JSON value serialises"));
        ([(header::CONTENT_TYPE, "application/x-binary")], packet).into_response()
    }
}

/// POST /inform
pub async fn inform(
    State(active): State<Arc<Active>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ts = clock::now_ts();
    let Ok(header) = Packet::parse(&body).map(|p| p.header) else { return StatusCode::BAD_REQUEST.into_response() };
    let mac = header.mac;
    // An unencrypted packet "opens" with any key: it proves nothing.
    if !header.flags.contains(Flags::ENCRYPTED) {
        tracing::warn!("{mac}: refusing an unencrypted inform from {}", peer.ip());
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Which keys may this AP use? Its own if apctl manages it; the factory key always.
    let state = active.live.read().unwrap().state.clone();
    let device_key = crate::adopt::device_key(state.as_deref(), &active.keys, &mac);
    // Its record's AES-GCM pin, as the official controller keeps it (see `managed_inform`).
    let pinned = state.as_deref().and_then(|st| crate::adopt::device_doc(st, &mac)).is_some_and(|d| d["x_aes_gcm"].as_bool() == Some(true));
    drop(state);
    let (used, key, payload, _permit) = match active.open(body, device_key).await {
        Ok(opened) => opened,
        Err(StatusCode::SERVICE_UNAVAILABLE) => {
            tracing::debug!("{mac}: too many informs waiting: turning one from {} away", peer.ip());
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(code) => {
            tracing::warn!("{mac}: inform from {} could not be decrypted", peer.ip());
            return code.into_response();
        }
    };
    if payload["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) != Some(mac) {
        tracing::warn!("{mac}: header and payload MACs differ");
        return StatusCode::BAD_REQUEST.into_response();
    }
    let caller = Caller { mac, gcm: header.flags.contains(Flags::GCM), key, peer: peer.ip(), source: active.proxies.client_ip(&headers, peer.ip()) };
    // Only an AP apctl manages is tried with a key of its own.
    if used == KeyUsed::Default {
        factory_key_inform(&active, ts, caller, payload, device_key.is_some()).await
    } else {
        managed_inform(&active, ts, caller, header, used, payload, pinned).await
    }
}

/// An inform under the factory key: an AP apctl is adopting gets its own key;
/// any other is answered 404 and listed for adoption. `known`: apctl manages
/// an AP of this MAC.
async fn factory_key_inform(active: &Arc<Active>, ts: Ts, caller: Caller, payload: Value, known: bool) -> Response {
    let mac = caller.mac;
    let adopting = active.live.read().unwrap().adoption.adopting.contains_key(&mac);
    if known && adopting {
        // Adopt pressed: hand the AP its own key (in mgmt_cfg), with the factory key.
        let a = active.clone();
        let Ok(sealed) = tokio::task::spawn_blocking(move || caller.seal(&a.adoption_reply(ts, mac, &payload))).await else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        tracing::info!("{mac}: adoption: sending its key");
        return sealed;
    }
    // Not being adopted (any more): the adoption's mgmt_cfg goes.
    active.adoption_cfgs.lock().unwrap().remove(&mac);
    // Not ours, or ours but reset: answered 404 and listed for adoption.
    // What apctl remembers about an AP it no longer has (e.g. AES-GCM) goes,
    // stored too, so that a restart does not bring it back. For one it has,
    // the factory key proves nothing (anyone can send this under its MAC):
    // that is kept until it is adopted again.
    if !known {
        active.unmanage(mac);
    } else if active.live.read().unwrap().devices.get(&mac).is_some_and(|d| ts - d.last_seen < RESET_QUIET_SECS) {
        // It informed with its own key moments ago: a reset AP is silent
        // while it reboots, so this is most likely someone else. Listing
        // it would let an Adopt hand them the AP's key.
        tracing::warn!("{mac}: factory-key inform from {} while the AP still informs with its own key: ignored", caller.peer);
        return StatusCode::NOT_FOUND.into_response();
    }
    let inform = crate::adopt::pending_inform(&payload);
    drop(payload);
    let data = json!({ "model": inform["model"], "ip": inform["ip"], "known": known });
    let new = crate::adopt::note_pending(&mut active.live.write().unwrap(), inform, known, ts, caller.source);
    if new {
        tracing::info!("{mac}: {} informing from {}", if known { "reset AP (adoption required)" } else { "AP waiting for adoption" }, caller.peer);
        let _ = active.engine.send(Input::Note(Event::device(ts, EventKind::ApPending, mac, data))).await;
    }
    StatusCode::NOT_FOUND.into_response()
}

/// An inform under an AP's own key: the reply to it (a config push, a
/// command, a heartbeat), and the inform for the engine. `pinned`: the AP's
/// record says it uses AES-GCM (`x_aes_gcm`, imported from the other
/// controller), which pins it from the first inform apctl hears from it.
async fn managed_inform(active: &Arc<Active>, ts: Ts, caller: Caller, header: inform::Header, used: KeyUsed, payload: Value, pinned: bool) -> Response {
    let (mac, gcm) = (caller.mac, caller.gcm);
    // Its own key: an adoption is complete; a forgotten AP is told to reset
    // (once: the entry goes, so later informs don't finish the forget again).
    let (was_adopting, forgetting) = {
        let busy = |a: &crate::adopt::Adoption| a.pending.contains_key(&mac) || a.adopting.contains_key(&mac) || a.forgetting.contains_key(&mac);
        if busy(&active.live.read().unwrap().adoption) {
            let mut live = active.live.write().unwrap();
            live.adoption.pending.remove(&mac);
            (live.adoption.adopting.remove(&mac).is_some(), live.adoption.forgetting.remove(&mac).is_some())
        } else {
            (false, false)
        }
    };
    if was_adopting {
        // A new start: the config is pushed under a new version, and AES-GCM
        // is pinned again from this inform. The empty version is never
        // current, and keeps the AP from being taken for one that runs its
        // config already (as at cutover): it only had `mgmt_cfg` so far.
        let fresh = Managed { cfgversion: Some(String::new()), ..Default::default() };
        active.devices.lock().unwrap().insert(mac, fresh.clone());
        active.persist(mac, &fresh);
        active.adoption_cfgs.lock().unwrap().remove(&mac);
        let data = json!({ "model": payload["model"], "ip": payload["ip"], "version": payload["version"] });
        let _ = active.engine.send(Input::Note(Event::device(ts, EventKind::ApAdopted, mac, data))).await;
    }
    if forgetting {
        tracing::warn!("{mac}: forgotten: telling it to reset");
        let engine = active.engine.clone();
        tokio::spawn(async move { crate::adopt::finish_forget(&engine, mac, true).await });
        active.devices.lock().unwrap().remove(&mac);
        let reply = json!({ "_type": "setdefault", "server_time_in_utc": server_time(ts) });
        return caller.seal(&reply);
    }
    {
        let mut devices = active.devices.lock().unwrap();
        // Once apctl knows the AP, its own record of AES-GCM decides (an
        // adoption above starts it afresh).
        let d = devices.entry(mac).or_insert_with(|| Managed { gcm: pinned, ..Default::default() });
        if d.gcm && !gcm {
            tracing::warn!("{mac}: refusing a CBC inform from a device that uses AES-GCM");
            return StatusCode::BAD_REQUEST.into_response();
        }
        if gcm && !d.gcm {
            d.gcm = true;
            let snapshot = d.clone();
            drop(devices);
            active.persist(mac, &snapshot);
        }
    }

    // Rendering the config and sealing the reply take a while: off the async workers.
    let a = active.clone();
    let Ok((reply, response, payload)) = tokio::task::spawn_blocking(move || {
        let reply = a.reply(ts, mac, &payload);
        let response = caller.seal(&reply);
        (reply, response, payload)
    })
    .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let decoded = Decoded { header, key: used, payload };
    if active.engine.send(Input::Inform { ts, peer: caller.source, decoded }).await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    // The engine follows the interval it asked for (or the AP would be called
    // offline on a site where informs come more than a minute apart) and
    // records each push. An AP's interval rarely changes: a heartbeat that
    // repeats the one the engine has is only counted.
    let tell = {
        let live = active.live.read().unwrap();
        let interval = reply.get("interval").and_then(Value::as_i64);
        let tell = reply["_type"] == "setparam" || interval.is_some_and(|i| live.devices.get(&mac).is_none_or(|d| d.interval != i));
        if !tell && interval.is_some() {
            live.counters.replies.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        tell
    };
    if tell {
        let _ = active.engine.send(Input::Replied { ts, mac, payload: reply }).await;
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::{TestDir, flushed};
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
        rx: mpsc::Receiver<Input>,
        active: Arc<Active>,
        _dir: TestDir,
    }

    fn rig(with_state: bool, last_push: Option<(String, String, Option<String>)>) -> Rig {
        rig_with_stored(with_state, last_push, None)
    }

    /// `stored`: a push already in the database (as written in shadow mode, masked).
    fn rig_with_stored(with_state: bool, last_push: Option<(String, String, Option<String>)>, stored: Option<(String, String, String)>) -> Rig {
        let dir = TestDir::new("active");
        let (store, writer) = Store::open(&dir).unwrap();
        if let Some((mgmt, system, version)) = stored {
            writer.exec(
                Db::Config,
                "INSERT INTO device_config (mac, ts, cfgversion, mgmt_cfg, system_cfg) VALUES (?1, 0, ?2, ?3, ?4)",
                vec![Sql::Text(AP.into()), Sql::Text(version), Sql::Text(wire::cfgdiff::redact(&mgmt)), Sql::Text(wire::cfgdiff::redact(&system))],
            );
            flushed(&writer);
        }
        let live: SharedLive = Default::default();
        {
            let mut l = live.write().unwrap();
            if with_state {
                l.state = Some(Arc::new(fixture("controller-state.json")));
            }
            if let Some((mgmt_cfg, system_cfg, cfgversion)) = last_push {
                l.last_config.insert(AP.parse().unwrap(), Arc::new(PushedConfig { mgmt_cfg, system_cfg, cfgversion }));
            }
        }
        let mut keys = KeyStore::default();
        keys.insert(AP, &hex::encode(KEY)).unwrap();
        let (tx, rx) = mpsc::channel(1000);
        let active = Arc::new(Active::new(&store, writer, live.clone(), Arc::new(keys), tx, controller(), Default::default()).unwrap());
        let app = axum::Router::new().route("/inform", axum::routing::post(inform)).with_state(active.clone());
        Rig { app, live, rx, active, _dir: dir }
    }

    fn controller() -> apcfg::Controller {
        apcfg::Controller {
            host: "unifi.example.net".into(),
            version: "10.6.106".into(),
            reporter_uuid: "00000000-0000-4000-8000-000000000004".into(),
            ..Default::default()
        }
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
    async fn inform_as_ap(rig: &Rig, payload: &Value, key: [u8; 16], flags: Flags) -> (StatusCode, Option<(Flags, Value)>) {
        let mac: Mac = payload["mac"].as_str().unwrap().parse().unwrap();
        let packet = inform::seal(mac, flags, random_bytes::<16>(), &key, payload.to_string().as_bytes());
        let (status, body) = send(rig, packet).await;
        if status != StatusCode::OK {
            return (status, None);
        }
        let pkt = Packet::parse(&body).unwrap();
        let reply: Value = serde_json::from_slice(&pkt.open(&key).expect("reply decrypts with the AP's key")).unwrap();
        (status, Some((pkt.header.flags, reply)))
    }

    const GCM_ZLIB: Flags = Flags(Flags::ENCRYPTED.0 | Flags::GCM.0 | Flags::ZLIB.0);

    #[test]
    fn the_inform_interval_stays_within_what_the_insights_allow_for() {
        let macs: Vec<Mac> = (0..=255u8).map(|b| Mac([0x02, 0, 0, 0, 0x10, b])).collect();
        for n in 0..40 {
            for &mac in &macs {
                let i = interval(mac, n);
                assert!((10..=MAX_INFORM_INTERVAL).contains(&i), "{n} APs: {i}");
                assert_eq!(interval(mac, n), i, "the same AP is asked for the same interval");
            }
        }
        assert!(macs.iter().any(|&m| interval(m, 30) == MAX_INFORM_INTERVAL), "a large site reaches the longest");
        let spread: std::collections::HashSet<Ts> = macs.iter().map(|&m| interval(m, 30)).collect();
        assert_eq!(spread.len(), 31, "and the APs are spread over the whole range");
    }

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
            crate::actions::edit_client(&mut state, "aa:bb:cc:00:00:09".parse().unwrap(), &[("blocked", json!(true))]);
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
        assert_eq!(flags, Flags::ENCRYPTED | Flags::GCM, "same mode as the request, never compressed");
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
    async fn the_engine_hears_the_interval_and_each_push() {
        let Some(_) = fixtures() else { return };
        let mut rig = rig(true, None);
        let replied = |rig: &mut Rig| {
            std::iter::from_fn(|| rig.rx.try_recv().ok()).filter_map(|i| if let Input::Replied { payload, .. } = i { Some(payload) } else { None }).collect::<Vec<_>>()
        };
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        let version = reply.unwrap().1["cfgversion"].as_str().unwrap().to_string();
        assert_eq!(replied(&mut rig).iter().map(|p| p["_type"].as_str()).collect::<Vec<_>>(), [Some("setparam")]);
        // A heartbeat sets the interval: the engine must know it to tell when the AP is gone.
        inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        let r = replied(&mut rig);
        assert_eq!((r.len(), r[0]["_type"].as_str()), (1, Some("noop")));
        let interval = r[0]["interval"].as_i64().unwrap();
        // Once the engine has that interval, a heartbeat is only counted.
        let live = rig.live.clone();
        let seen = |interval: Ts| {
            let snapshot = crate::model::parse(0, &ap_payload(&version)).unwrap();
            let d = crate::engine::DeviceView { snapshot, online: true, first_seen: 0, last_seen: 0, peer: None, interval, last_full_inform: 0, last_config_push: None };
            live.write().unwrap().devices.insert(AP.parse().unwrap(), d);
        };
        seen(interval);
        let replies = || live.read().unwrap().counters.replies.load(std::sync::atomic::Ordering::Relaxed);
        let before = replies();
        inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        assert!(replied(&mut rig).is_empty());
        assert_eq!(replies(), before + 1);
        // Another interval than the engine's is heard.
        seen(interval + 1);
        inform_as_ap(&rig, &ap_payload(&version), KEY, GCM_ZLIB).await;
        assert_eq!(replied(&mut rig).len(), 1);
        // A notification's bare noop sets nothing.
        let mut notif = ap_payload(&version);
        notif["inform_as_notif"] = json!(true);
        inform_as_ap(&rig, &notif, KEY, GCM_ZLIB).await;
        assert!(replied(&mut rig).is_empty());
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
    async fn a_settings_edit_after_the_stored_push_means_a_push() {
        let Some(_) = fixtures() else { return };
        let probe = rig(true, None);
        let payload = ap_payload("abcdefabcdefabcd");
        let out = probe.active.render(&probe.live.read().unwrap().state.clone().unwrap(), AP.parse().unwrap(), &payload, "abcdefabcdefabcd").unwrap();
        // The stored push is masked: a password changed in apctl since would not show.
        let rig = rig_with_stored(true, None, Some((out.rendered.mgmt_cfg, out.rendered.system_cfg, "abcdefabcdefabcd".into())));
        rig.active.writer.exec(Db::Config, "INSERT INTO events (ts, kind, data) VALUES (5, 'settings_changed', '{}')", vec![]);
        flushed(&rig.active.writer);
        let (_, reply) = inform_as_ap(&rig, &payload, KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "setparam");
    }

    #[tokio::test]
    async fn a_readopted_ap_gets_its_full_config() {
        let Some(_) = fixtures() else { return };
        let ap: Mac = AP.parse().unwrap();
        // As imported from the other controller: the AP's record carries the
        // version of the last push stored for it, which apctl renders the same.
        let probe = rig(true, None);
        let state = probe.live.read().unwrap().state.clone().unwrap();
        let old = crate::adopt::device_doc(&state, &ap).unwrap()["cfgversion"].as_str().unwrap().to_string();
        let out = probe.active.render(&state, ap, &ap_payload(&old), &old).unwrap();
        let rig = rig_with_stored(true, None, Some((out.rendered.mgmt_cfg, out.rendered.system_cfg, old.clone())));
        // Reset, then adopted again.
        {
            let mut live = rig.live.write().unwrap();
            let mut state = live.state.as_deref().cloned().unwrap();
            crate::adopt::adopt_device(&mut state, &ap, &ap_payload("1")).unwrap();
            live.state = Some(Arc::new(state));
            live.adoption.adopting.insert(ap, 0);
        }
        let (_, reply) = inform_as_ap(&rig, &ap_payload(""), DEFAULT_KEY, GCM_ZLIB).await;
        let mgmt = reply.unwrap().1["mgmt_cfg"].as_str().unwrap().to_string();
        let value = |k: &str| mgmt.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')).unwrap().to_string();
        let (version, key_hex) = (value("cfgversion"), value("authkey"));
        assert_ne!(version, old, "a new version, not the record's");
        let key: [u8; 16] = inform::parse_key(&key_hex).unwrap();
        assert_ne!(key, KEY, "a new key: the old one went out under the factory key");
        // Another inform under the factory key gets the same reply, without a new render.
        let (_, again) = inform_as_ap(&rig, &ap_payload(""), DEFAULT_KEY, GCM_ZLIB).await;
        assert_eq!(again.unwrap().1["mgmt_cfg"], mgmt.as_str());
        // Back with its new key, on the factory config with only mgmt_cfg: the full config follows.
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&version), key, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!(reply["_type"], "setparam");
        assert!(reply["system_cfg"].as_str().unwrap().lines().count() > 100);
        assert!(rig.active.adoption_cfgs.lock().unwrap().is_empty());
        // Applied: heartbeats from then on.
        let pushed = reply["cfgversion"].as_str().unwrap().to_string();
        let (_, reply) = inform_as_ap(&rig, &ap_payload(&pushed), key, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
    }

    #[tokio::test]
    async fn radio_settings_are_taken_from_an_inform_that_lists_radios() {
        let Some(_) = fixtures() else { return };
        let mut rig = rig(true, None);
        let ap: Mac = AP.parse().unwrap();
        {
            // As if adopted over SSH: no radio settings yet.
            let mut live = rig.live.write().unwrap();
            let mut state = live.state.as_deref().cloned().unwrap();
            crate::adopt::device_doc_mut(&mut state, &ap).unwrap()["radio_table"] = json!([]);
            live.state = Some(Arc::new(state));
        }
        let edits = |rig: &mut Rig| std::iter::from_fn(|| rig.rx.try_recv().ok()).filter_map(|i| if let Input::EditState { edit, .. } = i { Some(edit) } else { None }).collect::<Vec<_>>();
        // An inform that lists none changes nothing (each change makes every AP inform again).
        let mut none = ap_payload("1");
        none["radio_table"] = json!([]);
        let (_, reply) = inform_as_ap(&rig, &none, KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
        assert!(edits(&mut rig).is_empty());
        // One that lists them: their settings, once.
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
        inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        let mut edits = edits(&mut rig);
        assert_eq!(edits.len(), 2, "the engine has not applied the first yet");
        let mut state = rig.live.read().unwrap().state.as_deref().cloned().unwrap();
        let first = edits.remove(0);
        assert!(first(&mut state).is_ok());
        assert!(!crate::adopt::device_doc(&state, &ap).unwrap()["radio_table"].as_array().unwrap().is_empty());
        assert!(edits.remove(0)(&mut state).is_err(), "the second changes nothing");
    }

    #[tokio::test]
    async fn an_ap_adopted_over_ssh_joins_the_channel_locks_with_its_radios() {
        let Some(_) = fixtures() else { return };
        let mut rig = rig(true, None);
        let ap: Mac = AP.parse().unwrap();
        {
            let mut live = rig.live.write().unwrap();
            let mut state = live.state.as_deref().cloned().unwrap();
            crate::adopt::device_doc_mut(&mut state, &ap).unwrap()["radio_table"] = json!([]);
            // Every SSID it broadcasts has the IoT channel lock.
            for w in state["wlanconf"].as_array_mut().unwrap() {
                w["iot_channel_lock"] = json!(true);
            }
            live.state = Some(Arc::new(state));
        }
        inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        let edit = std::iter::from_fn(|| rig.rx.try_recv().ok()).find_map(|i| if let Input::EditState { edit, .. } = i { Some(edit) } else { None }).unwrap();
        let mut state = rig.live.read().unwrap().state.as_deref().cloned().unwrap();
        let what = edit(&mut state).unwrap();
        assert!(what.contains("2.4 GHz channel 6"), "{what}");
        let radios = crate::adopt::device_doc(&state, &ap).unwrap()["radio_table"].as_array().unwrap().clone();
        assert_eq!(radios.iter().find(|r| r["radio"] == "ng").unwrap()["channel"], "6");
        assert!(radios.iter().filter(|r| r["radio"] != "ng").all(|r| r["channel"] == "auto"), "the other bands stay on auto");
    }

    #[tokio::test]
    async fn an_upgrade_that_cannot_be_sent_fails_at_once() {
        let Some(_) = fixtures() else { return };
        let mut rig = rig(true, None);
        let (_, reply) = inform_as_ap(&rig, &ap_payload("1111111111111111"), KEY, GCM_ZLIB).await;
        let version = reply.unwrap().1["cfgversion"].as_str().unwrap().to_string();
        rig.live.write().unwrap().firmware.enqueue(vec![crate::firmware::Job {
            mac: AP.parse().unwrap(),
            name: None,
            from: None,
            target: "8.8.12.20200".into(),
            url: "https://fw-download.example/U6M-8.8.12.bin".into(),
            md5: None,
            sha256: None,
            custom: false,
            state: crate::firmware::JobState::Queued,
            sent_at: None,
            expires: None,
        }]);
        let mut offline = ap_payload(&version);
        offline["internet"] = json!(false);
        let (_, reply) = inform_as_ap(&rig, &offline, KEY, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
        assert!(rig.live.read().unwrap().firmware.current.is_none());
        let failed = std::iter::from_fn(|| rig.rx.try_recv().ok()).find_map(|i| if let Input::Note(e) = i && e.kind == EventKind::ApUpgradeFailed { Some(e.data) } else { None }).unwrap();
        assert_eq!((failed["reason"].as_str(), failed["target"].as_str()), (Some("not sent"), Some("8.8.12.20200")));
        assert!(failed["detail"].as_str().unwrap().contains("internet"));
    }

    #[tokio::test]
    async fn refuses_unencrypted_informs() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        // Plain JSON under an adopted AP's MAC "opens" with its key: it must not count.
        for flags in [Flags::NONE, Flags::ZLIB, Flags::GCM, Flags::GCM | Flags::ZLIB] {
            let (status, _) = inform_as_ap(&rig, &ap_payload("1"), KEY, flags).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "flags {flags:?}");
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
        let packet = inform::seal("02:00:00:00:00:01".parse().unwrap(), GCM_ZLIB, random_bytes::<16>(), &KEY, {
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
    fn only_a_digest_of_the_config_is_stored_and_old_rows_keep_their_version() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let ap: Mac = AP.parse().unwrap();
        let state = rig.live.read().unwrap().state.clone().unwrap();
        let render = rig.active.placeholder_render(&state, ap, &ap_payload("1")).unwrap();
        // As written before digests: the rendered text itself, secrets and all.
        let text = format!("{}\n--\n{}\n--\n{}", render.out.rendered.mgmt_cfg, render.out.rendered.system_cfg, render.blocked);
        let (a, w) = (&rig.active, &rig.active.writer);
        w.exec(Db::Config, "INSERT INTO managed_devices (mac, cfgversion, content, gcm, updated) VALUES (?1, 'abcdefabcdefabcd', ?2, 1, 0)", vec![Sql::Text(AP.into()), Sql::Text(text)]);
        flushed(w);
        // After a restart it reads as the digest of the same render: the config is current, under the version it had.
        let (tx, _rx) = mpsc::channel(10);
        let again = Active::new(&a.store, w.clone(), rig.live.clone(), a.keys.clone(), tx, controller(), Default::default()).unwrap();
        assert_eq!(again.devices.lock().unwrap()[&ap].content, Some(render.digest));
        assert_eq!(again.decide_version(ap, "abcdefabcdefabcd", &render, false), "abcdefabcdefabcd");
        // And the row is rewritten with the digest alone.
        flushed(w);
        let stored: String = a.store.read(Db::Config, |c| Ok(c.query_row("SELECT content FROM managed_devices WHERE mac = ?1", [AP], |r| r.get(0))?)).unwrap();
        assert_eq!(stored, hex::encode(render.digest));
        assert_eq!(stored_digest(&stored), (render.digest, false));
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
    fn inform_inputs_match_as_the_inputs_compare() {
        let base = json!({ "fw_caps": 1, "uptime": 5, "vap_table": [{ "name": "ath0", "tx_bytes": 9 }], "port_table": [{ "ifname": "eth0" }] });
        let inputs = apcfg::inform_inputs(&base);
        let changed = |f: &dyn Fn(&mut Value)| {
            let mut p = base.clone();
            f(&mut p);
            p
        };
        for p in [
            base.clone(),
            changed(&|p| p["uptime"] = json!(6)),
            changed(&|p| p["vap_table"][0]["tx_bytes"] = json!(10)),
            changed(&|p| p["has_eth1"] = json!(true)),
            changed(&|p| p["fw_caps"] = json!(2)),
            changed(&|p| p["vap_table"] = json!([{ "name": "ath0" }, { "name": "ath1" }])),
            changed(&|p| p["vap_table"] = json!({})),
            changed(&|p| p["port_table"] = Value::Null),
            changed(&|p| p["port_table"][0]["ifname"] = json!("eth1")),
            json!(null),
        ] {
            assert_eq!(apcfg::inform_inputs_match(&inputs, &p), apcfg::inform_inputs(&p) == inputs, "{p}");
        }
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
        assert_eq!(Arc::strong_count(&copy), 1, "the cached render does not keep the settings");
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
        let key: [u8; 16] = inform::parse_key(&key_hex).unwrap();
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
        assert!(rig.live.read().unwrap().adoption.forgetting.is_empty(), "the forget is finished once");
    }

    #[tokio::test]
    async fn an_ap_is_adopted_even_when_its_full_config_cannot_be_rendered() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let new: Mac = "02:00:00:00:00:09".parse().unwrap();
        let mut payload = ap_payload("1");
        payload["mac"] = json!(new.to_string());
        {
            let mut live = rig.live.write().unwrap();
            let mut state = live.state.as_deref().cloned().unwrap();
            crate::adopt::adopt_device(&mut state, &new, &payload).unwrap();
            // As after setting the SSH password in apctl: system_cfg cannot be rendered.
            for s in state["setting"].as_array_mut().unwrap().iter_mut().filter(|s| s["key"] == "mgmt") {
                s.as_object_mut().unwrap().retain(|k, _| !k.starts_with("x_ssh_") || !k.ends_with("passwd"));
            }
            live.state = Some(Arc::new(state));
            live.adoption.adopting.insert(new, 0);
        }
        let key_hex = crate::adopt::device_doc(rig.live.read().unwrap().state.as_deref().unwrap(), &new).unwrap()["x_authkey"].as_str().unwrap().to_string();
        let (_, reply) = inform_as_ap(&rig, &payload, DEFAULT_KEY, GCM_ZLIB).await;
        let reply = reply.unwrap().1;
        assert_eq!(reply["_type"], "setparam");
        assert!(reply["mgmt_cfg"].as_str().unwrap().contains(&format!("authkey={key_hex}")));
        // Its full config waits for the settings to be fixed.
        let key: [u8; 16] = inform::parse_key(&key_hex).unwrap();
        let (_, reply) = inform_as_ap(&rig, &payload, key, GCM_ZLIB).await;
        assert_eq!(reply.unwrap().1["_type"], "noop");
    }

    #[tokio::test]
    async fn a_factory_key_inform_under_a_managed_mac_changes_nothing() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        // Anyone can send this (the factory key is public): listed, but the AP keeps its AES-GCM pin.
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), DEFAULT_KEY, Flags::ENCRYPTED).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), KEY, Flags::ENCRYPTED).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "still no CBC");
    }

    #[tokio::test]
    async fn a_forgotten_ap_leaves_nothing_behind_in_active_mode() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let mac: Mac = AP.parse().unwrap();
        inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        assert!(rig.active.devices.lock().unwrap().get(&mac).is_some_and(|d| d.gcm && d.content.is_some()));
        // The engine calls this however the AP is forgotten, reporting or not (see `Engine::forget`).
        rig.active.adoption_cfgs.lock().unwrap().insert(mac, (Weak::new(), "authkey=x".into()));
        let forget = rig.live.read().unwrap().forget_managed.clone().expect("set by Active::new");
        forget(&mac);
        assert!(!rig.active.devices.lock().unwrap().contains_key(&mac));
        assert!(rig.active.adoption_cfgs.lock().unwrap().is_empty(), "nor the mgmt_cfg of an adoption");
    }

    #[tokio::test]
    async fn an_adoption_that_timed_out_drops_its_mgmt_cfg() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let new: Mac = "02:00:00:00:00:09".parse().unwrap();
        let mut payload = ap_payload("1");
        payload["mac"] = json!(new.to_string());
        {
            let mut live = rig.live.write().unwrap();
            let mut state = live.state.as_deref().cloned().unwrap();
            crate::adopt::adopt_device(&mut state, &new, &payload).unwrap();
            live.state = Some(Arc::new(state));
            live.adoption.adopting.insert(new, 0);
        }
        inform_as_ap(&rig, &payload, DEFAULT_KEY, GCM_ZLIB).await;
        assert!(rig.active.adoption_cfgs.lock().unwrap().contains_key(&new));
        crate::adopt::expire(&mut rig.live.write().unwrap(), crate::adopt::ADOPT_TIMEOUT);
        let (status, _) = inform_as_ap(&rig, &payload, DEFAULT_KEY, GCM_ZLIB).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(rig.active.adoption_cfgs.lock().unwrap().is_empty());
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
    async fn a_factory_key_inform_is_ignored_while_the_ap_informs_with_its_own() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let mac: Mac = AP.parse().unwrap();
        let seen = |last_seen: Ts| {
            let snapshot = crate::model::parse(last_seen, &ap_payload("1")).unwrap();
            let d = crate::engine::DeviceView {
                snapshot, online: true, first_seen: 0, last_seen, peer: None, interval: 10,
                last_full_inform: last_seen, last_config_push: None,
            };
            rig.live.write().unwrap().devices.insert(mac, d);
        };
        seen(clock::now_ts());
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), DEFAULT_KEY, GCM_ZLIB).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!rig.live.read().unwrap().adoption.pending.contains_key(&mac), "not offered for adoption");
        // Quiet for long enough: it was reset.
        seen(clock::now_ts() - RESET_QUIET_SECS - 1);
        inform_as_ap(&rig, &ap_payload("1"), DEFAULT_KEY, GCM_ZLIB).await;
        assert!(rig.live.read().unwrap().adoption.pending.get(&mac).is_some_and(|p| p.known));
    }

    #[tokio::test]
    async fn no_cbc_after_gcm_and_cbc_replies_for_cbc_devices() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        no_gcm_on_record(&rig);
        // A CBC-only exchange is answered in CBC.
        let (status, reply) = inform_as_ap(&rig, &ap_payload("1"), KEY, Flags::ENCRYPTED).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reply.unwrap().0, Flags::ENCRYPTED);
        // Once the device has used GCM, CBC is refused.
        inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), KEY, Flags::ENCRYPTED).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_ap_whose_record_says_aes_gcm_may_not_use_cbc_from_the_first_inform() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let ap: Mac = AP.parse().unwrap();
        {
            let mut live = rig.live.write().unwrap();
            let mut state = live.state.as_deref().cloned().unwrap();
            crate::adopt::device_doc_mut(&mut state, &ap).unwrap()["x_aes_gcm"] = json!(true);
            live.state = Some(Arc::new(state));
        }
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), KEY, Flags::ENCRYPTED).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "as imported from the other controller");
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), KEY, GCM_ZLIB).await;
        assert_eq!(status, StatusCode::OK);
        // Without the flag, CBC is answered until the AP has used AES-GCM.
        let rig = self::rig(true, None);
        no_gcm_on_record(&rig);
        let (status, _) = inform_as_ap(&rig, &ap_payload("1"), KEY, Flags::ENCRYPTED).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The AP's record without `x_aes_gcm` (the fixture's has it, as imported).
    fn no_gcm_on_record(rig: &Rig) {
        let mut live = rig.live.write().unwrap();
        let mut state = live.state.as_deref().cloned().unwrap();
        crate::adopt::device_doc_mut(&mut state, &AP.parse().unwrap()).unwrap().as_object_mut().unwrap().remove("x_aes_gcm");
        live.state = Some(Arc::new(state));
    }

    #[tokio::test]
    async fn a_factory_key_inform_under_a_mac_apctl_no_longer_has_drops_its_stored_record() {
        let Some(_) = fixtures() else { return };
        let rig = rig(true, None);
        let gone = "02:00:00:00:00:77";
        let w = &rig.active.writer;
        w.exec(Db::Config, "INSERT INTO managed_devices (mac, cfgversion, content, gcm, updated) VALUES (?1, 'abcdefabcdefabcd', NULL, 1, 0)", vec![Sql::Text(gone.into())]);
        flushed(w);
        let restarted = |rig: &Rig| {
            let (tx, _rx) = mpsc::channel(10);
            let a = &rig.active;
            Active::new(&a.store, a.writer.clone(), rig.live.clone(), a.keys.clone(), tx, controller(), Default::default()).unwrap()
        };
        let again = Arc::new(restarted(&rig));
        assert!(again.devices.lock().unwrap().contains_key(&gone.parse().unwrap()));
        let app = axum::Router::new().route("/inform", axum::routing::post(inform)).with_state(again);
        let rig = Rig { app, ..rig };
        let mut stranger = ap_payload("1");
        stranger["mac"] = json!(gone);
        let (status, _) = inform_as_ap(&rig, &stranger, DEFAULT_KEY, GCM_ZLIB).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        flushed(&rig.active.writer);
        // After another restart, nothing of it comes back (its version, its AES-GCM pin).
        assert!(!restarted(&rig).devices.lock().unwrap().contains_key(&gone.parse().unwrap()));
    }

    #[tokio::test]
    async fn informs_beyond_what_may_wait_are_turned_away() {
        let gate = Gate::new(1, 3 * WAIT_OVERHEAD);
        let first = gate.enter(0).await.expect("a free permit is taken at once");
        // Two may wait (the bound is in bytes); a third is turned away.
        let waiting: Vec<_> = (0..2).map(|_| Box::pin(gate.enter(WAIT_OVERHEAD / 2))).collect();
        let mut waiting: Vec<_> = waiting.into_iter().map(|mut w| {
            assert!(futures_poll(&mut w).is_none(), "waits for the permit");
            w
        }).collect();
        assert!(gate.enter(WAIT_OVERHEAD / 2).await.is_none());
        // One that gives up waiting (its AP hung up) makes room again.
        drop(waiting.pop());
        let mut third = Box::pin(gate.enter(WAIT_OVERHEAD / 2));
        assert!(futures_poll(&mut third).is_none());
        drop(first);
        assert!(waiting.pop().unwrap().await.is_some());
        drop(third);
        assert_eq!(gate.waiting.load(Ordering::Relaxed), 0, "nothing counted as waiting once they are gone");
    }

    /// Polls a future once.
    fn futures_poll<F: std::future::Future + Unpin>(f: &mut F) -> Option<F::Output> {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match std::pin::Pin::new(f).poll(&mut cx) {
            std::task::Poll::Ready(v) => Some(v),
            std::task::Poll::Pending => None,
        }
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
