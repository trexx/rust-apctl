//! apctl (working title): a controller for Ubiquiti access points.
//!
//! Milestone 2 runs in shadow mode: it learns everything from a capture of
//! another controller's traffic and never talks to the APs itself.

mod actions;
mod adopt;
mod active;
mod alerts;
mod api;
mod auth;
mod backup;
mod channelai;
mod channelplan;
mod clock;
mod connections;
mod dryrun;
mod engine;
mod firmware;
mod insights;
mod logevents;
mod model;
mod ratelimit;
mod series;
mod settings;
mod shadow;
mod site;
mod ssh;
mod stun;
mod store;
mod syslog;
mod threats;
mod vendor;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::{broadcast, mpsc};
use tracing_subscriber::EnvFilter;
use wire::keys::KeyStore;

use engine::{Engine, Input, SharedLive};

/// The controller version rendered configs claim by default (`--emulate-version`).
const EMULATE_VERSION: &str = "10.6.106";

#[derive(Parser)]
#[command(version, about = "Controller for UniFi access points")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the controller.
    Serve(Box<ServeArgs>),
    /// Read a password from stdin and print its Argon2id hash for the users file.
    HashPassword,
    /// Print the config apctl would generate for one AP (for debugging the generator).
    DebugRender {
        /// Settings snapshot (`informdump import` output).
        #[arg(long)]
        state: PathBuf,
        /// The AP's latest inform payload as JSON (e.g. from `informdump pcap --save`).
        #[arg(long)]
        inform: PathBuf,
        #[arg(long)]
        mac: String,
        #[arg(long, default_value = "0000000000000000")]
        cfgversion: String,
    },
    /// Decode AP syslog datagrams in a pcap file by trying each known syslog key.
    DebugSyslog {
        pcap: String,
        #[arg(long)]
        keys: String,
        #[arg(long, default_value = "5514")]
        port: u16,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Directory for config.db, metrics.db and logs.db.
    #[arg(long, env = "APCTL_DATA_DIR", default_value = "data")]
    pub data_dir: PathBuf,
    /// Device keys: an `informdump import` snapshot or a MAC->key JSON map.
    #[arg(long, env = "APCTL_KEYS")]
    pub keys: Option<String>,
    /// Shadow mode: pcap stream to read ("-" for stdin, or a file/FIFO path).
    #[arg(long, env = "APCTL_SHADOW", conflicts_with = "shadow_cmd")]
    pub shadow: Option<String>,
    /// Shadow mode: command whose stdout is a pcap stream (restarted if it exits).
    #[arg(long, env = "APCTL_SHADOW_CMD")]
    pub shadow_cmd: Option<String>,
    /// Inform port(s) in the capture, comma-separated or repeated.
    #[arg(long = "inform-port", env = "APCTL_INFORM_PORT", default_value = "8080", value_delimiter = ',')]
    pub inform_ports: Vec<u16>,
    /// Address for the web UI and API.
    #[arg(long, env = "APCTL_LISTEN", default_value = "127.0.0.1:8090")]
    pub listen: SocketAddr,
    /// UDP address to receive AP syslog on (e.g. 0.0.0.0:5514). Shadow mode also
    /// picks syslog sent to the other controller out of the capture.
    #[arg(long, env = "APCTL_SYSLOG_LISTEN")]
    pub syslog_listen: Option<SocketAddr>,
    /// File of `username:argon2-hash` lines (see `apctl hash-password`).
    /// Without it apctl is read-only and needs no login.
    #[arg(long, env = "APCTL_USERS_FILE")]
    pub users_file: Option<PathBuf>,
    /// Controller version to emulate in rendered configs (`unifi.version`). The dry run
    /// compares with the existing controller, so this should match its version.
    #[arg(long, env = "APCTL_EMULATE_VERSION", default_value = EMULATE_VERSION)]
    pub emulate_version: String,
    /// Active mode: answer the APs' informs and push config. Off by default;
    /// cannot be combined with shadow mode.
    #[arg(long, env = "APCTL_ACTIVE", conflicts_with_all = ["shadow", "shadow_cmd"])]
    pub active: bool,
    /// IEEE MAC prefix registry (oui.csv) for manufacturer names; optional.
    #[arg(long, env = "APCTL_OUI_FILE", default_value = "/usr/share/apctl/oui.csv")]
    pub oui_file: PathBuf,
    /// Where to receive informs in active mode.
    #[arg(long, env = "APCTL_INFORM_LISTEN", default_value = "0.0.0.0:8080")]
    pub inform_listen: SocketAddr,
    /// The URL APs should inform to, given to APs adopted over SSH (e.g.
    /// http://unifi.example:8080/inform). Defaults to the one the managed APs use.
    #[arg(long, env = "APCTL_INFORM_URL")]
    pub inform_url: Option<String>,
    /// Where to answer STUN in active mode (the APs' `stun_url`; also used to
    /// ask APs to inform right away).
    #[arg(long, env = "APCTL_STUN_LISTEN", default_value = "0.0.0.0:3478")]
    pub stun_listen: SocketAddr,
    /// File holding the 64-hex-character key that encrypts backups (e.g. from a
    /// SealedSecret). Without it backups are written unencrypted.
    #[arg(long, env = "APCTL_BACKUP_KEY")]
    pub backup_key: Option<PathBuf>,
    /// Reverse proxies in front of apctl, as comma-separated addresses or CIDR
    /// ranges (e.g. 10.42.0.0/16). X-Forwarded-For is only believed on
    /// connections from these, for the login throttle and AP addresses; by
    /// default it is ignored.
    #[arg(long, env = "APCTL_TRUSTED_PROXIES", value_delimiter = ',')]
    pub trusted_proxies: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    match Cli::parse().cmd {
        Cmd::Serve(args) => serve(*args).await,
        Cmd::HashPassword => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let password = line.trim_end_matches(['\n', '\r']);
            anyhow::ensure!(password.chars().count() >= 8, "use a password of at least 8 characters");
            println!("{}", auth::hash_password(password)?);
            Ok(())
        }
        Cmd::DebugSyslog { pcap, keys, port } => debug_syslog(&pcap, &keys, port),
        Cmd::DebugRender { state, inform, mac, cfgversion } => {
            let state: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&state)?)?;
            let inform: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&inform)?)?;
            let render = dryrun::apcfg_renderer(EMULATE_VERSION.into());
            let req = dryrun::RenderRequest { state: &state, device_mac: &mac, inform: Some(&inform), cfgversion: &cfgversion, previous_system_cfg: None };
            let (mgmt, system) = render(&req)?;
            println!("# mgmt_cfg\n{mgmt}\n# system_cfg\n{system}");
            Ok(())
        }
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    let ServeArgs {
        data_dir, keys, shadow, shadow_cmd, inform_ports, listen, syslog_listen, users_file, emulate_version, active, inform_listen,
        oui_file, backup_key, inform_url, stun_listen, trusted_proxies,
    } = args;
    // The configuration is read first: a mistake in it stops the start before
    // anything has changed (a staged restore applied) or started listening.
    let proxies = Arc::new(auth::Proxies::parse(&trusted_proxies)?);
    let users = match &users_file {
        Some(p) => auth::Users::load(p)?,
        None => auth::Users::default(),
    };
    let backups = backup::Backups::new(data_dir.clone(), backup_key.as_deref().map(backup::load_key).transpose()?);
    let vendors = match vendor::Vendors::load(&oui_file) {
        Ok(v) => {
            tracing::info!("loaded {} manufacturer prefixes from {}", v.len(), oui_file.display());
            v
        }
        Err(e) => {
            tracing::warn!("no manufacturer names: {e:#}");
            vendor::Vendors::default()
        }
    };
    let keys = match &keys {
        Some(p) => KeyStore::load(p)?,
        None => KeyStore::default(),
    };
    for why in keys.skipped() {
        tracing::warn!("device keys: {why}");
    }
    tracing::info!("loaded {} device keys and {} syslog keys", keys.len(), keys.syslog_len());
    let keys = Arc::new(keys);
    if users.is_empty() {
        tracing::warn!("no users configured: the API is read-only and needs no login");
    } else {
        tracing::info!("login enabled for {} user(s)", users.len());
    }
    if backups.key.is_none() {
        tracing::warn!("no --backup-key: backups are written unencrypted");
    }

    // A restore chosen in the UI is applied now, before the databases are opened.
    backup::apply_pending(&backups);
    let (store, writer) = store::Store::open(&data_dir)?;
    let live: SharedLive = Default::default();
    let (live_tx, _) = broadcast::channel(4096);
    let (in_tx, in_rx) = mpsc::channel::<Input>(10_000);

    let source = match (shadow, shadow_cmd) {
        (Some(s), _) if s == "-" => Some(shadow::Source::Stdin),
        (Some(s), _) => Some(shadow::Source::Path(s.into())),
        (None, Some(c)) => Some(shadow::Source::Command(c)),
        (None, None) => None,
    };
    let clock = Arc::new(shadow::Clock::default());
    let source_desc = source.as_ref().map_or("none".to_string(), |s| s.to_string());
    match source {
        Some(src) => {
            tracing::info!("shadow mode: reading inform traffic from {src}");
            let syslog_port = syslog_listen.map_or(5514, |a| a.port());
            shadow::spawn(src, inform_ports, syslog_port, keys.clone(), in_tx.clone(), clock.clone());
        }
        None if active => {}
        None => tracing::warn!("no shadow source configured: nothing will be ingested"),
    }

    if let Some(addr) = syslog_listen {
        let counters = live.read().unwrap().counters.clone();
        spawn_syslog(addr, in_tx.clone(), counters).await?;
    }

    // The engine owns all mutable state and processes inputs in order.
    let mut engine = Engine::new(writer.clone(), keys.clone(), live.clone(), live_tx.clone());
    engine.restore(&store)?;
    // The controller the configs describe: in active mode, the configs pushed
    // name this controller's own address and ports; else the official defaults.
    let controller = if active {
        let (host, inform_port) = inform_address(inform_url.as_deref(), inform_listen);
        apcfg::Controller { host, inform_port, stun_port: stun_listen.port(), ..dryrun::controller(emulate_version, reporter_id(&store)?) }
    } else {
        dryrun::controller(emulate_version, String::new())
    };
    // The config generator, for dry runs: what active mode would push.
    let renderer = dryrun::renderer_for(&controller);
    engine.set_renderer(renderer.clone());
    // Alert-worthy events reach the alert watcher on a channel of their own.
    let (alert_sink, alert_events) = alerts::channel();
    engine.set_alerts(alert_sink);
    let alert_clock = clock.clone();
    let tick_tx = in_tx.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(5));
        // Ticks missed while the engine's queue was full are not made up back to back.
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            // The capture's time in shadow mode; a replay ticks itself (see `shadow::Clock`).
            let Some(now) = clock.now() else { continue };
            if tick_tx.send(Input::Tick(now)).await.is_err() {
                return;
            }
        }
    });
    // The engine is synchronous and at times busy (diffs, dry-run renders): it
    // gets a thread of its own rather than an async worker.
    let runtime = tokio::runtime::Handle::current();
    let (drain, closing, drained) = Drain::new(in_tx.clone());
    std::thread::Builder::new().name("engine".into()).spawn(move || {
        // However the thread ends, its queue closes with it, which /healthz reports.
        struct Stopped;
        impl Drop for Stopped {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    tracing::error!("the engine stopped after a panic: nothing more is processed");
                }
            }
        }
        let _stopped = Stopped;
        let _runtime = runtime.enter();
        engine_loop(in_rx, &closing, &drained, |input| engine.handle(input));
    })?;

    if active {
        let active_state = active::Active::new(&store, writer.clone(), live.clone(), keys.clone(), in_tx.clone(), controller, proxies.clone())?;
        start_active(Arc::new(active_state), &live, inform_url.as_deref(), inform_listen, stun_listen).await?;
    }

    let auth = Arc::new(auth::Auth::new(users, &store, writer.clone(), proxies)?);
    let threat_state: Arc<threats::ThreatState> = Default::default();
    threats::watch(store.clone(), threat_state.clone(), live.clone(), in_tx.clone(), writer.clone());
    alerts::spawn(store.clone(), writer.clone(), live.clone(), live_tx.clone(), alert_events, alert_clock);
    backup::schedule(backups.clone(), store.clone());
    firmware::schedule(writer.clone());
    let state = api::AppState::new(api::AppStateInner {
        backups, active, writer: writer.clone(), store, vendors: Arc::new(vendors), renderer, auth, engine: in_tx.clone(), live, tx: api::live_json(&live_tx), started: clock::now_ts(),
        source: source_desc, inform_url: inform_url.filter(|_| active), memo: Default::default(), threats: threat_state,
    });
    channelai::schedule(state.clone());
    ratelimit::spawn(state.clone());
    adopt::spawn(state.clone());
    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
    tracing::info!("web UI and API on http://{listen}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(shutdown(writer.clone(), drain.clone())).await?;
    finish(writer, drain).await;
    Ok(())
}

/// The engine thread's loop: `handle` each input in turn, until the queue
/// closes. At exit (`closing`), nothing more is taken and what is queued still
/// is; `drained` tells when it is done.
fn engine_loop(mut queue: mpsc::Receiver<Input>, closing: &AtomicBool, drained: &tokio::sync::watch::Sender<bool>, mut handle: impl FnMut(Input)) {
    while let Some(input) = queue.blocking_recv() {
        handle(input);
        if closing.load(Ordering::Relaxed) {
            queue.close();
        }
    }
    let _ = drained.send(true);
}

/// How long an exit waits for the engine to handle what is queued.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Ends the engine's work at exit: it stops taking inputs and handles the
/// ones queued, so that their writes are among those committed last.
#[derive(Clone)]
struct Drain {
    closing: Arc<AtomicBool>,
    queue: mpsc::Sender<Input>,
    /// True once the engine's loop has ended; closed if the engine thread panicked.
    drained: tokio::sync::watch::Receiver<bool>,
}

impl Drain {
    /// The drain, and the engine thread's ends: the flag it checks after each input, and what it sets when done.
    fn new(queue: mpsc::Sender<Input>) -> (Drain, Arc<AtomicBool>, tokio::sync::watch::Sender<bool>) {
        let closing = Arc::new(AtomicBool::new(false));
        let (done, drained) = tokio::sync::watch::channel(false);
        (Drain { closing: closing.clone(), queue, drained }, closing, done)
    }

    /// Stops the engine taking inputs (it still handles the queued ones).
    fn start(&self) {
        self.closing.store(true, Ordering::Relaxed);
        // An idle engine is woken to see the flag. A full queue needs no
        // wake: the engine looks at the flag after the input it is on.
        let _ = self.queue.try_send(Input::Wake);
    }

    /// Waits for the queue to be handled, at most `DRAIN_TIMEOUT`.
    async fn wait(&self) {
        let mut drained = self.drained.clone();
        if tokio::time::timeout(DRAIN_TIMEOUT, drained.wait_for(|d| *d)).await.is_err() {
            let left = self.queue.max_capacity() - self.queue.capacity();
            tracing::warn!("the engine did not get through its queue before exit: {left} input(s) not handled");
        }
    }
}

/// What an exit does last: the engine's queue handled, then the writes committed.
async fn finish(writer: store::Writer, drain: Drain) {
    drain.start();
    drain.wait().await;
    flush_writes(writer).await;
}

/// Receives AP syslog on `addr` and hands each datagram to the engine.
async fn spawn_syslog(addr: SocketAddr, tx: mpsc::Sender<Input>, counters: Arc<engine::Counters>) -> Result<()> {
    let socket = tokio::net::UdpSocket::bind(addr).await.with_context(|| format!("binding syslog {addr}"))?;
    tracing::info!("receiving AP syslog on udp://{addr}");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        // Syslog shares the engine's queue with the informs: when the queue is
        // full, datagrams are dropped (and counted) rather than holding up the
        // APs' informs behind a flood. The drops are logged at most once a
        // minute, at the next datagram, whether that one gets through or not.
        let (mut dropped, mut last_warning) = (0u64, None::<std::time::Instant>);
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    // An IPv4 AP on a dual-stack socket goes by its IPv4 address, as its informs report it.
                    let input = Input::Datagram { ts: clock::now_ts(), src_ip: src.ip().to_canonical().to_string(), payload: buf[..n].to_vec() };
                    match tx.try_send(input) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            dropped += 1;
                            counters.syslog_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                    if dropped > 0 && last_warning.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                        tracing::warn!("engine busy: dropped {dropped} syslog datagram(s)");
                        (dropped, last_warning) = (0, Some(std::time::Instant::now()));
                    }
                }
                Err(e) => {
                    // A socket that keeps failing must not spin a core and flood the log.
                    tracing::warn!("syslog socket: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(())
}

/// The other controller's installation ID, so rendered configs stay identical
/// to what the APs run; a new one only when none was ever seen.
fn reporter_id(store: &store::Store) -> Result<String> {
    let seen: Option<String> = store.read(store::Db::Config, |c| {
        use rusqlite::OptionalExtension;
        let cfg: Option<String> = c
            .query_row("SELECT system_cfg FROM device_config WHERE instr(system_cfg, 'unifi.reporterid=') > 0 LIMIT 1", [], |r| r.get(0))
            .optional()?;
        Ok(cfg.and_then(|cfg| cfg.lines().find_map(|l| l.strip_prefix("unifi.reporterid=")).map(str::to_string)))
    })?;
    Ok(seen.unwrap_or_else(|| {
        let h = random_hex::<16>();
        format!("{}-{}-4{}-a{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
    }))
}

/// `N` bytes from the system's random source.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system random source");
    b
}

/// `N` random bytes, in hex.
pub(crate) fn random_hex<const N: usize>() -> String {
    hex::encode(random_bytes::<N>())
}

/// Active mode's servers: STUN (`inform_url`'s host is the address its answers
/// give), and the APs' informs, on listeners of their own.
async fn start_active(state: Arc<active::Active>, live: &SharedLive, inform_url: Option<&str>, inform_listen: SocketAddr, stun_listen: SocketAddr) -> Result<()> {
    let advertised = match inform_url {
        Some(u) => advertised_ip(u).await,
        None => None,
    };
    if let Err(e) = stun::serve(stun_listen, advertised, live).await {
        tracing::warn!("STUN not available on {stun_listen}: {e}");
    }
    let inform_app = axum::Router::new().route("/inform", axum::routing::post(active::inform)).with_state(state);
    let inform_socket = tokio::net::TcpListener::bind(inform_listen).await.with_context(|| format!("binding {inform_listen}"))?;
    tracing::warn!("ACTIVE MODE: answering AP informs on http://{inform_listen}/inform and pushing config");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(inform_socket, inform_app.into_make_service_with_connect_info::<SocketAddr>()).await {
            tracing::error!("inform server stopped: {e}");
        }
    });
    Ok(())
}

/// Commits the writes still queued (they are batched about once a second).
async fn flush_writes(writer: store::Writer) {
    let flushed = tokio::task::spawn_blocking(move || writer.flush(Duration::from_secs(5))).await.unwrap_or(false);
    if !flushed {
        tracing::warn!("pending writes could not be committed before exit");
    }
}

fn debug_syslog(pcap: &str, keys: &str, port: u16) -> Result<()> {
    let keys = KeyStore::load(keys)?;
    for why in keys.skipped() {
        tracing::warn!("device keys: {why}");
    }
    // Every key's cipher, set up once.
    let mut ciphers = syslog::Ciphers::default();
    ciphers.refresh(None, &keys);
    let input = wire::capture::open_input(pcap)?;
    let end = wire::capture::run_with_udp(input, &[], &[port], |ev| {
        if let wire::capture::HttpEvent::Datagram { ts, src, payload, .. } = ev {
            let found = if payload.starts_with(&syslog::MAGIC) {
                ciphers.all().find_map(|(mac, cipher)| Some((Some(mac), syslog::decrypt_with(&payload, mac, cipher).ok()?)))
            } else {
                Some((None, String::from_utf8_lossy(&payload).into_owned()))
            };
            match found {
                Some((mac, text)) => {
                    if std::env::var_os("APCTL_DEBUG_RAW").is_some() {
                        println!("raw: {:?}", text.chars().take(70).collect::<String>());
                    }
                    // Line by line, as the engine stores them (a datagram can carry several).
                    for line in text.lines().filter(|l| !l.trim().is_empty()) {
                        let line = syslog::parse(ts / 1_000_000, &src.ip().to_string(), mac, line);
                        println!("{} {:?} prog={:?} sev={:?} {}", line.ts, line.device_mac, line.program, line.severity, line.msg);
                    }
                }
                None => println!("{ts} {src}: could not decode {} bytes", payload.len()),
            }
        }
        std::ops::ControlFlow::Continue(())
    })?;
    if end == wire::capture::End::Truncated {
        tracing::warn!("the capture ends in the middle of a packet (truncated?); ignoring the rest");
    }
    Ok(())
}

/// Resolves on Ctrl-C or SIGTERM (what Kubernetes sends). Open WebSockets would
/// keep a graceful shutdown waiting forever, so the process exits after a short
/// grace period regardless, once the engine's queue is handled and the queued
/// writes are committed. The engine stops taking inputs at once.
async fn shutdown(writer: store::Writer, drain: Drain) {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
    }
    tracing::info!("shutting down");
    drain.start();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        finish(writer, drain).await;
        std::process::exit(0);
    });
}

/// The controller's host and inform port as pushed configs give them: those of
/// `inform_url` (port 80 when it names none, as for any http URL), else the
/// name `unifi` and the inform listener's port.
fn inform_address(inform_url: Option<&str>, inform_listen: SocketAddr) -> (String, u16) {
    let parsed = inform_url.and_then(|u| {
        let uri: axum::http::Uri = u.parse().ok()?;
        Some((uri.host()?.to_string(), uri.port_u16().unwrap_or(80)))
    });
    if parsed.is_none()
        && let Some(u) = inform_url
    {
        tracing::warn!("--inform-url {u} has no host: configs name the controller unifi:{}", inform_listen.port());
    }
    parsed.unwrap_or_else(|| ("unifi".into(), inform_listen.port()))
}

/// The address put in STUN answers: the host of the inform URL, an address
/// or a name resolved once (to IPv4). None if it does not resolve; the
/// socket's own address is used then.
async fn advertised_ip(inform_url: &str) -> Option<std::net::IpAddr> {
    let uri: axum::http::Uri = inform_url.parse().ok()?;
    // An IPv6 address comes in brackets (http://[fd00::1]:8080/inform).
    let host = uri.host()?.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse() {
        return Some(ip);
    }
    let lookup = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 0))).await;
    match lookup.map(|r| r.map(|mut addrs| addrs.find(|a| a.is_ipv4()))) {
        Ok(Ok(Some(a))) => Some(a.ip()),
        Ok(Ok(None)) => {
            tracing::warn!("{host} has no IPv4 address: STUN answers carry the socket's address");
            None
        }
        Ok(Err(e)) => {
            tracing::warn!("cannot resolve {host} ({e}): STUN answers carry the socket's address");
            None
        }
        Err(_) => {
            tracing::warn!("resolving {host} timed out: STUN answers carry the socket's address");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_name_the_inform_urls_host_and_port() {
        let listen: SocketAddr = "0.0.0.0:8081".parse().unwrap();
        let addr = |u: Option<&str>| inform_address(u, listen);
        assert_eq!(addr(Some("http://unifi.example.net:8088/inform")), ("unifi.example.net".into(), 8088));
        assert_eq!(addr(Some("http://unifi.example.net/inform")), ("unifi.example.net".into(), 80));
        assert_eq!(addr(Some("http://[fd00::1]:8080/inform")), ("[fd00::1]".into(), 8080));
        assert_eq!(addr(None), ("unifi".into(), 8081));
        assert_eq!(addr(Some("not a url")), ("unifi".into(), 8081));
    }

    #[test]
    fn inform_ports_take_a_comma_list_or_repeated_flags() {
        let ports = |args: &[&str]| match Cli::try_parse_from([&["apctl", "serve"], args].concat()).unwrap().cmd {
            Cmd::Serve(a) => a.inform_ports,
            _ => unreachable!(),
        };
        assert_eq!(ports(&["--inform-port", "8080,8443"]), [8080, 8443]);
        assert_eq!(ports(&["--inform-port", "8080", "--inform-port", "8443"]), [8080, 8443]);
    }

    #[tokio::test]
    async fn at_exit_the_engine_handles_what_is_queued_and_takes_nothing_more() {
        let (tx, rx) = mpsc::channel::<Input>(100);
        let (drain, closing, drained) = Drain::new(tx.clone());
        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = handled.clone();
        // Idle at first: the drain wakes it.
        let engine = std::thread::spawn(move || {
            engine_loop(rx, &closing, &drained, |_| {
                count.fetch_add(1, Ordering::Relaxed);
            })
        });
        drain.start();
        drain.wait().await;
        assert!(tx.is_closed() && tx.try_send(Input::DecodeError).is_err(), "nothing more is taken");
        engine.join().unwrap();
        assert_eq!(handled.load(Ordering::Relaxed), 1, "the wake-up only");

        // Busy: what is queued is handled before the end, though the queue is full.
        let (tx, rx) = mpsc::channel::<Input>(50);
        for _ in 0..50 {
            tx.try_send(Input::DecodeError).unwrap();
        }
        let (drain, closing, drained) = Drain::new(tx.clone());
        drain.start();
        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = handled.clone();
        let engine = std::thread::spawn(move || {
            engine_loop(rx, &closing, &drained, |_| {
                count.fetch_add(1, Ordering::Relaxed);
            })
        });
        drain.wait().await;
        engine.join().unwrap();
        assert_eq!(handled.load(Ordering::Relaxed), 50);
    }

    #[tokio::test]
    async fn the_advertised_address_is_the_inform_urls_host() {
        let ip = |s: &str| Some(s.parse::<std::net::IpAddr>().unwrap());
        assert_eq!(advertised_ip("http://192.0.2.1:8080/inform").await, ip("192.0.2.1"));
        assert_eq!(advertised_ip("http://192.0.2.1/inform").await, ip("192.0.2.1"));
        assert_eq!(advertised_ip("http://[fd00::1]:8080/inform").await, ip("fd00::1"));
        assert_eq!(advertised_ip("http://[fd00::1]/inform").await, ip("fd00::1"));
        assert_eq!(advertised_ip("not a url").await, None);
    }
}
