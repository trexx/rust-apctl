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
mod clock;
mod connections;
mod dryrun;
mod engine;
mod firmware;
mod insights;
mod logevents;
mod model;
mod ratelimit;
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
    /// Inform port(s) in the capture.
    #[arg(long = "inform-port", env = "APCTL_INFORM_PORT", default_value = "8080")]
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
    let proxies = Arc::new(auth::Proxies::parse(&trusted_proxies)?);
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
    tracing::info!("loaded {} device keys and {} syslog keys", keys.len(), keys.syslog_len());
    let keys = Arc::new(keys);

    let backups = backup::Backups::new(data_dir.clone(), backup_key.as_deref().map(backup::load_key).transpose()?);
    if backups.key.is_none() {
        tracing::warn!("no --backup-key: backups are written unencrypted");
    }
    // A restore chosen in the UI is applied now, before the databases are opened.
    backup::apply_pending(&backups);
    let (store, writer) = store::Store::open(&data_dir)?;
    let live: SharedLive = Default::default();
    let (live_tx, _) = broadcast::channel(4096);
    let (in_tx, mut in_rx) = mpsc::channel::<Input>(10_000);

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
        spawn_syslog(addr, in_tx.clone()).await?;
    }

    // The engine owns all mutable state and processes inputs in order.
    let mut engine = Engine::new(writer.clone(), keys.clone(), live.clone(), live_tx.clone());
    engine.restore(&store)?;
    // The config generator, for dry runs.
    let renderer = dryrun::apcfg_renderer(emulate_version.clone());
    engine.set_renderer(renderer.clone());
    // Alert-worthy events reach the alert watcher on a channel of their own.
    let (alert_sink, alert_events) = alerts::channel();
    engine.set_alerts(alert_sink);
    let tick_tx = in_tx.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(5));
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
        while let Some(input) = in_rx.blocking_recv() {
            engine.handle(input);
        }
    })?;

    if active {
        let url = inform_url.clone().unwrap_or_else(|| format!("http://unifi:{}/inform", inform_listen.port()));
        let controller = dryrun::controller(url, emulate_version, reporter_id(&store)?);
        let active_state = active::Active::new(&store, writer.clone(), live.clone(), keys.clone(), in_tx.clone(), controller, proxies.clone())?;
        start_active(Arc::new(active_state), inform_url, inform_listen, stun_listen).await?;
    }

    let users = match &users_file {
        Some(p) => auth::Users::load(p)?,
        None => auth::Users::default(),
    };
    if users.is_empty() {
        tracing::warn!("no users configured: the API is read-only and needs no login");
    } else {
        tracing::info!("login enabled for {} user(s)", users.len());
    }
    let auth = Arc::new(auth::Auth::new(users, &store, writer.clone(), proxies)?);
    threats::watch(store.clone(), live.clone(), in_tx.clone(), writer.clone());
    alerts::spawn(store.clone(), writer.clone(), live.clone(), live_tx.clone(), alert_events);
    backup::schedule(backups.clone(), store.clone());
    firmware::schedule(writer.clone());
    let state = api::AppState { backups, active, writer: writer.clone(), store, vendors: Arc::new(vendors), renderer, auth, engine: in_tx.clone(), live, tx: api::live_json(&live_tx), started: store::now_ts(), source: source_desc };
    channelai::schedule(state.clone());
    ratelimit::spawn(state.clone());
    adopt::spawn(state.clone());
    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
    tracing::info!("web UI and API on http://{listen}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(shutdown(writer.clone())).await?;
    flush_writes(writer).await;
    Ok(())
}

/// Receives AP syslog on `addr` and hands each datagram to the engine.
async fn spawn_syslog(addr: SocketAddr, tx: mpsc::Sender<Input>) -> Result<()> {
    let socket = tokio::net::UdpSocket::bind(addr).await.with_context(|| format!("binding syslog {addr}"))?;
    tracing::info!("receiving AP syslog on udp://{addr}");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        // Syslog shares the engine's queue with the informs: when the queue is
        // full, datagrams are dropped (and counted) rather than holding up the
        // APs' informs behind a flood.
        let (mut dropped, mut last_warning) = (0u64, None::<std::time::Instant>);
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    // An IPv4 AP on a dual-stack socket goes by its IPv4 address, as its informs report it.
                    let input = Input::Datagram { ts: store::now_ts(), src_ip: src.ip().to_canonical().to_string(), payload: buf[..n].to_vec() };
                    match tx.try_send(input) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            dropped += 1;
                            if last_warning.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                                tracing::warn!("engine busy: dropped {dropped} syslog datagram(s)");
                                (dropped, last_warning) = (0, Some(std::time::Instant::now()));
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
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
        let b: [u8; 16] = { let mut b = [0u8; 16]; getrandom::fill(&mut b).expect("random"); b };
        let h = hex::encode(b);
        format!("{}-{}-4{}-a{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
    }))
}

/// Active mode's servers: STUN (`inform_url`'s host is the address its answers
/// give), and the APs' informs, on listeners of their own.
async fn start_active(state: Arc<active::Active>, inform_url: Option<String>, inform_listen: SocketAddr, stun_listen: SocketAddr) -> Result<()> {
    let advertised = match &inform_url {
        Some(u) => advertised_ip(u).await,
        None => None,
    };
    if let Some(u) = inform_url {
        ssh::set_inform_url(u);
    }
    if let Err(e) = stun::serve(stun_listen, advertised).await {
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
    let candidates: Vec<_> = keys.syslog_keys().map(|(mac, key)| (*mac, *key)).collect();
    let input = wire::capture::open_input(pcap)?;
    wire::capture::run_with_udp(input, &[], &[port], |ev| {
        if let wire::capture::HttpEvent::Datagram { ts, src, payload, .. } = ev {
            let found = candidates.iter().find_map(|(mac, key)| syslog::open(&payload, |_| Some((*mac, *key))).ok());
            match found {
                Some((mac, text)) => {
                    if std::env::var_os("APCTL_DEBUG_RAW").is_some() {
                        println!("raw: {:?}", text.chars().take(70).collect::<String>());
                    }
                    let line = syslog::parse(ts / 1_000_000, src.ip().to_string(), mac, &text);
                    println!("{} {:?} prog={:?} sev={:?} {}", line.ts, line.device_mac, line.program, line.severity, line.msg);
                }
                None => println!("{ts} {src}: could not decode {} bytes", payload.len()),
            }
        }
    })
}

/// Resolves on Ctrl-C or SIGTERM (what Kubernetes sends). Open WebSockets would
/// keep a graceful shutdown waiting forever, so the process exits after a short
/// grace period regardless, once the queued writes are committed.
async fn shutdown(writer: store::Writer) {
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
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        flush_writes(writer).await;
        std::process::exit(0);
    });
}

/// The address put in STUN answers: the host of the inform URL, resolved once
/// (IPv4). None if it does not resolve; the socket's own address is used then.
async fn advertised_ip(inform_url: &str) -> Option<std::net::IpAddr> {
    let host = inform_url.split("://").nth(1)?.split([':', '/']).next()?;
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
