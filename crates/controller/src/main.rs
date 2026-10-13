//! apctl (working title): a controller for Ubiquiti access points.
//!
//! Milestone 2 runs in shadow mode: it learns everything from a capture of
//! another controller's traffic and never talks to the APs itself.

mod actions;
mod active;
mod alerts;
mod api;
mod auth;
mod backup;
mod connections;
mod dryrun;
mod engine;
mod firmware;
mod insights;
mod logevents;
mod model;
mod shadow;
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

#[derive(Parser)]
#[command(version, about = "Controller for Ubiquiti access points")]
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
    #[arg(long, env = "APCTL_EMULATE_VERSION", default_value = "10.6.106")]
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
    /// File holding the 64-hex-character key that encrypts backups (e.g. from a
    /// SealedSecret). Without it backups are written unencrypted.
    #[arg(long, env = "APCTL_BACKUP_KEY")]
    pub backup_key: Option<PathBuf>,
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
            let render = dryrun::apcfg_renderer("10.6.106".into());
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
        oui_file, backup_key,
    } = args;
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

    let backups = backup::Backups { data_dir: data_dir.clone(), key: backup_key.as_deref().map(backup::load_key).transpose()? };
    if backups.key.is_none() {
        tracing::warn!("no --backup-key: backups are written unencrypted");
    }
    // A restore chosen in the UI is applied now, before the databases are opened.
    backup::apply_pending(&backups)?;
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
    let source_desc = source.as_ref().map_or("none".to_string(), |s| s.to_string());
    match source {
        Some(src) => {
            tracing::info!("shadow mode: reading inform traffic from {src}");
            let syslog_port = syslog_listen.map_or(5514, |a| a.port());
            shadow::spawn(src, inform_ports, syslog_port, keys.clone(), in_tx.clone());
        }
        None if active => {}
        None => tracing::warn!("no shadow source configured: nothing will be ingested"),
    }

    if let Some(addr) = syslog_listen {
        let socket = tokio::net::UdpSocket::bind(addr).await.with_context(|| format!("binding syslog {addr}"))?;
        tracing::info!("receiving AP syslog on udp://{addr}");
        let tx = in_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        let input = Input::Datagram { ts: store::now_ts(), src_ip: src.ip().to_string(), payload: buf[..n].to_vec() };
                        if tx.send(input).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => tracing::warn!("syslog socket: {e}"),
                }
            }
        });
    }

    // The engine owns all mutable state and processes inputs in order.
    let mut engine = Engine::new(writer.clone(), keys.clone(), live.clone(), live_tx.clone());
    engine.restore(&store)?;
    // The config generator, for dry runs.
    let renderer: Option<dryrun::RenderFn> = Some(dryrun::apcfg_renderer(emulate_version.clone()));
    if let Some(r) = &renderer {
        engine.set_renderer(r.clone());
    }
    let tick_tx = in_tx.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(5));
        loop {
            every.tick().await;
            if tick_tx.send(Input::Tick(store::now_ts())).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(input) = in_rx.recv().await {
            engine.handle(input);
        }
    });

    if active {
        // The other controller's installation ID, so rendered configs stay identical
        // to what the APs run; a new one only when none was ever seen.
        let reporter: Option<String> = store.read(store::Db::Config, |c| {
            let cfgs: Vec<String> =
                c.prepare("SELECT system_cfg FROM device_config")?.query_map([], |r| r.get::<_, Option<String>>(0))?.flatten().flatten().collect();
            Ok(cfgs.iter().find_map(|cfg| cfg.lines().find_map(|l| l.strip_prefix("unifi.reporterid=")).map(str::to_string)))
        })?;
        let controller = apcfg::Controller {
            inform_url: format!("http://unifi:{}/inform", inform_listen.port()),
            mgmt_url: "https://unifi:8443".into(),
            stun_url: "stun://unifi:3478/".into(),
            syslog_ip: None,
            version: emulate_version,
            reporter_uuid: reporter.unwrap_or_else(|| {
                let b: [u8; 16] = { let mut b = [0u8; 16]; getrandom::fill(&mut b).expect("random"); b };
                let h = hex::encode(b);
                format!("{}-{}-4{}-a{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
            }),
        };
        let active_state = Arc::new(active::Active::new(&store, writer.clone(), live.clone(), keys.clone(), in_tx.clone(), controller)?);
        let inform_app = axum::Router::new().route("/inform", axum::routing::post(active::inform)).with_state(active_state);
        let inform_socket = tokio::net::TcpListener::bind(inform_listen).await.with_context(|| format!("binding {inform_listen}"))?;
        tracing::warn!("ACTIVE MODE: answering AP informs on http://{inform_listen}/inform and pushing config");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(inform_socket, inform_app.into_make_service_with_connect_info::<SocketAddr>()).await {
                tracing::error!("inform server stopped: {e}");
            }
        });
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
    let auth = Arc::new(auth::Auth::new(users, &store, writer.clone())?);
    threats::watch(store.clone(), live.clone(), in_tx.clone());
    alerts::spawn(store.clone(), writer.clone(), live.clone(), live_tx.clone());
    backup::schedule(backups.clone(), store.clone());
    firmware::schedule(writer.clone());
    let state = api::AppState { backups: Some(backups), active, writer: Some(writer.clone()), store, vendors: Arc::new(vendors), renderer, auth, engine: in_tx.clone(), live, tx: live_tx, started: store::now_ts(), source: source_desc };
    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
    tracing::info!("web UI and API on http://{listen}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(shutdown()).await?;
    Ok(())
}

fn debug_syslog(pcap: &str, keys: &str, port: u16) -> Result<()> {
    let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(keys)?)?;
    let mut candidates = Vec::new();
    for d in raw["devices"].as_array().into_iter().flatten() {
        if let (Some(mac), Some(k)) = (d["mac"].as_str(), d["syslog_key"].as_str()) {
            let key: [u8; 32] = hex::decode(k)?.try_into().map_err(|_| anyhow::anyhow!("bad syslog key"))?;
            candidates.push((mac.parse::<inform::Mac>()?, key));
        }
    }
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
/// grace period regardless.
async fn shutdown() {
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
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        std::process::exit(0);
    });
}
