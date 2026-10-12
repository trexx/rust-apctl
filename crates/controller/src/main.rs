//! apctl (working title): a controller for Ubiquiti access points.
//!
//! Milestone 2 runs in shadow mode: it learns everything from a capture of
//! another controller's traffic and never talks to the APs itself.

mod api;
mod engine;
mod model;
mod shadow;
mod store;
mod syslog;
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
    Serve {
        /// Directory for config.db, metrics.db and logs.db.
        #[arg(long, env = "APCTL_DATA_DIR", default_value = "data")]
        data_dir: PathBuf,
        /// Device keys: an `informdump import` snapshot or a MAC->key JSON map.
        #[arg(long, env = "APCTL_KEYS")]
        keys: Option<String>,
        /// Shadow mode: pcap stream to read ("-" for stdin, or a file/FIFO path).
        #[arg(long, env = "APCTL_SHADOW", conflicts_with = "shadow_cmd")]
        shadow: Option<String>,
        /// Shadow mode: command whose stdout is a pcap stream (restarted if it exits).
        #[arg(long, env = "APCTL_SHADOW_CMD")]
        shadow_cmd: Option<String>,
        /// Inform port(s) in the capture.
        #[arg(long = "inform-port", env = "APCTL_INFORM_PORT", default_value = "8080")]
        inform_ports: Vec<u16>,
        /// Address for the web UI and API.
        #[arg(long, env = "APCTL_LISTEN", default_value = "127.0.0.1:8090")]
        listen: SocketAddr,
        /// UDP address to receive AP syslog on (e.g. 0.0.0.0:5514). Shadow mode also
        /// picks syslog sent to the other controller out of the capture.
        #[arg(long, env = "APCTL_SYSLOG_LISTEN")]
        syslog_listen: Option<SocketAddr>,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    match Cli::parse().cmd {
        Cmd::Serve { data_dir, keys, shadow, shadow_cmd, inform_ports, listen, syslog_listen } => {
            serve(data_dir, keys, shadow, shadow_cmd, inform_ports, listen, syslog_listen).await
        }
        Cmd::DebugSyslog { pcap, keys, port } => debug_syslog(&pcap, &keys, port),
    }
}

async fn serve(
    data_dir: PathBuf,
    keys: Option<String>,
    shadow: Option<String>,
    shadow_cmd: Option<String>,
    inform_ports: Vec<u16>,
    listen: SocketAddr,
    syslog_listen: Option<SocketAddr>,
) -> Result<()> {
    let keys = match &keys {
        Some(p) => KeyStore::load(p)?,
        None => KeyStore::default(),
    };
    tracing::info!("loaded {} device keys and {} syslog keys", keys.len(), keys.syslog_len());
    let keys = Arc::new(keys);

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
    let mut engine = Engine::new(writer, keys.clone(), live.clone(), live_tx.clone());
    engine.restore(&store)?;
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

    let state = api::AppState { store, live, tx: live_tx, started: store::now_ts(), source: source_desc };
    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
    tracing::info!("web UI and API on http://{listen}");
    axum::serve(listener, app).with_graceful_shutdown(shutdown()).await?;
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
