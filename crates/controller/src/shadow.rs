//! Shadow mode: learn everything from a packet capture of the traffic between
//! APs and another controller, without the APs knowing we exist.
//!
//! The capture arrives as a pcap stream: stdin, a file or FIFO (reopened when
//! it ends, for a tcpdump sidecar), or a command whose stdout is pcap
//! (restarted with backoff, e.g. `kubectl exec ... tcpdump -w -`).

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use wire::capture;
use wire::exchange::{InformEvent, Pairer};
use wire::keys::KeyStore;

use crate::engine::Input;

#[derive(Debug, Clone)]
pub enum Source {
    Stdin,
    Path(PathBuf),
    Command(String),
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Stdin => write!(f, "stdin"),
            Source::Path(p) => write!(f, "{}", p.display()),
            Source::Command(c) => write!(f, "command `{c}`"),
        }
    }
}

pub fn spawn(source: Source, ports: Vec<u16>, syslog_port: u16, keys: Arc<KeyStore>, tx: mpsc::Sender<Input>) {
    std::thread::Builder::new()
        .name("shadow-capture".into())
        .spawn(move || {
            let mut backoff = Duration::from_secs(1);
            loop {
                let started = std::time::Instant::now();
                let result = match &source {
                    Source::Stdin => run_once(std::io::stdin(), &ports, syslog_port, &keys, &tx),
                    Source::Path(p) => match std::fs::File::open(p) {
                        Ok(f) => run_once(std::io::BufReader::new(f), &ports, syslog_port, &keys, &tx),
                        Err(e) => Err(anyhow::anyhow!("opening {}: {e}", p.display())),
                    },
                    Source::Command(cmd) => run_command(cmd, &ports, syslog_port, &keys, &tx),
                };
                match result {
                    Ok(()) => tracing::warn!("shadow capture from {source} ended"),
                    Err(e) => tracing::warn!("shadow capture from {source} failed: {e:#}"),
                }
                // Stdin and regular files are read once; FIFOs and commands are
                // live feeds that are reopened when they end.
                let is_regular_file = matches!(&source, Source::Path(p) if p.metadata().is_ok_and(|m| m.is_file()));
                if matches!(source, Source::Stdin) || is_regular_file || tx.is_closed() {
                    return;
                }
                if started.elapsed() > Duration::from_secs(60) {
                    backoff = Duration::from_secs(1);
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        })
        .expect("spawning the capture thread");
}

fn run_command(cmd: &str, ports: &[u16], syslog_port: u16, keys: &KeyStore, tx: &mpsc::Sender<Input>) -> anyhow::Result<()> {
    tracing::info!("starting shadow capture: {cmd}");
    let mut child = Command::new("sh").arg("-c").arg(cmd).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let result = run_once(stdout, ports, syslog_port, keys, tx);
    let _ = child.kill();
    let _ = child.wait();
    result
}

fn run_once<R: Read + Send>(
    input: R,
    ports: &[u16],
    syslog_port: u16,
    keys: &KeyStore,
    tx: &mpsc::Sender<Input>,
) -> anyhow::Result<()> {
    let mut pairer = Pairer::default();
    capture::run_with_udp(input, ports, &[syslog_port], |event| {
        // AP syslog sent to the other controller's address.
        if let capture::HttpEvent::Datagram { ts, src, payload, .. } = event {
            let _ = tx.blocking_send(Input::Datagram { ts: ts / 1_000_000, src_ip: src.ip().to_string(), payload });
            return;
        }
        let Some(ev) = pairer.handle(keys, event) else { return };
        let input = match ev {
            InformEvent::Inform { ts, peer, decoded: Ok(decoded), .. } => {
                Some(Input::Inform { ts: ts / 1_000_000, peer, decoded })
            }
            InformEvent::Inform { decoded: Err(e), mac, .. } => {
                tracing::debug!("undecodable inform from {mac:?}: {e:#}");
                Some(Input::DecodeError)
            }
            InformEvent::Reply { ts, mac: Some(mac), decoded: Some(Ok(decoded)), .. } => {
                Some(Input::Reply { ts: ts / 1_000_000, mac, decoded })
            }
            InformEvent::Reply { .. } => None,
        };
        if let Some(input) = input {
            // Blocks when the engine is behind, which back-pressures the capture.
            let _ = tx.blocking_send(input);
        }
    })
}
