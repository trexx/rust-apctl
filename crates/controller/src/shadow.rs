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
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Informs this far behind the wall clock come from a capture being replayed
/// (a saved file, or a backlog).
const REPLAY_LAG_SECS: i64 = 120;
/// How often a replay ticks the engine, in capture time.
const REPLAY_TICK_SECS: i64 = 5;

/// `replaying` is set while the capture runs behind the wall clock. The engine's
/// clock then follows the capture: the capture sends the ticks (in capture
/// time) and the wall-clock ticks pause, or every AP and client would look gone
/// between two replayed informs.
pub fn spawn(source: Source, ports: Vec<u16>, syslog_port: u16, keys: Arc<KeyStore>, tx: mpsc::Sender<Input>, replaying: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("shadow-capture".into())
        .spawn(move || {
            let mut backoff = Duration::from_secs(1);
            loop {
                let started = std::time::Instant::now();
                // A panic in the capture reader ends this run like an error does,
                // rather than shadow mode for good.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match &source {
                    Source::Stdin => run_once(std::io::stdin(), &ports, syslog_port, &keys, &tx, &replaying),
                    Source::Path(p) => match std::fs::File::open(p) {
                        Ok(f) => run_once(std::io::BufReader::new(f), &ports, syslog_port, &keys, &tx, &replaying),
                        Err(e) => Err(anyhow::anyhow!("opening {}: {e}", p.display())),
                    },
                    Source::Command(cmd) => run_command(cmd, &ports, syslog_port, &keys, &tx, &replaying),
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("the capture reader panicked")));
                replaying.store(false, Ordering::Relaxed);
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

fn run_command(cmd: &str, ports: &[u16], syslog_port: u16, keys: &KeyStore, tx: &mpsc::Sender<Input>, replaying: &AtomicBool) -> anyhow::Result<()> {
    tracing::info!("starting shadow capture: {cmd}");
    let mut child = Command::new("sh").arg("-c").arg(cmd).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    // The command is stopped even when the reader panics.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_once(stdout, ports, syslog_port, keys, tx, replaying)));
    let _ = child.kill();
    let _ = child.wait();
    result.unwrap_or_else(|_| Err(anyhow::anyhow!("the capture reader panicked")))
}

fn run_once<R: Read + Send>(
    input: R,
    ports: &[u16],
    syslog_port: u16,
    keys: &KeyStore,
    tx: &mpsc::Sender<Input>,
    replaying: &AtomicBool,
) -> anyhow::Result<()> {
    let mut pairer = Pairer::default();
    let mut last_tick = 0;
    capture::run_with_udp(input, ports, &[syslog_port], |event| {
        // AP syslog sent to the other controller's address.
        if let capture::HttpEvent::Datagram { ts, src, payload, .. } = event {
            let _ = tx.blocking_send(Input::Datagram { ts: ts / 1_000_000, src_ip: src.ip().to_string(), payload });
            return;
        }
        // A message the decoder cannot cope with is skipped, not the whole capture:
        // the pairer starts afresh, as its half-paired exchanges may be inconsistent.
        let ev = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pairer.handle(keys, event))) {
            Ok(Some(ev)) => ev,
            Ok(None) => return,
            Err(_) => {
                tracing::warn!("skipped a captured message the decoder panicked on");
                pairer = Pairer::default();
                return;
            }
        };
        let mut tick = None;
        let input = match ev {
            InformEvent::Inform { ts, peer, decoded: Ok(decoded), .. } => {
                let ts = ts / 1_000_000;
                let behind = ts < crate::store::now_ts() - REPLAY_LAG_SECS;
                replaying.store(behind, Ordering::Relaxed);
                if behind && ts >= last_tick + REPLAY_TICK_SECS {
                    last_tick = ts;
                    tick = Some(Input::Tick(ts));
                }
                Some(Input::Inform { ts, peer, decoded })
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
        if let Some(tick) = tick {
            let _ = tx.blocking_send(tick);
        }
    })
}
