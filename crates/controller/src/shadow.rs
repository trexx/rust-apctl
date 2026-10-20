//! Shadow mode: learn everything from a packet capture of the traffic between
//! APs and another controller, without the APs knowing we exist.
//!
//! The capture arrives as a pcap stream: stdin, a file or FIFO (reopened when
//! it ends, for a tcpdump sidecar), or a command whose stdout is pcap
//! (restarted with backoff, e.g. `kubectl exec ... tcpdump -w -`).

use std::io::Read;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use wire::capture;
use wire::exchange::{InformEvent, Pairer};
use wire::keys::KeyStore;

use crate::engine::Input;
use crate::model::Ts;

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

/// The engine's clock in shadow mode, which follows the capture's: how far the
/// capture runs behind the wall clock, as of its latest inform.
///
/// A live capture can lag (tcpdump buffering, a slow pipe): the wall-clock
/// ticks are moved back by the lag, or an AP would look gone between two of
/// its informs. A capture further behind than `REPLAY_LAG_SECS` is a replay:
/// it sends the ticks itself, in capture time, and the wall-clock ticks pause
/// until it ends, or until it has gone `REPLAY_LAG_SECS` without an inform (a
/// live feed that stalled behind): time then runs on from where the capture
/// got to, so the APs it no longer shows informing time out.
#[derive(Debug, Default)]
pub struct Clock {
    lag: AtomicI64,
    /// The wall-clock time of the latest inform noted.
    seen: AtomicI64,
}

impl Clock {
    /// The engine's time now, or `None` while a replay ticks in its own time.
    pub fn now(&self) -> Option<Ts> {
        let lag = self.lag.load(Ordering::Acquire);
        let wall = crate::clock::now_ts();
        (lag <= REPLAY_LAG_SECS || wall - self.seen.load(Ordering::Relaxed) > REPLAY_LAG_SECS).then_some(wall - lag)
    }

    /// Notes an inform's capture time; true if the capture is being replayed.
    fn observe(&self, ts: Ts) -> bool {
        let wall = crate::clock::now_ts();
        let lag = (wall - ts).max(0);
        self.seen.store(wall, Ordering::Relaxed);
        self.lag.store(lag, Ordering::Release);
        lag > REPLAY_LAG_SECS
    }

    fn reset(&self) {
        self.lag.store(0, Ordering::Release);
    }
}

/// `clock` follows the capture (see [`Clock`]).
pub fn spawn(source: Source, ports: Vec<u16>, syslog_port: u16, keys: Arc<KeyStore>, tx: mpsc::Sender<Input>, clock: Arc<Clock>) {
    std::thread::Builder::new()
        .name("shadow-capture".into())
        .spawn(move || {
            let mut backoff = Duration::from_secs(1);
            loop {
                let started = std::time::Instant::now();
                // A panic in the capture reader ends this run like an error does,
                // rather than shadow mode for good.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match &source {
                    Source::Stdin => run_once(std::io::stdin(), &ports, syslog_port, &keys, &tx, &clock),
                    // The capture reader has its own buffer.
                    Source::Path(p) => match std::fs::File::open(p) {
                        Ok(f) => run_once(f, &ports, syslog_port, &keys, &tx, &clock),
                        Err(e) => Err(anyhow::anyhow!("opening {}: {e}", p.display())),
                    },
                    Source::Command(cmd) => run_command(cmd, &ports, syslog_port, &keys, &tx, &clock),
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("the capture reader panicked")));
                clock.reset();
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

fn run_command(cmd: &str, ports: &[u16], syslog_port: u16, keys: &KeyStore, tx: &mpsc::Sender<Input>, clock: &Clock) -> anyhow::Result<()> {
    tracing::info!("starting shadow capture: {cmd}");
    let mut child = Command::new("sh").arg("-c").arg(cmd).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    // The command is stopped even when the reader panics.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_once(stdout, ports, syslog_port, keys, tx, clock)));
    let _ = child.kill();
    let _ = child.wait();
    result.unwrap_or_else(|_| Err(anyhow::anyhow!("the capture reader panicked")))
}

/// A capture's input that ends at the next read once `stop` is set.
struct Until<'a, R> {
    input: R,
    stop: &'a AtomicBool,
}

impl<R: Read> Read for Until<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.stop.load(Ordering::Relaxed) {
            return Ok(0);
        }
        self.input.read(buf)
    }
}

/// Reads one capture into the engine. Once the engine is gone, the capture
/// ends (a live one would otherwise be read for ever) with an error.
fn run_once<R: Read + Send>(
    input: R,
    ports: &[u16],
    syslog_port: u16,
    keys: &KeyStore,
    tx: &mpsc::Sender<Input>,
    clock: &Clock,
) -> anyhow::Result<()> {
    let mut pairer = Pairer::default();
    let mut last_tick = 0;
    let stop = AtomicBool::new(false);
    // Blocks when the engine is behind, which back-pressures the capture.
    let send = |input: Input| {
        if tx.blocking_send(input).is_err() {
            stop.store(true, Ordering::Relaxed);
        }
    };
    let end = capture::run_with_udp(Until { input, stop: &stop }, ports, &[syslog_port], |event| {
        // Once the engine is gone the run stops; what is left of the reader's buffer is not decoded.
        if stop.load(Ordering::Relaxed) {
            return ControlFlow::Break(());
        }
        // AP syslog sent to the other controller's address.
        if let capture::HttpEvent::Datagram { ts, src, payload, .. } = event {
            send(Input::Datagram { ts: ts / 1_000_000, src_ip: src.ip().to_string(), payload });
            return ControlFlow::Continue(());
        }
        // A message the decoder cannot cope with is skipped, not the whole capture:
        // the pairer starts afresh, as its half-paired exchanges may be inconsistent.
        let ev = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pairer.handle(keys, event))) {
            Ok(Some(ev)) => ev,
            Ok(None) => return ControlFlow::Continue(()),
            Err(_) => {
                tracing::warn!("skipped a captured message the decoder panicked on");
                pairer = Pairer::default();
                return ControlFlow::Continue(());
            }
        };
        let mut tick = None;
        let input = match ev {
            InformEvent::Inform { ts, peer, decoded: Ok(decoded), .. } => {
                let ts = ts / 1_000_000;
                if clock.observe(ts) && ts >= last_tick + REPLAY_TICK_SECS {
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
            send(input);
        }
        if let Some(tick) = tick {
            send(tick);
        }
        ControlFlow::Continue(())
    });
    if stop.load(Ordering::Relaxed) {
        anyhow::bail!("the engine has stopped");
    }
    let end = end?;
    if end == capture::End::Truncated {
        tracing::warn!("the shadow capture ends in the middle of a packet (truncated?); ignoring the rest");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_follows_a_lagging_capture_and_pauses_for_a_replay() {
        let clock = Clock::default();
        let now = crate::clock::now_ts();
        assert!(clock.now().is_some_and(|t| (now..now + 2).contains(&t)), "no capture yet: the wall clock");
        // A live capture 90 s behind: ticks in its time, or every AP would look offline.
        assert!(!clock.observe(now - 90));
        assert!(clock.now().is_some_and(|t| (now - 90..now - 88).contains(&t)));
        // A replay sends its own ticks.
        assert!(clock.observe(now - 3600));
        assert_eq!(clock.now(), None);
        // One that has sent nothing for a while has stalled: its time runs on.
        clock.seen.store(now - REPLAY_LAG_SECS - 10, Ordering::Relaxed);
        assert!(clock.now().is_some_and(|t| (now - 3600..now - 3598).contains(&t)));
        clock.reset();
        assert!(clock.now().is_some());
    }

    /// An endless live capture: a pcap header, then the same syslog datagram for ever.
    struct Endless {
        data: Vec<u8>,
        /// Where the record starts in `data`, and how far it has been read.
        record: usize,
        at: usize,
        served: usize,
    }

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Read this far, the capture was not stopped.
            assert!(self.served < 64 << 20, "the capture is still being read");
            if self.at == self.data.len() {
                self.at = self.record;
            }
            let n = buf.len().min(self.data.len() - self.at);
            buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
            (self.at, self.served) = (self.at + n, self.served + n);
            Ok(n)
        }
    }

    #[test]
    fn a_live_capture_stops_once_the_engine_is_gone() {
        use wire::synth::{Endpoint, udp_frame, write_pcap_header, write_pcap_record};
        let (ap, controller) = (Endpoint { mac: [2, 0, 0, 0, 0, 1], ip: [192, 0, 2, 10], port: 40000 }, Endpoint { mac: [2, 0, 0, 0, 0, 2], ip: [192, 0, 2, 1], port: 5514 });
        let mut data = Vec::new();
        write_pcap_header(&mut data, 65535).unwrap();
        let record = data.len();
        write_pcap_record(&mut data, 1_000_000, &udp_frame(ap, controller, b"<14>hostapd: hello").unwrap()).unwrap();
        let (tx, rx) = mpsc::channel(4);
        drop(rx);
        let mut input = Endless { data, record, at: 0, served: 0 };
        let err = run_once(&mut input, &[8080], 5514, &KeyStore::default(), &tx, &Clock::default()).unwrap_err();
        assert!(err.to_string().contains("the engine has stopped"), "{err:#}");
        // It ends within a buffer or so of the first send that failed.
        assert!(input.served <= 4 << 20, "{} bytes read", input.served);
    }
}
