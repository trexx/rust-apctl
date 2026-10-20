//! Events from AP syslog lines. The official controller turns no syslog line
//! into an event (it stores the lines and only watches netconsole output for
//! kernel crashes); these are apctl's own, from what UniFi AP firmware logs:
//!
//! - `stamgr`: `kick-sta-on <client> <vap> (reason:Low RSSI rssi:19)`, a
//!   client disconnected by minimum RSSI (signal = rssi - 95 dBm);
//! - kernel `BTM:` lines: 802.11v BSS transition (steering) requests, their
//!   candidate APs, and the client's answer (status 0 accepts);
//! - `mcad` `log_sta_anomalies()`: why a client's experience is poor,
//!   reported when the reasons change, not on every line;
//! - `hostapd`: `AP-STA-POSSIBLE-PSK-MISMATCH <client>`, upstream hostapd's
//!   report of a client failing the handshake with what looks like a wrong
//!   password (not yet seen from these APs; matched strictly);
//! - crashes, as the official controller detects them in netconsole output:
//!   kernel oopses and panics, and processes killed by faults.

use std::collections::HashMap;

use inform::Mac;
use serde_json::{Value, json};

use crate::engine::{Event, EventKind, LogLine};
use crate::model::Ts;

/// Noise floor that `stamgr`'s relative RSSI is measured against.
const NOISE_FLOOR: i64 = -95;
/// How long a crash capture collects lines before it is reported.
const CRASH_WINDOW: Ts = 180;
/// After a crash is reported, another fault of the same AP within this long
/// starts no capture: a crash loop is one report per period, not one per boot.
const CRASH_COOLDOWN: Ts = 600;
/// At most this many crash captures at once (each is one AP's).
const MAX_CRASHES: usize = 64;
/// At most this many lines, and this much text, kept per crash capture.
const CRASH_LINES: usize = 200;
const CRASH_BYTES: usize = 64 * 1024;
/// At most this many entries in each map below: anyone can send syslog lines,
/// so made-up clients and senders must not grow them without bound.
const MAX_TRACKED: usize = 10_000;
/// At most this many candidate APs kept per steering request.
const MAX_TARGETS: usize = 16;
/// The longest a line's event is held back for repeating it (see
/// [`LogEvents::fresh`]), and so how long a report is remembered.
const MAX_REPEAT: Ts = 600;
/// How long after a steering request the client's answer is paired with it,
/// and so how long a request is kept.
const STEER_ANSWER: Ts = 30;
/// A client's unchanged experience problems are reported again after this
/// long, and forgotten then.
const ANOMALIES_AGAIN: Ts = 1800;

#[derive(Default)]
struct Steering {
    /// The device that made the request: only its candidate lines are the request's.
    from: Option<Source>,
    ts: Ts,
    rssi: Option<i64>,
    candidates: Option<i64>,
    targets: Vec<Value>,
    vap: Option<String>,
}

/// What kind of fault a crash capture started with (or ended in).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrashKind {
    Panic,
    Oops,
    Segfault,
    MemoryFault,
}

impl CrashKind {
    /// As the event's data names it.
    fn as_str(self) -> &'static str {
        match self {
            CrashKind::Panic => "kernel panic",
            CrashKind::Oops => "kernel oops",
            CrashKind::Segfault => "process crashed (segmentation fault)",
            CrashKind::MemoryFault => "process crashed (memory fault)",
        }
    }
}

/// The fault a kernel line reports, if any, with the process it killed.
fn fault(msg: &str) -> Option<(CrashKind, Option<String>)> {
    if msg.contains("---[ end Kernel panic") {
        // The panic's closing line, after the panic itself was reported.
        None
    } else if msg.contains("Kernel panic") {
        Some((CrashKind::Panic, None))
    } else if msg.contains("Oops:") || msg.contains("Oops[#") || msg.contains("Internal error:") {
        Some((CrashKind::Oops, None))
    } else if let Some((_, after)) = msg.split_once("sending SIGSEGV to ") {
        // `... sending SIGSEGV to mcad for ...`: the word after, if there is one.
        let name = after.split_whitespace().next().map(|w| w.trim_end_matches(':')).filter(|n| !n.is_empty());
        Some((CrashKind::Segfault, name.map(str::to_string)))
    } else if let Some((before, _)) = msg.split_once("unhandled level 2 translation fault") {
        // `mcad[1234]: unhandled ...`, maybe after a printk timestamp: the word just before, up to its PID.
        let name = before.split_whitespace().next_back().and_then(|w| w.split_once('[')).map(|(n, _)| n).filter(|n| !n.is_empty());
        Some((CrashKind::MemoryFault, name.map(str::to_string)))
    } else {
        None
    }
}

struct Crash {
    started: Ts,
    kind: CrashKind,
    process: Option<String>,
    lines: Vec<String>,
    /// The size of `lines`, against [`CRASH_BYTES`].
    bytes: usize,
    /// Set at the first line that did not fit: later ones are not kept (nor
    /// formatted), so the capture has no holes.
    full: bool,
}

impl Crash {
    fn push(&mut self, line: impl FnOnce() -> String) {
        if self.full {
            return;
        }
        let line = line();
        if self.lines.len() < CRASH_LINES && self.bytes + line.len() <= CRASH_BYTES {
            self.bytes += line.len();
            self.lines.push(line);
        } else {
            self.full = true;
        }
    }
}

/// Who sent a line: the AP, else the address of a sender apctl can't name.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Source {
    Device(Mac),
    Address(String),
}

#[derive(Default)]
pub struct LogEvents {
    /// Steering requests waiting for the client's answer, by client.
    steering: HashMap<Mac, Steering>,
    /// The client each device's latest steering request was about.
    steering_by_device: HashMap<Source, Mac>,
    /// Last report per kind, client and detail (e.g. a steering answer's
    /// status), to avoid repeating one line's event.
    recent: HashMap<(EventKind, Mac, i64), Ts>,
    /// Current experience problems per client, and when they were reported.
    anomalies: HashMap<Mac, (String, Ts)>,
    /// Crash captures in progress, by AP.
    crashes: HashMap<Mac, Crash>,
    /// When each AP's last crash was reported, for [`CRASH_COOLDOWN`].
    crash_reported: HashMap<Mac, Ts>,
}

/// Inserts unless the map is full (a key already there is always replaced).
fn bounded<K: std::hash::Hash + Eq, V>(map: &mut HashMap<K, V>, key: K, value: V) -> bool {
    if map.len() >= MAX_TRACKED && !map.contains_key(&key) {
        return false;
    }
    map.insert(key, value);
    true
}

/// Text after `key` up to the next space, comma or bracket.
fn field<'a>(msg: &'a str, key: &str) -> Option<&'a str> {
    let rest = &msg[msg.find(key)? + key.len()..];
    let end = rest.find([' ', ',', ')', ']']).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn mac(s: &str) -> Option<Mac> {
    s.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

/// Meaning of an 802.11v BSS Transition Management response status.
fn btm_status(code: i64) -> &'static str {
    match code {
        0 => "accepted",
        1 => "rejected (unspecified)",
        2 => "rejected: insufficient beacon reports",
        3 => "rejected: insufficient capacity",
        4 => "rejected: BSS termination undesired",
        5 => "rejected: BSS termination delay requested",
        6 => "rejected: client proposed its own candidates",
        7 => "rejected: no suitable AP to move to",
        8 => "rejected: leaving the network",
        _ => "unknown response",
    }
}

impl LogEvents {
    /// Reports at most once per `secs` for the same kind, client and detail.
    /// Past [`MAX_TRACKED`] new subjects are not reported (a flood of made-up
    /// clients must not become a flood of events).
    fn fresh(&mut self, kind: EventKind, client: Mac, detail: i64, ts: Ts, secs: Ts) -> bool {
        debug_assert!(secs <= MAX_REPEAT, "reports are forgotten after MAX_REPEAT");
        match self.recent.get_mut(&(kind, client, detail)) {
            Some(t) if (0..secs).contains(&(ts - *t)) => false,
            Some(t) => {
                *t = ts;
                true
            }
            None => bounded(&mut self.recent, (kind, client, detail), ts),
        }
    }

    pub fn feed(&mut self, line: &LogLine) -> Vec<Event> {
        let mut out = Vec::new();
        let msg = line.msg.as_str();
        let prog = line.program.as_deref().unwrap_or("");
        // Crashes and steering are followed per sender; the key is made only
        // for a line that needs it.
        let dev_key = || line.device_mac.map_or_else(|| Source::Address(line.src_ip.clone()), Source::Device);

        // Crashes are followed only for a sender known to be one of our APs, as
        // the official controller does: anyone can send a line saying "Kernel panic".
        if let Some(dev) = line.device_mac
            && self.crash(dev, line, &mut out)
        {
            return out;
        }
        // A line without a priority is netconsole's: the kernel's own output,
        // which syslog carries too. Only crashes are looked for in it.
        if line.facility.is_none() {
            return out;
        }

        if prog == "stamgr"
            && let Some(rest) = msg.strip_prefix("kick-sta-on ")
        {
            let mut parts = rest.split_whitespace();
            let client = parts.next().and_then(mac);
            let vap = parts.next().map(str::to_string);
            let reason = rest.split("reason:").nth(1).map(|r| r.split_once(" rssi:").map_or(r, |(r, _)| r).trim_end_matches(')').trim().to_string());
            let signal = field(rest, "rssi:").and_then(|v| v.parse::<i64>().ok()).map(|r| r + NOISE_FLOOR);
            if let Some(c) = client
                && self.fresh(EventKind::ClientKicked, c, 0, line.ts, 60)
            {
                out.push(Event { ts: line.ts, kind: EventKind::ClientKicked, device_mac: line.device_mac, client_mac: Some(c), data: json!({ "reason": reason, "signal": signal, "vap": vap }) });
            }
            return out;
        }

        if msg.contains("BTM:") {
            if let Some(c) = msg.split("BTM: STA ").nth(1).and_then(|r| r.split_whitespace().next()).and_then(mac) {
                // A request: the client's signal and how many APs were offered,
                // and the VAP it was made on.
                let vap = msg.split("vap-").nth(1).and_then(|r| r.split_once('(')).and_then(|(_, r)| r.split_once(')')).map(|(v, _)| v.to_string());
                let s = Steering {
                    from: Some(dev_key()),
                    ts: line.ts,
                    rssi: field(msg, "RSSI: ").and_then(|v| v.parse().ok()),
                    candidates: field(msg, "candidates: ").and_then(|v| v.parse().ok()),
                    targets: vec![],
                    vap,
                };
                if bounded(&mut self.steering, c, s) {
                    bounded(&mut self.steering_by_device, dev_key(), c);
                }
            } else if let Some(t) = msg.split("BTM: [").nth(1).filter(|t| t.contains("]{"))
                && let dev = dev_key()
                && let Some(client) = self.steering_by_device.get(&dev)
                && let Some(s) = self.steering.get_mut(client)
                && s.from.as_ref() == Some(&dev)
                && s.targets.len() < MAX_TARGETS
            {
                // A candidate: "[0]{bssid chNN/opNN/phyNN}".
                let inner = t.split('{').nth(1).unwrap_or("").trim_end_matches('}');
                let mut it = inner.split_whitespace();
                let bssid = it.next().unwrap_or("").to_string();
                let channel = it.next().and_then(|c| c.strip_prefix("ch")).and_then(|c| c.split('/').next()).and_then(|c| c.parse::<i64>().ok());
                s.targets.push(json!({ "bssid": bssid, "channel": channel }));
            } else if let Some(r) = msg.split("Received response from ").nth(1) {
                let client = r.split(']').next().and_then(mac);
                let status = field(msg, "status ").and_then(|v| v.parse::<i64>().ok());
                if let (Some(c), Some(st)) = (client, status) {
                    let req = self.steering.remove(&c).filter(|s| (0..=STEER_ANSWER).contains(&(line.ts - s.ts))).unwrap_or_default();
                    let to = field(msg, "bssid ").filter(|b| *b != "n/a").map(str::to_string);
                    if self.fresh(EventKind::ClientSteered, c, st, line.ts, 600) {
                        out.push(Event {
                            ts: line.ts,
                            kind: EventKind::ClientSteered,
                            device_mac: line.device_mac,
                            client_mac: Some(c),
                            data: json!({
                                "status": st, "result": btm_status(st), "accepted": st == 0, "to_bssid": to,
                                "signal": req.rssi, "candidates": req.targets, "offered": req.candidates, "vap": req.vap,
                            }),
                        });
                    }
                }
            }
            return out;
        }

        if prog == "hostapd"
            && let Some(rest) = msg.split("AP-STA-POSSIBLE-PSK-MISMATCH ").nth(1)
            && let Some(c) = rest.split_whitespace().next().and_then(mac)
        {
            let vap = msg.split(':').next().filter(|v| v.starts_with("wifi")).map(str::to_string);
            if self.fresh(EventKind::ClientWrongPassword, c, 0, line.ts, 600) {
                out.push(Event { ts: line.ts, kind: EventKind::ClientWrongPassword, device_mac: line.device_mac, client_mac: Some(c), data: json!({ "vap": vap }) });
            }
            return out;
        }

        if prog == "mcad" && msg.contains("log_sta_anomalies") {
            let client = field(msg, "sta=").and_then(mac);
            // A comma-separated list: read up to the next space.
            let reasons = msg.split("anomalies=").nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or("");
            if let Some(c) = client
                && !reasons.is_empty()
            {
                // Copied only when reported: the same reasons come every 10 s or so.
                let changed = self.anomalies.get(&c).is_none_or(|(r, t)| r != reasons || !(0..ANOMALIES_AGAIN).contains(&(line.ts - t)));
                if changed && bounded(&mut self.anomalies, c, (reasons.to_string(), line.ts)) {
                    out.push(Event {
                        ts: line.ts,
                        kind: EventKind::ClientExperience,
                        device_mac: line.device_mac,
                        client_mac: Some(c),
                        data: json!({
                            "anomalies": reasons.split(',').map(str::trim).filter(|x| !x.is_empty()).collect::<Vec<_>>(),
                            "satisfaction": field(msg, "satisfaction_now=").and_then(|v| v.parse::<i64>().ok()),
                            "signal": field(msg, "signal=").and_then(|v| v.parse::<i64>().ok()),
                        }),
                    });
                }
            }
        }
        out
    }

    /// Crash capture: everything the AP says for a while after a fault, while
    /// its other events are still reported; a panic is reported at once.
    /// Returns whether the line was a fault.
    fn crash(&mut self, dev: Mac, line: &LogLine, out: &mut Vec<Event>) -> bool {
        let (msg, prog) = (line.msg.as_str(), line.program.as_deref());
        let text = || prog.map_or_else(|| msg.to_string(), |p| format!("{p}: {msg}"));
        let fault = match (prog, line.facility) {
            // Netconsole sends the kernel's lines with no priority, and the parser
            // may have taken their first word for a program (`mcad[1234]: unhandled
            // ...`, `Oops: ...`): such a line is read as sent, and a memory fault
            // whose name went with its PID is the program's.
            (_, None) => fault(&text()).map(|(kind, name)| {
                let program = prog.filter(|&p| kind == CrashKind::MemoryFault && p != "kernel").map(str::to_string);
                (kind, name.or(program))
            }),
            (Some("kernel"), _) | (_, Some(0)) => fault(msg),
            _ => None,
        };
        let is_fault = fault.is_some();
        if let Some(c) = self.crashes.get_mut(&dev) {
            c.push(text);
            if let Some((CrashKind::Panic, _)) = fault {
                c.kind = CrashKind::Panic;
                out.extend(self.flush(dev, line.ts));
            }
        } else if let Some((kind, process)) = fault
            && self.crash_reported.get(&dev).is_none_or(|t| !(0..CRASH_COOLDOWN).contains(&(line.ts - t)))
            && self.crashes.len() < MAX_CRASHES
        {
            let mut crash = Crash { started: line.ts, kind, process, lines: Vec::new(), bytes: 0, full: false };
            crash.push(text);
            self.crashes.insert(dev, crash);
            if kind == CrashKind::Panic {
                out.extend(self.flush(dev, line.ts));
            }
        }
        is_fault
    }

    fn flush(&mut self, dev: Mac, now: Ts) -> Option<Event> {
        let c = self.crashes.remove(&dev)?;
        self.crash_reported.insert(dev, now);
        let data = json!({ "kind": c.kind.as_str(), "process": c.process, "source": "syslog", "lines": c.lines });
        Some(Event::device(now, EventKind::ApCrash, dev, data))
    }

    /// Reports crash captures that have collected long enough.
    pub fn tick(&mut self, now: Ts) -> Vec<Event> {
        let due: Vec<Mac> = self.crashes.iter().filter(|(_, c)| !(0..CRASH_WINDOW).contains(&(now - c.started))).map(|(k, _)| *k).collect();
        let mut out: Vec<Event> = due.into_iter().filter_map(|k| self.flush(k, now)).collect();
        self.crash_reported.retain(|_, t| (0..CRASH_COOLDOWN).contains(&(now - *t)));
        // Forget de-duplication and steering state once no window reads it: a
        // flood of made-up clients that fills a map shuts real ones out of it
        // only that long.
        self.recent.retain(|_, t| (0..MAX_REPEAT).contains(&(now - *t)));
        self.steering.retain(|_, s| (0..=STEER_ANSWER).contains(&(now - s.ts)));
        let steering = &self.steering;
        self.steering_by_device.retain(|_, c| steering.contains_key(c));
        self.anomalies.retain(|_, (_, t)| (0..ANOMALIES_AGAIN).contains(&(now - *t)));
        // Every one is a crash: in AP order rather than the map's.
        out.sort_by_key(|f| f.device_mac);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: &str = "78:45:58:3c:52:bc";

    /// A syslog line from the AP: the kernel's with facility 0, the rest as user programs'.
    fn line(ts: Ts, prog: &str, msg: &str) -> LogLine {
        let facility = Some(if prog == "kernel" { 0 } else { 1 });
        LogLine { ts, device_mac: AP.parse().ok(), src_ip: "192.168.1.6".into(), facility, severity: Some(6), program: Some(prog.into()), msg: msg.into() }
    }

    /// A netconsole line from the AP: no priority, and the kernel's text as it is.
    fn netconsole(ts: Ts, raw: &str) -> LogLine {
        crate::syslog::parse(ts, "192.168.1.6", AP.parse().ok(), raw)
    }

    #[test]
    fn minimum_rssi_kicks() {
        let mut l = LogEvents::default();
        let f = l.feed(&line(100, "stamgr", "kick-sta-on 6c:ac:c2:00:00:01 wifi1ap1 (reason:Low RSSI rssi:19)"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, EventKind::ClientKicked);
        assert_eq!(f[0].client_mac, "6c:ac:c2:00:00:01".parse().ok());
        assert_eq!(f[0].data["reason"], "Low RSSI");
        assert_eq!(f[0].data["signal"], -76);
        // The same kick logged again moments later is one event.
        assert!(l.feed(&line(101, "stamgr", "kick-sta-on 6c:ac:c2:00:00:01 wifi1ap1 (reason:Low RSSI rssi:19)")).is_empty());
    }

    #[test]
    fn a_clock_step_back_does_not_silence_events() {
        let mut l = LogEvents::default();
        let kick = "kick-sta-on 6c:ac:c2:00:00:01 wifi1ap1 (reason:Low RSSI rssi:19)";
        let m = "wireless_agg_stats.log_sta_anomalies(): sta=92:00:00:00:00:05 signal=-48 satisfaction_now=70 anomalies=low_phy_rate";
        assert_eq!((l.feed(&line(10_000, "stamgr", kick)).len(), l.feed(&line(10_000, "mcad", m)).len()), (1, 1));
        // The clock goes back an hour: the same lines are new again, not 59 minutes away.
        assert_eq!((l.feed(&line(6_400, "stamgr", kick)).len(), l.feed(&line(6_400, "mcad", m)).len()), (1, 1));
        assert!(l.feed(&line(6_410, "stamgr", kick)).is_empty(), "and repeats are held back as usual");
        // A capture started before the step is reported, not held until the clock catches up.
        assert!(l.feed(&line(10_000, "kernel", "Internal error: Oops: 17 [#1] SMP ARM")).is_empty());
        assert_eq!(l.tick(6_420).len(), 1);
        // What was tracked "in the future" is forgotten.
        assert!(l.recent.is_empty() || l.recent.values().all(|t| *t <= 6_420));
        // A steering answer pairs only with a request made before it.
        let p = "wlan: [0:I:ANY] [UNSPECIFIED] vap-0(wifi1ap1):";
        l.feed(&line(9_000, "kernel", &format!("{p}BTM: STA 6c:ac:c2:00:00:02 RSSI: -77, candidates: 1, error: 0, flags: ALLOW (0x1)")));
        let f = l.feed(&line(6_430, "kernel", &format!("{p}BTM: Received response from [6c:ac:c2:00:00:02](len = 5): dialog_token 1, status 0, delay 0, bssid n/a, cancel 0")));
        assert_eq!(f[0].data["signal"], Value::Null);
    }

    #[test]
    fn steering_request_candidates_and_answer() {
        let mut l = LogEvents::default();
        let p = "wlan: [0:I:ANY] [UNSPECIFIED] vap-0(wifi1ap1):";
        assert!(l.feed(&line(10, "kernel", &format!("{p}BTM: STA 6c:ac:c2:00:00:01 RSSI: -77, candidates: 1, error: 0, flags: ALLOW (0x1)"))).is_empty());
        assert!(l.feed(&line(10, "kernel", &format!("{p}BTM: RSSI: [-74 -> -68 -> -74 -> -78]"))).is_empty());
        assert!(l.feed(&line(10, "kernel", &format!("{p}BTM: [0]{{78:45:58:3c:51:ae ch44/op128/phy14}}"))).is_empty());
        let f = l.feed(&line(11, "kernel", &format!("{p}BTM: Received response from [6c:ac:c2:00:00:01](len = 5): dialog_token 1, status 7, delay 0, bssid n/a, cancel 0")));
        assert_eq!(f.len(), 1);
        let d = &f[0].data;
        assert_eq!((f[0].kind, d["status"].as_i64(), d["accepted"].as_bool()), (EventKind::ClientSteered, Some(7), Some(false)));
        assert_eq!(d["result"], "rejected: no suitable AP to move to");
        assert_eq!(d["signal"], -77);
        assert_eq!(d["candidates"][0]["bssid"], "78:45:58:3c:51:ae");
        assert_eq!(d["candidates"][0]["channel"], 44);
        assert_eq!(d["vap"], "wifi1ap1");
        // The client repeating the same answer is not reported again within 10 minutes.
        assert!(l.feed(&line(20, "kernel", &format!("{p}BTM: Received response from [6c:ac:c2:00:00:01](len = 5): dialog_token 2, status 7, delay 0, bssid n/a, cancel 0"))).is_empty());
    }

    #[test]
    fn candidates_are_the_request_of_the_device_that_lists_them() {
        let mut l = LogEvents::default();
        let p = "wlan: [0:I:ANY] [UNSPECIFIED] vap-0(wifi1ap1):";
        let from = |ap: &str, ts: Ts, msg: String| LogLine { device_mac: ap.parse().ok(), ..line(ts, "kernel", &msg) };
        let (e, d) = ("02:00:00:00:00:0e", "02:00:00:00:00:0d");
        // AP E asks the client to move, then AP D does; E's candidates come after.
        l.feed(&from(e, 10, format!("{p}BTM: STA 6c:ac:c2:00:00:01 RSSI: -77, candidates: 1, error: 0, flags: ALLOW (0x1)")));
        l.feed(&from(d, 11, format!("{p}BTM: STA 6c:ac:c2:00:00:01 RSSI: -70, candidates: 1, error: 0, flags: ALLOW (0x1)")));
        l.feed(&from(e, 11, format!("{p}BTM: [0]{{78:45:58:3c:51:ae ch44/op128/phy14}}")));
        l.feed(&from(d, 11, format!("{p}BTM: [0]{{78:45:58:3c:51:af ch36/op128/phy14}}")));
        let f = l.feed(&from(d, 12, format!("{p}BTM: Received response from [6c:ac:c2:00:00:01](len = 5): dialog_token 1, status 0, delay 0, bssid n/a, cancel 0")));
        assert_eq!((f[0].data["signal"].as_i64(), f[0].data["candidates"].as_array().map(Vec::len)), (Some(-70), Some(1)));
        assert_eq!(f[0].data["candidates"][0]["bssid"], "78:45:58:3c:51:af");
    }

    #[test]
    fn experience_problems_when_they_change() {
        let mut l = LogEvents::default();
        let m = |r: &str| format!("wireless_agg_stats.log_sta_anomalies(): bssid=78:45:58:3c:51:ae radio=wifi1 vap=wifi1ap0 sta=92:00:00:00:00:05 signal=-48 satisfaction_now=70 anomalies={r}");
        let f = l.feed(&line(0, "mcad", &m("low_phy_rate")));
        assert_eq!((f.len(), f[0].data["satisfaction"].as_i64()), (1, Some(70)));
        assert_eq!(f[0].data["anomalies"][0], "low_phy_rate");
        assert!(l.feed(&line(10, "mcad", &m("low_phy_rate"))).is_empty(), "same reasons every 10 s: once");
        assert_eq!(l.feed(&line(20, "mcad", &m("low_phy_rate,high_tcp_latency"))).len(), 1, "new reason");
    }

    #[test]
    fn crashes_are_captured_then_reported() {
        let mut l = LogEvents::default();
        assert!(l.feed(&line(0, "kernel", "do_page_fault(): sending SIGSEGV to mcad for invalid read access from 00000000")).is_empty());
        assert!(l.feed(&line(1, "kernel", "epc = 0040a3c8 in mcad[400000+60000]")).is_empty());
        assert!(l.tick(60).is_empty(), "still collecting");
        let f = l.tick(200);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].kind, f[0].data["process"].as_str()), (EventKind::ApCrash, Some("mcad")));
        assert_eq!(f[0].data["lines"].as_array().map(Vec::len), Some(2));
        // Another crash within 10 minutes of the report is not reported.
        assert!(l.feed(&line(300, "kernel", "Kernel panic - not syncing: Fatal exception")).is_empty());
        assert!(l.tick(700).is_empty());
        // After that, a kernel panic is reported at once.
        let f = l.feed(&line(800, "kernel", "Kernel panic - not syncing: Fatal exception"));
        assert_eq!(f[0].data["kind"], "kernel panic");
        assert_eq!(f[0].data["lines"][0], "kernel: Kernel panic - not syncing: Fatal exception");
        // A wrong password, once per 10 minutes per client.
        let f = l.feed(&line(500, "hostapd", "wifi1ap0: AP-STA-POSSIBLE-PSK-MISMATCH 0e:00:00:00:00:02"));
        assert_eq!((f[0].kind, f[0].data["vap"].as_str()), (EventKind::ClientWrongPassword, Some("wifi1ap0")));
        assert!(l.feed(&line(510, "hostapd", "wifi1ap0: AP-STA-POSSIBLE-PSK-MISMATCH 0e:00:00:00:00:02")).is_empty());
        // Normal handshake lines are not mistaken for it.
        assert!(l.feed(&line(520, "hostapd", "wifi1ap0: STA 0e:00:00:00:00:02 WPA: pairwise key handshake completed (RSN)")).is_empty());
        // Unrelated lines produce nothing.
        assert!(l.feed(&line(400, "dnsmasq", "query[A] example.com")).is_empty());
    }

    #[test]
    fn a_fault_names_the_process_it_killed() {
        let name = |msg: &str| fault(msg).and_then(|(_, p)| p);
        assert_eq!(name("mcad[1234]: unhandled level 2 translation fault (11) at 0x0, esr 0x92000005"), Some("mcad".into()));
        assert_eq!(name("[ 12345.678] mcad[1234]: unhandled level 2 translation fault (11) at 0x0"), Some("mcad".into()));
        assert_eq!(name("[12345.678] hostapd[99]: unhandled level 2 translation fault (11) at 0x0"), Some("hostapd".into()));
        assert_eq!(name("unhandled level 2 translation fault (11) at 0x0"), None);
        assert_eq!(name("[12345.678] unhandled level 2 translation fault (11) at 0x0"), None, "a timestamp is no process");
        assert_eq!(name("[ 12345.678] unhandled level 2 translation fault (11) at 0x0"), None);
        // A segfault names the word after it, if there is one.
        assert_eq!(name("do_page_fault(): sending SIGSEGV to mcad: for invalid read access"), Some("mcad".into()));
        for nothing in ["do_page_fault(): sending SIGSEGV to ", "do_page_fault(): sending SIGSEGV to  :"] {
            assert_eq!(fault(nothing), Some((CrashKind::Segfault, None)), "{nothing:?}");
        }
    }

    #[test]
    fn crash_capture_keeps_other_events_and_the_first_fault() {
        let mut l = LogEvents::default();
        assert!(l.feed(&line(0, "kernel", "Internal error: Oops: 17 [#1] SMP ARM")).is_empty());
        // Other events of the device are still reported while capturing.
        let f = l.feed(&line(1, "stamgr", "kick-sta-on 6c:ac:c2:00:00:01 wifi1ap1 (reason:Low RSSI rssi:19)"));
        assert_eq!(f.len(), 1);
        for i in 0..300 {
            assert!(l.feed(&line(2, "kernel", &format!("line {i}"))).is_empty());
        }
        // A second fault in the same capture does not replace the first.
        assert!(l.feed(&line(3, "kernel", "do_page_fault(): sending SIGSEGV to mcad for invalid read access from 00000000")).is_empty());
        let f = l.tick(200);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].data["kind"], "kernel oops");
        assert_eq!(f[0].data["lines"].as_array().map(Vec::len), Some(200));
        assert!(l.tick(400).is_empty());
    }

    #[test]
    fn oops_only_from_kernel_lines() {
        let mut l = LogEvents::default();
        assert!(l.feed(&line(0, "hostapd", "wifi1ap0: STA 0e:00:00:00:00:02 IEEE 802.11: associated (ssid Oops: guest [#1])")).is_empty());
        assert!(l.feed(&line(1, "dnsmasq", "query[A] oops.example.com")).is_empty());
        assert!(l.feed(&line(2, "kernel", "wlan: hostname Oopsie connected")).is_empty());
        assert!(l.tick(1000).is_empty());
        assert!(l.feed(&line(10, "kernel", "Oops[#1]:")).is_empty());
        assert_eq!(l.tick(1000)[0].data["kind"], "kernel oops");
    }

    #[test]
    fn netconsole_crashes_are_found() {
        let mut l = LogEvents::default();
        // The kernel's lines as netconsole sends them: no priority, no program.
        assert!(l.feed(&netconsole(0, "[ 1234.567890] Internal error: Oops: 17 [#1] SMP ARM")).is_empty());
        assert!(l.feed(&netconsole(0, "[ 1234.567900] CPU: 1 PID: 0 Comm: swapper/1 Not tainted")).is_empty());
        let f = l.feed(&netconsole(1, "[ 1234.568000] Kernel panic - not syncing: Fatal exception in interrupt"));
        assert_eq!((f.len(), f[0].data["kind"].as_str(), f[0].device_mac), (1, Some("kernel panic"), AP.parse().ok()));
        let lines: Vec<&str> = f[0].data["lines"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(lines[0], "[ 1234.567890] Internal error: Oops: 17 [#1] SMP ARM");
        assert_eq!(lines[1], "[ 1234.567900] CPU: 1 PID: 0 Comm: swapper/1 Not tainted");
        // The panic's closing line is not a second crash.
        assert!(l.feed(&netconsole(1, "[ 1234.568100] ---[ end Kernel panic - not syncing: Fatal exception in interrupt ]---")).is_empty());
        assert!(l.tick(1000).is_empty());
        // A process killed by a fault, without printk times.
        let f = l.feed(&netconsole(2000, "do_page_fault(): sending SIGSEGV to hostapd for invalid read access from 00000000"));
        assert!(f.is_empty());
        assert_eq!(l.tick(2200)[0].data["process"], "hostapd");
        // Netconsole lines make no other events (syslog carries the same lines).
        assert!(l.feed(&netconsole(3000, "wlan: [0:I:ANY] [UNSPECIFIED] vap-0(wifi1ap1):BTM: Received response from [6c:ac:c2:00:00:01](len = 5): dialog_token 1, status 7")).is_empty());
        // A memory fault without printk times: the parser takes `mcad[1234]` for its program.
        assert!(l.feed(&netconsole(3100, "mcad[1234]: unhandled level 2 translation fault (11) at 0x00000000, esr 0x92000006")).is_empty());
        let f = l.tick(3300);
        assert_eq!((f[0].data["kind"].as_str(), f[0].data["process"].as_str()), (Some("process crashed (memory fault)"), Some("mcad")));
        assert_eq!(f[0].data["lines"][0], "mcad: unhandled level 2 translation fault (11) at 0x00000000, esr 0x92000006");
        // An oops header without printk times, which the parser splits the same way.
        assert!(l.feed(&netconsole(4000, "Oops: 0000 [#1] PREEMPT SMP")).is_empty());
        assert_eq!(l.tick(4200)[0].data["kind"], "kernel oops");
    }

    #[test]
    fn crashes_only_from_our_aps() {
        let mut l = LogEvents::default();
        let mut stranger = line(0, "kernel", "Kernel panic - not syncing: Fatal exception");
        stranger.device_mac = None;
        assert!(l.feed(&stranger).is_empty());
        stranger.facility = None;
        assert!(l.feed(&stranger).is_empty());
        assert!(l.tick(1000).is_empty() && l.crashes.is_empty());
    }

    #[test]
    fn crash_captures_are_bounded() {
        let mut l = LogEvents::default();
        // At most so much text per capture.
        assert!(l.feed(&line(0, "kernel", "Internal error: Oops: 17 [#1] SMP ARM")).is_empty());
        let long = "x".repeat(8000);
        for _ in 0..100 {
            l.feed(&line(1, "kernel", &long));
        }
        // Once a line did not fit, a short one after it is not kept either: no holes.
        l.feed(&line(1, "kernel", "short"));
        let c = &l.crashes[&AP.parse::<Mac>().unwrap()];
        assert!(c.bytes <= CRASH_BYTES && c.lines.len() < 10, "{} lines", c.lines.len());
        assert!(c.full && c.lines.last().is_some_and(|l| l.ends_with('x')));
        // At most so many captures at once, reported in AP order.
        for i in 0..MAX_CRASHES + 10 {
            let mut f = line(0, "kernel", "Internal error: Oops: 17 [#1] SMP ARM");
            f.device_mac = format!("02:00:00:00:{:02x}:{:02x}", i >> 8, i & 0xff).parse().ok();
            l.feed(&f);
        }
        assert_eq!(l.crashes.len(), MAX_CRASHES);
        let f = l.tick(1000);
        assert_eq!(f.len(), MAX_CRASHES);
        assert!(f.windows(2).all(|w| w[0].device_mac < w[1].device_mac));
    }

    #[test]
    fn what_is_tracked_is_bounded() {
        let mut l = LogEvents::default();
        let client = |i: usize| format!("02:00:{:02x}:{:02x}:{:02x}:01", i >> 16, (i >> 8) & 0xff, i & 0xff);
        let p = "wlan: [0:I:ANY] [UNSPECIFIED] vap-0(wifi1ap1):";
        let mut kicks = 0;
        for i in 0..MAX_TRACKED + 50 {
            kicks += l.feed(&line(1, "stamgr", &format!("kick-sta-on {} wifi1ap1 (reason:Low RSSI rssi:19)", client(i)))).len();
            l.feed(&line(1, "kernel", &format!("{p}BTM: STA {} RSSI: -77, candidates: 1, error: 0, flags: ALLOW (0x1)", client(i))));
        }
        assert_eq!(kicks, MAX_TRACKED, "made-up clients past the limit are not reported");
        assert_eq!((l.recent.len(), l.steering.len()), (MAX_TRACKED, MAX_TRACKED));
        for _ in 0..100 {
            l.feed(&line(1, "kernel", &format!("{p}BTM: [0]{{78:45:58:3c:51:ae ch44/op128/phy14}}")));
        }
        assert!(l.steering.values().all(|s| s.targets.len() <= MAX_TARGETS));
        // Time clears them once no window reads them, and the device's pointer
        // to its last request goes with its request.
        assert!(l.tick(1 + STEER_ANSWER).is_empty());
        assert_eq!((l.recent.len(), l.steering.len()), (MAX_TRACKED, MAX_TRACKED), "both still read");
        assert!(l.tick(2 + STEER_ANSWER).is_empty());
        assert!(l.steering.is_empty() && l.steering_by_device.is_empty() && l.recent.len() == MAX_TRACKED);
        assert!(l.tick(1 + MAX_REPEAT).is_empty());
        assert!(l.recent.is_empty());
        // So a client new after them is reported again.
        assert_eq!(l.feed(&line(1 + MAX_REPEAT, "stamgr", &format!("kick-sta-on {} wifi1ap1 (reason:Low RSSI rssi:19)", client(MAX_TRACKED + 60)))).len(), 1);
    }

    #[test]
    fn hostile_lines_do_not_panic() {
        let mut l = LogEvents::default();
        let p = "wlan: [0:I:ANY] [UNSPECIFIED] vap-0(wifi1ap1):";
        let samples = [
            "BTM: vap-)(".to_string(),
            "BTM: vap-(".to_string(),
            "vap-)BTM: STA 6c:ac:c2:00:00:01 (".to_string(),
            format!("{p}BTM: STA 6c:ac:c2:00:00:01 RSSI: -77, candidates: 1, error: 0, flags: ALLOW (0x1)"),
            format!("{p}BTM: [0]{{78:45:58:3c:51:ae ch44/op128/phy14}}"),
            format!("{p}BTM: Received response from [6c:ac:c2:00:00:01](len = 5): dialog_token 1, status 7, delay 0, bssid n/a, cancel 0"),
            "kick-sta-on 6c:ac:c2:00:00:01 wifi1ap1 (reason:Low RSSI rssi:19)".to_string(),
            "wireless_agg_stats.log_sta_anomalies(): sta=92:00:00:00:00:05 signal=-48 satisfaction_now=70 anomalies=low_phy_rate".to_string(),
            "wifi1ap0: AP-STA-POSSIBLE-PSK-MISMATCH 0e:00:00:00:00:02".to_string(),
            "do_page_fault(): sending SIGSEGV to ".to_string(),
            "unhandled level 2 translation fault (11) at 0x0, esr 0x92000005 ü[".to_string(),
            "BTM: ü vap-ü)ü(ü BTM: [ü]{ü status ü bssid ü Received response from ü]".to_string(),
        ];
        // Every prefix of every sample, from every program that has a parser.
        for s in &samples {
            for (i, _) in s.char_indices().chain([(s.len(), ' ')]) {
                for prog in ["kernel", "stamgr", "mcad", "hostapd"] {
                    l.feed(&line(i as Ts, prog, &s[..i]));
                }
            }
        }
        l.tick(10_000);
    }
}
