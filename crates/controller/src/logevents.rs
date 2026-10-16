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

use crate::engine::{EventKind, LogLine};
use crate::model::Ts;

/// Noise floor that `stamgr`'s relative RSSI is measured against.
const NOISE_FLOOR: i64 = -95;
/// How long a crash capture collects lines before it is reported.
const CRASH_WINDOW: Ts = 180;
/// At most this many entries in each map below: anyone can send syslog lines,
/// so made-up clients and senders must not grow them without bound.
const MAX_TRACKED: usize = 10_000;
/// At most this many candidate APs kept per steering request.
const MAX_TARGETS: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub kind: EventKind,
    pub device: Option<Mac>,
    pub client: Option<Mac>,
    pub data: Value,
}

#[derive(Default)]
struct Steering {
    ts: Ts,
    rssi: Option<i64>,
    candidates: Option<i64>,
    targets: Vec<Value>,
    vap: Option<String>,
}

struct Crash {
    started: Ts,
    kind: &'static str,
    process: Option<String>,
    lines: Vec<String>,
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
    /// Crash captures in progress, by sender.
    crashes: HashMap<Source, (Option<Mac>, Crash)>,
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
pub fn btm_status(code: i64) -> &'static str {
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
        match self.recent.get_mut(&(kind, client, detail)) {
            Some(t) if ts - *t < secs => false,
            Some(t) => {
                *t = ts;
                true
            }
            None => bounded(&mut self.recent, (kind, client, detail), ts),
        }
    }

    pub fn feed(&mut self, line: &LogLine) -> Vec<Found> {
        let mut out = Vec::new();
        let msg = line.msg.as_str();
        let prog = line.program.as_deref().unwrap_or("");
        // Crashes and steering are followed per sender; the key is made only
        // for a line that needs it.
        let dev_key = || line.device_mac.map_or_else(|| Source::Address(line.src_ip.clone()), Source::Device);

        // Crash capture: collect everything the device says for a while after a
        // fault (up to 200 lines), while its other events are still reported.
        let kernel = prog == "kernel" || line.facility == Some(0);
        let fault = if !kernel {
            None
        } else if msg.contains("Kernel panic") {
            Some(("kernel panic", None))
        } else if msg.contains("Oops:") || msg.contains("Oops[#") || msg.contains("Internal error:") {
            Some(("kernel oops", None))
        } else if let Some(p) = msg.split("sending SIGSEGV to ").nth(1) {
            Some(("process crashed (segmentation fault)", Some(p.split_whitespace().next().unwrap_or(p).trim_end_matches(':').to_string())))
        } else if msg.contains("unhandled level 2 translation fault") {
            Some(("process crashed (memory fault)", msg.split_whitespace().find(|w| w.contains('[')).map(|w| w.to_string())))
        } else {
            None
        };
        let is_fault = fault.is_some();
        if is_fault || !self.crashes.is_empty() {
            let key = dev_key();
            if let Some((_, c)) = self.crashes.get_mut(&key) {
                if c.lines.len() < 200 {
                    c.lines.push(format!("{prog}: {msg}"));
                }
                if matches!(fault, Some(("kernel panic", _))) {
                    c.kind = "kernel panic";
                    out.extend(self.flush(&key));
                }
            } else if let Some((kind, process)) = fault {
                let crash = Crash { started: line.ts, kind, process, lines: vec![format!("{prog}: {msg}")] };
                if bounded(&mut self.crashes, key.clone(), (line.device_mac, crash)) && kind == "kernel panic" {
                    out.extend(self.flush(&key));
                }
            }
        }
        if is_fault {
            return out;
        }

        if prog == "stamgr"
            && let Some(rest) = msg.strip_prefix("kick-sta-on ")
        {
            let mut parts = rest.split_whitespace();
            let client = parts.next().and_then(mac);
            let vap = parts.next().map(str::to_string);
            let reason = rest.split("reason:").nth(1).map(|r| r.split(" rssi:").next().unwrap_or(r).trim_end_matches(')').trim().to_string());
            let signal = field(rest, "rssi:").and_then(|v| v.parse::<i64>().ok()).map(|r| r + NOISE_FLOOR);
            if let Some(c) = client
                && self.fresh(EventKind::ClientKicked, c, 0, line.ts, 60)
            {
                out.push(Found { kind: EventKind::ClientKicked, device: line.device_mac, client: Some(c), data: json!({ "reason": reason, "signal": signal, "vap": vap }) });
            }
            return out;
        }

        if msg.contains("BTM:") {
            let vap = msg.split("vap-").nth(1).and_then(|r| r.split_once('(')).and_then(|(_, r)| r.split_once(')')).map(|(v, _)| v.to_string());
            if let Some(c) = msg.split("BTM: STA ").nth(1).and_then(|r| r.split_whitespace().next()).and_then(mac) {
                // A request: the client's signal and how many APs were offered.
                let s = Steering {
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
                && let Some(client) = self.steering_by_device.get(&dev_key())
                && let Some(s) = self.steering.get_mut(client)
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
                    let req = self.steering.remove(&c).filter(|s| line.ts - s.ts <= 30).unwrap_or_default();
                    let to = field(msg, "bssid ").filter(|b| *b != "n/a").map(str::to_string);
                    if self.fresh(EventKind::ClientSteered, c, st, line.ts, 600) {
                        out.push(Found {
                            kind: EventKind::ClientSteered,
                            device: line.device_mac,
                            client: Some(c),
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
                out.push(Found { kind: EventKind::ClientWrongPassword, device: line.device_mac, client: Some(c), data: json!({ "vap": vap }) });
            }
            return out;
        }

        if prog == "mcad" && msg.contains("log_sta_anomalies") {
            let client = field(msg, "sta=").and_then(mac);
            // A comma-separated list: read up to the next space.
            let reasons = msg.split("anomalies=").nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or("").to_string();
            if let Some(c) = client
                && !reasons.is_empty()
            {
                let changed = self.anomalies.get(&c).is_none_or(|(r, t)| *r != reasons || line.ts - t >= 1800);
                if changed && bounded(&mut self.anomalies, c, (reasons.clone(), line.ts)) {
                    out.push(Found {
                        kind: EventKind::ClientExperience,
                        device: line.device_mac,
                        client: Some(c),
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

    fn flush(&mut self, key: &Source) -> Option<Found> {
        let (device, c) = self.crashes.remove(key)?;
        Some(Found { kind: EventKind::ApCrash, device, client: None, data: json!({ "kind": c.kind, "process": c.process, "source": "syslog", "lines": c.lines }) })
    }

    /// Reports crash captures that have collected long enough.
    pub fn tick(&mut self, now: Ts) -> Vec<Found> {
        let due: Vec<Source> = self.crashes.iter().filter(|(_, (_, c))| now - c.started >= CRASH_WINDOW).map(|(k, _)| k.clone()).collect();
        let mut out: Vec<Found> = due.iter().filter_map(|k| self.flush(k)).collect();
        // Forget old de-duplication and steering state.
        self.recent.retain(|_, t| now - *t < 3600);
        self.steering.retain(|_, s| now - s.ts < 300);
        let steering = &self.steering;
        self.steering_by_device.retain(|_, c| steering.contains_key(c));
        self.anomalies.retain(|_, (_, t)| now - *t < 3 * 3600);
        out.sort_by_key(|f| f.kind.as_str());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: &str = "78:45:58:3c:52:bc";

    fn line(ts: Ts, prog: &str, msg: &str) -> LogLine {
        LogLine { ts, device_mac: AP.parse().ok(), src_ip: "192.168.1.6".into(), facility: None, severity: Some(6), program: Some(prog.into()), msg: msg.into() }
    }

    #[test]
    fn minimum_rssi_kicks() {
        let mut l = LogEvents::default();
        let f = l.feed(&line(100, "stamgr", "kick-sta-on 6c:ac:c2:00:00:01 wifi1ap1 (reason:Low RSSI rssi:19)"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, EventKind::ClientKicked);
        assert_eq!(f[0].client, "6c:ac:c2:00:00:01".parse().ok());
        assert_eq!(f[0].data["reason"], "Low RSSI");
        assert_eq!(f[0].data["signal"], -76);
        // The same kick logged again moments later is one event.
        assert!(l.feed(&line(101, "stamgr", "kick-sta-on 6c:ac:c2:00:00:01 wifi1ap1 (reason:Low RSSI rssi:19)")).is_empty());
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
        // A kernel panic is reported at once.
        let f = l.feed(&line(300, "kernel", "Kernel panic - not syncing: Fatal exception"));
        assert_eq!(f[0].data["kind"], "kernel panic");
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
        // Time clears them, and the device's pointer to its last request goes with it.
        assert!(l.tick(4000).is_empty());
        assert!(l.recent.is_empty() && l.steering.is_empty() && l.steering_by_device.is_empty());
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
