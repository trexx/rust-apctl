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
//! - crashes, as the official controller detects them in netconsole output:
//!   kernel oopses and panics, and processes killed by faults.

use std::collections::HashMap;

use inform::Mac;
use serde_json::{Value, json};

use crate::engine::LogLine;
use crate::model::Ts;

/// Noise floor that `stamgr`'s relative RSSI is measured against.
const NOISE_FLOOR: i64 = -95;
/// How long a crash capture collects lines before it is reported.
const CRASH_WINDOW: Ts = 180;

#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub kind: &'static str,
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

#[derive(Default)]
pub struct LogEvents {
    /// Steering requests waiting for the client's answer, by client.
    steering: HashMap<String, Steering>,
    /// The client each device's latest steering request was about.
    steering_by_device: HashMap<String, String>,
    /// Last report per (kind, subject), to avoid repeating one line's event.
    recent: HashMap<(&'static str, String), Ts>,
    /// Current experience problems per client, and when they were reported.
    anomalies: HashMap<String, (String, Ts)>,
    /// Crash captures in progress, by device (or source address).
    crashes: HashMap<String, (Option<Mac>, Crash)>,
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
    /// Reports at most once per `secs` for the same kind and subject.
    fn fresh(&mut self, kind: &'static str, subject: &str, ts: Ts, secs: Ts) -> bool {
        let k = (kind, subject.to_string());
        if self.recent.get(&k).is_some_and(|t| ts - t < secs) {
            return false;
        }
        self.recent.insert(k, ts);
        true
    }

    pub fn feed(&mut self, line: &LogLine) -> Vec<Found> {
        let mut out = Vec::new();
        let msg = line.msg.as_str();
        let prog = line.program.as_deref().unwrap_or("");
        let dev_key = line.device_mac.map_or_else(|| line.src_ip.clone(), |m| m.to_string());

        // Crash capture: collect everything the device says for a while after a fault.
        if let Some((_, c)) = self.crashes.get_mut(&dev_key)
            && c.lines.len() < 200
        {
            c.lines.push(format!("{prog}: {msg}"));
            if msg.contains("Kernel panic") {
                c.kind = "kernel panic";
                out.extend(self.flush(&dev_key));
            }
            return out;
        }
        let fault = if msg.contains("Kernel panic") {
            Some(("kernel panic", None))
        } else if msg.contains("Oops") || (msg.contains("[#") && msg.contains("Internal error")) {
            Some(("kernel oops", None))
        } else if let Some(p) = msg.split("sending SIGSEGV to ").nth(1) {
            Some(("process crashed (segmentation fault)", Some(p.split_whitespace().next().unwrap_or(p).trim_end_matches(':').to_string())))
        } else if msg.contains("unhandled level 2 translation fault") {
            Some(("process crashed (memory fault)", msg.split_whitespace().find(|w| w.contains('[')).map(|w| w.to_string())))
        } else {
            None
        };
        if let Some((kind, process)) = fault {
            self.crashes.insert(dev_key.clone(), (line.device_mac, Crash { started: line.ts, kind, process, lines: vec![format!("{prog}: {msg}")] }));
            if kind == "kernel panic" {
                out.extend(self.flush(&dev_key));
            }
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
                && self.fresh("client_kicked", &c.to_string(), line.ts, 60)
            {
                out.push(Found { kind: "client_kicked", device: line.device_mac, client: Some(c), data: json!({ "reason": reason, "signal": signal, "vap": vap }) });
            }
            return out;
        }

        if msg.contains("BTM:") {
            let vap = msg.split("vap-").nth(1).and_then(|r| Some(r[r.find('(')? + 1..r.find(')')?].to_string()));
            if let Some(c) = msg.split("BTM: STA ").nth(1).and_then(|r| r.split_whitespace().next()).and_then(mac) {
                // A request: the client's signal and how many APs were offered.
                let s = Steering {
                    ts: line.ts,
                    rssi: field(msg, "RSSI: ").and_then(|v| v.parse().ok()),
                    candidates: field(msg, "candidates: ").and_then(|v| v.parse().ok()),
                    targets: vec![],
                    vap,
                };
                self.steering.insert(c.to_string(), s);
                self.steering_by_device.insert(dev_key, c.to_string());
            } else if let Some(t) = msg.split("BTM: [").nth(1).filter(|t| t.contains("]{"))
                && let Some(client) = self.steering_by_device.get(&dev_key).cloned()
                && let Some(s) = self.steering.get_mut(&client)
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
                    let req = self.steering.remove(&c.to_string()).filter(|s| line.ts - s.ts <= 30);
                    let to = field(msg, "bssid ").filter(|b| *b != "n/a").map(str::to_string);
                    if self.fresh("client_steered", &format!("{c}/{st}"), line.ts, 600) {
                        out.push(Found {
                            kind: "client_steered",
                            device: line.device_mac,
                            client: Some(c),
                            data: json!({
                                "status": st, "result": btm_status(st), "accepted": st == 0, "to_bssid": to,
                                "signal": req.as_ref().and_then(|s| s.rssi), "candidates": req.as_ref().map(|s| s.targets.clone()).unwrap_or_default(),
                                "offered": req.as_ref().and_then(|s| s.candidates),
                                "vap": req.and_then(|s| s.vap),
                            }),
                        });
                    }
                }
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
                let key = c.to_string();
                let changed = self.anomalies.get(&key).is_none_or(|(r, t)| *r != reasons || line.ts - t >= 1800);
                if changed {
                    self.anomalies.insert(key, (reasons.clone(), line.ts));
                    out.push(Found {
                        kind: "client_experience",
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

    fn flush(&mut self, key: &str) -> Option<Found> {
        let (device, c) = self.crashes.remove(key)?;
        Some(Found { kind: "ap_crash", device, client: None, data: json!({ "kind": c.kind, "process": c.process, "source": "syslog", "lines": c.lines }) })
    }

    /// Reports crash captures that have collected long enough.
    pub fn tick(&mut self, now: Ts) -> Vec<Found> {
        let due: Vec<String> = self.crashes.iter().filter(|(_, (_, c))| now - c.started >= CRASH_WINDOW).map(|(k, _)| k.clone()).collect();
        let mut out: Vec<Found> = due.iter().filter_map(|k| self.flush(k)).collect();
        // Forget old de-duplication and steering state.
        self.recent.retain(|_, t| now - *t < 3600);
        self.steering.retain(|_, s| now - s.ts < 300);
        self.anomalies.retain(|_, (_, t)| now - *t < 3 * 3600);
        out.sort_by_key(|f| f.kind);
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
        assert_eq!(f[0].kind, "client_kicked");
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
        assert_eq!((f[0].kind, d["status"].as_i64(), d["accepted"].as_bool()), ("client_steered", Some(7), Some(false)));
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
        assert_eq!((f[0].kind, f[0].data["process"].as_str()), ("ap_crash", Some("mcad")));
        assert_eq!(f[0].data["lines"].as_array().map(Vec::len), Some(2));
        // A kernel panic is reported at once.
        let f = l.feed(&line(300, "kernel", "Kernel panic - not syncing: Fatal exception"));
        assert_eq!(f[0].data["kind"], "kernel panic");
        // Unrelated lines produce nothing.
        assert!(l.feed(&line(400, "dnsmasq", "query[A] example.com")).is_empty());
    }
}
