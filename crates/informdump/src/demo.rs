//! A made-up site for demos, screenshots and UI work: three access points and
//! their clients over a day, written as a pcap stream that apctl's shadow mode
//! reads like a capture of real traffic.
//!
//! ```text
//! informdump demo-state > demo.json
//! apctl serve --data-dir demo-data --keys demo.json --shadow-cmd "informdump demo --live"
//! ```
//!
//! Everything is generated: names, MACs (real manufacturer prefixes so clients
//! get vendor names, made-up device parts), keys, neighbours and the routine.
//! The templates in `demo/` hold the fields a U6-Mesh on firmware 8.8 sends
//! and a site's settings, with made-up values. The output is deterministic
//! apart from where "now" falls.

use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use etherparse::PacketBuilder;
use inform::{Flags, Mac};
use serde_json::{Value, json};
use wire::synth::{self, http};

const TEMPLATE_INFORM: &str = include_str!("demo/inform.json");
const TEMPLATE_STATE: &str = include_str!("demo/state.json");

const SSID: &str = "Homestead";
const IOT_SSID: &str = "Homestead IoT";
const CONTROLLER_IP: [u8; 4] = [192, 168, 1, 10];
const VERSION: &str = "8.8.11.20161";

struct Ap {
    mac: &'static str,
    name: &'static str,
    ip: [u8; 4],
    ng: i64,
    na: i64,
    na_bw: i64,
    power: (i64, i64),
    /// Seconds before the end of the history when the AP restarts, and how long it is away.
    reboot: Option<(i64, i64)>,
}

const APS: [Ap; 3] = [
    Ap { mac: "0e:5d:7a:10:00:01", name: "Living Room", ip: [192, 168, 1, 21], ng: 1, na: 36, na_bw: 80, power: (14, 20), reboot: None },
    Ap { mac: "0e:5d:7a:10:00:02", name: "Upstairs", ip: [192, 168, 1, 22], ng: 6, na: 100, na_bw: 80, power: (12, 20), reboot: None },
    Ap { mac: "0e:5d:7a:10:00:03", name: "Studio", ip: [192, 168, 1, 23], ng: 11, na: 44, na_bw: 40, power: (12, 17), reboot: Some((5 * 3600 + 1200, 420)) },
];

/// Signal (dBm) at each location (living room, upstairs, studio) from each AP.
const SIGNAL: [[i64; 3]; 3] = [[-46, -66, -77], [-69, -49, -79], [-78, -76, -51]];

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Phone,
    Laptop,
    Tablet,
    Tv,
    Speaker,
    Iot,
    Server,
}

struct Client {
    mac: &'static str,
    hostname: &'static str,
    alias: Option<&'static str>,
    kind: Kind,
    /// Only on the 2.4 GHz IoT network.
    iot: bool,
    /// Signal offset from the location's.
    offset: i64,
    /// (from hour, to hour, location) in UTC; hours past the last entry and
    /// before the first are away.
    plan: &'static [(f64, f64, usize)],
}

const ALWAYS_LIVING: &[(f64, f64, usize)] = &[(0.0, 24.0, 0)];
const ALWAYS_UP: &[(f64, f64, usize)] = &[(0.0, 24.0, 1)];
const ALWAYS_STUDIO: &[(f64, f64, usize)] = &[(0.0, 24.0, 2)];

const CLIENTS: &[Client] = &[
    Client { mac: "a4:83:e7:3c:41:0a", hostname: "Sams-iPhone", alias: Some("Sam's iPhone"), kind: Kind::Phone, iot: false, offset: 0,
             plan: &[(0.0, 7.4, 1), (7.4, 8.2, 0), (17.6, 18.4, 0), (18.4, 19.1, 2), (19.1, 23.2, 0), (23.2, 24.0, 1)] },
    Client { mac: "7c:2e:bd:92:5e:11", hostname: "Pixel-8", alias: Some("Robin's Pixel"), kind: Kind::Phone, iot: false, offset: -3,
             plan: &[(0.0, 7.0, 1), (7.0, 8.6, 0), (8.6, 12.4, 2), (12.4, 13.1, 0), (13.1, 17.4, 2), (17.4, 22.6, 0), (22.6, 24.0, 1)] },
    Client { mac: "a0:a4:c5:5b:21:7f", hostname: "WORK-LT-0417", alias: Some("Work laptop"), kind: Kind::Laptop, iot: false, offset: 2,
             plan: &[(8.7, 12.5, 2), (13.0, 17.7, 2)] },
    Client { mac: "f0:18:98:6e:0c:d2", hostname: "MacBook-Air", alias: None, kind: Kind::Laptop, iot: false, offset: 0,
             plan: &[(6.9, 7.6, 0), (19.4, 23.1, 0)] },
    Client { mac: "3c:22:fb:a1:77:40", hostname: "iPad", alias: None, kind: Kind::Tablet, iot: false, offset: -2,
             plan: &[(7.0, 7.5, 0), (20.6, 23.0, 1)] },
    Client { mac: "6c:ac:c2:18:9d:33", hostname: "Galaxy-Tab-S9", alias: None, kind: Kind::Tablet, iot: false, offset: -4,
             plan: &[(15.8, 18.2, 0)] },
    Client { mac: "98:d6:f7:20:4b:6e", hostname: "LG-webOS-TV", alias: Some("Living room TV"), kind: Kind::Tv, iot: false, offset: -6, plan: ALWAYS_LIVING },
    Client { mac: "5c:aa:fd:0d:e1:5a", hostname: "Sonos-Kitchen", alias: Some("Kitchen speaker"), kind: Kind::Speaker, iot: false, offset: -8, plan: ALWAYS_LIVING },
    Client { mac: "48:a6:b8:7f:02:c9", hostname: "Sonos-Bedroom", alias: Some("Bedroom speaker"), kind: Kind::Speaker, iot: false, offset: -5, plan: ALWAYS_UP },
    Client { mac: "f4:f5:d8:44:9a:10", hostname: "Chromecast", alias: None, kind: Kind::Tv, iot: false, offset: -7, plan: ALWAYS_UP },
    Client { mac: "dc:a6:32:b7:58:0f", hostname: "raspberrypi", alias: Some("Home Assistant"), kind: Kind::Server, iot: false, offset: -4, plan: ALWAYS_UP },
    Client { mac: "fc:a1:83:5a:3e:62", hostname: "amazon-echo", alias: None, kind: Kind::Speaker, iot: true, offset: -3, plan: ALWAYS_LIVING },
    Client { mac: "18:b4:30:6d:12:a5", hostname: "Nest-Thermostat", alias: Some("Thermostat"), kind: Kind::Iot, iot: true, offset: -9, plan: ALWAYS_LIVING },
    Client { mac: "70:ee:50:3a:19:c4", hostname: "Netatmo-Weather", alias: None, kind: Kind::Iot, iot: true, offset: -6, plan: ALWAYS_STUDIO },
    Client { mac: "24:0a:c4:91:2f:08", hostname: "esp-greenhouse", alias: Some("Greenhouse sensor"), kind: Kind::Iot, iot: true, offset: -24, plan: ALWAYS_STUDIO },
    Client { mac: "9c:9c:1f:c2:60:4d", hostname: "esp-doorbell", alias: Some("Doorbell"), kind: Kind::Iot, iot: true, offset: -14, plan: ALWAYS_LIVING },
    Client { mac: "50:ec:50:4e:aa:17", hostname: "roborock-vacuum", alias: Some("Vacuum"), kind: Kind::Iot, iot: true, offset: -8,
             plan: &[(0.0, 10.2, 0), (10.2, 10.7, 1), (10.7, 11.0, 2), (11.0, 24.0, 0)] },
    Client { mac: "00:bb:3a:7e:05:b8", hostname: "Kindle", alias: None, kind: Kind::Tablet, iot: false, offset: -2, plan: &[(21.4, 23.6, 1)] },
    Client { mac: "ac:bc:32:0f:6a:93", hostname: "Guest-iPhone", alias: None, kind: Kind::Phone, iot: false, offset: 0, plan: &[] },
];

/// A guest that was here for a few hours at the start of the history.
const GUEST: &str = "ac:bc:32:0f:6a:93";

/// A neighbouring network: (bssid, essid, band, channel, width, signal at each AP).
type Neighbour = (&'static str, &'static str, &'static str, i64, i64, [i64; 3]);

const NEIGHBOURS: &[Neighbour] = &[
    ("16:9e:2c:41:4f:21", "Fibre-4F21", "ng", 1, 20, [-71, -78, -84]),
    ("16:9e:2c:41:4f:25", "Fibre-4F21-5G", "na", 36, 80, [-81, -86, -90]),
    ("3a:07:b1:62:91:02", "HomeHub-91", "ng", 6, 20, [-83, -74, -86]),
    ("3a:07:b1:62:91:06", "HomeHub-91", "na", 52, 80, [-89, -79, -91]),
    ("a6:51:0e:7b:20:c3", "Castle Guest", "ng", 11, 20, [-88, -85, -73]),
    ("da:12:6f:ee:01:9b", "DIRECT-9B-Printer", "ng", 6, 20, [-79, -72, -87]),
    ("5e:c4:88:03:d0:70", "", "ng", 11, 20, [-90, -86, -77]),
    ("72:3d:91:5a:b8:44", "Riverside", "na", 100, 80, [-90, -84, -92]),
];

/// A stranger broadcasting our network name (shown as a suspicious network).
const LOOKALIKE: (&str, &str, i64, i64) = ("ae:41:73:09:c2:5e", SSID, 11, -82);

/// Deterministic noise.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + (self.next() % (hi - lo + 1) as u64) as i64
    }
}

fn mac_bytes(mac: &str) -> [u8; 6] {
    let m: Mac = mac.parse().expect("valid demo MAC");
    m.0
}

/// A BSSID derived from the AP's MAC, as the firmware numbers its VAPs.
fn bssid(ap: &Ap, radio: &str, vap: u8) -> String {
    let mut b = mac_bytes(ap.mac);
    b[0] |= 0x02;
    b[3] = b[3].wrapping_add(if radio == "na" { 0x20 } else { 0x10 });
    b[5] = b[5].wrapping_add(vap * 8);
    Mac(b).to_string()
}

fn hex_key(seed: &str, bytes: usize) -> String {
    let mut r = Rng(seed.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3)));
    hex::encode((0..bytes).map(|_| r.next() as u8).collect::<Vec<u8>>())
}

fn authkey(ap: &Ap) -> [u8; 16] {
    let mut k = [0u8; 16];
    hex::decode_to_slice(hex_key(ap.mac, 16), &mut k).expect("hex");
    k
}

fn ip(v: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])
}

/// The controller settings to import (`apctl serve --keys`, then the
/// Settings page): the template site with our APs, networks and clients.
pub fn state() -> Result<Value> {
    let mut s: Value = serde_json::from_str(TEMPLATE_STATE)?;
    let template = s["devices"].as_array().and_then(|d| d.first()).cloned().unwrap_or_default();
    s["devices"] = APS
        .iter()
        .enumerate()
        .map(|(i, ap)| {
            let mut d = template.clone();
            d["_id"] = json!({ "$oid": format!("{:024x}", 0xd0 + i) });
            d["mac"] = json!(ap.mac);
            d["name"] = json!(ap.name);
            d["ip"] = json!(ip(ap.ip));
            d["serial"] = json!(ap.mac.replace(':', "").to_uppercase());
            d["x_authkey"] = json!(hex_key(ap.mac, 16));
            d["syslog_key"] = json!(hex_key(&format!("syslog {}", ap.mac), 32));
            d["inform_url"] = json!(format!("http://{}:8080/inform", ip(CONTROLLER_IP)));
            for r in d["radio_table"].as_array_mut().into_iter().flatten() {
                let na = r["radio"] == "na";
                r["channel"] = json!(if na { ap.na } else { ap.ng });
                r["ht"] = json!(if na { ap.na_bw } else { 20 });
                r["tx_power_mode"] = json!("custom");
                r["tx_power"] = json!(if na { ap.power.1 } else { ap.power.0 });
            }
            d
        })
        .collect();
    // Both networks on every AP.
    let all = s["apgroup"].as_array().and_then(|g| g.iter().find(|g| g["attr_hidden_id"] == "default")).map(|g| g["_id"]["$oid"].clone());
    for w in s["wlanconf"].as_array_mut().into_iter().flatten() {
        if let Some(all) = &all
            && w.get("ap_group_ids").is_some()
        {
            w["ap_group_ids"] = json!([all]);
        }
    }
    for g in s["apgroup"].as_array_mut().into_iter().flatten() {
        if g.get("device_macs").is_some() {
            g["device_macs"] = json!(APS.iter().map(|a| a.mac).collect::<Vec<_>>());
        }
    }
    s["clients"] = CLIENTS
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut v = json!({ "_id": { "$oid": format!("{:024x}", 0x100 + i) }, "mac": c.mac, "hostname": c.hostname, "is_wired": false,
                                "first_seen": 1_760_000_000 + i as i64 * 86_400, "last_seen": 1_791_000_000 });
            if let Some(a) = c.alias {
                v["name"] = json!(a);
                v["noted"] = json!(true);
            }
            v
        })
        .collect();
    Ok(s)
}

/// Where a client is at `ts` (seconds since the epoch), if at home.
fn location(c: &Client, ts: i64, start: i64) -> Option<usize> {
    if c.mac == GUEST {
        let since = ts - start;
        return (2 * 3600..5 * 3600 + 900).contains(&since).then_some(0);
    }
    let hour = (ts.rem_euclid(86_400)) as f64 / 3600.0;
    c.plan.iter().find(|(a, b, _)| hour >= *a && hour < *b).map(|p| p.2)
}

/// How busy a client is at this hour (0..1).
fn activity(kind: Kind, hour: f64) -> f64 {
    let evening = if (18.5..23.0).contains(&hour) { 1.0 } else { 0.15 };
    match kind {
        Kind::Tv => if (19.0..23.0).contains(&hour) { 1.0 } else { 0.01 },
        Kind::Speaker => if (7.0..8.0).contains(&hour) || (18.0..21.0).contains(&hour) { 0.8 } else { 0.02 },
        Kind::Laptop => 0.6,
        Kind::Phone | Kind::Tablet => 0.3 + 0.5 * evening,
        Kind::Iot => 1.0,
        Kind::Server => 0.7,
    }
}

/// Peak download rate in bytes per second.
fn peak_rate(kind: Kind) -> f64 {
    match kind {
        Kind::Tv => 2_400_000.0,
        Kind::Laptop => 900_000.0,
        Kind::Phone | Kind::Tablet => 250_000.0,
        Kind::Speaker => 40_000.0,
        Kind::Iot => 600.0,
        Kind::Server => 60_000.0,
    }
}

#[derive(Clone, Default)]
struct Session {
    ap: usize,
    radio: &'static str,
    since: i64,
    rx: f64,
    tx: f64,
    signal: i64,
}

#[derive(Default, Clone)]
struct ApCounters {
    tx: f64,
    rx: f64,
    pkts: f64,
    retries: f64,
}

/// One inform or notification to send: (time, AP index, payload).
type Out = (i64, usize, Value);

struct Sim {
    rng: Rng,
    template: Value,
    start: i64,
    end_history: i64,
    sessions: Vec<Option<Session>>,
    counters: Vec<ApCounters>,
    vap_counters: Vec<[ApCounters; 3]>,
    syslog: Vec<(i64, usize, String)>,
    cfgversion: Vec<String>,
}

impl Sim {
    fn ap_up(&self, i: usize, ts: i64) -> bool {
        match APS[i].reboot {
            Some((before_end, away)) => {
                let down = self.end_history - before_end;
                !(down..down + away).contains(&ts)
            }
            None => true,
        }
    }

    fn uptime(&self, i: usize, ts: i64) -> i64 {
        match APS[i].reboot {
            Some((before_end, away)) if ts >= self.end_history - before_end + away => ts - (self.end_history - before_end + away) + 60,
            _ => ts - self.start + 9 * 86_400 + 3_717 * (i as i64 + 1),
        }
    }

    fn notif(&self, ap: usize, payload: Value) -> Value {
        json!({ "mac": APS[ap].mac, "inform_as_notif": true, "notif_reason": "event", "notif_payload": payload,
                "cfgversion": self.cfgversion[ap], "hostname": APS[ap].name, "version": VERSION, "model": "U6M" })
    }

    fn log(&mut self, ts: i64, ap: usize, prog: &str, msg: String) {
        self.syslog.push((ts, ap, format!("{prog}: {msg}")));
    }

    /// Moves clients to where they are at `ts`, returning connection notifications.
    fn step_clients(&mut self, ts: i64, out: &mut Vec<Out>) {
        for (ci, c) in CLIENTS.iter().enumerate() {
            let want = location(c, ts, self.start).and_then(|loc| {
                // The strongest AP that is up, if the signal is usable.
                (0..APS.len())
                    .filter(|a| self.ap_up(*a, ts))
                    .map(|a| (a, SIGNAL[loc][a] + c.offset))
                    .max_by_key(|(_, s)| *s)
                    .filter(|(_, s)| *s > -84)
            });
            let at = ts - self.rng.range(1, 40);
            let cur = self.sessions[ci].as_ref().map(|s| s.ap);
            match (cur, want) {
                (None, Some((ap, signal))) => {
                    // The doorbell sometimes fails its handshake first.
                    if c.hostname == "esp-doorbell" && self.rng.unit() < 0.5 {
                        out.push((at - 6, ap, self.notif(ap, json!({ "message_type": "STA_ASSOC_TRACKER", "event_type": "failure", "mac": c.mac, "vap": "wifi0ap1",
                            "assoc_delta": "21000", "wpa_auth_failures": "1", "auth_rssi": signal.to_string(), "sta_dc_reason": "4-way handshake timeout" }))));
                        self.log(at - 6, ap, "hostapd", format!("wifi0ap1: AP-STA-POSSIBLE-PSK-MISMATCH {}", c.mac));
                    }
                    let radio = if c.iot || signal < -72 { "ng" } else { "na" };
                    let vap = vap_name(radio, c.iot);
                    let assoc = self.rng.range(8_000, 40_000);
                    let auth = assoc + self.rng.range(20_000, 90_000);
                    let ipd = auth + self.rng.range(40_000, 900_000);
                    let traffic = ipd + self.rng.range(30_000, 300_000);
                    out.push((at, ap, self.notif(ap, json!({ "message_type": "STA_ASSOC_TRACKER", "event_type": "success", "mac": c.mac, "vap": vap,
                        "assoc_delta": assoc.to_string(), "wpa_auth_delta": auth.to_string(), "ip_delta": ipd.to_string(), "traffic_delta": traffic.to_string(),
                        "dns_responses": "2", "dns_timeouts": "0", "auth_rssi": signal.to_string(), "avg_rssi": signal.to_string(),
                        "auth_algo": "wpa2", "ip_assign_type": "dhcp" }))));
                    self.log(at, ap, "hostapd", format!("{vap}: STA {} IEEE 802.11: associated", c.mac));
                    self.log(at, ap, "hostapd", format!("{vap}: STA {} WPA: pairwise key handshake completed (RSN)", c.mac));
                    self.sessions[ci] = Some(Session { ap, radio, since: at, signal, ..Default::default() });
                }
                (Some(old), None) => {
                    let s = self.sessions[ci].take().unwrap();
                    out.push((at, old, self.notif(old, json!({ "message_type": "STA_ASSOC_TRACKER", "event_type": "sta_leave", "mac": c.mac,
                        "vap": vap_name(s.radio, c.iot), "avg_rssi": s.signal.to_string() }))));
                    self.log(at, old, "hostapd", format!("{}: STA {} IEEE 802.11: disassociated", vap_name(s.radio, c.iot), c.mac));
                }
                (Some(old), Some((ap, signal))) if old != ap => {
                    let s = self.sessions[ci].take().unwrap();
                    let radio = if c.iot || signal < -72 { "ng" } else { "na" };
                    let old_vap = vap_name(s.radio, c.iot);
                    // Phones get a steering request first; most accept.
                    if c.kind == Kind::Phone {
                        let p = format!("wlan: [0:I:ANY] [UNSPECIFIED] vap-0({old_vap}):");
                        self.log(at - 2, old, "kernel", format!("{p}BTM: STA {} RSSI: {}, candidates: 1, error: 0, flags: ALLOW (0x1)", c.mac, s.signal));
                        self.log(at - 2, old, "kernel", format!("{p}BTM: [0]{{{} ch{}/op128/phy14}}", bssid(&APS[ap], radio, 0), if radio == "na" { APS[ap].na } else { APS[ap].ng }));
                        let status = if self.rng.unit() < 0.8 { 0 } else { 7 };
                        self.log(at - 1, old, "kernel", format!("{p}BTM: Received response from [{}](len = 5): dialog_token 1, status {status}, delay 0, bssid {}, cancel 0", c.mac,
                            if status == 0 { bssid(&APS[ap], radio, 0) } else { "n/a".into() }));
                    }
                    let fast = !c.iot && c.kind != Kind::Iot;
                    let left_at = s.signal - self.rng.range(4, 10);
                    let assoc = self.rng.range(4_000, 15_000);
                    out.push((at, old, self.notif(old, json!({ "message_type": "STA_ASSOC_TRACKER", "event_type": "sta_roam", "mac": c.mac, "vap": old_vap,
                        "avg_rssi": left_at.to_string(), "assoc_status": "0" }))));
                    out.push((at + 1, ap, self.notif(ap, json!({ "message_type": "STA_ASSOC_TRACKER", "event_type": "soft failure", "mac": c.mac, "vap": vap_name(radio, c.iot),
                        "ip_assign_type": "roam", "auth_rssi": signal.to_string(), "auth_algo": if fast { "ft" } else { "wpa2" },
                        "assoc_delta": assoc.to_string() }))));
                    self.sessions[ci] = Some(Session { ap, radio, since: s.since, signal, rx: s.rx, tx: s.tx });
                }
                _ => {}
            }
        }
    }

    /// A full status report from AP `i`, after `dt` seconds of traffic.
    fn inform(&mut self, i: usize, ts: i64, dt: f64) -> Value {
        let ap = &APS[i];
        let hour = ts.rem_euclid(86_400) as f64 / 3600.0;
        let mut p = self.template.clone();
        let mut stas: [Vec<Value>; 3] = Default::default();
        let mut vap_traffic = [(0.0f64, 0.0f64); 3];
        for (ci, c) in CLIENTS.iter().enumerate() {
            let Some(s) = self.sessions[ci].as_mut().filter(|s| s.ap == i) else { continue };
            let loc = location(c, ts, self.start).unwrap_or(0);
            let signal = SIGNAL[loc][i] + c.offset + self.rng.range(-3, 3);
            s.signal = signal;
            let load = activity(c.kind, hour) * (0.4 + 0.6 * self.rng.unit());
            let down = peak_rate(c.kind) * load * dt;
            let up = down * if c.kind == Kind::Server { 0.9 } else { 0.12 };
            s.rx += up;
            s.tx += down;
            let vi = if c.iot { 2 } else if s.radio == "na" { 1 } else { 0 };
            vap_traffic[vi].0 += down;
            vap_traffic[vi].1 += up;
            let na = s.radio == "na";
            let rate = match (na, signal) {
                (true, s) if s > -55 => 1_200_900,
                (true, s) if s > -65 => 864_800,
                (true, _) => 432_300,
                (false, s) if s > -60 => 286_800,
                (false, s) if s > -72 => 144_400,
                (false, _) => 57_800,
            };
            let ax = !matches!(c.kind, Kind::Iot | Kind::Speaker);
            let sat = (100 + (signal + 60).min(0) * 2).clamp(20, 100);
            let pkts = (s.tx + s.rx) / 900.0;
            stas[vi].push(json!({
                "mac": c.mac, "hostname": c.hostname, "ip": format!("192.168.1.{}", 100 + ci), "authorized": true, "state": 11,
                "rssi": signal + 95, "signal": signal, "noise": -95, "tx_rate": rate, "rx_rate": rate * 9 / 10,
                "tx_bytes": s.tx as i64, "rx_bytes": s.rx as i64, "tx_packets": (s.tx / 1200.0) as i64, "rx_packets": (s.rx / 600.0) as i64,
                "tx_retries": (pkts * if signal < -70 { 0.18 } else { 0.04 }) as i64, "idletime": self.rng.range(0, 8), "uptime": ts - s.since,
                "satisfaction": sat, "satisfaction_reason": 0, "anomalies": if sat < 70 { 1 } else { 0 },
                "nss": if c.kind == Kind::Iot { 1 } else { 2 }, "chwidth": if na { 3 } else { 1 },
                "is_11ax": ax, "is_11ac": na, "is_11n": true, "is_11r": !c.iot, "vlan_id": 1,
                "wifi_tx_latency_mov": { "avg": if signal < -70 { 12 } else { 2 }, "max": 40, "min": 0 },
            }));
            // Now and then (about hourly and every two hours): poor experience, and a kick.
            if c.hostname == "esp-greenhouse" && self.rng.unit() < dt / 3600.0 {
                self.log(ts, i, "mcad", format!("wireless_agg_stats.log_sta_anomalies(): bssid={} radio=wifi0 vap=wifi0ap1 sta={} signal={signal} satisfaction_now={sat} anomalies=low_rssi,high_tcp_latency", bssid(ap, "ng", 1), c.mac));
            }
            if c.hostname == "esp-greenhouse" && signal < -76 && self.rng.unit() < dt / 7200.0 {
                self.log(ts, i, "stamgr", format!("kick-sta-on {} wifi0ap1 (reason:Low RSSI rssi:{})", c.mac, signal + 95));
            }
        }
        let busy = 0.5 + 0.5 * (((hour - 20.0) / 24.0 * std::f64::consts::TAU).cos());
        let c = &mut self.counters[i];
        let (down, up): (f64, f64) = vap_traffic.iter().fold((0.0, 0.0), |a, v| (a.0 + v.0, a.1 + v.1));
        c.tx += up + 400.0 * dt;
        c.rx += down + 900.0 * dt;
        c.pkts += (down + up) / 1000.0;
        c.retries += (down + up) / 1000.0 * 0.05;
        let (eth_rx, eth_tx, ap_pkts, ap_retries) = (c.rx, c.tx, c.pkts, c.retries);

        let vaps: Vec<Value> = [("ng", 0u8, SSID, 0usize), ("na", 0u8, SSID, 1), ("ng", 1u8, IOT_SSID, 2)]
            .into_iter()
            .map(|(radio, idx, essid, vi)| {
                let vc = &mut self.vap_counters[i][vi];
                vc.tx += vap_traffic[vi].0 + 2_000.0 * dt;
                vc.rx += vap_traffic[vi].1 + 500.0 * dt;
                vc.pkts += (vap_traffic[vi].0 + vap_traffic[vi].1) / 1000.0 + dt;
                let sta = std::mem::take(&mut stas[vi]);
                let n = sta.len() as i64;
                let avg = if n > 0 { sta.iter().map(|s| s["signal"].as_i64().unwrap_or(0)).sum::<i64>() / n } else { 0 };
                let sat = if n > 0 { sta.iter().map(|s| s["satisfaction"].as_i64().unwrap_or(0)).sum::<i64>() / n } else { 100 };
                let na = radio == "na";
                json!({
                    "bssid": bssid(ap, radio, idx), "essid": essid, "radio": radio, "radio_name": if na { "wifi1" } else { "wifi0" },
                    "name": vap_name(radio, vi == 2), "id": format!("{vi}"), "channel": if na { ap.na } else { ap.ng }, "bw": if na { ap.na_bw } else { 20 },
                    "tx_power": if na { ap.power.1 } else { ap.power.0 }, "usage": "user", "up": true, "state": "RUN", "num_sta": n,
                    "tx_bytes": vc.tx as i64, "rx_bytes": vc.rx as i64, "tx_packets": (vc.tx / 1100.0) as i64, "rx_packets": (vc.rx / 500.0) as i64,
                    "tx_retries": (vc.tx / 1100.0 * if na { 0.04 } else { 0.11 }) as i64, "tx_dropped": 0, "rx_dropped": 0, "tx_errors": 0, "ccq": 0,
                    "satisfaction": sat, "avg_client_signal": avg, "wifi_tx_latency_mov": { "avg": if na { 2 } else { 6 }, "max": 40, "min": 0 },
                    "tx_mcast": (vc.pkts * 0.02) as i64, "rx_mcast": (vc.pkts * 0.01) as i64, "tx_bcast": (vc.pkts * 0.01) as i64, "rx_bcast": (vc.pkts * 0.005) as i64,
                    "wifi_tx_attempts": (vc.tx / 1000.0) as i64, "wifi_tx_dropped": 0, "sta_table": sta,
                })
            })
            .collect();

        for r in p["radio_table"].as_array_mut().into_iter().flatten() {
            let na = r["radio"] == "na";
            let base = if na { 6.0 } else { 22.0 };
            let interf = if na { 2 } else { self.rng.range(9, 18) };
            let self_tx = ((if na { 14.0 } else { 6.0 }) * busy + self.rng.unit() * 3.0) as i64;
            let total = (base * (0.6 + 0.4 * busy)) as i64 + interf + self_tx;
            let ath = &mut r["athstats"];
            ath["cu_total"] = json!(total.min(95));
            ath["cu_self_tx"] = json!(self_tx);
            ath["cu_self_rx"] = json!(self_tx / 3);
            ath["cu_interf"] = json!(interf);
            ath["noise_floor"] = json!(if na { -96 } else { -93 + self.rng.range(-1, 1) });
            ath["n_tx_pkts"] = json!(ap_pkts as i64);
            ath["n_tx_retries"] = json!((ap_retries * if na { 0.7 } else { 1.6 }) as i64);
            ath["n_rx_pkts"] = json!((ap_pkts * 0.6) as i64);
            let band = if na { "na" } else { "ng" };
            let mut scan: Vec<Value> = NEIGHBOURS
                .iter()
                .filter(|n| n.2 == band)
                .map(|n| neighbour(n.0, n.1, band, n.3, n.4, n.5[i] + self.rng.range(-2, 2), false, ""))
                .collect();
            for (j, other) in APS.iter().enumerate().filter(|(j, _)| *j != i) {
                let signal = [[0, -58, -71], [-58, 0, -74], [-71, -74, 0]][i][j] + if na { -9 } else { 0 } + self.rng.range(-2, 2);
                let ch = if na { other.na } else { other.ng };
                scan.push(neighbour(&bssid(other, band, 0), SSID, band, ch, if na { other.na_bw } else { 20 }, signal, true, other.name));
            }
            if !na && i == 2 && ts > self.end_history - 3 * 3600 {
                scan.push(neighbour(LOOKALIKE.0, LOOKALIKE.1, "ng", LOOKALIKE.2, 20, LOOKALIKE.3 + self.rng.range(-2, 2), false, ""));
            }
            r["scan_table"] = json!(scan);
            let channels: Vec<i64> = if na { vec![36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140] } else { (1..=13).collect() };
            r["spectrum_table"] = json!(channels
                .iter()
                .map(|ch| {
                    let others = NEIGHBOURS.iter().filter(|n| n.2 == band && (n.3 - ch).abs() <= if na { 12 } else { 2 }).count() as i64;
                    let util = (others * if na { 4 } else { 9 }) + self.rng.range(1, 6) + if *ch == if na { ap.na } else { ap.ng } { self_tx } else { 0 };
                    json!({ "channel": ch, "center_freq": if na { 5000 + ch * 5 } else { 2407 + ch * 5 }, "width": 20,
                            "utilization": util.min(90), "interference": -96 + others * 3, "interference_type": [], "other_bss_count": others, "total_samples": 120 })
                })
                .collect::<Vec<_>>());
            r["spectrum_table_time"] = json!(1800);
        }

        let n_clients: i64 = vaps.iter().map(|v| v["num_sta"].as_i64().unwrap_or(0)).sum();
        let cpu = 3.0 + n_clients as f64 * 0.6 + busy * 4.0 + self.rng.unit() * 3.0;
        let mem = 24.0 + n_clients as f64 * 0.3 + self.rng.unit();
        let uptime = self.uptime(i, ts);
        let mac = ap.mac;
        p["mac"] = json!(mac);
        p["serial"] = json!(mac.replace(':', "").to_uppercase());
        p["hash_id"] = json!(hex_key(&format!("hash {mac}"), 8));
        p["anon_id"] = json!(format!("00000000-0000-4000-8000-0000000000{:02x}", 0x10 + i));
        p["hostname"] = json!(ap.name);
        p["ip"] = json!(ip(ap.ip));
        p["inform_ip"] = json!(ip(CONTROLLER_IP));
        p["inform_url"] = json!(format!("http://{}:8080/inform", ip(CONTROLLER_IP)));
        p["cfgversion"] = json!(self.cfgversion[i]);
        p["uptime"] = json!(uptime);
        p["time"] = json!(ts);
        p["last_error_conns"] = json!([]);
        p["fingerprint"] = json!(format!("SHA256:{}", hex_key(&format!("fp {mac}"), 21)));
        p["qrid"] = json!(hex_key(&format!("qr {mac}"), 3));
        p["satisfaction"] = json!(vaps.iter().filter(|v| v["num_sta"].as_i64().unwrap_or(0) > 0).map(|v| v["satisfaction"].as_i64().unwrap_or(100)).min().unwrap_or(100));
        p["sys_stats"]["mem_used"] = json!((mem / 100.0 * 939_495_424.0) as i64);
        p["sys_stats"]["loadavg_1"] = json!(format!("{:.2}", 0.6 + cpu / 25.0));
        p["sys_stats"]["loadavg_5"] = json!(format!("{:.2}", 0.6 + cpu / 30.0));
        p["sys_stats"]["loadavg_15"] = json!(format!("{:.2}", 0.6 + cpu / 35.0));
        p["system-stats"] = json!({ "cpu": format!("{cpu:.1}"), "mem": format!("{mem:.1}"), "uptime": uptime.to_string() });
        if let Some(eth) = p["if_table"].as_array_mut().and_then(|t| t.first_mut()) {
            eth["mac"] = json!(mac);
            eth["rx_bytes"] = json!(eth_rx as i64);
            eth["tx_bytes"] = json!(eth_tx as i64);
            eth["rx_packets"] = json!((eth_rx / 900.0) as i64);
            eth["tx_packets"] = json!((eth_tx / 600.0) as i64);
        }
        p["vap_table"] = json!(vaps);
        p
    }
}

fn vap_name(radio: &str, iot: bool) -> &'static str {
    match (radio, iot) {
        (_, true) => "wifi0ap1",
        ("na", _) => "wifi1ap0",
        _ => "wifi0ap0",
    }
}

#[allow(clippy::too_many_arguments)]
fn neighbour(bssid: &str, essid: &str, band: &str, channel: i64, bw: i64, signal: i64, ours: bool, ap_name: &str) -> Value {
    let freq = if band == "na" { 5000 + channel * 5 } else { 2407 + channel * 5 };
    json!({ "bssid": bssid, "essid": essid, "band": band, "channel": channel, "bw": bw, "freq": freq, "center_freq": freq,
            "signal": signal, "rssi": signal + 95, "noise": -95, "security": if essid.is_empty() { "WPA2-Personal (AES/CCMP)" } else { "WPA2+WPA3-Personal (AES/CCMP)" },
            "is_unifi": ours, "is_ubnt": ours, "is_isolated": false, "ap_name": ap_name, "model": if ours { "U6M" } else { "" }, "age": 30 })
}

/// Writes pcap records: one HTTP keep-alive connection per AP and syslog datagrams.
struct PcapWriter<W: Write> {
    out: W,
    seq: Vec<(u32, u32)>,
}

impl<W: Write> PcapWriter<W> {
    fn new(mut out: W) -> Result<Self> {
        synth::write_pcap_header(&mut out, 262_144)?;
        Ok(PcapWriter { out, seq: vec![(1, 1); APS.len()] })
    }

    fn record(&mut self, ts_ms: i64, frame: &[u8]) -> Result<()> {
        Ok(synth::write_pcap_record(&mut self.out, ts_ms * 1000, frame)?)
    }

    fn tcp(&mut self, ts_ms: i64, ap: usize, to_server: bool, data: &[u8]) -> Result<()> {
        let a = &APS[ap];
        let (apmac, ctrl_mac) = (mac_bytes(a.mac), [0x0e, 0x5d, 0x7a, 0, 0, 0x10]);
        let port = 41_000 + ap as u16;
        for chunk in data.chunks(32_000) {
            let seq = if to_server { &mut self.seq[ap].0 } else { &mut self.seq[ap].1 };
            let builder = if to_server {
                PacketBuilder::ethernet2(apmac, ctrl_mac).ipv4(a.ip, CONTROLLER_IP, 64).tcp(port, 8080, *seq, 65_535)
            } else {
                PacketBuilder::ethernet2(ctrl_mac, apmac).ipv4(CONTROLLER_IP, a.ip, 64).tcp(8080, port, *seq, 65_535)
            };
            *seq = seq.wrapping_add(chunk.len() as u32);
            let mut frame = Vec::with_capacity(chunk.len() + 64);
            builder.write(&mut frame, chunk)?;
            self.record(ts_ms, &frame)?;
        }
        Ok(())
    }

    fn syslog(&mut self, ts_ms: i64, ap: usize, text: &str) -> Result<()> {
        let a = &APS[ap];
        let mut frame = Vec::new();
        PacketBuilder::ethernet2(mac_bytes(a.mac), [0x0e, 0x5d, 0x7a, 0, 0, 0x10]).ipv4(a.ip, CONTROLLER_IP, 64).udp(38_000, 5514).write(&mut frame, text.as_bytes())?;
        self.record(ts_ms, &frame)
    }
}

/// Streams the demo capture: `hours` of history ending now, then (with
/// `live`) a new report from every AP every 10 seconds, in real time.
pub fn run(hours: f64, live: bool, out: impl Write) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let start = now - (hours * 3600.0) as i64;
    let mut template: Value = serde_json::from_str(TEMPLATE_INFORM)?;
    template["version"] = json!(VERSION);
    let mut sim = Sim {
        rng: Rng(42),
        template,
        start,
        end_history: now,
        sessions: vec![None; CLIENTS.len()],
        counters: vec![ApCounters::default(); APS.len()],
        vap_counters: vec![Default::default(); APS.len()],
        syslog: Vec::new(),
        cfgversion: APS.iter().map(|a| hex_key(&format!("cfg {}", a.mac), 8)).collect(),
    };
    let mut pcap = PcapWriter::new(out)?;
    let mut t = start;
    let mut last = vec![start; APS.len()];
    loop {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        if t > wall {
            if !live {
                break;
            }
            pcap.out.flush()?;
            std::thread::sleep(Duration::from_secs((t - wall) as u64));
        }
        // Once a minute while catching up, every 10 seconds near real time.
        let step = if wall - t > 300 { 60 } else { 10 };
        let mut batch: Vec<Out> = Vec::new();
        sim.step_clients(t, &mut batch);
        for (i, last) in last.iter_mut().enumerate() {
            if !sim.ap_up(i, t) {
                continue;
            }
            let at = t + i as i64 * 3;
            if APS[i].reboot.is_some() && !sim.ap_up(i, t - step) {
                sim.log(at - 30, i, "syswrapper", "Restarting system after power loss".into());
            }
            let dt = (at - *last).max(1) as f64;
            *last = at;
            let p = sim.inform(i, at, dt);
            batch.push((at, i, p));
        }
        batch.sort_by_key(|b| b.0);
        let mut logs = std::mem::take(&mut sim.syslog);
        logs.sort_by_key(|l| l.0);
        let mut logs = logs.into_iter().peekable();
        for (at, i, payload) in batch {
            while let Some((lt, li, line)) = logs.next_if(|l| l.0 <= at) {
                write_syslog(&mut pcap, lt, li, &line)?;
            }
            let key = authkey(&APS[i]);
            let mac: Mac = APS[i].mac.parse()?;
            let body = inform::seal(mac, Flags(Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB), crate::random_iv(), &key, payload.to_string().as_bytes());
            pcap.tcp(at * 1000, i, true, &http("POST /inform HTTP/1.1\r\nHost: controller.home.arpa:8080\r\nContent-Type: application/x-binary\r\n", &body))?;
            let reply = json!({ "_type": "noop", "interval": step, "server_time_in_utc": (at * 1000).to_string() });
            let sealed = inform::seal(mac, Flags(Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB), crate::random_iv(), &key, reply.to_string().as_bytes());
            pcap.tcp(at * 1000 + 40, i, false, &http("HTTP/1.1 200 OK\r\nContent-Type: application/x-binary\r\n", &sealed))?;
        }
        for (lt, li, line) in logs {
            write_syslog(&mut pcap, lt, li, &line)?;
        }
        t += step;
    }
    pcap.out.flush()?;
    Ok(())
}

fn write_syslog<W: Write>(pcap: &mut PcapWriter<W>, ts: i64, ap: usize, line: &str) -> Result<()> {
    let a = &APS[ap];
    let stamp = chrono_like(ts);
    let tag = format!("{},U6M-{VERSION}", a.mac.replace(':', ""));
    pcap.syslog(ts * 1000, ap, &format!("<14>{stamp} {} {tag}: {line}", a.name.replace(' ', "-")))
}

/// `Mon dd hh:mm:ss` in UTC, as BSD syslog writes it.
fn chrono_like(ts: i64) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let secs = ts.rem_euclid(86_400);
    let (_, m, d) = wire::civil_from_days(ts.div_euclid(86_400));
    format!("{} {d:>2} {:02}:{:02}:{:02}", MONTHS[(m - 1) as usize], secs / 3600, secs / 60 % 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_dates() {
        assert_eq!(chrono_like(1_791_830_666), "Oct 12 18:44:26");
        assert_eq!(chrono_like(0), "Jan  1 00:00:00");
    }

    #[test]
    fn capture_decodes_with_the_state_keys() {
        let keys = wire::keys::KeyStore::from_value(&state().unwrap());
        let mut buf = Vec::new();
        run(0.5, false, &mut buf).unwrap();
        let mut pairer = wire::exchange::Pairer::default();
        let mut informs = 0;
        let mut syslog = 0;
        wire::capture::run_with_udp(&buf[..], &[8080], &[5514], |ev| {
            if matches!(ev, wire::capture::HttpEvent::Datagram { .. }) {
                syslog += 1;
            } else if let Some(wire::exchange::InformEvent::Inform { decoded, .. }) = pairer.handle(&keys, ev) {
                decoded.unwrap();
                informs += 1;
            }
        })
        .unwrap();
        assert!(informs > 3 * 30, "{informs} informs");
        assert!(syslog > 0);
    }
}
