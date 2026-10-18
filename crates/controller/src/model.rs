//! Normalised view of an AP's inform: typed samples for storage and the API.
//!
//! Firmware sends some numbers as strings (`"cpu": "3.9"`), so every field goes
//! through lenient helpers. A missing field becomes `None` rather than an error:
//! models and firmware versions differ in what they report.

use std::sync::Arc;

use inform::Mac;
use serde::Serialize;
use serde_json::Value;

/// Seconds since the Unix epoch.
pub type Ts = i64;

/// A MAC as a number with the locally administered bit cleared, so the
/// addresses a device derives from its own (an AP's BSSIDs, a phone's
/// hotspot) sit next to it.
pub fn hardware_num(mac: &Mac) -> u64 {
    let mut b = mac.0;
    b[0] &= !0x02;
    b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x))
}

/// Whether two [`hardware_num`]s are likely one device's: within 16 of each
/// other (an AP's BSSIDs are its MAC plus a little).
pub fn same_hardware(a: u64, b: u64) -> bool {
    a.abs_diff(b) <= 16
}

/// Declares a fieldless enum whose variants are stored and sent by name, with
/// `as_str`, `parse`, `Display` and serialisation as that name (and, in tests,
/// `ALL` variants in order).
macro_rules! named_enum {
    ($(#[$attr:meta])* $vis:vis enum $name:ident { $($variant:ident = $str:literal),* $(,)? }) => {
        $(#[$attr])*
        $vis enum $name {
            $($variant,)*
        }

        impl $name {
            #[cfg(test)]
            #[allow(dead_code)]
            pub const ALL: &[$name] = &[$($name::$variant,)*];

            /// As stored and as the API names it.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $str,)*
                }
            }

            #[allow(dead_code)]
            pub fn parse(s: &str) -> Option<$name> {
                match s {
                    $($str => Some($name::$variant),)*
                    _ => None,
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}
pub(crate) use named_enum;

#[derive(Debug, Clone, Serialize)]
pub struct ApSample {
    pub mac: Mac,
    pub ts: Ts,
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub model_display: Option<String>,
    pub version: Option<String>,
    pub ip: Option<String>,
    pub serial: Option<String>,
    pub hash_id: Option<String>,
    pub cfgversion: Option<String>,
    pub uptime: Option<i64>,
    pub cpu: Option<f64>,
    pub mem: Option<f64>,
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
    pub mem_total: Option<i64>,
    pub mem_used: Option<i64>,
    pub satisfaction: Option<i64>,
    pub num_sta: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UplinkSample {
    pub ifname: String,
    pub up: Option<bool>,
    pub speed: Option<i64>,
    pub full_duplex: Option<bool>,
    pub rx_bytes: Option<i64>,
    pub tx_bytes: Option<i64>,
    pub rx_packets: Option<i64>,
    pub tx_packets: Option<i64>,
    pub rx_errors: Option<i64>,
    pub tx_errors: Option<i64>,
    pub rx_dropped: Option<i64>,
    pub tx_dropped: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RadioSample {
    /// Band code as the AP reports it: `ng` (2.4 GHz), `na` (5 GHz), `6e` (6 GHz).
    pub radio: String,
    pub name: Option<String>,
    /// Channel, width and power come from the radio's VAPs (the radio table lacks them).
    pub channel: Option<i64>,
    pub bw: Option<i64>,
    pub tx_power: Option<i64>,
    pub cu_total: Option<i64>,
    pub cu_self_rx: Option<i64>,
    pub cu_self_tx: Option<i64>,
    pub cu_interf: Option<i64>,
    pub noise_floor: Option<i64>,
    pub tx_packets: Option<i64>,
    pub tx_retries: Option<i64>,
    pub rx_packets: Option<i64>,
    pub num_sta: i64,
    /// Built-in antenna gain in dBi (EIRP = transmit power + gain).
    pub antenna_gain: Option<i64>,
    pub min_txpower: Option<i64>,
    pub max_txpower: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VapSample {
    pub bssid: String,
    pub essid: Option<String>,
    pub radio: Option<String>,
    pub name: Option<String>,
    pub channel: Option<i64>,
    /// Channel width (MHz) and transmit power (dBm) of its radio, as this VAP reports them.
    pub bw: Option<i64>,
    pub tx_power: Option<i64>,
    pub num_sta: Option<i64>,
    pub rx_bytes: Option<i64>,
    pub tx_bytes: Option<i64>,
    pub rx_packets: Option<i64>,
    pub tx_packets: Option<i64>,
    pub tx_retries: Option<i64>,
    pub tx_dropped: Option<i64>,
    pub ccq: Option<i64>,
    pub satisfaction: Option<i64>,
    pub avg_client_signal: Option<i64>,
    /// Moving average of Wi-Fi TX latency in ms, when the AP reports it.
    pub latency_avg: Option<i64>,
    pub tx_mcast: Option<i64>,
    pub rx_mcast: Option<i64>,
    pub tx_bcast: Option<i64>,
    pub rx_bcast: Option<i64>,
    pub rx_dropped: Option<i64>,
    pub tx_errors: Option<i64>,
    /// Transmit attempts and frames given up on (retries = attempts - successes).
    pub wifi_tx_attempts: Option<i64>,
    pub wifi_tx_dropped: Option<i64>,
}

/// A network heard by one of the AP's radios in a background scan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NeighborSample {
    pub radio: Option<String>,
    pub bssid: String,
    pub essid: Option<String>,
    pub channel: Option<i64>,
    pub bw: Option<i64>,
    pub center_freq: Option<i64>,
    pub security: Option<String>,
    pub signal: Option<i64>,
    pub noise: Option<i64>,
    /// A Ubiquiti AP (possibly one of ours: see `ap_name`).
    pub is_unifi: bool,
    /// A Ubiquiti AP's beacon saying it has lost its uplink (isolated).
    pub is_isolated: bool,
    pub ap_name: Option<String>,
    pub model: Option<String>,
}

/// One channel from a spectrum (channel survey) scan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpectrumSample {
    pub radio: String,
    pub channel: i64,
    pub width: Option<i64>,
    pub utilization: Option<i64>,
    pub interference: Option<i64>,
    pub other_bss_count: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ClientSample {
    pub mac: Mac,
    pub ap_mac: Mac,
    pub bssid: String,
    pub essid: Option<String>,
    pub radio: Option<String>,
    pub channel: Option<i64>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub rssi: Option<i64>,
    pub signal: Option<i64>,
    pub noise: Option<i64>,
    /// PHY rates in kbps.
    pub tx_rate: Option<i64>,
    pub rx_rate: Option<i64>,
    pub tx_bytes: Option<i64>,
    pub rx_bytes: Option<i64>,
    pub tx_packets: Option<i64>,
    pub rx_packets: Option<i64>,
    pub tx_retries: Option<i64>,
    pub idletime: Option<i64>,
    /// Seconds connected to this AP.
    pub uptime: Option<i64>,
    pub satisfaction: Option<i64>,
    pub anomalies: Option<i64>,
    pub nss: Option<i64>,
    pub wifi_gen: Option<&'static str>,
    pub vlan_id: Option<i64>,
    pub latency_avg: Option<i64>,
    pub is_11r: Option<bool>,
    /// Multicast and broadcast traffic by type, when the AP reports it.
    pub multicast: Option<Multicast>,
}

/// Packet and byte counters. `tx` is what the AP delivered to the client,
/// `rx` what the client sent.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq)]
pub struct McastCounts {
    pub tx_pkts: i64,
    pub tx_bytes: i64,
    pub rx_pkts: i64,
    pub rx_bytes: i64,
}

impl McastCounts {
    fn parse(v: &Value) -> McastCounts {
        let n = |k: &str| v[k].as_i64().unwrap_or(0);
        McastCounts { tx_pkts: n("tx_pkts"), tx_bytes: n("tx_bytes"), rx_pkts: n("rx_pkts"), rx_bytes: n("rx_bytes") }
    }

    pub fn add(&mut self, o: &McastCounts) {
        self.tx_pkts += o.tx_pkts;
        self.tx_bytes += o.tx_bytes;
        self.rx_pkts += o.rx_pkts;
        self.rx_bytes += o.rx_bytes;
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct McastGroup {
    pub group_ip: String,
    pub dst_port: Option<i64>,
    /// Traffic type: mdns, ssdp, igmp, stream, dhcp, arp...
    #[serde(rename = "type")]
    pub kind: Option<String>,
    #[serde(flatten)]
    pub counts: McastCounts,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Multicast {
    /// Counters per traffic type (arp, dhcp, dhcpv6, igmp, ipv6_nd, mdns, mld, ssdp, stream, other).
    pub types: std::collections::BTreeMap<String, McastCounts>,
    /// Destination groups the client's traffic used.
    pub groups: Vec<McastGroup>,
    /// Groups the client has joined.
    pub memberships: Vec<String>,
    /// mDNS service types the client's traffic concerned (e.g. `_googlecast._tcp.local`).
    pub services: Vec<McastService>,
}

#[derive(Debug, Clone, Serialize)]
pub struct McastService {
    pub name: String,
    pub pkts: i64,
    pub bytes: i64,
}

impl Multicast {
    fn parse(v: &Value) -> Option<Multicast> {
        let types = v["types"].as_object()?.iter().map(|(k, x)| (k.clone(), McastCounts::parse(x))).collect();
        let groups = v["groups"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|g| {
                Some(McastGroup { group_ip: g["group_ip"].as_str()?.to_string(), dst_port: g["dst_port"].as_i64(), kind: string(&g["type"]), counts: McastCounts::parse(g) })
            })
            .collect();
        let memberships = v["memberships"].as_array().into_iter().flatten().filter_map(|m| m["group_ip"].as_str().map(str::to_string)).collect();
        let services = v["services"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| Some(McastService { name: x["name"].as_str()?.to_string(), pkts: x["pkts"].as_i64().unwrap_or(0), bytes: x["bytes"].as_i64().unwrap_or(0) }))
            .collect();
        Some(Multicast { types, groups, memberships, services })
    }

    /// "optimized" when the client joined groups and the AP tracks them,
    /// "flooding" when it joined groups the AP floods to everyone.
    pub fn delivery(&self) -> Option<&'static str> {
        if self.memberships.is_empty() {
            None
        } else if self.groups.is_empty() {
            Some("flooding")
        } else {
            Some("optimized")
        }
    }

    pub fn total(&self) -> McastCounts {
        let mut t = McastCounts::default();
        for c in self.types.values() {
            t.add(c);
        }
        t
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub ap: ApSample,
    pub uplink: Option<UplinkSample>,
    pub radios: Vec<RadioSample>,
    pub vaps: Vec<VapSample>,
    /// Shared with the live client list, which holds the same samples.
    /// Not sent with the AP (nor its neighbours and spectrum): its page gets
    /// the clients beside it, and the RF pages have routes of their own.
    #[serde(skip_serializing)]
    pub clients: Vec<Arc<ClientSample>>,
    #[serde(skip_serializing)]
    pub neighbors: Vec<NeighborSample>,
    /// Only channels with survey samples (empty until a spectrum scan runs).
    #[serde(skip_serializing)]
    pub spectrum: Vec<SpectrumSample>,
    /// False for an inform without a VAP table: the absence of clients then
    /// says nothing about whether they are still connected. Only notifications
    /// (which are not parsed) have been seen without one. An empty table is a
    /// report like any other: an AP with every network off has no clients.
    pub has_vap_table: bool,
}

fn int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse::<f64>().ok().map(|f| f as i64),
        _ => None,
    }
}

fn float(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn string(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

fn wifi_gen(sta: &Value) -> Option<&'static str> {
    // Highest standard the client is using.
    [("is_11be", "be"), ("is_11ax", "ax"), ("is_11ac", "ac"), ("is_11n", "n"), ("is_11a", "a"), ("is_11b", "b")]
        .into_iter()
        .find(|(k, _)| sta[*k].as_bool() == Some(true))
        .map(|(_, g)| g)
}

/// Parses an inform payload. `ts` is when it was received (capture time in shadow mode).
pub fn parse(ts: Ts, p: &Value) -> anyhow::Result<Snapshot> {
    let mac: Mac = p["mac"].as_str().ok_or_else(|| anyhow::anyhow!("inform without mac"))?.parse()?;
    let sys = &p["sys_stats"];
    let stats = &p["system-stats"];
    let vap_table = p["vap_table"].as_array();
    let has_vap_table = vap_table.is_some();

    let mut vaps = Vec::new();
    let mut clients = Vec::new();
    for v in vap_table.into_iter().flatten() {
        // Lower case, as the neighbours' BSSIDs are kept: the two are compared.
        let Some(bssid) = string(&v["bssid"]).map(|b| b.to_ascii_lowercase()) else { continue };
        // Clients come from user and guest VAPs; mesh uplink/downlink VAPs are skipped.
        let usage = v["usage"].as_str().unwrap_or("user");
        let essid = string(&v["essid"]);
        let radio = string(&v["radio"]);
        let channel = int(&v["channel"]);
        vaps.push(VapSample {
            bssid: bssid.clone(),
            essid: essid.clone(),
            radio: radio.clone(),
            name: string(&v["name"]),
            channel,
            bw: int(&v["bw"]),
            tx_power: int(&v["tx_power"]),
            num_sta: int(&v["num_sta"]),
            rx_bytes: int(&v["rx_bytes"]),
            tx_bytes: int(&v["tx_bytes"]),
            rx_packets: int(&v["rx_packets"]),
            tx_packets: int(&v["tx_packets"]),
            tx_retries: int(&v["tx_retries"]),
            tx_dropped: int(&v["tx_dropped"]),
            ccq: int(&v["ccq"]),
            satisfaction: int(&v["satisfaction"]),
            avg_client_signal: int(&v["avg_client_signal"]),
            latency_avg: int(&v["wifi_tx_latency_mov"]["avg"]),
            tx_mcast: int(&v["tx_mcast"]),
            rx_mcast: int(&v["rx_mcast"]),
            tx_bcast: int(&v["tx_bcast"]),
            rx_bcast: int(&v["rx_bcast"]),
            rx_dropped: int(&v["rx_dropped"]),
            tx_errors: int(&v["tx_errors"]),
            wifi_tx_attempts: int(&v["wifi_tx_attempts"]),
            wifi_tx_dropped: int(&v["wifi_tx_dropped"]),
        });
        if !matches!(usage, "user" | "guest") {
            continue;
        }
        for s in v["sta_table"].as_array().into_iter().flatten() {
            let Some(cmac) = s["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else { continue };
            clients.push(Arc::new(ClientSample {
                mac: cmac,
                ap_mac: mac,
                bssid: bssid.clone(),
                essid: essid.clone(),
                radio: radio.clone(),
                channel,
                hostname: string(&s["hostname"]),
                ip: string(&s["ip"]),
                rssi: int(&s["rssi"]),
                signal: int(&s["signal"]),
                noise: int(&s["noise"]),
                tx_rate: int(&s["tx_rate"]),
                rx_rate: int(&s["rx_rate"]),
                tx_bytes: int(&s["tx_bytes"]),
                rx_bytes: int(&s["rx_bytes"]),
                tx_packets: int(&s["tx_packets"]),
                rx_packets: int(&s["rx_packets"]),
                tx_retries: int(&s["tx_retries"]),
                idletime: int(&s["idletime"]),
                uptime: int(&s["uptime"]),
                satisfaction: int(&s["satisfaction"]),
                anomalies: int(&s["anomalies"]),
                nss: int(&s["nss"]),
                wifi_gen: wifi_gen(s),
                vlan_id: int(&s["vlan_id"]),
                latency_avg: int(&s["wifi_tx_latency_mov"]["avg"]),
                is_11r: s["is_11r"].as_bool(),
                multicast: Multicast::parse(&s["multicast"]),
            }));
        }
    }

    let mut radios = Vec::new();
    let mut neighbors = Vec::new();
    let mut spectrum = Vec::new();
    for r in p["radio_table"].as_array().into_iter().flatten() {
        let radio = string(&r["radio"]);
        for n in r["scan_table"].as_array().into_iter().flatten() {
            let Some(bssid) = string(&n["bssid"]) else { continue };
            neighbors.push(NeighborSample {
                radio: string(&n["band"]).or(radio.clone()),
                bssid: bssid.to_ascii_lowercase(),
                essid: string(&n["essid"]),
                channel: int(&n["channel"]),
                bw: int(&n["bw"]),
                center_freq: int(&n["center_freq"]),
                security: string(&n["security"]),
                signal: int(&n["signal"]),
                noise: int(&n["noise"]),
                is_unifi: n["is_unifi"].as_bool() == Some(true) || n["is_ubnt"].as_bool() == Some(true),
                is_isolated: n["is_isolated"].as_bool() == Some(true),
                ap_name: string(&n["ap_name"]),
                model: string(&n["model"]),
            });
        }
        let Some(radio) = radio else { continue };
        for c in r["spectrum_table"].as_array().into_iter().flatten() {
            let Some(channel) = int(&c["channel"]) else { continue };
            if int(&c["total_samples"]).unwrap_or(0) == 0 {
                continue; // no survey has run for this channel
            }
            spectrum.push(SpectrumSample {
                radio: radio.clone(),
                channel,
                width: int(&c["width"]),
                utilization: int(&c["utilization"]),
                interference: int(&c["interference"]),
                other_bss_count: int(&c["other_bss_count"]),
            });
        }
        let ath = &r["athstats"];
        // Channel, width and power all from the same VAP.
        let first_vap = vaps.iter().find(|v| v.radio.as_deref() == Some(radio.as_str()));
        radios.push(RadioSample {
            name: string(&r["name"]),
            channel: first_vap.and_then(|v| v.channel),
            bw: first_vap.and_then(|v| v.bw),
            tx_power: first_vap.and_then(|v| v.tx_power),
            cu_total: int(&ath["cu_total"]),
            cu_self_rx: int(&ath["cu_self_rx"]),
            cu_self_tx: int(&ath["cu_self_tx"]),
            cu_interf: int(&ath["cu_interf"]),
            noise_floor: int(&ath["noise_floor"]),
            tx_packets: int(&ath["n_tx_pkts"]),
            tx_retries: int(&ath["n_tx_retries"]),
            rx_packets: int(&ath["n_rx_pkts"]),
            antenna_gain: int(&r["builtin_ant_gain"]),
            min_txpower: int(&r["min_txpower"]),
            max_txpower: int(&r["max_txpower"]),
            num_sta: clients.iter().filter(|c| c.radio.as_deref() == Some(radio.as_str())).count() as i64,
            radio,
        });
    }

    // The uplink is the interface named by `uplink` (eth0 for wired APs).
    let uplink_name = p["uplink"].as_str().unwrap_or("eth0");
    let uplink = p["if_table"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|i| i["name"].as_str() == Some(uplink_name))
        .map(|i| UplinkSample {
            ifname: uplink_name.to_string(),
            up: i["up"].as_bool(),
            speed: int(&i["speed"]),
            full_duplex: i["full_duplex"].as_bool(),
            rx_bytes: int(&i["rx_bytes"]),
            tx_bytes: int(&i["tx_bytes"]),
            rx_packets: int(&i["rx_packets"]),
            tx_packets: int(&i["tx_packets"]),
            rx_errors: int(&i["rx_errors"]),
            tx_errors: int(&i["tx_errors"]),
            rx_dropped: int(&i["rx_dropped"]),
            tx_dropped: int(&i["tx_dropped"]),
        });

    let mem_total = int(&sys["mem_total"]);
    let mem_used = int(&sys["mem_used"]);
    let ap = ApSample {
        mac,
        ts,
        hostname: string(&p["hostname"]),
        model: string(&p["model"]),
        model_display: string(&p["model_display"]),
        version: string(&p["version"]),
        ip: string(&p["ip"]),
        serial: string(&p["serial"]),
        hash_id: string(&p["hash_id"]),
        cfgversion: string(&p["cfgversion"]),
        uptime: int(&p["uptime"]),
        cpu: float(&stats["cpu"]),
        mem: float(&stats["mem"]),
        load1: float(&sys["loadavg_1"]),
        load5: float(&sys["loadavg_5"]),
        load15: float(&sys["loadavg_15"]),
        mem_total,
        mem_used,
        satisfaction: int(&p["satisfaction"]),
        num_sta: has_vap_table.then_some(clients.len() as i64),
    };

    Ok(Snapshot { ap, uplink, radios, vaps, clients, neighbors, spectrum, has_vap_table })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The sanitised captures, kept outside the repository.
    pub use wire::capture::sample::fixtures;

    pub fn fixture(name_part: &str) -> Value {
        let dir = fixtures().expect("capture fixtures");
        let file = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().contains(name_part))
            .unwrap();
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
    }

    /// A test's own empty directory under the temp dir, removed with all in it
    /// when dropped (declare it first, so that it outlives the store using it).
    pub struct TestDir(std::path::PathBuf);

    impl TestDir {
        pub fn new(name: &str) -> TestDir {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("apctl-{name}-{}-{seq}", std::process::id()));
            // One left by a run that was killed, with a process id used again.
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TestDir(dir)
        }
    }

    impl std::ops::Deref for TestDir {
        type Target = std::path::Path;

        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl AsRef<std::path::Path> for TestDir {
        fn as_ref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            // A store's writer thread can still be closing its files: once it
            // has, nothing more appears in the directory.
            for _ in 0..20 {
                if std::fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }

    #[test]
    fn a_test_dir_goes_when_dropped() {
        let dir = TestDir::new("testdir");
        std::fs::write(dir.join("f"), "x").unwrap();
        let path = dir.to_path_buf();
        assert!(path.is_dir());
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn a_device_s_derived_addresses_are_the_same_hardware() {
        let num = |s: &str| hardware_num(&s.parse().unwrap());
        // The locally administered copy of a MAC is the same number.
        assert_eq!(num("7a:45:58:3c:52:be"), num("78:45:58:3c:52:be"));
        assert!(same_hardware(num("78:45:58:3c:52:be"), num("7a:45:58:3c:52:ce")), "16 apart");
        assert!(!same_hardware(num("78:45:58:3c:52:be"), num("78:45:58:3c:52:cf")), "17 apart");
        assert!(same_hardware(num("78:45:58:3c:52:ff"), num("78:45:58:3c:53:01")), "across a byte");
    }

    #[test]
    fn parses_a_full_inform_from_a_u6_mesh() {
        let Some(_) = fixtures() else { return };
        let s = parse(1000, &fixture("000001_020000000001_inform")).unwrap();
        assert!(s.has_vap_table);
        assert_eq!(s.ap.mac.to_string(), "02:00:00:00:00:01");
        assert_eq!(s.ap.model.as_deref(), Some("U6M"));
        assert!(s.ap.cpu.is_some() && s.ap.mem.is_some() && s.ap.load1.is_some());
        assert!(s.ap.mem_total.unwrap() > s.ap.mem_used.unwrap());
        assert_eq!(s.radios.len(), 2);
        let na = s.radios.iter().find(|r| r.radio == "na").unwrap();
        assert!(na.channel.is_some() && na.bw.is_some() && na.noise_floor.unwrap() < -50);
        assert_eq!(s.ap.num_sta, Some(s.clients.len() as i64));
        assert!(!s.clients.is_empty());
        let c = &s.clients[0];
        assert!(c.signal.unwrap() < 0 && c.tx_rate.unwrap() > 0);
        assert_eq!(c.ap_mac, s.ap.mac);
        let up = s.uplink.as_ref().unwrap();
        assert_eq!(up.ifname, "eth0");
        assert!(up.rx_bytes.unwrap() > 0);
        assert!(s.vaps.iter().all(|v| v.tx_mcast.is_some()));
        assert!(na.antenna_gain.is_some());
    }

    #[test]
    fn an_inform_without_a_vap_table_has_no_client_information() {
        let Some(_) = fixtures() else { return };
        // A notification (`inform_as_notif`, here a client's association; the
        // engine does not parse those): the only kind of inform captured
        // without a VAP table.
        let s = parse(1000, &fixture("000593_020000000002_inform")).unwrap();
        assert!(!s.has_vap_table);
        assert!(s.clients.is_empty());
        assert_eq!(s.ap.num_sta, None, "unknown, not zero");
    }

    #[test]
    fn an_empty_vap_table_means_no_clients() {
        // Every network off (a schedule, or no SSID for this AP).
        let s = parse(1000, &serde_json::json!({ "mac": "02:00:00:00:00:01", "vap_table": [] })).unwrap();
        assert!(s.has_vap_table);
        assert_eq!(s.ap.num_sta, Some(0));
    }

    #[test]
    fn bssids_are_kept_in_lower_case() {
        let p = serde_json::json!({
            "mac": "02:00:00:00:00:01",
            "vap_table": [{ "bssid": "02:AB:00:00:00:01", "essid": "Home", "radio": "na" }],
            "radio_table": [{ "radio": "na", "scan_table": [{ "bssid": "02:CD:00:00:00:01", "essid": "Next door" }] }],
        });
        let s = parse(1000, &p).unwrap();
        assert_eq!((s.vaps[0].bssid.as_str(), s.neighbors[0].bssid.as_str()), ("02:ab:00:00:00:01", "02:cd:00:00:00:01"));
    }

    #[test]
    fn a_radio_takes_its_settings_from_one_vap() {
        // A VAP without a BSSID (e.g. a mesh link coming up) lists first.
        let p = serde_json::json!({
            "mac": "02:00:00:00:00:01",
            "vap_table": [
                { "radio": "na", "channel": 100, "bw": 20, "tx_power": 23 },
                { "bssid": "02:ab:00:00:00:01", "radio": "na", "channel": 36, "bw": 80, "tx_power": 17 },
            ],
            "radio_table": [{ "radio": "na" }],
        });
        let r = &parse(1000, &p).unwrap().radios[0];
        assert_eq!((r.channel, r.bw, r.tx_power), (Some(36), Some(80), Some(17)));
    }
}
