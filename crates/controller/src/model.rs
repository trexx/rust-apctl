//! Normalised view of an AP's inform: typed samples for storage and the API.
//!
//! Firmware sends some numbers as strings (`"cpu": "3.9"`), so every field goes
//! through lenient helpers. A missing field becomes `None` rather than an error:
//! informs sent while a radio restarts are much shorter than normal ones.

use inform::Mac;
use serde::Serialize;
use serde_json::Value;

/// Seconds since the Unix epoch.
pub type Ts = i64;

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

#[derive(Debug, Clone, Serialize)]
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
    pub num_sta: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct VapSample {
    pub bssid: String,
    pub essid: Option<String>,
    pub radio: Option<String>,
    pub name: Option<String>,
    pub channel: Option<i64>,
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
    pub satisfaction_reason: Option<i64>,
    pub anomalies: Option<i64>,
    pub nss: Option<i64>,
    pub chwidth: Option<i64>,
    pub wifi_gen: Option<&'static str>,
    pub vlan_id: Option<i64>,
    pub latency_avg: Option<i64>,
    pub is_11r: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub ap: ApSample,
    pub uplink: Option<UplinkSample>,
    pub radios: Vec<RadioSample>,
    pub vaps: Vec<VapSample>,
    pub clients: Vec<ClientSample>,
    /// False for the short informs sent while radios restart: the absence of
    /// clients then says nothing about whether they are still connected.
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
    let has_vap_table = vap_table.is_some_and(|v| !v.is_empty());

    let mut vaps = Vec::new();
    let mut clients = Vec::new();
    for v in vap_table.into_iter().flatten() {
        let Some(bssid) = string(&v["bssid"]) else { continue };
        // Only user-facing VAPs carry clients we care about; mesh/uplink VAPs are skipped.
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
        });
        if usage != "user" {
            continue;
        }
        for s in v["sta_table"].as_array().into_iter().flatten() {
            let Some(cmac) = s["mac"].as_str().and_then(|m| m.parse::<Mac>().ok()) else { continue };
            clients.push(ClientSample {
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
                satisfaction_reason: int(&s["satisfaction_reason"]),
                anomalies: int(&s["anomalies"]),
                nss: int(&s["nss"]),
                chwidth: int(&s["chwidth"]),
                wifi_gen: wifi_gen(s),
                vlan_id: int(&s["vlan_id"]),
                latency_avg: int(&s["wifi_tx_latency_mov"]["avg"]),
                is_11r: s["is_11r"].as_bool(),
            });
        }
    }

    let radios = p["radio_table"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let radio = string(&r["radio"])?;
            let ath = &r["athstats"];
            let first_vap = vaps.iter().find(|v| v.radio.as_deref() == Some(radio.as_str()));
            let vap_json = vap_table
                .into_iter()
                .flatten()
                .find(|v| v["radio"].as_str() == Some(radio.as_str()));
            Some(RadioSample {
                name: string(&r["name"]),
                channel: first_vap.and_then(|v| v.channel),
                bw: vap_json.and_then(|v| int(&v["bw"])),
                tx_power: vap_json.and_then(|v| int(&v["tx_power"])),
                cu_total: int(&ath["cu_total"]),
                cu_self_rx: int(&ath["cu_self_rx"]),
                cu_self_tx: int(&ath["cu_self_tx"]),
                cu_interf: int(&ath["cu_interf"]),
                noise_floor: int(&ath["noise_floor"]),
                tx_packets: int(&ath["n_tx_pkts"]),
                tx_retries: int(&ath["n_tx_retries"]),
                num_sta: clients.iter().filter(|c| c.radio.as_deref() == Some(radio.as_str())).count() as i64,
                radio,
            })
        })
        .collect();

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

    Ok(Snapshot { ap, uplink, radios, vaps, clients, has_vap_table })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name_part: &str) -> Value {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/captures/2026-10-12-u6m-8.8.11");
        let file = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().contains(name_part))
            .unwrap();
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
    }

    #[test]
    fn parses_a_full_inform_from_a_u6_mesh() {
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
    }

    #[test]
    fn short_inform_during_radio_restart_has_no_client_information() {
        let s = parse(1000, &fixture("000593_020000000002_inform")).unwrap();
        assert!(!s.has_vap_table);
        assert!(s.clients.is_empty());
        assert_eq!(s.ap.num_sta, None, "unknown, not zero");
    }
}
