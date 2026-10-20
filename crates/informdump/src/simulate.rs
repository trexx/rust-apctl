//! Plays APs against a controller: replays real informs from a capture,
//! re-encrypted with each AP's key and sealed as the AP sealed them (AES-CBC or
//! AES-GCM, and the compression), and behaves like the AP (a pushed `cfgversion`
//! is reported from the next inform on, a pushed `use_aes_gcm=true` turns on
//! GCM). For rehearsing a cutover against a local apctl; never point it at a
//! production controller.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::ops::ControlFlow;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use inform::{Flags, Mac, Packet};
use serde_json::Value;
use wire::capture;
use wire::decode::{Decoded, KeyUsed};
use wire::exchange::{InformEvent, Pairer};
use wire::keys::KeyStore;

/// An `http://` URL's authority (`host:port`) and request target (path and query).
fn split_url(url: &str) -> Option<(&str, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, target) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let target = target.split('#').next().unwrap_or("");
    Some((authority, if target.starts_with('/') { target.to_string() } else { format!("/{target}") }))
}

/// The address to connect to for a URL's authority: port 80 when it names none.
fn with_port(authority: &str) -> String {
    let has_port = match authority.rsplit_once(']') {
        Some((_, after)) => after.starts_with(':'),
        None => authority.contains(':'),
    };
    if has_port { authority.to_string() } else { format!("{authority}:80") }
}

/// POSTs a body with plain HTTP/1.1 and returns (status, body).
fn post(url: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
    let (authority, path) = split_url(url).context("only http:// URLs are supported")?;
    let addr = with_port(authority);
    let mut s = TcpStream::connect(&addr).with_context(|| format!("connecting to {addr}"))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(s, "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/x-binary\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    s.write_all(body)?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp)?;
    capture::parse_response(&resp).context("malformed or truncated HTTP response")
}

/// Whether `url` is `http://` to this machine: `localhost`, 127.0.0.0/8 or `[::1]`.
fn is_local(url: &str) -> bool {
    let Some((authority, _)) = split_url(url) else { return false };
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((h, port)) if port.is_empty() || port.starts_with(':') => h,
            _ => return false,
        },
        None => authority.split_once(':').map_or(authority, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The key a captured inform was sealed with: the factory key, or the AP's own.
fn captured_key(d: &Decoded, keys: &KeyStore) -> [u8; 16] {
    match d.key {
        KeyUsed::Default => inform::DEFAULT_KEY,
        KeyUsed::Device | KeyUsed::None => keys.get(&d.header.mac).copied().unwrap_or(inform::DEFAULT_KEY),
    }
}

/// Readies a captured inform to be sent by an AP that runs `running` (if it took a
/// pushed config) and seals with `key`: it says it is in factory state when that key
/// is the factory one, whatever it said in the capture.
fn prepare(payload: &mut Value, running: Option<&str>, key: &[u8; 16]) {
    if let Some(v) = running {
        payload["cfgversion"] = Value::from(v);
    }
    payload["default"] = Value::from(*key == inform::DEFAULT_KEY);
}

/// A captured inform's payload, the key it was sealed with, and its header's cipher
/// and compression bits.
type Captured = (Value, [u8; 16], Flags);

/// The cipher and compression bits of a captured inform's header.
fn sealing(flags: Flags) -> Flags {
    Flags(flags.0 & (Flags::GCM | Flags::ZLIB | Flags::SNAPPY).0)
}

/// Whether a pushed mgmt_cfg turns on AES-GCM.
fn turns_on_gcm(mgmt: &str) -> bool {
    mgmt.lines().any(|l| l.trim_end() == "use_aes_gcm=true")
}

/// The first `limit` informs of a capture that decode, in capture order. The capture is
/// read no further than the last of them.
fn collect(input: impl Read + Send, ports: &[u16], keys: &KeyStore, limit: usize) -> Result<(Vec<Captured>, capture::End)> {
    let mut informs = Vec::new();
    let mut pairer = Pairer::default();
    let end = capture::run(input, ports, |ev| {
        if let Some(InformEvent::Inform { decoded: Ok(d), .. }) = pairer.handle(keys, ev)
            && informs.len() < limit
        {
            let key = captured_key(&d, keys);
            informs.push((d.payload, key, sealing(d.header.flags)));
        }
        if informs.len() >= limit { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    })?;
    Ok((informs, end))
}

pub fn run(pcap: &str, ports: &[u16], keys: &KeyStore, url: &str, limit: usize, every: Duration) -> Result<()> {
    if !is_local(url) {
        bail!("refusing to simulate APs against {url}: only local controllers (http:// to 127.0.0.1, ::1 or localhost)");
    }
    // The informs are collected first; from a live pipe, the replay starts once there are enough.
    let (informs, end) = collect(capture::open_input(pcap)?, ports, keys, limit)?;
    crate::warn_if_truncated(end);
    eprintln!("replaying {} informs to {url}", informs.len());

    // What each simulated AP currently runs (it adopts pushed versions), and
    // the key it uses: the one its inform was captured with (its own, or the
    // factory key), the factory key after a reset (`setdefault`), then
    // whatever key an adoption hands it (`authkey=` in mgmt_cfg). It seals
    // as captured, with AES-GCM once a pushed mgmt_cfg turns that on.
    let mut running: HashMap<Mac, String> = HashMap::new();
    let mut keys_now: HashMap<Mac, [u8; 16]> = HashMap::new();
    let mut gcm_on: HashSet<Mac> = HashSet::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (i, (mut payload, captured, how)) in informs.into_iter().enumerate() {
        if i > 0 && !every.is_zero() {
            std::thread::sleep(every);
        }
        let mac: Mac = payload["mac"].as_str().context("inform without mac")?.parse()?;
        let key = keys_now.get(&mac).copied().unwrap_or(captured);
        prepare(&mut payload, running.get(&mac).map(String::as_str), &key);
        // These are real AP keys: a GCM nonce must never repeat under one.
        let how = if gcm_on.contains(&mac) { how | Flags::GCM } else { how };
        let packet = inform::seal(mac, Flags::ENCRYPTED | how, crate::random_iv(), &key, payload.to_string().as_bytes());
        let (status, body) = post(url, &packet)?;
        // Replies are counted by status, and those with 200 by their type.
        let (counted, detail) = if status != 200 {
            (format!("HTTP {status}"), String::new())
        } else {
            let pkt = Packet::parse(&body)?;
            let reply: Value = serde_json::from_slice(&pkt.open(&key).context("reply does not decrypt with the AP's key")?)?;
            let kind = reply["_type"].as_str().unwrap_or("?").to_string();
            let detail = match kind.as_str() {
                "setparam" => {
                    let mgmt = reply["mgmt_cfg"].as_str().unwrap_or("");
                    if let Some(k) = mgmt.lines().find_map(|l| l.strip_prefix("authkey=")).and_then(|k| inform::parse_key(k).ok()) {
                        keys_now.insert(mac, k);
                    }
                    if turns_on_gcm(mgmt) {
                        gcm_on.insert(mac);
                    }
                    let v = reply["cfgversion"].as_str().or_else(|| mgmt.lines().find_map(|l| l.strip_prefix("cfgversion="))).unwrap_or("").to_string();
                    let lines = reply["system_cfg"].as_str().map(|s| s.lines().count());
                    let adopted = if mgmt.contains("authkey=") { ", new key (adopted)" } else { "" };
                    let detail = format!("cfgversion {v}, system_cfg {} lines, flags {:?}{adopted}", lines.unwrap_or(0), pkt.header.flags);
                    if lines.is_some() {
                        running.insert(mac, v);
                    }
                    detail
                }
                "setdefault" => {
                    // Factory reset: the factory key and no config.
                    keys_now.insert(mac, inform::DEFAULT_KEY);
                    running.remove(&mac);
                    "factory reset".to_string()
                }
                "noop" => format!("interval {}", reply["interval"]),
                "cmd" => format!("{} {}", reply["cmd"].as_str().unwrap_or("?"), reply["mac"].as_str().unwrap_or("")),
                "reboot" => reply["reboot_type"].as_str().unwrap_or("").to_string(),
                _ => String::new(),
            };
            (kind, detail)
        };
        println!("{mac} reports {:<16} -> {}", payload["cfgversion"].as_str().unwrap_or(""), format!("{counted} {detail}").trim_end());
        *counts.entry(counted).or_default() += 1;
    }
    eprintln!("replies: {counts:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_ap_replays_with_the_key_it_was_captured_with_and_says_whether_that_is_the_factory_one() {
        let mac: Mac = "02:00:00:00:00:01".parse().unwrap();
        let mut keys = KeyStore::default();
        let decoded = |keys: &KeyStore, key: &[u8; 16]| wire::decode::decode(&inform::seal(mac, Flags::ENCRYPTED | Flags::GCM, [1; 16], key, br#"{"default":false}"#), keys).unwrap();
        // A factory-reset AP: no stored key needed.
        assert_eq!(captured_key(&decoded(&keys, &inform::DEFAULT_KEY), &keys), inform::DEFAULT_KEY);
        keys.insert_for(mac, "000102030405060708090a0b0c0d0e0f").unwrap();
        let own = *keys.get(&mac).unwrap();
        assert_eq!(captured_key(&decoded(&keys, &own), &keys), own);
        assert_eq!(captured_key(&decoded(&keys, &inform::DEFAULT_KEY), &keys), inform::DEFAULT_KEY, "reset, though a key is stored");
        let mut p = json!({ "default": false, "cfgversion": "old" });
        prepare(&mut p, Some("new"), &inform::DEFAULT_KEY);
        assert_eq!(p, json!({ "default": true, "cfgversion": "new" }));
        prepare(&mut p, None, &own);
        assert_eq!(p, json!({ "default": false, "cfgversion": "new" }), "adopted: no longer in factory state");
    }

    #[test]
    fn collecting_stops_reading_the_capture_at_the_limit() {
        use wire::synth::{Endpoint, http, tcp_frame, write_pcap_header, write_pcap_record};
        let (ap, ctrl) = (Endpoint { mac: [2; 6], ip: [10, 0, 0, 5], port: 40000 }, Endpoint { mac: [4; 6], ip: [10, 0, 0, 1], port: 8080 });
        let mac: Mac = "02:00:00:00:00:01".parse().unwrap();
        let mut pcap = Vec::new();
        write_pcap_header(&mut pcap, 65535).unwrap();
        let mut seq = 1;
        for i in 0..3 {
            let packet = inform::seal(mac, Flags::ENCRYPTED | Flags::GCM, [i; 16], &inform::DEFAULT_KEY, format!(r#"{{"n":{i}}}"#).as_bytes());
            let request = http("POST /inform HTTP/1.1\r\n", &packet);
            write_pcap_record(&mut pcap, i64::from(i) * 1_000_000, &tcp_frame(ap, ctrl, seq, &request).unwrap()).unwrap();
            seq += request.len() as u32;
        }
        let keys = KeyStore::default();
        let (informs, end) = collect(&pcap[..], &[8080], &keys, 2).unwrap();
        assert_eq!((informs.iter().map(|(p, ..)| p["n"].as_i64().unwrap()).collect::<Vec<_>>(), end), (vec![0, 1], capture::End::Stopped));
        let (informs, end) = collect(&pcap[..], &[8080], &keys, 10).unwrap();
        assert_eq!((informs.len(), end), (3, capture::End::Complete));
        assert_eq!(informs[0].1, inform::DEFAULT_KEY);
        assert_eq!(informs[0].2, Flags::GCM, "sealed as captured");
    }

    #[test]
    fn an_inform_is_sealed_with_its_captured_cipher_and_compression() {
        assert_eq!(sealing(Flags::ENCRYPTED | Flags::ZLIB), Flags::ZLIB, "AES-CBC");
        assert_eq!(sealing(Flags::ENCRYPTED | Flags::GCM | Flags::SNAPPY), Flags::GCM | Flags::SNAPPY);
        assert!(turns_on_gcm("authkey=00\nuse_aes_gcm=true\n") && !turns_on_gcm("use_aes_gcm=false\n") && !turns_on_gcm(""));
    }

    #[test]
    fn urls_split_where_the_local_check_splits_them() {
        let split = |url| split_url(url).map(|(a, t)| (a.to_string(), t));
        assert_eq!(split("http://127.0.0.1:18180/inform"), Some(("127.0.0.1:18180".into(), "/inform".into())));
        assert_eq!(split("http://localhost?x=1#f"), Some(("localhost".into(), "/?x=1".into())));
        assert_eq!(split("http://localhost#/elsewhere"), Some(("localhost".into(), "/".into())));
        assert_eq!(split("http://[::1]:8080"), Some(("[::1]:8080".into(), "/".into())));
        assert_eq!(split("https://localhost/"), None);
    }

    #[test]
    fn port_80_is_the_default() {
        assert_eq!(with_port("localhost"), "localhost:80");
        assert_eq!(with_port("127.0.0.1:18180"), "127.0.0.1:18180");
        assert_eq!(with_port("[::1]"), "[::1]:80");
        assert_eq!(with_port("[::1]:8080"), "[::1]:8080");
    }

    #[test]
    fn only_local_urls_pass() {
        for ok in ["http://127.0.0.1:18180/inform", "http://localhost/inform", "http://LOCALHOST:8080", "http://127.1.2.3/x", "http://[::1]:8080/inform"] {
            assert!(is_local(ok), "{ok}");
        }
        for bad in [
            "http://prod/?127.0.0.1",
            "http://prod/127.0.0.1",
            "http://127.0.0.1.example.net/inform",
            "http://localhost.example.net/",
            "http://127.0.0.1@prod:8080/inform",
            "http://prod#127.0.0.1",
            "https://127.0.0.1/inform",
            "http://[::1].prod/",
            "http://10.0.0.1:8080/inform",
        ] {
            assert!(!is_local(bad), "{bad}");
        }
    }
}
