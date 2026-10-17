//! Plays APs against a controller: replays real informs from a capture,
//! re-encrypted with each AP's key, and behaves like the AP (a pushed
//! `cfgversion` is reported from the next inform on). For rehearsing a
//! cutover against a local apctl; never point it at a production controller.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use inform::{Flags, Mac, Packet};
use serde_json::Value;
use wire::capture;
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

pub fn run(pcap: &str, ports: &[u16], keys: &KeyStore, url: &str, limit: usize, every: f64) -> Result<()> {
    if !is_local(url) {
        bail!("refusing to simulate APs against {url}: only local controllers (http:// to 127.0.0.1, ::1 or localhost)");
    }
    // Collect the informs first, in capture order. Once there are enough, the rest of
    // the capture is read but not decoded.
    let mut informs: Vec<Value> = Vec::new();
    let mut pairer = Pairer::default();
    capture::run(capture::open_input(pcap)?, ports, |ev| {
        if informs.len() >= limit {
            return;
        }
        if let Some(InformEvent::Inform { decoded: Ok(d), .. }) = pairer.handle(keys, ev) {
            informs.push(d.payload);
        }
    })?;
    eprintln!("replaying {} informs to {url}", informs.len());

    // What each simulated AP currently runs (it adopts pushed versions), and
    // the key it uses: its own, the factory key after a reset (`setdefault`),
    // then whatever key an adoption hands it (`authkey=` in mgmt_cfg).
    let mut running: HashMap<Mac, String> = HashMap::new();
    let mut keys_now: HashMap<Mac, [u8; 16]> = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (i, mut payload) in informs.into_iter().enumerate() {
        if i > 0 && every > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(every));
        }
        let mac: Mac = payload["mac"].as_str().context("inform without mac")?.parse()?;
        let key = match keys_now.get(&mac) {
            Some(k) => *k,
            None => *keys.get(&mac).with_context(|| format!("no key for {mac}"))?,
        };
        if let Some(v) = running.get(&mac) {
            payload["cfgversion"] = Value::from(v.clone());
        }
        if key == inform::DEFAULT_KEY {
            payload["default"] = Value::from(true);
        }
        // These are real AP keys: a GCM nonce must never repeat under one.
        let packet = inform::seal(mac, Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB, crate::random_iv(), &key, payload.to_string().as_bytes());
        let (status, body) = post(url, &packet)?;
        // Replies are counted by status, and those with 200 by their type.
        let (counted, line) = if status != 200 {
            (format!("HTTP {status}"), format!("HTTP {status}"))
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
                    let v = reply["cfgversion"].as_str().or_else(|| mgmt.lines().find_map(|l| l.strip_prefix("cfgversion="))).unwrap_or("").to_string();
                    let lines = reply["system_cfg"].as_str().map_or(0, |s| s.lines().count());
                    if reply["system_cfg"].is_string() {
                        running.insert(mac, v.clone());
                    }
                    let adopted = if mgmt.contains("authkey=") { ", new key (adopted)" } else { "" };
                    format!("cfgversion {v}, system_cfg {lines} lines, flags {:?}{adopted}", pkt.header.flags)
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
            let line = format!("{kind} {detail}");
            (kind, line)
        };
        *counts.entry(counted).or_default() += 1;
        println!("{mac} reports {:<16} -> {line}", payload["cfgversion"].as_str().unwrap_or(""));
    }
    eprintln!("replies: {counts:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_local, split_url, with_port};

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
