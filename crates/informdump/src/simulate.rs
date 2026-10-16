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

/// POSTs a body with plain HTTP/1.1 and returns (status, body).
fn post(url: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
    let rest = url.strip_prefix("http://").context("only http:// URLs are supported")?;
    let (hostport, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{p}")));
    let mut s = TcpStream::connect(hostport).with_context(|| format!("connecting to {hostport}"))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(s, "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/x-binary\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    s.write_all(body)?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp)?;
    let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").context("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&resp[..head_end]);
    let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).context("no status")?;
    Ok((status, resp[head_end + 4..].to_vec()))
}

/// Whether `url` is `http://` to this machine: `localhost`, 127.0.0.0/8 or `[::1]`.
fn is_local(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
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

pub fn run(pcap: &str, keys: &KeyStore, url: &str, limit: usize, every: f64) -> Result<()> {
    if !is_local(url) {
        bail!("refusing to simulate APs against {url}: only local controllers (http:// to 127.0.0.1, ::1 or localhost)");
    }
    // Collect the informs first, in capture order.
    let mut informs: Vec<Value> = Vec::new();
    let mut pairer = Pairer::default();
    capture::run(capture::open_input(pcap)?, &[8080], |ev| {
        if let Some(InformEvent::Inform { decoded: Ok(d), .. }) = pairer.handle(keys, ev) {
            informs.push(d.payload);
        }
    })?;
    eprintln!("replaying {} of {} informs to {url}", limit.min(informs.len()), informs.len());

    // What each simulated AP currently runs (it adopts pushed versions), and
    // the key it uses: its own, the factory key after a reset (`setdefault`),
    // then whatever key an adoption hands it (`authkey=` in mgmt_cfg).
    let mut running: HashMap<Mac, String> = HashMap::new();
    let mut keys_now: HashMap<Mac, [u8; 16]> = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (i, mut payload) in informs.into_iter().take(limit).enumerate() {
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
        let packet = inform::seal(mac, Flags(Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB), crate::random_iv(), &key, payload.to_string().as_bytes());
        let (status, body) = post(url, &packet)?;
        let line = if status != 200 {
            format!("HTTP {status}")
        } else {
            let pkt = Packet::parse(&body)?;
            let reply: Value = serde_json::from_slice(&pkt.open(&key).context("reply does not decrypt with the AP's key")?)?;
            let kind = reply["_type"].as_str().unwrap_or("?").to_string();
            let detail = match kind.as_str() {
                "setparam" => {
                    let mgmt = reply["mgmt_cfg"].as_str().unwrap_or("");
                    if let Some(k) = mgmt.lines().find_map(|l| l.strip_prefix("authkey=")).and_then(|k| hex::decode(k).ok()).and_then(|k| <[u8; 16]>::try_from(k).ok()) {
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
            format!("{kind} {detail}")
        };
        *counts.entry(line.split_whitespace().next().unwrap_or("").to_string()).or_default() += 1;
        println!("{mac} reports {:<16} -> {line}", payload["cfgversion"].as_str().unwrap_or(""));
    }
    eprintln!("replies: {counts:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_local;

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
