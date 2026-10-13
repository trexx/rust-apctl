//! Plays APs against a controller: replays real informs from a capture,
//! re-encrypted with each AP's key, and behaves like the AP (a pushed
//! `cfgversion` is reported from the next inform on). For rehearsing a
//! cutover against a local apctl; never point it at a production controller.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
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

pub fn run(pcap: &str, keys: &KeyStore, url: &str, limit: usize) -> Result<()> {
    if !(url.contains("127.0.0.1") || url.contains("localhost")) {
        bail!("refusing to simulate APs against {url}: only local controllers (127.0.0.1/localhost)");
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

    // What each simulated AP currently runs (it adopts pushed versions).
    let mut running: HashMap<Mac, String> = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for mut payload in informs.into_iter().take(limit) {
        let mac: Mac = payload["mac"].as_str().context("inform without mac")?.parse()?;
        let key = *keys.get(&mac).with_context(|| format!("no key for {mac}"))?;
        if let Some(v) = running.get(&mac) {
            payload["cfgversion"] = Value::from(v.clone());
        }
        let mut iv = [0u8; 16];
        iv.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(31) ^ (counts.values().sum::<usize>() as u8));
        let packet = inform::seal(mac, Flags(Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB), iv, &key, payload.to_string().as_bytes());
        let (status, body) = post(url, &packet)?;
        let line = if status != 200 {
            format!("HTTP {status}")
        } else {
            let pkt = Packet::parse(&body)?;
            let reply: Value = serde_json::from_slice(&pkt.open(&key).context("reply does not decrypt with the AP's key")?)?;
            let kind = reply["_type"].as_str().unwrap_or("?").to_string();
            let detail = match kind.as_str() {
                "setparam" => {
                    let v = reply["cfgversion"].as_str().unwrap_or("").to_string();
                    let lines = reply["system_cfg"].as_str().map_or(0, |s| s.lines().count());
                    running.insert(mac, v.clone());
                    format!("cfgversion {v}, system_cfg {lines} lines, flags {:?}", pkt.header.flags)
                }
                "noop" => format!("interval {}", reply["interval"]),
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
