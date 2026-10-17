//! Pairs captured HTTP requests and responses into inform exchanges.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use anyhow::Result;
use inform::Mac;

use crate::capture::{ConnId, HttpEvent, Micros};
use crate::decode::{Decoded, decode};
use crate::keys::KeyStore;

#[derive(Debug)]
pub enum InformEvent {
    /// An AP's inform. `peer` is its address (from X-Forwarded-For behind a proxy, if
    /// that holds an address).
    Inform { ts: Micros, peer: String, mac: Option<Mac>, decoded: Result<Decoded> },
    /// The controller's reply. `mac` is its request's, or when that was not captured,
    /// the one the reply is sealed under. `decoded` is `None` for an empty body.
    Reply { ts: Micros, mac: Option<Mac>, status: u16, decoded: Option<Result<Decoded>> },
}

/// What a response will be answering.
enum Pending {
    Inform(Option<Mac>),
    /// Some other HTTP request on the same port (health checks, a web UI, ...).
    Other,
}

/// Connections with requests in flight beyond which stale ones are forgotten.
const MAX_IN_FLIGHT: usize = 256;
/// How long a request may wait for its response before it is forgotten (a
/// response the capture missed, a connection that died).
const MAX_WAIT: Micros = 300_000_000;
/// Stale requests are looked for at most this often (capture time), not on every new connection.
const SWEEP_EVERY: Micros = 10_000_000;
/// Requests kept waiting per connection; older ones are taken to have lost their responses.
const MAX_QUEUED: usize = 32;

#[derive(Default)]
pub struct Pairer {
    /// Requests waiting for their response, per connection (HTTP/1.1 is in order),
    /// with the time of the latest one. A connection leaves the map when its queue
    /// empties, so a long-running shadow mode does not keep one entry per connection.
    in_flight: HashMap<ConnId, (Micros, VecDeque<Pending>)>,
    last_sweep: Micros,
}

impl Pairer {
    fn push(&mut self, conn: ConnId, ts: Micros, p: Pending) {
        if self.in_flight.len() >= MAX_IN_FLIGHT && ts.abs_diff(self.last_sweep) >= SWEEP_EVERY as u64 && !self.in_flight.contains_key(&conn) {
            self.last_sweep = ts;
            self.in_flight.retain(|_, (last, _)| ts - *last < MAX_WAIT);
        }
        let (last, queue) = self.in_flight.entry(conn).or_default();
        *last = ts;
        if queue.len() >= MAX_QUEUED {
            queue.pop_front();
        }
        queue.push_back(p);
    }

    /// The request a response answers: the next one in order, or for a reply sealed
    /// under an AP's MAC, that AP's oldest waiting inform. Requests queued ahead of
    /// it lost their responses (a gap in the capture), and are dropped; without
    /// this, one lost response would pair every later reply on the connection with
    /// the wrong request, and behind a proxy, which carries many APs' informs on one
    /// connection, with the wrong AP.
    fn pop(&mut self, conn: ConnId, sealed_for: Option<Mac>) -> Option<Pending> {
        let (_, queue) = self.in_flight.get_mut(&conn)?;
        let p = match sealed_for {
            Some(mac) => {
                let at = queue.iter().position(|p| matches!(p, Pending::Inform(Some(m)) if *m == mac))?;
                queue.drain(..at);
                queue.pop_front()
            }
            None => queue.pop_front(),
        };
        if queue.is_empty() {
            self.in_flight.remove(&conn);
        }
        p
    }

    pub fn handle(&mut self, keys: &KeyStore, ev: HttpEvent) -> Option<InformEvent> {
        match ev {
            HttpEvent::Request { conn, ts, inform, forwarded_for, body } => {
                if !inform {
                    self.push(conn, ts, Pending::Other);
                    return None;
                }
                let peer = forwarded_for.as_deref().and_then(forwarded_ip).unwrap_or(conn.client.ip()).to_string();
                let decoded = decode(&body, keys, None);
                let mac = match &decoded {
                    Ok(d) => Some(d.header.mac),
                    Err(_) => inform::Header::parse(&body).ok().map(|h| h.mac),
                };
                self.push(conn, ts, Pending::Inform(mac));
                Some(InformEvent::Inform { ts, peer, mac, decoded })
            }
            HttpEvent::Response { conn, ts, status, body } => {
                // A reply is sealed under the MAC of the inform it answers (its header
                // is sent back), which is in the clear.
                let sealed_for = inform::Header::parse(&body).ok().map(|h| h.mac);
                let mac = match self.pop(conn, sealed_for) {
                    Some(Pending::Inform(mac)) => mac.or(sealed_for),
                    // The request was not captured: only look at bodies that are inform packets.
                    None if body.starts_with(inform::MAGIC) => sealed_for,
                    Some(Pending::Other) | None => return None,
                };
                let decoded = (!body.is_empty()).then(|| decode(&body, keys, mac));
                Some(InformEvent::Reply { ts, mac, status, decoded })
            }
            HttpEvent::Datagram { .. } => None,
        }
    }
}

/// The client's address from an X-Forwarded-For header: its first entry, if that is
/// an address (some proxies add the port).
fn forwarded_ip(header: &str) -> Option<IpAddr> {
    let first = header.split(',').next()?.trim();
    first.parse().ok().or_else(|| first.parse::<SocketAddr>().ok().map(|a| a.ip()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn conn(port: u16) -> ConnId {
        ConnId { client: SocketAddr::from(([10, 0, 0, 5], port)), server: SocketAddr::from(([10, 0, 0, 1], 8080)) }
    }

    fn get(c: ConnId, ts: Micros) -> HttpEvent {
        HttpEvent::Request { conn: c, ts, inform: false, forwarded_for: None, body: Vec::new() }
    }

    fn ok(c: ConnId, ts: Micros) -> HttpEvent {
        HttpEvent::Response { conn: c, ts, status: 200, body: b"{}".to_vec() }
    }

    #[test]
    fn answered_and_stale_requests_are_forgotten() {
        let keys = KeyStore::default();
        let mut p = Pairer::default();
        for port in 0..1000 {
            p.handle(&keys, get(conn(port), 0));
            assert!(p.handle(&keys, ok(conn(port), 0)).is_none());
        }
        assert!(p.in_flight.is_empty(), "every request was answered");
        // Requests that never see a response are dropped once they are old.
        for port in 0..1000 {
            p.handle(&keys, get(conn(port), Micros::from(port) * 10_000_000));
        }
        assert!(p.in_flight.len() <= MAX_IN_FLIGHT + 1, "{}", p.in_flight.len());
        // Many live connections at once: the map is not rescanned for every new one.
        let mut p = Pairer::default();
        for port in 0..1000 {
            p.handle(&keys, get(conn(port), 20_000_000 + Micros::from(port)));
        }
        assert_eq!(p.in_flight.len(), 1000);
        assert_eq!(p.last_sweep, 20_000_000 + Micros::from(MAX_IN_FLIGHT as u16), "one sweep, when the map filled up");
    }

    fn sealed(mac: &str, json: &str) -> Vec<u8> {
        inform::seal(mac.parse().unwrap(), inform::Flags(inform::Flags::ENCRYPTED | inform::Flags::GCM), [1; 16], &inform::DEFAULT_KEY, json.as_bytes())
    }

    fn inform(c: ConnId, from: &str, forwarded_for: Option<&str>) -> HttpEvent {
        HttpEvent::Request { conn: c, ts: 0, inform: true, forwarded_for: forwarded_for.map(str::to_string), body: sealed(from, "{}") }
    }

    fn reply(c: ConnId, to: &str) -> HttpEvent {
        HttpEvent::Response { conn: c, ts: 0, status: 200, body: sealed(to, r#"{"_type":"noop"}"#) }
    }

    fn reply_mac(ev: Option<InformEvent>) -> Option<String> {
        match ev {
            Some(InformEvent::Reply { mac, decoded: Some(Ok(_)), .. }) => mac.map(|m| m.to_string()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn replies_pair_by_the_mac_they_are_sealed_under() {
        let (a, b) = ("02:00:00:00:00:01", "02:00:00:00:00:02");
        let keys = KeyStore::default();
        let mut p = Pairer::default();
        // A proxy's connection carries both APs' informs; the response to A's first is lost.
        for from in [a, b, a] {
            p.handle(&keys, inform(conn(1), from, None));
        }
        assert_eq!(reply_mac(p.handle(&keys, reply(conn(1), b))).as_deref(), Some(b));
        assert_eq!(reply_mac(p.handle(&keys, reply(conn(1), a))).as_deref(), Some(a));
        assert!(p.in_flight.is_empty(), "the request whose response was lost is dropped");
        // A reply whose request was not captured names its AP.
        assert_eq!(reply_mac(p.handle(&keys, reply(conn(2), b))).as_deref(), Some(b));
        // Other responses still go in order.
        p.handle(&keys, get(conn(3), 0));
        assert!(p.handle(&keys, ok(conn(3), 0)).is_none());
        // Requests that never see a response do not pile up on a connection.
        for _ in 0..100 {
            p.handle(&keys, inform(conn(4), a, None));
        }
        assert_eq!(p.in_flight[&conn(4)].1.len(), MAX_QUEUED);
    }

    #[test]
    fn the_peer_is_an_address() {
        let keys = KeyStore::default();
        let mut p = Pairer::default();
        let mut peer = |xff: Option<&str>| match p.handle(&keys, inform(conn(1), "02:00:00:00:00:01", xff)) {
            Some(InformEvent::Inform { peer, .. }) => peer,
            other => panic!("{other:?}"),
        };
        assert_eq!(peer(Some(" 203.0.113.9 , 10.0.0.1")), "203.0.113.9");
        assert_eq!(peer(Some("198.51.100.7:4711")), "198.51.100.7");
        assert_eq!(peer(Some("[2001:db8::1]:80")), "2001:db8::1");
        assert_eq!(peer(Some("2001:db8::2")), "2001:db8::2");
        assert_eq!(peer(Some("not-an-address, 10.0.0.1")), "10.0.0.5", "not an address: the connection's");
        assert_eq!(peer(Some("")), "10.0.0.5");
        assert_eq!(peer(None), "10.0.0.5");
    }
}
