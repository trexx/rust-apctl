//! Pairs captured HTTP requests and responses into inform exchanges.

use std::collections::{HashMap, VecDeque};

use anyhow::Result;
use inform::Mac;

use crate::capture::{ConnId, HttpEvent, Micros};
use crate::decode::{Decoded, decode};
use crate::keys::KeyStore;

#[derive(Debug)]
pub enum InformEvent {
    /// An AP's inform. `peer` is its address (from X-Forwarded-For behind a proxy).
    Inform { ts: Micros, peer: String, mac: Option<Mac>, decoded: Result<Decoded> },
    /// The controller's reply. `decoded` is `None` for an empty body.
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
        queue.push_back(p);
    }

    fn pop(&mut self, conn: ConnId) -> Option<Pending> {
        let (_, queue) = self.in_flight.get_mut(&conn)?;
        let p = queue.pop_front();
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
                let peer = forwarded_for
                    .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
                    .unwrap_or_else(|| conn.client.ip().to_string());
                let decoded = decode(&body, keys, None);
                let mac = match &decoded {
                    Ok(d) => Some(d.header.mac),
                    Err(_) => inform::Header::parse(&body).ok().map(|h| h.mac),
                };
                self.push(conn, ts, Pending::Inform(mac));
                Some(InformEvent::Inform { ts, peer, mac, decoded })
            }
            HttpEvent::Response { conn, ts, status, body } => {
                let mac = match self.pop(conn) {
                    Some(Pending::Inform(mac)) => mac,
                    // The request was not captured: only look at bodies that are inform packets.
                    None if body.starts_with(inform::MAGIC) => None,
                    Some(Pending::Other) | None => return None,
                };
                let decoded = (!body.is_empty()).then(|| decode(&body, keys, mac));
                Some(InformEvent::Reply { ts, mac, status, decoded })
            }
            HttpEvent::Datagram { .. } => None,
        }
    }
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
}
