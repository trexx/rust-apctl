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

#[derive(Default)]
pub struct Pairer {
    /// Requests waiting for their response, per connection (HTTP/1.1 is in order).
    in_flight: HashMap<ConnId, VecDeque<Pending>>,
}

impl Pairer {
    pub fn handle(&mut self, keys: &KeyStore, ev: HttpEvent) -> Option<InformEvent> {
        match ev {
            HttpEvent::Request { conn, ts, method, path, headers, body } => {
                if method != "POST" || !path.starts_with("/inform") {
                    self.in_flight.entry(conn).or_default().push_back(Pending::Other);
                    return None;
                }
                let peer = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
                    .map(|(_, v)| v.split(',').next().unwrap_or("").trim().to_string())
                    .unwrap_or_else(|| conn.client.ip().to_string());
                let decoded = decode(&body, keys, None);
                let mac = match &decoded {
                    Ok(d) => Some(d.header.mac),
                    Err(_) => inform::Header::parse(&body).ok().map(|h| h.mac),
                };
                self.in_flight.entry(conn).or_default().push_back(Pending::Inform(mac));
                Some(InformEvent::Inform { ts, peer, mac, decoded })
            }
            HttpEvent::Response { conn, ts, status, body, .. } => {
                let mac = match self.in_flight.get_mut(&conn).and_then(|q| q.pop_front()) {
                    Some(Pending::Inform(mac)) => mac,
                    Some(Pending::Other) => return None,
                    // The request was not captured: only look at bodies that are inform packets.
                    None if body.starts_with(inform::MAGIC) => None,
                    None => return None,
                };
                let decoded = (!body.is_empty()).then(|| decode(&body, keys, mac));
                Some(InformEvent::Reply { ts, mac, status, decoded })
            }
            HttpEvent::Datagram { .. } => None,
        }
    }
}
