//! Turns a pcap/pcapng stream into HTTP messages exchanged on the inform port.
//!
//! This is deliberately small: TCP segments are reassembled per direction
//! (tolerating duplicates, which `tcpdump -i any` produces, and reordering),
//! then HTTP/1.1 requests and responses are cut out of each byte stream.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, bail};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{Block, Linktype, PcapBlockOwned, PcapError, create_reader};

/// Time since the Unix epoch, in microseconds.
pub type Micros = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId {
    pub client: SocketAddr,
    pub server: SocketAddr,
}

#[derive(Debug)]
pub enum HttpEvent {
    Request { conn: ConnId, ts: Micros, method: String, path: String, headers: Vec<(String, String)>, body: Vec<u8> },
    #[allow(dead_code)] // headers are kept for future use (e.g. content-type checks)
    Response { conn: ConnId, ts: Micros, status: u16, headers: Vec<(String, String)>, body: Vec<u8> },
    /// A UDP datagram to one of the watched UDP ports (e.g. AP syslog on 5514).
    Datagram { ts: Micros, src: SocketAddr, dst: SocketAddr, payload: Vec<u8> },
}

/// Reads packets from `input` and calls `on_event` for every complete HTTP message
/// whose TCP connection has one of `ports` as its server port.
pub fn run<R: Read + Send>(input: R, ports: &[u16], on_event: impl FnMut(HttpEvent)) -> Result<()> {
    run_with_udp(input, ports, &[], on_event)
}

/// Like [`run`], and also reports UDP datagrams sent to one of `udp_ports`.
pub fn run_with_udp<R: Read + Send>(
    input: R,
    ports: &[u16],
    udp_ports: &[u16],
    mut on_event: impl FnMut(HttpEvent),
) -> Result<()> {
    let mut reader = create_reader(1 << 20, input).map_err(|e| anyhow::anyhow!("reading capture header: {e:?}"))?;
    let mut tracker = Tracker::new(ports.to_vec(), udp_ports.to_vec());
    // pcapng: per-interface link type and timestamp resolution.
    let mut interfaces: Vec<(Linktype, u64, i64)> = Vec::new();
    let mut legacy_linktype = Linktype::ETHERNET;
    let mut legacy_nanos = false;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(h) => {
                        legacy_linktype = h.network;
                        legacy_nanos = h.is_nanosecond_precision();
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let frac = if legacy_nanos { b.ts_usec as i64 / 1000 } else { b.ts_usec as i64 };
                        let ts = b.ts_sec as i64 * 1_000_000 + frac;
                        tracker.packet(legacy_linktype, ts, b.data, &mut on_event);
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => interfaces.clear(),
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        interfaces.push((idb.linktype, idb.ts_resolution().unwrap_or(1_000_000), idb.ts_offset()));
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        let Some(&(linktype, res, off)) = interfaces.get(epb.if_id as usize) else { continue };
                        let (sec, frac) = epb.decode_ts(off.max(0) as u64, res);
                        let ts = sec as i64 * 1_000_000 + (frac as i128 * 1_000_000 / res as i128) as i64;
                        tracker.packet(linktype, ts, epb.data, &mut on_event);
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                        if let Some(&(linktype, ..)) = interfaces.first() {
                            tracker.packet(linktype, 0, spb.data, &mut on_event);
                        }
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => return Ok(()),
            Err(PcapError::Incomplete(_)) => {
                // Blocks until more data arrives when reading a live `tcpdump -w -` pipe.
                if let Err(e) = reader.refill() {
                    bail!("reading capture: {e:?}");
                }
            }
            Err(e) => bail!("parsing capture: {e:?}"),
        }
    }
}

fn slice(linktype: Linktype, data: &[u8]) -> Option<SlicedPacket<'_>> {
    let ip = |d| SlicedPacket::from_ip(d).ok();
    match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok(),
        Linktype::LINUX_SLL => SlicedPacket::from_linux_sll(data).ok(),
        // SLL2 (tcpdump -i any on recent libpcap) has a fixed 20-byte header.
        Linktype::LINUX_SLL2 => data.get(20..).and_then(ip),
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => ip(data),
        Linktype::NULL | Linktype::LOOP => data.get(4..).and_then(ip),
        _ => None,
    }
}

struct Tracker {
    ports: Vec<u16>,
    udp_ports: Vec<u16>,
    conns: HashMap<ConnId, Conn>,
}

#[derive(Default)]
struct Conn {
    to_server: HalfStream,
    to_client: HalfStream,
    last_seen: Micros,
}

impl Tracker {
    fn new(ports: Vec<u16>, udp_ports: Vec<u16>) -> Self {
        Tracker { ports, udp_ports, conns: HashMap::new() }
    }

    fn packet(&mut self, linktype: Linktype, ts: Micros, data: &[u8], on_event: &mut impl FnMut(HttpEvent)) {
        let Some(pkt) = slice(linktype, data) else { return };
        let (src_ip, dst_ip): (IpAddr, IpAddr) = match &pkt.net {
            Some(NetSlice::Ipv4(v4)) => (v4.header().source_addr().into(), v4.header().destination_addr().into()),
            Some(NetSlice::Ipv6(v6)) => (v6.header().source_addr().into(), v6.header().destination_addr().into()),
            _ => return,
        };
        let tcp = match &pkt.transport {
            Some(TransportSlice::Tcp(tcp)) => tcp,
            Some(TransportSlice::Udp(udp)) => {
                if self.udp_ports.contains(&udp.destination_port()) {
                    on_event(HttpEvent::Datagram {
                        ts,
                        src: SocketAddr::new(src_ip, udp.source_port()),
                        dst: SocketAddr::new(dst_ip, udp.destination_port()),
                        payload: udp.payload().to_vec(),
                    });
                }
                return;
            }
            _ => return,
        };
        let src = SocketAddr::new(src_ip, tcp.source_port());
        let dst = SocketAddr::new(dst_ip, tcp.destination_port());
        let (conn_id, to_server) = if self.ports.contains(&dst.port()) {
            (ConnId { client: src, server: dst }, true)
        } else if self.ports.contains(&src.port()) {
            (ConnId { client: dst, server: src }, false)
        } else {
            return;
        };

        let conn = self.conns.entry(conn_id).or_default();
        conn.last_seen = ts;
        let half = if to_server { &mut conn.to_server } else { &mut conn.to_client };
        if tcp.rst() {
            self.conns.remove(&conn_id);
            return;
        }
        half.segment(tcp.sequence_number(), tcp.syn(), tcp.payload());

        while let Some(msg) = half.take_http(to_server) {
            on_event(match msg {
                Parsed::Request { method, path, headers, body } => {
                    HttpEvent::Request { conn: conn_id, ts, method, path, headers, body }
                }
                Parsed::Response { status, headers, body } => {
                    HttpEvent::Response { conn: conn_id, ts, status, headers, body }
                }
            });
        }

        // Forget connections idle for more than five minutes (long live captures).
        if self.conns.len() > 256 {
            self.conns.retain(|_, c| ts - c.last_seen < 300_000_000);
        }
    }
}

#[derive(Default)]
struct HalfStream {
    next_seq: Option<u32>,
    /// Segments that arrived ahead of `next_seq`.
    pending: Vec<(u32, Vec<u8>)>,
    buf: Vec<u8>,
}

const MAX_PENDING: usize = 4096;
const MAX_BUFFER: usize = 32 << 20;

impl HalfStream {
    fn segment(&mut self, seq: u32, syn: bool, payload: &[u8]) {
        if syn {
            self.next_seq = Some(seq.wrapping_add(1));
            self.pending.clear();
            self.buf.clear();
            return;
        }
        if payload.is_empty() {
            return;
        }
        let next = *self.next_seq.get_or_insert(seq);
        let offset = seq.wrapping_sub(next) as i32;
        if offset > 0 {
            if self.pending.len() < MAX_PENDING {
                self.pending.push((seq, payload.to_vec()));
            }
            return;
        }
        self.append(seq, payload);
        // Apply any queued segments that are now contiguous.
        loop {
            let next = self.next_seq.unwrap();
            let Some(i) = self.pending.iter().position(|(s, _)| s.wrapping_sub(next) as i32 <= 0) else { break };
            let (s, p) = self.pending.swap_remove(i);
            self.append(s, &p);
        }
    }

    /// Appends the part of a segment that lies at or beyond `next_seq` (skips retransmitted bytes).
    fn append(&mut self, seq: u32, payload: &[u8]) {
        let next = self.next_seq.unwrap();
        let skip = next.wrapping_sub(seq) as usize;
        if skip >= payload.len() {
            return;
        }
        let fresh = &payload[skip..];
        if self.buf.len() + fresh.len() > MAX_BUFFER {
            self.buf.clear();
        }
        self.buf.extend_from_slice(fresh);
        self.next_seq = Some(next.wrapping_add(fresh.len() as u32));
    }

    fn take_http(&mut self, request: bool) -> Option<Parsed> {
        loop {
            match parse_http(&self.buf, request) {
                ParseResult::Complete(msg, used) => {
                    self.buf.drain(..used);
                    return Some(msg);
                }
                ParseResult::Partial => return None,
                ParseResult::Garbage => {
                    // The capture started mid-message: skip to the next message start.
                    let marker: &[u8] = if request { b"POST " } else { b"HTTP/1." };
                    match find(&self.buf[1..], marker) {
                        Some(i) => {
                            self.buf.drain(..i + 1);
                        }
                        None => {
                            self.buf.clear();
                            return None;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum Parsed {
    Request { method: String, path: String, headers: Vec<(String, String)>, body: Vec<u8> },
    Response { status: u16, headers: Vec<(String, String)>, body: Vec<u8> },
}

enum ParseResult {
    Complete(Parsed, usize),
    Partial,
    Garbage,
}

fn parse_http(buf: &[u8], request: bool) -> ParseResult {
    if buf.is_empty() {
        return ParseResult::Partial;
    }
    let mut storage = [httparse::EMPTY_HEADER; 64];
    let (head_len, headers, start) = if request {
        let mut req = httparse::Request::new(&mut storage);
        match req.parse(buf) {
            Ok(httparse::Status::Complete(n)) => {
                let start = (req.method.unwrap_or("").to_string(), req.path.unwrap_or("").to_string(), 0);
                (n, collect_headers(req.headers), start)
            }
            Ok(httparse::Status::Partial) => return ParseResult::Partial,
            Err(_) => return ParseResult::Garbage,
        }
    } else {
        let mut resp = httparse::Response::new(&mut storage);
        match resp.parse(buf) {
            Ok(httparse::Status::Complete(n)) => {
                (n, collect_headers(resp.headers), (String::new(), String::new(), resp.code.unwrap_or(0)))
            }
            Ok(httparse::Status::Partial) => return ParseResult::Partial,
            Err(_) => return ParseResult::Garbage,
        }
    };

    let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
    let rest = &buf[head_len..];
    let (body, body_len) = if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        match dechunk(rest) {
            Some(r) => r,
            None => return ParseResult::Partial,
        }
    } else {
        let len = header("content-length").and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
        if rest.len() < len {
            return ParseResult::Partial;
        }
        (rest[..len].to_vec(), len)
    };

    let (method, path, status) = start;
    let msg = if request {
        Parsed::Request { method, path, headers, body }
    } else {
        Parsed::Response { status, headers, body }
    };
    ParseResult::Complete(msg, head_len + body_len)
}

fn collect_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
        .collect()
}

/// Decodes a chunked body. Returns `None` until the terminating chunk is present.
fn dechunk(mut buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let total = buf.len();
    let mut body = Vec::new();
    loop {
        let line_end = find(buf, b"\r\n")?;
        let size_str = std::str::from_utf8(&buf[..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        buf = &buf[line_end + 2..];
        if size == 0 {
            // Skip optional trailers up to the blank line.
            let end = find(buf, b"\r\n")?;
            if end == 0 {
                buf = &buf[2..];
            } else {
                let end = find(buf, b"\r\n\r\n")?;
                buf = &buf[end + 4..];
            }
            return Some((body, total - buf.len()));
        }
        if buf.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&buf[..size]);
        buf = &buf[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Opens a capture file, or stdin for `-`.
pub fn open_input(path: &str) -> Result<Box<dyn Read + Send>> {
    if path == "-" {
        Ok(Box::new(std::io::stdin()))
    } else {
        let f = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        Ok(Box::new(std::io::BufReader::new(f)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_out_of_order_and_duplicate_segments() {
        let mut h = HalfStream::default();
        h.segment(100, true, b"");
        h.segment(101, false, b"hello ");
        h.segment(113, false, b"!"); // ahead
        h.segment(101, false, b"hello "); // duplicate
        h.segment(107, false, b"world "); // fills the gap
        assert_eq!(h.buf, b"hello world !");
    }

    #[test]
    fn parses_content_length_and_chunked_messages() {
        let mut h = HalfStream { buf: b"POST /inform HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcPOST /inform HTTP/1.1\r\nContent-Le".to_vec(), ..Default::default() };
        match h.take_http(true) {
            Some(Parsed::Request { path, body, .. }) => {
                assert_eq!(path, "/inform");
                assert_eq!(body, b"abc");
            }
            other => panic!("{other:?}"),
        }
        assert!(h.take_http(true).is_none(), "second request is still partial");

        let mut h = HalfStream { buf: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".to_vec(), ..Default::default() };
        match h.take_http(false) {
            Some(Parsed::Response { status, body, .. }) => {
                assert_eq!(status, 200);
                assert_eq!(body, b"abcde");
            }
            other => panic!("{other:?}"),
        }
        assert!(h.buf.is_empty());
    }

    #[test]
    fn resynchronises_after_starting_mid_message() {
        let mut h = HalfStream { buf: b"tail of an old body\x00\x01POST /inform HTTP/1.1\r\nContent-Length: 1\r\n\r\nx".to_vec(), ..Default::default() };
        assert!(matches!(h.take_http(true), Some(Parsed::Request { .. })));
    }
}

/// Builds synthetic captures for tests (here and in dependent crates).
#[doc(hidden)]
pub mod sample {
    use etherparse::PacketBuilder;

    /// A legacy pcap containing the given TCP segments as (to_server, seq, payload).
    pub fn pcap(segments: &[(bool, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // ethernet
        let (ap, ctrl) = ([10, 0, 0, 5], [10, 0, 0, 1]);
        for (i, (to_server, seq, payload)) in segments.iter().enumerate() {
            let builder = if *to_server {
                PacketBuilder::ethernet2([2; 6], [4; 6]).ipv4(ap, ctrl, 64).tcp(40000, 8080, *seq, 1024)
            } else {
                PacketBuilder::ethernet2([4; 6], [2; 6]).ipv4(ctrl, ap, 64).tcp(8080, 40000, *seq, 1024)
            };
            let mut frame = Vec::new();
            builder.write(&mut frame, payload).unwrap();
            let ts_sec = 1_791_840_600 + i as u32;
            out.extend_from_slice(&ts_sec.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&frame);
        }
        out
    }

    pub fn http_request(body: &[u8]) -> Vec<u8> {
        let mut m = format!(
            "POST /inform HTTP/1.1\r\nHost: unifi\r\nX-Forwarded-For: 192.168.1.20\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        m.extend_from_slice(body);
        m
    }

    pub fn http_response(body: &[u8]) -> Vec<u8> {
        let mut m = format!("HTTP/1.1 200 OK\r\nContent-Type: application/x-binary\r\nContent-Length: {}\r\n\r\n", body.len())
            .into_bytes();
        m.extend_from_slice(body);
        m
    }
}

#[cfg(test)]
mod pcap_tests {
    use super::*;

    #[test]
    fn extracts_request_and_response_from_a_pcap() {
        let req = sample::http_request(b"REQUEST-BODY");
        let resp = sample::http_response(b"RESPONSE");
        let (a, rest) = req.split_at(30);
        let (b, c) = rest.split_at(20);
        let data = sample::pcap(&[
            (true, 1000, a),
            (true, 1050, c), // arrives before b (out of order)
            (true, 1000, a), // duplicate, as seen with `-i any`
            (true, 1030, b),
            (false, 5000, &resp),
        ]);
        let mut events = Vec::new();
        run(&data[..], &[8080], |e| events.push(e)).unwrap();
        assert_eq!(events.len(), 2, "{events:?}");
        match &events[0] {
            HttpEvent::Request { body, conn, ts, .. } => {
                assert_eq!(body, b"REQUEST-BODY");
                assert_eq!(conn.server.port(), 8080);
                assert_eq!(*ts, 1_791_840_603_000_000, "timestamp of the segment that completed it");
            }
            e => panic!("{e:?}"),
        }
        assert!(matches!(&events[1], HttpEvent::Response { status: 200, body, .. } if body == b"RESPONSE"));
    }
}
