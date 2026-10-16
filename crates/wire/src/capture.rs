//! Turns a pcap/pcapng stream into HTTP messages exchanged on the inform port.
//!
//! This is deliberately small: TCP segments are reassembled per direction
//! (tolerating duplicates, which `tcpdump -i any` produces, and reordering),
//! then HTTP/1.1 requests and responses are cut out of each byte stream.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
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
    /// A request: `inform` for a POST to `/inform`. `forwarded_for` is its
    /// X-Forwarded-For header, the only header anything reads.
    Request { conn: ConnId, ts: Micros, inform: bool, forwarded_for: Option<String>, body: Vec<u8> },
    Response { conn: ConnId, ts: Micros, status: u16, body: Vec<u8> },
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
    let mut buffer_size = 1 << 20;
    let mut reader = create_reader(buffer_size, input).map_err(|e| anyhow::anyhow!("reading capture header: {e:?}"))?;
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
            // tcpdump killed mid-write leaves half a block at the end: keep what came before.
            Err(PcapError::UnexpectedEof) => {
                eprintln!("warning: the capture ends in the middle of a packet (truncated?); ignoring the rest");
                return Ok(());
            }
            // A block larger than the buffer (jumbo frames, huge snaplen).
            Err(PcapError::BufferTooSmall) => {
                if buffer_size >= MAX_BLOCK {
                    bail!("capture block over {MAX_BLOCK} bytes");
                }
                buffer_size *= 4;
                reader.grow(buffer_size);
                if let Err(e) = reader.refill() {
                    bail!("reading capture: {e:?}");
                }
            }
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

/// Largest capture block the reader grows its buffer for.
const MAX_BLOCK: usize = 64 << 20;

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
    /// Capture time of the last sweep for idle connections.
    last_sweep: Micros,
}

#[derive(Default)]
struct Conn {
    to_server: HalfStream,
    to_client: HalfStream,
    last_seen: Micros,
}

impl Conn {
    /// Both sides closed and nothing is missing.
    fn closed(&self) -> bool {
        self.to_server.closed() && self.to_client.closed()
    }
}

/// Connections tracked beyond which idle ones are swept, at most once per `SWEEP_EVERY` of capture time.
const SWEEP_ABOVE: usize = 256;
const SWEEP_EVERY: Micros = 10_000_000;
/// How long an open connection may idle before it is forgotten (long live captures).
const MAX_IDLE: Micros = 300_000_000;
/// How long a closed connection is kept: long enough for the duplicate copies of its
/// last segments that `-i any` captures, which arrive right behind the originals.
const CLOSED_LINGER: Micros = 2_000_000;

impl Tracker {
    fn new(ports: Vec<u16>, udp_ports: Vec<u16>) -> Self {
        Tracker { ports, udp_ports, conns: HashMap::new(), last_sweep: 0 }
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
        half.segment(ts, tcp.sequence_number(), tcp.syn(), tcp.payload());
        half.fin |= tcp.fin();

        while let Some(msg) = half.take_http(to_server) {
            on_event(match msg {
                Parsed::Request { inform, forwarded_for, body } => HttpEvent::Request { conn: conn_id, ts, inform, forwarded_for, body },
                Parsed::Response { status, body } => HttpEvent::Response { conn: conn_id, ts, status, body },
            });
        }
        // Both sides closed and nothing is missing: release the buffers. The
        // entry itself stays a little longer (`CLOSED_LINGER`), so the duplicate
        // copies that `-i any` captures of the last segments count as
        // retransmissions instead of starting a new stream.
        if conn.closed() {
            conn.to_server.release();
            conn.to_client.release();
        }

        self.sweep(ts);
    }

    /// Forgets idle connections. Not on every packet: that would scan the whole map each time.
    fn sweep(&mut self, ts: Micros) {
        if self.conns.len() > SWEEP_ABOVE && ts.abs_diff(self.last_sweep) >= SWEEP_EVERY as u64 {
            self.last_sweep = ts;
            self.conns.retain(|_, c| ts - c.last_seen < if c.closed() { CLOSED_LINGER } else { MAX_IDLE });
        }
    }
}

#[derive(Default)]
struct HalfStream {
    next_seq: Option<u32>,
    /// Where `next_seq` lies in the stream, counted in bytes from where tracking
    /// started: unlike sequence numbers it does not wrap, so it can order `pending`.
    pos: i64,
    /// Segments that arrived ahead of `next_seq`, by stream position (one per
    /// position: a duplicate is kept once), and their total size.
    pending: BTreeMap<i64, Vec<u8>>,
    pending_bytes: usize,
    /// Since when the stream has been waiting for the bytes before `pending`.
    gap_since: Option<Micros>,
    buf: Vec<u8>,
    /// A FIN was seen.
    fin: bool,
}

/// How much may wait behind a gap before the missing bytes are given up on.
const MAX_PENDING: usize = 4096;
const MAX_PENDING_BYTES: usize = 4 << 20;
/// How long a gap may wait for its retransmission. A segment the capture missed
/// but the peer received is never sent again, so without this the stream would
/// stall for good.
const MAX_GAP_AGE: Micros = 10_000_000;
/// Largest unparsed message kept. Inform bodies are a few KB (the largest
/// decoded ones a few hundred KB), and anything bigger on the port is not an inform.
const MAX_BUFFER: usize = 8 << 20;

impl HalfStream {
    fn segment(&mut self, ts: Micros, seq: u32, syn: bool, payload: &[u8]) {
        if syn {
            *self = HalfStream { next_seq: Some(seq.wrapping_add(1)), ..HalfStream::default() };
            return;
        }
        if payload.is_empty() {
            return;
        }
        let next = *self.next_seq.get_or_insert(seq);
        let at = self.pos + i64::from(seq.wrapping_sub(next) as i32);
        if at > self.pos {
            match self.pending.entry(at) {
                Entry::Vacant(e) => {
                    self.pending_bytes += payload.len();
                    e.insert(payload.to_vec());
                }
                // A copy (`-i any` captures each segment twice), or a resend that carries more.
                Entry::Occupied(mut e) if e.get().len() < payload.len() => {
                    self.pending_bytes += payload.len() - e.get().len();
                    e.insert(payload.to_vec());
                }
                Entry::Occupied(_) => {}
            }
            self.gap_since.get_or_insert(ts);
        } else {
            self.append(at, payload);
            self.apply_pending(ts);
        }
        while self.pending.len() > MAX_PENDING
            || self.pending_bytes > MAX_PENDING_BYTES
            || self.gap_since.is_some_and(|since| ts.saturating_sub(since) > MAX_GAP_AGE)
        {
            self.skip_gap(ts);
        }
    }

    /// Applies the queued segments that are now contiguous.
    fn apply_pending(&mut self, ts: Micros) {
        let mut progress = false;
        while let Some(e) = self.pending.first_entry()
            && *e.key() <= self.pos
        {
            let (at, p) = e.remove_entry();
            self.pending_bytes -= p.len();
            self.append(at, &p);
            progress = true;
        }
        if self.pending.is_empty() {
            self.gap_since = None;
        } else if progress {
            self.gap_since = Some(ts);
        }
    }

    /// Gives up on the missing bytes and goes on from the earliest queued segment.
    /// The message they belonged to is lost, so the partial one in `buf` goes too;
    /// `take_http` then resynchronises on the next message start.
    fn skip_gap(&mut self, ts: Micros) {
        let Some(&lowest) = self.pending.keys().next() else {
            self.gap_since = None;
            return;
        };
        self.buf.clear();
        self.next_seq = self.next_seq.map(|next| next.wrapping_add((lowest - self.pos) as u32));
        self.pos = lowest;
        self.apply_pending(ts);
    }

    /// Closed by its sender with every byte received.
    fn closed(&self) -> bool {
        self.fin && self.pending.is_empty()
    }

    /// Frees the buffers but keeps `next_seq`.
    fn release(&mut self) {
        self.buf = Vec::new();
        self.pending = BTreeMap::new();
        self.pending_bytes = 0;
        self.gap_since = None;
    }

    /// Appends the part of a segment starting at stream position `at` (at or before
    /// `pos`) that lies beyond `pos`: retransmitted bytes are skipped.
    fn append(&mut self, at: i64, payload: &[u8]) {
        let skip = (self.pos - at) as usize;
        if skip >= payload.len() {
            return;
        }
        let fresh = &payload[skip..];
        if self.buf.len() + fresh.len() > MAX_BUFFER {
            self.buf.clear();
        }
        self.buf.extend_from_slice(fresh);
        self.pos += fresh.len() as i64;
        self.next_seq = self.next_seq.map(|next| next.wrapping_add(fresh.len() as u32));
    }

    fn take_http(&mut self, request: bool) -> Option<Parsed> {
        loop {
            match parse_http(&self.buf, request, self.closed()) {
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
    Request { inform: bool, forwarded_for: Option<String>, body: Vec<u8> },
    Response { status: u16, body: Vec<u8> },
}

enum ParseResult {
    Complete(Parsed, usize),
    Partial,
    Garbage,
}

/// Cuts the first message out of `buf`. `closed`: its sender closed the stream with
/// every byte received, which is what ends a response that has no length.
fn parse_http(buf: &[u8], request: bool, closed: bool) -> ParseResult {
    if buf.is_empty() {
        return ParseResult::Partial;
    }
    // Until the whole message is there this runs again on every segment, so nothing
    // is copied before it is complete.
    let mut storage = [httparse::EMPTY_HEADER; 64];
    let (head_len, headers, inform, status): (usize, &[httparse::Header<'_>], _, _) = if request {
        let mut req = httparse::Request::new(&mut storage);
        match req.parse(buf) {
            Ok(httparse::Status::Complete(n)) => {
                let inform = req.method == Some("POST") && req.path.is_some_and(|p| p.starts_with("/inform"));
                (n, req.headers, inform, 0)
            }
            Ok(httparse::Status::Partial) => return ParseResult::Partial,
            Err(_) => return ParseResult::Garbage,
        }
    } else {
        let mut resp = httparse::Response::new(&mut storage);
        match resp.parse(buf) {
            Ok(httparse::Status::Complete(n)) => (n, resp.headers, false, resp.code.unwrap_or(0)),
            Ok(httparse::Status::Partial) => return ParseResult::Partial,
            Err(_) => return ParseResult::Garbage,
        }
    };

    let header = |name: &str| headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value);
    let rest = &buf[head_len..];
    let chunked = header("transfer-encoding").is_some_and(|v| v.windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked")));
    let (body, body_len) = if chunked {
        match chunked_len(rest, |_| {}) {
            Chunked::Complete(used, size) => {
                let mut body = Vec::with_capacity(size);
                chunked_len(rest, |chunk| body.extend_from_slice(chunk));
                (body, used)
            }
            Chunked::Partial => return ParseResult::Partial,
            Chunked::Garbage => return ParseResult::Garbage,
        }
    } else {
        let len = match header("content-length") {
            Some(v) => match std::str::from_utf8(v).ok().and_then(|v| v.trim().parse::<usize>().ok()) {
                Some(len) => len,
                None => return ParseResult::Garbage,
            },
            // No length: a request has no body, nor has a response that never carries
            // one; any other response runs until the connection closes.
            None if request || status / 100 == 1 || status == 204 || status == 304 => 0,
            None if closed => rest.len(),
            None => return ParseResult::Partial,
        };
        if rest.len() < len {
            return ParseResult::Partial;
        }
        (rest[..len].to_vec(), len)
    };

    let msg = if request {
        let forwarded_for = header("x-forwarded-for").map(|v| String::from_utf8_lossy(v).into_owned());
        Parsed::Request { inform, forwarded_for, body }
    } else {
        Parsed::Response { status, body }
    };
    ParseResult::Complete(msg, head_len + body_len)
}

enum Chunked {
    /// The bytes the chunked body takes up (with its trailers), and the size of its data.
    Complete(usize, usize),
    Partial,
    /// A chunk size that is not hex or larger than any message we keep.
    Garbage,
}

/// Walks a chunked body, calling `chunk` with each chunk's data, until the terminating
/// chunk and the trailers after it.
fn chunked_len<'b>(mut buf: &'b [u8], mut chunk: impl FnMut(&'b [u8])) -> Chunked {
    let total = buf.len();
    let mut data = 0;
    loop {
        let Some(line_end) = find(buf, b"\r\n") else { return Chunked::Partial };
        let size = std::str::from_utf8(&buf[..line_end])
            .ok()
            .and_then(|line| usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16).ok());
        // A chunk that could not fit the buffer is not one we will ever see whole; the
        // cap also keeps `size + 2` from overflowing.
        let Some(size) = size.filter(|&s| s <= MAX_BUFFER) else { return Chunked::Garbage };
        buf = &buf[line_end + 2..];
        if size == 0 {
            // Skip optional trailers up to the blank line.
            let Some(end) = find(buf, b"\r\n") else { return Chunked::Partial };
            if end == 0 {
                buf = &buf[2..];
            } else {
                let Some(end) = find(buf, b"\r\n\r\n") else { return Chunked::Partial };
                buf = &buf[end + 4..];
            }
            return Chunked::Complete(total - buf.len(), data);
        }
        if buf.len() < size + 2 {
            return Chunked::Partial;
        }
        chunk(&buf[..size]);
        data += size;
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
        h.segment(0, 100, true, b"");
        h.segment(0, 101, false, b"hello ");
        h.segment(0, 113, false, b"!"); // ahead
        h.segment(0, 101, false, b"hello "); // duplicate
        h.segment(0, 107, false, b"world "); // fills the gap
        assert_eq!(h.buf, b"hello world !");
        assert_eq!((h.pending_bytes, h.gap_since), (0, None));
        // A new connection on the same addresses starts open.
        h.fin = true;
        h.segment(0, 9000, true, b"");
        assert!(!h.closed() && h.buf.is_empty());
        // Sequence numbers that wrap around, out of order.
        let mut h = HalfStream::default();
        h.segment(0, u32::MAX - 4, true, b"");
        h.segment(0, 2, false, b"cd");
        h.segment(0, 1, false, b"b");
        h.segment(0, u32::MAX - 3, false, b"aaaa");
        assert_eq!(h.buf, b"aaaa");
        h.segment(0, 0, false, b"_");
        assert_eq!((&h.buf[..], h.pending.len(), h.next_seq), (&b"aaaa_bcd"[..], 0, Some(4)));
    }

    #[test]
    fn a_gap_that_never_fills_is_skipped() {
        let msg = |body: &str| format!("POST /inform HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes();
        let (first, second) = (msg("lost"), msg("next"));
        let mut h = HalfStream::default();
        h.segment(0, 99, true, b"");
        h.segment(0, 100, false, &first[..10]);
        // The rest of the first message never shows up; the second one queues behind the gap.
        let at = 100 + first.len() as u32;
        h.segment(1_000_000, at, false, &second);
        assert!(h.take_http(true).is_none());
        // Still waiting while a retransmission may come ...
        h.segment(5_000_000, at, false, &second);
        assert_eq!(h.pending_bytes, second.len(), "the copy is queued once");
        // ... then gives up on it and carries on with the second message.
        h.segment(12_000_000, at, false, &second);
        assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"next"));
        assert!(h.take_http(true).is_none());
        assert_eq!((h.pending_bytes, h.gap_since), (0, None));
        h.segment(12_000_000, at + second.len() as u32, false, &first);
        assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"lost"), "in sync again");
    }

    #[test]
    fn pending_bytes_are_bounded() {
        let mut h = HalfStream::default();
        h.segment(0, 0, true, b"");
        h.segment(0, 1, false, b"x");
        let chunk = vec![b'y'; 60_000];
        for i in 0..200u32 {
            h.segment(0, 100 + i * 60_000, false, &chunk); // all behind the gap at 2..100
            assert!(h.pending_bytes <= MAX_PENDING_BYTES);
        }
        assert!(h.next_seq.unwrap() > 100, "skipped ahead");
    }

    #[test]
    fn parses_content_length_and_chunked_messages() {
        let mut h = HalfStream { buf: b"POST /inform HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcPOST /inform HTTP/1.1\r\nContent-Le".to_vec(), ..Default::default() };
        match h.take_http(true) {
            Some(Parsed::Request { inform, body, .. }) => {
                assert!(inform);
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
    fn oversized_or_malformed_chunk_sizes_are_garbage() {
        let good = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n";
        for size in ["ffffffffffffffff", "fffffffffffffffe", "1000000000", "zz"] {
            let mut buf = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nabc").into_bytes();
            buf.extend_from_slice(good);
            let mut h = HalfStream { buf, ..Default::default() };
            assert!(matches!(h.take_http(false), Some(Parsed::Response { body, .. }) if body == b"ok"), "{size}: skipped to the next response");
            assert!(h.buf.is_empty());
        }
        // A size that is still arriving is not garbage.
        assert!(matches!(chunked_len(b"fff", |_| {}), Chunked::Partial));
        assert!(matches!(chunked_len(b"3\r\nab", |_| {}), Chunked::Partial));
    }

    #[test]
    fn closed_connections_are_swept_soon_and_idle_ones_later() {
        let mut t = Tracker::new(vec![8080], Vec::new());
        let conn = |port: u16| ConnId { client: SocketAddr::from(([10, 0, 0, 5], port)), server: SocketAddr::from(([10, 0, 0, 1], 8080)) };
        for port in 0..300u16 {
            let mut c = Conn::default();
            if port % 2 == 0 {
                (c.to_server.fin, c.to_client.fin) = (true, true);
            }
            t.conns.insert(conn(port), c);
        }
        t.sweep(1_000_000);
        assert_eq!(t.conns.len(), 300, "at most one sweep per SWEEP_EVERY");
        t.sweep(20_000_000);
        assert_eq!(t.conns.len(), 150, "closed ones go after CLOSED_LINGER");
        assert!(t.conns.values().all(|c| !c.closed()));
        t.conns.extend((300..500u16).map(|p| (conn(p), Conn::default())));
        t.sweep(400_000_000);
        assert!(t.conns.is_empty(), "open ones after MAX_IDLE");
    }

    #[test]
    fn messages_without_a_usable_length() {
        // An unreadable Content-Length is skipped to the next message, not read as empty.
        let mut h = HalfStream { buf: b"POST /inform HTTP/1.1\r\nContent-Length: x1\r\n\r\nabcPOST /inform HTTP/1.1\r\nContent-Length: 1\r\nX-Forwarded-For: 10.0.0.9\r\n\r\nz".to_vec(), ..Default::default() };
        match h.take_http(true) {
            Some(Parsed::Request { inform: true, forwarded_for, body }) => assert_eq!((forwarded_for.as_deref(), &body[..]), (Some("10.0.0.9"), &b"z"[..])),
            other => panic!("{other:?}"),
        }
        // A GET without a length has no body, and is not an inform.
        let mut h = HalfStream { buf: b"GET /status HTTP/1.1\r\n\r\n".to_vec(), ..Default::default() };
        assert!(matches!(h.take_http(true), Some(Parsed::Request { inform: false, body, .. }) if body.is_empty()));
        // A response without one runs until the connection closes.
        let mut h = HalfStream { buf: b"HTTP/1.0 200 OK\r\n\r\nall of it".to_vec(), ..Default::default() };
        assert!(h.take_http(false).is_none());
        h.fin = true;
        assert!(matches!(h.take_http(false), Some(Parsed::Response { status: 200, body }) if body == b"all of it"));
        let mut h = HalfStream { buf: b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), ..Default::default() };
        assert!(matches!(h.take_http(false), Some(Parsed::Response { status: 204, body }) if body.is_empty()));
    }

    #[test]
    fn resynchronises_after_starting_mid_message() {
        let mut h = HalfStream { buf: b"tail of an old body\x00\x01POST /inform HTTP/1.1\r\nContent-Length: 1\r\n\r\nx".to_vec(), ..Default::default() };
        assert!(matches!(h.take_http(true), Some(Parsed::Request { .. })));
    }
}

/// Synthetic captures and the capture fixtures, for tests here and in dependent crates (and
/// informdump's made-up demo site, which writes the same pcap framing).
#[doc(hidden)]
pub mod sample {
    use std::io::{self, Write};
    use std::path::PathBuf;

    use etherparse::PacketBuilder;

    use super::Micros;

    /// The sanitised capture fixtures, kept outside the repository:
    /// `$APCTL_TESTDATA/2026-10-12-u6m-8.8.11`. `None`, saying why, when they are not
    /// there: tests that need them skip.
    pub fn fixtures() -> Option<PathBuf> {
        let Some(root) = std::env::var_os("APCTL_TESTDATA") else {
            eprintln!("skipped: APCTL_TESTDATA is not set, so the capture fixtures are not available");
            return None;
        };
        let dir = PathBuf::from(root).join("2026-10-12-u6m-8.8.11");
        if !dir.is_dir() {
            eprintln!("skipped: no capture fixtures in {}", dir.display());
            return None;
        }
        Some(dir)
    }

    /// The header of a legacy pcap (microsecond timestamps) of Ethernet frames.
    pub fn write_pcap_header(out: &mut impl Write, snaplen: u32) -> io::Result<()> {
        out.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&snaplen.to_le_bytes())?;
        out.write_all(&1u32.to_le_bytes()) // ethernet
    }

    /// One legacy pcap record holding all of `frame`.
    pub fn write_pcap_record(out: &mut impl Write, ts: Micros, frame: &[u8]) -> io::Result<()> {
        out.write_all(&((ts / 1_000_000) as u32).to_le_bytes())?;
        out.write_all(&((ts % 1_000_000) as u32).to_le_bytes())?;
        out.write_all(&(frame.len() as u32).to_le_bytes())?;
        out.write_all(&(frame.len() as u32).to_le_bytes())?;
        out.write_all(frame)
    }

    /// A legacy pcap containing the given TCP segments as (to_server, seq, payload).
    pub fn pcap(segments: &[(bool, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        write_pcap_header(&mut out, 65535).unwrap();
        let (ap, ctrl) = ([10, 0, 0, 5], [10, 0, 0, 1]);
        for (i, (to_server, seq, payload)) in segments.iter().enumerate() {
            let builder = if *to_server {
                PacketBuilder::ethernet2([2; 6], [4; 6]).ipv4(ap, ctrl, 64).tcp(40000, 8080, *seq, 1024)
            } else {
                PacketBuilder::ethernet2([4; 6], [2; 6]).ipv4(ctrl, ap, 64).tcp(8080, 40000, *seq, 1024)
            };
            let mut frame = Vec::new();
            builder.write(&mut frame, payload).unwrap();
            write_pcap_record(&mut out, (1_791_840_600 + i as Micros) * 1_000_000, &frame).unwrap();
        }
        out
    }

    /// An HTTP/1.1 message: `head` is the start line and headers, each ending in CRLF;
    /// the Content-Length and the blank line are added.
    pub fn http(head: &str, body: &[u8]) -> Vec<u8> {
        let mut m = format!("{head}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
        m.extend_from_slice(body);
        m
    }

    pub fn http_request(body: &[u8]) -> Vec<u8> {
        http("POST /inform HTTP/1.1\r\nHost: unifi\r\nX-Forwarded-For: 192.168.1.20\r\n", body)
    }

    pub fn http_response(body: &[u8]) -> Vec<u8> {
        http("HTTP/1.1 200 OK\r\nContent-Type: application/x-binary\r\n", body)
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

    #[test]
    fn a_truncated_capture_keeps_what_it_has() {
        let req = sample::http_request(b"REQUEST-BODY");
        let resp = sample::http_response(b"RESPONSE");
        let data = sample::pcap(&[(true, 1000, &req), (false, 5000, &resp)]);
        let mut events = Vec::new();
        run(&data[..data.len() - 5], &[8080], |e| events.push(e)).unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
    }

    #[test]
    fn blocks_larger_than_the_buffer_are_read() {
        let req = sample::http_request(b"REQUEST-BODY");
        let mut data = sample::pcap(&[]);
        // A 3 MiB record (not a frame we parse), then a normal one.
        let big = 3 << 20;
        for v in [1_791_840_600u32, 0, big, big] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        data.resize(data.len() + big as usize, 0);
        data.extend_from_slice(&sample::pcap(&[(true, 1000, &req)])[24..]);
        let mut events = Vec::new();
        run(&data[..], &[8080], |e| events.push(e)).unwrap();
        assert!(matches!(&events[..], [HttpEvent::Request { body, .. }] if body == b"REQUEST-BODY"), "{events:?}");
    }
}
