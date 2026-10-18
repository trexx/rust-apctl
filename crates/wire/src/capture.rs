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
use pcap_parser::traits::PcapNGPacketBlock;
use pcap_parser::{Block, IDB_MAGIC, Linktype, PcapBlockOwned, PcapError, create_reader};

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
    // A pcapng simple packet block has no timestamp: it gets the last one seen, so
    // shadow mode's capture-following clock does not jump back to 1970.
    let mut last_ts: Micros = 0;

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
                        last_ts = b.ts_sec as i64 * 1_000_000 + frac;
                        tracker.packet(legacy_linktype, last_ts, b.data, &mut on_event);
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => interfaces.clear(),
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        // pcap-parser reads the offset as little-endian whatever the section's byte order.
                        let offset = if idb.block_type == IDB_MAGIC { idb.if_tsoffset } else { idb.if_tsoffset.swap_bytes() };
                        interfaces.push((idb.linktype, ts_units(idb.if_tsresol), offset));
                    }
                    // A packet naming an interface no block described is skipped: the
                    // reader still has to move past it, below.
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        if let Some(&(linktype, units, offset)) = interfaces.get(epb.if_id as usize) {
                            last_ts = epb_micros(epb.ts_high, epb.ts_low, units, offset);
                            tracker.packet(linktype, last_ts, epb.packet_data(), &mut on_event);
                        }
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                        if let Some(&(linktype, ..)) = interfaces.first() {
                            tracker.packet(linktype, last_ts, spb.packet_data(), &mut on_event);
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

/// Timestamp units per second of a pcapng interface, from its `if_tsresol`: a power of
/// ten, or of two when the top bit is set. pcap-parser's own `ts_resolution` rejects
/// every power of two, so it is worked out here; one that does not fit falls back to
/// the default, microseconds.
fn ts_units(tsresol: u8) -> u64 {
    let exp = u32::from(tsresol & 0x7f);
    let units = if tsresol & 0x80 != 0 { 1u64.checked_shl(exp) } else { 10u64.checked_pow(exp) };
    units.unwrap_or(1_000_000)
}

/// An enhanced packet block's time in microseconds since the epoch. Worked out here
/// because pcap-parser's `decode_ts` cuts the fraction to 32 bits (picoseconds do not
/// fit) and takes no negative offset.
fn epb_micros(ts_high: u32, ts_low: u32, units: u64, offset_secs: i64) -> Micros {
    let ts = u64::from(ts_high) << 32 | u64::from(ts_low);
    let (secs, frac) = (i128::from(ts / units), i128::from(ts % units));
    let micros = (i128::from(offset_secs) + secs) * 1_000_000 + frac * 1_000_000 / i128::from(units);
    micros.clamp(Micros::MIN.into(), Micros::MAX.into()) as Micros
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
    /// When idle connections were last swept.
    sweeper: Sweeper,
}

#[derive(Default)]
struct Conn {
    to_server: HalfStream,
    to_client: HalfStream,
    last_seen: Micros,
    /// Some segment in either direction carried data.
    carried: bool,
}

impl Conn {
    /// Both sides closed and nothing is missing.
    fn closed(&self) -> bool {
        self.to_server.closed() && self.to_client.closed()
    }

    /// How long the connection may go unseen before it is forgotten.
    fn max_idle(&self) -> Micros {
        if self.closed() {
            CLOSED_LINGER
        } else if self.carried {
            MAX_IDLE
        } else {
            MAX_IDLE_EMPTY
        }
    }
}

/// Entries in a map of connections (here, and the requests waiting in `exchange`) beyond
/// which stale ones are swept, at most once per `SWEEP_EVERY` of capture time: not on
/// every packet, which would scan the whole map each time.
pub(crate) const SWEEP_ABOVE: usize = 256;
const SWEEP_EVERY: Micros = 10_000_000;

/// When a map of connections was last swept.
#[derive(Default)]
pub(crate) struct Sweeper {
    pub(crate) last: Micros,
}

impl Sweeper {
    /// Whether a map of `len` entries is due for a sweep at `ts`; if it is, the sweep counts as done.
    pub(crate) fn due(&mut self, len: usize, ts: Micros) -> bool {
        let due = len > SWEEP_ABOVE && ts.abs_diff(self.last) >= SWEEP_EVERY as u64;
        if due {
            self.last = ts;
        }
        due
    }
}
/// Most connections tracked at once. An AP keeps one open, so this is far more than
/// any site has; it bounds what packets with made-up addresses can make us hold.
const MAX_CONNS: usize = 16_384;
/// How long an open connection may idle before it is forgotten (long live captures).
const MAX_IDLE: Micros = 300_000_000;
/// The same for one that never carried data (a handshake, a stray ACK): an AP sends
/// its request as soon as it has connected.
const MAX_IDLE_EMPTY: Micros = 10_000_000;
/// How long a closed connection is kept: long enough for the duplicate copies of its
/// last segments that `-i any` captures, which arrive right behind the originals.
const CLOSED_LINGER: Micros = 2_000_000;

impl Tracker {
    fn new(ports: Vec<u16>, udp_ports: Vec<u16>) -> Self {
        Tracker { ports, udp_ports, conns: HashMap::new(), sweeper: Sweeper::default() }
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

        if tcp.rst() {
            self.conns.remove(&conn_id);
            return;
        }
        if self.conns.len() >= MAX_CONNS && !self.conns.contains_key(&conn_id) {
            self.make_room(ts);
        }
        let conn = self.conns.entry(conn_id).or_default();
        conn.last_seen = ts;
        conn.carried |= !tcp.payload().is_empty();
        let half = if to_server { &mut conn.to_server } else { &mut conn.to_client };
        half.segment(ts, tcp.sequence_number(), tcp.syn(), tcp.fin(), tcp.payload());

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

    /// Forgets idle connections, when a sweep is due.
    fn sweep(&mut self, ts: Micros) {
        if self.sweeper.due(self.conns.len(), ts) {
            self.conns.retain(|_, c| ts - c.last_seen < c.max_idle());
        }
    }

    /// Called when the map is full and a new connection shows up: sweeps, and if
    /// that frees too little, forgets an eighth of the map, those that never carried
    /// data first and then the least recently seen. Packets with made-up addresses
    /// cost no more than that, and a real connection that is forgotten picks up again
    /// at its next message.
    fn make_room(&mut self, ts: Micros) {
        self.sweeper.last = ts;
        self.conns.retain(|_, c| ts - c.last_seen < c.max_idle());
        if self.conns.len() > MAX_CONNS - MAX_CONNS / 8 {
            let mut order: Vec<(bool, Micros)> = self.conns.values().map(|c| (c.carried, c.last_seen)).collect();
            let (_, &mut cutoff, _) = order.select_nth_unstable(MAX_CONNS / 8);
            self.conns.retain(|_, c| (c.carried, c.last_seen) > cutoff);
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
    /// How much of `buf` has been cut into messages or skipped. The used bytes are
    /// dropped only once they are most of the buffer: dropping them after each
    /// message would move the rest of the buffer every time.
    consumed: usize,
    /// The stream position of a FIN that was seen: the end of the stream. It may arrive
    /// ahead of the last bytes, so the stream is closed only once `pos` reaches it.
    fin_at: Option<i64>,
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
/// Largest message head (start line and headers). Until a head is complete it is
/// parsed again with every segment, so one that never ends is given up on early.
const MAX_HEAD: usize = 64 << 10;
/// Most chunks in a chunked body: a body is walked again with every segment until
/// it is complete. Inform replies, a few hundred KB at most, come in far fewer.
const MAX_CHUNKS: usize = 4096;

impl HalfStream {
    fn segment(&mut self, ts: Micros, seq: u32, syn: bool, fin: bool, payload: &[u8]) {
        if syn {
            *self = HalfStream { next_seq: Some(seq.wrapping_add(1)), ..HalfStream::default() };
            return;
        }
        // Where the segment lies in the stream (where we are, for the first one seen).
        let at = self.pos + self.next_seq.map_or(0, |next| i64::from(seq.wrapping_sub(next) as i32));
        if fin {
            self.fin_at.get_or_insert(at + payload.len() as i64);
        }
        if payload.is_empty() {
            return;
        }
        self.next_seq.get_or_insert(seq);
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
            let pos = self.pos;
            self.append(at, payload);
            // Bytes before the gap are still arriving, so the wait for the rest starts
            // again. Nor could a gap be skipped below without losing a message these
            // bytes may just have completed, which the caller has not taken yet; the
            // queue only shrinks here, so no size limit can force a skip either.
            if self.pos > pos && self.gap_since.is_some() {
                self.gap_since = Some(ts);
            }
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
        self.clear_buf();
        self.next_seq = self.next_seq.map(|next| next.wrapping_add((lowest - self.pos) as u32));
        self.pos = lowest;
        self.apply_pending(ts);
    }

    /// Closed by its sender with every byte received.
    fn closed(&self) -> bool {
        self.fin_at.is_some_and(|fin_at| self.pos >= fin_at) && self.pending.is_empty()
    }

    /// Frees the buffers but keeps `next_seq`.
    fn release(&mut self) {
        self.buf = Vec::new();
        self.consumed = 0;
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
        if self.buf.len() - self.consumed + fresh.len() > MAX_BUFFER {
            self.clear_buf();
        }
        self.buf.extend_from_slice(fresh);
        self.pos += fresh.len() as i64;
        self.next_seq = self.next_seq.map(|next| next.wrapping_add(fresh.len() as u32));
    }

    fn clear_buf(&mut self) {
        self.buf.clear();
        self.consumed = 0;
    }

    fn take_http(&mut self, request: bool) -> Option<Parsed> {
        let msg = self.next_http(request);
        // Each byte is moved at most once more than it is parsed, however many
        // messages arrive at once.
        if self.consumed == self.buf.len() {
            self.clear_buf();
        } else if self.consumed > self.buf.len() / 2 {
            self.buf.drain(..self.consumed);
            self.consumed = 0;
        }
        msg
    }

    fn next_http(&mut self, request: bool) -> Option<Parsed> {
        loop {
            let rest = &self.buf[self.consumed..];
            match parse_http(rest, request, self.closed()) {
                ParseResult::Complete(msg, used) => {
                    self.consumed += used;
                    return Some(msg);
                }
                ParseResult::Partial => return None,
                ParseResult::Garbage => {
                    // The capture started mid-message: skip to the next message start.
                    let marker: &[u8] = if request { b"POST " } else { b"HTTP/1." };
                    match find(&rest[1..], marker) {
                        Some(i) => self.consumed += i + 1,
                        None => {
                            self.consumed = self.buf.len();
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
            Ok(httparse::Status::Partial) => return head_partial(buf),
            Err(_) => return ParseResult::Garbage,
        }
    } else {
        let mut resp = httparse::Response::new(&mut storage);
        match resp.parse(buf) {
            Ok(httparse::Status::Complete(n)) => (n, resp.headers, false, resp.code.unwrap_or(0)),
            Ok(httparse::Status::Partial) => return head_partial(buf),
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
        // A message that could not fit the buffer would stall the stream until the buffer
        // is cleared, losing the messages behind it: skip it, as an oversized chunk.
        if len > MAX_BUFFER.saturating_sub(head_len) {
            return ParseResult::Garbage;
        }
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

/// A head that is not complete yet, unless it is already longer than any we accept.
fn head_partial(buf: &[u8]) -> ParseResult {
    if buf.len() > MAX_HEAD { ParseResult::Garbage } else { ParseResult::Partial }
}

enum Chunked {
    /// The bytes the chunked body takes up (with its trailers), and the size of its data.
    Complete(usize, usize),
    Partial,
    /// A chunk size that is not hex or larger than any message we keep, or more
    /// than `MAX_CHUNKS` chunks.
    Garbage,
}

/// Walks a chunked body, calling `chunk` with each chunk's data, until the terminating
/// chunk and the trailers after it.
fn chunked_len<'b>(mut buf: &'b [u8], mut chunk: impl FnMut(&'b [u8])) -> Chunked {
    let total = buf.len();
    let mut data = 0;
    for _ in 0..=MAX_CHUNKS {
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
    Chunked::Garbage
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}

/// The status and body (chunked encoding undone) of the HTTP response in `buf`, which
/// holds everything the server sent before it closed the connection. `None` when that
/// is not one whole, well-formed response.
pub fn parse_response(buf: &[u8]) -> Option<(u16, Vec<u8>)> {
    match parse_http(buf, false, true) {
        ParseResult::Complete(Parsed::Response { status, body }, _) => Some((status, body)),
        _ => None,
    }
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
        h.segment(0, 100, true, false, b"");
        h.segment(0, 101, false, false, b"hello ");
        h.segment(0, 113, false, false, b"!"); // ahead
        h.segment(0, 101, false, false, b"hello "); // duplicate
        h.segment(0, 107, false, false, b"world "); // fills the gap
        assert_eq!(h.buf, b"hello world !");
        assert_eq!((h.pending_bytes, h.gap_since), (0, None));
        // A new connection on the same addresses starts open.
        h.fin_at = Some(h.pos);
        h.segment(0, 9000, true, false, b"");
        assert!(!h.closed() && h.buf.is_empty());
        // Sequence numbers that wrap around, out of order.
        let mut h = HalfStream::default();
        h.segment(0, u32::MAX - 4, true, false, b"");
        h.segment(0, 2, false, false, b"cd");
        h.segment(0, 1, false, false, b"b");
        h.segment(0, u32::MAX - 3, false, false, b"aaaa");
        assert_eq!(h.buf, b"aaaa");
        h.segment(0, 0, false, false, b"_");
        assert_eq!((&h.buf[..], h.pending.len(), h.next_seq), (&b"aaaa_bcd"[..], 0, Some(4)));
    }

    #[test]
    fn a_gap_that_never_fills_is_skipped() {
        let msg = |body: &str| format!("POST /inform HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes();
        let (first, second) = (msg("lost"), msg("next"));
        let mut h = HalfStream::default();
        h.segment(0, 99, true, false, b"");
        h.segment(0, 100, false, false, &first[..10]);
        // The rest of the first message never shows up; the second one queues behind the gap.
        let at = 100 + first.len() as u32;
        h.segment(1_000_000, at, false, false, &second);
        assert!(h.take_http(true).is_none());
        // Still waiting while a retransmission may come ...
        h.segment(5_000_000, at, false, false, &second);
        assert_eq!(h.pending_bytes, second.len(), "the copy is queued once");
        // ... then gives up on it and carries on with the second message.
        h.segment(12_000_000, at, false, false, &second);
        assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"next"));
        assert!(h.take_http(true).is_none());
        assert_eq!((h.pending_bytes, h.gap_since), (0, None));
        h.segment(12_000_000, at + second.len() as u32, false, false, &first);
        assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"lost"), "in sync again");
    }

    #[test]
    fn a_message_completed_while_a_later_gap_is_old_is_kept() {
        let msg = |body: &str| format!("POST /inform HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes();
        let (first, second, third) = (msg("first"), msg("second"), msg("third"));
        let mut h = HalfStream::default();
        h.segment(0, 99, true, false, b"");
        h.segment(0, 100, false, false, &first[..10]);
        // The third message queues behind a gap: the rest of the first and all of the second.
        let third_at = 100 + (first.len() + second.len()) as u32;
        h.segment(1_000_000, third_at, false, false, &third);
        // Long after, the rest of the first arrives (the second never does).
        h.segment(12_000_000, 110, false, false, &first[10..]);
        assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"first"));
        assert!(h.take_http(true).is_none());
        // The gap then ages again and is skipped, carrying on with the third.
        h.segment(23_000_000, third_at, false, false, &third);
        assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"third"));
    }

    #[test]
    fn pending_bytes_are_bounded() {
        let mut h = HalfStream::default();
        h.segment(0, 0, true, false, b"");
        h.segment(0, 1, false, false, b"x");
        let chunk = vec![b'y'; 60_000];
        for i in 0..200u32 {
            h.segment(0, 100 + i * 60_000, false, false, &chunk); // all behind the gap at 2..100
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
    fn a_content_length_beyond_the_buffer_is_garbage() {
        let next = b"POST /inform HTTP/1.1\r\nContent-Length: 2\r\n\r\nok";
        for len in [MAX_BUFFER, usize::MAX] {
            let mut buf = format!("POST /inform HTTP/1.1\r\nContent-Length: {len}\r\n\r\nabc").into_bytes();
            buf.extend_from_slice(next);
            let mut h = HalfStream { buf, ..Default::default() };
            assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"ok"), "{len}: skipped to the next request");
            assert!(h.buf.is_empty());
        }
        // One that fits, with its head, is waited for.
        let head = "POST /inform HTTP/1.1\r\nContent-Length: 0000000000\r\n\r\n";
        let buf = head.replace("0000000000", &format!("{:010}", MAX_BUFFER - head.len())).into_bytes();
        assert!(matches!(parse_http(&buf, true, false), ParseResult::Partial));
    }

    #[test]
    fn closed_connections_are_swept_soon_and_idle_ones_later() {
        let mut t = Tracker::new(vec![8080], Vec::new());
        let conn = |port: u16| ConnId { client: SocketAddr::from(([10, 0, 0, 5], port)), server: SocketAddr::from(([10, 0, 0, 1], 8080)) };
        for port in 0..300u16 {
            let mut c = Conn { carried: true, ..Conn::default() };
            if port % 2 == 0 {
                (c.to_server.fin_at, c.to_client.fin_at) = (Some(0), Some(0));
            }
            t.conns.insert(conn(port), c);
        }
        t.sweep(1_000_000);
        assert_eq!(t.conns.len(), 300, "at most one sweep per SWEEP_EVERY");
        t.sweep(20_000_000);
        assert_eq!(t.conns.len(), 150, "closed ones go after CLOSED_LINGER");
        assert!(t.conns.values().all(|c| !c.closed()));
        t.conns.extend((300..500u16).map(|p| (conn(p), Conn { carried: true, ..Conn::default() })));
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
        h.fin_at = Some(h.pos);
        assert!(matches!(h.take_http(false), Some(Parsed::Response { status: 200, body }) if body == b"all of it"));
        let mut h = HalfStream { buf: b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), ..Default::default() };
        assert!(matches!(h.take_http(false), Some(Parsed::Response { status: 204, body }) if body.is_empty()));
    }

    #[test]
    fn a_fin_ahead_of_the_last_bytes_waits_for_them() {
        let (a, b, c) = (&b"HTTP/1.0 200 OK\r\n\r\nall "[..], &b"of "[..], &b"it"[..]);
        let (b_seq, c_seq) = (1 + a.len() as u32, 1 + (a.len() + b.len()) as u32);
        let end = c_seq + c.len() as u32;
        // A bare FIN that overtakes the last two segments.
        let mut h = HalfStream::default();
        h.segment(0, 0, true, false, b"");
        h.segment(0, 1, false, false, a);
        h.segment(0, end, false, true, b"");
        assert!(!h.closed());
        assert!(h.take_http(false).is_none(), "a response without a length is not cut at the early FIN");
        h.segment(0, c_seq, false, false, c);
        h.segment(0, end, false, true, b""); // its `-i any` copy
        assert!(!h.closed());
        h.segment(0, b_seq, false, false, b);
        assert!(h.closed());
        assert!(matches!(h.take_http(false), Some(Parsed::Response { status: 200, body }) if body == b"all of it"));
        // A FIN on the last data, ahead of the segment before it.
        let mut h = HalfStream::default();
        h.segment(0, 0, true, false, b"");
        h.segment(0, 1, false, false, a);
        h.segment(0, c_seq, false, true, c);
        assert!(!h.closed() && h.take_http(false).is_none());
        h.segment(0, b_seq, false, false, b);
        assert!(h.closed());
        assert!(matches!(h.take_http(false), Some(Parsed::Response { status: 200, body }) if body == b"all of it"));
        // A FIN in order closes at once, as does one that tracking starts at.
        h.segment(0, 9000, true, false, b"");
        h.segment(0, 9001, false, true, a);
        assert!(h.closed());
        let mut h = HalfStream::default();
        h.segment(0, 77, false, true, b"");
        assert!(h.closed());
    }

    #[test]
    fn a_whole_response_is_parsed_for_its_reader() {
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA"), Some((200, b"ok".to_vec())));
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n1\r\n!\r\n0\r\n\r\n"), Some((200, b"ok!".to_vec())));
        assert_eq!(parse_response(b"HTTP/1.0 404 Not Found\r\n\r\nall of it"), Some((404, b"all of it".to_vec())));
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok"), None, "truncated");
        assert_eq!(parse_response(b"not http"), None);
    }

    #[test]
    fn resynchronises_after_starting_mid_message() {
        let mut h = HalfStream { buf: b"tail of an old body\x00\x01POST /inform HTTP/1.1\r\nContent-Length: 1\r\n\r\nx".to_vec(), ..Default::default() };
        assert!(matches!(h.take_http(true), Some(Parsed::Request { .. })));
    }

    /// Before the buffer kept an offset, each of these drained the rest of a 2 MB buffer.
    #[test]
    fn a_burst_of_pipelined_requests_is_cut_in_linear_time() {
        let one = b"POST /inform HTTP/1.1\r\nContent-Length: 1\r\n\r\nx";
        let mut h = HalfStream::default();
        h.segment(0, 0, true, false, b"");
        h.segment(0, 1, false, false, &one.repeat(50_000));
        let mut n = 0;
        while let Some(Parsed::Request { body, .. }) = h.take_http(true) {
            assert_eq!(body, b"x");
            n += 1;
            assert!(h.consumed <= h.buf.len() - h.consumed, "compacted once used bytes are the larger part");
        }
        assert_eq!((n, h.buf.len(), h.consumed), (50_000, 0, 0));
        // Garbage with a message start every few bytes is skipped as quickly.
        let mut h = HalfStream { buf: b"POST POST ".repeat(100_000), ..Default::default() };
        h.buf.extend_from_slice(one);
        assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"x"));
        assert!(h.buf.is_empty());
    }

    #[test]
    fn a_head_that_never_ends_is_given_up_on() {
        let mut h = HalfStream::default();
        h.segment(0, 0, true, false, b"");
        let mut seq = 1;
        let mut send = |h: &mut HalfStream, data: &[u8]| {
            h.segment(0, seq, false, false, data);
            seq += data.len() as u32;
        };
        send(&mut h, b"POST /inform HTTP/1.1\r\nX-Long: ");
        for _ in 0..100 {
            send(&mut h, &[b'a'; 1400]);
            assert!(h.take_http(true).is_none());
            assert!(h.buf.len() <= MAX_HEAD + 1400, "{}", h.buf.len());
        }
        send(&mut h, b"\r\n\r\nPOST /inform HTTP/1.1\r\nContent-Length: 2\r\n\r\nok");
        assert!(matches!(h.take_http(true), Some(Parsed::Request { body, .. }) if body == b"ok"));
        // A chunked body in more chunks than any reply has.
        let mut buf = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        buf.extend_from_slice(&b"1\r\nx\r\n".repeat(MAX_CHUNKS + 1));
        assert!(matches!(chunked_len(&buf[45..], |_| {}), Chunked::Garbage));
        assert!(matches!(chunked_len(&b"1\r\nx\r\n".repeat(MAX_CHUNKS), |_| {}), Chunked::Partial));
    }

    #[test]
    fn connections_are_capped() {
        let mut t = Tracker::new(vec![8080], Vec::new());
        let syn = |port: u16| {
            let mut frame = Vec::new();
            etherparse::PacketBuilder::ethernet2([2; 6], [4; 6]).ipv4([10, 0, (port >> 8) as u8, port as u8], [10, 0, 0, 1], 64).tcp(port, 8080, 1, 1024).syn().write(&mut frame, b"").unwrap();
            frame
        };
        // A real connection that carried data, then a flood of bare SYNs from made-up addresses.
        let (ap, ctrl) = sample::endpoints();
        let frame = crate::synth::tcp_frame(ap, ctrl, 1, &sample::http_request(b"x")).unwrap();
        let mut events = 0;
        t.packet(Linktype::ETHERNET, 0, &frame, &mut |_| events += 1);
        assert_eq!(events, 1);
        for port in 0..(MAX_CONNS + MAX_CONNS / 4) as u16 {
            t.packet(Linktype::ETHERNET, 1, &syn(port), &mut |_| {});
            assert!(t.conns.len() <= MAX_CONNS);
        }
        assert!(t.conns.values().any(|c| c.carried), "connections that carried data are kept over ones that did not");
        // Ones that never carried data are swept after a short while.
        t.sweep(1 + MAX_IDLE_EMPTY);
        assert_eq!(t.conns.len(), 1);
        // A reset of an unknown connection does not create one.
        let mut frame = Vec::new();
        etherparse::PacketBuilder::ethernet2([2; 6], [4; 6]).ipv4([10, 0, 9, 9], [10, 0, 0, 1], 64).tcp(9, 8080, 1, 1024).rst().write(&mut frame, b"").unwrap();
        t.packet(Linktype::ETHERNET, 2 + MAX_IDLE_EMPTY, &frame, &mut |_| {});
        assert_eq!(t.conns.len(), 1);
    }
}

/// The capture fixtures and synthetic captures, for tests here and in dependent crates
/// (which enable the `test-util` feature from their dev-dependencies).
#[cfg(any(test, feature = "test-util"))]
pub mod sample {
    use std::path::PathBuf;

    use serde_json::Value;

    use super::Micros;
    use crate::synth::{Endpoint, http, tcp_frame, write_pcap_header, write_pcap_record};

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

    /// A JSON file of the capture fixtures (a decoded inform or reply, the manifest).
    pub fn load(file: &str) -> Value {
        let dir = fixtures().expect("capture fixtures");
        let text = std::fs::read_to_string(dir.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}"))
    }

    /// The fixtures' `manifest.json`: the capture session's steps, each with the pushes
    /// it caused and, after the baselines, what each push changed (`expect`).
    pub fn manifest() -> Value {
        load("manifest.json")
    }

    /// How many pushes in the manifest carry an `expect` (all but the two baselines).
    pub const EXPECTED_PUSHES: usize = 22;

    /// Checks a diff against a manifest push's `expect`: either `counts` ([added,
    /// removed, changed]) or the keys `added`, `removed` and `changed`.
    pub fn check_expectation(ctx: &str, expect: &Value, d: &crate::cfgdiff::Diff) {
        if let Some(counts) = expect.get("counts") {
            let want: Vec<usize> = counts.as_array().unwrap().iter().map(|n| n.as_u64().unwrap() as usize).collect();
            assert_eq!(d.counts().to_vec(), want, "{ctx}: [added, removed, changed]");
            return;
        }
        let list = |name: &str| -> Vec<&str> { expect.get(name).and_then(Value::as_array).map(|a| a.iter().map(|s| s.as_str().unwrap()).collect()).unwrap_or_default() };
        let changed: Vec<&str> = d.changed.iter().map(|(k, ..)| *k).collect();
        let added: Vec<&str> = d.added.iter().map(|(k, _)| *k).collect();
        let removed: Vec<&str> = d.removed.iter().map(|(k, _)| *k).collect();
        assert_eq!(changed, list("changed"), "{ctx}: changed keys");
        assert_eq!(added, list("added"), "{ctx}: added keys");
        assert_eq!(removed, list("removed"), "{ctx}: removed keys");
    }

    /// The AP (10.0.0.5:40000) and the controller (10.0.0.1:8080) of the synthetic captures.
    pub fn endpoints() -> (Endpoint, Endpoint) {
        (Endpoint { mac: [2; 6], ip: [10, 0, 0, 5], port: 40000 }, Endpoint { mac: [4; 6], ip: [10, 0, 0, 1], port: 8080 })
    }

    /// A legacy pcap containing the given TCP segments as (to_server, seq, payload).
    pub fn pcap(segments: &[(bool, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        write_pcap_header(&mut out, 65535).unwrap();
        let (ap, ctrl) = endpoints();
        for (i, (to_server, seq, payload)) in segments.iter().enumerate() {
            let (src, dst) = if *to_server { (ap, ctrl) } else { (ctrl, ap) };
            let frame = tcp_frame(src, dst, *seq, payload).unwrap();
            write_pcap_record(&mut out, (1_791_840_600 + i as Micros) * 1_000_000, &frame).unwrap();
        }
        out
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

    /// One pcapng block: its body padded to four bytes between the two lengths.
    fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
        let padded = body.len().next_multiple_of(4);
        let len = (12 + padded) as u32;
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(body);
        out.resize(out.len() + padded - body.len(), 0);
        out.extend_from_slice(&len.to_le_bytes());
    }

    /// A little-endian pcapng section header.
    fn section(out: &mut Vec<u8>) {
        let mut shb = 0x1a2b3c4du32.to_le_bytes().to_vec();
        shb.extend_from_slice(&[1, 0, 0, 0]);
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        block(out, 0x0a0d0d0a, &shb);
    }

    /// An Ethernet interface (snaplen 256 KiB) with the given options as (code, value).
    fn interface(out: &mut Vec<u8>, options: &[(u16, &[u8])]) {
        let mut idb = vec![1, 0, 0, 0, 0, 0, 4, 0];
        for (code, value) in options {
            idb.extend_from_slice(&code.to_le_bytes());
            idb.extend_from_slice(&(value.len() as u16).to_le_bytes());
            idb.extend_from_slice(value);
            idb.resize(idb.len().next_multiple_of(4), 0);
        }
        if !options.is_empty() {
            idb.extend_from_slice(&[0; 4]);
        }
        block(out, 1, &idb);
    }

    /// An enhanced packet block on interface `if_id` with the raw timestamp `ts`.
    fn packet(out: &mut Vec<u8>, if_id: u32, ts: u64, frame: &[u8]) {
        let mut epb = if_id.to_le_bytes().to_vec();
        for v in [(ts >> 32) as u32, ts as u32, frame.len() as u32, frame.len() as u32] {
            epb.extend_from_slice(&v.to_le_bytes());
        }
        epb.extend_from_slice(frame);
        block(out, 6, &epb);
    }

    fn frame(to_server: bool, payload: &[u8]) -> Vec<u8> {
        let (ap, ctrl) = sample::endpoints();
        let (src, dst) = if to_server { (ap, ctrl) } else { (ctrl, ap) };
        crate::synth::tcp_frame(src, dst, 1, payload).unwrap()
    }

    #[test]
    fn simple_packet_blocks_take_the_last_timestamp() {
        let ts: Micros = 1_791_840_600_000_000;
        let mut data = Vec::new();
        section(&mut data);
        interface(&mut data, &[]);
        packet(&mut data, 0, ts as u64, &frame(true, &sample::http_request(b"Q")));
        let resp = frame(false, &sample::http_response(b"A"));
        let mut spb = (resp.len() as u32).to_le_bytes().to_vec();
        spb.extend_from_slice(&resp);
        block(&mut data, 3, &spb);
        let mut events = Vec::new();
        run(&data[..], &[8080], |e| events.push(e)).unwrap();
        assert!(matches!(&events[..], [HttpEvent::Request { ts: a, .. }, HttpEvent::Response { ts: b, .. }] if *a == ts && *b == ts), "{events:?}");
    }

    /// Before, such a packet was never consumed, and the reader spun on it for ever.
    #[test]
    fn a_packet_on_an_undescribed_interface_is_skipped() {
        let mut data = Vec::new();
        section(&mut data);
        interface(&mut data, &[]);
        packet(&mut data, 5, 0, &frame(true, &sample::http_request(b"lost")));
        packet(&mut data, 0, 1_791_840_600_000_000, &frame(true, &sample::http_request(b"Q")));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut events = Vec::new();
            let result = run(&data[..], &[8080], |e| events.push(e));
            tx.send((result.is_ok(), events)).ok();
        });
        let (ok, events) = rx.recv_timeout(std::time::Duration::from_secs(30)).expect("the reader moves on");
        assert!(ok && matches!(&events[..], [HttpEvent::Request { body, .. }] if body == b"Q"), "{events:?}");
    }

    #[test]
    fn pcapng_timestamps_follow_the_interface_resolution_and_offset() {
        // 2^20 units per second, and an offset that is negative.
        let mut data = Vec::new();
        section(&mut data);
        interface(&mut data, &[(9, &[0x80 | 20]), (14, &(-10i64).to_le_bytes())]);
        packet(&mut data, 0, (1_791_840_610 << 20) + (1 << 19), &frame(true, &sample::http_request(b"Q")));
        let mut events = Vec::new();
        run(&data[..], &[8080], |e| events.push(e)).unwrap();
        assert!(matches!(&events[..], [HttpEvent::Request { ts, .. }] if *ts == 1_791_840_600_500_000), "{events:?}");
        assert_eq!((ts_units(6), ts_units(9), ts_units(0x80 | 10), ts_units(0x80 | 64), ts_units(20)), (1_000_000, 1_000_000_000, 1024, 1_000_000, 1_000_000));
        // Picoseconds: the fraction does not fit 32 bits.
        let ts = 5_000_000_000_000 + 123_456_789_012u64;
        assert_eq!(epb_micros((ts >> 32) as u32, ts as u32, ts_units(12), 1_791_840_600), 1_791_840_605_123_456);
        assert_eq!(epb_micros(u32::MAX, u32::MAX, 1, i64::MAX), Micros::MAX, "clamped, not wrapped");
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
