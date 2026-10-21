//! Writing captures: the legacy pcap framing, Ethernet frames and HTTP/1.1 messages,
//! for informdump's made-up demo site and for tests (the syslog datagrams they carry
//! are [`crate::syslog_frame`]'s).

use std::io::{self, Write};

use etherparse::PacketBuilder;

use crate::capture::Micros;

/// One end of a made-up IPv4 conversation.
#[derive(Clone, Copy, Debug)]
pub struct Endpoint {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub port: u16,
}

/// An Ethernet frame holding one IPv4 TCP segment from `src` to `dst` (TTL 64, a full
/// window, no flags).
pub fn tcp_frame(src: Endpoint, dst: Endpoint, seq: u32, payload: &[u8]) -> io::Result<Vec<u8>> {
    let builder = PacketBuilder::ethernet2(src.mac, dst.mac).ipv4(src.ip, dst.ip, 64).tcp(src.port, dst.port, seq, 65_535);
    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut frame, payload).map_err(io::Error::other)?;
    Ok(frame)
}

/// An Ethernet frame holding one IPv4 UDP datagram from `src` to `dst` (TTL 64).
pub fn udp_frame(src: Endpoint, dst: Endpoint, payload: &[u8]) -> io::Result<Vec<u8>> {
    let builder = PacketBuilder::ethernet2(src.mac, dst.mac).ipv4(src.ip, dst.ip, 64).udp(src.port, dst.port);
    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut frame, payload).map_err(io::Error::other)?;
    Ok(frame)
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

/// An HTTP/1.1 message: `head` is the start line and headers, each ending in CRLF;
/// the Content-Length and the blank line are added.
pub fn http(head: &str, body: &[u8]) -> Vec<u8> {
    let mut m = format!("{head}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    m.extend_from_slice(body);
    m
}
