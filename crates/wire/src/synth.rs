//! Writing captures: the legacy pcap framing and HTTP/1.1 messages, for informdump's
//! made-up demo site and for tests.

use std::io::{self, Write};

use crate::capture::Micros;

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
