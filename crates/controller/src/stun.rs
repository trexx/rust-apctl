//! The STUN service APs are given in `mgmt_cfg` (`stun_url`), and the
//! "connection request" that makes an AP inform right away.
//!
//! As the official controller does it: a classic (RFC 3489) Binding Response
//! to each Binding Request, with MAPPED-ADDRESS (where the request came from)
//! and SOURCE-/CHANGED-ADDRESS (this server). An AP that learned its address
//! this way reports `connect_request_ip`/`connect_request_port`; a 20-byte
//! packet starting 0x8888, sent from the STUN socket to that address, makes it
//! inform at once instead of at its next interval (used when a command or new
//! config is waiting).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use inform::Mac;
use tokio::net::UdpSocket;

use crate::engine::{Live, SharedLive};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const SOURCE_ADDRESS: u16 = 0x0004;
const CHANGED_ADDRESS: u16 = 0x0005;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// An address attribute: family 1 (IPv4) or 2 (IPv6, as RFC 5389 has it; an
/// IPv4 peer on a dual-stack socket is written as IPv4). `xor`: the 16 bytes
/// after the type and length (magic cookie and transaction ID) to mask it with.
fn address(out: &mut Vec<u8>, kind: u16, addr: SocketAddr, xor: Option<&[u8]>) {
    let mut port = addr.port();
    let (family, mut ip): (u8, Vec<u8>) = match addr.ip().to_canonical() {
        IpAddr::V4(ip) => (1, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2, ip.octets().to_vec()),
    };
    if let Some(mask) = xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        ip.iter_mut().zip(mask).for_each(|(b, m)| *b ^= m);
    }
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(4 + ip.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, family]);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&ip);
}

/// The answer to a STUN packet from `from`, if it is a Binding Request.
/// `local` is this server's address as the AP sees it.
fn answer(req: &[u8], from: SocketAddr, local: SocketAddr) -> Option<Vec<u8>> {
    if req.len() < 20 || u16::from_be_bytes([req[0], req[1]]) != BINDING_REQUEST {
        return None;
    }
    let len = u16::from_be_bytes([req[2], req[3]]) as usize;
    if req.len() < 20 + len {
        return None;
    }
    // Bytes 4-19: the transaction ID (RFC 5389 clients start it with the magic cookie).
    let modern = u32::from_be_bytes([req[4], req[5], req[6], req[7]]) == MAGIC_COOKIE;
    let mut attrs = Vec::new();
    address(&mut attrs, MAPPED_ADDRESS, from, None);
    address(&mut attrs, SOURCE_ADDRESS, local, None);
    address(&mut attrs, CHANGED_ADDRESS, local, None);
    if modern {
        address(&mut attrs, XOR_MAPPED_ADDRESS, from, Some(&req[4..20]));
    }
    let mut out = Vec::with_capacity(20 + attrs.len());
    out.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    out.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    out.extend_from_slice(&req[4..20]);
    out.extend_from_slice(&attrs);
    Some(out)
}

/// Serves STUN on `listen`; `advertised` is the address put in the answers
/// when the socket is bound to all interfaces. The socket goes in `live`,
/// for [`poke`].
pub async fn serve(listen: SocketAddr, advertised: Option<IpAddr>, live: &SharedLive) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(listen).await?);
    live.write().unwrap().stun = Some(socket.clone());
    let mut local = socket.local_addr()?;
    if local.ip().is_unspecified()
        && let Some(ip) = advertised
    {
        local.set_ip(ip);
    }
    tracing::info!("STUN on udp {listen}");
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    // E.g. an ICMP error reported for an earlier reply: not worth a busy loop.
                    tracing::debug!("STUN: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            if let Some(reply) = answer(&buf[..n], from, local) {
                let _ = socket.send_to(&reply, from).await;
            }
        }
    });
    Ok(())
}

/// The connection request packet.
const REQUEST_PACKET: [u8; 20] = {
    let mut p = [0u8; 20];
    p[0] = 0x88;
    p[1] = 0x88;
    p
};

/// Asks an AP to inform now, if it told us where it can be reached.
pub fn poke(live: &Live, mac: &Mac) {
    let Some(socket) = &live.stun else { return };
    let Some(p) = live.raw_informs.get(mac) else { return };
    let ip = p["connect_request_ip"].as_str().and_then(|i| i.parse::<IpAddr>().ok());
    let port = p["connect_request_port"].as_u64().or_else(|| p["connect_request_port"].as_str()?.parse().ok()).and_then(|v| u16::try_from(v).ok());
    if let (Some(ip), Some(port)) = (ip, port) {
        let _ = socket.try_send_to(&REQUEST_PACKET, SocketAddr::new(ip, port));
    }
}

/// Asks every AP to inform now (after a settings change).
pub fn poke_all(live: &Live) {
    for mac in live.devices.keys() {
        poke(live, mac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_classic_binding_requests() {
        let mut req = vec![0x00, 0x01, 0x00, 0x08];
        req.extend_from_slice(&[7; 16]);
        // CHANGE-REQUEST, as the APs send it.
        req.extend_from_slice(&[0x00, 0x03, 0x00, 0x04, 0, 0, 0, 0]);
        let from: SocketAddr = "192.0.2.9:40000".parse().unwrap();
        let local: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let r = answer(&req, from, local).unwrap();
        assert_eq!(&r[0..2], &[0x01, 0x01]);
        assert_eq!(&r[4..20], &[7; 16], "same transaction ID");
        assert_eq!(u16::from_be_bytes([r[2], r[3]]) as usize, r.len() - 20);
        // MAPPED-ADDRESS: family 1, port 40000, 192.0.2.9.
        assert_eq!(&r[20..32], &[0x00, 0x01, 0x00, 0x08, 0, 1, 0x9c, 0x40, 192, 0, 2, 9]);
        assert_eq!(r.len(), 20 + 3 * 12, "no XOR-MAPPED-ADDRESS for a classic request");
        assert!(answer(&[0x01, 0x01, 0, 0], from, local).is_none());
    }

    #[test]
    fn modern_requests_also_get_the_xor_address() {
        let mut req = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
        req.extend_from_slice(&[1; 12]);
        let r = answer(&req, "192.0.2.9:40000".parse().unwrap(), "192.0.2.1:3478".parse().unwrap()).unwrap();
        assert_eq!(r.len(), 20 + 4 * 12);
        // XOR-MAPPED-ADDRESS port: 40000 ^ 0x2112.
        assert_eq!(&r[56..58], &[0x00, 0x20]);
        assert_eq!(&r[62..64], &(40000u16 ^ 0x2112).to_be_bytes());
        assert_eq!(&r[64..68], &[192 ^ 0x21, 0x12, 2 ^ 0xA4, 9 ^ 0x42]);
        assert_eq!(&REQUEST_PACKET[..4], &[0x88, 0x88, 0, 0]);
    }

    #[test]
    fn ipv6_peers_get_their_address() {
        let local: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let mut req = vec![0x00, 0x01, 0x00, 0x00];
        req.extend_from_slice(&[7; 16]);
        // An IPv4 peer seen through a dual-stack socket is an IPv4 address.
        let r = answer(&req, "[::ffff:192.0.2.9]:40000".parse().unwrap(), local).unwrap();
        assert_eq!(&r[20..32], &[0x00, 0x01, 0x00, 0x08, 0, 1, 0x9c, 0x40, 192, 0, 2, 9]);
        // A real IPv6 peer: family 2, 16 bytes.
        let r = answer(&req, "[2001:db8::9]:40000".parse().unwrap(), local).unwrap();
        assert_eq!(&r[20..28], &[0x00, 0x01, 0x00, 0x14, 0, 2, 0x9c, 0x40]);
        assert_eq!(&r[28..44], &"2001:db8::9".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(u16::from_be_bytes([r[2], r[3]]) as usize, r.len() - 20);
    }
}
