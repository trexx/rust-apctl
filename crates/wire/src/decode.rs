//! Decrypting inform packets with the right key.

use anyhow::Result;
use inform::{DEFAULT_KEY, Mac, Packet};
use serde_json::Value;

use crate::keys::KeyStore;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyUsed {
    None,
    Device,
    Default,
}

#[derive(Debug)]
pub struct Decoded {
    pub header: inform::Header,
    pub key: KeyUsed,
    pub payload: Value,
}

/// Decrypts a packet, trying the device's key first and then the factory default key.
pub fn decode(body: &[u8], keys: &KeyStore, mac_hint: Option<Mac>) -> Result<Decoded> {
    let pkt = Packet::parse(body)?;
    let flags = pkt.header.flags;
    let mut attempts: Vec<(KeyUsed, &[u8; 16])> = Vec::new();
    if !flags.has(inform::Flags::ENCRYPTED) {
        attempts.push((KeyUsed::None, &DEFAULT_KEY));
    } else {
        let hint = mac_hint.filter(|m| *m != pkt.header.mac);
        for mac in [Some(pkt.header.mac), hint].into_iter().flatten() {
            if let Some(k) = keys.get(&mac) {
                attempts.push((KeyUsed::Device, k));
            }
        }
        attempts.push((KeyUsed::Default, &DEFAULT_KEY));
    }

    let mut last_err = None;
    for (used, key) in attempts {
        match pkt.open(key) {
            Ok(plain) => {
                // CBC has no authentication, so a wrong key shows up as non-JSON output.
                match serde_json::from_slice::<Value>(&plain) {
                    Ok(payload) => return Ok(Decoded { header: pkt.header.clone(), key: used, payload }),
                    Err(e) => last_err = Some(anyhow::anyhow!("decrypted payload is not JSON: {e}")),
                }
            }
            Err(e) => last_err = Some(e.into()),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no key to try"))
        .context(format!("no known key decrypts the packet from {} (flags {:?})", pkt.header.mac, flags)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use inform::{Flags, seal};

    #[test]
    fn decode_prefers_device_key_and_falls_back_to_default() {
        let mac: Mac = "00:11:22:33:44:55".parse().unwrap();
        let mut keys = KeyStore::default();
        keys.insert("00:11:22:33:44:55", "000102030405060708090a0b0c0d0e0f").unwrap();
        let device_key = *keys.get(&mac).unwrap();
        let flags = Flags(Flags::ENCRYPTED | Flags::GCM);

        let wire = seal(mac, flags, [1; 16], &device_key, br#"{"model":"U7PG2"}"#);
        let d = decode(&wire, &keys, None).unwrap();
        assert_eq!(d.key, KeyUsed::Device);
        assert_eq!(d.payload["model"], "U7PG2");

        let wire = seal(mac, Flags(Flags::ENCRYPTED), [2; 16], &DEFAULT_KEY, br#"{"default":true}"#);
        assert_eq!(decode(&wire, &keys, None).unwrap().key, KeyUsed::Default);

        let wire = seal(mac, flags, [3; 16], &[9; 16], b"{}");
        assert!(decode(&wire, &keys, None).is_err());
    }
}
