//! Decrypting inform packets with the right key.

use anyhow::{Context, Result};
use inform::{DEFAULT_KEY, Flags, Mac, Packet};
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
    decode_packet(Packet::parse(body)?, keys, mac_hint)
}

/// [`decode`] for a packet already split.
pub fn decode_packet(pkt: Packet<'_>, keys: &KeyStore, mac_hint: Option<Mac>) -> Result<Decoded> {
    let flags = pkt.header.flags;
    let encrypted = flags.contains(Flags::ENCRYPTED);
    // An unencrypted packet needs no key; otherwise the device's (by the header's MAC,
    // then by the hint), then the default one.
    let hint = mac_hint.filter(|m| *m != pkt.header.mac);
    let device = [Some(pkt.header.mac), hint].into_iter().flatten().filter(|_| encrypted).flat_map(|mac| keys.device_keys(&mac));
    let last = (if encrypted { KeyUsed::Default } else { KeyUsed::None }, DEFAULT_KEY);
    let (key, _, payload) = open_with(&pkt, device.map(|k| (KeyUsed::Device, *k)).chain([last]))
        .with_context(|| format!("no known key decrypts the packet from {} (flags {:?})", pkt.header.mac, flags))?;
    Ok(Decoded { header: pkt.header, key, payload })
}

/// Opens a packet with each of `keys` in turn and parses the plaintext as JSON. The
/// first key that yields JSON wins: CBC has no authentication, so a wrong key shows up
/// as output that is not JSON rather than as an error. Returns that key with the
/// payload, or why no key worked: a failure after decryption (decompressing, the JSON)
/// rather than "wrong key", and for AES-GCM, which authenticates, the first key that
/// decrypted is the answer whatever comes after.
///
/// An unencrypted packet opens with any key (see [`Packet::open`]): callers that
/// require encryption check the header's flags first.
pub fn open_with(pkt: &Packet<'_>, keys: impl IntoIterator<Item = (KeyUsed, [u8; 16])>) -> Result<(KeyUsed, [u8; 16], Value)> {
    let flags = pkt.header.flags;
    // Whether getting past decryption proves the key right (or no key is involved).
    let authenticated = !flags.contains(Flags::ENCRYPTED) || flags.contains(Flags::GCM);
    let mut err = None;
    for (used, key) in keys {
        let e = match pkt.open(&key) {
            Ok(plain) => match serde_json::from_slice::<Value>(&plain) {
                Ok(payload) => return Ok((used, key, payload)),
                Err(e) => anyhow::anyhow!("decrypted payload is not JSON: {e}"),
            },
            Err(inform::Error::Decrypt) => {
                err.get_or_insert_with(|| inform::Error::Decrypt.into());
                continue;
            }
            Err(e) => e.into(),
        };
        if authenticated {
            return Err(e);
        }
        // CBC: a wrong key can get this far too; the first such failure is kept.
        if err.as_ref().is_none_or(|e: &anyhow::Error| matches!(e.downcast_ref(), Some(inform::Error::Decrypt))) {
            err = Some(e);
        }
    }
    Err(err.unwrap_or_else(|| anyhow::anyhow!("no key to try")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use inform::seal;

    #[test]
    fn decode_prefers_device_key_and_falls_back_to_default() {
        let mac: Mac = "00:11:22:33:44:55".parse().unwrap();
        let mut keys = KeyStore::default();
        keys.insert("00:11:22:33:44:55", "000102030405060708090a0b0c0d0e0f").unwrap();
        let device_key = *keys.get(&mac).unwrap();
        let flags = Flags::ENCRYPTED | Flags::GCM;

        let wire = seal(mac, flags, [1; 16], &device_key, br#"{"model":"U7PG2"}"#);
        let d = decode(&wire, &keys, None).unwrap();
        assert_eq!(d.key, KeyUsed::Device);
        assert_eq!(d.payload["model"], "U7PG2");

        let wire = seal(mac, Flags::ENCRYPTED, [2; 16], &DEFAULT_KEY, br#"{"default":true}"#);
        assert_eq!(decode(&wire, &keys, None).unwrap().key, KeyUsed::Default);

        let wire = seal(mac, flags, [3; 16], &[9; 16], b"{}");
        assert!(decode(&wire, &keys, None).is_err());
    }

    #[test]
    fn an_inform_under_the_key_the_device_has_yet_to_switch_from_decodes() {
        let mac: Mac = "00:11:22:33:44:55".parse().unwrap();
        let old = "0f0e0d0c0b0a09080706050403020100";
        let keys = KeyStore::from_value(&serde_json::json!({ "devices": [
            { "mac": "00:11:22:33:44:55", "x_authkey": "000102030405060708090a0b0c0d0e0f", "x_inform_authkey": old },
        ]}));
        let old = inform::parse_key(old).unwrap();
        for flags in [Flags::ENCRYPTED | Flags::GCM, Flags::ENCRYPTED | Flags::ZLIB] {
            let d = decode(&seal(mac, flags, [5; 16], &old, br#"{"a":1}"#), &keys, None).unwrap();
            assert_eq!((d.key, &d.payload["a"]), (KeyUsed::Device, &1.into()), "{flags:?}");
        }
    }

    #[test]
    fn open_with_takes_the_first_key_that_gives_json() {
        let mac: Mac = "00:11:22:33:44:55".parse().unwrap();
        // CBC: the wrong key "decrypts" too (or fails on the padding); only JSON counts.
        let wire = seal(mac, Flags::ENCRYPTED | Flags::ZLIB, [4; 16], &DEFAULT_KEY, br#"{"a":1}"#);
        let pkt = Packet::parse(&wire).unwrap();
        let (used, key, v) = open_with(&pkt, [(KeyUsed::Device, [7; 16]), (KeyUsed::Default, DEFAULT_KEY)]).unwrap();
        assert_eq!((used, key, v["a"].as_i64()), (KeyUsed::Default, DEFAULT_KEY, Some(1)));
        assert!(open_with(&pkt, [(KeyUsed::Device, [7; 16])]).is_err());
        assert!(open_with(&pkt, []).unwrap_err().to_string().contains("no key"));
    }

    #[test]
    fn open_with_reports_what_failed_after_decryption() {
        let mac: Mac = "00:11:22:33:44:55".parse().unwrap();
        let keys = [(KeyUsed::Device, [7; 16]), (KeyUsed::Default, DEFAULT_KEY)];
        // AES-GCM authenticated the device key: its failure is the answer, not the default key's.
        let wire = seal(mac, Flags::ENCRYPTED | Flags::GCM, [5; 16], &[7; 16], b"not json");
        let err = open_with(&Packet::parse(&wire).unwrap(), keys).unwrap_err().to_string();
        assert!(err.contains("not JSON"), "{err}");
        // No key decrypts: that is what is reported.
        let wire = seal(mac, Flags::ENCRYPTED | Flags::GCM, [6; 16], &[8; 16], b"{}");
        let err = open_with(&Packet::parse(&wire).unwrap(), keys).unwrap_err().to_string();
        assert!(err.contains("wrong key"), "{err}");
    }
}
