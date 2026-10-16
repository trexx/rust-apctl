//! AP remote syslog on UDP 5514.
//!
//! Adopted APs send each message as its own datagram, either plain text or
//! encrypted:
//!
//! ```text
//! offset size
//!      0    4  magic 0xABCDDCBA
//!      4    1  0x01
//!      5    4  1 (u32 BE)
//!      9    8  device hash_id (the 16-hex `hash_id` from its informs, raw)
//!     17   12  AES-GCM nonce
//!     29    n  AES-256-GCM ciphertext + 16-byte tag; AAD = bytes 0..29
//! ```
//!
//! The key is the device's 64-hex `syslog_key`.

use std::sync::{Arc, Weak};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, bail};
use inform::Mac;
use serde_json::Value;
use wire::keys::KeyStore;

use crate::engine::LogLine;
use crate::model::Ts;

pub const MAGIC: [u8; 4] = [0xab, 0xcd, 0xdc, 0xba];

/// APs log some secrets in clear text (e.g. `authkey: <hex>` when they save a
/// new management config). Values after these names are masked before storage.
static SECRET: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    // Any key name ending in one of these words, e.g. `x_passphrase`, `wpa_psk`.
    regex::Regex::new(r"(?i)\b([a-z_]*(?:authkey|syslog_key|vwirekey|psk|passphrase|password|passwd|secret|iapp_key))(\s*[:=]\s*)([^\s,;]+)").unwrap()
});

pub fn redact(msg: &str) -> String {
    SECRET.replace_all(msg, "${1}${2}<redacted>").into_owned()
}
const HEADER: usize = 29;

/// The sender's `hash_id` (16 hex characters) of an encrypted datagram.
pub fn hash_id(datagram: &[u8]) -> Option<String> {
    (datagram.starts_with(&MAGIC) && datagram.len() >= 17).then(|| hex::encode(&datagram[9..17]))
}

/// Decrypts or passes through one datagram. `lookup` maps a hash_id to the
/// device and its syslog key.
pub fn open(datagram: &[u8], lookup: impl Fn(&str) -> Option<(Mac, [u8; 32])>) -> Result<(Option<Mac>, String)> {
    if !datagram.starts_with(&MAGIC) {
        return Ok((None, String::from_utf8_lossy(datagram).into_owned()));
    }
    if datagram.len() < HEADER + 16 {
        bail!("encrypted syslog datagram too short ({} bytes)", datagram.len());
    }
    let hash_id = hex::encode(&datagram[9..17]);
    let (mac, key) = lookup(&hash_id).ok_or_else(|| anyhow!("no syslog key for hash_id {hash_id}"))?;
    Ok((Some(mac), decrypt(datagram, mac, &key)?))
}

/// Decrypts an encrypted datagram with `mac`'s syslog key.
pub fn decrypt(datagram: &[u8], mac: Mac, key: &[u8; 32]) -> Result<String> {
    decrypt_with(datagram, mac, &Aes256Gcm::new(key.into()))
}

/// Decrypts an encrypted datagram with `mac`'s cipher (see [`Ciphers`]).
pub fn decrypt_with(datagram: &[u8], mac: Mac, cipher: &Aes256Gcm) -> Result<String> {
    if !datagram.starts_with(&MAGIC) || datagram.len() < HEADER + 16 {
        bail!("not an encrypted syslog datagram ({} bytes)", datagram.len());
    }
    let plain = cipher
        .decrypt(&Nonce::try_from(&datagram[17..29]).expect("12 bytes"), Payload { msg: &datagram[HEADER..], aad: &datagram[..HEADER] })
        .map_err(|_| anyhow!("syslog decryption failed for {mac}"))?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

/// The ciphers of every syslog key known (`adopt::syslog_keys`: the settings'
/// before the key file's), set up once per version of the settings rather
/// than for each datagram.
#[derive(Default)]
pub struct Ciphers {
    /// The settings they were made from, once made. Compared by address: the
    /// Weak keeps that address from being reused without keeping the settings.
    from: Option<Option<Weak<Value>>>,
    keys: Vec<(Mac, Aes256Gcm)>,
}

impl Ciphers {
    /// Makes the ciphers again if the settings changed since the last call.
    pub fn refresh(&mut self, state: Option<&Arc<Value>>, keys: &KeyStore) {
        let same = match (&self.from, state) {
            (Some(None), None) => true,
            (Some(Some(w)), Some(s)) => std::ptr::eq(w.as_ptr(), Arc::as_ptr(s)),
            _ => false,
        };
        if !same {
            self.from = Some(state.map(Arc::downgrade));
            self.keys = crate::adopt::syslog_keys(state.map(|s| &**s), keys).into_iter().map(|(m, k)| (m, Aes256Gcm::new(&k.into()))).collect();
        }
    }

    /// The AP's cipher: its record's key, else the key file's.
    pub fn get(&self, mac: &Mac) -> Option<&Aes256Gcm> {
        self.keys.iter().find(|(m, _)| m == mac).map(|(_, c)| c)
    }

    /// Every key, to find whose a datagram is.
    pub fn all(&self) -> impl Iterator<Item = (Mac, &Aes256Gcm)> {
        self.keys.iter().map(|(m, c)| (*m, c))
    }
}

/// Splits a syslog message into priority, program and text. Handles
/// `<PRI>` prefixes and BSD-style `Mon dd hh:mm:ss host prog[pid]: msg`
/// headers, and falls back to the raw text.
pub fn parse(ts: Ts, src_ip: String, device_mac: Option<Mac>, raw: &str) -> LogLine {
    let mut rest = raw.trim_end_matches(['\n', '\r', '\0']);
    let mut facility = None;
    let mut severity = None;
    if let Some(stripped) = rest.strip_prefix('<')
        && let Some((pri, after)) = stripped.split_once('>')
            && let Ok(p) = pri.parse::<i64>() {
                facility = Some(p / 8);
                severity = Some(p % 8);
                rest = after;
            }
    // Optional BSD timestamp ("Oct 12 19:45:01 ") and hostname.
    let bytes = rest.as_bytes();
    if bytes.len() > 16 && bytes[3] == b' ' && bytes[6] == b' ' && bytes[9] == b':' && bytes[12] == b':' && bytes[15] == b' ' {
        rest = &rest[16..];
        // The next token is the hostname unless it already looks like `prog:`.
        if let Some((first, after)) = rest.split_once(' ')
            && !first.ends_with(':') && !first.contains('[') {
                rest = after;
            }
    }
    // UniFi APs add a device tag after the hostname: `<mac>,<model>-<version>:`.
    if let Some((tag, after)) = rest.split_once(": ") {
        let is_device_tag = tag
            .split_once(',')
            .is_some_and(|(m, _)| m.len() == 12 && m.bytes().all(|b| b.is_ascii_hexdigit()));
        if is_device_tag && !tag.contains(' ') {
            rest = after;
        }
    }
    let mut program = None;
    if let Some((head, msg)) = rest.split_once(": ")
        && !head.contains(' ') && !head.is_empty() && head.len() < 64 {
            program = Some(head.split('[').next().unwrap_or(head).to_string());
            rest = msg;
        }
    LogLine { ts, device_mac, src_ip, facility, severity, program, msg: redact(rest.trim()) }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn seal(hash_id: [u8; 8], key: [u8; 32], text: &str) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&MAGIC);
        header.push(1);
        header.extend_from_slice(&1u32.to_be_bytes());
        header.extend_from_slice(&hash_id);
        let nonce = Nonce::try_from(&[9u8; 12][..]).unwrap();
        header.extend_from_slice(&nonce);
        let ct = Aes256Gcm::new(&key.into()).encrypt(&nonce, Payload { msg: text.as_bytes(), aad: &header }).unwrap();
        header.extend_from_slice(&ct);
        header
    }

    #[test]
    fn decrypts_encrypted_datagrams() {
        let mac: Mac = "02:00:00:00:00:01".parse().unwrap();
        let key = [7u8; 32];
        let dgram = seal([1, 2, 3, 4, 5, 6, 7, 8], key, "<14>hostapd: wifi1ap0: STA aa:bb AUTHENTICATED");
        let lookup = |h: &str| (h == "0102030405060708").then_some((mac, key));
        let (m, text) = open(&dgram, lookup).unwrap();
        assert_eq!(m, Some(mac));
        assert!(text.starts_with("<14>hostapd"));
        assert!(open(&dgram, |_| Some((mac, [8u8; 32]))).is_err(), "wrong key");
        assert!(open(&dgram, |_| None).is_err(), "unknown device");
        assert_eq!(open(b"plain text", lookup).unwrap(), (None, "plain text".to_string()));
    }

    #[test]
    fn ciphers_follow_the_settings_without_keeping_them() {
        let ap: Mac = "02:00:00:00:00:02".parse().unwrap();
        let mut keys = KeyStore::default();
        keys.insert_syslog("02:00:00:00:00:01", &hex::encode([1u8; 32])).unwrap();
        let mut c = Ciphers::default();
        c.refresh(None, &keys);
        assert_eq!(c.all().count(), 1, "the key file's");
        let state = Arc::new(serde_json::json!({ "devices": [{ "mac": "02:00:00:00:00:02", "syslog_key": hex::encode([5u8; 32]) }] }));
        c.refresh(Some(&state), &keys);
        let dgram = tests::seal([3; 8], [5; 32], "<14>hostapd: hello");
        assert!(decrypt_with(&dgram, ap, c.get(&ap).unwrap()).is_ok());
        assert_eq!(Arc::strong_count(&state), 1, "the settings are not held");
        // Another version of the settings, even an equal one, is read again.
        let other = Arc::new(serde_json::json!({ "devices": [] }));
        c.refresh(Some(&other), &keys);
        assert!(c.get(&ap).is_none());
    }

    #[test]
    fn parses_common_syslog_shapes() {
        let l = parse(1, "ip".into(), None, "<30>Oct 12 19:45:01 U6-Mesh hostapd[123]: wifi1ap0: STA connected\n");
        assert_eq!((l.facility, l.severity), (Some(3), Some(6)));
        assert_eq!(l.program.as_deref(), Some("hostapd"));
        assert_eq!(l.msg, "wifi1ap0: STA connected");
        let l = parse(1, "ip".into(), None, "<14>kernel: [12.3] something");
        assert_eq!(l.program.as_deref(), Some("kernel"));
        // The shape UniFi APs (U6-Mesh, 8.8.11) actually send.
        let l = parse(1, "ip".into(), None, "<14>Oct 12 21:41:29 ap-name 020000000001,U6-Mesh-8.8.11+20161: mcad[3443]: wireless_agg_stats.log_sta_anomalies(): x");
        assert_eq!((l.facility, l.severity), (Some(1), Some(6)));
        assert_eq!(l.program.as_deref(), Some("mcad"));
        assert_eq!(l.msg, "wireless_agg_stats.log_sta_anomalies(): x");
        let l = parse(1, "ip".into(), None, "<14>mcad: ace_reporter.reporter_save_config(): authkey: 0123456789abcdef0123456789abcdef");
        assert_eq!(l.msg, "ace_reporter.reporter_save_config(): authkey: <redacted>");
        assert_eq!(redact("x_passphrase=hunter2, psk:abc; channel=36"), "x_passphrase=<redacted>, psk:<redacted>; channel=36");
        let l = parse(1, "ip".into(), None, "free text without a program");
        assert_eq!((l.program, l.msg.as_str()), (None, "free text without a program"));
    }
}
