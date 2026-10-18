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

use std::borrow::Cow;
use std::sync::{Arc, Weak};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, bail};
use inform::Mac;
use serde_json::Value;
use wire::cfgdiff::{At, SECRET_PARTS};
use wire::keys::KeyStore;

use crate::engine::LogLine;
use crate::model::Ts;

pub const MAGIC: [u8; 4] = [0xab, 0xcd, 0xdc, 0xba];

/// A key name and its separator: `key=`, `key: `, and JSON's `"key": `. An
/// ASCII word boundary: a Unicode one would keep the regex off its fast path
/// on a line with any non-ASCII text.
static KEY: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#"(?i)(?-u:\b)([a-z0-9_.]+)["']?\s*[:=]\s*"#).unwrap());

/// Text that may hold a secret's key: any with one of the parts every secret's
/// key holds, so most lines are stored without a search for keys. Built from
/// the list `is_secret` reads, so the two cannot drift apart. A key starts at
/// a word boundary (see [`KEY`]) and a segment after a dot, so the `x_` that
/// starts a segment follows one: `tx_bytes` is not let through.
static HINT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    let parts: Vec<String> = SECRET_PARTS
        .iter()
        .map(|&(at, p)| match at {
            At::SegmentStart => format!(r"\b{}", regex::escape(p)),
            At::Last | At::LastEnd | At::Anywhere => regex::escape(p),
        })
        .collect();
    regex::Regex::new(&format!("(?i-u){}", parts.join("|"))).unwrap()
});

/// APs log some secrets in clear text (e.g. `authkey: <hex>` when they save a
/// new management config). The values of keys named like a secret in a
/// config (`x_passphrase`, `wpa.psk`, `snmp.community`...) are masked before
/// storage; a quoted value is masked whole, its quotes kept. A line without
/// one is given back as it is.
pub fn redact(msg: &str) -> Cow<'_, str> {
    if !HINT.is_match(msg) {
        return Cow::Borrowed(msg);
    }
    let mut out = String::new();
    // How much of `msg` is copied to `out` or masked.
    let mut done = 0;
    // Only a secret's value is skipped: another key's may hold a secret's
    // key (`wifi1ap0: psk=x`), which the search then finds.
    for c in KEY.captures_iter(msg) {
        let (all, key) = (c.get(0).expect("the whole match"), &c[1]);
        if all.start() < done || !wire::cfgdiff::is_secret(key) {
            continue;
        }
        let (len, quote) = value(&msg[all.end()..]);
        if len == 0 {
            continue;
        }
        out.push_str(&msg[done..all.end()]);
        match quote {
            Some(q) => {
                out.push(q);
                out.push_str("<redacted>");
                out.push(q);
            }
            None => out.push_str("<redacted>"),
        }
        done = all.end() + len;
    }
    // Nothing was masked: a masked value ends past the line's start.
    if done == 0 {
        return Cow::Borrowed(msg);
    }
    out.push_str(&msg[done..]);
    Cow::Owned(out)
}

/// The length of the value `s` starts with, and its quote if it is quoted: a
/// quoted string whole (`"a b"`, `"a\"b"`, `'a b'`), else up to a space,
/// comma, semicolon or closing brace.
fn value(s: &str) -> (usize, Option<char>) {
    let b = s.as_bytes();
    if let Some(&q @ (b'"' | b'\'')) = b.first() {
        let mut i = 1;
        while i < b.len() {
            match b[i] {
                b'\\' if q == b'"' => i += 2,
                c if c == q => return (i + 1, Some(char::from(q))),
                _ => i += 1,
            }
        }
    }
    (s.find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '}')).unwrap_or(s.len()), None)
}

const HEADER: usize = 29;

/// The sender's `hash_id` of an encrypted datagram, as a number (shown as 16
/// hex characters, as the AP's informs carry it: see [`parse_hash_id`]).
pub fn hash_id(datagram: &[u8]) -> Option<u64> {
    (datagram.starts_with(&MAGIC) && datagram.len() >= 17).then(|| u64::from_be_bytes(datagram[9..17].try_into().expect("8 bytes")))
}

/// A `hash_id` as an AP's informs carry it, as [`hash_id`] reads it from the
/// AP's datagrams.
pub fn parse_hash_id(hex: &str) -> Option<u64> {
    let mut b = [0u8; 8];
    hex::decode_to_slice(hex, &mut b).ok()?;
    Some(u64::from_be_bytes(b))
}

/// Decrypts an encrypted datagram with `mac`'s cipher (see [`Ciphers`]).
pub fn decrypt_with(datagram: &[u8], mac: Mac, cipher: &Aes256Gcm) -> Result<String> {
    if !datagram.starts_with(&MAGIC) || datagram.len() < HEADER + 16 {
        bail!("not an encrypted syslog datagram ({} bytes)", datagram.len());
    }
    let plain = cipher
        .decrypt(&Nonce::try_from(&datagram[17..29]).expect("12 bytes"), Payload { msg: &datagram[HEADER..], aad: &datagram[..HEADER] })
        .map_err(|_| anyhow!("syslog decryption failed for {mac}"))?;
    // Valid UTF-8 (the usual case) is taken as it is, not copied.
    Ok(String::from_utf8(plain).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
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
pub fn parse(ts: Ts, src_ip: &str, device_mac: Option<Mac>, raw: &str) -> LogLine {
    let mut rest = raw.trim_end_matches(['\n', '\r', '\0']);
    let mut facility = None;
    let mut severity = None;
    // A priority is one to three digits up to 191 (facility 23, severity 7):
    // anything else (`<-1>`, `<+5>`, `<999>`) is text, not a kernel line.
    if let Some(stripped) = rest.strip_prefix('<')
        && let Some((pri, after)) = stripped.split_once('>')
            && (1..=3).contains(&pri.len()) && pri.bytes().all(|b| b.is_ascii_digit())
            && let Ok(p) = pri.parse::<u8>()
            && p <= 191 {
                facility = Some(i64::from(p / 8));
                severity = Some(i64::from(p % 8));
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
    LogLine { ts, device_mac, src_ip: src_ip.to_string(), facility, severity, program, msg: redact(rest.trim()).into_owned() }
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
        assert_eq!(hash_id(&dgram), parse_hash_id("0102030405060708"));
        assert_eq!(hash_id(&dgram).map(|h| format!("{h:016x}")).as_deref(), Some("0102030405060708"));
        assert_eq!((parse_hash_id("0102030405060708"), parse_hash_id("01020304050607"), parse_hash_id("010203040506070g")), (Some(0x0102030405060708), None, None));
        let text = decrypt_with(&dgram, mac, &Aes256Gcm::new(&key.into())).unwrap();
        assert!(text.starts_with("<14>hostapd"));
        assert!(decrypt_with(&dgram, mac, &Aes256Gcm::new(&[8u8; 32].into())).is_err(), "wrong key");
        assert!(decrypt_with(b"plain text", mac, &Aes256Gcm::new(&key.into())).is_err());
        assert_eq!(hash_id(b"plain text"), None);
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
    fn secrets_are_masked_in_every_form() {
        for (line, want) in [
            ("x_passphrase=hunter2, psk:abc; channel=36", "x_passphrase=<redacted>, psk:<redacted>; channel=36"),
            // JSON and other quoted keys, a quoted value whole.
            (r#"{"x_passphrase": "a b", "name": "Home"}"#, r#"{"x_passphrase": "<redacted>", "name": "Home"}"#),
            (r#"cfg {"psk":"x","channel":36}"#, r#"cfg {"psk":"<redacted>","channel":36}"#),
            (r#"{"psk":"a\"b c"} done"#, r#"{"psk":"<redacted>"} done"#),
            ("'wpa_psk': 'a b' ok", "'wpa_psk': '<redacted>' ok"),
            (r#"psk="a b" channel=36"#, r#"psk="<redacted>" channel=36"#),
            (r#"psk="unterminated value"#, "psk=<redacted> value"),
            (r#"{"radius_secret":12345}"#, r#"{"radius_secret":<redacted>}"#),
            // The names config diffs mask.
            ("aaa.1.wpa.psk=x snmp.community=public unifi.key=k iapp_key: 0f sae_password = y", "aaa.1.wpa.psk=<redacted> snmp.community=<redacted> unifi.key=<redacted> iapp_key: <redacted> sae_password = <redacted>"),
            ("Authkey: ABC", "Authkey: <redacted>"),
            // A secret's key in another key's value is still found.
            ("wifi1ap0: psk=abc", "wifi1ap0: psk=<redacted>"),
            ("cfg: authkey: 0123", "cfg: authkey: <redacted>"),
            // Not secrets.
            ("max_txpower=20 channel: 36 key_mgmt WPA-PSK", "max_txpower=20 channel: 36 key_mgmt WPA-PSK"),
            ("psk: ", "psk: "),
            // Non-ASCII text around them.
            ("Café « psk=hunter2 » ключ=1 x_passphrase: пароль ✓", "Café « psk=<redacted> » ключ=1 x_passphrase: <redacted> ✓"),
            ("naïve_psk=ü", "naïve_psk=<redacted>"),
        ] {
            assert_eq!(redact(line), want, "{line}");
        }
    }

    #[test]
    fn only_a_line_that_may_hold_a_secret_is_searched() {
        // Each part that makes a key secret, in a key `is_secret` takes, in
        // either case: the quick test must let every one through.
        for &(at, p) in &SECRET_PARTS {
            for part in [p.to_ascii_lowercase(), p.to_ascii_uppercase()] {
                let key = match at {
                    At::SegmentStart => format!("aaa.{part}y"),
                    At::Last => format!("aaa.{part}"),
                    At::LastEnd => format!("aaa.b{part}"),
                    At::Anywhere => format!("a{part}b"),
                };
                assert!(wire::cfgdiff::is_secret(&key), "{key}");
                for line in [format!("{key}=v"), format!("cfg: {key}: v"), format!(r#"{{"{key}": "v"}}"#)] {
                    assert!(HINT.is_match(&line), "{line}");
                    assert!(redact(&line).contains("<redacted>"), "{line}");
                }
            }
        }
        assert!(HINT.is_match("x_passphrase=1") && HINT.is_match("Café x_y=1"));
        // Lines without one are given back unsearched, and so are lines that
        // name a part but hold no secret.
        for line in ["wifi1ap0: STA 02:00:00:00:00:01 IEEE 802.11: associated", "max_txpower=20 tx_bytes=1 rx_x_y=2", "WPA: pairwise key handshake completed (RSN)", "psk: "] {
            assert!(matches!(redact(line), Cow::Borrowed(l) if l == line), "{line}");
        }
        assert!(!HINT.is_match("max_txpower=20 tx_bytes=1"));
    }

    #[test]
    fn parses_common_syslog_shapes() {
        let l = parse(1, "ip", None, "<30>Oct 12 19:45:01 U6-Mesh hostapd[123]: wifi1ap0: STA connected\n");
        assert_eq!((l.facility, l.severity), (Some(3), Some(6)));
        assert_eq!(l.program.as_deref(), Some("hostapd"));
        assert_eq!(l.msg, "wifi1ap0: STA connected");
        let l = parse(1, "ip", None, "<14>kernel: [12.3] something");
        assert_eq!(l.program.as_deref(), Some("kernel"));
        // The shape UniFi APs (U6-Mesh, 8.8.11) actually send.
        let l = parse(1, "ip", None, "<14>Oct 12 21:41:29 ap-name 020000000001,U6-Mesh-8.8.11+20161: mcad[3443]: wireless_agg_stats.log_sta_anomalies(): x");
        assert_eq!((l.facility, l.severity), (Some(1), Some(6)));
        assert_eq!(l.program.as_deref(), Some("mcad"));
        assert_eq!(l.msg, "wireless_agg_stats.log_sta_anomalies(): x");
        let l = parse(1, "ip", None, "<14>mcad: ace_reporter.reporter_save_config(): authkey: 0123456789abcdef0123456789abcdef");
        assert_eq!(l.msg, "ace_reporter.reporter_save_config(): authkey: <redacted>");
        assert_eq!(redact("x_passphrase=hunter2, psk:abc; channel=36"), "x_passphrase=<redacted>, psk:<redacted>; channel=36");
        // Only a real priority is read as one.
        for bad in ["<-1>kernel: x", "<+5>kernel: x", "<192>kernel: x", "<0000>kernel: x", "<>kernel: x", "<256>kernel: x"] {
            let l = parse(1, "ip", None, bad);
            assert_eq!((l.facility, l.severity), (None, None), "{bad}");
        }
        let l = parse(1, "ip", None, "<191>x");
        assert_eq!((l.facility, l.severity), (Some(23), Some(7)));
        let l = parse(1, "ip", None, "free text without a program");
        assert_eq!((l.program, l.msg.as_str()), (None, "free text without a program"));
    }
}
