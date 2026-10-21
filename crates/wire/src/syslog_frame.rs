//! The encrypted syslog datagram an AP with a `syslog_key` sends: a header of
//! [`HEADER`] bytes (the [`MAGIC`], 0x01, 1 as a big-endian u32, the AP's
//! [`HASH_ID`], the [`NONCE`]), then the text sealed with AES-256-GCM over that
//! header, ending in a [`TAG`]-byte tag. The controller's syslog listener and
//! informdump's demo site both read and write it through here.

use std::ops::Range;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};

/// The first bytes of an encrypted syslog datagram.
pub const MAGIC: [u8; 4] = [0xab, 0xcd, 0xdc, 0xba];
/// Where the sending AP's `hash_id` (as its informs carry it) is.
pub const HASH_ID: Range<usize> = 9..17;
/// Where the AES-GCM nonce is: the header's last bytes.
pub const NONCE: Range<usize> = 17..29;
/// The length of the header, which is also the additional authenticated data.
pub const HEADER: usize = NONCE.end;
/// The length of the AES-GCM tag after the text.
pub const TAG: usize = 16;

/// Whether `datagram` is long enough to be a sealed one and starts with the [`MAGIC`].
pub fn is_sealed(datagram: &[u8]) -> bool {
    datagram.starts_with(&MAGIC) && datagram.len() >= HEADER + TAG
}

/// The sender's `hash_id` of a sealed datagram.
pub fn hash_id(datagram: &[u8]) -> Option<[u8; 8]> {
    is_sealed(datagram).then(|| datagram[HASH_ID].try_into().expect("8 bytes"))
}

/// A datagram as an AP with this `syslog_key` sends it.
pub fn seal(hash_id: [u8; 8], key: &[u8; 32], nonce: [u8; 12], text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + text.len() + TAG);
    out.extend_from_slice(&MAGIC);
    out.push(1);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&hash_id);
    out.extend_from_slice(&nonce);
    debug_assert_eq!(out.len(), HEADER);
    let sealed = Aes256Gcm::new(key.into()).encrypt(&nonce.into(), Payload { msg: text.as_bytes(), aad: &out }).expect("AES-GCM sealing");
    out.extend(sealed);
    out
}

/// The text of a sealed datagram, or `None` when it is not one or `cipher` (the
/// sender's key) does not open it.
pub fn open(cipher: &Aes256Gcm, datagram: &[u8]) -> Option<Vec<u8>> {
    if !is_sealed(datagram) {
        return None;
    }
    let nonce = datagram[NONCE].try_into().expect("12 bytes");
    cipher.decrypt(nonce, Payload { msg: &datagram[HEADER..], aad: &datagram[..HEADER] }).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_datagram_starts_with_its_header_and_opens_with_its_key() {
        let d = seal([1; 8], &[2; 32], [3; 12], "hi");
        assert_eq!(d[..HASH_ID.end], [0xab, 0xcd, 0xdc, 0xba, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        assert_eq!((&d[NONCE], d.len(), hash_id(&d)), (&[3; 12][..], HEADER + 2 + TAG, Some([1; 8])));
        assert_eq!(open(&Aes256Gcm::new(&[2; 32].into()), &d).as_deref(), Some(&b"hi"[..]));
        assert_eq!(open(&Aes256Gcm::new(&[4; 32].into()), &d), None, "another key");
        assert_eq!((open(&Aes256Gcm::new(&[2; 32].into()), &d[..HEADER + TAG - 1]), hash_id(&d[..HEADER + TAG - 1])), (None, None), "too short");
        assert!(is_sealed(&d[..HEADER + TAG]) && !is_sealed(b"<14>plain text, long enough to hold a header"));
    }
}
