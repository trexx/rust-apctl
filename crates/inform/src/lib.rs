//! Codec for the inform protocol spoken between access points and their controller.
//!
//! An inform is an HTTP POST to `/inform` whose body is a binary packet:
//!
//! ```text
//! offset size  field
//!      0    4  magic "TNBU"
//!      4    4  packet version (u32 BE, 0)
//!      8    6  device MAC
//!     14    2  flags (u16 BE, see [`Flags`])
//!     16   16  IV / nonce
//!     32    4  payload version (u32 BE, 1)
//!     36    4  payload length (u32 BE)
//!     40    n  payload
//! ```
//!
//! The payload is JSON that may be compressed (zlib or snappy) and then
//! encrypted with AES-128, either CBC with PKCS#7 padding or GCM with a
//! 16-byte nonce and the 40-byte header as associated data. The controller's
//! reply uses the same framing.

use std::borrow::Cow;
use std::fmt;
use std::io::Read;

use aes::Aes128;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::aead::{Aead, AeadInOut, KeyInit, Payload};
use aes_gcm::aead::consts::U16;
use aes_gcm::AesGcm;

pub const MAGIC: &[u8; 4] = b"TNBU";
const HEADER_LEN: usize = 40;
/// Largest payload accepted after decompression. Real informs are tens to a few
/// hundred KB; the cap stops a small compressed body from inflating to gigabytes.
const MAX_PLAINTEXT: usize = 8 << 20;

/// Key used by devices that have not been adopted yet (MD5 of "ubnt").
pub const DEFAULT_KEY: [u8; 16] = [
    0xba, 0x86, 0xf2, 0xbb, 0xe1, 0x07, 0xc7, 0xc5, 0x7e, 0xb5, 0xf2, 0x69, 0x07, 0x75, 0xc7, 0x12,
];

type Aes128Gcm16 = AesGcm<Aes128, U16>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("packet too short ({0} bytes)")]
    TooShort(usize),
    #[error("bad magic {0:02x?}")]
    BadMagic([u8; 4]),
    #[error("payload length {declared} is more than the {actual} bytes present")]
    Truncated { declared: usize, actual: usize },
    #[error("decryption failed (wrong key?)")]
    Decrypt,
    #[error("decompression failed: {0}")]
    Decompress(String),
    #[error("invalid key: not hex")]
    KeyNotHex(#[source] hex::FromHexError),
    #[error("invalid key: {got} bytes, expected {expected}")]
    KeyLength { expected: usize, got: usize },
    #[error("invalid MAC address {0:?}")]
    InvalidMac(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Mac(pub [u8; 6]);

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::str::FromStr for Mac {
    type Err = Error;

    /// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-...` (one separator throughout) or
    /// `aabbccddeeff`, any case.
    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        let mut hex = [0u8; 12];
        match b.len() {
            12 => hex.copy_from_slice(b),
            17 if matches!(b[2], b':' | b'-') && (2..17).step_by(3).all(|i| b[i] == b[2]) => {
                for (i, pair) in b.chunks(3).enumerate() {
                    hex[2 * i..2 * i + 2].copy_from_slice(&pair[..2]);
                }
            }
            _ => return Err(Error::InvalidMac(s.to_string())),
        }
        let mut mac = [0u8; 6];
        hex::decode_to_slice(hex, &mut mac).map_err(|_| Error::InvalidMac(s.to_string()))?;
        Ok(Mac(mac))
    }
}

/// Serialised as the `aa:bb:cc:dd:ee:ff` string form.
impl serde::Serialize for Mac {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Read from any of the string forms [`FromStr`](std::str::FromStr) accepts, borrowed or
/// not, without copying it.
impl<'de> serde::Deserialize<'de> for Mac {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct MacVisitor;
        impl serde::de::Visitor<'_> for MacVisitor {
            type Value = Mac;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a MAC address")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<Mac, E> {
                s.parse().map_err(E::custom)
            }
        }
        d.deserialize_str(MacVisitor)
    }
}

/// The header's flag bits; `.0` is the value on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u16);

impl Flags {
    /// No bit set: a plain, uncompressed payload.
    pub const NONE: Flags = Flags(0);
    pub const ENCRYPTED: Flags = Flags(0x01);
    pub const ZLIB: Flags = Flags(0x02);
    pub const SNAPPY: Flags = Flags(0x04);
    pub const GCM: Flags = Flags(0x08);

    /// Whether every bit of `other` is set.
    pub fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Flags {
    type Output = Flags;

    fn bitor(self, other: Flags) -> Flags {
        Flags(self.0 | other.0)
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names = Vec::new();
        for (bit, name) in [
            (Self::ENCRYPTED, "encrypted"),
            (Self::ZLIB, "zlib"),
            (Self::SNAPPY, "snappy"),
            (Self::GCM, "gcm"),
        ] {
            if self.contains(bit) {
                names.push(name);
            }
        }
        write!(f, "{:#06x}[{}]", self.0, names.join("|"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub packet_version: u32,
    pub mac: Mac,
    pub flags: Flags,
    pub iv: [u8; 16],
    pub payload_version: u32,
    pub payload_len: u32,
}

impl Header {
    /// Reads the header at the start of `buf`; what follows it is not looked at.
    pub fn parse(buf: &[u8]) -> Result<Header> {
        let Some(h) = buf.first_chunk::<HEADER_LEN>() else {
            return Err(Error::TooShort(buf.len()));
        };
        Header::from_raw(h)
    }

    fn from_raw(h: &[u8; HEADER_LEN]) -> Result<Header> {
        // A field of the header, sized at compile time.
        fn at<const N: usize>(h: &[u8; HEADER_LEN], offset: usize) -> [u8; N] {
            std::array::from_fn(|i| h[offset + i])
        }
        let magic = at(h, 0);
        if &magic != MAGIC {
            return Err(Error::BadMagic(magic));
        }
        Ok(Header {
            packet_version: u32::from_be_bytes(at(h, 4)),
            mac: Mac(at(h, 8)),
            flags: Flags(u16::from_be_bytes(at(h, 14))),
            iv: at(h, 16),
            payload_version: u32::from_be_bytes(at(h, 32)),
            payload_len: u32::from_be_bytes(at(h, 36)),
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(MAGIC);
        out[4..8].copy_from_slice(&self.packet_version.to_be_bytes());
        out[8..14].copy_from_slice(&self.mac.0);
        out[14..16].copy_from_slice(&self.flags.0.to_be_bytes());
        out[16..32].copy_from_slice(&self.iv);
        out[32..36].copy_from_slice(&self.payload_version.to_be_bytes());
        out[36..40].copy_from_slice(&self.payload_len.to_be_bytes());
        out
    }
}

/// Parses an `N`-byte key written in hex (an authkey's 32 characters, a syslog
/// key's 64), ignoring surrounding whitespace.
pub fn parse_key<const N: usize>(hex_key: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(hex_key.trim()).map_err(Error::KeyNotHex)?;
    bytes.try_into().map_err(|b: Vec<u8>| Error::KeyLength { expected: N, got: b.len() })
}

/// A packet split into its header and the payload exactly as it appeared on the wire.
#[derive(Clone, Debug)]
pub struct Packet<'a> {
    pub header: Header,
    /// The header's bytes, which AES-GCM authenticates.
    raw_header: &'a [u8; HEADER_LEN],
    pub body: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Splits a packet. Bytes after the declared payload are ignored; fewer than it
    /// declares is [`Error::Truncated`].
    pub fn parse(buf: &'a [u8]) -> Result<Packet<'a>> {
        let Some((raw_header, body)) = buf.split_first_chunk::<HEADER_LEN>() else {
            return Err(Error::TooShort(buf.len()));
        };
        let header = Header::from_raw(raw_header)?;
        let declared = header.payload_len as usize;
        if body.len() < declared {
            return Err(Error::Truncated { declared, actual: body.len() });
        }
        Ok(Packet { header, raw_header, body: &body[..declared] })
    }

    /// Decrypts and decompresses the payload, returning the plaintext (normally JSON).
    ///
    /// A packet without the ENCRYPTED flag is not decrypted at all: its body passes
    /// through (decompressed if flagged) whatever `key` is. Callers that require an
    /// encrypted inform must check `header.flags` themselves.
    pub fn open(&self, key: &[u8; 16]) -> Result<Vec<u8>> {
        let flags = self.header.flags;
        let decrypted = if !flags.contains(Flags::ENCRYPTED) {
            Cow::Borrowed(self.body)
        } else if flags.contains(Flags::GCM) {
            let cipher = Aes128Gcm16::new(key.into());
            let nonce = (&self.header.iv).into();
            let plain = cipher
                .decrypt(nonce, Payload { msg: self.body, aad: self.raw_header })
                .map_err(|_| Error::Decrypt)?;
            Cow::Owned(plain)
        } else {
            let mut buf = self.body.to_vec();
            let len = cbc::Decryptor::<Aes128>::new(key.into(), (&self.header.iv).into())
                .decrypt_padded::<Pkcs7>(&mut buf)
                .map_err(|_| Error::Decrypt)?
                .len();
            buf.truncate(len);
            Cow::Owned(buf)
        };
        decompress(flags, decrypted)
    }
}

/// Decompresses as flagged. An uncompressed payload is passed through, copied only if borrowed.
fn decompress(flags: Flags, data: Cow<'_, [u8]>) -> Result<Vec<u8>> {
    // Inflated JSON is a few times its compressed size: start there rather than growing from nothing.
    let hint = data.len().saturating_mul(4).min(MAX_PLAINTEXT);
    if flags.contains(Flags::ZLIB) {
        read_capped(flate2::bufread::ZlibDecoder::new(&data[..]), hint).map_err(|e| Error::Decompress(format!("zlib: {e}")))
    } else if flags.contains(Flags::SNAPPY) {
        // Raw snappy blocks are what we expect; fall back to the framed format. A raw
        // block declares its length up front, which the decoder would allocate.
        let raw = match snap::raw::decompress_len(&data) {
            Ok(n) if n > MAX_PLAINTEXT => Err(format!("{n} bytes is over the {MAX_PLAINTEXT} byte limit")),
            _ => snap::raw::Decoder::new().decompress_vec(&data).map_err(|e| e.to_string()),
        };
        match raw {
            Ok(out) => Ok(out),
            Err(raw_err) => read_capped(snap::read::FrameDecoder::new(&data[..]), hint)
                .map_err(|e| Error::Decompress(format!("snappy: {raw_err}; framed: {e}"))),
        }
    } else {
        Ok(data.into_owned())
    }
}

/// Reads a decompressing reader to the end, failing once it yields more than [`MAX_PLAINTEXT`].
/// `capacity` is a guess at the output size.
fn read_capped(r: impl Read, capacity: usize) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(capacity);
    r.take(MAX_PLAINTEXT as u64 + 1).read_to_end(&mut out)?;
    if out.len() > MAX_PLAINTEXT {
        return Err(std::io::Error::other(format!("output is over the {MAX_PLAINTEXT} byte limit")));
    }
    Ok(out)
}

/// Appends `data` to `out`, compressed as flagged.
fn compress_into(flags: Flags, data: &[u8], mut out: Vec<u8>) -> Vec<u8> {
    if flags.contains(Flags::ZLIB) {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(out, flate2::Compression::default());
        enc.write_all(data).expect("writing to a Vec cannot fail");
        enc.finish().expect("writing to a Vec cannot fail")
    } else if flags.contains(Flags::SNAPPY) {
        let start = out.len();
        out.resize(start + snap::raw::max_compress_len(data.len()), 0);
        let n = snap::raw::Encoder::new().compress(data, &mut out[start..]).expect("snappy compression of a buffer");
        out.truncate(start + n);
        out
    } else {
        out.extend_from_slice(data);
        out
    }
}

/// Builds a complete packet. `iv` must be unique per packet when encryption is on.
///
/// Everything happens in one buffer: the payload goes in (compressed or not) behind
/// room for the header, is encrypted in place, and the header is written last.
pub fn seal(mac: Mac, flags: Flags, iv: [u8; 16], key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    // The header, the payload and a GCM tag or CBC padding (at most one block).
    let snappy = flags.contains(Flags::SNAPPY) && !flags.contains(Flags::ZLIB);
    let room = if snappy { snap::raw::max_compress_len(plaintext.len()) } else { plaintext.len() };
    let mut out = Vec::with_capacity(HEADER_LEN + room + 16);
    out.resize(HEADER_LEN, 0);
    encrypt_into(mac, flags, iv, key, compress_into(flags, plaintext, out))
}

/// [`seal`] for an uncompressed packet, with the payload written by `write`
/// (e.g. `serde_json::to_writer`) at the end of the buffer it gets: straight
/// into the packet. A compressed packet is built with [`seal`].
pub fn seal_with(mac: Mac, flags: Flags, iv: [u8; 16], key: &[u8; 16], write: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    assert!(!flags.contains(Flags::ZLIB) && !flags.contains(Flags::SNAPPY), "seal_with builds uncompressed packets only");
    let mut out = vec![0; HEADER_LEN];
    write(&mut out);
    encrypt_into(mac, flags, iv, key, out)
}

/// Finishes a packet whose payload follows room for the header in `out`:
/// encrypted in place as flagged, then the header written.
fn encrypt_into(mac: Mac, flags: Flags, iv: [u8; 16], key: &[u8; 16], mut out: Vec<u8>) -> Vec<u8> {
    let msg_len = out.len() - HEADER_LEN;
    let mut header = Header {
        packet_version: 0,
        mac,
        flags,
        iv,
        payload_version: 1,
        payload_len: 0,
    };
    if flags.contains(Flags::ENCRYPTED) && flags.contains(Flags::GCM) {
        // The header (with the final length) is the associated data, so the
        // ciphertext length must be known first: plaintext + 16-byte tag.
        header.payload_len = (msg_len + 16) as u32;
        let aad = header.to_bytes();
        let tag = Aes128Gcm16::new(key.into())
            .encrypt_inout_detached((&iv).into(), &aad, (&mut out[HEADER_LEN..]).into())
            .expect("AES-GCM encryption of an in-memory buffer");
        out.extend_from_slice(&tag);
    } else if flags.contains(Flags::ENCRYPTED) {
        // PKCS#7 always pads, by 1 to 16 bytes, up to the next whole block.
        out.resize(HEADER_LEN + (msg_len / 16 + 1) * 16, 0);
        cbc::Encryptor::<Aes128>::new(key.into(), (&iv).into())
            .encrypt_padded::<Pkcs7>(&mut out[HEADER_LEN..], msg_len)
            .expect("room for the padding");
    }
    header.payload_len = (out.len() - HEADER_LEN) as u32;
    out[..HEADER_LEN].copy_from_slice(&header.to_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: Mac = Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    const KEY: [u8; 16] = *b"0123456789abcdef";
    const IV: [u8; 16] = [7; 16];
    const JSON: &[u8] = br#"{"_type":"noop","interval":10}"#;

    #[test]
    fn default_key_is_md5_of_ubnt() {
        assert_eq!(hex::encode(DEFAULT_KEY), "ba86f2bbe107c7c57eb5f2690775c712");
    }

    #[test]
    fn flags_combine_into_their_wire_bits() {
        let f = Flags::ENCRYPTED | Flags::GCM;
        assert_eq!(f.0, 0x09);
        assert!(f.contains(Flags::GCM) && f.contains(Flags::ENCRYPTED | Flags::GCM));
        assert!(!f.contains(Flags::GCM | Flags::ZLIB), "every bit asked for must be set");
        assert_eq!(format!("{f:?}"), "0x0009[encrypted|gcm]");
    }

    #[test]
    fn a_key_is_read_without_its_surrounding_whitespace() {
        assert_eq!(parse_key::<16>(" ba86f2bbe107c7c57eb5f2690775c712\n").unwrap(), DEFAULT_KEY);
        assert_eq!(parse_key::<2>("abcd").unwrap(), [0xab, 0xcd]);
        assert!(matches!(parse_key::<16>("abcd"), Err(Error::KeyLength { expected: 16, got: 2 })));
        let e = parse_key::<2>("abzz").unwrap_err();
        assert!(matches!(e, Error::KeyNotHex(_)));
        assert!(std::error::Error::source(&e).is_some_and(|s| s.to_string().contains("'z'")), "the hex error is kept as the source");
    }

    #[test]
    fn round_trips_every_flag_combination() {
        let combos = [
            Flags::NONE,
            Flags::ZLIB,
            Flags::SNAPPY,
            Flags::ENCRYPTED,
            Flags::ENCRYPTED | Flags::ZLIB,
            Flags::ENCRYPTED | Flags::SNAPPY,
            Flags::ENCRYPTED | Flags::GCM,
            Flags::ENCRYPTED | Flags::GCM | Flags::SNAPPY,
            Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB,
        ];
        for bits in combos {
            let wire = seal(MAC, bits, IV, &KEY, JSON);
            if !bits.contains(Flags::ZLIB) && !bits.contains(Flags::SNAPPY) {
                assert_eq!(seal_with(MAC, bits, IV, &KEY, |out| out.extend_from_slice(JSON)), wire, "flags {:?}", bits);
            }
            let pkt = Packet::parse(&wire).unwrap();
            assert_eq!(pkt.header.mac, MAC);
            assert_eq!(pkt.header.flags, bits);
            assert_eq!(pkt.header.payload_len as usize, wire.len() - HEADER_LEN);
            assert_eq!(pkt.open(&KEY).unwrap(), JSON, "flags {:?}", bits);
        }
        // CBC pads to the next whole block, by a full block when already aligned.
        for len in [0, 1, 15, 16, 17, 32] {
            let plain = vec![b'x'; len];
            let wire = seal(MAC, Flags::ENCRYPTED, IV, &KEY, &plain);
            assert_eq!(wire.len() - HEADER_LEN, (len / 16 + 1) * 16, "{len} bytes");
            assert_eq!(Packet::parse(&wire).unwrap().open(&KEY).unwrap(), plain);
        }
    }

    /// The bytes of a sealed packet do not change (they are what the APs decrypt).
    #[test]
    fn sealed_bytes_are_stable() {
        let hex_of = |bits| hex::encode(seal(MAC, bits, IV, &KEY, JSON));
        assert_eq!(
            hex_of(Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB),
            "544e425500000000001122334455000b07070707070707070707070707070707000000010000003660058e882d29aecd91e16f1209e5c750f7a3983d0d57362bdc62aa6880dbfc79831072a78ee2c5b49eaaba69cb66cb9226714823938f"
        );
        assert_eq!(
            hex_of(Flags::ENCRYPTED | Flags::SNAPPY),
            "544e4255000000000011223344550005070707070707070707070707070707070000000100000030de3330cf20349f36d3f31176e1f4c3bcd208509ddbe77f9a6ad35880644ee6259bfb8524e7377a8f089c2bf6c81e554a"
        );
    }

    #[test]
    fn wrong_key_is_rejected_for_gcm() {
        let wire = seal(MAC, Flags::ENCRYPTED | Flags::GCM, IV, &KEY, JSON);
        let pkt = Packet::parse(&wire).unwrap();
        assert!(matches!(pkt.open(&DEFAULT_KEY), Err(Error::Decrypt)));
    }

    #[test]
    fn gcm_authenticates_the_header() {
        let mut wire = seal(MAC, Flags::ENCRYPTED | Flags::GCM, IV, &KEY, JSON);
        wire[13] ^= 1; // flip a bit of the MAC
        let pkt = Packet::parse(&wire).unwrap();
        assert!(matches!(pkt.open(&KEY), Err(Error::Decrypt)));
    }

    #[test]
    fn header_round_trip_and_errors() {
        let wire = seal(MAC, Flags::ENCRYPTED, IV, &KEY, JSON);
        let h = Header::parse(&wire).unwrap();
        assert_eq!(&h.to_bytes()[..], &wire[..HEADER_LEN]);
        assert!(matches!(Header::parse(&wire[..10]), Err(Error::TooShort(10))));
        let mut bad = wire.clone();
        bad[0] = b'X';
        assert!(matches!(Header::parse(&bad), Err(Error::BadMagic(_))));
        assert!(matches!(
            Packet::parse(&wire[..wire.len() - 1]),
            Err(Error::Truncated { .. })
        ));
        // Trailing bytes are left out of the body.
        let mut long = wire.clone();
        long.extend_from_slice(b"junk");
        assert_eq!(Packet::parse(&long).unwrap().body, &wire[HEADER_LEN..]);
    }

    #[test]
    fn mac_parsing() {
        assert_eq!("00:11:22:33:44:55".parse::<Mac>().unwrap(), MAC);
        assert_eq!("001122334455".parse::<Mac>().unwrap(), MAC);
        assert_eq!(MAC.to_string(), "00:11:22:33:44:55");
        assert!(matches!("00:11".parse::<Mac>(), Err(Error::InvalidMac(_))));
        assert!(matches!("zz:11:22:33:44:55".parse::<Mac>(), Err(Error::InvalidMac(_))));
        assert_eq!("00-11-22-33-44-55".parse::<Mac>().unwrap(), MAC);
        assert_eq!("00:11:22:33:44:AA".parse::<Mac>().unwrap().to_string(), "00:11:22:33:44:aa");
        let aa = Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        for good in ["aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "Aa-bB-cc-DD-ee-FF", "aabbccddeeff", "AABBCCDDEEFF"] {
            assert_eq!(good.parse::<Mac>().unwrap(), aa, "{good}");
        }
        for bad in [
            "00:11-22:33:44:55", "001122:334455", "0:11:22:33:44:555", "00:11:22:33:44:55:", "+0:11:22:33:44:55", "", "00.11.22.33.44.55", "00::11:22:33:44:5",
            "00112233445g", "0011223344556", "00:11:22:33:44:5g", " 00:11:22:33:44:55", "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", "+01122334455",
        ] {
            assert!(bad.parse::<Mac>().is_err(), "{bad}");
        }
    }

    #[test]
    fn mac_deserializes_from_borrowed_and_owned_strings() {
        use serde::Deserialize;
        use serde::de::IntoDeserializer;
        use serde::de::value::{BorrowedStrDeserializer, Error};
        assert_eq!(Mac::deserialize(BorrowedStrDeserializer::<Error>::new("00:11:22:33:44:55")), Ok(MAC));
        assert_eq!(Mac::deserialize(IntoDeserializer::<Error>::into_deserializer("00-11-22-33-44-55".to_string())), Ok(MAC));
        assert!(Mac::deserialize(IntoDeserializer::<Error>::into_deserializer("00:11")).is_err());
        assert!(Mac::deserialize(IntoDeserializer::<Error>::into_deserializer(5u32)).is_err());
    }

    #[test]
    fn decompression_is_capped() {
        // Highly compressible, just over the cap: a few KB on the wire.
        let big = vec![b' '; MAX_PLAINTEXT + 1];
        for bits in [Flags::ZLIB, Flags::SNAPPY, Flags::ENCRYPTED | Flags::GCM | Flags::ZLIB, Flags::ENCRYPTED | Flags::GCM | Flags::SNAPPY] {
            let wire = seal(MAC, bits, IV, &KEY, &big);
            assert!(wire.len() < MAX_PLAINTEXT / 16, "{:?} compresses", bits);
            let pkt = Packet::parse(&wire).unwrap();
            assert!(matches!(pkt.open(&KEY), Err(Error::Decompress(_))), "{:?}", bits);
        }
        // Exactly at the cap still decodes.
        let max = vec![b' '; MAX_PLAINTEXT];
        let wire = seal(MAC, Flags::ZLIB, IV, &KEY, &max);
        assert_eq!(Packet::parse(&wire).unwrap().open(&KEY).unwrap().len(), MAX_PLAINTEXT);
        // A raw snappy header claiming 4 GiB is refused before anything is allocated.
        let mut lie = vec![0xff, 0xff, 0xff, 0xff, 0x0f];
        lie.extend_from_slice(b"\x00x");
        assert!(matches!(decompress(Flags::SNAPPY, lie.into()), Err(Error::Decompress(_))));
        // The framed snappy format is capped too.
        let mut framed = Vec::new();
        {
            use std::io::Write;
            let mut w = snap::write::FrameEncoder::new(&mut framed);
            w.write_all(&big).unwrap();
        }
        assert!(matches!(decompress(Flags::SNAPPY, framed.into()), Err(Error::Decompress(_))));
    }
}
