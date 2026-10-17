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
pub const HEADER_LEN: usize = 40;
/// Largest payload accepted after decompression. Real informs are tens to a few
/// hundred KB; the cap stops a small compressed body from inflating to gigabytes.
pub const MAX_PLAINTEXT: usize = 8 << 20;

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
    #[error("payload length {declared} does not match the {actual} bytes present")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("decryption failed (wrong key?)")]
    Decrypt,
    #[error("decompression failed: {0}")]
    Decompress(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
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

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u16);

impl Flags {
    pub const ENCRYPTED: u16 = 0x01;
    pub const ZLIB: u16 = 0x02;
    pub const SNAPPY: u16 = 0x04;
    pub const GCM: u16 = 0x08;

    pub fn has(self, bit: u16) -> bool {
        self.0 & bit != 0
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
            if self.has(bit) {
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
    pub fn parse(buf: &[u8]) -> Result<Header> {
        if buf.len() < HEADER_LEN {
            return Err(Error::TooShort(buf.len()));
        }
        let magic: [u8; 4] = buf[0..4].try_into().unwrap();
        if &magic != MAGIC {
            return Err(Error::BadMagic(magic));
        }
        let u32_at = |o: usize| u32::from_be_bytes(buf[o..o + 4].try_into().unwrap());
        Ok(Header {
            packet_version: u32_at(4),
            mac: Mac(buf[8..14].try_into().unwrap()),
            flags: Flags(u16::from_be_bytes([buf[14], buf[15]])),
            iv: buf[16..32].try_into().unwrap(),
            payload_version: u32_at(32),
            payload_len: u32_at(36),
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

/// Parses a hex authkey (32 hex chars) into a 16-byte AES key.
pub fn parse_key(hex_key: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_key.trim()).map_err(|e| Error::InvalidKey(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| Error::InvalidKey("expected 16 bytes".into()))
}

/// A packet split into its header and the payload exactly as it appeared on the wire.
#[derive(Clone, Debug)]
pub struct Packet<'a> {
    pub header: Header,
    pub raw_header: &'a [u8],
    pub body: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Packet<'a>> {
        let header = Header::parse(buf)?;
        let body = &buf[HEADER_LEN..];
        let declared = header.payload_len as usize;
        if body.len() < declared {
            return Err(Error::LengthMismatch { declared, actual: body.len() });
        }
        Ok(Packet { header, raw_header: &buf[..HEADER_LEN], body: &body[..declared] })
    }

    /// Decrypts and decompresses the payload, returning the plaintext (normally JSON).
    ///
    /// A packet without the ENCRYPTED flag is not decrypted at all: its body passes
    /// through (decompressed if flagged) whatever `key` is. Callers that require an
    /// encrypted inform must check `header.flags` themselves.
    pub fn open(&self, key: &[u8; 16]) -> Result<Vec<u8>> {
        let flags = self.header.flags;
        let decrypted = if !flags.has(Flags::ENCRYPTED) {
            Cow::Borrowed(self.body)
        } else if flags.has(Flags::GCM) {
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
    if flags.has(Flags::ZLIB) {
        read_capped(flate2::bufread::ZlibDecoder::new(&data[..]), hint).map_err(|e| Error::Decompress(format!("zlib: {e}")))
    } else if flags.has(Flags::SNAPPY) {
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
    if flags.has(Flags::ZLIB) {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(out, flate2::Compression::default());
        enc.write_all(data).expect("writing to a Vec cannot fail");
        enc.finish().expect("writing to a Vec cannot fail")
    } else if flags.has(Flags::SNAPPY) {
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
    let snappy = flags.has(Flags::SNAPPY) && !flags.has(Flags::ZLIB);
    let room = if snappy { snap::raw::max_compress_len(plaintext.len()) } else { plaintext.len() };
    let mut out = Vec::with_capacity(HEADER_LEN + room + 16);
    out.resize(HEADER_LEN, 0);
    let mut out = compress_into(flags, plaintext, out);
    let msg_len = out.len() - HEADER_LEN;
    let mut header = Header {
        packet_version: 0,
        mac,
        flags,
        iv,
        payload_version: 1,
        payload_len: 0,
    };
    if flags.has(Flags::ENCRYPTED) && flags.has(Flags::GCM) {
        // The header (with the final length) is the associated data, so the
        // ciphertext length must be known first: plaintext + 16-byte tag.
        header.payload_len = (msg_len + 16) as u32;
        let aad = header.to_bytes();
        let tag = Aes128Gcm16::new(key.into())
            .encrypt_inout_detached((&iv).into(), &aad, (&mut out[HEADER_LEN..]).into())
            .expect("AES-GCM encryption of an in-memory buffer");
        out.extend_from_slice(&tag);
    } else if flags.has(Flags::ENCRYPTED) {
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
    fn round_trips_every_flag_combination() {
        let combos = [
            0,
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
            let wire = seal(MAC, Flags(bits), IV, &KEY, JSON);
            let pkt = Packet::parse(&wire).unwrap();
            assert_eq!(pkt.header.mac, MAC);
            assert_eq!(pkt.header.flags, Flags(bits));
            assert_eq!(pkt.header.payload_len as usize, wire.len() - HEADER_LEN);
            assert_eq!(pkt.open(&KEY).unwrap(), JSON, "flags {:?}", Flags(bits));
        }
        // CBC pads to the next whole block, by a full block when already aligned.
        for len in [0, 1, 15, 16, 17, 32] {
            let plain = vec![b'x'; len];
            let wire = seal(MAC, Flags(Flags::ENCRYPTED), IV, &KEY, &plain);
            assert_eq!(wire.len() - HEADER_LEN, (len / 16 + 1) * 16, "{len} bytes");
            assert_eq!(Packet::parse(&wire).unwrap().open(&KEY).unwrap(), plain);
        }
    }

    /// The bytes of a sealed packet do not change (they are what the APs decrypt).
    #[test]
    fn sealed_bytes_are_stable() {
        let hex_of = |bits| hex::encode(seal(MAC, Flags(bits), IV, &KEY, JSON));
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
        let wire = seal(MAC, Flags(Flags::ENCRYPTED | Flags::GCM), IV, &KEY, JSON);
        let pkt = Packet::parse(&wire).unwrap();
        assert!(matches!(pkt.open(&DEFAULT_KEY), Err(Error::Decrypt)));
    }

    #[test]
    fn gcm_authenticates_the_header() {
        let mut wire = seal(MAC, Flags(Flags::ENCRYPTED | Flags::GCM), IV, &KEY, JSON);
        wire[13] ^= 1; // flip a bit of the MAC
        let pkt = Packet::parse(&wire).unwrap();
        assert!(matches!(pkt.open(&KEY), Err(Error::Decrypt)));
    }

    #[test]
    fn header_round_trip_and_errors() {
        let wire = seal(MAC, Flags(Flags::ENCRYPTED), IV, &KEY, JSON);
        let h = Header::parse(&wire).unwrap();
        assert_eq!(&h.to_bytes()[..], &wire[..HEADER_LEN]);
        assert!(matches!(Header::parse(&wire[..10]), Err(Error::TooShort(10))));
        let mut bad = wire.clone();
        bad[0] = b'X';
        assert!(matches!(Header::parse(&bad), Err(Error::BadMagic(_))));
        assert!(matches!(
            Packet::parse(&wire[..wire.len() - 1]),
            Err(Error::LengthMismatch { .. })
        ));
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
            let wire = seal(MAC, Flags(bits), IV, &KEY, &big);
            assert!(wire.len() < MAX_PLAINTEXT / 16, "{:?} compresses", Flags(bits));
            let pkt = Packet::parse(&wire).unwrap();
            assert!(matches!(pkt.open(&KEY), Err(Error::Decompress(_))), "{:?}", Flags(bits));
        }
        // Exactly at the cap still decodes.
        let max = vec![b' '; MAX_PLAINTEXT];
        let wire = seal(MAC, Flags(Flags::ZLIB), IV, &KEY, &max);
        assert_eq!(Packet::parse(&wire).unwrap().open(&KEY).unwrap().len(), MAX_PLAINTEXT);
        // A raw snappy header claiming 4 GiB is refused before anything is allocated.
        let mut lie = vec![0xff, 0xff, 0xff, 0xff, 0x0f];
        lie.extend_from_slice(b"\x00x");
        assert!(matches!(decompress(Flags(Flags::SNAPPY), lie.into()), Err(Error::Decompress(_))));
        // The framed snappy format is capped too.
        let mut framed = Vec::new();
        {
            use std::io::Write;
            let mut w = snap::write::FrameEncoder::new(&mut framed);
            w.write_all(&big).unwrap();
        }
        assert!(matches!(decompress(Flags(Flags::SNAPPY), framed.into()), Err(Error::Decompress(_))));
    }
}
