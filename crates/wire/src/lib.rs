//! Turning captured traffic into decoded inform exchanges: pcap reading, TCP/HTTP
//! reassembly, key lookup and decryption. Shared by `informdump` and the controller's
//! shadow mode.

pub mod capture;
pub mod cfgdiff;
pub mod decode;
pub mod exchange;
pub mod keys;
