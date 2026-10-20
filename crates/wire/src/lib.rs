//! Turning captured traffic into decoded inform exchanges: pcap reading, TCP/HTTP
//! reassembly, key lookup and decryption. Shared by `informdump` and the controller's
//! shadow mode.

pub mod capture;
pub mod cfgdiff;
pub mod decode;
pub mod exchange;
pub mod keys;
pub mod synth;

use std::net::{IpAddr, SocketAddr};

/// The address of an X-Forwarded-For hop: an address alone, with a port
/// (`203.0.113.7:4711`, `[2001:db8::1]:4711`), or in brackets alone (`[2001:db8::1]`).
pub fn hop_ip(hop: &str) -> Option<IpAddr> {
    hop.parse::<IpAddr>().ok().or_else(|| hop.parse::<SocketAddr>().ok().map(|a| a.ip())).or_else(|| hop.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
}

/// Civil date `(year, month, day)` of a day count since 1970-01-01, proleptic
/// Gregorian (Howard Hinnant's `civil_from_days`).
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Civil UTC time `(year, month, day, hour, minute, second)` of seconds since
/// 1970-01-01, as [`civil_from_days`] counts days.
pub fn civil_from_secs(ts: i64) -> (i64, i64, i64, i64, i64, i64) {
    let (y, m, d) = civil_from_days(ts.div_euclid(86_400));
    let secs = ts.rem_euclid(86_400);
    (y, m, d, secs / 3600, secs / 60 % 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, civil_from_secs};

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_738), (2026, 10, 12));
        assert_eq!(civil_from_days(-719_468), (0, 3, 1));
    }

    #[test]
    fn civil_times() {
        assert_eq!(civil_from_secs(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_secs(-1), (1969, 12, 31, 23, 59, 59));
        assert_eq!(civil_from_secs(951_782_400 + 86_399), (2000, 2, 29, 23, 59, 59));
        assert_eq!(civil_from_secs(1_791_801_045), (2026, 10, 12, 10, 30, 45));
    }
}
