//! Olson time zone name -> POSIX `TZ` string, as the AP's libc wants it.
//!
//! A deliberately small table of common zones (rules from the public tz database).
//! Unknown zones make the `system.timezone` lines disappear, which is also what the
//! official controller does when its own lookup fails.

const CET: &str = "CET-1CEST,M3.5.0,M10.5.0/3";
const EET: &str = "EET-2EEST,M3.5.0/3,M10.5.0/4";
const US_EAST: &str = "EST5EDT,M3.2.0,M11.1.0";
const US_CENTRAL: &str = "CST6CDT,M3.2.0,M11.1.0";
const US_MOUNTAIN: &str = "MST7MDT,M3.2.0,M11.1.0";
const US_PACIFIC: &str = "PST8PDT,M3.2.0,M11.1.0";
const AU_EAST: &str = "AEST-10AEDT,M10.1.0,M4.1.0/3";

const ZONES: &[(&str, &str)] = &[
    ("UTC", "UTC0"),
    ("Etc/UTC", "UTC0"),
    ("GMT", "GMT0"),
    ("Europe/London", "GMT0BST,M3.5.0/1,M10.5.0"),
    ("Europe/Dublin", "GMT0IST,M3.5.0/1,M10.5.0"),
    ("Europe/Lisbon", "WET0WEST,M3.5.0/1,M10.5.0"),
    ("Europe/Amsterdam", CET),
    ("Europe/Belgrade", CET),
    ("Europe/Berlin", CET),
    ("Europe/Bratislava", CET),
    ("Europe/Brussels", CET),
    ("Europe/Budapest", CET),
    ("Europe/Copenhagen", CET),
    ("Europe/Ljubljana", CET),
    ("Europe/Luxembourg", CET),
    ("Europe/Madrid", CET),
    ("Europe/Monaco", CET),
    ("Europe/Oslo", CET),
    ("Europe/Paris", CET),
    ("Europe/Prague", CET),
    ("Europe/Rome", CET),
    ("Europe/Stockholm", CET),
    ("Europe/Vienna", CET),
    ("Europe/Warsaw", CET),
    ("Europe/Zagreb", CET),
    ("Europe/Zurich", CET),
    ("Europe/Athens", EET),
    ("Europe/Bucharest", EET),
    ("Europe/Helsinki", EET),
    ("Europe/Kiev", EET),
    ("Europe/Kyiv", EET),
    ("Europe/Riga", EET),
    ("Europe/Sofia", EET),
    ("Europe/Tallinn", EET),
    ("Europe/Vilnius", EET),
    ("Europe/Istanbul", "<+03>-3"),
    ("Europe/Moscow", "MSK-3"),
    ("America/New_York", US_EAST),
    ("America/Detroit", US_EAST),
    ("America/Toronto", US_EAST),
    ("America/Chicago", US_CENTRAL),
    ("America/Winnipeg", US_CENTRAL),
    ("America/Denver", US_MOUNTAIN),
    ("America/Edmonton", US_MOUNTAIN),
    ("America/Phoenix", "MST7"),
    ("America/Los_Angeles", US_PACIFIC),
    ("America/Vancouver", US_PACIFIC),
    ("America/Anchorage", "AKST9AKDT,M3.2.0,M11.1.0"),
    ("America/Halifax", "AST4ADT,M3.2.0,M11.1.0"),
    ("America/Sao_Paulo", "<-03>3"),
    ("America/Mexico_City", "CST6"),
    ("Pacific/Honolulu", "HST10"),
    ("Pacific/Auckland", "NZST-12NZDT,M9.5.0,M4.1.0/3"),
    ("Asia/Tokyo", "JST-9"),
    ("Asia/Seoul", "KST-9"),
    ("Asia/Shanghai", "CST-8"),
    ("Asia/Hong_Kong", "HKT-8"),
    ("Asia/Singapore", "<+08>-8"),
    ("Asia/Kolkata", "IST-5:30"),
    ("Asia/Dubai", "<+04>-4"),
    ("Asia/Jerusalem", "IST-2IDT,M3.4.4/26,M10.5.0"),
    ("Australia/Sydney", AU_EAST),
    ("Australia/Melbourne", AU_EAST),
    ("Australia/Brisbane", "AEST-10"),
    ("Australia/Adelaide", "ACST-9:30ACDT,M10.1.0,M4.1.0/3"),
    ("Australia/Perth", "AWST-8"),
    ("Africa/Johannesburg", "SAST-2"),
];

/// The zones [`posix`] knows, in table order.
pub fn names() -> impl Iterator<Item = &'static str> {
    ZONES.iter().map(|(name, _)| *name)
}

pub fn posix(olson: &str) -> Option<&'static str> {
    ZONES.iter().find(|(name, _)| *name == olson).map(|(_, tz)| *tz)
}
