//! Local time for schedules set in the site's time zone (e.g. the nightly
//! channel optimisation at 05:00). The image has no zoneinfo, so the zone's
//! POSIX rule (`apcfg::tz`, the same table the APs get) is evaluated here.

use crate::model::Ts;

/// Seconds since the Unix epoch by the wall clock (0 if it is set before 1970).
pub fn now_ts() -> Ts {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Civil date (year, month, day) of a day number.
pub use wire::civil_from_days;
use wire::days_from_civil;

fn days_in_month(y: i64, m: i64) -> i64 {
    days_from_civil(if m == 12 { y + 1 } else { y }, if m == 12 { 1 } else { m + 1 }, 1) - days_from_civil(y, m, 1)
}

/// `[+-]hh[:mm[:ss]]` in seconds.
fn hms(s: &str) -> Option<i64> {
    let (sign, rest) = match s.as_bytes().first()? {
        b'-' => (-1, &s[1..]),
        b'+' => (1, &s[1..]),
        _ => (1, s),
    };
    let mut total = 0;
    for (i, part) in rest.split(':').enumerate() {
        total += part.parse::<i64>().ok()? * [3600, 60, 1].get(i)?;
    }
    Some(sign * total)
}

/// Splits a zone name (`CET` or `<+03>`) off the front.
fn name(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('<') {
        let end = rest.find('>')?;
        return Some((&rest[..end], &rest[end + 1..]));
    }
    let end = s.find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(s.len());
    (end >= 3).then(|| (&s[..end], &s[end..]))
}

/// Splits an offset off the front.
fn offset(s: &str) -> (Option<i64>, &str) {
    let end = s.find(|c: char| !(c.is_ascii_digit() || c == ':' || c == '+' || c == '-')).unwrap_or(s.len());
    (hms(&s[..end]), &s[end..])
}

/// The day of the week of a day number (days since 1970-01-01), Sunday = 0
/// as in POSIX rules: 1970-01-01 was a Thursday.
pub fn weekday(day: i64) -> i64 {
    (day + 4).rem_euclid(7)
}

/// A change rule, `Mm.w.d` (day d of week w of month m), `Jn` (day n of
/// 1..=365, never counting February 29) or `n` (day n of 0..=365), with an
/// optional `/time`: the local day number of the change and its time, in
/// seconds after midnight.
fn rule_day(rule: &str, year: i64) -> Option<(i64, i64)> {
    let (date, time) = rule.split_once('/').map_or((rule, None), |(d, t)| (d, Some(t)));
    let jan1 = days_from_civil(year, 1, 1);
    let num = |s: &str, range: std::ops::RangeInclusive<i64>| s.parse::<i64>().ok().filter(|n| range.contains(n));
    let day = if let Some(mwd) = date.strip_prefix('M') {
        let mut parts = mwd.split('.');
        let (m, w, d) = (num(parts.next()?, 1..=12)?, num(parts.next()?, 1..=5)?, num(parts.next()?, 0..=6)?);
        let first = days_from_civil(year, m, 1);
        let first_wd = weekday(first);
        let mut day = 1 + (d - first_wd).rem_euclid(7) + (w - 1) * 7;
        while day > days_in_month(year, m) {
            day -= 7;
        }
        first + day - 1
    } else if let Some(n) = date.strip_prefix('J') {
        let n = num(n, 1..=365)?;
        jan1 + n - 1 + i64::from(n >= 60 && days_in_month(year, 2) == 29)
    } else {
        jan1 + num(date, 0..=365)?
    };
    Some((day, time.map_or(Some(7200), hms)?))
}

/// The UTC offset (seconds east) a POSIX TZ rule gives at a UTC time. A
/// summer time part that cannot be read leaves the standard offset.
pub fn utc_offset(tz: &str, at: Ts) -> Option<i64> {
    let (_, rest) = name(tz)?;
    let (std, rest) = offset(rest);
    let std = -std?;
    Some(if rest.is_empty() { std } else { summer_offset(rest, std, at).unwrap_or(std) })
}

/// The offset at a UTC time by a rule's summer time part (`EDT,M3.2.0,M11.1.0`),
/// the standard offset being `std`.
fn summer_offset(rest: &str, std: i64, at: Ts) -> Option<i64> {
    let (_, rest) = name(rest)?;
    let (dst, rest) = offset(rest);
    let dst = dst.map_or(std + 3600, |o| -o);
    let mut rules = rest.strip_prefix(',')?.split(',');
    let (start, end) = (rules.next()?, rules.next()?);
    let year = civil_from_days((at + std).div_euclid(86400)).0;
    // A change happens at local wall time: the start in standard time, the end in summer time.
    let (sd, st) = rule_day(start, year)?;
    let (ed, et) = rule_day(end, year)?;
    let start_utc = sd * 86400 + st - std;
    let end_utc = ed * 86400 + et - dst;
    let summer = if start_utc < end_utc { at >= start_utc && at < end_utc } else { at >= start_utc || at < end_utc };
    Some(if summer { dst } else { std })
}

/// Local (day number, minute of the day) at a UTC time in an Olson zone;
/// unknown zones are treated as UTC.
pub fn local(olson: Option<&str>, at: Ts) -> (i64, i64) {
    let off = olson.and_then(apcfg::tz::posix).and_then(|tz| utc_offset(tz, at)).unwrap_or(0);
    let t = at + off;
    (t.div_euclid(86400), t.rem_euclid(86400) / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(y: i64, m: i64, d: i64, h: i64, min: i64) -> Ts {
        days_from_civil(y, m, d) * 86400 + h * 3600 + min * 60
    }

    #[test]
    fn weekdays_count_from_sunday() {
        assert_eq!(weekday(0), 4, "1970-01-01, a Thursday");
        assert_eq!(weekday(-1), 3);
        assert_eq!(weekday(days_from_civil(2026, 10, 25)), 0, "a Sunday");
    }

    #[test]
    fn european_summer_time_starts_and_ends_on_the_right_sundays() {
        let cet = apcfg::tz::posix("Europe/Berlin").unwrap();
        // 2026: last Sunday of March (29th) and of October (25th), at 01:00 UTC.
        assert_eq!(utc_offset(cet, ts(2026, 3, 29, 0, 59)), Some(3600));
        assert_eq!(utc_offset(cet, ts(2026, 3, 29, 1, 0)), Some(7200));
        assert_eq!(utc_offset(cet, ts(2026, 10, 25, 0, 59)), Some(7200));
        assert_eq!(utc_offset(cet, ts(2026, 10, 25, 1, 0)), Some(3600));
        assert_eq!(local(Some("Europe/Berlin"), ts(2026, 7, 1, 3, 0)).1, 5 * 60, "05:00 local in summer is 03:00 UTC");
        assert_eq!(local(Some("Europe/Berlin"), ts(2026, 12, 1, 4, 0)).1, 5 * 60);
    }

    #[test]
    fn other_hemispheres_and_plain_offsets() {
        let us = apcfg::tz::posix("America/New_York").unwrap();
        assert_eq!(utc_offset(us, ts(2026, 3, 8, 6, 59)), Some(-5 * 3600));
        assert_eq!(utc_offset(us, ts(2026, 3, 8, 7, 0)), Some(-4 * 3600));
        assert_eq!(utc_offset("AEST-10AEDT,M10.1.0,M4.1.0/3", ts(2026, 1, 15, 0, 0)), Some(11 * 3600), "summer in January");
        assert_eq!(utc_offset("AEST-10AEDT,M10.1.0,M4.1.0/3", ts(2026, 6, 15, 0, 0)), Some(10 * 3600));
        assert_eq!(utc_offset("<+0530>-5:30", 0), Some(5 * 3600 + 1800));
        assert_eq!(local(Some("Nowhere/Unknown"), ts(2026, 1, 1, 5, 7)).1, 5 * 60 + 7);
    }

    #[test]
    fn julian_day_rules_and_unreadable_ones() {
        // In 2024, a leap year, J60 is March 1 (February 29 is never counted)
        // and a zero-based 59 is February 29.
        for tz in ["XST-1XDT,J60/0,J301/0", "XST-1XDT,59/0,300/0"] {
            assert_eq!(utc_offset(tz, ts(2024, 2, 29, 12, 0)), Some(if tz.contains('J') { 3600 } else { 7200 }), "{tz}");
            assert_eq!(utc_offset(tz, ts(2024, 3, 1, 12, 0)), Some(7200), "{tz}");
            assert_eq!(utc_offset(tz, ts(2024, 10, 28, 12, 0)), Some(3600), "{tz}");
        }
        // A summer time part that cannot be read: the standard offset, not UTC.
        assert_eq!(utc_offset("XST-1XDT,M13.1.0,M10.5.0", ts(2026, 7, 1, 0, 0)), Some(3600));
        assert_eq!(utc_offset("XST-1XDT", ts(2026, 7, 1, 0, 0)), Some(3600));
    }
}
