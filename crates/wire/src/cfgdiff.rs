//! Diffs `system_cfg` / `mgmt_cfg` blobs, which are newline-separated `key=value` lines.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write;

use serde_json::{Value, json};

/// The values of each key, in order (a key can repeat), borrowed from `cfg`.
fn parse(cfg: &str) -> BTreeMap<&str, Vec<&str>> {
    let mut map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for line in cfg.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        map.entry(k).or_default().push(v);
    }
    map
}

/// What changed between two configs, borrowed from them. A key's value is its line's
/// value, or the values of a repeated key joined with ` | `.
#[derive(Debug, Default, PartialEq)]
pub struct Diff<'a> {
    pub added: Vec<(&'a str, Cow<'a, str>)>,
    pub removed: Vec<(&'a str, Cow<'a, str>)>,
    pub changed: Vec<(&'a str, Cow<'a, str>, Cow<'a, str>)>,
}

impl Diff<'_> {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// How many keys were added, removed and changed.
    pub fn counts(&self) -> [usize; 3] {
        [self.added.len(), self.removed.len(), self.changed.len()]
    }

    /// The counts and the redacted rendering, as config history and previews show a
    /// change: `{"added", "removed", "changed", "diff"}`.
    pub fn summary(&self) -> Value {
        let [added, removed, changed] = self.counts();
        json!({ "added": added, "removed": removed, "changed": changed, "diff": self.render("", true) })
    }

    /// Renders the diff with `+`, `-` and `~` markers, one key per line, sorted by key.
    /// With `redact`, values of secret-looking keys are masked.
    pub fn render(&self, indent: &str, redact: bool) -> String {
        let show = |k: &str, v: &str| (if redact && is_secret(k) { "<redacted>" } else { v }).to_string();
        let mut lines: Vec<(&str, String)> = Vec::new();
        for (k, v) in &self.added {
            lines.push((k, format!("{indent}+ {k}={}", show(k, v))));
        }
        for (k, v) in &self.removed {
            lines.push((k, format!("{indent}- {k}={}", show(k, v))));
        }
        for (k, old, new) in &self.changed {
            lines.push((k, format!("{indent}~ {k}: {} -> {}", show(k, old), show(k, new))));
        }
        lines.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = String::new();
        for (_, l) in lines {
            let _ = writeln!(out, "{l}");
        }
        out
    }
}

/// Keys whose values are credentials (PSKs, RADIUS secrets, authkeys, passwords,
/// the SNMP community).
pub fn is_secret(key: &str) -> bool {
    // Case-insensitive, without lowercasing a copy of every key.
    let starts = |s: &str, p: &str| s.len() >= p.len() && s.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes());
    let ends = |s: &str, p: &str| s.len() >= p.len() && s.as_bytes()[s.len() - p.len()..].eq_ignore_ascii_case(p.as_bytes());
    let contains = |s: &str, p: &str| s.as_bytes().windows(p.len()).any(|w| w.eq_ignore_ascii_case(p.as_bytes()));
    // `x_` marks secret fields in the controller's database, but only as a prefix
    // (`max_txpower` must stay visible).
    let last = key.rsplit('.').next().unwrap_or("");
    key.split('.').any(|seg| starts(seg, "x_"))
        || last.eq_ignore_ascii_case("key")
        || ends(last, "_key")
        || last.eq_ignore_ascii_case("community")
        || ["psk", "passphrase", "secret", "authkey", "password", "passwd", "syslog_key", "sae_"]
            .iter()
            .any(|s| contains(key, s))
}

/// Masks secret values in a whole `key=value` blob.
pub fn redact(cfg: &str) -> String {
    let mut out = String::with_capacity(cfg.len());
    for (i, l) in cfg.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        match l.split_once('=') {
            Some((k, _)) if is_secret(k) => {
                out.push_str(k);
                out.push_str("=<redacted>");
            }
            _ => out.push_str(l),
        }
    }
    out
}

pub fn diff<'a>(old: &'a str, new: &'a str) -> Diff<'a> {
    let (old, new) = (parse(old), parse(new));
    let mut d = Diff::default();
    let join = |v: &[&'a str]| -> Cow<'a, str> { if let [one] = v { Cow::Borrowed(*one) } else { Cow::Owned(v.join(" | ")) } };
    for (&k, nv) in &new {
        match old.get(k) {
            None => d.added.push((k, join(nv))),
            Some(ov) if ov != nv => d.changed.push((k, join(ov), join(nv))),
            _ => {}
        }
    }
    for (&k, ov) in &old {
        if !new.contains_key(k) {
            d.removed.push((k, join(ov)));
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs_by_key() {
        let old = "aaa.1.ssid=Home\nwireless.1.security=wpa2\nradio.1.channel=36\n";
        let new = "aaa.1.ssid=Home\nwireless.1.security=wpa3\nwireless.2.ssid=Test\n";
        let d = diff(old, new);
        assert_eq!(d.added, vec![("wireless.2.ssid", "Test".into())]);
        assert_eq!(d.removed, vec![("radio.1.channel", "36".into())]);
        assert_eq!(d.changed, vec![("wireless.1.security", "wpa2".into(), "wpa3".into())]);
        assert!(diff(old, old).is_empty());
        assert!(matches!(d.added[0].1, Cow::Borrowed(_)), "single values are borrowed");
        let repeated = diff("a=1\n", "a=1\na=2\n");
        assert_eq!(repeated.changed, vec![("a", "1".into(), Cow::Owned::<str>("1 | 2".into()))]);
        assert_eq!(d.counts(), [1, 1, 1]);
        assert_eq!(diff("x.psk=a", "x.psk=b").summary(), serde_json::json!({ "added": 0, "removed": 0, "changed": 1, "diff": "~ x.psk: <redacted> -> <redacted>\n" }));
        let rendered = d.render("", true);
        assert!(rendered.starts_with("- radio.1.channel=36\n"));
        let secret = diff("aaa.1.wpa.psk=old", "aaa.1.wpa.psk=new").render("", true);
        assert_eq!(secret, "~ aaa.1.wpa.psk: <redacted> -> <redacted>\n");
        assert_eq!(redact("a=1\nmgmt.authkey=abc"), "a=1\nmgmt.authkey=<redacted>");
        assert!(!is_secret("radio.1.max_txpower"));
        assert!(is_secret("x_passphrase"));
        assert!(is_secret("aaa.3.iapp_key") && is_secret("unifi.key"));
        assert!(!is_secret("aaa.3.wpa.key.1.mgmt"));
        assert!(is_secret("snmp.community") && is_secret("community"));
        assert!(is_secret("X_Passphrase") && is_secret("aaa.1.WPA.PSK") && is_secret("Unifi.KEY") && is_secret("a.b_KEY") && is_secret("SNMP.Community"));
        assert!(!is_secret("") && !is_secret("radio.1.ht") && !is_secret("aaa.1.x") && !is_secret("max_x_power"));
        assert_eq!(redact("a=1\n\nb\nc.psk=x=y\n"), "a=1\n\nb\nc.psk=<redacted>");
        assert_eq!(redact("snmp.status=enabled\nsnmp.community=public"), "snmp.status=enabled\nsnmp.community=<redacted>");
    }
}

/// Replays the labelled config pushes captured from real APs (sanitised) and
/// checks that each step's diff is exactly what was observed.
#[cfg(test)]
mod capture_fixtures {
    use super::*;
    use crate::capture::sample::{EXPECTED_PUSHES, check_expectation, fixtures, load, manifest};
    use std::collections::HashMap;

    fn system_cfg(file: &str) -> String {
        let v = load(file);
        assert_eq!(v["_type"], "setparam", "{file}");
        v["system_cfg"].as_str().unwrap().to_string()
    }

    #[test]
    fn each_labelled_change_produces_the_observed_diff() {
        let Some(_) = fixtures() else { return };
        let mut previous: HashMap<String, String> = HashMap::new();
        let mut checked = 0;
        for step in manifest()["steps"].as_array().unwrap() {
            let label = step["label"].as_str().unwrap();
            for push in step["pushes"].as_array().unwrap() {
                let ap = push["ap"].as_str().unwrap().to_string();
                let cfg = system_cfg(push["file"].as_str().unwrap());
                if let Some(expect) = push.get("expect") {
                    let d = diff(previous.get(&ap).expect("baseline first"), &cfg);
                    check_expectation(&format!("step {} ({label}) on AP {ap}", step["step"]), expect, &d);
                    checked += 1;
                }
                previous.insert(ap, cfg);
            }
        }
        assert_eq!(checked, EXPECTED_PUSHES, "every push after the two baselines is checked");
    }

    #[test]
    fn wpa3_transition_duplicates_the_psk_line() {
        let Some(_) = fixtures() else { return };
        // Step 2 on AP B: section 3 is the 2.4 GHz copy of the test SSID.
        let before = system_cfg("2026-10-12T184539.445Z_000026_020000000001_reply-setparam.json");
        let after = system_cfg("2026-10-12T184900.729Z_000094_020000000001_reply-setparam.json");
        let count = |cfg: &str| cfg.lines().filter(|l| l.starts_with("aaa.3.wpa.psk=")).count();
        assert_eq!((count(&before), count(&after)), (1, 2));
        assert!(after.lines().any(|l| l == "aaa.3.wpa.key.1.mgmt=SAE"));
    }
}
