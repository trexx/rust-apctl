//! Turns decoded payloads from a real network into shareable test fixtures.
//!
//! Every identifying or secret value is replaced with a stable fake: the same
//! input always maps to the same output within one run, so diffs between
//! fixtures stay meaningful. After rewriting, the output is scanned for every
//! original value that was replaced; any survivor aborts the run.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;

use wire::cfgdiff;

pub struct Sanitizer {
    /// original -> replacement, per category so fakes stay readable.
    maps: HashMap<&'static str, BTreeMap<String, String>>,
    mac: Regex,
    mac_bare: Regex,
    uuid: Regex,
    hex: Regex,
    ipv6: Regex,
    /// Domain suffixes to replace (e.g. the controller's DNS name).
    domains: Vec<String>,
}

const KEEP_MACS: [&str; 2] = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"];

impl Sanitizer {
    pub fn new(domains: Vec<String>) -> Self {
        Sanitizer {
            maps: HashMap::new(),
            mac: Regex::new(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b").unwrap(),
            mac_bare: Regex::new(r"(?i)\b[0-9a-f]{12}\b").unwrap(),
            uuid: Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap(),
            hex: Regex::new(r"(?i)\b[0-9a-f]{16,}\b").unwrap(),
            ipv6: Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b").unwrap(),
            domains,
        }
    }

    fn fake(&mut self, kind: &'static str, original: &str, make: impl FnOnce(usize) -> String) -> String {
        let map = self.maps.entry(kind).or_default();
        if let Some(f) = map.get(original) {
            return f.clone();
        }
        let f = make(map.len() + 1);
        map.insert(original.to_string(), f.clone());
        f
    }

    fn fake_mac(&mut self, mac: &str) -> String {
        let lower = mac.to_ascii_lowercase();
        if KEEP_MACS.contains(&lower.as_str()) {
            return lower;
        }
        // Locally administered unicast range, numbered by first appearance.
        self.fake("mac", &lower, |n| format!("02:00:00:00:{:02x}:{:02x}", n >> 8, n & 0xff))
    }

    /// Rewrites identifiers that can appear inside any string value.
    fn scrub(&mut self, s: &str) -> String {
        let mut out = s.to_string();
        // Hostnames and SSIDs learned from their own fields can also appear inside
        // other values (e.g. `resolv.host.1.name`). Longest first, so a name that
        // contains another name is replaced whole.
        let mut known: Vec<(String, String)> = ["name", "ssid"]
            .iter()
            .filter_map(|k| self.maps.get(k))
            .flat_map(|m| m.iter().filter(|(o, _)| o.len() >= 4).map(|(o, f)| (o.clone(), f.clone())))
            .collect();
        known.sort_by_key(|(o, _)| std::cmp::Reverse(o.len()));
        for (original, fake) in known {
            if out.contains(&original) && out != fake {
                out = out.replace(&original, &fake);
            }
        }
        for d in self.domains.clone() {
            out = out.replace(&d, "example.net");
        }
        out = replace_all(&self.uuid.clone(), &out, |m| {
            self.fake("uuid", &m.to_ascii_lowercase(), |n| format!("00000000-0000-4000-8000-{n:012x}"))
        });
        out = replace_all(&self.mac.clone(), &out, |m| self.fake_mac(m));
        // A bare 12-hex string is only treated as a MAC when we already know that MAC
        // (serial numbers on these APs are the MAC without colons).
        out = replace_all(&self.mac_bare.clone(), &out, |m| {
            let colon: String = m
                .to_ascii_lowercase()
                .as_bytes()
                .chunks(2)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(":");
            match self.maps.get("mac").and_then(|mm| mm.get(&colon)).cloned() {
                Some(fake) => {
                    let bare = fake.replace(':', "");
                    if m.chars().any(|c| c.is_ascii_uppercase()) { bare.to_ascii_uppercase() } else { bare }
                }
                None => m.to_string(),
            }
        });
        out = replace_all(&self.hex.clone(), &out, |m| {
            let len = m.len();
            self.fake("hex", &m.to_ascii_lowercase(), |n| format!("{n:0len$x}"))
        });
        let mac_shape = Regex::new(r"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$").unwrap();
        out = replace_all(&self.ipv6.clone(), &out, |m| {
            // Keep MACs (already handled), link-local and the like; global
            // addresses would reveal the ISP prefix.
            if mac_shape.is_match(m) || m.to_ascii_lowercase().starts_with("fe80") || m.starts_with("::") {
                m.to_string()
            } else {
                self.fake("ipv6", &m.to_ascii_lowercase(), |n| format!("2001:db8::{n:x}"))
            }
        });
        out
    }

    /// Value for a named field: secrets, SSIDs and hostnames get category fakes.
    fn field(&mut self, key: &str, value: &str) -> String {
        let k = key.to_ascii_lowercase();
        let last = k.rsplit('.').next().unwrap_or(&k);
        // A bare `key` field names a settings document (`"key": "country"`); only
        // dotted config keys ending in `.key` hold secrets.
        let is_secret = cfgdiff::is_secret(&k) && k != "key";
        if value.is_empty() {
            value.to_string()
        } else if is_secret
            // The device SSH account name (stored as x_ssh_username in the controller).
            || (k.starts_with("users.") && last == "name")
            || (k.starts_with("cron.") && last == "user")
        {
            self.fake("secret", value, |n| format!("secret-{n}"))
        } else if last == "ssid" || last == "essid" {
            self.fake("ssid", value, |n| format!("ssid-{n}"))
        } else if last == "hostname" {
            self.fake("name", value, |n| format!("name-{n}"))
        } else {
            self.scrub(value)
        }
    }

    /// Rewrites a `key=value` config blob line by line.
    fn cfg(&mut self, blob: &str) -> String {
        blob.lines()
            .map(|l| match l.split_once('=') {
                Some((k, v)) => format!("{k}={}", self.field(k, v)),
                None => self.scrub(l),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn json(&mut self, v: &Value) -> Value {
        self.json_at("", "", v)
    }

    /// `parent` is the key of the enclosing object or array (e.g. `clients`).
    fn json_at(&mut self, parent: &str, key: &str, v: &Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), self.json_at(key, k, v))).collect()),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.json_at(parent, key, x)).collect()),
            Value::String(s) if key.ends_with("_cfg") => Value::String(self.cfg(s)),
            // Names people gave their devices in the other controller.
            Value::String(s) if key == "name" && (parent == "clients" || parent == "user") && !s.is_empty() => {
                Value::String(self.fake("alias", s, |n| format!("alias-{n}")))
            }
            Value::String(s) => Value::String(self.field(key, s)),
            other => other.clone(),
        }
    }

    pub fn file_name(&mut self, name: &str) -> String {
        // `_` is a regex word character, so `\b` would not split `_7845583c52bc_`.
        name.split('_').map(|part| self.scrub(part)).collect::<Vec<_>>().join("_")
    }

    /// Fails if any original value we replaced still appears in `text`.
    pub fn check_clean(&self, text: &str, what: &str) -> Result<()> {
        let lower = text.to_ascii_lowercase();
        for (kind, map) in &self.maps {
            for original in map.keys() {
                // Names and SSIDs under 4 characters ("tv", "Mac") collide with
                // ordinary words such as the JSON key "mac"; they identify nothing.
                if *kind != "secret" && original.chars().count() < 4 {
                    continue;
                }
                let original = original.to_ascii_lowercase();
                let found = if *kind == "secret" { contains_value(&lower, &original) } else { contains_word(&lower, &original) };
                if found {
                    bail!("{what}: a {kind} value ({} chars) survived sanitising", original.len());
                }
            }
        }
        Ok(())
    }
}

/// Whole-word match: names inside longer identifiers (a hostname inside an
/// mDNS service code) are not leaks.
fn contains_word(text: &str, value: &str) -> bool {
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    text.match_indices(value).any(|(i, _)| !is_word(text[..i].chars().next_back()) && !is_word(text[i + value.len()..].chars().next()))
}

/// Substring match for long values; short values (e.g. an SSID called "test")
/// must stand alone, so they don't match inside ordinary words.
fn contains_value(text: &str, value: &str) -> bool {
    if value.len() < 3 {
        return false;
    }
    if value.len() >= 8 {
        return text.contains(value);
    }
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    text.match_indices(value).any(|(i, _)| {
        !is_word(text[..i].chars().next_back()) && !is_word(text[i + value.len()..].chars().next())
    })
}

fn replace_all(re: &Regex, s: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for m in re.find_iter(s) {
        out.push_str(&s[last..m.start()]);
        out.push_str(&f(m.as_str()));
        last = m.end();
    }
    out.push_str(&s[last..]);
    out
}

/// Sanitises the named JSON files from `input` into `output`.
pub fn run(input: &Path, output: &Path, files: &[String], domains: Vec<String>, seed_macs: &[String]) -> Result<()> {
    let mut s = Sanitizer::new(domains);
    // Seed known device MACs first so they get the lowest, stable fake numbers.
    for m in seed_macs {
        s.fake_mac(m);
    }
    std::fs::create_dir_all(output)?;
    let mut docs = Vec::new();
    for name in files {
        let path = input.join(name);
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let v: Value = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        docs.push((name, v));
    }
    // First pass only learns the hostnames and SSIDs, so the second pass can
    // also replace them where they show up inside unrelated values.
    for (_, v) in &docs {
        s.json(v);
    }
    let mut written = Vec::new();
    for (name, v) in &docs {
        let clean = serde_json::to_string_pretty(&s.json(v))? + "\n";
        let out_name = s.file_name(name);
        written.push((output.join(&out_name), clean));
    }
    // Check everything against the final maps, so values first seen in a later
    // file are also caught in earlier ones.
    for (path, text) in &written {
        s.check_clean(text, &path.display().to_string())?;
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        s.check_clean(&name, &format!("file name {name}"))?;
    }
    for (path, text) in written {
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    for (kind, map) in &s.maps {
        eprintln!("replaced {} distinct {kind} values", map.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn replaces_identifiers_consistently_and_checks_for_leaks() {
        let mut s = Sanitizer::new(vec!["home.example.org".into()]);
        let v = json!({
            "mac": "78:45:58:3c:52:bc",
            "serial": "7845583C52BC",
            "hostname": "kitchen-tv",
            "inform_url": "http://unifi.home.example.org:8080/inform",
            "x_authkey": "00112233445566778899aabbccddeeff",
            "system_cfg": "users.1.name=admin42\ncron.1.user=admin42\naaa.1.ssid=My Home\naaa.1.wpa.psk=hunter22\nwireless.1.bcfilt.1.mac=ff:ff:ff:ff:ff:ff\nwireless.2.bcfilt.1.mac=78:45:58:3c:52:bc\nunifi.siteid=6a1b2c3d4e5f60718293a4b5",
            "vap_table": [{"essid": "My Home", "sta_table": [{"mac": "AA:BB:CC:DD:EE:FF"}]}],
        });
        let out = s.json(&v);
        let text = out.to_string();
        assert_eq!(out["mac"], "02:00:00:00:00:01");
        assert_eq!(out["serial"], "020000000001");
        assert_eq!(out["hostname"], "name-1");
        assert_eq!(out["inform_url"], "http://unifi.example.net:8080/inform");
        assert_eq!(out["x_authkey"], "secret-1");
        assert_eq!(out["vap_table"][0]["essid"], "ssid-1");
        let cfg = out["system_cfg"].as_str().unwrap();
        assert!(cfg.contains("aaa.1.ssid=ssid-1"), "{cfg}");
        assert!(cfg.contains("users.1.name=secret-2") && cfg.contains("cron.1.user=secret-2"), "{cfg}");
        assert!(cfg.contains("aaa.1.wpa.psk=secret-3"));
        assert!(cfg.contains("bcfilt.1.mac=ff:ff:ff:ff:ff:ff"));
        assert!(cfg.contains("bcfilt.1.mac=02:00:00:00:00:01"));
        assert!(!cfg.contains("6a1b2c3d"));
        s.check_clean(&text, "test").unwrap();
        assert!(s.check_clean("contains hunter22", "leak").is_err());
        assert_eq!(s.file_name("t_7845583c52bc_x.json"), "t_020000000001_x.json");
        assert_eq!(s.json(&json!({ "key": "country" }))["key"], "country", "a settings document's name");
        let v = s.json(&json!({ "clients": [{ "name": "Dad's phone" }], "wlanconf": [{ "name": "x" }] }));
        assert_eq!(v["clients"][0]["name"], "alias-1");
        assert!(contains_word("ssid=chromecast", "chromecast") && !contains_word("_googlecast._tcp", "googlecas"));
        assert_eq!(s.scrub("host kitchen-tv.lan"), "host name-1.lan");
        assert!(contains_value("ssid=test\n", "test") && !contains_value("testdata/x", "test"));
    }
}
