//! Turns decoded payloads from a real network into shareable test fixtures.
//!
//! Every identifying or secret value is replaced with a stable fake: the same
//! input always maps to the same output within one run, so diffs between
//! fixtures stay meaningful. After rewriting, the output is scanned for every
//! original value that was replaced; any survivor aborts the run.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;

use wire::cfgdiff;

/// original -> replacement, per category so fakes stay readable.
type Maps = HashMap<&'static str, BTreeMap<String, String>>;

pub struct Sanitizer {
    maps: Maps,
    mac: Regex,
    mac_bare: Regex,
    mac_shape: Regex,
    uuid: Regex,
    hex: Regex,
    ipv6: Regex,
    ipv4: Regex,
    /// Domain suffixes to replace (e.g. the controller's DNS name).
    domains: Vec<String>,
    /// Known hostnames and SSIDs as (original, fake), longest first, and the sizes
    /// of the two maps it was built from (the maps only grow).
    known: Vec<(String, String)>,
    known_sizes: (usize, usize),
}

const KEEP_MACS: [&str; 2] = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"];

impl Sanitizer {
    pub fn new(domains: Vec<String>) -> Self {
        Sanitizer {
            maps: HashMap::new(),
            mac: Regex::new(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b").unwrap(),
            mac_bare: Regex::new(r"(?i)\b[0-9a-f]{12}\b").unwrap(),
            mac_shape: Regex::new(r"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$").unwrap(),
            uuid: Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap(),
            hex: Regex::new(r"(?i)\b[0-9a-f]{16,}\b").unwrap(),
            ipv6: Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b").unwrap(),
            ipv4: Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap(),
            domains,
            known: Vec::new(),
            known_sizes: (0, 0),
        }
    }

    fn fake(&mut self, kind: &'static str, original: &str, make: impl FnOnce(usize) -> String) -> String {
        fake(&mut self.maps, kind, original, make)
    }

    fn fake_mac(&mut self, mac: &str) -> String {
        fake_mac(&mut self.maps, mac)
    }

    /// Hostnames and SSIDs learned from their own fields can also appear inside
    /// other values (e.g. `resolv.host.1.name`). Longest first, so a name that
    /// contains another name is replaced whole. Rebuilt only when a map grew.
    fn refresh_known(&mut self) {
        let size = |k: &str| self.maps.get(k).map_or(0, BTreeMap::len);
        let sizes = (size("name"), size("ssid"));
        if sizes == self.known_sizes {
            return;
        }
        self.known = ["name", "ssid"]
            .iter()
            .filter_map(|k| self.maps.get(k))
            .flat_map(|m| m.iter().filter(|(o, _)| o.len() >= 4).map(|(o, f)| (o.clone(), f.clone())))
            .collect();
        self.known.sort_by_key(|(o, _)| std::cmp::Reverse(o.len()));
        self.known_sizes = sizes;
    }

    /// Rewrites identifiers that can appear inside any string value.
    fn scrub(&mut self, s: &str) -> String {
        let mut out = s.to_string();
        self.refresh_known();
        for (original, fake) in &self.known {
            if out.contains(original.as_str()) && out != *fake {
                out = out.replace(original.as_str(), fake);
            }
        }
        for d in &self.domains {
            out = out.replace(d.as_str(), "example.net");
        }
        let maps = &mut self.maps;
        out = replace_all(&self.uuid, &out, |m| fake(maps, "uuid", &m.to_ascii_lowercase(), |n| format!("00000000-0000-4000-8000-{n:012x}")));
        out = replace_all(&self.mac, &out, |m| fake_mac(maps, m));
        // A bare 12-hex string is only treated as a MAC when we already know that MAC
        // (serial numbers on these APs are the MAC without colons).
        out = replace_all(&self.mac_bare, &out, |m| {
            if maps.get("mac").is_some_and(|mm| mm.contains_key(&colon_mac(m))) { fake_bare_mac(maps, m) } else { m.to_string() }
        });
        out = replace_all(&self.hex, &out, |m| {
            let len = m.len();
            fake(maps, "hex", &m.to_ascii_lowercase(), |n| format!("{n:0len$x}"))
        });
        let mac_shape = &self.mac_shape;
        out = replace_all(&self.ipv6, &out, |m| {
            // Keep MACs (already handled), link-local and the like; global
            // addresses would reveal the ISP prefix.
            if mac_shape.is_match(m) || m.to_ascii_lowercase().starts_with("fe80") || m.starts_with("::") {
                m.to_string()
            } else {
                fake(maps, "ipv6", &m.to_ascii_lowercase(), |n| format!("2001:db8::{n:x}"))
            }
        });
        // Public IPv4 addresses (the WAN address, the ISP's DNS servers) likewise;
        // private ones say nothing about where the network is.
        let mut ipv4 = String::with_capacity(out.len());
        let mut last = 0;
        for m in self.ipv4.find_iter(&out) {
            let (a, b) = (m.start(), m.end());
            if is_public_ipv4(m.as_str()) && !in_longer_dotted(&out, a, b) {
                ipv4.push_str(&out[last..a]);
                ipv4.push_str(&fake(maps, "ipv4", m.as_str(), fake_ipv4));
                last = b;
            }
        }
        if last > 0 {
            ipv4.push_str(&out[last..]);
            out = ipv4;
        }
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
        } else if matches!(last, "serial" | "serialno" | "serial_no") && self.mac_bare.is_match(value) && value.len() == 12 {
            // Serial numbers are the device's MAC without colons, including those
            // of neighbouring APs in scan results: their real BSSIDs follow from them.
            fake_bare_mac(&mut self.maps, value)
        } else if last == "fingerprint" {
            // SSH host key fingerprints identify the device.
            self.fake("fingerprint", value, |n| format!("SHA256:fingerprint-{n}"))
        } else if last == "qrid" {
            self.fake("qrid", value, |n| format!("qrid-{n}"))
        } else if last == "oui" {
            // Manufacturer names of clients profile the household.
            self.fake("vendor", value, |n| format!("vendor-{n}"))
        } else if last == "base64" {
            // Binary UUIDs (`external_id`) as MongoDB exports them.
            self.fake("uuid64", value, |n| format!("{n:0>22}=="))
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
            // mDNS services a client announced: device IDs hide in their names
            // (`_FC9F5ED42C8A._tcp.local`); plain service types are kept.
            Value::String(s) if key == "name" && parent == "services" && !is_service_type(s) => {
                Value::String(self.fake("service", s, |n| format!("_service-{n}._tcp.local")))
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
    #[cfg(test)]
    pub fn check_clean(&self, text: &str, what: &str) -> Result<()> {
        self.leak_check().check(text, what)
    }

    /// The replaced values to look for, prepared once for checking many texts.
    pub fn leak_check(&self) -> LeakCheck {
        let mut originals = Vec::new();
        for (kind, map) in &self.maps {
            for original in map.keys() {
                // Names and SSIDs under 4 characters ("tv", "Mac") collide with
                // ordinary words such as the JSON key "mac"; they identify nothing.
                if *kind != "secret" && original.chars().count() < 4 {
                    continue;
                }
                let original = original.to_ascii_lowercase();
                // MACs also appear without colons (serial numbers, file names).
                let bare = (*kind == "mac").then(|| original.replace(':', ""));
                originals.push((*kind, original, bare));
            }
        }
        LeakCheck { originals }
    }
}

/// The original values a sanitiser replaced, lowercased.
pub struct LeakCheck {
    originals: Vec<(&'static str, String, Option<String>)>,
}

impl LeakCheck {
    /// Fails if any of the originals still appears in `text`.
    pub fn check(&self, text: &str, what: &str) -> Result<()> {
        let lower = text.to_ascii_lowercase();
        for (kind, original, bare) in &self.originals {
            let found = match *kind {
                "secret" => contains_value(&lower, original),
                "ipv4" => contains_ipv4(&lower, original),
                _ => contains_word(&lower, original),
            };
            if found || bare.as_ref().is_some_and(|b| lower.contains(b.as_str())) {
                bail!("{what}: a {kind} value ({} chars) survived sanitising", original.len());
            }
        }
        Ok(())
    }
}

fn fake(maps: &mut Maps, kind: &'static str, original: &str, make: impl FnOnce(usize) -> String) -> String {
    let map = maps.entry(kind).or_default();
    if let Some(f) = map.get(original) {
        return f.clone();
    }
    let f = make(map.len() + 1);
    map.insert(original.to_string(), f.clone());
    f
}

fn fake_mac(maps: &mut Maps, mac: &str) -> String {
    let lower = mac.to_ascii_lowercase();
    if KEEP_MACS.contains(&lower.as_str()) {
        return lower;
    }
    // Locally administered unicast range, numbered by first appearance.
    fake(maps, "mac", &lower, |n| format!("02:00:00:00:{:02x}:{:02x}", n >> 8, n & 0xff))
}

/// `aabbccddeeff` (any case) as `aa:bb:cc:dd:ee:ff`.
fn colon_mac(bare: &str) -> String {
    bare.to_ascii_lowercase().as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":")
}

/// A MAC written without colons (as in serial numbers), keeping its case.
fn fake_bare_mac(maps: &mut Maps, bare: &str) -> String {
    let fake = fake_mac(maps, &colon_mac(bare)).replace(':', "");
    if bare.chars().any(|c| c.is_ascii_uppercase()) { fake.to_ascii_uppercase() } else { fake }
}

/// A plain mDNS service type such as `_googlecast._tcp.local`, with no device ID in it.
fn is_service_type(name: &str) -> bool {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let id_like = |l: &str| {
        let l = l.trim_start_matches('_');
        l.len() >= 6 && l.chars().all(|c| c.is_ascii_hexdigit())
    };
    matches!(labels.as_slice(), [service, proto, "local"] if service.starts_with('_') && matches!(*proto, "_tcp" | "_udp"))
        && labels.iter().all(|l| !id_like(l) && *l == l.to_ascii_lowercase())
}

/// An IPv4 address that tells where a network is: not private, loopback, link-local,
/// multicast or reserved (netmasks such as 255.255.255.0 are reserved), nor one of
/// the documentation and benchmarking ranges the fakes come from.
fn is_public_ipv4(s: &str) -> bool {
    let Ok(ip) = s.parse::<Ipv4Addr>() else { return false };
    let [a, b, ..] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        || (a == 198 && (b == 18 || b == 19)))
}

/// The `n`-th (from 1) public IPv4 address's fake: the documentation ranges, then the
/// benchmarking range.
fn fake_ipv4(n: usize) -> String {
    let i = n - 1;
    match ["192.0.2", "198.51.100", "203.0.113"].get(i / 254) {
        Some(net) => format!("{net}.{}", i % 254 + 1),
        None => {
            let j = i - 3 * 254;
            format!("198.{}.{}.{}", 18 + j / (256 * 254) % 2, j / 254 % 256, j % 254 + 1)
        }
    }
}

/// Whether the address-shaped `text[a..b]` is part of a longer dotted number (an SNMP
/// OID, a version such as 1.2.3.4.5), which is not an address.
fn in_longer_dotted(text: &str, a: usize, b: usize) -> bool {
    let (before, after) = (&text.as_bytes()[..a], &text.as_bytes()[b..]);
    matches!(before, [.., d, b'.'] if d.is_ascii_digit()) || matches!(after, [b'.', d, ..] if d.is_ascii_digit())
}

/// [`contains_word`] for an IPv4 address, which, like the sanitiser, does not count one
/// inside a longer dotted number.
fn contains_ipv4(text: &str, ip: &str) -> bool {
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    text.match_indices(ip).any(|(i, _)| {
        let end = i + ip.len();
        !is_word(text[..i].chars().next_back()) && !is_word(text[end..].chars().next()) && !in_longer_dotted(text, i, end)
    })
}

/// Whole-word match: names inside longer identifiers (a hostname inside an
/// mDNS service code) are not leaks.
fn contains_word(text: &str, value: &str) -> bool {
    // `_` joins identifier parts (`google_chromecast` is one word).
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
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
    let leaks = s.leak_check();
    for (path, text) in &written {
        leaks.check(text, &path.display().to_string())?;
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        leaks.check(&name, &format!("file name {name}"))?;
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
            "vap_table": [{"essid": "My Home", "sta_table": [{"mac": "AA:BB:CC:DD:EE:FF", "multicast": {"services": [
                {"name": "_googlecast._tcp.local"}, {"name": "_A1B2C3D4E5F6._tcp.local"}, {"name": "_77AB12CD._sub._googlecast._tcp"}]}}]}],
            "radio_table": [{"scan_table": [{"bssid": "f6:92:bf:22:33:44", "serialno": "F492BF223344"}]}],
            "fingerprint": "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            "qrid": "Xy7Qa",
            "clients": [{ "oui": "Example Devices Ltd", "mac": "00:11:22:33:44:55" }],
            "external_id": { "$binary": { "base64": "qR9+x3ytPgeIyDW5NH4lkw==", "subType": "04" } },
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
        let services = &out["vap_table"][0]["sta_table"][0]["multicast"]["services"];
        assert_eq!(services[0]["name"], "_googlecast._tcp.local", "a plain service type is kept");
        assert_eq!(services[1]["name"], "_service-1._tcp.local");
        assert_eq!(services[2]["name"], "_service-2._tcp.local");
        let serial = out["radio_table"][0]["scan_table"][0]["serialno"].as_str().unwrap();
        assert!(serial.starts_with("020000000") && serial.chars().all(|c| !c.is_ascii_lowercase()), "a neighbour's serial: {serial}");
        assert_eq!(out["fingerprint"], "SHA256:fingerprint-1");
        assert_eq!(out["qrid"], "qrid-1");
        assert_eq!(out["clients"][0]["oui"], "vendor-1");
        assert_ne!(out["external_id"]["$binary"]["base64"], "qR9+x3ytPgeIyDW5NH4lkw==");
        s.check_clean(&text, "test").unwrap();
        assert!(s.check_clean("contains hunter22", "leak").is_err());
        assert_eq!(s.file_name("t_7845583c52bc_x.json"), "t_020000000001_x.json");
        assert_eq!(s.json(&json!({ "key": "country" }))["key"], "country", "a settings document's name");
        let v = s.json(&json!({ "clients": [{ "name": "Dad's phone" }], "wlanconf": [{ "name": "x" }] }));
        assert_eq!(v["clients"][0]["name"], "alias-1");
        assert!(contains_word("ssid=chromecast", "chromecast") && !contains_word("_googlecast._tcp", "googlecas"));
        assert!(!contains_word("code: google_chromecast", "chromecast"));
        assert_eq!(s.scrub("host kitchen-tv.lan"), "host name-1.lan");
        assert!(contains_value("ssid=test\n", "test") && !contains_value("testdata/x", "test"));
    }

    #[test]
    fn public_ipv4_addresses_become_documentation_addresses() {
        let mut s = Sanitizer::new(Vec::new());
        let v = json!({
            "wan_ip": "81.2.69.160",
            "dns": ["81.2.69.160", "9.9.9.9", "192.168.1.1", "10.0.0.2", "172.16.4.4", "127.0.0.1", "169.254.1.1"],
            "system_cfg": "resolv.nameserver.1=9.9.9.9\nnet.netmask=255.255.255.0\nmcast=239.255.255.250\nroute=0.0.0.0",
            "kept": ["1.3.6.1.4.1.41112", "version 4.3.2.1.5", "192.0.2.7", "8.8.8.8x", "300.1.1.1"],
            "inform_url": "http://81.2.69.160:8080/inform",
        });
        let out = s.json(&v);
        assert_eq!(out["wan_ip"], "192.0.2.1");
        assert_eq!(out["dns"], json!(["192.0.2.1", "192.0.2.2", "192.168.1.1", "10.0.0.2", "172.16.4.4", "127.0.0.1", "169.254.1.1"]));
        assert_eq!(out["system_cfg"], "resolv.nameserver.1=192.0.2.2\nnet.netmask=255.255.255.0\nmcast=239.255.255.250\nroute=0.0.0.0");
        assert_eq!(out["kept"], v["kept"]);
        assert_eq!(out["inform_url"], "http://192.0.2.1:8080/inform");
        s.check_clean(&out.to_string(), "test").unwrap();
        assert!(s.check_clean("dns 9.9.9.9", "leak").is_err());
        assert!(s.check_clean("oid 1.9.9.9.9", "not an address").is_ok());
        assert_eq!((fake_ipv4(254), fake_ipv4(255), fake_ipv4(763), fake_ipv4(763 + 254)), ("192.0.2.254".into(), "198.51.100.1".into(), "198.18.0.1".into(), "198.18.1.1".into()));
    }
}
