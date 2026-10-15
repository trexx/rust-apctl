//! Diffs `system_cfg` / `mgmt_cfg` blobs, which are newline-separated `key=value` lines.

use std::collections::BTreeMap;
use std::fmt::Write;

pub fn parse(cfg: &str) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in cfg.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        map.entry(k.to_string()).or_default().push(v.to_string());
    }
    map
}

#[derive(Debug, Default, PartialEq)]
pub struct Diff {
    pub added: Vec<(String, String)>,
    pub removed: Vec<(String, String)>,
    pub changed: Vec<(String, String, String)>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Renders the diff with `+`, `-` and `~` markers, one key per line, sorted by key.
    /// With `redact`, values of secret-looking keys are masked.
    pub fn render(&self, indent: &str, redact: bool) -> String {
        let show = |k: &str, v: &str| if redact && is_secret(k) { "<redacted>".to_string() } else { v.to_string() };
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

/// Keys whose values are credentials (PSKs, RADIUS secrets, authkeys, passwords).
pub fn is_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    // `x_` marks secret fields in the controller's database, but only as a prefix
    // (`max_txpower` must stay visible).
    let last = k.rsplit('.').next().unwrap_or("");
    k.split('.').any(|seg| seg.starts_with("x_"))
        || last == "key"
        || last.ends_with("_key")
        || ["psk", "passphrase", "secret", "authkey", "password", "passwd", "syslog_key", "sae_"]
            .iter()
            .any(|s| k.contains(s))
}

/// Masks secret values in a whole `key=value` blob.
pub fn redact(cfg: &str) -> String {
    cfg.lines()
        .map(|l| match l.split_once('=') {
            Some((k, _)) if is_secret(k) => format!("{k}=<redacted>"),
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn diff(old: &str, new: &str) -> Diff {
    let (old, new) = (parse(old), parse(new));
    let mut d = Diff::default();
    let join = |v: &Vec<String>| v.join(" | ");
    for (k, nv) in &new {
        match old.get(k) {
            None => d.added.push((k.clone(), join(nv))),
            Some(ov) if ov != nv => d.changed.push((k.clone(), join(ov), join(nv))),
            _ => {}
        }
    }
    for (k, ov) in &old {
        if !new.contains_key(k) {
            d.removed.push((k.clone(), join(ov)));
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
        assert_eq!(d.added, vec![("wireless.2.ssid".into(), "Test".into())]);
        assert_eq!(d.removed, vec![("radio.1.channel".into(), "36".into())]);
        assert_eq!(d.changed, vec![("wireless.1.security".into(), "wpa2".into(), "wpa3".into())]);
        assert!(diff(old, old).is_empty());
        let rendered = d.render("", true);
        assert!(rendered.starts_with("- radio.1.channel=36\n"));
        let secret = diff("aaa.1.wpa.psk=old", "aaa.1.wpa.psk=new").render("", true);
        assert_eq!(secret, "~ aaa.1.wpa.psk: <redacted> -> <redacted>\n");
        assert_eq!(redact("a=1\nmgmt.authkey=abc"), "a=1\nmgmt.authkey=<redacted>");
        assert!(!is_secret("radio.1.max_txpower"));
        assert!(is_secret("x_passphrase"));
        assert!(is_secret("aaa.3.iapp_key") && is_secret("unifi.key"));
        assert!(!is_secret("aaa.3.wpa.key.1.mgmt"));
    }
}

/// Replays the labelled config pushes captured from real APs (sanitised) and
/// checks that each step's diff is exactly what was observed.
#[cfg(test)]
mod capture_fixtures {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// The sanitised captures, kept outside the repository: `$APCTL_TESTDATA/2026-10-12-u6m-8.8.11`.
    fn fixtures() -> Option<PathBuf> {
        let dir = PathBuf::from(std::env::var_os("APCTL_TESTDATA")?).join("2026-10-12-u6m-8.8.11");
        if !dir.is_dir() {
            eprintln!("skipped: no capture fixtures in {}", dir.display());
            return None;
        }
        Some(dir)
    }

    fn dir() -> PathBuf {
        fixtures().expect("capture fixtures")
    }

    fn system_cfg(file: &str) -> String {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(dir().join(file)).unwrap()).unwrap();
        assert_eq!(v["_type"], "setparam", "{file}");
        v["system_cfg"].as_str().unwrap().to_string()
    }

    fn keys(v: &[(String, String)]) -> Vec<&str> {
        v.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn each_labelled_change_produces_the_observed_diff() {
        let Some(_) = fixtures() else { return };
        let manifest: Value =
            serde_json::from_str(&std::fs::read_to_string(dir().join("manifest.json")).unwrap()).unwrap();
        let mut previous: HashMap<String, String> = HashMap::new();
        let mut checked = 0;
        for step in manifest["steps"].as_array().unwrap() {
            let label = step["label"].as_str().unwrap();
            for push in step["pushes"].as_array().unwrap() {
                let ap = push["ap"].as_str().unwrap().to_string();
                let cfg = system_cfg(push["file"].as_str().unwrap());
                if let Some(expect) = push.get("expect") {
                    let d = diff(previous.get(&ap).expect("baseline first"), &cfg);
                    let ctx = format!("step {} ({label}) on AP {ap}", step["step"]);
                    if let Some(c) = expect.get("counts") {
                        let got = [d.added.len(), d.removed.len(), d.changed.len()];
                        let want: Vec<usize> = c.as_array().unwrap().iter().map(|n| n.as_u64().unwrap() as usize).collect();
                        assert_eq!(got.to_vec(), want, "{ctx}: [added, removed, changed]");
                    } else {
                        let list = |name: &str| -> Vec<String> {
                            expect.get(name).and_then(Value::as_array).map(|a| {
                                a.iter().map(|s| s.as_str().unwrap().to_string()).collect()
                            }).unwrap_or_default()
                        };
                        let changed: Vec<&str> = d.changed.iter().map(|(k, ..)| k.as_str()).collect();
                        assert_eq!(changed, list("changed"), "{ctx}: changed");
                        assert_eq!(keys(&d.added), list("added"), "{ctx}: added");
                        assert_eq!(keys(&d.removed), list("removed"), "{ctx}: removed");
                    }
                    checked += 1;
                }
                previous.insert(ap, cfg);
            }
        }
        assert_eq!(checked, 22, "every push after the two baselines is checked");
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
