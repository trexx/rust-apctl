//! Dry run: render what apctl would push to an AP and compare it with what the
//! other controller actually pushed, without sending anything.

use std::borrow::Cow;
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use wire::cfgdiff;

/// What the config generator needs for one AP (mirrors `apcfg::Input`).
pub struct RenderRequest<'a> {
    pub state: &'a Value,
    pub device_mac: &'a str,
    pub inform: Option<&'a Value>,
    pub cfgversion: &'a str,
    /// The config the other controller pushed, for constants that identify that
    /// controller rather than describe the AP (its installation ID).
    pub previous_system_cfg: Option<&'a str>,
}

/// The controller as rendered configs describe it. Its URLs are fallbacks
/// only: the host comes from the settings and the AP's inform URL.
pub fn controller(inform_url: String, version: String, reporter_uuid: String) -> apcfg::Controller {
    apcfg::Controller {
        inform_url,
        mgmt_url: "https://unifi:8443".into(),
        stun_url: "stun://unifi:3478/".into(),
        syslog_ip: None,
        version,
        reporter_uuid,
    }
}

/// The real generator (`apcfg`), emulating a given controller version.
pub fn apcfg_renderer(version: String) -> RenderFn {
    Arc::new(move |req: &RenderRequest| {
        let reporter = req
            .previous_system_cfg
            .and_then(|c| c.lines().find_map(|l| l.strip_prefix("unifi.reporterid=")))
            .unwrap_or_default()
            .to_string();
        let controller = controller("http://unifi:8080/inform".into(), version.clone(), reporter);
        let input = apcfg::Input {
            state: req.state,
            device_mac: req.device_mac,
            inform: req.inform,
            cfgversion: req.cfgversion,
            controller: &controller,
        };
        let r = apcfg::render(&input)?;
        Ok((r.mgmt_cfg, r.system_cfg))
    })
}

/// `(mgmt_cfg, system_cfg)` for one AP.
pub type Rendered = (String, String);

/// The config generator, plugged in by `main` (kept behind a function so the
/// engine does not depend on how rendering is done).
pub type RenderFn = Arc<dyn Fn(&RenderRequest) -> anyhow::Result<Rendered> + Send + Sync>;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FieldComparison {
    pub expected_lines: usize,
    pub actual_lines: usize,
    /// Same lines in the same order.
    pub identical: bool,
    /// Same key=value pairs, ignoring order.
    pub same_content: bool,
    /// Identical once lists whose order the other controller does not keep
    /// stable are compared as sets (see `normalise_unordered`).
    pub equivalent: bool,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    /// Redacted key diff from the actual config to ours (`+` only in ours).
    pub diff: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Comparison {
    pub mgmt_cfg: FieldComparison,
    pub system_cfg: FieldComparison,
}

impl Comparison {
    /// Identical, or differing only in the order of unordered lists.
    pub fn matches(&self) -> bool {
        self.mgmt_cfg.equivalent && self.system_cfg.equivalent
    }
}

/// Lists the other controller writes in an arbitrary order that can change
/// between its restarts (they come from unordered sets): the services of an
/// mDNS filter, a VAP's broadcast-filter MACs, and lock-to-AP MAC entries.
/// Their values are sorted within each list, keeping the line positions.
fn normalise_unordered<'a>(lines: &[&'a str]) -> Vec<Cow<'a, str>> {
    let mut out: Vec<Cow<str>> = lines.iter().map(|l| Cow::Borrowed(*l)).collect();
    let mut groups: std::collections::BTreeMap<(&str, &str), Vec<usize>> = Default::default();
    // The `macacl.<k>.acl.<n>` entries that lock a client to an AP.
    let lock2ap: std::collections::HashSet<&str> = lines.iter().filter_map(|l| l.strip_suffix(".type=lock2ap")).collect();
    for (i, line) in lines.iter().enumerate() {
        let key = line.split_once('=').map_or(*line, |(k, _)| k);
        let group = if let Some(n) = list_of(key, "mdns_sd.filter.", "service.", ".name") {
            Some(("mdns", n))
        } else if let Some(n) = list_of(key, "wireless.", "bcfilt.", ".mac") {
            Some(("bcfilt", n))
        } else {
            list_of(key, "macacl.", "acl.", ".mac").filter(|_| key.strip_suffix(".mac").is_some_and(|k| lock2ap.contains(k))).map(|k| ("lock2ap", k))
        };
        if let Some(g) = group {
            groups.entry(g).or_default().push(i);
        }
    }
    for idx in groups.values() {
        let mut values: Vec<&str> = idx.iter().map(|&i| lines[i].split_once('=').map_or("", |(_, v)| v)).collect();
        values.sort_unstable();
        for (&i, v) in idx.iter().zip(values) {
            let (key, old) = lines[i].split_once('=').unwrap_or((lines[i], ""));
            if old != v {
                out[i] = Cow::Owned(format!("{key}={v}"));
            }
        }
    }
    out
}

/// The list a key is an entry of, for keys `<prefix><list>.<middle><index><suffix>`
/// (the list and index one part each): `list`.
fn list_of<'a>(key: &'a str, prefix: &str, middle: &str, suffix: &str) -> Option<&'a str> {
    let (list, rest) = key.strip_prefix(prefix)?.split_once('.')?;
    let index = rest.strip_prefix(middle)?.strip_suffix(suffix)?;
    (!index.contains('.')).then_some(list)
}

/// Line by line the same, or the same once [`normalise_unordered`] sorted the unordered lists.
fn equivalent_lines(o: &[&str], a: &[&str]) -> bool {
    o == a || o.len() == a.len() && normalise_unordered(o) == normalise_unordered(a)
}

/// What [`Comparison::matches`] says of one config, without making the diff.
/// With `redacted`, secrets are not compared: the caller must know they
/// cannot differ.
pub fn equivalent(ours: &str, actual: &str, redacted: bool) -> bool {
    if ours == actual {
        return true;
    }
    let (ours, actual) = masked(ours, actual, redacted);
    equivalent_lines(&lines(&ours), &lines(&actual))
}

/// Both configs, with their secret values masked if `redacted`.
fn masked<'a>(ours: &'a str, actual: &'a str, redacted: bool) -> (Cow<'a, str>, Cow<'a, str>) {
    if redacted { (cfgdiff::redact(ours).into(), cfgdiff::redact(actual).into()) } else { (ours.into(), actual.into()) }
}

fn lines(s: &str) -> Vec<&str> {
    s.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect()
}

/// Compares our config with the actual one. With `redacted`, secret values are
/// masked on both sides first (used when only a redacted copy of the actual
/// config is available).
pub fn compare_field(ours: &str, actual: &str, redacted: bool) -> FieldComparison {
    let (ours, actual) = masked(ours, actual, redacted);
    let (o, a) = (lines(&ours), lines(&actual));
    let d = cfgdiff::diff(&actual, &ours);
    FieldComparison {
        expected_lines: o.len(),
        actual_lines: a.len(),
        identical: o == a,
        same_content: d.is_empty(),
        equivalent: equivalent_lines(&o, &a),
        added: d.added.len(),
        removed: d.removed.len(),
        changed: d.changed.len(),
        diff: d.render("", true),
    }
}

pub fn compare(ours: &Rendered, actual_mgmt: &str, actual_system: &str, redacted: bool) -> Comparison {
    Comparison {
        mgmt_cfg: compare_field(&ours.0, actual_mgmt, redacted),
        system_cfg: compare_field(&ours.1, actual_system, redacted),
    }
}

/// A short human summary of an import snapshot, for the settings page.
pub fn summarize_state(state: &Value) -> Value {
    let count = |k: &str| state[k].as_array().map_or(0, Vec::len);
    let names = |k: &str| -> Vec<Value> {
        state[k].as_array().into_iter().flatten().filter_map(|x| x["name"].as_str().map(|s| Value::from(s.to_string()))).collect()
    };
    serde_json::json!({
        "sites": count("sites"),
        "wlans": names("wlanconf"),
        "networks": names("networkconf"),
        "ap_groups": names("apgroup"),
        "devices": count("devices"),
        "clients": count("clients"),
        "settings": count("setting"),
    })
}

/// Checks that an uploaded document looks like an `informdump import` snapshot.
pub fn validate_state(state: &Value) -> anyhow::Result<()> {
    for k in ["sites", "wlanconf", "networkconf", "setting", "devices"] {
        anyhow::ensure!(state[k].is_array(), "not a controller snapshot: missing `{k}`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_order_content_and_masks_secrets() {
        let actual = "a=1\nb=2\naaa.1.wpa.psk=hunter2\n";
        let same = compare_field("a=1\nb=2\naaa.1.wpa.psk=hunter2", actual, false);
        assert!(same.identical && same.same_content);

        let reordered = compare_field("b=2\na=1\naaa.1.wpa.psk=hunter2", actual, false);
        assert!(!reordered.identical && reordered.same_content);

        let different = compare_field("a=1\nb=3\naaa.1.wpa.psk=other\nc=4", actual, false);
        assert_eq!((different.added, different.removed, different.changed), (1, 0, 2));
        assert!(!different.diff.contains("hunter2") && !different.diff.contains("other"), "{}", different.diff);

        // The other controller's mDNS service order changes between its restarts.
        let cast_zone = "mdns_sd.filter.2.service.1.name=_googlecast._tcp.local\nmdns_sd.filter.2.service.2.name=_googlezone._tcp.local";
        let zone_cast = "mdns_sd.filter.2.service.1.name=_googlezone._tcp.local\nmdns_sd.filter.2.service.2.name=_googlecast._tcp.local";
        let swapped = compare_field(zone_cast, cast_zone, false);
        assert!(!swapped.identical && !swapped.same_content && swapped.equivalent);
        let real_change = compare_field("mdns_sd.filter.2.service.1.name=_airplay._tcp.local", "mdns_sd.filter.2.service.1.name=_googlecast._tcp.local", false);
        assert!(!real_change.equivalent);
        // So do a VAP's broadcast-filter MACs and the lock-to-AP entries, but no other MAC list.
        let acl = |kind: &str, a: &str, b: &str| {
            format!("wireless.1.bcfilt.1.mac={a}\nwireless.1.bcfilt.2.mac={b}\nmacacl.3.acl.1.type={kind}\nmacacl.3.acl.1.mac={a}\nmacacl.3.acl.2.type={kind}\nmacacl.3.acl.2.mac={b}")
        };
        assert!(compare_field(&acl("lock2ap", "aa", "bb"), &acl("lock2ap", "bb", "aa"), false).equivalent);
        assert!(!compare_field(&acl("deny", "aa", "bb"), &acl("deny", "bb", "aa"), false).equivalent);
        assert!(!compare_field("wireless.1.bcfilt.1.mac=aa\nwireless.2.bcfilt.1.mac=bb", "wireless.1.bcfilt.1.mac=bb\nwireless.2.bcfilt.1.mac=aa", false).equivalent, "per VAP");

        // Against a redacted copy, secret values cannot differ.
        let r = compare_field("a=1\nb=2\naaa.1.wpa.psk=other", &cfgdiff::redact(actual), true);
        assert!(r.identical);

        // The quick check agrees with the full comparison.
        for (ours, theirs, redacted) in [(zone_cast, cast_zone, false), ("mdns_sd.filter.2.service.1.name=_airplay._tcp.local", cast_zone, false), ("a=1\nb=2\naaa.1.wpa.psk=other", actual, true), ("a=1\nb=3", "a=1\nb=2", false)] {
            assert_eq!(equivalent(ours, theirs, redacted), compare_field(ours, theirs, redacted).equivalent, "{ours:?}");
        }
    }

    #[test]
    fn validates_snapshots() {
        assert!(validate_state(&serde_json::json!({ "devices": [] })).is_err());
        let ok = serde_json::json!({ "sites": [], "wlanconf": [{ "name": "Home" }], "networkconf": [], "setting": [], "devices": [] });
        assert!(validate_state(&ok).is_ok());
        assert_eq!(summarize_state(&ok)["wlans"][0], "Home");
    }
}
