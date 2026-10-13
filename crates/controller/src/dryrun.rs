//! Dry run: render what apctl would push to an AP and compare it with what the
//! other controller actually pushed, without sending anything.

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
    pub fn matches(&self) -> bool {
        self.mgmt_cfg.identical && self.system_cfg.identical
    }
}

fn lines(s: &str) -> Vec<&str> {
    s.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect()
}

/// Compares our config with the actual one. With `redacted`, secret values are
/// masked on both sides first (used when only a redacted copy of the actual
/// config is available).
pub fn compare_field(ours: &str, actual: &str, redacted: bool) -> FieldComparison {
    let (ours, actual) = if redacted { (cfgdiff::redact(ours), cfgdiff::redact(actual)) } else { (ours.to_string(), actual.to_string()) };
    let (o, a) = (lines(&ours), lines(&actual));
    let d = cfgdiff::diff(&actual, &ours);
    FieldComparison {
        expected_lines: o.len(),
        actual_lines: a.len(),
        identical: o == a,
        same_content: d.is_empty(),
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

        // Against a redacted copy, secret values cannot differ.
        let r = compare_field("a=1\nb=2\naaa.1.wpa.psk=other", &cfgdiff::redact(actual), true);
        assert!(r.identical);
    }

    #[test]
    fn validates_snapshots() {
        assert!(validate_state(&serde_json::json!({ "devices": [] })).is_err());
        let ok = serde_json::json!({ "sites": [], "wlanconf": [{ "name": "Home" }], "networkconf": [], "setting": [], "devices": [] });
        assert!(validate_state(&ok).is_ok());
        assert_eq!(summarize_state(&ok)["wlans"][0], "Home");
    }
}
