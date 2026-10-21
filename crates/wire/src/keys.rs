//! Per-device authkeys used to decrypt informs.
//!
//! Accepts either a plain `{"aa:bb:cc:dd:ee:ff": "<32 hex chars>"}` map or an
//! import snapshot written by `informdump import` (`{"devices": [{"mac", "x_authkey"}]}`).

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use inform::{Mac, parse_key};
use serde_json::Value;

#[derive(Default)]
pub struct KeyStore {
    keys: HashMap<Mac, [u8; 16]>,
    /// AES-256 keys for encrypted remote syslog, from the devices' `syslog_key`.
    syslog: HashMap<Mac, [u8; 32]>,
    /// Why entries were left out when loading, for the caller to report.
    skipped: Vec<String>,
}

impl KeyStore {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading keys from {path}"))?;
        let json: Value = serde_json::from_str(&text).with_context(|| format!("parsing {path}"))?;
        Ok(KeyStore::from_value(&json))
    }

    /// The keys in a MAC->key map or an import snapshot. An entry that cannot be read
    /// (a malformed MAC, or a key that is malformed or not a string) is left out and
    /// listed in [`skipped`](Self::skipped): one bad device does not cost the keys of
    /// the others. A device without a key (waiting for adoption) is not listed.
    pub fn from_value(json: &Value) -> Self {
        let mut store = KeyStore::default();
        let mut skipped = Vec::new();
        let mut add = |what: &str, r: Result<()>| {
            if let Err(e) = r {
                skipped.push(format!("skipping {what}: {e:#}"));
            }
        };
        if let Some(devices) = json.get("devices").and_then(Value::as_array) {
            for d in devices {
                let Some(mac) = d["mac"].as_str() else { continue };
                match &d["x_authkey"] {
                    Value::Null => {}
                    Value::String(key) => add("an authkey", store.insert(mac, key)),
                    other => add("an authkey", Err(anyhow!("key for {mac} is not a string: {}", kind(other)))),
                }
                match &d["syslog_key"] {
                    Value::Null => {}
                    Value::String(key) => add("a syslog key", store.insert_syslog(mac, key)),
                    other => add("a syslog key", Err(anyhow!("syslog key for {mac} is not a string: {}", kind(other)))),
                }
            }
        } else if let Some(map) = json.as_object() {
            for (mac, key) in map {
                match key.as_str() {
                    Some(key) => add("an authkey", store.insert(mac, key)),
                    None => add("an authkey", Err(anyhow!("key for {mac} is not a string: {}", kind(key)))),
                }
            }
        }
        store.skipped = skipped;
        store
    }

    /// The entries loading left out, and why.
    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }

    pub fn insert(&mut self, mac: &str, key: &str) -> Result<()> {
        self.insert_for(mac.parse()?, key)
    }

    /// [`insert`](Self::insert) for a MAC at hand.
    pub fn insert_for(&mut self, mac: Mac, key: &str) -> Result<()> {
        self.keys.insert(mac, parse_key(key).with_context(|| format!("key for {mac}"))?);
        Ok(())
    }

    pub fn insert_syslog(&mut self, mac: &str, key: &str) -> Result<()> {
        let mac: Mac = mac.parse()?;
        self.syslog.insert(mac, parse_key(key).with_context(|| format!("syslog key for {mac}"))?);
        Ok(())
    }

    pub fn syslog_keys(&self) -> impl Iterator<Item = (&Mac, &[u8; 32])> {
        self.syslog.iter()
    }

    pub fn get(&self, mac: &Mac) -> Option<&[u8; 16]> {
        self.keys.get(mac)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn syslog_len(&self) -> usize {
        self.syslog.len()
    }
}

/// What a JSON value is, for an error message (not the value: it may be a key).
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_bad_entry_costs_only_itself() {
        let good = "000102030405060708090a0b0c0d0e0f";
        let snapshot = json!({ "devices": [
            { "mac": "00:11:22:33:44:55", "x_authkey": good, "syslog_key": "nothex" },
            { "mac": "not-a-mac", "x_authkey": good },
            { "mac": "00:11:22:33:44:66", "x_authkey": "short", "syslog_key": "07".repeat(32) },
        ]});
        let keys = KeyStore::from_value(&snapshot);
        assert_eq!((keys.len(), keys.syslog_len(), keys.skipped().len()), (1, 1, 3));
        let keys = KeyStore::from_value(&json!({ "00:11:22:33:44:55": good, "00:11:22:33:44:66": 7, "00:11:22:33:44:77": null }));
        assert_eq!((keys.len(), keys.skipped().len()), (1, 2), "{:?}", keys.skipped());
        assert!(keys.skipped()[0].contains("00:11:22:33:44:66 is not a string: a number"), "{:?}", keys.skipped());
        // A device waiting for adoption has no key: nothing to report.
        let keys = KeyStore::from_value(&json!({ "devices": [{ "mac": "00:11:22:33:44:55" }, { "mac": "00:11:22:33:44:66", "x_authkey": 7, "syslog_key": [] }] }));
        assert_eq!(keys.skipped().len(), 2, "{:?}", keys.skipped());
    }
}
