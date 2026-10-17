//! Per-device authkeys used to decrypt informs.
//!
//! Accepts either a plain `{"aa:bb:cc:dd:ee:ff": "<32 hex chars>"}` map or an
//! import snapshot written by `informdump import` (`{"devices": [{"mac", "x_authkey"}]}`).

use std::collections::HashMap;

use anyhow::{Context, Result};
use inform::{Mac, parse_key};
use serde_json::Value;

#[derive(Default)]
pub struct KeyStore {
    keys: HashMap<Mac, [u8; 16]>,
    /// AES-256 keys for encrypted remote syslog, from the devices' `syslog_key`.
    syslog: HashMap<Mac, [u8; 32]>,
}

impl KeyStore {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading keys from {path}"))?;
        let json: Value = serde_json::from_str(&text).with_context(|| format!("parsing {path}"))?;
        Ok(KeyStore::from_value(&json))
    }

    /// The keys in a MAC->key map or an import snapshot. An entry that cannot be read
    /// (a malformed MAC or key) is reported on stderr and left out: one bad device
    /// does not cost the keys of the others.
    pub fn from_value(json: &Value) -> Self {
        let mut store = KeyStore::default();
        let add = |what: &str, r: Result<()>| {
            if let Err(e) = r {
                eprintln!("warning: skipping {what}: {e:#}");
            }
        };
        if let Some(devices) = json.get("devices").and_then(Value::as_array) {
            for d in devices {
                if let (Some(mac), Some(key)) = (d["mac"].as_str(), d["x_authkey"].as_str()) {
                    add("an authkey", store.insert(mac, key));
                }
                if let (Some(mac), Some(key)) = (d["mac"].as_str(), d["syslog_key"].as_str()) {
                    add("a syslog key", store.insert_syslog(mac, key));
                }
            }
        } else if let Some(map) = json.as_object() {
            for (mac, key) in map {
                if let Some(key) = key.as_str() {
                    add("an authkey", store.insert(mac, key));
                }
            }
        }
        store
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
        assert_eq!((keys.len(), keys.syslog_len()), (1, 1));
        let keys = KeyStore::from_value(&json!({ "00:11:22:33:44:55": good, "00:11:22:33:44:66": 7 }));
        assert_eq!(keys.len(), 1);
    }
}
