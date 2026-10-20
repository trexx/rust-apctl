//! Per-device authkeys used to decrypt informs.
//!
//! Accepts either a plain `{"aa:bb:cc:dd:ee:ff": "<32 hex chars>"}` map or an
//! import snapshot written by `informdump import` (`{"devices": [{"mac", "x_authkey"}]}`).
//! A snapshot device whose `x_inform_authkey` (the key the official controller last saw
//! it inform with) differs from `x_authkey` has not switched to its new key yet: that
//! key is kept too, and tried after `x_authkey`.

use std::collections::HashMap;

use anyhow::{Context, Result};
use inform::{Mac, parse_key};
use serde_json::Value;

#[derive(Default)]
pub struct KeyStore {
    keys: HashMap<Mac, [u8; 16]>,
    /// A device's `x_inform_authkey` where it differs from its `x_authkey`.
    inform_keys: HashMap<Mac, [u8; 16]>,
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
    /// (a malformed MAC or key) is left out and listed in [`skipped`](Self::skipped):
    /// one bad device does not cost the keys of the others.
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
                if let (Some(mac), Some(key)) = (d["mac"].as_str(), d["x_authkey"].as_str()) {
                    add("an authkey", store.insert(mac, key));
                }
                if let (Some(mac), Some(key)) = (d["mac"].as_str(), d["x_inform_authkey"].as_str())
                    && !key.is_empty()
                    && Some(key) != d["x_authkey"].as_str()
                {
                    add("an inform authkey", store.insert_inform(mac, key));
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

    fn insert_inform(&mut self, mac: &str, key: &str) -> Result<()> {
        let mac: Mac = mac.parse()?;
        self.inform_keys.insert(mac, parse_key(key).with_context(|| format!("inform key for {mac}"))?);
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

    /// The device's key (`x_authkey`).
    pub fn get(&self, mac: &Mac) -> Option<&[u8; 16]> {
        self.keys.get(mac)
    }

    /// Every key the device may inform with: its own, then the one it last informed
    /// with if that differs.
    pub fn device_keys(&self, mac: &Mac) -> impl Iterator<Item = &[u8; 16]> + use<'_> {
        self.keys.get(mac).into_iter().chain(self.inform_keys.get(mac))
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
        assert_eq!((keys.len(), keys.syslog_len(), keys.skipped().len()), (1, 1, 3));
        let keys = KeyStore::from_value(&json!({ "00:11:22:33:44:55": good, "00:11:22:33:44:66": 7 }));
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn a_key_the_device_has_yet_to_switch_from_is_tried_second() {
        let (new, old) = ("000102030405060708090a0b0c0d0e0f", "0f0e0d0c0b0a09080706050403020100");
        let snapshot = json!({ "devices": [
            { "mac": "00:11:22:33:44:55", "x_authkey": new, "x_inform_authkey": old },
            { "mac": "00:11:22:33:44:66", "x_authkey": new, "x_inform_authkey": new },
            { "mac": "00:11:22:33:44:77", "x_authkey": new, "x_inform_authkey": "" },
        ]});
        let keys = KeyStore::from_value(&snapshot);
        assert!(keys.skipped().is_empty(), "{:?}", keys.skipped());
        let of = |mac: &str| keys.device_keys(&mac.parse().unwrap()).copied().collect::<Vec<_>>();
        assert_eq!(of("00:11:22:33:44:55"), [parse_key(new).unwrap(), parse_key(old).unwrap()]);
        assert_eq!(of("00:11:22:33:44:66"), [parse_key(new).unwrap()]);
        assert_eq!(of("00:11:22:33:44:77"), [parse_key(new).unwrap()]);
        assert!(of("00:11:22:33:44:88").is_empty());
    }
}
