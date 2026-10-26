//! What `informdump import` reads and keeps, apart from the MongoDB driver code: built
//! without the `mongo` feature too, so the tests run in every check. It reads the
//! collections rendering reads ([`apcfg::COLLECTIONS`]), of devices and clients only
//! the fields below, and of the settings only [`apcfg::SETTING_KEYS`].

use serde_json::Value;

/// The official controller's collection each snapshot collection is read from.
pub fn source(collection: &str) -> &str {
    match collection {
        "sites" => "site",
        "devices" => "device",
        "clients" => "user",
        c => c,
    }
}

/// Device fields kept besides the ones rendering reads ([`apcfg::DEVICE_KEYS`]): what
/// the controller shows and copies onto a new AP. The rest (stats caches, SSH
/// credentials, `x_fingerprint`) is left out.
const DEVICE_FIELDS: &[&str] = &["model", "version", "serial", "ip", "adopted", "x_aes_gcm", "cfgversion", "wlangroup_id_na", "wlangroup_id_ng"];

/// Client fields kept besides the ones rendering reads ([`apcfg::CLIENT_KEYS`]): the
/// names and notes people gave their devices (an import into apctl takes them as the
/// aliases of clients not yet named there), and their speed limit (user group).
const USER_FIELDS: &[&str] = &["name", "note", "noted", "hostname", "oui", "first_seen", "last_seen", "is_wired", "is_guest", "usergroup_id"];

/// The fields of a device document an import keeps.
pub fn device_fields() -> Vec<&'static str> {
    [apcfg::DEVICE_KEYS, DEVICE_FIELDS].concat()
}

/// The fields of a client (`user`) document an import keeps.
pub fn client_fields() -> Vec<&'static str> {
    [apcfg::CLIENT_KEYS, USER_FIELDS].concat()
}

/// Settings of which only these fields are kept, with `_id`, `key` and `site_id`: the
/// rest of `element_adopt` is its pairing secrets, which nothing reads.
const SETTING_FIELDS: &[(&str, &[&str])] = &[("element_adopt", &["enabled"])];

/// Drops the fields [`SETTING_FIELDS`] leaves out.
pub fn trim_settings(settings: &mut [Value]) {
    for s in settings {
        let Some(&(_, fields)) = SETTING_FIELDS.iter().find(|(k, _)| s["key"].as_str() == Some(k)) else { continue };
        if let Some(o) = s.as_object_mut() {
            o.retain(|k, _| matches!(k.as_str(), "_id" | "key" | "site_id") || fields.contains(&k.as_str()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn element_adoption_keeps_only_whether_it_is_on() {
        let mut settings = vec![
            json!({ "_id": "a", "key": "element_adopt", "site_id": "s", "enabled": true, "x_element_psk": "secret", "x_pregenerated_dh_key": "k" }),
            json!({ "_id": "b", "key": "mgmt", "site_id": "s", "x_ssh_password": "kept" }),
        ];
        trim_settings(&mut settings);
        assert_eq!(settings[0], json!({ "_id": "a", "key": "element_adopt", "site_id": "s", "enabled": true }));
        assert_eq!(settings[1]["x_ssh_password"], "kept");
    }

    /// The fields the controller reads are kept, and of the `x_` fields (the official
    /// controller's secrets) only the AP's inform key and its AES-GCM flag.
    #[test]
    fn imports_keep_what_the_controller_reads_and_no_other_secret() {
        let (devices, clients) = (device_fields(), client_fields());
        for f in ["mac", "site_id", "x_authkey", "syslog_key", "radio_table", "model", "version", "cfgversion", "x_aes_gcm", "mgmt_network_id", "wlangroup_id_ng", "wlangroup_id_na"] {
            assert!(devices.contains(&f), "devices: {f}");
        }
        for f in ["mac", "site_id", "blocked", "fixed_ap_mac", "name", "note", "usergroup_id"] {
            assert!(clients.contains(&f), "clients: {f}");
        }
        let secrets: Vec<&str> = devices.iter().chain(&clients).copied().filter(|f| f.starts_with("x_")).collect();
        assert_eq!(secrets, ["x_authkey", "x_aes_gcm"]);
        for fields in [&devices, &clients] {
            assert!(fields.iter().enumerate().all(|(i, f)| !fields[..i].contains(f)), "{fields:?}");
        }
    }

    #[test]
    fn each_collection_is_read_once_from_the_officials_name() {
        let read = apcfg::COLLECTIONS;
        assert!(read.iter().enumerate().all(|(i, c)| !read[..i].contains(c)), "{read:?}");
        for c in ["sites", "setting", "devices", "clients"] {
            assert!(read.contains(&c), "import reads {c} by this name");
        }
        assert_eq!([source("sites"), source("devices"), source("clients"), source("wlanconf")], ["site", "device", "user", "wlanconf"]);
    }
}
