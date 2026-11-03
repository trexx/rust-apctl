//! What `informdump import` reads and keeps, apart from the MongoDB driver code: built
//! without the `mongo` feature too, so the tests run in every check. It reads the
//! collections rendering reads ([`apcfg::COLLECTIONS`]), of devices and clients only
//! the fields below, of clients only those [`keeps_client`] keeps, and of the settings
//! only [`apcfg::SETTING_KEYS`].

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

/// Device fields kept besides the ones rendering reads ([`apcfg::DEVICE_KEYS`]). The
/// controller reads: the model (shown), the address (which AP an SSH host key belongs
/// to), whether the AP pins AES-GCM, the fingerprint of its SSH host key
/// (`SHA256:<base64>`, a public key's), which adopting it over SSH checks, `cfgversion`
/// (the config version the other controller expected, which the dry run compares with
/// the AP's) and the WLAN groups it copies onto a new AP. `version`, `serial` and
/// `adopted` are read by nothing, but apctl writes them into the records of the APs it
/// adopts, so an imported record has the same fields. The rest (stats caches, SSH
/// credentials, `x_fingerprint`) is left out.
const DEVICE_FIELDS: &[&str] = &["model", "version", "serial", "ip", "adopted", "x_aes_gcm", "x_ssh_hostkey_fingerprint", "cfgversion", "wlangroup_id_na", "wlangroup_id_ng"];

/// Client fields kept besides the ones rendering reads ([`apcfg::CLIENT_KEYS`]): the
/// names and notes people gave their devices (an import into apctl takes them as the
/// aliases of clients not yet named there), their speed limit (user group) and their
/// reserved address (`use_fixedip`, `fixed_ip`), which a static AP address may not take.
const USER_FIELDS: &[&str] = &["name", "note", "hostname", "usergroup_id", "use_fixedip", "fixed_ip"];

/// Whether an import keeps a client (`user`) document: one with a name, a note or a
/// speed limit, or that is blocked, locked to an AP or has a reserved address. The
/// official controller keeps one for every MAC it ever saw; the rest carry only
/// that and a hostname, which nothing reads (apctl makes a client's document when it
/// first edits one).
pub fn keeps_client(u: &Value) -> bool {
    let text = |k: &str| u.get(k).and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty());
    ["name", "note", "usergroup_id"].into_iter().any(text) || ["blocked", "fixed_ap_enabled", "use_fixedip"].into_iter().any(|k| apcfg::flag(u, k, false))
}

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

    /// The fields the controller reads are kept, and of the `x_` fields (mostly the
    /// official controller's secrets) only the AP's inform key, its AES-GCM flag and its
    /// SSH host key's fingerprint.
    #[test]
    fn imports_keep_what_the_controller_reads_and_no_other_secret() {
        let (devices, clients) = (device_fields(), client_fields());
        for f in ["mac", "site_id", "x_authkey", "x_ssh_hostkey_fingerprint", "syslog_key", "radio_table", "model", "ip", "cfgversion", "x_aes_gcm", "mgmt_network_id", "wlangroup_id_ng", "wlangroup_id_na"] {
            assert!(devices.contains(&f), "devices: {f}");
        }
        for f in ["mac", "site_id", "blocked", "fixed_ap_mac", "name", "note", "hostname", "usergroup_id", "use_fixedip", "fixed_ip"] {
            assert!(clients.contains(&f), "clients: {f}");
        }
        let secrets: Vec<&str> = devices.iter().chain(&clients).copied().filter(|f| f.starts_with("x_")).collect();
        assert_eq!(secrets, ["x_authkey", "x_aes_gcm", "x_ssh_hostkey_fingerprint"]);
        for fields in [&devices, &clients] {
            assert!(fields.iter().enumerate().all(|(i, f)| !fields[..i].contains(f)), "{fields:?}");
        }
    }

    #[test]
    fn only_clients_with_settings_or_names_are_kept() {
        let site = json!({ "mac": "02:00:00:00:00:01", "site_id": "s" });
        let with = |k: &str, v: Value| {
            let mut u = site.clone();
            u[k] = v;
            u
        };
        for kept in [with("name", json!("TV")), with("note", json!("tablet")), with("usergroup_id", json!("g")), with("blocked", json!(true)), with("fixed_ap_enabled", json!("true")), with("use_fixedip", json!(true))] {
            assert!(keeps_client(&kept), "{kept}");
        }
        for left in [site.clone(), with("hostname", json!("kitchen-tv")), with("name", json!(" ")), with("usergroup_id", json!("")), with("blocked", json!(false)), with("use_fixedip", json!("false")), with("fixed_ap_enabled", json!(1))] {
            assert!(!keeps_client(&left), "{left}");
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
