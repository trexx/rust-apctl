//! What `informdump import` reads and keeps, apart from the MongoDB driver code: built
//! without the `mongo` feature too, so the tests run in every check.

use serde_json::Value;

/// Collections carried over besides the ones rendering reads ([`apcfg::COLLECTIONS`]):
/// the WLAN groups the devices name.
pub const EXTRA_COLLECTIONS: &[&str] = &["wlangroup"];

/// Every collection a snapshot holds, in the order they are read.
pub fn collections() -> impl Iterator<Item = &'static str> {
    apcfg::COLLECTIONS.iter().chain(EXTRA_COLLECTIONS).copied()
}

/// The official controller's collection each snapshot collection is read from.
pub fn source(collection: &str) -> &str {
    match collection {
        "sites" => "site",
        "devices" => "device",
        "clients" => "user",
        c => c,
    }
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

    #[test]
    fn each_collection_is_read_once_from_the_officials_name() {
        let read: Vec<_> = collections().collect();
        assert!(read.iter().enumerate().all(|(i, c)| !read[..i].contains(c)), "{read:?}");
        for c in ["sites", "setting", "devices", "clients", "wlangroup"] {
            assert!(read.contains(&c), "import reads {c} by this name");
        }
        assert_eq!([source("sites"), source("devices"), source("clients"), source("wlanconf")], ["site", "device", "user", "wlanconf"]);
    }
}
