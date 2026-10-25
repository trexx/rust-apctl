//! Read-only snapshot of an existing controller's MongoDB: the collections rendering
//! reads ([`apcfg::COLLECTIONS`]), devices with their authkeys. Only `find` is ever issued.
//! What is read and kept, without the driver, is in [`crate::snapshot`].
//!
//! The output contains secrets (device authkeys, WLAN passphrases): it is
//! written with mode 0600 and must never be committed.

use std::path::Path;

use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use mongodb::bson::{Bson, Document, doc};
use mongodb::options::{ClientOptions, FindOptions};
use serde_json::{Value, json};

use crate::snapshot::{source, trim_settings};

/// Device fields worth carrying over besides the ones rendering reads
/// ([`apcfg::DEVICE_KEYS`]). Everything else (stats caches, etc.) is skipped.
const DEVICE_FIELDS: &[&str] = &[
    "model", "version", "serial", "ip", "adopted", "x_aes_gcm", "cfgversion", "wlangroup_id_na", "wlangroup_id_ng",
];

/// Client fields besides the ones rendering reads ([`apcfg::CLIENT_KEYS`]): the
/// names and notes people gave their devices.
const USER_FIELDS: &[&str] = &[
    "name", "note", "noted", "hostname", "oui", "first_seen", "last_seen", "is_wired", "is_guest",
    // speed limit (user group) of the client
    "usergroup_id",
];

pub async fn run(uri: &str, db: &str, out: &Path) -> Result<()> {
    let mut opts = ClientOptions::parse(uri).await.context("parsing MongoDB URI")?;
    opts.direct_connection = Some(true);
    opts.app_name = Some("informdump-import".into());
    let client = mongodb::Client::with_options(opts)?;
    let db = client.database(db);

    let keep = |fields: &[&[&str]]| -> Document { fields.concat().into_iter().map(|f| (f.to_string(), Bson::Int32(1))).collect() };
    let mut snapshot = serde_json::Map::new();
    snapshot.insert("source".into(), json!("unifi-network-application"));
    let mut read = Vec::new();
    for &c in apcfg::COLLECTIONS {
        let (filter, projection) = match c {
            // Only the settings apctl reads ([`apcfg::SETTING_KEYS`]): the others hold
            // credentials (mail, cloud access, guest portal) nothing here uses.
            "setting" => (doc! { "key": { "$in": apcfg::SETTING_KEYS } }, doc! {}),
            "devices" => (doc! {}, keep(&[apcfg::DEVICE_KEYS, DEVICE_FIELDS])),
            "clients" => (doc! {}, keep(&[apcfg::CLIENT_KEYS, USER_FIELDS])),
            _ => (doc! {}, doc! {}),
        };
        let mut docs = find_all(&db, source(c), filter, projection).await?;
        if c == "setting" {
            trim_settings(&mut docs);
        }
        read.push(format!("{} {c}", docs.len()));
        snapshot.insert(c.to_string(), Value::Array(docs));
    }
    let devices = snapshot["devices"].as_array().map_or(&[][..], Vec::as_slice);
    let with_key = devices.iter().filter(|d| d.get("x_authkey").is_some_and(Value::is_string)).count();
    let aps = devices.iter().filter(|d| d.get("type").and_then(Value::as_str) == Some("uap")).count();
    let clients = snapshot["clients"].as_array().map_or(&[][..], Vec::as_slice);
    let named = clients.iter().filter(|u| u.get("name").and_then(Value::as_str).is_some_and(|n| !n.is_empty())).count();
    eprintln!("read {}; {aps} APs, {with_key} with authkeys; {named} named clients", read.join(", "));

    crate::write_private(out, &serde_json::to_vec_pretty(&Value::Object(snapshot))?)?;
    eprintln!("wrote {} (mode 0600; contains secrets, keep it out of git)", out.display());
    Ok(())
}

async fn find_all(db: &mongodb::Database, coll: &str, filter: Document, projection: Document) -> Result<Vec<Value>> {
    // Driver 2.x: the 3.x driver refuses servers older than MongoDB 4.4, and
    // the official application still bundles 3.6.
    let options = FindOptions::builder().projection((!projection.is_empty()).then_some(projection)).build();
    let mut cursor = db
        .collection::<Document>(coll)
        .find(filter, options)
        .await
        .with_context(|| format!("querying {coll}"))?;
    let mut out = Vec::new();
    while let Some(d) = cursor.try_next().await.with_context(|| format!("reading {coll}"))? {
        out.push(Bson::Document(d).into_relaxed_extjson());
    }
    Ok(out)
}
