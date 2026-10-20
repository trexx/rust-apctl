//! Read-only snapshot of an existing controller's MongoDB: sites, WLANs and
//! devices with their authkeys. Only `find` is ever issued.
//!
//! The output contains secrets (device authkeys, WLAN passphrases): it is
//! written with mode 0600 and must never be committed.

use std::path::Path;

use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use mongodb::bson::{Bson, Document, doc};
use mongodb::options::{ClientOptions, FindOptions};
use serde_json::{Value, json};

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

    let sites = find_all(&db, "site", doc! {}, doc! {}).await?;
    let wlans = find_all(&db, "wlanconf", doc! {}, doc! {}).await?;
    let wlangroups = find_all(&db, "wlangroup", doc! {}, doc! {}).await?;
    let networks = find_all(&db, "networkconf", doc! {}, doc! {}).await?;
    // Only the settings apctl reads ([`apcfg::SETTING_KEYS`]): the others hold
    // credentials (mail, cloud access, guest portal) nothing here uses.
    let settings = find_all(&db, "setting", doc! { "key": { "$in": apcfg::SETTING_KEYS } }, doc! {}).await?;
    // AP groups decide which WLANs each AP broadcasts; config_meta pins the
    // per-AP wireless/aaa indices and VAP names across edits.
    let apgroups = find_all(&db, "apgroup", doc! {}, doc! {}).await?;
    let config_meta = find_all(&db, "config_meta", doc! {}, doc! {}).await?;
    // User groups are the speed limits of SSIDs and clients.
    let usergroups = find_all(&db, "usergroup", doc! {}, doc! {}).await?;
    let keep = |fields: &[&[&str]]| -> Document { fields.concat().into_iter().map(|f| (f.to_string(), Bson::Int32(1))).collect() };
    let projection = keep(&[apcfg::DEVICE_KEYS, DEVICE_FIELDS]);
    let devices = find_all(&db, "device", doc! {}, projection).await?;
    let user_projection = keep(&[apcfg::CLIENT_KEYS, USER_FIELDS]);
    let users = find_all(&db, "user", doc! {}, user_projection).await?;
    let named = users.iter().filter(|u| u.get("name").and_then(Value::as_str).is_some_and(|n| !n.is_empty())).count();

    let with_key = devices.iter().filter(|d| d.get("x_authkey").is_some_and(Value::is_string)).count();
    let aps = devices.iter().filter(|d| d.get("type").and_then(Value::as_str) == Some("uap")).count();
    eprintln!(
        "read {} sites, {} WLANs, {} WLAN groups, {} AP groups, {} networks, {} settings, {} config_meta, \
         {} user groups, {} devices ({} APs, {} with authkeys), {} clients ({} named)",
        sites.len(), wlans.len(), wlangroups.len(), apgroups.len(), networks.len(), settings.len(),
        config_meta.len(), usergroups.len(), devices.len(), aps, with_key, users.len(), named
    );

    let snapshot = json!({
        "source": "unifi-network-application",
        "sites": sites,
        "wlanconf": wlans,
        "wlangroup": wlangroups,
        "networkconf": networks,
        "setting": settings,
        "apgroup": apgroups,
        "config_meta": config_meta,
        "usergroup": usergroups,
        "devices": devices,
        "clients": users,
    });
    crate::write_private(out, &serde_json::to_vec_pretty(&snapshot)?)?;
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
