//! Read-only snapshot of an existing controller's MongoDB: sites, WLANs and
//! devices with their authkeys. Only `find` is ever issued.
//!
//! The output contains secrets (device authkeys, WLAN passphrases): it is
//! written with mode 0600 and must never be committed.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use mongodb::bson::{Bson, Document, doc};
use mongodb::options::{ClientOptions, FindOptions};
use serde_json::{Value, json};

/// Device fields worth carrying over. Everything else (stats caches, etc.) is skipped.
const DEVICE_FIELDS: &[&str] = &[
    "mac", "name", "model", "type", "version", "serial", "ip", "site_id", "adopted",
    "x_authkey", "syslog_key", "x_aes_gcm", "cfgversion", "inform_url", "led_override", "radio_table", "wlangroup_id_na",
    "wlangroup_id_ng", "config_network", "mgmt_network_id",
];

/// Client fields: the names and notes people gave their devices.
const USER_FIELDS: &[&str] = &[
    "mac", "name", "note", "noted", "hostname", "oui", "first_seen", "last_seen", "is_wired",
    // used when rendering AP config: lock-to-AP, blocked clients, guests
    "fixed_ap_enabled", "fixed_ap_mac", "blocked", "is_guest",
];

pub async fn run(uri: &str, db: &str, out: &Path) -> Result<()> {
    let mut opts = ClientOptions::parse(uri).await.context("parsing MongoDB URI")?;
    opts.direct_connection = Some(true);
    opts.app_name = Some("informdump-import".into());
    let client = mongodb::Client::with_options(opts)?;
    let db = client.database(db);

    let sites = find_all(&db, "site", doc! {}).await?;
    let wlans = find_all(&db, "wlanconf", doc! {}).await?;
    let wlangroups = find_all(&db, "wlangroup", doc! {}).await?;
    let networks = find_all(&db, "networkconf", doc! {}).await?;
    let settings = find_all(&db, "setting", doc! {}).await?;
    // AP groups decide which WLANs each AP broadcasts; config_meta pins the
    // per-AP wireless/aaa indices and VAP names across edits.
    let apgroups = find_all(&db, "apgroup", doc! {}).await?;
    let config_meta = find_all(&db, "config_meta", doc! {}).await?;
    let projection: Document = DEVICE_FIELDS.iter().map(|f| (f.to_string(), Bson::Int32(1))).collect();
    let devices = find_all(&db, "device", projection).await?;
    let user_projection: Document = USER_FIELDS.iter().map(|f| (f.to_string(), Bson::Int32(1))).collect();
    let users = find_all(&db, "user", user_projection).await?;
    let named = users.iter().filter(|u| u.get("name").and_then(Value::as_str).is_some_and(|n| !n.is_empty())).count();

    let with_key = devices.iter().filter(|d| d.get("x_authkey").is_some_and(Value::is_string)).count();
    let aps = devices.iter().filter(|d| d.get("type").and_then(Value::as_str) == Some("uap")).count();
    eprintln!(
        "read {} sites, {} WLANs, {} WLAN groups, {} AP groups, {} networks, {} settings, {} config_meta, \
         {} devices ({} APs, {} with authkeys), {} clients ({} named)",
        sites.len(), wlans.len(), wlangroups.len(), apgroups.len(), networks.len(), settings.len(),
        config_meta.len(), devices.len(), aps, with_key, users.len(), named
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
        "devices": devices,
        "clients": users,
    });
    write_private(out, &serde_json::to_vec_pretty(&snapshot)?)?;
    eprintln!("wrote {} (mode 0600; contains secrets, keep it out of git)", out.display());
    Ok(())
}

async fn find_all(db: &mongodb::Database, coll: &str, projection: Document) -> Result<Vec<Value>> {
    // Driver 2.x: the 3.x driver refuses servers older than MongoDB 4.4, and
    // the official application still bundles 3.6.
    let options = FindOptions::builder().projection((!projection.is_empty()).then_some(projection)).build();
    let mut cursor = db
        .collection::<Document>(coll)
        .find(doc! {}, options)
        .await
        .with_context(|| format!("querying {coll}"))?;
    let mut out = Vec::new();
    while let Some(d) = cursor.try_next().await.with_context(|| format!("reading {coll}"))? {
        out.push(Bson::Document(d).into_relaxed_extjson());
    }
    Ok(out)
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}
