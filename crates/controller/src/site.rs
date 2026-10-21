//! Site-wide device settings: the LED and outdoor defaults, the APs' SSH
//! access, remote syslog, SNMP, NTP, country and time zone.
//! Changes go through [`crate::settings::change`], so they can be previewed
//! per AP like SSID and AP edits.

use axum::extract::State;
use serde_json::{Value, json};
use std::sync::LazyLock;

use crate::api::{ApiError, AppState, Json, Query};
use crate::settings::Kind::{Bool, Enum, Int};
use crate::settings::{COUNTRIES, Patch, PreviewQuery, band_name, copy_fields, country, dedup_in_order, docs_mut, illegal_fixed_channel, mgmt_flag, num, outdoor_with, pick, record_label, setting, setting_mut, str_field, timezone};

/// A host name or IPv4 address, as NTP and syslog targets take (the official
/// controller refuses IPv6 there).
fn is_host(h: &str) -> bool {
    h.parse::<std::net::Ipv4Addr>().is_ok() || is_domain_name(h)
}

/// A domain name: labels of letters, digits and hyphens, neither starting nor
/// ending with a hyphen, and a letter somewhere (so it is no address).
pub(crate) fn is_domain_name(h: &str) -> bool {
    let label = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    h.len() <= 253 && h.chars().any(|c| c.is_ascii_alphabetic()) && h.split('.').all(label)
}

/// The servers automatic NTP stands for.
const NTP_POOL: [&str; 4] = ["0.ubnt.pool.ntp.org", "1.ubnt.pool.ntp.org", "2.ubnt.pool.ntp.org", "3.ubnt.pool.ntp.org"];
/// The `ntp` setting's four servers, in order.
const NTP_KEYS: [&str; 4] = ["ntp_server_1", "ntp_server_2", "ntp_server_3", "ntp_server_4"];

/// Sets fixed channels that the site's country and the APs' indoor/outdoor
/// mode no longer allow back to auto, as the official controller does when
/// the country changes. Returns them as "AP 5 GHz channel 44" lines.
fn reset_illegal_channels(state: &mut Value) -> Vec<String> {
    let c = country(state);
    let site_outdoor = mgmt_flag(state, "outdoor_mode_enabled");
    let mut out = Vec::new();
    for d in docs_mut(state, "devices") {
        let o = outdoor_with(d, site_outdoor);
        let name = record_label(d, "?");
        for r in d["radio_table"].as_array_mut().into_iter().flatten() {
            if let Some(ch) = illegal_fixed_channel(c, r, o) {
                out.push(format!("AP {name} {} channel {ch} → auto", band_name(r["radio"].as_str().unwrap_or(""))));
                r["channel"] = json!("auto");
            }
        }
    }
    out
}

const SECRETS: &[&str] = &["x_ssh_password", "x_ssh_sha512passwd", "x_ssh_md5passwd", "x_password"];

/// The `setting` documents [`apply_site`] can change (Channel AI's follows the country).
const SITE_KEYS: [&str; 7] = ["mgmt", "rsyslogd", "ntp", "snmp", "country", "locale", "radio_ai"];

/// Applies a patch: `{ mgmt: {...}, rsyslogd: {...}, snmp: {...}, ntp: {...}, country, timezone }`.
pub fn apply_site(state: &mut Value, p: &Value) -> Result<String, String> {
    let before = SITE_KEYS.map(|k| setting(state, k).clone());
    let rules_before = (country(state), mgmt_flag(state, "outdoor_mode_enabled"));
    let mut notes: Vec<String> = Vec::new();
    if !p["mgmt"].is_null() {
        site_mgmt(setting_mut(state, "mgmt"), &p["mgmt"], &mut notes)?;
    }
    if !p["rsyslogd"].is_null() {
        site_syslog(setting_mut(state, "rsyslogd"), &p["rsyslogd"])?;
    }
    if !p["ntp"].is_null() {
        site_ntp(setting_mut(state, "ntp"), &p["ntp"])?;
    }
    if !p["snmp"].is_null() {
        site_snmp(setting_mut(state, "snmp"), &p["snmp"], &mut notes)?;
    }
    site_region(state, p)?;

    // The country and the outdoor default decide which fixed channels are legal:
    // when either changes, fixed channels no longer allowed go back to auto.
    // Other saves leave the channels alone.
    if (country(state), mgmt_flag(state, "outdoor_mode_enabled")) != rules_before {
        notes.extend(reset_illegal_channels(state));
    }
    if country(state) != rules_before.0 && !setting(state, "radio_ai").is_null() {
        // Channel AI's channel lists follow the country.
        crate::channelai::apply_settings(state, &json!({}))?;
    }

    let mut changed = changed_settings(&before, state);
    changed.extend(notes);
    dedup_in_order(&mut changed);
    Ok(if changed.is_empty() { "site settings: nothing changed".into() } else { format!("site settings: {}", changed.join(", ")) })
}

/// The fields of the [`SITE_KEYS`] documents that differ from `before` (taken
/// in that order), as "key.field" (secrets left out: they are summed up as
/// e.g. "SSH password" by the editors).
fn changed_settings(before: &[Value; SITE_KEYS.len()], state: &Value) -> Vec<String> {
    let mut changed = Vec::new();
    for (key, old) in SITE_KEYS.iter().zip(before) {
        for (k, v) in setting(state, key).as_object().into_iter().flatten() {
            if old[k] != *v && !SECRETS.contains(&k.as_str()) && !matches!(k.as_str(), "key" | "site_id") {
                changed.push(if k == "x_ssh_keys" { "SSH keys".to_string() } else { format!("{key}.{k}") });
            }
        }
    }
    changed
}

/// LEDs, the outdoor default and the APs' SSH access (`mgmt`).
fn site_mgmt(doc: &mut Value, m: &Value, notes: &mut Vec<String>) -> Result<(), String> {
    copy_fields(m, doc, &[("led_enabled", Bool), ("outdoor_mode_enabled", Bool), ("x_ssh_enabled", Bool), ("x_ssh_auth_password_enabled", Bool), ("x_ssh_bind_wildcard", Bool)])?;
    // The official controller turns this on with every save of these settings; the
    // features it gates (band steering, minimum signal and more) need it.
    doc["advanced_feature_enabled"] = json!(true);
    if let Some(u) = str_field(m, "x_ssh_username")?.map(str::trim) {
        let ok = (1..=30).contains(&u.len())
            && u.chars().enumerate().all(|(i, c)| c.is_ascii_alphanumeric() || c == '_' || i > 0 && matches!(c, '-' | '.'))
            && u != "root";
        if !ok {
            return Err("the SSH user name must be 1 to 30 letters, digits, '_', '-' or '.', starting with a letter, digit or '_' (and not root)".into());
        }
        doc["x_ssh_username"] = json!(u);
    }
    if let Some(pw) = str_field(m, "x_ssh_password")? {
        set_ssh_password(doc, pw)?;
        notes.push("SSH password".into());
    }
    if !m["x_ssh_keys"].is_null() {
        let keys = ssh_keys(&m["x_ssh_keys"], &doc["x_ssh_keys"])?;
        doc["x_ssh_keys"] = json!(keys);
    }
    if doc["x_ssh_enabled"].as_bool() != Some(false) && doc["x_ssh_auth_password_enabled"].as_bool() == Some(false) && doc["x_ssh_keys"].as_array().is_none_or(Vec::is_empty) {
        return Err("with password logins off, SSH needs at least one key".into());
    }
    Ok(())
}

/// Remote syslog and netconsole (`rsyslogd`).
fn site_syslog(doc: &mut Value, r: &Value) -> Result<(), String> {
    copy_fields(r, doc, &[("debug", Bool), ("netconsole_enabled", Bool), ("port", Int(1, 65535)), ("netconsole_port", Int(1, 65535))])?;
    // Off, to apctl ("Network Application"), or to a server, saved as the official UI does.
    match str_field(r, "mode")? {
        None => {}
        Some("off") => {
            doc["enabled"] = json!(false);
            doc["log_all_contents"] = json!(true);
            doc["debug"] = json!(false);
        }
        Some("controller") => {
            doc["enabled"] = json!(true);
            doc["this_controller"] = json!(true);
            doc["log_all_contents"] = json!(true);
            doc["netconsole_enabled"] = json!(false);
        }
        Some("server") => {
            doc["enabled"] = json!(true);
            doc["this_controller"] = json!(false);
            doc["log_all_contents"] = json!(true);
        }
        Some(_) => return Err("the syslog mode must be off, controller or server".into()),
    }
    doc["this_controller_encrypted_only"] = json!(false);
    // The syslog server and the netconsole host.
    for key in ["ip", "netconsole_host"] {
        if let Some(h) = str_field(r, key)?.map(str::trim) {
            if !h.is_empty() && !is_host(h) {
                return Err(format!("{h} is not a host name or address"));
            }
            doc[key] = json!(h);
        }
    }
    let doc = &*doc;
    let on = |k: &str| doc[k].as_bool() == Some(true);
    if on("enabled") && !on("this_controller") && doc["ip"].as_str().is_none_or(str::is_empty) {
        return Err("remote syslog needs a server".into());
    }
    if on("netconsole_enabled") && doc["netconsole_host"].as_str().is_none_or(str::is_empty) {
        return Err("netconsole needs a host".into());
    }
    Ok(())
}

/// The APs' time servers (`ntp`).
fn site_ntp(doc: &mut Value, n: &Value) -> Result<(), String> {
    let was_manual = doc["setting_preference"].as_str() == Some("manual");
    copy_fields(n, doc, &[("setting_preference", Enum(&["auto", "manual"]))])?;
    // The servers named, checked whatever the mode.
    let mut named: [Option<&str>; 4] = [None; 4];
    for (h, k) in named.iter_mut().zip(NTP_KEYS) {
        *h = str_field(n, k)?.map(str::trim);
        if let Some(h) = h.filter(|h| !h.is_empty() && !is_host(h)) {
            return Err(format!("{h} is not a host name or IPv4 address"));
        }
    }
    if doc["setting_preference"].as_str() == Some("auto") {
        // Going back to automatic restores the pool, as the official controller does.
        if was_manual || doc[NTP_KEYS[0]].is_null() {
            for (k, h) in NTP_KEYS.iter().zip(NTP_POOL) {
                doc[*k] = json!(h);
            }
        }
        // Automatic uses the pool: other servers named with it are refused (the pool's own, as read back, pass).
        if let Some(h) = named.iter().zip(NTP_KEYS).find_map(|(h, k)| h.filter(|h| !h.is_empty() && doc[k].as_str() != Some(h))) {
            return Err(format!("{h}: time servers are set only with manual NTP"));
        }
    } else if named.iter().any(Option::is_some) || !was_manual && doc["setting_preference"].as_str() == Some("manual") {
        // The servers named replace those stored, and the four close up. Coming
        // from automatic, the pool's servers are no choice of the user's: the
        // ones not named are blank (all four when none is named).
        let mut list = Vec::new();
        for (h, k) in named.into_iter().zip(NTP_KEYS) {
            let h = match h {
                Some(h) => h,
                None if was_manual => doc[k].as_str().unwrap_or_default(),
                None => "",
            };
            if !h.is_empty() {
                list.push(h.to_string());
            }
        }
        for (i, k) in NTP_KEYS.iter().enumerate() {
            doc[*k] = json!(list.get(i).map_or("", String::as_str));
        }
    }
    if doc["setting_preference"].as_str() == Some("manual") && NTP_KEYS.iter().all(|k| doc[*k].as_str().is_none_or(str::is_empty)) {
        return Err("manual NTP needs at least one server".into());
    }
    Ok(())
}

/// SNMP v1/v2c and v3 (`snmp`).
fn site_snmp(doc: &mut Value, sn: &Value, notes: &mut Vec<String>) -> Result<(), String> {
    copy_fields(sn, doc, &[("enabled", Bool), ("enabledV3", Bool)])?;
    if let Some(c) = str_field(sn, "community")? {
        if c.is_empty() || c.len() > 256 || c.contains(char::is_whitespace) {
            return Err("the SNMP community must be 1 to 256 characters without spaces".into());
        }
        doc["community"] = json!(c);
    }
    if let Some(u) = str_field(sn, "username")?.map(str::trim) {
        if !(1..=30).contains(&u.len()) {
            return Err("the SNMPv3 user name must be 1 to 30 characters".into());
        }
        doc["username"] = json!(u);
    }
    if let Some(pw) = str_field(sn, "x_password")? {
        if !(8..=32).contains(&pw.len()) || pw.contains(['"', '\'']) {
            return Err("the SNMPv3 password must be 8 to 32 characters without quotes".into());
        }
        doc["x_password"] = json!(pw);
        notes.push("SNMPv3 password".into());
    }
    if doc["enabled"].as_bool() == Some(true) && doc["community"].as_str().is_none_or(str::is_empty) {
        return Err("SNMP v1/v2c needs a community".into());
    }
    if doc["enabledV3"].as_bool() == Some(true) && (doc["username"].as_str().is_none_or(str::is_empty) || doc["x_password"].as_str().is_none_or(str::is_empty)) {
        return Err("SNMPv3 needs a user name and password".into());
    }
    Ok(())
}

/// The country (which channels are legal) and the time zone.
fn site_region(state: &mut Value, p: &Value) -> Result<(), String> {
    if !p["country"].is_null() {
        let code = num(&p["country"]).ok_or("country must be an ISO 3166 numeric code")?;
        if !COUNTRIES.iter().any(|c| c.code == code) {
            return Err(format!("country {code} is not one apctl has channel rules for"));
        }
        setting_mut(state, "country")["code"] = json!(code.to_string());
    }
    if let Some(tz) = str_field(p, "timezone")? {
        if apcfg::tz::posix(tz).is_none() {
            return Err(format!("{tz} is not a time zone apctl knows"));
        }
        setting_mut(state, "locale")["timezone"] = json!(tz);
    }
    Ok(())
}

/// The APs' SSH password: kept for apctl's own SSH (adoption) and as the
/// crypt(3) hashes the AP config carries.
fn set_ssh_password(doc: &mut Value, pw: &str) -> Result<(), String> {
    // The official rule is 12 or more with upper and lower case, a digit and a
    // symbol; a long password (20 or more, e.g. a generated one) is accepted too.
    let classes = [|c: char| c.is_ascii_uppercase(), |c: char| c.is_ascii_lowercase(), |c: char| c.is_ascii_digit(), |c: char| c.is_ascii_punctuation() || c == ' '];
    let mixed = classes.iter().all(|f| pw.chars().any(f));
    if pw.len() > 128 || !pw.chars().all(|c| (' '..='~').contains(&c)) || !(pw.len() >= 20 || pw.len() >= 12 && mixed) {
        return Err("the SSH password must be printable ASCII: 12 or more characters with upper and lower case, a digit and a symbol, or 20 or more of any kind".into());
    }
    doc["x_ssh_password"] = json!(pw);
    doc["x_ssh_sha512passwd"] = json!(crate::ssh::sha512_crypt(pw));
    // Only firmware without SHA-512 crypt used the MD5 one; a stale copy must not stay.
    if let Some(o) = doc.as_object_mut() {
        o.remove("x_ssh_md5passwd");
    }
    Ok(())
}

/// SSH public keys as `{name, key, type, comment}`; a pasted OpenSSH line
/// (`ssh-ed25519 AAAA... comment`) is split up. A key without a name of its
/// own keeps the one it has in `stored` (the editor sends OpenSSH lines,
/// which have no place for it), else is named after its comment or type.
fn ssh_keys(v: &Value, stored: &Value) -> Result<Vec<Value>, String> {
    // The official controller takes RSA and Ed25519 keys only.
    const TYPES: &[&str] = &["ssh-ed25519", "ssh-rsa"];
    let mut out = Vec::new();
    for k in v.as_array().ok_or("x_ssh_keys must be a list")? {
        let (kind, key, comment) = match k {
            Value::String(line) => {
                let mut parts = line.split_whitespace();
                (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string(), parts.collect::<Vec<_>>().join(" "))
            }
            o => (o["type"].as_str().unwrap_or("").to_string(), o["key"].as_str().unwrap_or("").to_string(), o["comment"].as_str().unwrap_or("").to_string()),
        };
        if !TYPES.contains(&kind.as_str()) || key.len() < 32 || !key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')) {
            return Err(format!("not an SSH public key: {}", if key.is_empty() { kind } else { format!("{kind} {}…", key.chars().take(12).collect::<String>()) }));
        }
        let kept = || stored.as_array().into_iter().flatten().find(|s| s["key"].as_str() == Some(key.as_str()))?["name"].as_str().filter(|n| !n.is_empty());
        let name = k["name"].as_str().filter(|n| !n.is_empty()).or_else(kept).map(str::to_string).unwrap_or_else(|| if comment.is_empty() { kind.clone() } else { comment.clone() });
        if !out.iter().any(|o: &Value| o["key"].as_str() == Some(key.as_str())) {
            out.push(json!({ "name": name, "type": kind, "key": key, "comment": comment }));
        }
    }
    Ok(out)
}

/// The site settings as shown, with the choices of country and time zone.
#[derive(serde::Serialize)]
pub struct SiteView {
    #[serde(flatten)]
    settings: Value,
    countries: &'static Value,
    timezones: &'static Value,
}

/// GET /api/settings/site. Read-only mode (no users) leaves out the SNMP
/// community, which works as a password.
pub async fn get_site(State(s): State<AppState>) -> Result<Json<SiteView>, ApiError> {
    let state = crate::api::current_state(&s)?;
    // The choices never change: built once, and serialised from there.
    static COUNTRY_LIST: LazyLock<Value> = LazyLock::new(|| COUNTRIES.iter().map(|c| json!({ "code": c.code, "name": c.name })).collect());
    static TIMEZONES: LazyLock<Value> = LazyLock::new(|| apcfg::tz::names().collect());
    Ok(Json(SiteView { settings: site_view(&state, s.active, s.auth.enabled()), countries: &COUNTRY_LIST, timezones: &TIMEZONES }))
}

fn site_view(state: &Value, active: bool, secrets: bool) -> Value {
    let m = setting(state, "mgmt");
    let mut mgmt = Value::Object(pick(m, &["led_enabled", "outdoor_mode_enabled", "x_ssh_enabled", "x_ssh_username", "x_ssh_auth_password_enabled", "x_ssh_bind_wildcard", "x_ssh_keys"]));
    mgmt["has_ssh_password"] = json!(m["x_ssh_password"].as_str().is_some_and(|p| !p.is_empty()));
    let r = setting(state, "rsyslogd");
    let mut rsyslogd = Value::Object(pick(r, &["ip", "port", "debug", "netconsole_enabled", "netconsole_host", "netconsole_port"]));
    rsyslogd["mode"] = json!(match (r["enabled"].as_bool() == Some(true), r["this_controller"].as_bool() == Some(true)) {
        (false, _) => "off",
        (true, true) => "controller",
        (true, false) => "server",
    });
    let n = setting(state, "ntp");
    let mut ntp = Value::Object(pick(n, &NTP_KEYS));
    ntp["setting_preference"] = n["setting_preference"].clone();
    let sn = setting(state, "snmp");
    let snmp = json!({
        "enabled": sn["enabled"], "enabledV3": sn["enabledV3"], "community": if secrets { sn["community"].clone() } else { Value::Null }, "username": sn["username"],
        "has_v3_password": sn["x_password"].as_str().is_some_and(|p| !p.is_empty()),
    });
    json!({
        "active": active, "mgmt": mgmt, "rsyslogd": rsyslogd, "ntp": ntp, "snmp": snmp,
        "country": country(state), "timezone": timezone(state),
    })
}

/// PUT /api/settings/site {patch} (`?preview=true` to see the effect)
pub async fn put_site(State(s): State<AppState>, Query(q): Query<PreviewQuery>, Json(b): Json<Patch>) -> Result<Json<Value>, ApiError> {
    crate::settings::change(&s, &q, apply_site, b.patch).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Value {
        json!({
            "devices": [{ "mac": "02:00:00:00:00:01", "name": "Hall", "site_id": "s1", "radio_table": [{ "radio": "na", "channel": 44, "ht": 80 }, { "radio": "ng", "channel": 13, "ht": 20 }] }],
            "setting": [
                { "key": "country", "code": "276", "site_id": "s1" },
                { "key": "mgmt", "site_id": "s1", "x_ssh_username": "admin", "x_ssh_password": "old-password", "x_ssh_md5passwd": "$1$x$y" },
            ],
        })
    }

    fn edit(s: &mut Value, patch: Value) -> Result<String, String> {
        apply_site(s, &patch)
    }

    #[test]
    fn ssh_password_and_keys() {
        let mut s = state();
        let what = edit(&mut s, json!({ "mgmt": { "x_ssh_password": "a much better passphrase" } })).unwrap();
        assert!(what.contains("SSH password") && !what.contains("better"), "{what}");
        edit(&mut s, json!({ "mgmt": { "x_ssh_password": "Sh0rt-but-mixed" } })).unwrap();
        assert!(edit(&mut s, json!({ "mgmt": { "x_ssh_password": "shortbutlonger1" } })).is_err(), "12-19 characters need all four kinds");
        assert_eq!(setting(&s, "mgmt")["advanced_feature_enabled"], true, "kept on, as the official controller does");
        let m = setting(&s, "mgmt");
        assert!(m["x_ssh_sha512passwd"].as_str().unwrap().starts_with("$6$") && m["x_ssh_md5passwd"].is_null());
        assert!(edit(&mut s, json!({ "mgmt": { "x_ssh_password": "short" } })).is_err());
        assert!(edit(&mut s, json!({ "mgmt": { "x_ssh_username": "root" } })).is_err());
        assert!(edit(&mut s, json!({ "mgmt": { "x_ssh_auth_password_enabled": false } })).unwrap_err().contains("key"));
        let line = format!("ssh-ed25519 {} me@laptop", "A".repeat(68));
        edit(&mut s, json!({ "mgmt": { "x_ssh_keys": [line], "x_ssh_auth_password_enabled": false } })).unwrap();
        assert_eq!(setting(&s, "mgmt")["x_ssh_keys"][0]["name"], "me@laptop");
        assert!(edit(&mut s, json!({ "mgmt": { "x_ssh_keys": ["ssh-dss AAAA"] } })).is_err());
        assert!(edit(&mut s, json!({ "mgmt": { "x_ssh_keys": [format!("ecdsa-sha2-nistp256 {}", "A".repeat(68))] } })).is_err(), "RSA and Ed25519 only");
        assert!(edit(&mut s, json!({ "mgmt": { "x_ssh_username": "-dash" } })).is_err());
        // The same key twice, as a line and as an object: kept once.
        let key = "A".repeat(68);
        edit(&mut s, json!({ "mgmt": { "x_ssh_keys": [format!("ssh-ed25519 {key} me@laptop"), { "type": "ssh-ed25519", "key": key, "name": "again" }] } })).unwrap();
        assert_eq!(setting(&s, "mgmt")["x_ssh_keys"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn ssh_keys_keep_their_names_through_the_editor() {
        let mut s = state();
        let (a, b) = ("A".repeat(68), "B".repeat(68));
        // Named in the official controller; the editor sends them back as lines.
        setting_mut(&mut s, "mgmt")["x_ssh_keys"] = json!([
            { "name": "Office laptop", "type": "ssh-ed25519", "key": a, "comment": "me@desk" },
            { "name": "backup", "type": "ssh-rsa", "key": b, "comment": "" },
        ]);
        let new = format!("ssh-ed25519 {} new@host", "C".repeat(68));
        edit(&mut s, json!({ "mgmt": { "x_ssh_keys": [format!("ssh-ed25519 {a} me@desk"), format!("ssh-rsa {b}"), new] } })).unwrap();
        let names: Vec<_> = setting(&s, "mgmt")["x_ssh_keys"].as_array().unwrap().iter().map(|k| k["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(names, ["Office laptop", "backup", "new@host"]);
        // A name given wins.
        edit(&mut s, json!({ "mgmt": { "x_ssh_keys": [{ "type": "ssh-ed25519", "key": a, "name": "renamed" }] } })).unwrap();
        assert_eq!(setting(&s, "mgmt")["x_ssh_keys"][0]["name"], "renamed");
    }

    #[test]
    fn country_and_outdoor_defaults_reset_illegal_channels() {
        let mut s = state();
        // Channel 13 is not allowed in the US: it goes back to auto, as in the official controller.
        let what = edit(&mut s, json!({ "country": 840 })).unwrap();
        assert!(what.contains("AP Hall 2.4 GHz channel 13 → auto"), "{what}");
        assert_eq!(s["devices"][0]["radio_table"][1]["channel"], "auto");
        // An AP without a name is named by its MAC, written aa:bb:.. whatever its record holds.
        let mut s = state();
        (s["devices"][0]["name"], s["devices"][0]["mac"]) = (json!(""), json!("02-00-00-00-00-01"));
        assert!(edit(&mut s, json!({ "country": 840 })).unwrap().contains("AP 02:00:00:00:00:01 2.4 GHz"));
        let mut s = state();
        let what = edit(&mut s, json!({ "mgmt": { "outdoor_mode_enabled": true } })).unwrap();
        assert!(what.contains("5 GHz channel 44 → auto"), "{what}");
        assert!(edit(&mut s, json!({ "country": 999 })).is_err());
        edit(&mut s, json!({ "country": 208, "timezone": "Europe/Copenhagen" })).unwrap();
        assert_eq!((setting(&s, "country")["code"].as_str(), setting(&s, "locale")["timezone"].as_str()), (Some("208"), Some("Europe/Copenhagen")));
        assert!(edit(&mut s, json!({ "timezone": "Mars/Olympus" })).is_err());
    }

    #[test]
    fn channel_ai_lists_follow_a_new_country_only() {
        let mut s = state();
        crate::channelai::apply_settings(&mut s, &json!({})).unwrap();
        // The US 5 GHz list has 149, Germany's does not.
        let na = |s: &Value| setting(s, "radio_ai")["channels_na"].clone();
        let has_149 = |s: &Value| na(s).as_array().unwrap().iter().any(|c| crate::settings::num(c) == Some(149));
        assert!(!has_149(&s), "{}", na(&s));
        edit(&mut s, json!({ "country": 840 })).unwrap();
        assert!(has_149(&s), "{}", na(&s));
        // The same country again leaves them as they are.
        setting_mut(&mut s, "radio_ai")["channels_na"] = json!(["36"]);
        assert_eq!(edit(&mut s, json!({ "country": 840, "timezone": "Europe/Berlin" })).unwrap(), "site settings: locale.timezone");
        assert_eq!(na(&s), json!(["36"]));
    }

    #[test]
    fn other_saves_leave_fixed_channels_alone() {
        // An imported country apctl has no rules for, and a 6 GHz radio: nothing to judge.
        let mut s = state();
        s["setting"][0]["code"] = json!("392");
        s["devices"][0]["radio_table"].as_array_mut().unwrap().push(json!({ "radio": "6e", "channel": "37", "ht": "160" }));
        s["devices"][0]["radio_table"][0]["channel"] = json!(149);
        edit(&mut s, json!({ "mgmt": { "outdoor_mode_enabled": true } })).unwrap();
        assert_eq!((s["devices"][0]["radio_table"][0]["channel"].as_i64(), s["devices"][0]["radio_table"][2]["channel"].as_str()), (Some(149), Some("37")));
        // Only a change of country or outdoor default resets channels; an NTP save does not.
        let mut s = state();
        s["devices"][0]["radio_table"][0]["channel"] = json!(149);
        let what = edit(&mut s, json!({ "ntp": { "setting_preference": "auto" } })).unwrap();
        assert!(!what.contains("auto,") && s["devices"][0]["radio_table"][0]["channel"] == 149, "{what}");
        let what = edit(&mut s, json!({ "country": 276 })).unwrap();
        assert!(!what.contains("→"), "the same country: {what}");
        let what = edit(&mut s, json!({ "country": 840 })).unwrap();
        assert!(what.contains("2.4 GHz channel 13 → auto") && !what.contains("5 GHz"), "149 is fine in the US: {what}");
    }

    #[test]
    fn a_bad_key_with_wide_characters_is_refused_not_a_panic() {
        let mut s = state();
        let err = edit(&mut s, json!({ "mgmt": { "x_ssh_keys": [format!("ssh-ed25519 {}", "é".repeat(40))] } })).unwrap_err();
        assert!(err.contains("éééééééééééé…"), "{err}");
    }

    #[test]
    fn snmp_needs_its_credentials() {
        let mut s = state();
        assert!(edit(&mut s, json!({ "snmp": { "enabled": true, "community": "with space" } })).is_err());
        edit(&mut s, json!({ "snmp": { "enabled": true, "community": "c0mmunity" } })).unwrap();
        assert!(edit(&mut s, json!({ "snmp": { "enabledV3": true, "username": "mon" } })).unwrap_err().contains("password"));
        assert!(edit(&mut s, json!({ "snmp": { "enabledV3": true, "username": "mon", "x_password": "short" } })).is_err());
        let what = edit(&mut s, json!({ "snmp": { "enabledV3": true, "username": "mon", "x_password": "v3-secret-pw" } })).unwrap();
        assert!(what.contains("SNMPv3 password") && !what.contains("v3-secret"), "{what}");
        // Shown to logged-in users; never the v3 password, and nothing in read-only mode.
        assert_eq!(site_view(&s, true, true)["snmp"]["community"], "c0mmunity");
        assert_eq!(site_view(&s, true, true)["snmp"]["has_v3_password"], true);
        assert!(site_view(&s, true, false)["snmp"]["community"].is_null());
        assert!(!site_view(&s, true, true).to_string().contains("v3-secret"));
    }

    #[test]
    fn syslog_and_ntp_need_their_servers() {
        let mut s = state();
        assert!(edit(&mut s, json!({ "rsyslogd": { "mode": "server" } })).unwrap_err().contains("server"));
        edit(&mut s, json!({ "rsyslogd": { "mode": "server", "ip": "logs.example.net", "port": 514 } })).unwrap();
        assert!(edit(&mut s, json!({ "rsyslogd": { "port": 70000 } })).is_err());
        assert!(edit(&mut s, json!({ "rsyslogd": { "mode": "server", "ip": "fd00::1" } })).is_err(), "IPv4 or a name");
        edit(&mut s, json!({ "rsyslogd": { "mode": "controller" } })).unwrap();
        let r = setting(&s, "rsyslogd");
        assert_eq!((r["this_controller"].as_bool(), r["log_all_contents"].as_bool(), r["netconsole_enabled"].as_bool()), (Some(true), Some(true), Some(false)));

        assert!(edit(&mut s, json!({ "ntp": { "setting_preference": "manual" } })).is_err());
        edit(&mut s, json!({ "ntp": { "setting_preference": "manual", "ntp_server_1": "time.example.net", "ntp_server_2": "", "ntp_server_3": "192.0.2.1" } })).unwrap();
        let n = setting(&s, "ntp");
        assert_eq!((n["ntp_server_2"].as_str(), n["ntp_server_4"].as_str()), (Some("192.0.2.1"), Some("")), "the list replaces all four");
        assert!(edit(&mut s, json!({ "ntp": { "ntp_server_2": "bad host!" } })).is_err());
        // Anything but text is refused, not taken as a blank (which would remove the server).
        assert_eq!(edit(&mut s, json!({ "ntp": { "ntp_server_1": 5 } })).unwrap_err(), "ntp_server_1 must be text");
        assert!(edit(&mut s, json!({ "timezone": 1 })).is_err() && edit(&mut s, json!({ "mgmt": { "x_ssh_password": true } })).is_err());
        assert_eq!(setting(&s, "ntp")["ntp_server_1"].as_str(), Some("time.example.net"));
        for bad in ["-time.example.net", "time-.example.net", "time.-example.net"] {
            assert!(edit(&mut s, json!({ "ntp": { "ntp_server_2": bad } })).is_err(), "{bad}");
        }
        assert!(is_host("time-1.example.net") && is_host("192.0.2.1"));
        // A manual patch merges the servers it names into those stored.
        edit(&mut s, json!({ "ntp": { "ntp_server_3": "ntp.example.org" } })).unwrap();
        let servers = |s: &Value| NTP_KEYS.map(|k| setting(s, "ntp")[k].as_str().unwrap_or("?").to_string());
        assert_eq!(servers(&s), ["time.example.net", "192.0.2.1", "ntp.example.org", ""]);
        edit(&mut s, json!({ "ntp": { "ntp_server_1": "" } })).unwrap();
        assert_eq!(servers(&s), ["192.0.2.1", "ntp.example.org", "", ""], "a blank one closes up");
        edit(&mut s, json!({ "ntp": { "setting_preference": "auto" } })).unwrap();
        assert_eq!(setting(&s, "ntp")["ntp_server_1"], "0.ubnt.pool.ntp.org");
        // On automatic, servers are still checked, and other than the pool's refused.
        assert_eq!(edit(&mut s, json!({ "ntp": { "ntp_server_1": 5 } })).unwrap_err(), "ntp_server_1 must be text");
        assert!(edit(&mut s, json!({ "ntp": { "ntp_server_1": "bad host!" } })).unwrap_err().contains("not a host name"));
        assert!(edit(&mut s, json!({ "ntp": { "setting_preference": "auto", "ntp_server_2": "time.example.net" } })).unwrap_err().contains("only with manual"));
        let pool = setting(&s, "ntp").clone();
        assert_eq!(edit(&mut s, json!({ "ntp": pool })).unwrap(), "site settings: nothing changed");
        // From automatic, the pool is not kept for the servers not named: manual alone has none.
        assert_eq!(edit(&mut s.clone(), json!({ "ntp": { "setting_preference": "manual" } })).unwrap_err(), "manual NTP needs at least one server");
        edit(&mut s, json!({ "ntp": { "setting_preference": "manual", "ntp_server_2": "time.example.net" } })).unwrap();
        assert_eq!(servers(&s), ["time.example.net", "", "", ""]);
    }
}
