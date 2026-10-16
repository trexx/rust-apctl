//! Site-wide device settings: the LED and outdoor defaults, the APs' SSH
//! access, remote syslog, NTP, country and time zone.
//! Changes go through [`crate::settings::change`], so they can be previewed
//! per AP like SSID and AP edits.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};
use crate::settings::{COUNTRY_NAMES, PreviewQuery, docs, legal_channels, outdoor, site_id};

/// The site's setting document with this key, created when missing.
fn setting_mut<'a>(state: &'a mut Value, key: &str) -> Result<&'a mut Value, String> {
    let site = site_id(state);
    if !state["setting"].is_array() {
        state["setting"] = json!([]);
    }
    let list = state["setting"].as_array_mut().unwrap();
    let i = match list.iter().position(|s| s["key"].as_str() == Some(key) && (site.is_none() || s["site_id"].as_str().is_none_or(|x| Some(x) == site.as_deref()))) {
        Some(i) => i,
        None => {
            list.push(json!({ "key": key, "site_id": site }));
            list.len() - 1
        }
    };
    Ok(&mut list[i])
}

fn setting<'a>(state: &'a Value, key: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    docs(state, "setting").find(|s| s["key"].as_str() == Some(key)).unwrap_or(&NULL)
}

/// A host name or IPv4 address, as NTP and syslog targets take (the official
/// controller refuses IPv6 there).
fn is_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && (h.parse::<std::net::Ipv4Addr>().is_ok()
            || h.chars().any(|c| c.is_ascii_alphabetic()) && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')))
}

/// The servers automatic NTP stands for.
const NTP_POOL: [&str; 4] = ["0.ubnt.pool.ntp.org", "1.ubnt.pool.ntp.org", "2.ubnt.pool.ntp.org", "3.ubnt.pool.ntp.org"];

fn port(v: &Value, what: &str) -> Result<Option<i64>, String> {
    match v {
        Value::Null => Ok(None),
        v => match v.as_i64().or_else(|| v.as_str()?.parse().ok()) {
            Some(n) if (1..=65535).contains(&n) => Ok(Some(n)),
            _ => Err(format!("{what} must be a port from 1 to 65535")),
        },
    }
}

fn bools(p: &Value, doc: &mut Value, keys: &[&str]) -> Result<(), String> {
    for k in keys {
        match &p[*k] {
            Value::Null => {}
            Value::Bool(b) => doc[*k] = json!(b),
            _ => return Err(format!("{k} must be true or false")),
        }
    }
    Ok(())
}

/// Sets fixed channels that the site's country and the APs' indoor/outdoor
/// mode no longer allow back to auto, as the official controller does when
/// the country changes. Returns them as "AP 5 GHz channel 44" lines.
fn reset_illegal_channels(state: &mut Value) -> Vec<String> {
    let c = crate::settings::country(state);
    let modes: Vec<bool> = docs(state, "devices").map(|d| outdoor(state, d)).collect();
    let site = site_id(state);
    let mut out = Vec::new();
    let devices = state["devices"].as_array_mut().into_iter().flatten().filter(|d| site.is_none() || d["site_id"].as_str().is_none_or(|x| Some(x) == site.as_deref()));
    for (d, o) in devices.zip(modes) {
        let name = d["name"].as_str().or(d["mac"].as_str()).unwrap_or("?").to_string();
        for r in d["radio_table"].as_array_mut().into_iter().flatten() {
            let band = r["radio"].as_str().unwrap_or("").to_string();
            let width = r["ht"].as_i64().or_else(|| r["ht"].as_str()?.parse().ok()).unwrap_or(20);
            if let Some(ch) = r["channel"].as_i64().or_else(|| r["channel"].as_str()?.parse().ok())
                && !legal_channels(c, &band, width, o).contains(&ch)
            {
                r["channel"] = json!("auto");
                out.push(format!("AP {name} {} channel {ch} → auto", if band == "ng" { "2.4 GHz" } else { "5 GHz" }));
            }
        }
    }
    out
}

const SECRETS: &[&str] = &["x_ssh_password", "x_ssh_sha512passwd", "x_ssh_md5passwd"];

/// Applies `body.patch`: `{ mgmt: {...}, rsyslogd: {...}, ntp: {...}, country, timezone }`.
pub fn apply_site(state: &mut Value, body: &Value) -> Result<String, String> {
    let p = &body["patch"];
    let before = state["setting"].clone();
    let mut notes: Vec<String> = Vec::new();

    let m = &p["mgmt"];
    if !m.is_null() {
        let doc = setting_mut(state, "mgmt")?;
        bools(m, doc, &["led_enabled", "outdoor_mode_enabled", "x_ssh_enabled", "x_ssh_auth_password_enabled", "x_ssh_bind_wildcard"])?;
        // The official controller turns this on with every save of these settings; the
        // features it gates (band steering, minimum signal and more) need it.
        doc["advanced_feature_enabled"] = json!(true);
        if let Some(u) = m["x_ssh_username"].as_str().map(str::trim) {
            let ok = (1..=30).contains(&u.len())
                && u.chars().enumerate().all(|(i, c)| c.is_ascii_alphanumeric() || c == '_' || i > 0 && matches!(c, '-' | '.'))
                && u != "root";
            if !ok {
                return Err("the SSH user name must be 1 to 30 letters, digits, '_', '-' or '.', starting with a letter, digit or '_' (and not root)".into());
            }
            doc["x_ssh_username"] = json!(u);
        }
        if let Some(pw) = m["x_ssh_password"].as_str() {
            set_ssh_password(doc, pw)?;
            notes.push("SSH password".into());
        }
        if !m["x_ssh_keys"].is_null() {
            doc["x_ssh_keys"] = json!(ssh_keys(&m["x_ssh_keys"])?);
        }
        let doc = &*doc;
        if doc["x_ssh_enabled"].as_bool() != Some(false) && doc["x_ssh_auth_password_enabled"].as_bool() == Some(false) && doc["x_ssh_keys"].as_array().is_none_or(Vec::is_empty) {
            return Err("with password logins off, SSH needs at least one key".into());
        }
    }

    let r = &p["rsyslogd"];
    if !r.is_null() {
        let doc = setting_mut(state, "rsyslogd")?;
        bools(r, doc, &["debug", "netconsole_enabled"])?;
        // Off, to apctl ("Network Application"), or to a server, saved as the official UI does.
        match r["mode"].as_str() {
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
        if let Some(ip) = r["ip"].as_str().map(str::trim) {
            if !ip.is_empty() && !is_host(ip) {
                return Err(format!("{ip} is not a host name or address"));
            }
            doc["ip"] = json!(ip);
        }
        if let Some(n) = port(&r["port"], "the syslog port")? {
            doc["port"] = json!(n);
        }
        if let Some(h) = r["netconsole_host"].as_str().map(str::trim) {
            if !h.is_empty() && !is_host(h) {
                return Err(format!("{h} is not a host name or address"));
            }
            doc["netconsole_host"] = json!(h);
        }
        if let Some(n) = port(&r["netconsole_port"], "the netconsole port")? {
            doc["netconsole_port"] = json!(n);
        }
        let doc = &*doc;
        let on = |k: &str| doc[k].as_bool() == Some(true);
        if on("enabled") && !on("this_controller") && doc["ip"].as_str().is_none_or(str::is_empty) {
            return Err("remote syslog needs a server".into());
        }
        if on("netconsole_enabled") && doc["netconsole_host"].as_str().is_none_or(str::is_empty) {
            return Err("netconsole needs a host".into());
        }
    }

    let n = &p["ntp"];
    if !n.is_null() {
        let doc = setting_mut(state, "ntp")?;
        let was_manual = doc["setting_preference"].as_str() == Some("manual");
        match n["setting_preference"].as_str() {
            None => {}
            Some(pref @ ("auto" | "manual")) => doc["setting_preference"] = json!(pref),
            Some(_) => return Err("setting_preference must be auto or manual".into()),
        }
        if doc["setting_preference"].as_str() == Some("auto") {
            // Going back to automatic restores the pool, as the official controller does.
            if was_manual || doc["ntp_server_1"].is_null() {
                for (i, h) in NTP_POOL.iter().enumerate() {
                    doc[format!("ntp_server_{}", i + 1)] = json!(h);
                }
            }
        } else if (1..=4).any(|i| !n[format!("ntp_server_{i}")].is_null()) {
            // Manual servers replace all four.
            let mut list = Vec::new();
            for i in 1..=4 {
                if let Some(h) = n[format!("ntp_server_{i}")].as_str().map(str::trim).filter(|h| !h.is_empty()) {
                    if !is_host(h) {
                        return Err(format!("{h} is not a host name or IPv4 address"));
                    }
                    list.push(h.to_string());
                }
            }
            for i in 1..=4 {
                doc[format!("ntp_server_{i}")] = json!(list.get(i - 1).cloned().unwrap_or_default());
            }
        }
        if doc["setting_preference"].as_str() == Some("manual") && (1..=4).all(|i| doc[format!("ntp_server_{i}")].as_str().is_none_or(str::is_empty)) {
            return Err("manual NTP needs at least one server".into());
        }
    }

    if !p["country"].is_null() {
        let code = p["country"].as_i64().or_else(|| p["country"].as_str()?.parse().ok()).ok_or("country must be an ISO 3166 numeric code")?;
        if !COUNTRY_NAMES.iter().any(|(c, _)| *c == code) {
            return Err(format!("country {code} is not one apctl has channel rules for"));
        }
        setting_mut(state, "country")?["code"] = json!(code.to_string());
    }
    if let Some(tz) = p["timezone"].as_str() {
        if !apcfg::tz::names().any(|n| n == tz) {
            return Err(format!("{tz} is not a time zone apctl knows"));
        }
        setting_mut(state, "locale")?["timezone"] = json!(tz);
    }

    // The country and the outdoor default decide which fixed channels are legal.
    notes.extend(reset_illegal_channels(state));
    if !p["country"].is_null() && docs(state, "setting").any(|s| s["key"].as_str() == Some("radio_ai")) {
        // Channel AI's channel lists follow the country.
        crate::channelai::apply_settings(state, &json!({ "patch": {} }))?;
    }

    let mut changed: Vec<String> = Vec::new();
    let after = state["setting"].as_array().cloned().unwrap_or_default();
    for s in &after {
        let key = s["key"].as_str().unwrap_or("?");
        let old = before.as_array().and_then(|l| l.iter().find(|o| o["key"] == s["key"] && o["site_id"] == s["site_id"])).cloned().unwrap_or(Value::Null);
        for (k, v) in s.as_object().into_iter().flatten() {
            // Secrets are summed up as "SSH password" (from `notes`).
            if old[k] != *v && !SECRETS.contains(&k.as_str()) {
                changed.push(if k == "x_ssh_keys" { "SSH keys".to_string() } else { format!("{key}.{k}") });
            }
        }
    }
    changed.extend(notes);
    changed.dedup();
    Ok(if changed.is_empty() { "site settings: nothing changed".into() } else { format!("site settings: {}", changed.join(", ")) })
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
/// (`ssh-ed25519 AAAA... comment`) is split up.
fn ssh_keys(v: &Value) -> Result<Vec<Value>, String> {
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
            return Err(format!("not an SSH public key: {}", if key.is_empty() { kind } else { format!("{kind} {}…", &key[..key.len().min(12)]) }));
        }
        let name = k["name"].as_str().filter(|n| !n.is_empty()).map(str::to_string).unwrap_or_else(|| if comment.is_empty() { kind.clone() } else { comment.clone() });
        if !out.iter().any(|o: &Value| o["key"] == json!(key)) {
            out.push(json!({ "name": name, "type": kind, "key": key, "comment": comment }));
        }
    }
    Ok(out)
}

/// GET /api/settings/site
pub async fn get_site(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let state = s.live.read().unwrap().state.clone().ok_or_else(|| ApiError(StatusCode::CONFLICT, "no settings imported yet".into()))?;
    let m = setting(&state, "mgmt");
    let mut mgmt = json!({ "has_ssh_password": m["x_ssh_password"].as_str().is_some_and(|p| !p.is_empty()) });
    for k in ["led_enabled", "outdoor_mode_enabled", "x_ssh_enabled", "x_ssh_username", "x_ssh_auth_password_enabled", "x_ssh_bind_wildcard", "x_ssh_keys"] {
        mgmt[k] = m[k].clone();
    }
    let r = setting(&state, "rsyslogd");
    let mut rsyslogd = json!({});
    for k in ["ip", "port", "debug", "netconsole_enabled", "netconsole_host", "netconsole_port"] {
        rsyslogd[k] = r[k].clone();
    }
    rsyslogd["mode"] = json!(match (r["enabled"].as_bool() == Some(true), r["this_controller"].as_bool() == Some(true)) {
        (false, _) => "off",
        (true, true) => "controller",
        (true, false) => "server",
    });
    let n = setting(&state, "ntp");
    let mut ntp = json!({});
    for k in ["setting_preference", "ntp_server_1", "ntp_server_2", "ntp_server_3", "ntp_server_4"] {
        ntp[k] = n[k].clone();
    }
    Ok(Json(json!({
        "active": s.active, "mgmt": mgmt, "rsyslogd": rsyslogd, "ntp": ntp,
        "country": crate::settings::country(&state), "timezone": setting(&state, "locale")["timezone"],
        "countries": COUNTRY_NAMES.iter().map(|(c, n)| json!({ "code": c, "name": n })).collect::<Vec<_>>(),
        "timezones": apcfg::tz::names().collect::<Vec<_>>(),
    })))
}

/// PUT /api/settings/site {patch} (`?preview=true` to see the effect)
pub async fn put_site(State(s): State<AppState>, headers: HeaderMap, Query(q): Query<PreviewQuery>, Json(b): Json<Value>) -> Result<Json<Value>, ApiError> {
    crate::settings::change(&s, &headers, &q, apply_site, json!({ "patch": b["patch"] })).await
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
        apply_site(s, &json!({ "patch": patch }))
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
    }

    #[test]
    fn country_and_outdoor_defaults_reset_illegal_channels() {
        let mut s = state();
        // Channel 13 is not allowed in the US: it goes back to auto, as in the official controller.
        let what = edit(&mut s, json!({ "country": 840 })).unwrap();
        assert!(what.contains("AP Hall 2.4 GHz channel 13 → auto"), "{what}");
        assert_eq!(s["devices"][0]["radio_table"][1]["channel"], "auto");
        let mut s = state();
        let what = edit(&mut s, json!({ "mgmt": { "outdoor_mode_enabled": true } })).unwrap();
        assert!(what.contains("5 GHz channel 44 → auto"), "{what}");
        assert!(edit(&mut s, json!({ "country": 999 })).is_err());
        edit(&mut s, json!({ "country": 208, "timezone": "Europe/Copenhagen" })).unwrap();
        assert_eq!((setting(&s, "country")["code"].as_str(), setting(&s, "locale")["timezone"].as_str()), (Some("208"), Some("Europe/Copenhagen")));
        assert!(edit(&mut s, json!({ "timezone": "Mars/Olympus" })).is_err());
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
        edit(&mut s, json!({ "ntp": { "setting_preference": "auto" } })).unwrap();
        assert_eq!(setting(&s, "ntp")["ntp_server_1"], "0.ubnt.pool.ntp.org");
    }
}
