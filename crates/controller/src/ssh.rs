//! Adopting an AP over SSH ("adopt by IP"), for an AP that informs somewhere
//! else (e.g. a reset AP whose "unifi" DNS name points at another controller).
//!
//! As the official controller does it: log in with the given credentials
//! (else the site's device credentials, else the factory ones), and run
//! `/usr/bin/syswrapper.sh set-adopt <inform url> <key>`: the AP then informs
//! here with its new key. apctl first reads the AP's MAC (and model) so it can
//! create its record and key. The host key is accepted the first time and
//! kept (`x_ssh_hostkey_fingerprint`). For an AP apctl already knows at that
//! address, the kept key is checked before any password is sent.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use inform::Mac;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, AppState, Json};
use crate::clock;
use crate::engine::{Event, EventKind};

/// The URL APs should inform to: `--inform-url`, else the one the managed APs use.
pub fn inform_url(s: &AppState) -> Option<String> {
    if let Some(u) = &s.inform_url {
        return Some(u.clone());
    }
    let live = s.live.read().unwrap();
    live.state.as_deref()?["devices"].as_array()?.iter().find_map(|d| d["inform_url"].as_str().filter(|u| u.starts_with("http")).map(str::to_string))
}

/// Whether adopting over SSH can work: active mode and an inform URL to give.
pub fn available(s: &AppState) -> Value {
    let url = inform_url(s);
    json!({ "possible": s.active && url.is_some(), "inform_url": url })
}

struct Client {
    /// The fingerprint the server must present, if known.
    expected: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = match key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(russh::keys::HashAlg::Sha256).to_string(),
            // APs present plain keys; a certificate is identified by its public key.
            russh::keys::PublicKeyOrCertificate::Certificate(c) => c.public_key().fingerprint(russh::keys::HashAlg::Sha256).to_string(),
        };
        *self.seen.lock().unwrap() = Some(fp.clone());
        Ok(self.expected.as_ref().is_none_or(|e| *e == fp))
    }
}

/// Why an SSH adoption failed, as the official controller tells them apart.
#[derive(Debug, PartialEq)]
pub enum Failure {
    Unreachable(String),
    Login,
    HostKey,
    Command(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Unreachable(e) => write!(f, "could not reach the AP over SSH: {e}"),
            Failure::Login => write!(f, "the AP refused the username and password"),
            Failure::HostKey => write!(f, "the AP's SSH host key changed since last time"),
            Failure::Command(e) => write!(f, "the command failed on the AP: {e}"),
        }
    }
}

/// An SSH session to an AP.
struct Session {
    handle: russh::client::Handle<Client>,
    fingerprint: Option<String>,
}

/// How long connecting may take: an address with no AP answers late or never.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long each later step (a login attempt, a command) may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(15);
/// The most a command may print: what the AP prints is short, and another
/// host at that address could send anything.
const MAX_OUTPUT: usize = 64 << 10;

/// A connection, and the fingerprint of the host key it was made with.
type Conn = (russh::client::Handle<Client>, Arc<Mutex<Option<String>>>);

/// A connection with the host key checked, and the key's fingerprint.
async fn open(config: &Arc<russh::client::Config>, ip: &str, port: u16, expected: Option<&str>) -> Result<Conn, Failure> {
    let seen = Arc::new(Mutex::new(None));
    let client = Client { expected: expected.map(str::to_string), seen: seen.clone() };
    match tokio::time::timeout(CONNECT_TIMEOUT, russh::client::connect(config.clone(), (ip, port), client)).await {
        Err(_) => Err(Failure::Unreachable("timed out".into())),
        Ok(Err(russh::Error::UnknownKey)) => Err(Failure::HostKey),
        Ok(Err(e)) => Err(Failure::Unreachable(e.to_string())),
        Ok(Ok(h)) => Ok((h, seen)),
    }
}

/// Logs in with each username and password in turn, on one connection while
/// the AP keeps it open after a refusal (a new one when it doesn't).
async fn connect(ip: &str, port: u16, logins: &[(String, String)], expected: Option<String>) -> Result<Session, Failure> {
    let config = Arc::new(russh::client::Config { inactivity_timeout: Some(Duration::from_secs(20)), ..Default::default() });
    let login = |(mut handle, seen): Conn, user: String, pass: String| async move {
        let r = match tokio::time::timeout(STEP_TIMEOUT, handle.authenticate_password(user, pass)).await {
            Ok(Ok(r)) => Ok(r.success()),
            Ok(Err(e)) => Err(Failure::Unreachable(e.to_string())),
            Err(_) => Err(Failure::Unreachable("timed out".into())),
        };
        ((handle, seen), r)
    };
    let (handle, seen) = try_logins(logins, || open(&config, ip, port, expected.as_deref()), login).await?;
    let fingerprint = seen.lock().unwrap().clone();
    Ok(Session { handle, fingerprint })
}

/// Tries each login in turn (true: accepted), on the last connection while it
/// stays open. One that fails on a connection already used (the AP may have
/// closed it after a refusal) is tried once more on a new one, so a refusal is
/// not reported as an AP that cannot be reached.
async fn try_logins<C, O, L>(logins: &[(String, String)], mut open: impl FnMut() -> O, mut login: impl FnMut(C, String, String) -> L) -> Result<C, Failure>
where
    O: Future<Output = Result<C, Failure>>,
    L: Future<Output = (C, Result<bool, Failure>)>,
{
    let mut last = Failure::Login;
    let mut conn = None;
    for (user, pass) in logins {
        let mut reused = conn.is_some();
        loop {
            let c = match conn.take() {
                Some(c) => c,
                None => open().await?,
            };
            match login(c, user.clone(), pass.clone()).await {
                (c, Ok(true)) => return Ok(c),
                (c, Ok(false)) => {
                    last = Failure::Login;
                    conn = Some(c);
                }
                (_, Err(_)) if reused => {
                    reused = false;
                    continue;
                }
                (_, Err(f)) => last = f,
            }
            break;
        }
    }
    Err(last)
}

impl Session {
    /// Runs a command and returns what it printed; an error if it exited
    /// non-zero or didn't finish in time.
    async fn run(&self, cmd: &str) -> Result<String, Failure> {
        let mut out = Vec::new();
        let mut status = None;
        let run = async {
            let mut ch = self.handle.channel_open_session().await.map_err(|e| Failure::Command(e.to_string()))?;
            ch.exec(true, cmd).await.map_err(|e| Failure::Command(e.to_string()))?;
            // The exit status comes after the end of the output, so read until the channel closes.
            while let Some(msg) = ch.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data } => {
                        if out.len() + data.len() > MAX_OUTPUT {
                            return Err(Failure::Command(format!("more than {MAX_OUTPUT} bytes of output")));
                        }
                        out.extend_from_slice(&data)
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            Ok(())
        };
        tokio::time::timeout(STEP_TIMEOUT, run).await.map_err(|_| Failure::Command("timed out".into()))??;
        let out = String::from_utf8_lossy(&out).into_owned();
        match status {
            Some(code) if code != 0 => Err(Failure::Command(format!("exit status {code}: {}", out.trim()))),
            _ => Ok(out),
        }
    }
}

/// A word for the AP's shell, in single quotes.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The host key apctl kept for an AP it knows at this address, and that AP:
/// the AP informing from it, else one whose record has this IP (written at
/// adoption, never refreshed) unless it informs from another address now.
fn known_host_key(live: &crate::engine::Live, ip: &str) -> Option<(Mac, String)> {
    let state = live.state.as_deref()?;
    let fingerprint = |mac: &Mac| crate::adopt::device_doc(state, mac).and_then(|d| d["x_ssh_hostkey_fingerprint"].as_str()).map(str::to_string);
    // The AP there now is the one to check against: its key, or none kept.
    if let Some(mac) = live.by_ip.get(ip) {
        return Some((*mac, fingerprint(mac)?));
    }
    let moved = |mac: &Mac| live.by_ip.values().any(|m| m == mac);
    let by_record = state["devices"].as_array()?.iter().filter(|d| d["ip"].as_str() == Some(ip)).filter_map(|d| crate::settings::doc_mac(&d["mac"]));
    by_record.filter(|mac| !moved(mac)).find_map(|mac| Some((mac, fingerprint(&mac)?)))
}

/// A MAC as the AP prints it (`/sys/class/net/eth0/address`, `board.hwaddr`):
/// with or without separators, and a line end.
fn parse_mac(text: &str) -> Option<Mac> {
    text.trim().parse().ok()
}

/// The address typed for the AP, written as apctl writes addresses (the APs'
/// records, `by_ip`): an IPv4-mapped IPv6 one as IPv4, IPv6 in its short form.
fn canonical_ip(text: &str) -> Option<String> {
    text.trim().parse::<std::net::IpAddr>().ok().map(|ip| ip.to_canonical().to_string())
}

/// `key=value` lines (as in /etc/board.info).
fn board_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.trim().strip_prefix(key)?.strip_prefix('=')).map(str::trim).filter(|v| !v.is_empty())
}

/// The usernames and passwords to try: the ones given, else the site's device
/// login (its password, with the user the APs get: [`apcfg::ssh_username`]),
/// then the factory ones.
fn logins(state: Option<&Value>, given: Option<(String, String)>) -> Vec<(String, String)> {
    if let Some(g) = given {
        return vec![g];
    }
    let mut out: Vec<(String, String)> = Vec::new();
    let site = state.map(|st| crate::settings::setting(st, "mgmt")).and_then(|m| Some((apcfg::ssh_username(m), m["x_ssh_password"].as_str()?)));
    // A stored empty user name reaches the APs as it is, but no SSH login has it.
    if let Some((u, p)) = site.filter(|(u, _)| !u.is_empty()) {
        out.push((u.to_string(), p.to_string()));
    }
    for (u, p) in [("ubnt", "ubnt"), ("ui", "ui")] {
        let login = (u.to_string(), p.to_string());
        if !out.contains(&login) {
            out.push(login);
        }
    }
    out
}

/// What [`ssh_record`] did to the AP's record.
#[derive(Clone, Copy, Debug)]
struct Made {
    /// This edit made the record, so a failed adoption removes what it added,
    /// and only that: the settings may have changed in the time the SSH
    /// commands took.
    created: bool,
    /// The record's key, read as informs read it: what `set-adopt` sends.
    key: [u8; 16],
}

/// The edit that readies an AP's record for adoption over SSH: a new record
/// (and key) unless apctl has one, the URL it is to inform to, and its host
/// key the first time. A kept record without a usable key takes the key file's
/// (`file_key`), which its informs open with (see `adopt::device_key`); without
/// one it is refused, unchanged.
fn ssh_record(st: &mut Value, mac: &Mac, payload: &Value, fingerprint: Option<&str>, file_key: Option<[u8; 16]>) -> Result<(String, Made), String> {
    // A known AP keeps its key: it reaches the AP over SSH, and is never sealed
    // with the factory key (see `Adopting::kept_key`).
    let created = crate::adopt::device_doc(st, mac).is_none();
    if !created && record_key(st, mac).is_none() {
        let k = file_key.ok_or_else(|| format!("{mac}: neither its record (x_authkey) nor the key file has a usable key; forget the AP and adopt it again"))?;
        crate::adopt::device_doc_mut(st, mac).ok_or("no record")?["x_authkey"] = json!(hex::encode(k));
    }
    let what = if created { format!("{} over SSH", crate::adopt::adopt_device(st, mac, payload)?) } else { format!("adopting {mac} over SSH") };
    let key = record_key(st, mac).ok_or("the new record has no key")?;
    let d = crate::adopt::device_doc_mut(st, mac).ok_or("no record")?;
    d["inform_url"] = payload["inform_url"].clone();
    if let Some(fp) = fingerprint
        && d["x_ssh_hostkey_fingerprint"].is_null()
    {
        d["x_ssh_hostkey_fingerprint"] = json!(fp);
    }
    Ok((what, Made { created, key }))
}

/// The record's `x_authkey`, as `inform::parse_key` reads it (trimmed, 16 bytes of hex).
fn record_key(st: &Value, mac: &Mac) -> Option<[u8; 16]> {
    inform::parse_key(crate::adopt::device_doc(st, mac)?["x_authkey"].as_str()?).ok()
}

#[derive(Deserialize)]
pub struct AdoptBody {
    ip: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// POST /api/devices/adopt-ssh {ip, port?, username?, password?}. Run as a
/// task of its own: a request dropped mid-way (the page left, the proxy giving
/// up) must not stop it between its record edit and what follows (`set-adopt`,
/// and undoing the record if that fails).
pub async fn adopt(State(s): State<AppState>, Json(b): Json<AdoptBody>) -> Result<Json<Value>, ApiError> {
    tokio::spawn(adopt_over_ssh(s, b)).await?
}

/// [`adopt`]'s work.
async fn adopt_over_ssh(s: AppState, b: AdoptBody) -> Result<Json<Value>, ApiError> {
    crate::api::require_active(&s, "adoption needs")?;
    let url = inform_url(&s).ok_or_else(|| ApiError::conflict("apctl doesn't know the URL APs should inform to: set --inform-url"))?;
    let ip = canonical_ip(&b.ip).ok_or_else(|| ApiError::bad("enter the AP's IP address"))?;
    let state = s.live.read().unwrap().state.clone();
    let given = match (b.username.filter(|u| !u.is_empty()), b.password) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    };
    let bad = |f: Failure| ApiError(StatusCode::BAD_GATEWAY, f.to_string());
    // A known AP keeps its host key, checked before any password is sent; a new one is trusted the first time.
    let expected = known_host_key(&s.live.read().unwrap(), &ip);
    let connected = connect(&ip, b.port.unwrap_or(22), &logins(state.as_deref(), given), expected.as_ref().map(|e| e.1.clone())).await;
    let session = match (connected, &expected) {
        (Err(Failure::HostKey), Some((mac, _))) => {
            s.note(Event::device(clock::now_ts(), EventKind::ApHostKeyMismatch, *mac, json!({ "ip": ip }))).await;
            return Err(bad(Failure::HostKey));
        }
        (r, _) => r.map_err(bad)?,
    };
    let board = session.run("cat /etc/board.info").await.unwrap_or_default();
    let eth0 = session.run("cat /sys/class/net/eth0/address").await.unwrap_or_default();
    let mac = parse_mac(&eth0)
        .or_else(|| board_value(&board, "board.hwaddr").and_then(parse_mac))
        .ok_or_else(|| ApiError(StatusCode::BAD_GATEWAY, "could not read the AP's MAC address: is this a UniFi AP?".into()))?;
    // An AP apctl knows by its MAC but not at this address: check its key too.
    let known = state.as_deref().and_then(|st| crate::adopt::device_doc(st, &mac));
    if let (Some(k), Some(seen)) = (known.and_then(|d| d["x_ssh_hostkey_fingerprint"].as_str()), &session.fingerprint)
        && k != seen
    {
        s.note(Event::device(clock::now_ts(), EventKind::ApHostKeyMismatch, mac, json!({ "ip": ip }))).await;
        return Err(bad(Failure::HostKey));
    }
    // Its record (and key), unless apctl has it already.
    let payload = json!({
        "mac": mac.to_string(), "ip": ip, "model": board_value(&board, "board.shortname").or(board_value(&board, "board.name")),
        "hostname": board_value(&board, "board.name"), "inform_url": url,
    });
    let fingerprint = session.fingerprint.clone();
    let file_key = s.keys.get(&mac).copied();
    // Held until the adoption is expected: no other adoption gives the AP a new key meanwhile.
    let claim = crate::adopt::Claim::take(&s.live, mac)?;
    let cell = Arc::new(Mutex::new(None));
    let made = cell.clone();
    let edit = move |st: &mut Value| {
        let (what, m) = ssh_record(st, &mac, &payload, fingerprint.as_deref(), file_key)?;
        *made.lock().unwrap() = Some(m);
        Ok(what)
    };
    crate::actions::apply_edit(&s, Box::new(edit)).await?;
    let Made { created, key: made_key } = cell.lock().unwrap().ok_or_else(|| ApiError::internal("the record edit said nothing of its key"))?;
    let key = hex::encode(made_key);
    // Expected from now on: the AP may inform with its key before the command returns.
    let since = clock::now_ts();
    let adopting = crate::adopt::Adopting { since, kept_key: !created };
    {
        let mut live = s.live.write().unwrap();
        live.adoption.adopting.insert(mac, adopting);
        claim.release(&mut live);
    }
    let out = match session.run(&format!("/usr/bin/syswrapper.sh set-adopt {} {}", shell_quote(&url), shell_quote(&key))).await {
        Ok(out) => out,
        // Tested and taken in one write: an AP back with its key already has ended the adoption, so it worked.
        Err(f) if s.live.write().unwrap().adoption.adopting.remove(&mac).is_none() => {
            tracing::warn!("{mac}: set-adopt reported a failure, but the AP informs with its key: {f}");
            String::new()
        }
        Err(f) => {
            // Not adopted after all: a record made for it would make it look like one of ours. Left
            // alone if it is no longer this adoption's (another gave it a new key), or the AP informed
            // with its key after all (from now on it is no longer expected): removing it would strand
            // the AP until it is reset.
            if created {
                let live = s.live.clone();
                let undo = move |st: &mut Value| {
                    let heard = live.read().unwrap().devices.get(&mac).is_some_and(|d| d.last_seen >= since);
                    if heard || record_key(st, &mac) != Some(made_key) {
                        return Ok(format!("{mac}: adopting it over SSH failed, but its record stays"));
                    }
                    crate::adopt::remove_device(st, &mac).map(|what| format!("{what}: adopting it over SSH failed"))
                };
                let _ = crate::actions::apply_edit(&s, Box::new(undo)).await;
            }
            return Err(bad(f));
        }
    };
    s.note(Event::device(clock::now_ts(), EventKind::ApAdopting, mac, json!({ "ip": ip, "via": "ssh" }))).await;
    tracing::info!("{mac}: set-adopt {url} sent over SSH ({})", out.trim());
    Ok(Json(json!({ "adopting": true, "mac": mac, "inform_url": url })))
}

/// A SHA-512 crypt(3) hash (`$6$salt$hash`, 5000 rounds, 8-character salt):
/// what the AP config carries for the SSH password.
pub fn sha512_crypt(password: &str) -> String {
    use sha_crypt::{PasswordHasher, ShaCrypt};
    let h = ShaCrypt::SHA512.hash_password_with_salt(password.as_bytes(), &crate::random_bytes::<6>()).expect("SHA-512 crypt").to_string();
    // The default round count need not be spelled out, and the APs' own hashes leave it out.
    h.replacen("$rounds=5000$", "$", 1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ssh_password_hashes_are_standard_sha512_crypt() {
        use sha_crypt::{PasswordVerifier, ShaCrypt};
        // The test vector from the SHA-crypt specification checks the verifier reads this form.
        ShaCrypt::SHA512.verify_password(b"Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1").unwrap();
        let h = super::sha512_crypt("correct horse");
        let parts: Vec<&str> = h.split('$').collect();
        assert_eq!((parts[1], parts[2].len(), parts[3].len()), ("6", 8, 86), "{h}");
        ShaCrypt::SHA512.verify_password(b"correct horse", h.as_str()).unwrap();
        assert!(ShaCrypt::SHA512.verify_password(b"wrong", h.as_str()).is_err());
    }

    use super::*;

    #[test]
    fn credentials_are_tried_given_then_site_then_factory() {
        let state = json!({ "devices": [{ "site_id": "s1" }], "setting": [{ "key": "mgmt", "site_id": "s1", "x_ssh_username": "admin", "x_ssh_password": "pw" }] });
        assert_eq!(logins(Some(&state), Some(("me".into(), "mine".into()))), vec![("me".to_string(), "mine".to_string())], "given: only that");
        let users: Vec<String> = logins(Some(&state), None).into_iter().map(|x| x.0).collect();
        assert_eq!(users, ["admin", "ubnt", "ui"]);
        assert_eq!(logins(None, None).len(), 2);
        // The site's login may be a factory one: each is tried once.
        let state = json!({ "devices": [{ "site_id": "s1" }], "setting": [{ "key": "mgmt", "site_id": "s1", "x_ssh_username": "ui", "x_ssh_password": "ui" }] });
        let users: Vec<String> = logins(Some(&state), None).into_iter().map(|x| x.0).collect();
        assert_eq!(users, ["ui", "ubnt"]);
        // A site with only a password set: the APs' user is ubnt, with that password.
        let state = json!({ "devices": [{ "site_id": "s1" }], "setting": [{ "key": "mgmt", "site_id": "s1", "x_ssh_password": "pw" }] });
        assert_eq!(logins(Some(&state), None)[..2], [("ubnt".to_string(), "pw".to_string()), ("ubnt".to_string(), "ubnt".to_string())]);
    }

    /// `try_logins` against an AP that accepts `password` and closes a
    /// connection after `refusals` refused logins on it: the connections
    /// opened, and the outcome (the connection logged in on).
    async fn logins_against(password: &str, refusals: usize, tries: &[&str]) -> (usize, Result<usize, Failure>) {
        use std::cell::RefCell;
        // Per connection: how many logins it refused.
        let refused = RefCell::new(Vec::<usize>::new());
        let conns = &refused;
        let logins: Vec<(String, String)> = tries.iter().map(|p| ("ubnt".to_string(), p.to_string())).collect();
        let open = move || async move {
            conns.borrow_mut().push(0);
            Ok::<usize, Failure>(conns.borrow().len() - 1)
        };
        let login = move |c: usize, _user: String, pass: String| async move {
            let mut conns = conns.borrow_mut();
            if conns[c] >= refusals {
                return (c, Err(Failure::Unreachable("disconnected".into())));
            }
            if pass == password {
                return (c, Ok(true));
            }
            conns[c] += 1;
            (c, Ok(false))
        };
        let r = try_logins(&logins, open, login).await;
        (refused.borrow().len(), r)
    }

    #[tokio::test]
    async fn a_login_is_tried_again_when_the_ap_closed_the_connection() {
        // The AP closes the connection after each refusal: each login gets a new one.
        assert_eq!(logins_against("ui", 1, &["admin", "ubnt", "ui"]).await, (3, Ok(2)));
        assert_eq!(logins_against("x", 1, &["admin", "ubnt", "ui"]).await, (3, Err(Failure::Login)), "refused, not unreachable");
        // One that keeps it open: one connection for all.
        assert_eq!(logins_against("ui", 5, &["admin", "ubnt", "ui"]).await, (1, Ok(0)));
        assert_eq!(logins_against("ui", 2, &["admin", "ubnt", "ui"]).await, (2, Ok(1)));
    }

    #[test]
    fn board_info_values() {
        let text = "board.sysid=0xa611\nboard.name=U6-Mesh\nboard.shortname=U6M\nboard.hwaddr=02:00:00:00:00:09\n";
        assert_eq!((board_value(text, "board.shortname"), board_value(text, "board.name")), (Some("U6M"), Some("U6-Mesh")));
        assert_eq!(board_value(text, "board.missing"), None);
        assert_eq!(parse_mac("02AB0000009A").map(|m| m.to_string()).as_deref(), Some("02:ab:00:00:00:9a"));
        assert_eq!(parse_mac("02:ab:00:00:00:9a\n").map(|m| m.to_string()).as_deref(), Some("02:ab:00:00:00:9a"));
        assert!(parse_mac("cat: no such file").is_none());
        assert!(parse_mac("02:ab-00:00:00:9a").is_none(), "one separator throughout");
    }

    #[test]
    fn the_record_edit_says_whether_it_made_the_record() {
        let mac: Mac = "02:00:00:00:00:09".parse().unwrap();
        let payload = json!({ "mac": mac.to_string(), "ip": "192.0.2.9", "model": "U6M", "inform_url": "http://192.0.2.1:8080/inform" });
        let mut st = json!({ "devices": [{ "mac": "02:00:00:00:00:01", "site_id": "s1" }] });
        let (what, made) = ssh_record(&mut st, &mac, &payload, Some("SHA256:abc"), None).unwrap();
        assert!(what.starts_with("adopted AP U6M") && made.created);
        let d = crate::adopt::device_doc(&st, &mac).unwrap();
        assert_eq!((d["inform_url"].as_str(), d["x_ssh_hostkey_fingerprint"].as_str(), d["x_authkey"].as_str().map(str::len)), (Some("http://192.0.2.1:8080/inform"), Some("SHA256:abc"), Some(32)));
        assert_eq!(d["x_authkey"].as_str(), Some(hex::encode(made.key).as_str()));
        // A record already there (made meanwhile, say) is not this edit's: a rollback leaves it, and its key.
        let key = d["x_authkey"].clone();
        let (what, made) = ssh_record(&mut st, &mac, &payload, Some("SHA256:other"), None).unwrap();
        assert_eq!((what, made.created), (format!("adopting {mac} over SSH"), false));
        let d = crate::adopt::device_doc(&st, &mac).unwrap();
        assert_eq!((&d["x_authkey"], d["x_ssh_hostkey_fingerprint"].as_str()), (&key, Some("SHA256:abc")), "the first host key is kept");
        // A kept key is sent as informs read it: trimmed. One that does not read is refused, the record unchanged.
        let padded = format!(" {}\n", key.as_str().unwrap().to_uppercase());
        crate::adopt::device_doc_mut(&mut st, &mac).unwrap()["x_authkey"] = json!(padded);
        assert_eq!(hex::encode(ssh_record(&mut st, &mac, &payload, None, None).unwrap().1.key), key.as_str().unwrap());
        crate::adopt::device_doc_mut(&mut st, &mac).unwrap()["x_authkey"] = json!("not hex");
        let before = st.clone();
        assert!(ssh_record(&mut st, &mac, &json!({ "inform_url": "http://192.0.2.2:8080/inform" }), None, None).unwrap_err().contains("nor the key file"));
        assert_eq!(st, before);
        // Unless the key file has the AP's key, which its informs open with: the record takes it.
        let (_, made) = ssh_record(&mut st, &mac, &payload, None, Some([7; 16])).unwrap();
        assert_eq!((made.key, crate::adopt::device_doc(&st, &mac).unwrap()["x_authkey"].as_str()), ([7; 16], Some("07".repeat(16).as_str())));
    }

    #[test]
    fn shell_words_are_quoted() {
        assert_eq!(shell_quote("http://192.0.2.1:8080/inform"), "'http://192.0.2.1:8080/inform'");
        assert_eq!(shell_quote("http://x/$(reboot);a'b"), r"'http://x/$(reboot);a'\''b'");
    }

    #[test]
    fn host_keys_of_aps_known_at_an_address() {
        let ap: Mac = "02:00:00:00:00:01".parse().unwrap();
        let state = json!({ "devices": [
            { "mac": "02:00:00:00:00:01", "ip": "192.0.2.5", "x_ssh_hostkey_fingerprint": "SHA256:abc" },
            { "mac": "02:00:00:00:00:02", "ip": "192.0.2.6" },
        ] });
        let mut live = crate::engine::Live { state: Some(std::sync::Arc::new(state)), ..Default::default() };
        assert_eq!(known_host_key(&live, "192.0.2.5"), Some((ap, "SHA256:abc".into())));
        assert_eq!(known_host_key(&live, "192.0.2.6"), None, "no key kept yet");
        assert_eq!(known_host_key(&live, "192.0.2.7"), None);
        // An AP that informs from another address than its record says.
        live.by_ip.insert("192.0.2.7".into(), ap);
        assert_eq!(known_host_key(&live, "192.0.2.7"), Some((ap, "SHA256:abc".into())));
        // Its record's address is no longer its own (DHCP moved it): another AP there is not checked against its key.
        assert_eq!(known_host_key(&live, "192.0.2.5"), None);
        // Nor when the AP informing from an address has no key kept, whatever a stale record says.
        live.by_ip.clear();
        live.by_ip.insert("192.0.2.5".into(), "02:00:00:00:00:02".parse().unwrap());
        assert_eq!(known_host_key(&live, "192.0.2.5"), None);
    }

    #[test]
    fn a_typed_address_is_written_as_the_records_write_it() {
        assert_eq!(canonical_ip(" 192.0.2.5 ").as_deref(), Some("192.0.2.5"));
        assert_eq!(canonical_ip("::ffff:192.0.2.5").as_deref(), Some("192.0.2.5"));
        assert_eq!(canonical_ip("2001:DB8:0:0::0:5").as_deref(), Some("2001:db8::5"));
        assert_eq!(canonical_ip("ap.example"), None);
        // So the kept host key of an AP is found however its address is typed.
        let state = json!({ "devices": [{ "mac": "02:00:00:00:00:01", "ip": "2001:db8::5", "x_ssh_hostkey_fingerprint": "SHA256:abc" }] });
        let live = crate::engine::Live { state: Some(std::sync::Arc::new(state)), ..Default::default() };
        let typed = canonical_ip("2001:0db8::0005").unwrap();
        assert_eq!(known_host_key(&live, &typed).map(|k| k.1).as_deref(), Some("SHA256:abc"));
    }
}
