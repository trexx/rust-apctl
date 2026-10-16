//! Built-in login: users from a file of `username:argon2-hash` lines, and
//! cookie sessions.
//!
//! Session tokens are 256 random bits. Only their SHA-256 is kept (in memory
//! and in `config.db`), so a copy of the database cannot be used to log in.
//! Sessions slide: each use extends them to 30 days from now.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::types::Value as Sql;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::api::AppState;
use crate::model::Ts;
use crate::store::{self, Db, Store, Writer};

pub const COOKIE: &str = "apctl_session";
const SESSION_SECS: Ts = 30 * 86400;
const MAX_FAILURES: u32 = 5;
const FAILURE_WINDOW: Ts = 300;

/// Hashes a password for the users file (Argon2id, random salt).
pub fn hash_password(password: &str) -> Result<String> {
    Ok(Argon2::default().hash_password(password.as_bytes()).map_err(|e| anyhow::anyhow!("{e}"))?.to_string())
}

#[derive(Default)]
pub struct Users {
    hashes: HashMap<String, String>,
    /// What an unknown username is checked against: the first user's hash, so
    /// it costs the same as a known one whatever parameters the file uses.
    dummy: String,
}

impl Users {
    /// Reads `username:hash` lines; blank lines and `#` comments are ignored.
    /// A line that is not `username:hash` stops the start. Lines that could
    /// never log in (no username, a name listed again, a hash other than
    /// Argon2) are skipped with a warning, as `--keys` does with its entries;
    /// a file left without users then is an error, not read-only mode.
    pub fn load(path: &Path) -> Result<Users> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading users from {}", path.display()))?;
        let mut users = Users::default();
        let mut skipped = 0;
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = format!("{}:{}", path.display(), n + 1);
            let Some((user, hash)) = line.split_once(':') else { bail!("{at}: expected username:hash") };
            let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("{at}: invalid hash: {e}"))?;
            let why = if user.is_empty() {
                Some("no username".to_string())
            } else if users.hashes.contains_key(user) {
                Some(format!("{user:?} is listed already (the first line counts)"))
            } else if argon2::Algorithm::try_from(parsed.algorithm.as_str()).is_err() {
                Some(format!("{user:?} has a {} hash, and only Argon2 ones can log in (see apctl hash-password)", parsed.algorithm.as_str()))
            } else {
                None
            };
            if let Some(why) = why {
                tracing::warn!("{at}: skipping the line: {why}");
                skipped += 1;
                continue;
            }
            if users.hashes.is_empty() {
                users.dummy = hash.to_string();
            }
            users.hashes.insert(user.to_string(), hash.to_string());
        }
        if users.is_empty() && skipped > 0 {
            bail!("{}: no user can log in (see the warnings above)", path.display());
        }
        Ok(users)
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Checks a password. Unknown users cost the same as wrong passwords, so
    /// timing does not reveal which usernames exist: they are checked against
    /// a real user's hash, which no password can pass for them.
    pub fn verify(&self, user: &str, password: &str) -> bool {
        let (hash, known) = match self.hashes.get(user) {
            Some(h) => (h.as_str(), true),
            None => (self.dummy.as_str(), false),
        };
        let ok = PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok());
        ok && known
    }
}

#[derive(Clone)]
struct Session {
    user: String,
    expires: Ts,
}

pub struct Auth {
    pub users: Users,
    sessions: Mutex<HashMap<String, Session>>,
    /// Login attempts per address in the current window (the count, and when
    /// the window started).
    failures: Mutex<HashMap<IpAddr, (u32, Ts)>>,
    writer: Writer,
    proxies: Arc<Proxies>,
}

pub type SharedAuth = Arc<Auth>;

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl Auth {
    pub fn new(users: Users, store: &Store, writer: Writer, proxies: Arc<Proxies>) -> Result<Auth> {
        let now = store::now_ts();
        let rows = store.read(Db::Config, |c| {
            let mut stmt = c.prepare("SELECT token_hash, username, expires FROM sessions WHERE expires > ?1")?;
            let rows = stmt
                .query_map([now], |r| Ok((r.get::<_, String>(0)?, Session { user: r.get(1)?, expires: r.get(2)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        // Sessions of users that were removed from the file stop working.
        let sessions = rows.into_iter().filter(|(_, s)| users.hashes.contains_key(&s.user)).collect();
        Ok(Auth { users, sessions: Mutex::new(sessions), failures: Mutex::new(HashMap::new()), writer, proxies })
    }

    pub fn enabled(&self) -> bool {
        !self.users.is_empty()
    }

    pub(crate) fn create(&self, user: &str) -> Result<String> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random: {e}"))?;
        let token = hex::encode(bytes);
        let now = store::now_ts();
        let session = Session { user: user.to_string(), expires: now + SESSION_SECS };
        let hash = token_hash(&token);
        self.writer.exec(
            Db::Config,
            "INSERT OR REPLACE INTO sessions (token_hash, username, created, expires) VALUES (?1, ?2, ?3, ?4)",
            vec![Sql::Text(hash.clone()), Sql::Text(user.to_string()), Sql::Integer(now), Sql::Integer(session.expires)],
        );
        let mut sessions = self.sessions.lock().unwrap();
        // Expired sessions are otherwise only dropped when presented. Every
        // session starts here, so this keeps the map to the live ones.
        sessions.retain(|_, s| s.expires > now);
        sessions.insert(hash, session);
        Ok(token)
    }

    /// Returns the user for a valid session token, extending it.
    fn check(&self, token: &str) -> Option<String> {
        let hash = token_hash(token);
        let now = store::now_ts();
        let mut sessions = self.sessions.lock().unwrap();
        let s = sessions.get_mut(&hash)?;
        if s.expires <= now {
            sessions.remove(&hash);
            return None;
        }
        // Persist the extension at most about once a day per session.
        if now + SESSION_SECS - s.expires > 86400 {
            s.expires = now + SESSION_SECS;
            self.writer.exec(Db::Config, "UPDATE sessions SET expires = ?1 WHERE token_hash = ?2", vec![Sql::Integer(s.expires), Sql::Text(hash.clone())]);
        }
        Some(s.user.clone())
    }

    fn revoke(&self, token: &str) {
        let hash = token_hash(token);
        self.sessions.lock().unwrap().remove(&hash);
        self.writer.exec(Db::Config, "DELETE FROM sessions WHERE token_hash = ?1", vec![Sql::Text(hash)]);
    }

    /// Counts a login attempt from `ip`, before the password is checked, so
    /// parallel requests cannot all get in under the limit. False when the
    /// address has used up its attempts for this window.
    fn attempt(&self, ip: IpAddr) -> bool {
        let now = store::now_ts();
        let mut f = self.failures.lock().unwrap();
        // Forget windows that have passed, so the map stays small.
        f.retain(|_, (_, since)| now - *since < FAILURE_WINDOW);
        let e = f.entry(throttled(ip)).or_insert((0, now));
        if e.0 >= MAX_FAILURES {
            return false;
        }
        e.0 += 1;
        true
    }

    /// An attempt that does not count against the address: a successful
    /// login, or one never checked.
    fn refund(&self, ip: IpAddr) {
        if let Some(e) = self.failures.lock().unwrap().get_mut(&throttled(ip)) {
            e.0 = e.0.saturating_sub(1);
        }
    }
}

/// What login attempts are counted by: the address, or for IPv6 its /64 (one
/// host usually has a whole /64 to pick addresses from).
fn throttled(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(a) => IpAddr::V6((u128::from(a) & !u128::from(u64::MAX)).into()),
        v4 => v4,
    }
}

/// Reverse proxies whose X-Forwarded-For header is believed (`--trusted-proxies`).
#[derive(Debug, Default)]
pub struct Proxies(Vec<(IpAddr, u8)>);

impl Proxies {
    /// Addresses (`10.0.0.1`) and CIDR ranges (`10.42.0.0/16`, `fd00::/8`).
    pub fn parse(list: &[String]) -> Result<Proxies> {
        let mut out = Vec::new();
        for item in list.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let (addr, len) = item.split_once('/').map_or((item, None), |(a, l)| (a, Some(l)));
            let addr: IpAddr = addr.parse().with_context(|| format!("trusted proxy {item:?}: not an IP address"))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            let len = match len {
                Some(l) => l.parse::<u8>().ok().filter(|l| *l <= max).with_context(|| format!("trusted proxy {item:?}: bad prefix length"))?,
                None => max,
            };
            out.push((addr, len));
        }
        Ok(Proxies(out))
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|&(net, len)| match (net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => len == 0 || (u32::from(n) ^ u32::from(a)) >> (32 - u32::from(len)) == 0,
            (IpAddr::V6(n), IpAddr::V6(a)) => len == 0 || (u128::from(n) ^ u128::from(a)) >> (128 - u32::from(len)) == 0,
            _ => false,
        })
    }

    /// The client's address. X-Forwarded-For counts only on a connection from
    /// a trusted proxy, and then its right-most hop that is not itself a
    /// trusted proxy: hops further left were written by the client and can
    /// be anything. A hop may carry a port (`203.0.113.7:4711`, `[2001:db8::1]:4711`).
    pub fn client_ip(&self, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
        let peer = peer.to_canonical();
        if !self.contains(peer) {
            return peer;
        }
        let mut client = peer;
        for hop in headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).rev() {
            let Some(ip) = hop_ip(hop.trim()) else {
                // Skipping it would believe the hops left of it, which the
                // client wrote: the last proxy's address is kept instead, so
                // the clients behind it share their login attempts. Said once,
                // as it is the proxy's setup that needs fixing.
                static SAID: std::sync::Once = std::sync::Once::new();
                SAID.call_once(|| tracing::warn!("X-Forwarded-For hop {hop:?} from {client} is not an address: logins through that proxy are throttled as one client"));
                break;
            };
            client = ip.to_canonical();
            if !self.contains(client) {
                break;
            }
        }
        client
    }
}

/// The address of an X-Forwarded-For hop, with or without a port.
fn hop_ip(hop: &str) -> Option<IpAddr> {
    hop.parse::<IpAddr>().ok().or_else(|| hop.parse::<SocketAddr>().ok().map(|a| a.ip())).or_else(|| hop.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
}

pub fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

fn cookie(headers: &HeaderMap, value: &str, max_age: Ts) -> String {
    let https = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https");
    format!("{COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}", if https { "; Secure" } else { "" })
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

/// Reads that hand out secrets: Wi-Fi passphrases, and backups (which hold the
/// APs' keys and the passphrases). Read-only mode does not serve them.
fn secret(path: &str) -> bool {
    path.starts_with("/api/backups/file/") || (path.starts_with("/api/settings/wlans/") && path.ends_with("/passphrase"))
}

/// Whether a request carries the header every change must have. Browsers
/// cannot add custom headers to cross-site requests without a CORS preflight,
/// which this server never approves, so another website cannot make a
/// visitor's browser change data.
fn csrf_ok(headers: &HeaderMap) -> bool {
    headers.get("x-requested-with").and_then(|v| v.to_str().ok()) == Some("apctl")
}

/// Guards every API route except login/logout/me; changes (anything but GET,
/// HEAD and OPTIONS) also need the CSRF header.
pub async fn require_login(State(s): State<AppState>, req: Request, next: Next) -> Response {
    let auth = &s.auth;
    let mutating = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !auth.enabled() {
        // Without users apctl is read-only, and keeps its secrets.
        if mutating {
            return json_error(StatusCode::FORBIDDEN, "read-only: no users are configured (see --users-file)");
        }
        if secret(req.uri().path()) {
            return json_error(StatusCode::FORBIDDEN, "this needs a login: no users are configured (see --users-file)");
        }
        return next.run(req).await;
    }
    match session_token(req.headers()).and_then(|t| auth.check(&t)) {
        Some(_) if mutating && !csrf_ok(req.headers()) => json_error(StatusCode::FORBIDDEN, "missing X-Requested-With: apctl header"),
        Some(_) => next.run(req).await,
        None => json_error(StatusCode::UNAUTHORIZED, "login required"),
    }
}

#[derive(Deserialize)]
pub struct LoginBody {
    username: String,
    password: String,
}

pub async fn login(
    State(s): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let auth = s.auth.clone();
    if !auth.enabled() {
        return json_error(StatusCode::NOT_FOUND, "login is not enabled");
    }
    let ip = auth.proxies.client_ip(&headers, peer.ip());
    if !auth.attempt(ip) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "too many failed attempts, try again in a few minutes");
    }
    // Argon2 is deliberately slow and takes about 19 MiB per check: keep it off
    // the async workers, and run at most two at a time. A queue kept full (by
    // many addresses) makes the others wait a few seconds at most, and a login
    // turned away unchecked does not count against its address.
    static VERIFYING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let _permit = match tokio::time::timeout(std::time::Duration::from_secs(5), VERIFYING.acquire()).await {
        Ok(p) => p.expect("the semaphore is never closed"),
        Err(_) => {
            auth.refund(ip);
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "too many logins at once, try again shortly");
        }
    };
    let verifier = auth.clone();
    let Ok((ok, user)) = tokio::task::spawn_blocking(move || (verifier.users.verify(&body.username, &body.password), body.username)).await else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "the password check failed");
    };
    if !ok {
        // The name is the client's, up to the whole body: the log gets its start.
        let shown = &user[..user.floor_char_boundary(64)];
        tracing::warn!("failed login for {shown:?}{} from {ip}", if shown.len() < user.len() { "…" } else { "" });
        return json_error(StatusCode::UNAUTHORIZED, "wrong username or password");
    }
    auth.refund(ip);
    match auth.create(&user) {
        Ok(token) => {
            tracing::info!("{user} logged in from {ip}");
            ([(header::SET_COOKIE, cookie(&headers, &token, SESSION_SECS))], Json(json!({ "user": user }))).into_response()
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    }
}

pub async fn logout(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = session_token(&headers) {
        s.auth.revoke(&t);
    }
    ([(header::SET_COOKIE, cookie(&headers, "", 0))], Json(json!({ "ok": true }))).into_response()
}

/// Who is logged in, and whether login is needed at all.
pub async fn me(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let auth = &s.auth;
    if !auth.enabled() {
        return Json(json!({ "auth": false, "user": null, "read_only": true })).into_response();
    }
    match session_token(&headers).and_then(|t| auth.check(&t)) {
        Some(user) => Json(json!({ "auth": true, "user": user, "read_only": false })).into_response(),
        None => (StatusCode::UNAUTHORIZED, Json(json!({ "auth": true, "user": null }))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_file_and_verification() {
        let dir = std::env::temp_dir().join(format!("apctl-users-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("users");
        std::fs::write(&file, format!("# admins\nadmin:{}\n\n", hash_password("correct horse").unwrap())).unwrap();
        let users = Users::load(&file).unwrap();
        assert_eq!(users.len(), 1);
        assert!(users.verify("admin", "correct horse"));
        assert!(!users.verify("admin", "wrong"));
        assert!(!users.verify("nobody", "correct horse"));
        std::fs::write(&file, "admin:not-a-hash\n").unwrap();
        assert!(Users::load(&file).is_err());
        // Lines that could never log in are skipped; the first of a name counts.
        let (first, second) = (hash_password("first").unwrap(), hash_password("second").unwrap());
        let pbkdf2 = "$pbkdf2-sha256$i=600000$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
        std::fs::write(&file, format!("admin:{first}\nadmin:{second}\n:{second}\nold:{pbkdf2}\n")).unwrap();
        let users = Users::load(&file).unwrap();
        assert_eq!(users.len(), 1);
        assert!(users.verify("admin", "first") && !users.verify("admin", "second"));
        assert_eq!(users.dummy, first, "unknown names cost what a real user does");
        assert!(!users.verify("old", "anything") && !users.verify("nobody", "first"));
        // Nobody left who could log in: an error, not an open read-only API.
        std::fs::write(&file, format!("old:{pbkdf2}\n")).unwrap();
        assert!(Users::load(&file).is_err());
        std::fs::write(&file, "# nobody yet\n").unwrap();
        assert!(Users::load(&file).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sessions_are_hashed_checked_and_revoked() {
        let dir = std::env::temp_dir().join(format!("apctl-sessions-{}-{}", std::process::id(), store::now_ts()));
        let (store, writer) = Store::open(&dir).unwrap();
        let mut users = Users::default();
        users.hashes.insert("admin".into(), hash_password("x").unwrap());
        let auth = Auth::new(users, &store, writer, Default::default()).unwrap();
        let token = auth.create("admin").unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(auth.check(&token).as_deref(), Some("admin"));
        assert!(!auth.sessions.lock().unwrap().contains_key(&token), "only the hash is stored");
        assert_eq!(auth.check("forged"), None);
        auth.revoke(&token);
        assert_eq!(auth.check(&token), None);
        // An expired session nobody presents again is dropped at the next login.
        let old = auth.create("admin").unwrap();
        auth.sessions.lock().unwrap().get_mut(&token_hash(&old)).unwrap().expires = 0;
        auth.create("admin").unwrap();
        assert!(!auth.sessions.lock().unwrap().contains_key(&token_hash(&old)));
        assert_eq!(auth.sessions.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn throttles_after_repeated_failures() {
        let dir = std::env::temp_dir().join(format!("apctl-throttle-{}-{}", std::process::id(), store::now_ts()));
        let (store, writer) = Store::open(&dir).unwrap();
        let auth = Auth::new(Users::default(), &store, writer, Default::default()).unwrap();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(auth.attempt(ip));
        }
        assert!(!auth.attempt(ip));
        assert!(auth.attempt("10.0.0.10".parse().unwrap()));
        // Windows that have passed are forgotten.
        auth.failures.lock().unwrap().get_mut(&ip).unwrap().1 -= FAILURE_WINDOW;
        assert!(auth.attempt("10.0.0.11".parse().unwrap()));
        assert!(!auth.failures.lock().unwrap().contains_key(&ip));
        // IPv6 counts by /64: a host cannot step through its own addresses.
        for i in 0..MAX_FAILURES {
            assert!(auth.attempt(format!("2001:db8:1:2::{i:x}").parse().unwrap()));
        }
        assert!(!auth.attempt("2001:db8:1:2:ffff::1".parse().unwrap()));
        assert!(auth.attempt("2001:db8:1:3::1".parse().unwrap()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forwarded_for_is_only_believed_from_trusted_proxies() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 203.0.113.7, 10.42.0.3".parse().unwrap());
        // No proxies configured: the header is ignored.
        assert_eq!(Proxies::default().client_ip(&h, ip("10.42.0.5")), ip("10.42.0.5"));
        let proxies = Proxies::parse(&["10.42.0.0/16".into(), " 192.0.2.1 ".into()]).unwrap();
        // From a trusted proxy: the right-most hop that is not a proxy, whatever the client put first.
        assert_eq!(proxies.client_ip(&h, ip("10.42.0.5")), ip("203.0.113.7"));
        assert_eq!(proxies.client_ip(&h, ip("::ffff:10.42.0.5")), ip("203.0.113.7"), "IPv4-mapped peer");
        // From anyone else: the peer.
        assert_eq!(proxies.client_ip(&h, ip("198.51.100.1")), ip("198.51.100.1"));
        assert_eq!(proxies.client_ip(&HeaderMap::new(), ip("192.0.2.1")), ip("192.0.2.1"));
        // Hops with ports, and over several headers (the last one is right-most).
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
        h.append("x-forwarded-for", "203.0.113.7:4711, 10.42.0.3".parse().unwrap());
        assert_eq!(proxies.client_ip(&h, ip("10.42.0.5")), ip("203.0.113.7"));
        h.insert("x-forwarded-for", "[2001:db8::7]:4711".parse().unwrap());
        assert_eq!(proxies.client_ip(&h, ip("10.42.0.5")), ip("2001:db8::7"));
        h.insert("x-forwarded-for", "[2001:db8::8]".parse().unwrap());
        assert_eq!(proxies.client_ip(&h, ip("10.42.0.5")), ip("2001:db8::8"));
        // A hop that is no address: the client's own hops left of it are not believed.
        h.insert("x-forwarded-for", "6.6.6.6, unknown, 10.42.0.3".parse().unwrap());
        assert_eq!(proxies.client_ip(&h, ip("10.42.0.5")), ip("10.42.0.3"));
        assert!(Proxies::parse(&["10.0.0.0/33".into()]).is_err());
        assert!(Proxies::parse(&["proxy.example".into()]).is_err());
        assert!(Proxies::parse(&["fd00::/8".into()]).unwrap().contains(ip("fd12::1")));
    }

    #[test]
    fn parses_the_session_cookie() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; apctl_session=abc; b=2".parse().unwrap());
        assert_eq!(session_token(&h).as_deref(), Some("abc"));
    }
}
