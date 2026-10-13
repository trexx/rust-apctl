//! Backup and restore, modelled on the official controller's: one file with
//! the settings plus a chosen amount of history (`days`: 0 settings only, N
//! days, -1 everything), automatic backups on a schedule keeping the newest N,
//! and restores that are staged and applied when apctl next starts. Unlike the
//! official controller's fixed built-in key, files are encrypted with a key the
//! operator supplies (AES-256-GCM); without a key they are written in clear.
//!
//! File layout (`.apb`):
//! - `APCTLBK1`, then a flags byte (bit 0: encrypted);
//! - encrypted: a 7-byte nonce prefix, then 1 MiB chunks, each sealed with
//!   AES-256-GCM under nonce = prefix | chunk counter (u32 BE) | last-chunk
//!   flag, with the 16-byte header as associated data, so reordering,
//!   truncation and tampering are all detected;
//! - the payload is a gzip-compressed tar of `manifest.json` (first) and the
//!   database snapshots `config.db`, and with history `metrics.db`, `logs.db`.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::{ApiError, AppState};
use crate::model::Ts;
use crate::store::{self, Db};

const MAGIC: &[u8; 8] = b"APCTLBK1";
const CHUNK: usize = 1 << 20;
const TAG: usize = 16;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where backups live and how they are sealed.
#[derive(Clone)]
pub struct Backups {
    pub data_dir: PathBuf,
    pub key: Option<[u8; 32]>,
}

impl Backups {
    pub fn dir(&self) -> PathBuf {
        self.data_dir.join("backups")
    }
    fn staging(&self) -> PathBuf {
        self.data_dir.join("restore")
    }
}

/// Reads a 32-byte key from a file holding 64 hex characters.
pub fn load_key(path: &Path) -> Result<[u8; 32]> {
    let text = fs::read_to_string(path).with_context(|| format!("reading backup key {}", path.display()))?;
    let bytes = hex::decode(text.trim()).context("the backup key must be 64 hex characters")?;
    bytes.try_into().map_err(|_| anyhow!("the backup key must be 64 hex characters (32 bytes)"))
}

// ---------------------------------------------------------------- sealing

fn nonce(prefix: &[u8; 7], counter: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(last);
    n
}

/// Encrypts everything written to it in sealed chunks.
struct SealWriter<W: Write> {
    out: W,
    cipher: Aes256Gcm,
    header: Vec<u8>,
    prefix: [u8; 7],
    counter: u32,
    buf: Vec<u8>,
}

impl<W: Write> SealWriter<W> {
    fn new(mut out: W, key: &[u8; 32]) -> Result<Self> {
        let mut prefix = [0u8; 7];
        getrandom::fill(&mut prefix).map_err(|e| anyhow!("random: {e}"))?;
        let mut header = MAGIC.to_vec();
        header.push(1);
        header.extend_from_slice(&prefix);
        out.write_all(&header)?;
        Ok(SealWriter { out, cipher: Aes256Gcm::new(key.into()), header, prefix, counter: 0, buf: Vec::with_capacity(CHUNK) })
    }

    fn seal(&mut self, last: bool) -> io::Result<()> {
        let n = nonce(&self.prefix, self.counter, last);
        let sealed = self
            .cipher
            .encrypt(&Nonce::try_from(&n[..]).expect("12 bytes"), Payload { msg: &self.buf, aad: &self.header })
            .map_err(|_| io::Error::other("encryption failed"))?;
        self.out.write_all(&sealed)?;
        self.counter = self.counter.checked_add(1).ok_or_else(|| io::Error::other("backup too large"))?;
        self.buf.clear();
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        self.seal(true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for SealWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let take = (CHUNK - self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..take]);
        if self.buf.len() == CHUNK {
            self.seal(false)?;
        }
        Ok(take)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Decrypts a sealed stream, failing on any tampering or truncation.
struct OpenReader<R: Read> {
    inp: R,
    cipher: Aes256Gcm,
    header: Vec<u8>,
    prefix: [u8; 7],
    counter: u32,
    plain: Vec<u8>,
    pos: usize,
    ahead: Option<Vec<u8>>,
    done: bool,
}

fn read_block<R: Read>(r: &mut R, size: usize) -> io::Result<Vec<u8>> {
    let mut b = Vec::with_capacity(size);
    r.take(size as u64).read_to_end(&mut b)?;
    Ok(b)
}

impl<R: Read> OpenReader<R> {
    fn next_chunk(&mut self) -> io::Result<()> {
        let block = match self.ahead.take() {
            Some(b) => b,
            None => read_block(&mut self.inp, CHUNK + TAG)?,
        };
        let after = read_block(&mut self.inp, CHUNK + TAG)?;
        let last = after.is_empty();
        if !last {
            self.ahead = Some(after);
        }
        let n = nonce(&self.prefix, self.counter, last);
        self.plain = self
            .cipher
            .decrypt(&Nonce::try_from(&n[..]).expect("12 bytes"), Payload { msg: &block, aad: &self.header })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the backup is damaged, truncated or was made with a different key"))?;
        self.pos = 0;
        self.counter += 1;
        self.done = last;
        Ok(())
    }
}

impl<R: Read> Read for OpenReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        let n = (self.plain.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Opens a backup file for reading its payload (gzip-compressed tar).
fn open_payload(path: &Path, key: Option<&[u8; 32]>) -> Result<Box<dyn Read>> {
    let mut f = BufReader::new(File::open(path)?);
    let mut head = [0u8; 9];
    f.read_exact(&mut head).context("not an apctl backup")?;
    if &head[..8] != MAGIC {
        bail!("not an apctl backup");
    }
    let gz: Box<dyn Read> = if head[8] & 1 == 1 {
        let key = key.ok_or_else(|| anyhow!("this backup is encrypted, but no backup key is configured"))?;
        let mut prefix = [0u8; 7];
        f.read_exact(&mut prefix)?;
        let mut header = head.to_vec();
        header.extend_from_slice(&prefix);
        Box::new(OpenReader { inp: f, cipher: Aes256Gcm::new(key.into()), header, prefix, counter: 0, plain: vec![], pos: 0, ahead: None, done: false })
    } else {
        Box::new(f)
    };
    Ok(Box::new(flate2::read::GzDecoder::new(gz)))
}

// ---------------------------------------------------------------- content

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileInfo {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub app: String,
    pub version: String,
    pub created: Ts,
    /// History kept: 0 settings only, N days, -1 everything.
    pub days: i64,
    pub files: std::collections::BTreeMap<String, FileInfo>,
}

/// A backup's description, kept beside it (`<name>.json`) for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    /// `auto`, `manual` or `pre-restore`.
    pub kind: String,
    pub version: String,
    pub created: Ts,
    pub days: i64,
    pub size: u64,
    pub encrypted: bool,
}

fn sha256_file(path: &Path) -> Result<FileInfo> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        size += n as u64;
    }
    Ok(FileInfo { size, sha256: hex::encode(h.finalize()) })
}

/// A consistent copy of a live database.
fn snapshot(src: &Path, dst: &Path) -> Result<()> {
    let c = Connection::open_with_flags(src, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .with_context(|| format!("opening {}", src.display()))?;
    c.execute_batch("PRAGMA busy_timeout=10000; PRAGMA temp_store=MEMORY;")?;
    c.execute("VACUUM INTO ?1", [dst.to_string_lossy()]).with_context(|| format!("copying {}", src.display()))?;
    Ok(())
}

/// Drops history older than the cutoff from snapshot copies. Clients that
/// have a name (alias) are kept whatever their age, as are settings, keys,
/// device configs and acknowledgements; login sessions never travel.
fn trim(dir: &Path, cutoff: Option<Ts>) -> Result<()> {
    let c = Connection::open(dir.join("config.db"))?;
    c.execute_batch("PRAGMA temp_store=MEMORY; DELETE FROM sessions;")?;
    if let Some(t) = cutoff {
        for (table, col) in [("events", "ts"), ("connections", "ts"), ("alerts", "ts"), ("neighbors", "last_seen"), ("spectrum", "ts"), ("dryrun_results", "ts")] {
            c.execute(&format!("DELETE FROM {table} WHERE {col} < ?1"), [t])?;
        }
        c.execute("DELETE FROM clients WHERE COALESCE(last_seen, 0) < ?1 AND mac NOT IN (SELECT mac FROM client_aliases)", [t])?;
    }
    c.execute_batch("VACUUM;")?;
    drop(c);
    if let Some(t) = cutoff {
        for name in ["metrics.db", "logs.db"] {
            let p = dir.join(name);
            if !p.exists() {
                continue;
            }
            let c = Connection::open(&p)?;
            c.execute_batch("PRAGMA temp_store=MEMORY;")?;
            let tables: Vec<String> = c
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE '%ts INTEGER%' AND name NOT LIKE '%fts%'")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for table in tables {
                c.execute(&format!("DELETE FROM \"{table}\" WHERE ts < ?1"), [t])?;
            }
            c.execute_batch("VACUUM;")?;
        }
    }
    Ok(())
}

fn stamp(ts: Ts) -> String {
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}-{:02}{:02}", secs / 3600, (secs % 3600) / 60)
}

/// Writes a backup of the databases in `src_dir` and returns its description.
pub fn create(b: &Backups, src_dir: &Path, kind: &str, days: i64) -> Result<Meta> {
    let now = store::now_ts();
    let dir = b.dir();
    fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!(".tmp-{now}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp)?;
    let result = (|| -> Result<Meta> {
        let mut names = vec!["config.db"];
        if days != 0 {
            names.extend(["metrics.db", "logs.db"]);
        }
        for n in &names {
            if src_dir.join(n).exists() {
                snapshot(&src_dir.join(n), &tmp.join(n))?;
            }
        }
        // Settings only drops all history; N days drops what is older; -1 keeps everything.
        let cutoff = match days {
            0 => Some(Ts::MAX),
            d if d > 0 => Some(now - d * 86400),
            _ => None,
        };
        trim(&tmp, cutoff)?;
        let mut files = std::collections::BTreeMap::new();
        for n in &names {
            if tmp.join(n).exists() {
                files.insert(n.to_string(), sha256_file(&tmp.join(n))?);
            }
        }
        let manifest = Manifest { format: 1, app: "apctl".into(), version: VERSION.into(), created: now, days, files };
        let prefix = match kind {
            "auto" => "apctl-auto-",
            "pre-restore" => "apctl-prerestore-",
            _ => "apctl-",
        };
        let name = format!("{prefix}{VERSION}-{}.apb", stamp(now));
        let part = dir.join(format!("{name}.part"));
        {
            let out = BufWriter::new(File::create(&part)?);
            let sink = match &b.key {
                Some(k) => Sink::Sealed(Box::new(SealWriter::new(out, k)?)),
                None => {
                    let mut out = out;
                    out.write_all(MAGIC)?;
                    out.write_all(&[0])?;
                    Sink::Plain(out)
                }
            };
            let gz = flate2::write::GzEncoder::new(sink, flate2::Compression::default());
            let mut tar = tar::Builder::new(gz);
            let mj = serde_json::to_vec_pretty(&manifest)?;
            let mut h = tar::Header::new_gnu();
            h.set_size(mj.len() as u64);
            h.set_mode(0o600);
            h.set_mtime(now as u64);
            h.set_cksum();
            tar.append_data(&mut h, "manifest.json", mj.as_slice())?;
            for n in manifest.files.keys() {
                tar.append_path_with_name(tmp.join(n), n)?;
            }
            let gz = tar.into_inner()?;
            gz.finish()?.finish()?.sync_all()?;
        }
        fs::rename(&part, dir.join(&name))?;
        let size = fs::metadata(dir.join(&name))?.len();
        let meta = Meta { name: name.clone(), kind: kind.into(), version: VERSION.into(), created: now, days, size, encrypted: b.key.is_some() };
        fs::write(dir.join(format!("{name}.json")), serde_json::to_vec_pretty(&meta)?)?;
        Ok(meta)
    })();
    let _ = fs::remove_dir_all(&tmp);
    result
}

/// Where the compressed archive goes: straight to the file, or sealed first.
enum Sink {
    Plain(BufWriter<File>),
    Sealed(Box<SealWriter<BufWriter<File>>>),
}

impl Sink {
    fn finish(self) -> io::Result<File> {
        let out = match self {
            Sink::Plain(w) => w,
            Sink::Sealed(w) => w.finish()?,
        };
        out.into_inner().map_err(|e| e.into_error())
    }
}

impl Write for Sink {
    fn write(&mut self, d: &[u8]) -> io::Result<usize> {
        match self {
            Sink::Plain(w) => w.write(d),
            Sink::Sealed(w) => w.write(d),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Unpacks a backup into `dest`, checking every file against the manifest.
pub fn unpack(path: &Path, key: Option<&[u8; 32]>, dest: &Path) -> Result<Manifest> {
    fs::create_dir_all(dest)?;
    let mut ar = tar::Archive::new(open_payload(path, key)?);
    let mut manifest: Option<Manifest> = None;
    for entry in ar.entries()? {
        let mut e = entry?;
        let name = e.path()?.to_string_lossy().to_string();
        if name == "manifest.json" {
            let mut s = String::new();
            e.read_to_string(&mut s)?;
            manifest = Some(serde_json::from_str(&s).context("the backup's manifest is unreadable")?);
            continue;
        }
        // Only the known database files, never paths.
        if !["config.db", "metrics.db", "logs.db"].contains(&name.as_str()) {
            bail!("unexpected file in backup: {name}");
        }
        let m = manifest.as_ref().ok_or_else(|| anyhow!("the backup has no manifest"))?;
        let expected = m.files.get(&name).ok_or_else(|| anyhow!("{name} is not listed in the manifest"))?;
        let mut out = File::create(dest.join(&name))?;
        io::copy(&mut e, &mut out)?;
        out.sync_all()?;
        let got = sha256_file(&dest.join(&name))?;
        if &got != expected {
            bail!("{name} does not match its checksum: the backup is damaged");
        }
    }
    let m = manifest.ok_or_else(|| anyhow!("the backup has no manifest"))?;
    for n in m.files.keys() {
        if !dest.join(n).exists() {
            bail!("{n} is listed but missing: the backup is incomplete");
        }
    }
    if m.app != "apctl" || m.format != 1 {
        bail!("not an apctl backup (format {})", m.format);
    }
    Ok(m)
}

/// Whether a backup made by `theirs` can be restored on `ours` (no newer backups).
pub fn version_ok(theirs: &str, ours: &str) -> bool {
    let parse = |v: &str| v.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    parse(theirs) <= parse(ours)
}

// ---------------------------------------------------------------- restore

/// Applies a staged restore, if any, before the databases are opened: saves
/// the current state as a pre-restore backup, then swaps the staged files in.
/// A settings-only backup leaves the current statistics and logs in place.
pub fn apply_pending(b: &Backups) -> Result<()> {
    let marker = b.staging().join("pending");
    let Ok(id) = fs::read_to_string(&marker) else { return Ok(()) };
    let staged = b.staging().join(id.trim());
    let manifest: Manifest = serde_json::from_slice(&fs::read(staged.join("manifest.json")).context("staged restore has no manifest")?)?;
    tracing::warn!("restoring the backup made {} by apctl {} (history: {} days)", manifest.created, manifest.version, manifest.days);
    if b.data_dir.join("config.db").exists() {
        let pre = create(b, &b.data_dir, "pre-restore", -1).context("saving the current state before restoring")?;
        tracing::info!("saved the state before the restore as {}", pre.name);
    }
    for n in manifest.files.keys() {
        for suffix in ["-wal", "-shm"] {
            let _ = fs::remove_file(b.data_dir.join(format!("{n}{suffix}")));
        }
        fs::copy(staged.join(n), b.data_dir.join(format!("{n}.restoring")))?;
        fs::rename(b.data_dir.join(format!("{n}.restoring")), b.data_dir.join(n))?;
    }
    fs::remove_file(&marker)?;
    let _ = fs::remove_dir_all(&staged);
    tracing::warn!("restore complete");
    Ok(())
}

// ---------------------------------------------------------------- settings and schedule

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// `daily`, `weekly` or `monthly`.
    pub frequency: String,
    /// Time of day in UTC, minutes after midnight.
    pub minute_utc: u32,
    /// Weekly: 0 Monday .. 6 Sunday.
    pub weekday: u32,
    /// Monthly: day 1-28.
    pub monthday: u32,
    pub keep: usize,
    pub days: i64,
}

impl Default for Settings {
    /// Daily at 03:30 UTC (before the cluster's 04:00 volume sync), keep 14, settings only.
    fn default() -> Self {
        Settings { enabled: true, frequency: "daily".into(), minute_utc: 3 * 60 + 30, weekday: 0, monthday: 1, keep: 14, days: 0 }
    }
}

impl Settings {
    fn validate(&self) -> Result<(), String> {
        if !["daily", "weekly", "monthly"].contains(&self.frequency.as_str()) {
            return Err("frequency must be daily, weekly or monthly".into());
        }
        if self.minute_utc >= 1440 || self.weekday > 6 || !(1..=28).contains(&self.monthday) {
            return Err("invalid time or day".into());
        }
        if !(1..=100).contains(&self.keep) {
            return Err("keep between 1 and 100 backups".into());
        }
        if self.days < -1 || self.days > 365 {
            return Err("history must be -1 (all), 0 (settings only) or 1-365 days".into());
        }
        Ok(())
    }

    /// Whether a backup is scheduled on this day (days since 1970-01-01, UTC).
    fn runs_on(&self, day: Ts) -> bool {
        match self.frequency.as_str() {
            // 1970-01-01 was a Thursday (weekday 3 with Monday = 0).
            "weekly" => (day + 3).rem_euclid(7) == Ts::from(self.weekday),
            "monthly" => stamp(day * 86400)[6..8].parse::<u32>().unwrap_or(0) == self.monthday,
            _ => true,
        }
    }

    fn at(&self, day: Ts) -> Ts {
        day * 86400 + Ts::from(self.minute_utc) * 60
    }

    /// The latest scheduled moment at or before `now` (0 if none in two months).
    pub fn last_due(&self, now: Ts) -> Ts {
        let today = now.div_euclid(86400);
        (0..62).map(|i| today - i).find(|d| self.runs_on(*d) && self.at(*d) <= now).map_or(0, |d| self.at(d))
    }

    /// The first scheduled moment after `now`.
    pub fn next_due(&self, now: Ts) -> Ts {
        let today = now.div_euclid(86400);
        (0..62).map(|i| today + i).find(|d| self.runs_on(*d) && self.at(*d) > now).map_or(0, |d| self.at(d))
    }
}

fn load_settings(store: &store::Store) -> Settings {
    store
        .read(Db::Config, |c| {
            let s: Option<String> = c.query_row("SELECT json FROM backup_settings WHERE id = 1", [], |r| r.get(0)).ok();
            Ok(s.and_then(|s| serde_json::from_str(&s).ok()))
        })
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Backups in the directory, newest first.
pub fn list(b: &Backups) -> Vec<Meta> {
    let mut out: Vec<Meta> = fs::read_dir(b.dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".apb.json"))
        .filter_map(|e| serde_json::from_slice::<Meta>(&fs::read(e.path()).ok()?).ok())
        .filter(|m| b.dir().join(&m.name).exists())
        .collect();
    out.sort_by(|a, b| b.created.cmp(&a.created).then(b.name.cmp(&a.name)));
    out
}

fn remove(b: &Backups, name: &str) {
    let _ = fs::remove_file(b.dir().join(name));
    let _ = fs::remove_file(b.dir().join(format!("{name}.json")));
}

/// Keeps the newest `keep` automatic backups and the newest 3 pre-restore ones.
fn prune(b: &Backups, keep: usize) {
    let all = list(b);
    for (kind, n) in [("auto", keep), ("pre-restore", 3)] {
        for m in all.iter().filter(|m| m.kind == kind).skip(n) {
            remove(b, &m.name);
        }
    }
}

/// Runs automatic backups when due (checked every minute).
pub fn schedule(b: Backups, store: Arc<store::Store>) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(60));
        loop {
            every.tick().await;
            let s = load_settings(&store);
            if !s.enabled {
                continue;
            }
            let now = store::now_ts();
            let due = s.last_due(now);
            let last = list(&b).iter().filter(|m| m.kind == "auto").map(|m| m.created).max().unwrap_or(0);
            if last >= due || now - due > 6 * 3600 && last > 0 && now - last < 86400 {
                continue;
            }
            let (b2, dir) = (b.clone(), b.data_dir.clone());
            match tokio::task::spawn_blocking(move || create(&b2, &dir, "auto", s.days)).await {
                Ok(Ok(m)) => {
                    tracing::info!("automatic backup {} ({} bytes)", m.name, m.size);
                    prune(&b, s.keep);
                }
                Ok(Err(e)) => tracing::error!("automatic backup failed: {e:#}"),
                Err(e) => tracing::error!("automatic backup failed: {e}"),
            }
        }
    });
}

// ---------------------------------------------------------------- API

fn backups(s: &AppState) -> Result<Backups, ApiError> {
    s.backups.clone().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "backups are not available".into()))
}

fn valid_name(name: &str) -> bool {
    name.starts_with("apctl-") && name.ends_with(".apb") && name.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c)) && !name.contains("..")
}

/// GET /api/backups
pub async fn index(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let b = backups(&s)?;
    let store = s.store.clone();
    let settings = tokio::task::spawn_blocking(move || load_settings(&store)).await.map_err(|e| ApiError::internal(e.to_string()))?;
    let staged = fs::read_to_string(b.staging().join("pending")).ok();
    let next = settings.enabled.then(|| settings.next_due(store::now_ts()));
    Ok(Json(json!({
        "encrypted": b.key.is_some(), "version": VERSION, "settings": settings, "next_run": next,
        "backups": list(&b), "restore_pending": staged.is_some(),
    })))
}

/// PUT /api/backups/settings
pub async fn put_settings(State(s): State<AppState>, headers: HeaderMap, Json(body): Json<Settings>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    body.validate().map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    s.engine
        .send(crate::engine::Input::SaveBackupSettings(serde_json::to_string(&body).unwrap_or_default()))
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "engine stopped".into()))?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct CreateBody {
    #[serde(default)]
    days: i64,
}

/// POST /api/backups: make a backup now.
pub async fn create_now(State(s): State<AppState>, headers: HeaderMap, Json(body): Json<CreateBody>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    if !(-1..=365).contains(&body.days) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "history must be -1, 0 or 1-365 days".into()));
    }
    let b = backups(&s)?;
    let dir = b.data_dir.clone();
    let meta = tokio::task::spawn_blocking(move || create(&b, &dir, "manual", body.days))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::internal(format!("{e:#}")))?;
    Ok(Json(json!(meta)))
}

/// GET /api/backups/file/{name}: download.
pub async fn download(State(s): State<AppState>, UrlPath(name): UrlPath<String>) -> Result<Response, ApiError> {
    let b = backups(&s)?;
    if !valid_name(&name) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid backup name".into()));
    }
    let file = tokio::fs::File::open(b.dir().join(&name)).await.map_err(|_| ApiError(StatusCode::NOT_FOUND, "no such backup".into()))?;
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file));
    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\""))],
        body,
    )
        .into_response())
}

/// DELETE /api/backups/file/{name}
pub async fn delete(State(s): State<AppState>, headers: HeaderMap, UrlPath(name): UrlPath<String>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    let b = backups(&s)?;
    if !valid_name(&name) || !b.dir().join(&name).exists() {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such backup".into()));
    }
    remove(&b, &name);
    Ok(Json(json!({ "ok": true })))
}

/// Unpacks and checks a backup into the staging area; returns its manifest and id.
fn stage(b: &Backups, path: &Path) -> Result<(String, Manifest)> {
    let id = format!("r{}", store::now_ts());
    let dest = b.staging().join(&id);
    let _ = fs::remove_dir_all(&dest);
    let m = match unpack(path, b.key.as_ref(), &dest) {
        Ok(m) => m,
        Err(e) => {
            let _ = fs::remove_dir_all(&dest);
            return Err(e);
        }
    };
    if !version_ok(&m.version, VERSION) {
        let _ = fs::remove_dir_all(&dest);
        bail!("this backup is from apctl {}, newer than this one ({VERSION}); upgrade apctl first", m.version);
    }
    fs::write(dest.join("manifest.json"), serde_json::to_vec_pretty(&m)?)?;
    Ok((id, m))
}

#[derive(Deserialize)]
pub struct RestoreBody {
    /// A backup in the list.
    name: Option<String>,
    /// A previously uploaded and checked backup.
    staged: Option<String>,
}

/// POST /api/backups/upload: checks an uploaded backup and stages it (not applied yet).
pub async fn upload(State(s): State<AppState>, headers: HeaderMap, body: axum::body::Bytes) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    let b = backups(&s)?;
    let res = tokio::task::spawn_blocking(move || -> Result<(String, Manifest)> {
        fs::create_dir_all(b.staging())?;
        let tmp = b.staging().join(format!("upload-{}.apb", store::now_ts()));
        fs::write(&tmp, &body)?;
        let r = stage(&b, &tmp);
        let _ = fs::remove_file(&tmp);
        r
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(json!({ "staged": res.0, "manifest": res.1 })))
}

/// POST /api/backups/restore: marks a backup to be restored and restarts apctl.
pub async fn restore(State(s): State<AppState>, headers: HeaderMap, Json(body): Json<RestoreBody>) -> Result<Json<Value>, ApiError> {
    crate::api::check_csrf(&headers)?;
    let b = backups(&s)?;
    let (id, m) = tokio::task::spawn_blocking(move || -> Result<(String, Manifest)> {
        let (id, m) = match (body.name, body.staged) {
            (Some(name), _) if valid_name(&name) => stage(&b, &b.dir().join(&name))?,
            (_, Some(id)) if id.starts_with('r') && id[1..].chars().all(|c| c.is_ascii_digit()) => {
                let m: Manifest = serde_json::from_slice(&fs::read(b.staging().join(&id).join("manifest.json")).context("that upload has expired")?)?;
                (id, m)
            }
            _ => bail!("say which backup to restore"),
        };
        fs::write(b.staging().join("pending"), &id)?;
        Ok((id, m))
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    tracing::warn!("restore of backup from {} staged as {id}; restarting", m.created);
    // Answer first, then exit: the container is restarted and applies it on start.
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(800)).await;
        std::process::exit(0);
    });
    Ok(Json(json!({ "ok": true, "restarting": true, "manifest": m })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("apctl-backup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// A data directory with a little of everything.
    fn data(name: &str) -> PathBuf {
        let d = dir(name);
        let (store, writer) = store::Store::open(&d).unwrap();
        drop(writer);
        drop(store);
        let c = Connection::open(d.join("config.db")).unwrap();
        let now = store::now_ts();
        c.execute_batch(&format!(
            "INSERT INTO events (ts, kind, data) VALUES ({old}, 'old', '{{}}'), ({now}, 'new', '{{}}');
             INSERT INTO clients (mac, hostname, last_seen) VALUES ('aa:aa:aa:aa:aa:01', 'gone', {old}), ('aa:aa:aa:aa:aa:02', 'named', {old}), ('aa:aa:aa:aa:aa:03', 'recent', {now});
             INSERT INTO client_aliases (mac, alias, updated) VALUES ('aa:aa:aa:aa:aa:02', 'Printer', {now});
             INSERT INTO sessions (token_hash, username, created, expires) VALUES ('x', 'u', {now}, {now});",
            old = now - 40 * 86400
        ))
        .unwrap();
        let m = Connection::open(d.join("metrics.db")).unwrap();
        m.execute_batch(&format!("INSERT INTO ap_stats (mac, ts, cpu) VALUES ('ap', {}, 1.0), ('ap', {now}, 2.0);", now - 40 * 86400)).unwrap();
        d
    }

    fn count(path: &Path, sql: &str) -> i64 {
        Connection::open(path).unwrap().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn encrypted_round_trip_with_history_filter() {
        let src = data("rt");
        let b = Backups { data_dir: src.clone(), key: Some([7u8; 32]) };
        let m = create(&b, &src, "manual", 7).unwrap();
        assert!(m.encrypted && m.days == 7);
        let raw = fs::read(b.dir().join(&m.name)).unwrap();
        assert_eq!(&raw[..9], b"APCTLBK1\x01");
        assert!(!raw.windows(15).any(|w| w == b"SQLite format 3"), "contents must not be readable");
        let out = dir("rt-out");
        let man = unpack(&b.dir().join(&m.name), b.key.as_ref(), &out).unwrap();
        assert_eq!(man.files.keys().cloned().collect::<Vec<_>>(), vec!["config.db", "logs.db", "metrics.db"]);
        let cfg = out.join("config.db");
        assert_eq!(count(&cfg, "SELECT COUNT(*) FROM events"), 1, "old events dropped");
        assert_eq!(count(&cfg, "SELECT COUNT(*) FROM clients"), 2, "named and recent clients kept");
        assert_eq!(count(&cfg, "SELECT COUNT(*) FROM clients WHERE hostname = 'named'"), 1);
        assert_eq!(count(&cfg, "SELECT COUNT(*) FROM sessions"), 0, "login sessions never travel");
        assert_eq!(count(&out.join("metrics.db"), "SELECT COUNT(*) FROM ap_stats"), 1);
        // The wrong key, or none, is refused.
        assert!(unpack(&b.dir().join(&m.name), Some(&[8u8; 32]), &dir("rt-wrong")).is_err());
        assert!(unpack(&b.dir().join(&m.name), None, &dir("rt-none")).is_err());
    }

    #[test]
    fn settings_only_and_unencrypted() {
        let src = data("so");
        let b = Backups { data_dir: src.clone(), key: None };
        let m = create(&b, &src, "auto", 0).unwrap();
        assert!(!m.encrypted && m.name.starts_with("apctl-auto-"));
        let out = dir("so-out");
        let man = unpack(&b.dir().join(&m.name), None, &out).unwrap();
        assert_eq!(man.files.keys().cloned().collect::<Vec<_>>(), vec!["config.db"]);
        assert_eq!(count(&out.join("config.db"), "SELECT COUNT(*) FROM events"), 0);
        assert_eq!(count(&out.join("config.db"), "SELECT COUNT(*) FROM client_aliases"), 1);
    }

    #[test]
    fn tampering_and_truncation_are_detected() {
        let src = data("tamper");
        let b = Backups { data_dir: src.clone(), key: Some([1u8; 32]) };
        let m = create(&b, &src, "manual", -1).unwrap();
        let path = b.dir().join(&m.name);
        let good = fs::read(&path).unwrap();
        let mut bad = good.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        fs::write(&path, &bad).unwrap();
        assert!(unpack(&path, b.key.as_ref(), &dir("t1")).is_err(), "a flipped bit");
        fs::write(&path, &good[..good.len() - 40]).unwrap();
        assert!(unpack(&path, b.key.as_ref(), &dir("t2")).is_err(), "a cut-off file");
    }

    #[test]
    fn staged_restore_is_applied_on_start_with_a_pre_restore_copy() {
        let src = data("apply");
        let b = Backups { data_dir: src.clone(), key: Some([3u8; 32]) };
        let m = create(&b, &src, "manual", -1).unwrap();
        // Change the live data after the backup.
        Connection::open(src.join("config.db")).unwrap().execute_batch("DELETE FROM client_aliases;").unwrap();
        let (id, _) = stage(&b, &b.dir().join(&m.name)).unwrap();
        fs::write(b.staging().join("pending"), &id).unwrap();
        apply_pending(&b).unwrap();
        assert_eq!(count(&src.join("config.db"), "SELECT COUNT(*) FROM client_aliases"), 1, "restored");
        assert!(!b.staging().join("pending").exists());
        assert!(list(&b).iter().any(|x| x.kind == "pre-restore"), "the replaced state was saved");
        // Nothing pending: nothing happens.
        apply_pending(&b).unwrap();
    }

    #[test]
    fn newer_backups_are_refused() {
        assert!(version_ok("0.8.0", "0.8.0"));
        assert!(version_ok("0.7.9", "0.8.0"));
        assert!(!version_ok("0.9.0", "0.8.0"));
        assert!(!version_ok("0.10.0", "0.9.5"));
    }

    #[test]
    fn schedules() {
        let daily = Settings::default();
        // 2026-10-13 is a Tuesday. 03:30 UTC that day:
        let t = 1_791_862_200; // 2026-10-13 03:30:00 UTC
        assert_eq!(stamp(t), "20261013-0330");
        assert_eq!(daily.last_due(t + 60), t);
        assert_eq!(daily.last_due(t - 60), t - 86400);
        let weekly = Settings { frequency: "weekly".into(), weekday: 0, ..Settings::default() }; // Mondays
        assert_eq!(weekly.last_due(t + 60), t - 86400);
        let monthly = Settings { frequency: "monthly".into(), monthday: 1, ..Settings::default() };
        assert_eq!(stamp(monthly.last_due(t)), "20261001-0330");
        assert_eq!(daily.next_due(t - 60), t);
        assert_eq!(daily.next_due(t), t + 86400);
        assert_eq!(stamp(monthly.next_due(t)), "20261101-0330");
        assert!(Settings { keep: 0, ..Settings::default() }.validate().is_err());
    }
}
