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
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
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
/// The largest backup that can be uploaded.
const UPLOAD_LIMIT: u64 = 1 << 30;
/// Staged restores and uploads not used within this long are deleted.
const STAGING_TTL: Duration = Duration::from_secs(3600);
/// The files a backup may hold besides its manifest: never paths.
const DATABASES: [&str; 3] = ["config.db", "metrics.db", "logs.db"];
/// A backup's databases may unpack to at most this many times the size of
/// the backup file (or 64 MiB): SQLite files compress well, but nowhere near
/// as well as a crafted archive.
const MAX_RATIO: u64 = 100;

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
    } else if key.is_some() {
        // With a key, only what was sealed with it is trusted: anyone who can
        // put a file in front of apctl could otherwise have it restored.
        bail!("this backup is not encrypted, but a backup key is configured: apctl only restores backups sealed with its key");
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

/// What made a backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Auto,
    Manual,
    PreRestore,
}

impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Kind::Auto => "apctl-auto-",
            Kind::PreRestore => "apctl-prerestore-",
            Kind::Manual => "apctl-",
        }
    }
}

/// A backup's description, kept beside it (`<name>.json`) for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    pub kind: Kind,
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

/// Hashes and counts what passes through to the file.
struct Hashing {
    out: File,
    hash: Sha256,
    size: u64,
}

impl Write for Hashing {
    fn write(&mut self, d: &[u8]) -> io::Result<usize> {
        let n = self.out.write(d)?;
        self.hash.update(&d[..n]);
        self.size += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// A snapshot copy, opened to be trimmed: it is thrown away if anything goes
/// wrong, so it needs no journal and no syncing.
fn scratch(p: &Path) -> Result<Connection> {
    let c = Connection::open(p)?;
    c.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA temp_store=MEMORY;")?;
    Ok(c)
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
    let mut c = scratch(&dir.join("config.db"))?;
    // The deletes in one transaction, then one rewrite to drop the pages they
    // freed. With nothing else to drop, the few session rows are overwritten
    // in place instead of rewriting the whole file again.
    if cutoff.is_none() {
        c.execute_batch("PRAGMA secure_delete=ON;")?;
    }
    let tx = c.transaction()?;
    tx.execute_batch("DELETE FROM sessions;")?;
    if let Some(t) = cutoff {
        for (table, col) in [("events", "ts"), ("connections", "ts"), ("alerts", "ts"), ("neighbors", "last_seen"), ("spectrum", "ts"), ("dryrun_results", "ts")] {
            tx.execute(&format!("DELETE FROM {table} WHERE {col} < ?1"), [t])?;
        }
        tx.execute("DELETE FROM clients WHERE COALESCE(last_seen, 0) < ?1 AND mac NOT IN (SELECT mac FROM client_aliases)", [t])?;
    }
    tx.commit()?;
    if cutoff.is_some() {
        c.execute_batch("VACUUM;")?;
    }
    drop(c);
    if let Some(t) = cutoff {
        // Every metric table in every tier, and the logs (whose full-text index follows by trigger).
        let metrics: Vec<String> = store::TABLES.iter().flat_map(|t| store::TIERS.iter().map(move |(suffix, ..)| format!("{}{suffix}", t.name))).collect();
        for (name, tables) in [("metrics.db", metrics), ("logs.db", vec!["logs".to_string()])] {
            let p = dir.join(name);
            if !p.exists() {
                continue;
            }
            let mut c = scratch(&p)?;
            let tx = c.transaction()?;
            for table in tables {
                // A database from an older version may lack the newest tables.
                let exists: bool = tx.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1", [&table], |r| r.get::<_, i64>(0))? > 0;
                if exists {
                    tx.execute(&format!("DELETE FROM \"{table}\" WHERE ts < ?1"), [t])?;
                }
            }
            tx.commit()?;
            c.execute_batch("VACUUM;")?;
        }
    }
    Ok(())
}

/// `YYYYMMDD-HHMMSS` in UTC.
fn stamp(ts: Ts) -> String {
    let (y, m, d) = crate::clock::civil_from_days(ts.div_euclid(86400));
    let secs = ts.rem_euclid(86400);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// One backup is written at a time (an automatic one may coincide with one
/// asked for), so each gets its own name.
static CREATING: Mutex<()> = Mutex::new(());

/// Writes a backup of the databases in `src_dir` and returns its description.
pub fn create(b: &Backups, src_dir: &Path, kind: Kind, days: i64) -> Result<Meta> {
    let _one = CREATING.lock().unwrap_or_else(PoisonError::into_inner);
    let now = store::now_ts();
    let dir = b.dir();
    fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!(".tmp-{now}-{}-{}", std::process::id(), crate::settings::random_hex(4)));
    fs::create_dir(&tmp)?;
    // A name no other backup has: the time to the second, then a counter.
    let base = format!("{}{VERSION}-{}", kind.prefix(), stamp(now));
    let name = (1..)
        .map(|i| if i == 1 { format!("{base}.apb") } else { format!("{base}-{i}.apb") })
        .find(|n| !dir.join(n).exists() && !dir.join(format!("{n}.part")).exists())
        .expect("a free name");
    let part = dir.join(format!("{name}.part"));
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
        {
            let out = BufWriter::new(fs::OpenOptions::new().write(true).create_new(true).open(&part)?);
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
        let meta = Meta { name: name.clone(), kind, version: VERSION.into(), created: now, days, size, encrypted: b.key.is_some() };
        fs::write(dir.join(format!("{name}.json")), serde_json::to_vec_pretty(&meta)?)?;
        Ok(meta)
    })();
    if result.is_err() {
        // Nothing half-written stays behind (the name is this call's own).
        let _ = fs::remove_file(&part);
        let _ = fs::remove_file(dir.join(&name));
    }
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
    let limit = fs::metadata(path)?.len().saturating_mul(MAX_RATIO).max(64 << 20);
    fs::create_dir_all(dest)?;
    let mut ar = tar::Archive::new(open_payload(path, key)?);
    let mut manifest: Option<Manifest> = None;
    for entry in ar.entries()? {
        let mut e = entry?;
        let name = e.path()?.to_string_lossy().to_string();
        if name == "manifest.json" {
            if e.header().size()? > 1 << 20 {
                bail!("the backup's manifest is too large");
            }
            let mut s = String::new();
            e.read_to_string(&mut s)?;
            let m: Manifest = serde_json::from_str(&s).context("the backup's manifest is unreadable")?;
            check_names(&m)?;
            if m.files.values().fold(0u64, |n, f| n.saturating_add(f.size)) > limit {
                bail!("the backup's contents are far larger than the file: it is damaged");
            }
            manifest = Some(m);
            continue;
        }
        // Only the known database files, never paths.
        if !DATABASES.contains(&name.as_str()) {
            bail!("unexpected file in backup: {name}");
        }
        let m = manifest.as_ref().ok_or_else(|| anyhow!("the backup has no manifest"))?;
        let expected = m.files.get(&name).ok_or_else(|| anyhow!("{name} is not listed in the manifest"))?;
        // Checked before anything is written: with the manifest's total checked
        // against the file's size, a crafted archive cannot fill the disk.
        if e.header().size()? != expected.size {
            bail!("{name} does not match its checksum: the backup is damaged");
        }
        // Hashed while it is written (a file twice in the archive is refused).
        let mut out = Hashing { out: fs::OpenOptions::new().write(true).create_new(true).open(dest.join(&name))?, hash: Sha256::new(), size: 0 };
        io::copy(&mut e, &mut out)?;
        out.out.sync_all()?;
        if (FileInfo { size: out.size, sha256: hex::encode(out.hash.finalize()) }) != *expected {
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

/// The manifest names files to restore by their place in the data directory:
/// only the known databases, so a crafted one cannot reach outside it.
fn check_names(m: &Manifest) -> Result<()> {
    match m.files.keys().find(|n| !DATABASES.contains(&n.as_str())) {
        Some(n) => bail!("unexpected file in backup: {n}"),
        None => Ok(()),
    }
}

/// Whether a backup made by `theirs` can be restored on `ours` (no newer
/// backups), compared as firmware versions are: a release candidate is older
/// than its release.
pub fn version_ok(theirs: &str, ours: &str) -> bool {
    crate::firmware::compare(theirs, ours).is_le()
}

// ---------------------------------------------------------------- restore

/// Whether a staging id is one `stage` made (`r` and digits).
fn valid_id(id: &str) -> bool {
    id.strip_prefix('r').is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
}

/// Applies a staged restore, if any, before the databases are opened: saves
/// the current state as a pre-restore backup, then swaps the staged files in.
/// A settings-only backup leaves the current statistics and logs in place.
///
/// A restore that fails is logged and set aside (`pending.failed`, shown on
/// the backups page) and apctl starts with the data it has, rather than
/// failing on every start. Also clears out staging left behind.
pub fn apply_pending(b: &Backups) {
    let marker = b.staging().join("pending");
    if let Ok(id) = fs::read_to_string(&marker) {
        match apply(b, id.trim()) {
            Ok(()) => {
                let _ = fs::remove_file(&marker);
                let _ = fs::remove_file(b.staging().join("pending.failed"));
                tracing::warn!("restore complete");
            }
            Err(e) => {
                tracing::error!("the staged restore failed; starting with the current data: {e:#}");
                let failed = b.staging().join("pending.failed");
                if fs::write(&failed, format!("{e:#}")).is_err() || fs::remove_file(&marker).is_err() {
                    let _ = fs::rename(&marker, &failed);
                }
            }
        }
    }
    clean_staging(b);
}

fn apply(b: &Backups, id: &str) -> Result<()> {
    if !valid_id(id) {
        bail!("the restore marker names no staged backup ({id:?})");
    }
    let staged = b.staging().join(id);
    let manifest: Manifest = serde_json::from_slice(&fs::read(staged.join("manifest.json")).context("staged restore has no manifest")?)?;
    check_names(&manifest)?;
    tracing::warn!("restoring the backup made {} by apctl {} (history: {} days)", manifest.created, manifest.version, manifest.days);
    if b.data_dir.join("config.db").exists() {
        let pre = create(b, &b.data_dir, Kind::PreRestore, -1).context("saving the current state before restoring")?;
        tracing::info!("saved the state before the restore as {}", pre.name);
    }
    // Copy everything first: if a copy fails, the current databases are untouched.
    let restoring = |n: &str| b.data_dir.join(format!("{n}.restoring"));
    for n in manifest.files.keys() {
        if let Err(e) = fs::copy(staged.join(n), restoring(n)) {
            for n in manifest.files.keys() {
                let _ = fs::remove_file(restoring(n));
            }
            return Err(e).with_context(|| format!("copying {n} into place"));
        }
    }
    for n in manifest.files.keys() {
        fs::rename(restoring(n), b.data_dir.join(n))?;
        // The replaced database's journal must not be applied to the restored one.
        for suffix in ["-wal", "-shm"] {
            let _ = fs::remove_file(b.data_dir.join(format!("{n}{suffix}")));
        }
    }
    let _ = fs::remove_dir_all(&staged);
    Ok(())
}

/// Deletes staged restores and uploads that were left behind (older than an
/// hour), except the restore waiting to be applied.
fn clean_staging(b: &Backups) {
    let keep = fs::read_to_string(b.staging().join("pending")).ok().map(|s| s.trim().to_string());
    for e in fs::read_dir(b.staging()).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "pending" || name == "pending.failed" || keep.as_deref() == Some(name.as_str()) {
            continue;
        }
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > STAGING_TTL);
        if old {
            let p = e.path();
            let _ = if p.is_dir() { fs::remove_dir_all(&p) } else { fs::remove_file(&p) };
        }
    }
}

// ---------------------------------------------------------------- settings and schedule

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frequency {
    Daily,
    Weekly,
    Monthly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    pub frequency: Frequency,
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
        Settings { enabled: true, frequency: Frequency::Daily, minute_utc: 3 * 60 + 30, weekday: 0, monthday: 1, keep: 14, days: 0 }
    }
}

impl Settings {
    fn validate(&self) -> Result<(), String> {
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
        match self.frequency {
            // 1970-01-01 was a Thursday (weekday 3 with Monday = 0).
            Frequency::Weekly => (day + 3).rem_euclid(7) == Ts::from(self.weekday),
            Frequency::Monthly => crate::clock::civil_from_days(day).2 == i64::from(self.monthday),
            Frequency::Daily => true,
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

/// The backup settings; the defaults when none are stored, or (with a
/// warning) when they cannot be read.
fn load_settings(store: &store::Store) -> Settings {
    let stored = store.read(Db::Config, |c| Ok(c.query_row("SELECT json FROM backup_settings WHERE id = 1", [], |r| r.get::<_, String>(0)).optional()?));
    match stored.and_then(|s| s.map(|s| serde_json::from_str::<Settings>(&s)).transpose().map_err(Into::into)) {
        Ok(s) => s.unwrap_or_default(),
        Err(e) => {
            tracing::warn!("the backup settings could not be read, the defaults apply: {e:#}");
            Settings::default()
        }
    }
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
    for (kind, n) in [(Kind::Auto, keep), (Kind::PreRestore, 3)] {
        for m in all.iter().filter(|m| m.kind == kind).skip(n) {
            remove(b, &m.name);
        }
    }
}

/// Runs automatic backups when due (checked every minute), and clears out
/// staging left behind.
pub fn schedule(b: Backups, store: Arc<store::Store>) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(60));
        // After a failed automatic backup, the next try waits an hour.
        let mut retry_at: Ts = 0;
        loop {
            every.tick().await;
            let (b2, st) = (b.clone(), store.clone());
            let checked = tokio::task::spawn_blocking(move || {
                clean_staging(&b2);
                let last = list(&b2).iter().filter(|m| m.kind == Kind::Auto).map(|m| m.created).max().unwrap_or(0);
                (load_settings(&st), last)
            });
            let Ok((s, last)) = checked.await else { continue };
            if !s.enabled {
                continue;
            }
            let now = store::now_ts();
            let due = s.last_due(now);
            if last >= due || now - due > 6 * 3600 && last > 0 && now - last < 86400 || now < retry_at {
                continue;
            }
            let (b2, dir) = (b.clone(), b.data_dir.clone());
            let made = tokio::task::spawn_blocking(move || {
                let m = create(&b2, &dir, Kind::Auto, s.days)?;
                prune(&b2, s.keep);
                Ok::<_, anyhow::Error>(m)
            });
            let failed = match made.await {
                Ok(Ok(m)) => {
                    tracing::info!("automatic backup {} ({} bytes)", m.name, m.size);
                    continue;
                }
                Ok(Err(e)) => format!("{e:#}"),
                Err(e) => e.to_string(),
            };
            tracing::error!("automatic backup failed (trying again in an hour): {failed}");
            retry_at = now + 3600;
        }
    });
}

// ---------------------------------------------------------------- API

fn valid_name(name: &str) -> bool {
    name.starts_with("apctl-") && name.ends_with(".apb") && name.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c)) && !name.contains("..")
}

/// GET /api/backups
pub async fn index(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let b = s.backups.clone();
    let encrypted = b.key.is_some();
    let store = s.store.clone();
    let (settings, list, staged, failed) = tokio::task::spawn_blocking(move || {
        let staged = b.staging().join("pending").exists();
        (load_settings(&store), list(&b), staged, fs::read_to_string(b.staging().join("pending.failed")).ok())
    })
    .await?;
    let next = settings.enabled.then(|| settings.next_due(store::now_ts()));
    Ok(Json(json!({
        "encrypted": encrypted, "version": VERSION, "settings": settings, "next_run": next,
        "backups": list, "restore_pending": staged, "restore_failed": failed,
    })))
}

/// PUT /api/backups/settings
pub async fn put_settings(State(s): State<AppState>, Json(body): Json<Settings>) -> Result<Json<Value>, ApiError> {
    body.validate().map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    s.send(crate::engine::Input::SaveBackupSettings(serde_json::to_string(&body).unwrap_or_default())).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct CreateBody {
    #[serde(default)]
    days: i64,
}

/// POST /api/backups: make a backup now.
pub async fn create_now(State(s): State<AppState>, Json(body): Json<CreateBody>) -> Result<Json<Value>, ApiError> {
    if !(-1..=365).contains(&body.days) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "history must be -1, 0 or 1-365 days".into()));
    }
    let b = s.backups.clone();
    let dir = b.data_dir.clone();
    let meta = tokio::task::spawn_blocking(move || create(&b, &dir, Kind::Manual, body.days)).await??;
    Ok(Json(json!(meta)))
}

/// GET /api/backups/file/{name}: download.
pub async fn download(State(s): State<AppState>, UrlPath(name): UrlPath<String>) -> Result<Response, ApiError> {
    let b = s.backups.clone();
    if !valid_name(&name) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid backup name".into()));
    }
    let file = tokio::fs::File::open(b.dir().join(&name)).await.map_err(|_| ApiError(StatusCode::NOT_FOUND, "no such backup".into()))?;
    // The length lets the browser show progress; the file is read a megabyte
    // per trip to the blocking pool, and (as octet-stream) never recompressed.
    let len = file.metadata().await?.len();
    let body = Body::from_stream(tokio_util::io::ReaderStream::with_capacity(file, 1 << 20));
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, len.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        body,
    )
        .into_response())
}

/// DELETE /api/backups/file/{name}
pub async fn delete(State(s): State<AppState>, UrlPath(name): UrlPath<String>) -> Result<Json<Value>, ApiError> {
    let b = s.backups.clone();
    let found = valid_name(&name)
        && tokio::task::spawn_blocking(move || {
            let found = b.dir().join(&name).exists();
            if found {
                remove(&b, &name);
            }
            found
        })
        .await?;
    if !found {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such backup".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

/// Unpacks and checks a backup into the staging area; returns its manifest and id.
fn stage(b: &Backups, path: &Path) -> Result<(String, Manifest)> {
    let mut r = [0u8; 2];
    getrandom::fill(&mut r).map_err(|e| anyhow!("random: {e}"))?;
    let id = format!("r{}{:05}", store::now_ts(), u16::from_be_bytes(r));
    let dest = b.staging().join(&id);
    fs::create_dir_all(b.staging())?;
    fs::create_dir(&dest)?;
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
/// The body is streamed to disk, so large backups need no memory.
pub async fn upload(State(s): State<AppState>, body: Body) -> Result<Json<Value>, ApiError> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let b = s.backups.clone();
    tokio::fs::create_dir_all(b.staging()).await?;
    let name = format!("upload-{}-{}.apb", store::now_ts(), crate::settings::random_hex(4));
    let tmp = TempFile(b.staging().join(name));
    let mut file = tokio::fs::File::create_new(&tmp.0).await?;
    let mut stream = body.into_data_stream();
    // DefaultBodyLimit does not apply to a streamed body: count here.
    let mut size = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("upload interrupted: {e}")))?;
        size += chunk.len() as u64;
        if size > UPLOAD_LIMIT {
            return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "the backup is too large (1 GiB at most)".into()));
        }
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    drop(file);
    let res = tokio::task::spawn_blocking(move || {
        let r = stage(&b, &tmp.0);
        drop(tmp);
        r
    })
    .await?
    .map_err(refused)?;
    Ok(Json(json!({ "staged": res.0, "manifest": res.1 })))
}

/// Why a backup could not be staged or restored. Most reasons are the
/// backup's (damaged, wrong key, too new: 400, with the reason), a missing one
/// is 404, and apctl's own trouble (a full disk, permissions) is a 500.
fn refused(e: anyhow::Error) -> ApiError {
    use io::ErrorKind::*;
    let kind = e.chain().find_map(|c| c.downcast_ref::<io::Error>()).map(io::Error::kind);
    match kind {
        Some(NotFound) => ApiError(StatusCode::NOT_FOUND, format!("{e:#}")),
        Some(StorageFull | QuotaExceeded | PermissionDenied | ReadOnlyFilesystem | OutOfMemory) => ApiError::from(e),
        _ => ApiError(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

/// A file deleted when dropped, so an upload cut off half way leaves nothing behind.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// POST /api/backups/restore: marks a backup to be restored and restarts apctl.
pub async fn restore(State(s): State<AppState>, Json(body): Json<RestoreBody>) -> Result<Json<Value>, ApiError> {
    let b = s.backups.clone();
    let (id, m) = tokio::task::spawn_blocking(move || -> Result<(String, Manifest)> {
        let (id, m) = match (body.name, body.staged) {
            (Some(name), _) if valid_name(&name) => {
                let path = b.dir().join(&name);
                if !path.exists() {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "no such backup").into());
                }
                stage(&b, &path)?
            }
            (_, Some(id)) if valid_id(&id) => {
                let m: Manifest = serde_json::from_slice(&fs::read(b.staging().join(&id).join("manifest.json")).context("that upload has expired")?)?;
                (id, m)
            }
            _ => bail!("say which backup to restore"),
        };
        let previous = fs::read_to_string(b.staging().join("pending")).ok();
        fs::write(b.staging().join("pending"), &id)?;
        let _ = fs::remove_file(b.staging().join("pending.failed"));
        // A restore staged before and now replaced.
        if let Some(p) = previous.as_deref().map(str::trim).filter(|p| *p != id && valid_id(p)) {
            let _ = fs::remove_dir_all(b.staging().join(p));
        }
        Ok((id, m))
    })
    .await?
    .map_err(refused)?;
    tracing::warn!("restore of backup from {} staged as {id}; restarting", m.created);
    // Answer first, then exit, and the restore is applied on the next start. The
    // exit status is 75 (EX_TEMPFAIL), a failure, so that a restart policy of
    // on-failure restarts apctl as well as one of always.
    let writer = s.writer.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        // What is queued is committed first: the copy saved before the restore,
        // and the data kept if the restore fails, have it.
        let flushed = tokio::task::spawn_blocking(move || writer.flush(Duration::from_secs(5))).await.unwrap_or(false);
        if !flushed {
            tracing::warn!("not all queued writes could be stored before the restart");
        }
        std::process::exit(75);
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
             INSERT INTO sessions (token_hash, username, created, expires) VALUES ('5e55107-hash-of-a-token', 'u', {now}, {now});",
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
        let m = create(&b, &src, Kind::Manual, 7).unwrap();
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
        let m = create(&b, &src, Kind::Auto, 0).unwrap();
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
        let m = create(&b, &src, Kind::Manual, -1).unwrap();
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
        let m = create(&b, &src, Kind::Manual, -1).unwrap();
        // Change the live data after the backup.
        Connection::open(src.join("config.db")).unwrap().execute_batch("DELETE FROM client_aliases;").unwrap();
        let (id, _) = stage(&b, &b.dir().join(&m.name)).unwrap();
        fs::write(b.staging().join("pending"), &id).unwrap();
        apply_pending(&b);
        assert_eq!(count(&src.join("config.db"), "SELECT COUNT(*) FROM client_aliases"), 1, "restored");
        assert!(!b.staging().join("pending").exists());
        assert!(list(&b).iter().any(|x| x.kind == Kind::PreRestore), "the replaced state was saved");
        // Nothing pending: nothing happens.
        apply_pending(&b);
    }

    #[test]
    fn backups_at_the_same_moment_get_their_own_names() {
        let src = data("same");
        let b = Backups { data_dir: src.clone(), key: None };
        let names: Vec<String> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..3).map(|_| sc.spawn(|| create(&b, &src, Kind::Manual, 0).unwrap().name)).collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "{names:?}");
        assert_eq!(list(&b).len(), 3);
        for n in &names {
            assert!(unpack(&b.dir().join(n), None, &dir(&format!("same-{n}"))).is_ok(), "{n}");
        }
        // Nothing half-written is left over.
        assert!(fs::read_dir(b.dir()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".part") && !e.file_name().to_string_lossy().starts_with(".tmp")));
    }

    #[test]
    fn a_failed_restore_is_set_aside_and_apctl_starts() {
        let src = data("failed");
        let b = Backups { data_dir: src.clone(), key: None };
        fs::create_dir_all(b.staging()).unwrap();
        fs::write(b.staging().join("pending"), "r123").unwrap();
        apply_pending(&b);
        assert!(!b.staging().join("pending").exists());
        assert!(fs::read_to_string(b.staging().join("pending.failed")).unwrap().contains("no manifest"));
        assert_eq!(count(&src.join("config.db"), "SELECT COUNT(*) FROM client_aliases"), 1, "the current data is kept");
        // A marker naming no staged backup.
        fs::write(b.staging().join("pending"), "../config.db").unwrap();
        apply_pending(&b);
        assert!(src.join("config.db").exists() && !b.staging().join("pending").exists());
    }

    /// A manifest listing `files`, for hand-made backups.
    fn manifest(files: &[(&str, u64)]) -> Manifest {
        let files = files.iter().map(|(n, size)| (n.to_string(), FileInfo { size: *size, sha256: "00".into() })).collect();
        Manifest { format: 1, app: "apctl".into(), version: VERSION.into(), created: 0, days: 0, files }
    }

    /// Writes an unencrypted backup holding `manifest` and then `entries`, as given.
    fn hand_made(path: &Path, manifest: &Manifest, entries: &[(&str, Vec<u8>)]) {
        let mut file = MAGIC.to_vec();
        file.push(0);
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(file, flate2::Compression::default()));
        for (name, data) in std::iter::once(("manifest.json", serde_json::to_vec(manifest).unwrap())).chain(entries.iter().map(|(n, d)| (*n, d.clone()))) {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_cksum();
            tar.append_data(&mut h, name, data.as_slice()).unwrap();
        }
        fs::write(path, tar.into_inner().unwrap().finish().unwrap()).unwrap();
    }

    #[test]
    fn oversized_entries_are_refused_before_they_are_written() {
        let d = dir("oversized");
        hand_made(&d.join("x.apb"), &manifest(&[("config.db", 4)]), &[("config.db", vec![0u8; 4096])]);
        let out = d.join("out");
        let err = unpack(&d.join("x.apb"), None, &out).unwrap_err();
        assert!(err.to_string().contains("damaged"), "{err:#}");
        assert!(!out.join("config.db").exists());
    }

    #[test]
    fn sessions_never_travel_even_with_all_history() {
        let src = data("sessions");
        let b = Backups { data_dir: src.clone(), key: None };
        let m = create(&b, &src, Kind::Manual, -1).unwrap();
        let out = dir("sessions-out");
        unpack(&b.dir().join(&m.name), None, &out).unwrap();
        assert_eq!(count(&out.join("config.db"), "SELECT COUNT(*) FROM sessions"), 0);
        // Not even in the pages the delete freed.
        let raw = fs::read(out.join("config.db")).unwrap();
        assert!(!raw.windows(23).any(|w| w == b"5e55107-hash-of-a-token"));
        assert_eq!(count(&out.join("config.db"), "SELECT COUNT(*) FROM events"), 2, "all history kept");
    }

    #[test]
    fn contents_far_larger_than_the_file_are_refused() {
        let d = dir("bomb");
        // A 4 GiB database claimed by a file of a few hundred bytes.
        hand_made(&d.join("x.apb"), &manifest(&[("config.db", 4 << 30)]), &[]);
        let err = unpack(&d.join("x.apb"), None, &d.join("out")).unwrap_err();
        assert!(err.to_string().contains("far larger"), "{err:#}");
    }

    #[test]
    fn with_a_key_only_sealed_backups_are_restored() {
        let src = data("plain");
        let plain = create(&Backups { data_dir: src.clone(), key: None }, &src, Kind::Manual, 0).unwrap();
        let b = Backups { data_dir: src, key: Some([5u8; 32]) };
        let err = unpack(&b.dir().join(&plain.name), b.key.as_ref(), &dir("plain-out")).unwrap_err();
        assert!(err.to_string().contains("not encrypted"), "{err:#}");
    }

    #[test]
    fn a_manifest_cannot_name_files_outside_the_data_directory() {
        let d = dir("names");
        // Listed, but never in the archive: the name alone must be refused.
        for name in ["../../config.db", "/tmp/x.db", "other.db"] {
            hand_made(&d.join("x.apb"), &manifest(&[(name, 1)]), &[]);
            let err = unpack(&d.join("x.apb"), None, &d.join("out")).unwrap_err();
            assert!(err.to_string().contains("unexpected file"), "{name}: {err:#}");
        }
        // Nor can a staged manifest, when the restore is applied.
        let src = data("names-apply");
        let b = Backups { data_dir: src, key: None };
        fs::create_dir_all(b.staging().join("r1")).unwrap();
        fs::write(b.staging().join("r1").join("manifest.json"), serde_json::to_vec(&manifest(&[("../config.db", 1)])).unwrap()).unwrap();
        fs::write(b.staging().join("pending"), "r1").unwrap();
        apply_pending(&b);
        assert!(fs::read_to_string(b.staging().join("pending.failed")).unwrap().contains("unexpected file"));
    }

    #[test]
    fn left_over_staging_is_cleared() {
        let src = dir("clean");
        let b = Backups { data_dir: src, key: None };
        fs::create_dir_all(b.staging().join("r1")).unwrap();
        fs::create_dir_all(b.staging().join("r2")).unwrap();
        fs::write(b.staging().join("upload-1-x.apb"), "x").unwrap();
        fs::write(b.staging().join("pending"), "r2").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(2 * 3600);
        for n in ["r1", "r2", "upload-1-x.apb"] {
            File::open(b.staging().join(n)).unwrap().set_modified(old).unwrap();
        }
        clean_staging(&b);
        let left: Vec<String> = fs::read_dir(b.staging()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert!(left.contains(&"r2".to_string()) && left.contains(&"pending".to_string()) && left.len() == 2, "{left:?}");
    }

    #[test]
    fn a_bad_backup_is_the_requests_fault_a_full_disk_is_not() {
        let status = |e: anyhow::Error| refused(e).0;
        assert_eq!(status(anyhow!("the backup is damaged")), StatusCode::BAD_REQUEST);
        assert_eq!(status(anyhow::Error::from(io::Error::from(io::ErrorKind::InvalidData)).context("reading")), StatusCode::BAD_REQUEST);
        assert_eq!(status(io::Error::new(io::ErrorKind::NotFound, "no such backup").into()), StatusCode::NOT_FOUND);
        let full = refused(anyhow::Error::from(io::Error::from(io::ErrorKind::StorageFull)).context("writing /data/restore/r1/config.db"));
        assert_eq!(full.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!full.1.contains("/data"), "paths stay in the log: {}", full.1);
    }

    #[test]
    fn newer_backups_are_refused() {
        assert!(version_ok("0.8.0", "0.8.0"));
        assert!(version_ok("0.7.9", "0.8.0"));
        assert!(!version_ok("0.9.0", "0.8.0"));
        assert!(!version_ok("0.10.0", "0.9.5"));
        // Pre-releases come before their release.
        assert!(version_ok("0.16.0-rc1", "0.16.0"));
        assert!(!version_ok("0.16.0", "0.16.0-rc1"));
        assert!(!version_ok("0.16.1-rc1", "0.16.0"));
    }

    #[test]
    fn schedules() {
        let daily = Settings::default();
        // 2026-10-13 is a Tuesday. 03:30 UTC that day:
        let t = 1_791_862_200; // 2026-10-13 03:30:00 UTC
        assert_eq!(stamp(t), "20261013-033000");
        assert_eq!(daily.last_due(t + 60), t);
        assert_eq!(daily.last_due(t - 60), t - 86400);
        let weekly = Settings { frequency: Frequency::Weekly, weekday: 0, ..Settings::default() }; // Mondays
        assert_eq!(weekly.last_due(t + 60), t - 86400);
        let monthly = Settings { frequency: Frequency::Monthly, monthday: 1, ..Settings::default() };
        assert_eq!(stamp(monthly.last_due(t)), "20261001-033000");
        assert_eq!(daily.next_due(t - 60), t);
        assert_eq!(daily.next_due(t), t + 86400);
        assert_eq!(stamp(monthly.next_due(t)), "20261101-033000");
        assert!(Settings { keep: 0, ..Settings::default() }.validate().is_err());
        // The settings and backup descriptions keep their JSON form.
        assert_eq!(serde_json::to_value(&monthly).unwrap()["frequency"], "monthly");
        assert_eq!(serde_json::to_value(Kind::PreRestore).unwrap(), "pre-restore");
        assert_eq!(serde_json::from_str::<Kind>("\"auto\"").unwrap(), Kind::Auto);
    }
}
