//! SQLite storage in three files.
//!
//! - `config.db`: devices, clients, events and config pushes. This is the state worth backing up.
//! - `metrics.db`: time series in raw, 5-minute and 1-hour tiers.
//! - `logs.db`: AP syslog with a full-text index.
//!
//! One writer thread owns the write connections and commits batched
//! transactions about once a second. It also runs the roll-ups and retention,
//! so no two writers ever contend. Readers use a small pool of read-only
//! connections, which WAL mode lets run alongside the writer.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, params_from_iter};
use serde::Serialize;

use crate::model::Ts;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Db {
    Config,
    Metrics,
    Logs,
}

impl Db {
    fn file(self) -> &'static str {
        match self {
            Db::Config => "config.db",
            Db::Metrics => "metrics.db",
            Db::Logs => "logs.db",
        }
    }
}

/// A metric table. One description drives the schema, inserts, roll-ups and queries.
pub struct Table {
    pub name: &'static str,
    /// Identify the series, together with `ts`.
    pub keys: &'static [&'static str],
    /// Context that may change over time (e.g. which AP a client is on). Roll-ups keep the latest.
    pub texts: &'static [&'static str],
    /// Instantaneous values. Roll-ups average them.
    pub gauges: &'static [&'static str],
    /// Monotonic counters (bytes, packets). Stored raw, returned as per-second rates.
    pub counters: &'static [&'static str],
}

impl Table {
    fn create_sql(&self, suffix: &str) -> String {
        let mut cols: Vec<String> = self.keys.iter().map(|k| format!("{k} TEXT NOT NULL")).collect();
        cols.push("ts INTEGER NOT NULL".into());
        cols.extend(self.texts.iter().map(|c| format!("{c} TEXT")));
        cols.extend(self.gauges.iter().chain(self.counters).map(|c| format!("{c} REAL")));
        let pk: Vec<&str> = self.keys.iter().copied().chain(["ts"]).collect();
        format!(
            "CREATE TABLE IF NOT EXISTS {}{suffix} ({}, PRIMARY KEY ({})) WITHOUT ROWID;\n\
             CREATE INDEX IF NOT EXISTS {}{suffix}_ts ON {}{suffix} (ts);",
            self.name,
            cols.join(", "),
            pk.join(", "),
            self.name,
            self.name
        )
    }

    fn insert_sql(&self) -> String {
        let cols: Vec<&str> = self.keys.iter().copied().chain(["ts"]).chain(self.texts.iter().chain(self.gauges).chain(self.counters).copied()).collect();
        let marks = vec!["?"; cols.len()].join(", ");
        format!("INSERT OR REPLACE INTO {} ({}) VALUES ({marks})", self.name, cols.join(", "))
    }

    /// The insert statement, built once per table (the writer runs it for every metric row).
    fn insert(&'static self) -> std::borrow::Cow<'static, str> {
        static INSERTS: LazyLock<HashMap<&'static str, String>> = LazyLock::new(|| TABLES.iter().map(|t| (t.name, t.insert_sql())).collect());
        match INSERTS.get(self.name) {
            Some(sql) => sql.as_str().into(),
            None => self.insert_sql().into(),
        }
    }

    /// Aggregates `from` rows into `step`-second buckets of `to`. Gauges are
    /// averaged; counters and texts take the bucket's last value. SQLite gives
    /// bare columns the values of the row holding the single `MAX(ts)`.
    fn rollup_sql(&self, from: &str, to: &str, step: i64) -> String {
        let keys = self.keys.join(", ");
        let mut select: Vec<String> = self.keys.iter().map(|k| k.to_string()).collect();
        select.push(format!("(ts / {step}) * {step}"));
        select.extend(self.texts.iter().map(|c| c.to_string()));
        select.extend(self.gauges.iter().map(|g| format!("AVG({g})")));
        select.extend(self.counters.iter().map(|c| c.to_string()));
        select.push("MAX(ts)".into());
        let cols: Vec<&str> = self.keys.iter().copied().chain(["ts"]).chain(self.texts.iter().chain(self.gauges).chain(self.counters).copied()).collect();
        // Wrap so the trailing MAX(ts) helper column is dropped.
        let inner_cols: Vec<String> = cols.iter().enumerate().map(|(i, _)| format!("c{i}")).collect();
        let aliased: Vec<String> = select.iter().take(cols.len()).enumerate().map(|(i, s)| format!("{s} AS c{i}")).collect();
        format!(
            "INSERT OR REPLACE INTO {to} ({}) SELECT {} FROM (SELECT {}, MAX(ts) FROM {from} \
             WHERE ts >= ?1 AND ts < ?2 GROUP BY {keys}, (ts / {step}))",
            cols.join(", "),
            inner_cols.join(", "),
            aliased.join(", "),
        )
    }
}

pub const AP: Table = Table {
    name: "ap_stats",
    keys: &["mac"],
    texts: &[],
    gauges: &["cpu", "mem", "load1", "load5", "load15", "mem_used", "mem_total", "uptime", "satisfaction", "num_sta"],
    counters: &[],
};
pub const UPLINK: Table = Table {
    name: "uplink_stats",
    keys: &["mac"],
    texts: &[],
    gauges: &["speed"],
    counters: &["rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"],
};
pub const RADIO: Table = Table {
    name: "radio_stats",
    keys: &["mac", "radio"],
    texts: &[],
    gauges: &["channel", "bw", "tx_power", "cu_total", "cu_self_rx", "cu_self_tx", "cu_interf", "noise_floor", "num_sta"],
    counters: &["tx_packets", "tx_retries"],
};
pub const VAP: Table = Table {
    name: "vap_stats",
    keys: &["bssid"],
    texts: &["ap_mac", "essid", "radio"],
    gauges: &["num_sta", "ccq", "satisfaction", "avg_client_signal", "latency_avg"],
    counters: &[
        "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "tx_retries", "tx_dropped", "tx_mcast", "rx_mcast", "wifi_tx_attempts", "wifi_tx_dropped", "tx_bcast",
        "rx_bcast",
    ],
};
pub const CLIENT: Table = Table {
    name: "client_stats",
    keys: &["mac"],
    texts: &["ap_mac", "bssid", "essid", "radio"],
    gauges: &["rssi", "signal", "noise", "tx_rate", "rx_rate", "satisfaction", "latency_avg", "channel"],
    counters: &["tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_retries", "mcast_tx_pkts", "mcast_rx_pkts", "mcast_tx_bytes", "mcast_rx_bytes"],
};
/// Multicast and broadcast per AP and traffic type, as rates: `tx` delivered
/// to clients (once per network), `rx` sent by clients (summed), and how many
/// clients sent that type.
pub const MCAST: Table = Table {
    name: "mcast_stats",
    keys: &["mac", "type"],
    texts: &[],
    gauges: &["tx_pps", "rx_pps", "tx_bytes_ps", "rx_bytes_ps", "clients"],
    counters: &[],
};

pub const TABLES: [&Table; 6] = [&AP, &UPLINK, &RADIO, &VAP, &CLIENT, &MCAST];

pub fn table(name: &str) -> Option<&'static Table> {
    TABLES.iter().copied().find(|t| t.name == name || t.name.trim_end_matches("_stats") == name)
}

/// Resolution tiers: (table suffix, bucket seconds, retention seconds).
pub const TIERS: [(&str, i64, i64); 3] = [("", 0, 48 * 3600), ("_5m", 300, 30 * 86400), ("_1h", 3600, 365 * 86400)];

const CONFIG_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, name TEXT, hostname TEXT, model TEXT, model_display TEXT, version TEXT,
    ip TEXT, serial TEXT, hash_id TEXT, first_seen INTEGER, last_seen INTEGER, uptime INTEGER,
    cfgversion TEXT, online INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS clients (
    mac TEXT PRIMARY KEY, hostname TEXT, ip TEXT, first_seen INTEGER, last_seen INTEGER,
    ap_mac TEXT, bssid TEXT, essid TEXT, radio TEXT, connected INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL,
    device_mac TEXT, client_mac TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_device ON events (device_mac, ts);
CREATE INDEX IF NOT EXISTS events_client ON events (client_mac, ts);
CREATE TABLE IF NOT EXISTS neighbors (
    bssid TEXT NOT NULL, ap_mac TEXT NOT NULL, radio TEXT, essid TEXT, channel INTEGER, bw INTEGER, center_freq INTEGER,
    security TEXT, signal INTEGER, best_signal INTEGER, noise INTEGER, is_unifi INTEGER NOT NULL DEFAULT 0, ap_name TEXT,
    model TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY (bssid, ap_mac)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS neighbors_seen ON neighbors (last_seen);
CREATE TABLE IF NOT EXISTS firmware_releases (
    platform TEXT PRIMARY KEY, version TEXT NOT NULL, url TEXT NOT NULL, md5 TEXT, sha256 TEXT, size INTEGER, created TEXT, checked INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS firmware_check (id INTEGER PRIMARY KEY CHECK (id = 1), ts INTEGER NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS backup_settings (id INTEGER PRIMARY KEY CHECK (id = 1), json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, ts INTEGER NOT NULL, key TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, entity TEXT NOT NULL,
    title TEXT NOT NULL, message TEXT NOT NULL, link TEXT, tag TEXT NOT NULL, resolved_ts INTEGER, read INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS alerts_unread ON alerts (read) WHERE read = 0;
CREATE TABLE IF NOT EXISTS network_acks (
    kind TEXT NOT NULL, bssid TEXT NOT NULL, note TEXT, ts INTEGER NOT NULL, PRIMARY KEY (kind, bssid)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS network_threats (
    kind TEXT NOT NULL, bssid TEXT NOT NULL, first_reported INTEGER NOT NULL, PRIMARY KEY (kind, bssid)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS spectrum (
    ap_mac TEXT NOT NULL, radio TEXT NOT NULL, channel INTEGER NOT NULL, width INTEGER, utilization INTEGER,
    interference INTEGER, other_bss_count INTEGER, ts INTEGER NOT NULL, PRIMARY KEY (ap_mac, radio, channel)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ap_mac TEXT NOT NULL, client_mac TEXT NOT NULL, vap TEXT, essid TEXT,
    radio TEXT, event_type TEXT NOT NULL, auth_algo TEXT, assoc_ms INTEGER, auth_ms INTEGER, ip_ms INTEGER,
    ip_assign_type TEXT, dns_responses INTEGER, dns_timeouts INTEGER, rssi INTEGER, reason TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS connections_ts ON connections (ts);
CREATE INDEX IF NOT EXISTS connections_client ON connections (client_mac, ts);
CREATE TABLE IF NOT EXISTS controller_state (
    id INTEGER PRIMARY KEY CHECK (id = 1), json TEXT NOT NULL, imported_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS dryrun_results (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, mac TEXT NOT NULL, cfgversion TEXT,
    matches INTEGER NOT NULL, comparison TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS dryrun_ts ON dryrun_results (ts);
CREATE TABLE IF NOT EXISTS managed_devices (
    mac TEXT PRIMARY KEY, cfgversion TEXT, content TEXT, gcm INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS client_aliases (
    mac TEXT PRIMARY KEY, alias TEXT, note TEXT, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device_config (
    mac TEXT PRIMARY KEY, ts INTEGER, cfgversion TEXT, mgmt_cfg TEXT, system_cfg TEXT);
";

const LOGS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, device_mac TEXT, src_ip TEXT,
    facility INTEGER, severity INTEGER, program TEXT, msg TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS logs_ts ON logs (ts);
CREATE INDEX IF NOT EXISTS logs_device ON logs (device_mac, ts);
CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5 (msg, program, content='logs', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts (rowid, msg, program) VALUES (new.id, new.msg, new.program);
END;
CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts (logs_fts, rowid, msg, program) VALUES ('delete', old.id, old.msg, old.program);
END;
";

const LOG_RETENTION: i64 = 14 * 86400;
/// Clients not seen for this long are forgotten, unless they have a name (an
/// alias). The same rule as a backup's history trim; the engine drops them
/// from its live view too.
pub const CLIENT_RETENTION: Ts = 365 * 86400;
/// Resolved alerts are kept this long; open ones until they resolve.
const ALERT_RETENTION: Ts = 90 * 86400;

fn open_rw(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    // temp_store=MEMORY: SQLite's temporary files (sorters, statement journals)
    // stay in memory. The container's root filesystem is read-only, so there is
    // no writable temp directory (SQLITE_IOERR_GETTEMPPATH, error 6410).
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA temp_store=MEMORY;")?;
    // The writer runs some 30 distinct statements on config.db; rusqlite keeps 16
    // prepared by default, so most would be compiled again on every batch.
    conn.set_prepared_statement_cache_capacity(64);
    Ok(conn)
}

fn open_ro(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .with_context(|| format!("opening {} read-only", path.display()))?;
    conn.execute_batch("PRAGMA busy_timeout=5000; PRAGMA temp_store=MEMORY;")?;
    // Room for every series query (6 tables in 3 tiers) besides the rest.
    conn.set_prepared_statement_cache_capacity(32);
    Ok(conn)
}

/// Columns added to config tables after their first release.
const CONFIG_COLUMNS: [(&str, &str, &str); 1] = [("connections", "detail", "TEXT")];

fn migrate(dir: &Path) -> Result<()> {
    let config = open_rw(&dir.join(Db::Config.file()))?;
    config.execute_batch(CONFIG_SCHEMA)?;
    for (table, col, ty) in CONFIG_COLUMNS {
        let has: bool = config.query_row(&format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"), [col], |r| r.get::<_, i64>(0))? > 0;
        if !has {
            config.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {col} {ty}"))?;
        }
    }
    drop(config);
    open_rw(&dir.join(Db::Logs.file()))?.execute_batch(LOGS_SCHEMA)?;
    let metrics = open_rw(&dir.join(Db::Metrics.file()))?;
    metrics.execute_batch("CREATE TABLE IF NOT EXISTS rollup_state (name TEXT PRIMARY KEY, upto INTEGER NOT NULL)")?;
    for t in TABLES {
        for (suffix, ..) in TIERS {
            let name = format!("{}{suffix}", t.name);
            metrics.execute_batch(&t.create_sql(suffix))?;
            // Columns added in later versions (CREATE IF NOT EXISTS keeps old tables as they are).
            let existing: Vec<String> = metrics
                .prepare(&format!("SELECT name FROM pragma_table_info('{name}')"))?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for c in t.texts.iter().chain(t.gauges).chain(t.counters) {
                if !existing.iter().any(|e| e == c) {
                    let ty = if t.texts.contains(c) { "TEXT" } else { "REAL" };
                    metrics.execute_batch(&format!("ALTER TABLE {name} ADD COLUMN {c} {ty}"))?;
                }
            }
        }
    }
    Ok(())
}

/// A write for the writer thread.
pub enum Write {
    /// One metric row; values in the table's column order (keys, texts, gauges, counters).
    Metric { table: &'static Table, ts: Ts, values: Vec<Value> },
    /// Arbitrary statement against one database.
    Exec { db: Db, sql: &'static str, params: Vec<Value> },
    /// Commit everything queued so far, then answer.
    Flush(Sender<()>),
}

#[derive(Clone)]
pub struct Writer {
    tx: Sender<Write>,
    /// Set when the writer thread has stopped: nothing sent is stored any more.
    stopped: Arc<AtomicBool>,
}

impl Writer {
    pub fn send(&self, w: Write) {
        // Fails only once the writer has stopped, which `stopped` reports.
        let _ = self.tx.send(w);
    }

    pub fn exec(&self, db: Db, sql: &'static str, params: Vec<Value>) {
        self.send(Write::Exec { db, sql, params });
    }

    /// Commits the writes queued so far, waiting at most `timeout`. False if
    /// they could not be committed in time (or the writer has stopped).
    pub fn flush(&self, timeout: Duration) -> bool {
        let (ack, done) = channel();
        self.tx.send(Write::Flush(ack)).is_ok() && done.recv_timeout(timeout).is_ok()
    }

    /// True once the writer thread has stopped (an error opening or writing the
    /// databases, or a panic): the process can no longer store anything.
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }
}

pub struct Store {
    dir: PathBuf,
    pools: [Mutex<Vec<Connection>>; 3],
}

impl Store {
    /// Creates the databases if needed and starts the writer thread.
    pub fn open(dir: &Path) -> Result<(std::sync::Arc<Store>, Writer)> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        migrate(dir)?;
        let (tx, rx) = channel();
        let stopped = Arc::new(AtomicBool::new(false));
        let writer_dir = dir.to_path_buf();
        let flag = stopped.clone();
        std::thread::Builder::new()
            .name("sqlite-writer".into())
            .spawn(move || {
                // Raised however the thread ends, a panic included.
                struct Stopped(Arc<AtomicBool>);
                impl Drop for Stopped {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Relaxed);
                    }
                }
                let _stopped = Stopped(flag);
                if let Err(e) = writer_loop(&writer_dir, rx) {
                    tracing::error!("sqlite writer stopped, nothing more will be stored: {e:#}");
                }
            })?;
        let store = Store { dir: dir.to_path_buf(), pools: Default::default() };
        Ok((std::sync::Arc::new(store), Writer { tx, stopped }))
    }

    /// Runs `f` with a pooled read-only connection. Call from a blocking context.
    pub fn read<T>(&self, db: Db, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let idx = db as usize;
        let conn = self.pools[idx].lock().unwrap().pop();
        let conn = match conn {
            Some(c) => c,
            None => open_ro(&self.dir.join(db.file()))?,
        };
        let result = f(&conn);
        let mut pool = self.pools[idx].lock().unwrap();
        if pool.len() < 4 {
            pool.push(conn);
        }
        result
    }
}

/// The writer's connections, indexed by `Db as usize`.
type Conns = [Connection; 3];

fn open_all(dir: &Path) -> Result<Conns> {
    Ok([open_rw(&dir.join(Db::Config.file()))?, open_rw(&dir.join(Db::Metrics.file()))?, open_rw(&dir.join(Db::Logs.file()))?])
}

/// The channel to the writer stays unbounded: the engine and the request
/// handlers must never block on the disk, and the writer drains a second's
/// worth of writes per commit, far more than the APs produce.
fn writer_loop(dir: &Path, rx: Receiver<Write>) -> Result<()> {
    let mut conns = open_all(dir)?;
    let mut pending: Vec<Write> = Vec::new();
    let mut acks: Vec<Sender<()>> = Vec::new();
    let mut last_flush = Instant::now();
    let mut last_maintenance = Instant::now() - Duration::from_secs(240);
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Write::Flush(ack)) => acks.push(ack),
            Ok(w) => pending.push(w),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                flush(&mut conns, &mut pending);
                return Ok(());
            }
        }
        if !acks.is_empty() || (!pending.is_empty() && (last_flush.elapsed() >= Duration::from_secs(1) || pending.len() >= 5000)) {
            flush(&mut conns, &mut pending);
            last_flush = Instant::now();
            for ack in acks.drain(..) {
                let _ = ack.send(());
            }
        }
        if last_maintenance.elapsed() >= Duration::from_secs(300) {
            flush(&mut conns, &mut pending);
            maintenance(&mut conns, now_ts());
            last_maintenance = Instant::now();
        }
    }
}

fn flush(conns: &mut Conns, pending: &mut Vec<Write>) {
    let mut by_db: [Vec<Write>; 3] = Default::default();
    for w in pending.drain(..) {
        let db = match &w {
            Write::Metric { .. } => Db::Metrics,
            Write::Exec { db, .. } => *db,
            Write::Flush(_) => continue,
        };
        by_db[db as usize].push(w);
    }
    for (conn, writes) in conns.iter_mut().zip(by_db) {
        if writes.is_empty() {
            continue;
        }
        if let Err(e) = apply(conn, writes) {
            tracing::error!("write batch failed: {e:#}");
        }
    }
}

/// Commits a batch in one transaction. A write that fails (e.g. a constraint)
/// is logged and skipped; SQLite undoes just that statement, so the rest of
/// the batch is still stored. Only an error that ends the transaction itself
/// (disk full, I/O) loses the batch.
fn apply(conn: &mut Connection, writes: Vec<Write>) -> Result<()> {
    let tx = conn.transaction()?;
    let (mut failed, mut first_error) = (0, None);
    for w in writes {
        let result = match &w {
            Write::Metric { table, ts, values } => {
                let n_keys = table.keys.len();
                let ts = Value::Integer(*ts);
                let params = values[..n_keys].iter().chain([&ts]).chain(&values[n_keys..]);
                tx.prepare_cached(&table.insert()).and_then(|mut s| s.execute(params_from_iter(params)))
            }
            Write::Exec { sql, params, .. } => tx.prepare_cached(sql).and_then(|mut s| s.execute(params_from_iter(params))),
            Write::Flush(_) => continue,
        };
        if let Err(e) = result {
            if tx.is_autocommit() {
                return Err(anyhow::Error::from(e).context("the transaction was rolled back"));
            }
            failed += 1;
            first_error.get_or_insert_with(|| match &w {
                Write::Metric { table, .. } => format!("{}: {e}", table.name),
                Write::Exec { sql, .. } => format!("{}: {e}", sql.split_whitespace().take(4).collect::<Vec<_>>().join(" ")),
                Write::Flush(_) => e.to_string(),
            });
        }
    }
    tx.commit()?;
    if let Some(e) = first_error {
        tracing::error!("{failed} write(s) failed and were skipped, the first: {e}");
    }
    Ok(())
}

pub fn now_ts() -> Ts {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Rolls complete buckets up into the coarser tiers, then applies retention.
/// Each step runs on its own: one that fails is logged and the rest still run.
///
/// Both go by the wall clock. A capture replayed from the past writes raw rows
/// that are older than the roll-up's progress mark (or than the raw tier's
/// retention), so they are never rolled up; the raw tier still shows them
/// while they are kept.
fn maintenance(conns: &mut Conns, now: Ts) {
    let step = |what: &str, result: Result<()>| {
        if let Err(e) = result {
            tracing::warn!("{what} failed: {e:#}");
        }
    };
    let [config, metrics, logs] = conns;
    for t in TABLES {
        for w in TIERS.windows(2) {
            let ((src_suffix, _, src_keep), (dst_suffix, step_secs, _)) = (w[0], w[1]);
            let (src, dst) = (format!("{}{src_suffix}", t.name), format!("{}{dst_suffix}", t.name));
            step(&format!("rolling up {dst}"), rollup(metrics, t, &src, &dst, step_secs, src_keep, now));
        }
        for (suffix, _, keep) in TIERS {
            let table = format!("{}{suffix}", t.name);
            step(&format!("retention of {table}"), delete_before(metrics, &table, Rows::Metric, now - keep));
        }
    }
    step("retention of logs", delete_before(logs, "logs", Rows::Rowid, now - LOG_RETENTION));
    step("retention of events", delete_before(config, "events", Rows::Rowid, now - 365 * 86400));
    step("expiring sessions", config.execute("DELETE FROM sessions WHERE expires < ?1", [now]).map(drop).map_err(Into::into));
    step("retention of dry runs", delete_before(config, "dryrun_results", Rows::Rowid, now - 90 * 86400));
    step("retention of connections", delete_before(config, "connections", Rows::Rowid, now - 90 * 86400));
    step("retention of neighbours", config.execute("DELETE FROM neighbors WHERE last_seen < ?1", [now - 30 * 86400]).map(drop).map_err(Into::into));
    step(
        "retention of clients",
        config
            .execute("DELETE FROM clients WHERE COALESCE(last_seen, 0) < ?1 AND mac NOT IN (SELECT mac FROM client_aliases)", [now - CLIENT_RETENTION])
            .map(drop)
            .map_err(Into::into),
    );
    step(
        "retention of alerts",
        config.execute("DELETE FROM alerts WHERE ts < ?1 AND resolved_ts < ?1", [now - ALERT_RETENTION]).map(drop).map_err(Into::into),
    );
}

/// Rolls the complete `step`-second buckets of `src` not done yet into `dst`.
fn rollup(metrics: &mut Connection, t: &Table, src: &str, dst: &str, step: i64, src_keep: i64, now: Ts) -> Result<()> {
    let state_key = format!("rollup:{dst}");
    // Not knowing how far it got (a transient error) skips this round: assuming
    // nothing was done would redo the source's whole retention window.
    let done = read_state(metrics, &state_key)?;
    // Only complete buckets, and never further back than the source keeps.
    let upto = (now / step) * step;
    let start = done.max(now - src_keep);
    if upto <= start {
        return Ok(());
    }
    let tx = metrics.transaction()?;
    tx.execute(&t.rollup_sql(src, dst, step), [start, upto])?;
    write_state(&tx, &state_key, upto)?;
    tx.commit()?;
    Ok(())
}

/// How far a roll-up has got; 0 before its first run.
fn read_state(conn: &Connection, key: &str) -> Result<Ts> {
    match conn.query_row("SELECT upto FROM rollup_state WHERE name = ?1", [key], |r| r.get(0)) {
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        r => Ok(r?),
    }
}

fn write_state(conn: &Connection, key: &str, upto: Ts) -> Result<()> {
    conn.execute("INSERT OR REPLACE INTO rollup_state (name, upto) VALUES (?1, ?2)", rusqlite::params![key, upto])?;
    Ok(())
}

/// How `delete_before` removes a table's old rows.
#[derive(Clone, Copy, PartialEq)]
enum Rows {
    /// A metric table: WITHOUT ROWID, and small per run because this runs every
    /// 5 minutes, so one statement.
    Metric,
    /// A rowid table: in batches, so the writer never holds a long lock.
    Rowid,
}

/// Deletes rows older than `cutoff`.
fn delete_before(conn: &Connection, table: &str, rows: Rows, cutoff: Ts) -> Result<()> {
    if rows == Rows::Metric {
        conn.execute(&format!("DELETE FROM {table} WHERE ts < ?1"), [cutoff])?;
        return Ok(());
    }
    let sql = format!("DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE ts < ?1 LIMIT 5000)");
    while conn.execute(&sql, [cutoff])? == 5000 {}
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Series {
    /// Raw, 5m or 1h.
    pub tier: &'static str,
    /// Bucket width in seconds (0 for raw samples).
    pub step: i64,
    pub ts: Vec<Ts>,
    /// Gauges as stored; counters converted to per-second rates.
    pub fields: BTreeMap<String, Vec<Option<f64>>>,
}

/// Picks the finest tier that covers the range and keeps the point count sensible.
pub fn tier_for(from: Ts, to: Ts, now: Ts) -> usize {
    let span = to.saturating_sub(from);
    if span <= 6 * 3600 && from >= now - TIERS[0].2 {
        0
    } else if span <= 8 * 86400 && from >= now - TIERS[1].2 {
        1
    } else {
        2
    }
}

pub fn series(conn: &Connection, table: &Table, keys: &[String], from: Ts, to: Ts, tier: usize) -> Result<Series> {
    let (suffix, step, _) = TIERS[tier];
    let fields: Vec<&str> = table.gauges.iter().chain(table.counters).copied().collect();
    let where_keys: Vec<String> = table.keys.iter().enumerate().map(|(i, k)| format!("{k} = ?{}", i + 3)).collect();
    // One row before `from`, so the first counter rate in range can be computed.
    let sql = format!(
        "SELECT ts, {} FROM {}{suffix} WHERE {} AND ts >= (SELECT COALESCE(MAX(ts), ?1) FROM {}{suffix} WHERE {} AND ts < ?1) AND ts <= ?2 ORDER BY ts",
        fields.join(", "),
        table.name,
        where_keys.join(" AND "),
        table.name,
        where_keys.join(" AND "),
    );
    let params = [Value::Integer(from), Value::Integer(to)].into_iter().chain(keys.iter().map(|k| Value::Text(k.clone())));
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows: Vec<(Ts, Vec<Option<f64>>)> = stmt
        .query_map(params_from_iter(params), |r| {
            let ts: Ts = r.get(0)?;
            let vals = (0..fields.len()).map(|i| r.get::<_, Option<f64>>(i + 1)).collect::<rusqlite::Result<_>>()?;
            Ok((ts, vals))
        })?
        .collect::<rusqlite::Result<_>>()?;

    let n_gauges = table.gauges.len();
    let mut ts_out = Vec::with_capacity(rows.len());
    // One column per field, in `fields` order; named at the end.
    let mut columns: Vec<Vec<Option<f64>>> = vec![Vec::with_capacity(rows.len()); fields.len()];
    for (i, (ts, vals)) in rows.iter().enumerate() {
        if *ts < from {
            continue; // the look-behind row only feeds the first rate
        }
        ts_out.push(*ts);
        for (j, column) in columns.iter_mut().enumerate() {
            let v = if j < n_gauges {
                vals[j]
            } else {
                // Rate from the previous row; a smaller value means the counter reset.
                i.checked_sub(1).and_then(|p| {
                    let (pts, pvals) = &rows[p];
                    let (cur, prev) = (vals[j]?, pvals[j]?);
                    let dt = (ts - pts) as f64;
                    (dt > 0.0).then(|| if cur >= prev { (cur - prev) / dt } else { cur / dt })
                })
            };
            column.push(v);
        }
    }
    let fields = fields.iter().map(|f| f.to_string()).zip(columns).collect();
    Ok(Series { tier: ["raw", "5m", "1h"][tier], step, ts: ts_out, fields })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("apctl-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn writes_rolls_up_and_queries_rates() {
        let dir = temp_dir("store");
        std::fs::create_dir_all(&dir).unwrap();
        migrate(&dir).unwrap();
        let mut conns = open_all(&dir).unwrap();
        let now = 1_800_000_000 + 1800; // half past an hour
        // 10 minutes of uplink samples every 10 s: 1000 bytes/s, counter reset half-way.
        let mut writes = Vec::new();
        for i in 0..60 {
            let ts = now - 1200 + i * 10;
            let bytes = if i < 30 { 1_000_000 + i * 10_000 } else { (i - 30) * 10_000 };
            let mut values = vec![Value::Text("aa".into()), Value::Real(1000.0)];
            values.push(Value::Real(bytes as f64));
            values.extend(std::iter::repeat_n(Value::Null, UPLINK.counters.len() - 1));
            writes.push(Write::Metric { table: &UPLINK, ts, values });
        }
        apply(&mut conns[Db::Metrics as usize], writes).unwrap();

        let m = &conns[Db::Metrics as usize];
        let s = series(m, &UPLINK, &["aa".into()], now - 1200, now, 0).unwrap();
        assert_eq!(s.ts.len(), 60);
        let rx = &s.fields["rx_bytes"];
        assert_eq!(rx[0], None, "no previous sample for the first point");
        assert_eq!(rx[1], Some(1000.0));
        assert_eq!(rx[31], Some(1000.0), "after the reset");
        assert_eq!(s.fields["speed"][5], Some(1000.0));

        // A second series without resets: 20 minutes at 1000 B/s, for the roll-up.
        let mut writes = Vec::new();
        for i in 0..120 {
            let mut values = vec![Value::Text("bb".into()), Value::Real(1000.0), Value::Real((i * 10_000) as f64)];
            values.extend(std::iter::repeat_n(Value::Null, UPLINK.counters.len() - 1));
            writes.push(Write::Metric { table: &UPLINK, ts: now - 1200 + i * 10, values });
        }
        apply(&mut conns[Db::Metrics as usize], writes).unwrap();

        maintenance(&mut conns, now);
        let m = &conns[Db::Metrics as usize];
        let five = series(m, &UPLINK, &["bb".into()], now - 3600, now, 1).unwrap();
        assert_eq!(five.step, 300);
        assert_eq!(five.ts, vec![now - 1200, now - 900, now - 600, now - 300]);
        assert_eq!(five.fields["speed"], vec![Some(1000.0); 4]);
        // Rates from the counters' last value in consecutive buckets.
        assert_eq!(five.fields["rx_bytes"], vec![None, Some(1000.0), Some(1000.0), Some(1000.0)]);
        // Running maintenance again is idempotent and does not redo finished buckets.
        maintenance(&mut conns, now);
        let m = &conns[Db::Metrics as usize];
        assert_eq!(series(m, &UPLINK, &["bb".into()], now - 3600, now, 1).unwrap().ts.len(), 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_failing_write_does_not_lose_the_rest_of_the_batch() {
        let dir = temp_dir("skip");
        std::fs::create_dir_all(&dir).unwrap();
        migrate(&dir).unwrap();
        let mut conns = open_all(&dir).unwrap();
        let alias = |mac: &str| Write::Exec {
            db: Db::Config,
            sql: "INSERT INTO client_aliases (mac, alias, updated) VALUES (?1, 'x', 1)",
            params: vec![Value::Text(mac.into())],
        };
        // The second write breaks the primary key.
        apply(&mut conns[Db::Config as usize], vec![alias("a"), alias("a"), alias("b")]).unwrap();
        let n: i64 = conns[Db::Config as usize].query_row("SELECT COUNT(*) FROM client_aliases", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_keeps_named_clients_and_open_alerts() {
        let dir = temp_dir("retention");
        std::fs::create_dir_all(&dir).unwrap();
        migrate(&dir).unwrap();
        let mut conns = open_all(&dir).unwrap();
        let now = 1_800_000_000;
        let (old, recent) = (now - CLIENT_RETENTION - 10, now - 10);
        conns[Db::Config as usize]
            .execute_batch(&format!(
                "INSERT INTO clients (mac, last_seen) VALUES ('gone', {old}), ('named', {old}), ('recent', {recent});
                 INSERT INTO client_aliases (mac, alias, updated) VALUES ('named', 'n', 0);
                 INSERT INTO alerts (id, ts, key, category, severity, entity, title, message, tag, resolved_ts)
                   VALUES ('done', {old}, 'k', 'c', 's', 'e', 't', 'm', 't', {old}), ('open', {old}, 'k', 'c', 's', 'e', 't', 'm', 't', NULL),
                          ('new', {recent}, 'k', 'c', 's', 'e', 't', 'm', 't', {recent});"
            ))
            .unwrap();
        // A roll-up that fails (here: a missing table) must not stop the retention.
        conns[Db::Metrics as usize].execute_batch("DROP TABLE ap_stats_5m").unwrap();
        maintenance(&mut conns, now);
        let ids = |sql: &str| -> Vec<String> {
            conns[Db::Config as usize].prepare(sql).unwrap().query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
        };
        assert_eq!(ids("SELECT mac FROM clients ORDER BY mac"), ["named", "recent"]);
        assert_eq!(ids("SELECT id FROM alerts ORDER BY id"), ["new", "open"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn flush_commits_before_answering() {
        let dir = temp_dir("flush");
        let (store, writer) = Store::open(&dir).unwrap();
        writer.exec(Db::Config, "INSERT INTO client_aliases (mac, alias, updated) VALUES ('a', 'x', 1)", vec![]);
        assert!(writer.flush(Duration::from_secs(5)));
        let n: i64 = store.read(Db::Config, |c| Ok(c.query_row("SELECT COUNT(*) FROM client_aliases", [], |r| r.get(0))?)).unwrap();
        assert_eq!(n, 1, "committed well before the usual one-second batch");
        assert!(!writer.stopped());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tier_selection() {
        let now = 10_000_000;
        assert_eq!(tier_for(now - 3600, now, now), 0);
        assert_eq!(tier_for(now - 3 * 86400, now, now), 1);
        assert_eq!(tier_for(now - 90 * 86400, now, now), 2);
        assert_eq!(tier_for(now - 40 * 86400, now - 39 * 86400, now), 2, "old data is only kept hourly");
        assert_eq!(tier_for(i64::MIN, i64::MAX, now), 2, "no overflow");
    }
}
