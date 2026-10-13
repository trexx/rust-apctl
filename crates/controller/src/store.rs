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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
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
CREATE TABLE IF NOT EXISTS backup_settings (id INTEGER PRIMARY KEY CHECK (id = 1), json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, ts INTEGER NOT NULL, key TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, entity TEXT NOT NULL,
    title TEXT NOT NULL, message TEXT NOT NULL, link TEXT, tag TEXT NOT NULL, resolved_ts INTEGER, read INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
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

fn open_rw(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    // temp_store=MEMORY: SQLite's temporary files (sorters, statement journals)
    // stay in memory. The container's root filesystem is read-only, so there is
    // no writable temp directory (SQLITE_IOERR_GETTEMPPATH, error 6410).
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA temp_store=MEMORY;")?;
    Ok(conn)
}

fn open_ro(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .with_context(|| format!("opening {} read-only", path.display()))?;
    conn.execute_batch("PRAGMA busy_timeout=5000; PRAGMA temp_store=MEMORY;")?;
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
}

#[derive(Clone)]
pub struct Writer(Sender<Write>);

impl Writer {
    pub fn send(&self, w: Write) {
        // The writer only stops when the process exits.
        let _ = self.0.send(w);
    }

    pub fn exec(&self, db: Db, sql: &'static str, params: Vec<Value>) {
        self.send(Write::Exec { db, sql, params });
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
        let writer_dir = dir.to_path_buf();
        std::thread::Builder::new()
            .name("sqlite-writer".into())
            .spawn(move || {
                if let Err(e) = writer_loop(&writer_dir, rx) {
                    tracing::error!("sqlite writer stopped: {e:#}");
                }
            })?;
        let store = Store { dir: dir.to_path_buf(), pools: Default::default() };
        Ok((std::sync::Arc::new(store), Writer(tx)))
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

fn writer_loop(dir: &Path, rx: Receiver<Write>) -> Result<()> {
    let mut conns: BTreeMap<u8, Connection> = BTreeMap::new();
    for db in [Db::Config, Db::Metrics, Db::Logs] {
        conns.insert(db as u8, open_rw(&dir.join(db.file()))?);
    }
    let mut pending: Vec<Write> = Vec::new();
    let mut last_flush = Instant::now();
    let mut last_maintenance = Instant::now() - Duration::from_secs(240);
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(w) => pending.push(w),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                flush(&mut conns, &mut pending);
                return Ok(());
            }
        }
        if !pending.is_empty() && (last_flush.elapsed() >= Duration::from_secs(1) || pending.len() >= 5000) {
            flush(&mut conns, &mut pending);
            last_flush = Instant::now();
        }
        if last_maintenance.elapsed() >= Duration::from_secs(300) {
            flush(&mut conns, &mut pending);
            let now = now_ts();
            if let Err(e) = maintenance(&mut conns, now) {
                tracing::warn!("roll-up/retention failed: {e:#}");
            }
            last_maintenance = Instant::now();
        }
    }
}

fn flush(conns: &mut BTreeMap<u8, Connection>, pending: &mut Vec<Write>) {
    let mut by_db: BTreeMap<u8, Vec<Write>> = BTreeMap::new();
    for w in pending.drain(..) {
        let db = match &w {
            Write::Metric { .. } => Db::Metrics,
            Write::Exec { db, .. } => *db,
        };
        by_db.entry(db as u8).or_default().push(w);
    }
    for (db, writes) in by_db {
        let conn = conns.get_mut(&db).expect("all databases open");
        if let Err(e) = apply(conn, writes) {
            tracing::error!("write batch failed: {e:#}");
        }
    }
}

fn apply(conn: &mut Connection, writes: Vec<Write>) -> Result<()> {
    let tx = conn.transaction()?;
    for w in writes {
        match w {
            Write::Metric { table, ts, values } => {
                let n_keys = table.keys.len();
                let params = values[..n_keys].iter().cloned().chain([Value::Integer(ts)]).chain(values[n_keys..].iter().cloned());
                tx.prepare_cached(&table.insert_sql())?.execute(params_from_iter(params))?;
            }
            Write::Exec { sql, params, .. } => {
                tx.prepare_cached(sql)?.execute(params_from_iter(params))?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn now_ts() -> Ts {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Rolls complete buckets up into the coarser tiers, then applies retention.
fn maintenance(conns: &mut BTreeMap<u8, Connection>, now: Ts) -> Result<()> {
    let metrics = conns.get_mut(&(Db::Metrics as u8)).unwrap();
    for t in TABLES {
        for w in TIERS.windows(2) {
            let ((src_suffix, ..), (dst_suffix, step, _)) = (w[0], w[1]);
            let (src, dst) = (format!("{}{src_suffix}", t.name), format!("{}{dst_suffix}", t.name));
            let state_key = format!("rollup:{dst}");
            let done = read_state(metrics, &state_key);
            // Only complete buckets, and never further back than the source keeps.
            let upto = (now / step) * step;
            let start = done.max(now - TIERS.iter().find(|x| x.0 == src_suffix).unwrap().2);
            if upto <= start {
                continue;
            }
            let tx = metrics.transaction()?;
            tx.execute(&t.rollup_sql(&src, &dst, step), [start, upto])?;
            write_state(&tx, &state_key, upto)?;
            tx.commit()?;
        }
        for (suffix, _, keep) in TIERS {
            delete_before(metrics, &format!("{}{suffix}", t.name), now - keep)?;
        }
    }
    let logs = conns.get_mut(&(Db::Logs as u8)).unwrap();
    delete_before(logs, "logs", now - LOG_RETENTION)?;
    let config = conns.get_mut(&(Db::Config as u8)).unwrap();
    delete_before(config, "events", now - 365 * 86400)?;
    config.execute("DELETE FROM sessions WHERE expires < ?1", [now])?;
    delete_before(config, "dryrun_results", now - 90 * 86400)?;
    delete_before(config, "connections", now - 90 * 86400)?;
    config.execute("DELETE FROM neighbors WHERE last_seen < ?1", [now - 30 * 86400])?;
    Ok(())
}

fn read_state(conn: &Connection, key: &str) -> Ts {
    conn.query_row("SELECT upto FROM rollup_state WHERE name = ?1", [key], |r| r.get(0)).unwrap_or(0)
}

fn write_state(conn: &Connection, key: &str, upto: Ts) -> Result<()> {
    conn.execute("INSERT OR REPLACE INTO rollup_state (name, upto) VALUES (?1, ?2)", rusqlite::params![key, upto])?;
    Ok(())
}

/// Deletes rows older than `cutoff`. Metric tables (WITHOUT ROWID, small per
/// run because this runs every 5 minutes) go in one statement; rowid tables in
/// batches so the writer never holds a long lock.
fn delete_before(conn: &Connection, table: &str, cutoff: Ts) -> Result<()> {
    if table.contains("_stats") {
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
    let span = to - from;
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
    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<(Ts, Vec<Option<f64>>)> = stmt
        .query_map(params_from_iter(params), |r| {
            let ts: Ts = r.get(0)?;
            let vals = (0..fields.len()).map(|i| r.get::<_, Option<f64>>(i + 1)).collect::<rusqlite::Result<_>>()?;
            Ok((ts, vals))
        })?
        .collect::<rusqlite::Result<_>>()?;

    let n_gauges = table.gauges.len();
    let mut out = Series { tier: ["raw", "5m", "1h"][tier], step, ts: Vec::new(), fields: BTreeMap::new() };
    for f in &fields {
        out.fields.insert(f.to_string(), Vec::new());
    }
    for (i, (ts, vals)) in rows.iter().enumerate() {
        if *ts < from {
            continue; // the look-behind row only feeds the first rate
        }
        out.ts.push(*ts);
        for (j, f) in fields.iter().enumerate() {
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
            out.fields.get_mut(*f).unwrap().push(v);
        }
    }
    Ok(out)
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
        let mut conns: BTreeMap<u8, Connection> = BTreeMap::new();
        for db in [Db::Config, Db::Metrics, Db::Logs] {
            conns.insert(db as u8, open_rw(&dir.join(db.file())).unwrap());
        }
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
        apply(conns.get_mut(&(Db::Metrics as u8)).unwrap(), writes).unwrap();

        let m = conns.get(&(Db::Metrics as u8)).unwrap();
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
        apply(conns.get_mut(&(Db::Metrics as u8)).unwrap(), writes).unwrap();

        maintenance(&mut conns, now).unwrap();
        let m = conns.get(&(Db::Metrics as u8)).unwrap();
        let five = series(m, &UPLINK, &["bb".into()], now - 3600, now, 1).unwrap();
        assert_eq!(five.step, 300);
        assert_eq!(five.ts, vec![now - 1200, now - 900, now - 600, now - 300]);
        assert_eq!(five.fields["speed"], vec![Some(1000.0); 4]);
        // Rates from the counters' last value in consecutive buckets.
        assert_eq!(five.fields["rx_bytes"], vec![None, Some(1000.0), Some(1000.0), Some(1000.0)]);
        // Running maintenance again is idempotent and does not redo finished buckets.
        maintenance(&mut conns, now).unwrap();
        let m = conns.get(&(Db::Metrics as u8)).unwrap();
        assert_eq!(series(m, &UPLINK, &["bb".into()], now - 3600, now, 1).unwrap().ts.len(), 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tier_selection() {
        let now = 10_000_000;
        assert_eq!(tier_for(now - 3600, now, now), 0);
        assert_eq!(tier_for(now - 3 * 86400, now, now), 1);
        assert_eq!(tier_for(now - 90 * 86400, now, now), 2);
        assert_eq!(tier_for(now - 40 * 86400, now - 39 * 86400, now), 2, "old data is only kept hourly");
    }
}
