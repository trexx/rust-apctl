//! The series the views are drawn from: the window a request asks for, the
//! samples of a metrics table loaded in it and the intervals between them,
//! the names of APs and clients, and the memo of what the views read lately.

use std::collections::{BTreeMap, HashMap};

use rusqlite::Connection;
use rusqlite::params_from_iter;
use rusqlite::types::Value as Sql;
use serde::Deserialize;

use crate::api::{ApiError, AppState, read};
use crate::clock;
use crate::engine::Live;
use crate::model::Ts;
use crate::store::{self, Db, TIERS};

#[derive(Deserialize, Default)]
pub struct RangeQuery {
    /// Seconds back from now (default one day).
    pub range: Option<Ts>,
    /// An explicit window instead of `range` (Unix seconds).
    pub from: Option<Ts>,
    pub to: Option<Ts>,
    /// `ng`, `na` or `6e`; all bands when absent.
    pub band: Option<String>,
    /// One AP only (activity), in any form a MAC is written in; another value
    /// is rejected (400).
    pub mac: Option<inform::Mac>,
}

impl RangeQuery {
    /// The query as a view that reads no band, and with `by_ap` its AP, is
    /// answered: what [`memo_read`] keys its read by, so that the same read is
    /// not made and kept again for each band asked.
    pub(crate) fn read_by(&self, by_ap: bool) -> RangeQuery {
        RangeQuery { range: self.range, from: self.from, to: self.to, band: None, mac: self.mac.filter(|_| by_ap) }
    }
}

/// The longest window a request can ask for.
const MAX_WINDOW: Ts = 400 * 86400;

/// The requested window, at least ten minutes and at most 400 days long,
/// ending no later than now (`to`, default now; from `from`, or `range`
/// seconds back from its end); and the storage tier to read it from.
pub fn window(q: &RangeQuery) -> (Ts, Ts, usize) {
    let now = clock::now_ts();
    let to = q.to.unwrap_or(now).clamp(0, now);
    let from = q.from.map(|f| f.min(to.saturating_sub(600)));
    bounded(from, Some(to), q.range.unwrap_or(86400).clamp(600, MAX_WINDOW))
}

/// A window ending no later than now (`to`, default now) and starting at
/// most 400 days before its end (`from`, default `range` seconds back from
/// it); and the storage tier to read it from. A `from` after `to` is kept:
/// the window is empty.
pub(crate) fn bounded(from: Option<Ts>, to: Option<Ts>, range: Ts) -> (Ts, Ts, usize) {
    let now = clock::now_ts();
    let to = to.unwrap_or(now).clamp(0, now);
    let from = from.unwrap_or(to.saturating_sub(range)).max(to.saturating_sub(MAX_WINDOW));
    (from, to, store::tier_for(from, to, now))
}

/// Bucket width for charts: a few hundred points whatever the range.
pub(crate) fn bucket_for(range: Ts, tier: usize) -> Ts {
    let min = TIERS[tier].step.max(60);
    let target = (range / 288).max(min);
    [60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 86400].into_iter().find(|b| *b >= target).unwrap_or(86400)
}

/// One interval between consecutive samples of a series.
pub(crate) struct Delta<'a> {
    /// When the later sample was taken.
    pub ts: Ts,
    /// Seconds since the earlier one.
    pub dt: f64,
    prev: &'a [Option<f64>],
    cur: &'a [Option<f64>],
}

impl Delta<'_> {
    /// How much a counter went up over the interval (see [`increase`]).
    pub fn inc(&self, col: usize) -> Option<f64> {
        self.cur[col].zip(self.prev[col]).map(|(c, p)| increase(p, c))
    }

    /// The same per second.
    pub fn rate(&self, col: usize) -> Option<f64> {
        self.inc(col).map(|d| d / self.dt)
    }
}

/// How much a counter went up from `prev` to `cur`. A counter that went down
/// (restarted) counts nothing, as in the official controller, which takes the
/// new value as its next baseline.
pub(crate) fn increase(prev: f64, cur: f64) -> f64 {
    (cur - prev).max(0.0)
}

/// The seconds between two consecutive samples of a counter taken at `pt` and
/// `t`, if its increase is counted over them: not across a gap of over two
/// hours (apctl or the AP was down, and when the traffic went is unknown).
pub(crate) fn interval(pt: Ts, t: Ts) -> Option<f64> {
    (t > pt && t - pt <= 2 * 3600).then(|| (t - pt) as f64)
}

/// The intervals between consecutive samples that end in the window (at or
/// after `from`); none across a gap (see [`interval`]).
pub(crate) fn deltas(samples: &Samples, from: Ts) -> impl Iterator<Item = Delta<'_>> {
    samples.ts.windows(2).enumerate().filter_map(move |(i, w)| {
        let (pt, t) = (w[0], w[1]);
        let dt = interval(pt, t).filter(|_| t >= from)?;
        Some(Delta { ts: t, dt, prev: samples.row(i), cur: samples.row(i + 1) })
    })
}

/// Samples of one series: their times, and for each the values of the
/// requested columns (in their order), all in one list.
#[derive(Debug, Default)]
pub(crate) struct Samples {
    width: usize,
    ts: Vec<Ts>,
    vals: Vec<Option<f64>>,
}

impl Samples {
    fn new(width: usize) -> Samples {
        Samples { width, ..Default::default() }
    }

    fn row(&self, i: usize) -> &[Option<f64>] {
        &self.vals[i * self.width..(i + 1) * self.width]
    }

    /// (time, values) of each sample, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = (Ts, &[Option<f64>])> {
        (0..self.ts.len()).map(|i| (self.ts[i], self.row(i)))
    }

    /// The samples at or after `from`.
    pub fn since(&self, from: Ts) -> impl Iterator<Item = (Ts, &[Option<f64>])> {
        self.iter().filter(move |(t, _)| *t >= from)
    }

    #[cfg(test)]
    pub(crate) fn from_rows(rows: Vec<(Ts, Vec<Option<f64>>)>) -> Samples {
        let mut s = Samples::new(rows.first().map_or(0, |r| r.1.len()));
        for (t, v) in rows {
            s.ts.push(t);
            s.vals.extend(v);
        }
        s
    }
}

/// Per key: its text columns and its samples.
pub(crate) type Loaded = BTreeMap<String, (Vec<String>, Samples)>;

/// Which rows of a metrics table to load.
#[derive(Clone, Copy)]
pub(crate) enum Only<'a> {
    /// The rows with this value in this column.
    Is(&'a str, &'a str),
    /// The rows with one of these values in this column (one AP's SSIDs, by
    /// BSSID: the table's key, so its own index is used).
    In(&'a str, &'a [String]),
}

/// What to load from a metrics table.
pub(crate) struct Spec<'a> {
    pub table: &'a str,
    /// SQL expression for the series key.
    pub key: &'a str,
    /// Text columns returned with each key.
    pub extra: &'a [&'a str],
    /// Numeric columns.
    pub cols: &'a [&'a str],
    /// Only some rows (one AP's); all when `None`.
    pub only: Option<Only<'a>>,
}

/// Where a column is in a column list (a list the caller wrote, so a miss is a bug).
pub(crate) fn col(cols: &[&str], name: &str) -> usize {
    cols.iter().position(|c| *c == name).unwrap_or_else(|| panic!("{name} is not among the loaded columns"))
}

/// Where each named column is in a column list.
pub(crate) fn cols_at<const N: usize>(cols: &[&str], names: [&str; N]) -> [usize; N] {
    names.map(|n| col(cols, n))
}

/// An AP's name (its host name): the one it reports, else, for an AP not
/// reporting since the start, the one stored.
pub(crate) fn ap_name(live: &Live, mac: &str) -> Option<String> {
    ap_name_of(live, &mac.parse().ok()?)
}

/// The same by MAC.
pub(crate) fn ap_name_of(live: &Live, mac: &inform::Mac) -> Option<String> {
    match live.devices.get(mac) {
        Some(d) => d.snapshot.ap.hostname.clone(),
        None => live.known_devices.get(mac).and_then(|k| k.hostname.clone()),
    }
}

/// Our APs' SSIDs (BSSIDs), with the AP of each.
pub(crate) fn own_bssids(live: &Live) -> impl Iterator<Item = (&inform::Mac, &crate::model::VapSample)> {
    live.devices.iter().flat_map(|(m, d)| d.snapshot.vaps.iter().map(move |v| (m, v)))
}

/// A client's display name: the alias given in apctl, else the host name it
/// reports; none when it has neither (an empty host name is none).
pub(crate) fn client_name(live: &Live, mac: Option<inform::Mac>) -> Option<&str> {
    let mac = mac?;
    let alias = live.aliases.get(&mac).and_then(|a| a.alias.as_deref());
    alias.or_else(|| live.clients.get(&mac)?.sample.hostname.as_deref()).filter(|n| !n.is_empty())
}

/// Loads a metrics table's samples in range, grouped by key.
pub(crate) fn load(c: &Connection, spec: Spec, tier: usize, from: Ts, to: Ts) -> anyhow::Result<Loaded> {
    let (sql, params) = load_query(&spec, tier, from, to)?;
    let Spec { extra, cols, .. } = spec;
    // In time order; the map groups them per key. The views run the same few
    // statements over and over: the read connections keep them prepared.
    let mut stmt = c.prepare_cached(&sql)?;
    let mut out: Loaded = BTreeMap::new();
    // Adds a row to its key's entry. Strings are made only for a new key, or for text that changed.
    let add = |e: &mut (Vec<String>, Samples), r: &rusqlite::Row| -> rusqlite::Result<()> {
        // The text columns of the latest sample.
        for (i, t) in e.0.iter_mut().enumerate() {
            let v = r.get_ref(2 + i)?.as_str_or_null()?.unwrap_or_default();
            if t != v {
                v.clone_into(t);
            }
        }
        e.1.ts.push(r.get(1)?);
        for i in 0..cols.len() {
            e.1.vals.push(r.get(2 + extra.len() + i)?);
        }
        Ok(())
    };
    let mut rows = stmt.query(params_from_iter(params))?;
    while let Some(r) = rows.next()? {
        // One lookup for a key already seen; a new key is added once.
        let k = r.get_ref(0)?.as_str()?;
        match out.get_mut(k) {
            Some(e) => add(e, r)?,
            None => add(out.entry(k.to_string()).or_insert_with(|| (vec![String::new(); extra.len()], Samples::new(cols.len()))), r)?,
        }
    }
    Ok(out)
}

/// The statement [`load`] runs, and its parameters.
fn load_query(spec: &Spec, tier: usize, from: Ts, to: Ts) -> anyhow::Result<(String, Vec<Sql>)> {
    let &Spec { table, key, extra, cols, only } = spec;
    let suffix = TIERS[tier].suffix;
    // Twice the longest interval between two samples, so the one before the window is read.
    // A raw sample covers at most the longest inform interval before it.
    let step = TIERS[tier].step.max(crate::active::MAX_INFORM_INTERVAL) * 2;
    let mut params = vec![Sql::Integer(from), Sql::Integer(to), Sql::Integer(step)];
    let only = match only {
        None => String::new(),
        Some(Only::Is(c, v)) => {
            params.push(Sql::Text(v.into()));
            format!(" AND {c} = ?4")
        }
        // The values as one JSON list: one statement whatever their number, where a
        // placeholder each made another statement for every count.
        Some(Only::In(c, vs)) => {
            params.push(Sql::Text(serde_json::to_string(vs)?));
            format!(" AND {c} IN (SELECT value FROM json_each(?4))")
        }
    };
    // One sample before the window so the first rate in range is known.
    let sql = format!(
        "SELECT {key}, ts, {}{}{} FROM {table}{suffix} WHERE ts >= ?1 - ?3 AND ts <= ?2{only} ORDER BY ts",
        extra.join(", "),
        if extra.is_empty() { "" } else { ", " },
        cols.join(", "),
    );
    Ok((sql, params))
}

/// The longest a view's read is reused (see `Tier::memo_secs`).
const LONGEST_MEMO_SECS: u64 = TIERS[TIERS.len() - 1].memo_secs;

/// A memoised read: its result and when it was read, once read. Whoever finds
/// it empty reads it; the others asking meanwhile wait for that read.
type Slot = std::sync::Arc<tokio::sync::OnceCell<(std::time::Instant, std::sync::Arc<dyn std::any::Any + Send + Sync>)>>;

/// What a memoised read is found by: the view, the type of what it read (so
/// that two views of the same name cannot be handed each other's), and the query.
#[derive(PartialEq, Eq, Hash)]
struct MemoKey {
    view: &'static str,
    read: std::any::TypeId,
    range: Option<Ts>,
    from: Option<Ts>,
    to: Option<Ts>,
    band: Option<String>,
    mac: Option<inform::Mac>,
}

/// What the views last read, by view and query (when its slot was made, and
/// the slot): several tabs, and each tab's refresh every minute, ask for the
/// same windows again. Kept in `AppState`.
#[derive(Default)]
pub struct Memo(std::sync::Mutex<HashMap<MemoKey, (std::time::Instant, Slot)>>);

/// [`read`] from `db` for `view`, reusing what the same query read less than
/// its tier's `memo_secs` ago (the window then ends that much earlier). Queries
/// made while the same query is being read wait for that read rather than read again.
pub(crate) async fn memo_read<T: Send + Sync + 'static>(
    s: &AppState,
    db: Db,
    view: &'static str,
    q: &RangeQuery,
    tier: usize,
    f: impl FnOnce(&Connection) -> anyhow::Result<T> + Send + 'static,
) -> Result<std::sync::Arc<T>, ApiError> {
    let RangeQuery { range, from, to, ref band, mac } = *q;
    let key = MemoKey { view, read: std::any::TypeId::of::<T>(), range, from, to, band: band.clone(), mac };
    let ttl = std::time::Duration::from_secs(TIERS[tier].memo_secs);
    // The slot being read or read recently enough, else a new one.
    let slot = {
        let mut m = s.memo.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match m.get(&key) {
            Some((_, slot)) if slot.get().is_none_or(|(at, _)| at.elapsed() < ttl) => slot.clone(),
            _ => {
                m.remove(&key);
                // A slot left empty (its read failed or was given up) goes too, after a while.
                m.retain(|_, (made, slot)| slot.get().map_or(*made, |(at, _)| *at).elapsed().as_secs() < LONGEST_MEMO_SECS);
                let slot = Slot::default();
                // Bounded: odd queries (explicit windows) are not all kept.
                if m.len() < 256 {
                    m.insert(key, (std::time::Instant::now(), slot.clone()));
                }
                slot
            }
        }
    };
    let (_, v) = slot
        .get_or_try_init(|| async {
            let v: std::sync::Arc<dyn std::any::Any + Send + Sync> = std::sync::Arc::new(read(&s.store, db, f).await?);
            Ok::<_, ApiError>((std::time::Instant::now(), v))
        })
        .await?;
    v.clone().downcast::<T>().map_err(|_| ApiError::internal(format!("{view}: memoised as another type")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::TestStore;

    #[test]
    fn a_client_is_named_by_its_alias_else_a_host_name_that_is_not_empty() {
        let mut live = Live::default();
        let (a, b): (inform::Mac, inform::Mac) = ("aa:00:00:00:00:01".parse().unwrap(), "aa:00:00:00:00:02".parse().unwrap());
        for (mac, hostname) in [(a, "phone"), (b, "")] {
            let sample = crate::model::ClientSample { mac, hostname: Some(hostname.into()), ..Default::default() };
            live.put_client(crate::engine::ClientView { sample: std::sync::Arc::new(sample), connected: true, first_seen: 0, last_seen: 0 });
        }
        assert_eq!((client_name(&live, Some(a)), client_name(&live, Some(b)), client_name(&live, None)), (Some("phone"), None, None));
        live.aliases.insert(b, crate::engine::Alias { alias: Some("Tablet".into()), note: None });
        assert_eq!(client_name(&live, Some(b)), Some("Tablet"));
    }

    #[test]
    fn windows_are_clamped() {
        let q = |range, from, to| RangeQuery { range, from, to, band: None, mac: None };
        let now = clock::now_ts();
        let (f, t, _) = window(&q(Some(3600), None, None));
        assert!(t - f == 3600 && t >= now);
        // An explicit window wins over `range`, and cannot end in the future.
        let (f, t, _) = window(&q(Some(3600), Some(now - 7200), Some(now + 999)));
        assert_eq!(t - f, 7200);
        assert!(t <= clock::now_ts());
        // Too short a window is widened backwards to ten minutes.
        let (f, t, _) = window(&q(None, Some(now - 100), Some(now - 60)));
        assert_eq!((t, t - f), (now - 60, 600));
        // `to` alone: `range` back from it; extreme values neither overflow nor leave the bounds.
        let (f, t, _) = window(&q(Some(3600), None, Some(now - 7200)));
        assert_eq!((t, t - f), (now - 7200, 3600));
        let (f, t, _) = window(&q(None, Some(i64::MIN), Some(i64::MIN)));
        assert_eq!((f, t), (-400 * 86400, 0));
        let (f, t, _) = window(&q(Some(i64::MAX), Some(i64::MAX), Some(i64::MAX)));
        assert!(t <= clock::now_ts() && t - f == 600);
        // The series route's windows have no shortest length, and one that starts after it ends is empty.
        let (f, t, tier) = bounded(Some(now - 5), Some(now + 999), 3600);
        assert!(f == now - 5 && t >= now && t <= clock::now_ts() && tier == 0);
        let (f, t, _) = bounded(None, Some(now - 60), 3600);
        assert_eq!((f, t), (now - 3660, now - 60));
        assert_eq!(bounded(Some(now - 9), Some(now - 10), 3600).0, now - 9);
        assert_eq!(bounded(Some(i64::MIN), Some(0), 3600), (-400 * 86400, 0, 2));
        // A week ago reads the five-minute tier; a day 60 days back reads hourly.
        assert_eq!(window(&q(None, Some(now - 7 * 86400), Some(now - 6 * 86400))).2, 1);
        assert_eq!(window(&q(None, Some(now - 60 * 86400), Some(now - 59 * 86400))).2, 2);
    }

    #[test]
    fn one_aps_ssids_and_clients_are_read_through_an_index() {
        let t = TestStore::new("insights-plan");
        let c = t.db(Db::Metrics);
        // How SQLite finds the rows: the first step of its plan.
        let plan = |spec: Spec, tier: usize| -> String {
            let (sql, params) = load_query(&spec, tier, 1000, 90_000).unwrap();
            c.query_row(&format!("EXPLAIN QUERY PLAN {sql}"), params_from_iter(params), |r| r.get(3)).unwrap()
        };
        let bssids = ["02:00:00:00:01:01".to_string(), "02:00:00:00:01:02".to_string()];
        for tier in 0..TIERS.len() {
            let p = plan(Spec { table: "vap_stats", key: "bssid", extra: &["radio"], cols: &["tx_bytes"], only: Some(Only::In("bssid", &bssids)) }, tier);
            assert!(p.contains("USING PRIMARY KEY (bssid=?"), "{p}");
            // One AP's clients: by AP from the roll-ups (the raw tier has no such index).
            let p = plan(Spec { table: "client_stats", key: "mac", extra: &[], cols: &["tx_bytes", "rx_bytes"], only: Some(Only::Is("ap_mac", "02:00:00:00:00:a1")) }, tier);
            assert_eq!(p.contains("(ap_mac=? AND ts>? AND ts<?)"), tier > 0, "{p}");
        }
    }

    #[test]
    fn the_first_interval_in_the_window_is_counted_at_long_inform_intervals() {
        // A site with many APs: an SSID reports every 75 s, the window starts between two reports.
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE vap_stats (bssid TEXT, ts INTEGER, radio TEXT, tx_bytes INTEGER)").unwrap();
        let from = 10_000;
        for (i, ts) in [from - 145, from - 70, from + 5, from + 80].into_iter().enumerate() {
            c.execute("INSERT INTO vap_stats VALUES ('bss', ?1, 'na', ?2)", [ts, 1000 * i as Ts]).unwrap();
        }
        let vaps = load(&c, Spec { table: "vap_stats", key: "bssid", extra: &["radio"], cols: &["tx_bytes"], only: None }, 0, from, from + 600).unwrap();
        let ends: Vec<(Ts, Option<f64>)> = deltas(&vaps["bss"].1, from).map(|d| (d.ts, d.inc(0))).collect();
        assert_eq!(ends, [(from + 5, Some(1000.0)), (from + 80, Some(1000.0))]);
    }

    #[test]
    fn rates_count_nothing_across_a_counter_restart_or_a_gap() {
        let s = |t, v| (t, vec![Some(v), None]);
        let samples = Samples::from_rows(vec![s(0, 100.0), s(10, 200.0), s(20, 50.0), s(30, 80.0), s(30 + 7201, 90.0), s(30 + 7211, 100.0)]);
        let r: Vec<(Ts, Option<f64>, Option<f64>)> = deltas(&samples, 0).map(|d| (d.ts, d.rate(0), d.inc(1))).collect();
        assert_eq!(r, [(10, Some(10.0), None), (20, Some(0.0), None), (30, Some(3.0), None), (7241, Some(1.0), None)]);
        // Only intervals ending in the window.
        assert_eq!(deltas(&samples, 20).map(|d| d.ts).collect::<Vec<_>>(), [20, 30, 7241]);
        assert_eq!(cols_at(&["a", "b", "c"], ["c", "a"]), [2, 0]);
    }
}
