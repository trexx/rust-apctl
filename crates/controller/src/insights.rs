//! Site-wide and RF views: activity, airtime, top APs and clients, retry
//! rates, connection success, the radio overview and neighbouring networks.

use std::collections::{BTreeMap, HashMap};

use axum::extract::State;
use rusqlite::Connection;
use rusqlite::params_from_iter;
use rusqlite::types::Value as Sql;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState, Json, Query, read};
use crate::channelai::is_dfs;
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
    /// One AP only (activity).
    pub mac: Option<String>,
}

/// The requested window, at least ten minutes and at most 400 days long,
/// ending no later than now (`to`, default now; from `from`, or `range`
/// seconds back from its end); and the storage tier to read it from.
pub fn window(q: &RangeQuery) -> (Ts, Ts, usize) {
    let now = clock::now_ts();
    let to = q.to.unwrap_or(now).clamp(0, now);
    let from = match q.from {
        Some(from) => from.clamp(to.saturating_sub(400 * 86400), to.saturating_sub(600)),
        None => to.saturating_sub(q.range.unwrap_or(86400).clamp(600, 400 * 86400)),
    };
    (from, to, store::tier_for(from, to, now))
}

/// Bucket width for charts: a few hundred points whatever the range.
fn bucket_for(range: Ts, tier: usize) -> Ts {
    let min = TIERS[tier].1.max(60);
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
    /// How much a counter went up over the interval. A counter that went down
    /// (restarted) counts nothing, as in the official controller, which takes
    /// the new value as its next baseline.
    pub fn inc(&self, col: usize) -> Option<f64> {
        self.cur[col].zip(self.prev[col]).map(|(c, p)| (c - p).max(0.0))
    }

    /// The same per second.
    pub fn rate(&self, col: usize) -> Option<f64> {
        self.inc(col).map(|d| d / self.dt)
    }

    /// A column's value in the later sample (for gauges).
    pub fn now(&self, col: usize) -> Option<f64> {
        self.cur[col]
    }
}

/// The intervals between consecutive samples that end in the window (at or
/// after `from`); none across a gap of over two hours.
pub(crate) fn deltas(samples: &Samples, from: Ts) -> impl Iterator<Item = Delta<'_>> {
    samples.ts.windows(2).enumerate().filter_map(move |(i, w)| {
        let (pt, t) = (w[0], w[1]);
        (t >= from && t > pt && t - pt <= 2 * 3600).then(|| Delta { ts: t, dt: (t - pt) as f64, prev: samples.row(i), cur: samples.row(i + 1) })
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
    fn from_rows(rows: Vec<(Ts, Vec<Option<f64>>)>) -> Samples {
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
fn col(cols: &[&str], name: &str) -> usize {
    cols.iter().position(|c| *c == name).unwrap_or_else(|| panic!("{name} is not among the loaded columns"))
}

/// Where each named column is in a column list.
fn cols_at<const N: usize>(cols: &[&str], names: [&str; N]) -> [usize; N] {
    names.map(|n| col(cols, n))
}

/// An AP's name (its host name), if it is reporting.
pub(crate) fn ap_name(live: &Live, mac: &str) -> Option<String> {
    ap_name_of(live, &mac.parse().ok()?)
}

/// The same by MAC.
pub(crate) fn ap_name_of(live: &Live, mac: &inform::Mac) -> Option<String> {
    live.devices.get(mac).and_then(|d| d.snapshot.ap.hostname.clone())
}

/// Our APs' SSIDs (BSSIDs), with the AP of each.
fn own_bssids(live: &Live) -> impl Iterator<Item = (&inform::Mac, &crate::model::VapSample)> {
    live.devices.iter().flat_map(|(m, d)| d.snapshot.vaps.iter().map(move |v| (m, v)))
}

/// A client's name: the alias given in apctl, else the host name it reports.
pub(crate) fn client_name(live: &Live, mac: Option<inform::Mac>) -> Option<String> {
    let mac = mac?;
    live.aliases.get(&mac).and_then(|a| a.alias.clone()).or_else(|| live.clients.get(&mac).and_then(|c| c.sample.hostname.clone()))
}

/// Loads a metrics table's samples in range, grouped by key.
pub(crate) fn load(c: &Connection, spec: Spec, tier: usize, from: Ts, to: Ts) -> anyhow::Result<Loaded> {
    let Spec { table, key, extra, cols, only } = spec;
    let suffix = TIERS[tier].0;
    // Twice the longest interval between two samples, so the one before the window is read.
    // A raw sample covers at most the longest inform interval before it.
    let step = TIERS[tier].1.max(crate::active::MAX_INFORM_INTERVAL) * 2;
    let mut params = vec![Sql::Integer(from), Sql::Integer(to), Sql::Integer(step)];
    let only = match only {
        None => String::new(),
        Some(Only::Is(c, v)) => {
            params.push(Sql::Text(v.into()));
            format!(" AND {c} = ?4")
        }
        Some(Only::In(c, vs)) => {
            params.extend(vs.iter().map(|v| Sql::Text(v.clone())));
            format!(" AND {c} IN ({})", (4..4 + vs.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", "))
        }
    };
    // One sample before the window so the first rate in range is known.
    let sql = format!(
        "SELECT {key}, ts, {}{}{} FROM {table}{suffix} WHERE ts >= ?1 - ?3 AND ts <= ?2{only} ORDER BY ts",
        extra.join(", "),
        if extra.is_empty() { "" } else { ", " },
        cols.join(", "),
    );
    // In time order; the map groups them per key. The views run the same few
    // statements over and over: the read connections keep them prepared.
    let mut stmt = c.prepare_cached(&sql)?;
    let mut out: Loaded = BTreeMap::new();
    let mut rows = stmt.query(params_from_iter(params))?;
    while let Some(r) = rows.next()? {
        // Strings are made only for a new key, or for text that changed.
        let k = r.get_ref(0)?.as_str()?;
        if !out.contains_key(k) {
            out.insert(k.to_string(), (vec![String::new(); extra.len()], Samples::new(cols.len())));
        }
        let e = out.get_mut(k).expect("just added");
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
    }
    Ok(out)
}

/// The BSSIDs an AP's SSIDs have had in a tier of `vap_stats` (a BSSID stays
/// on its AP): one step through the table's own index per BSSID, rather than
/// a scan of every row for `ap_mac`.
fn bssids_of(c: &Connection, tier: usize, ap: &str) -> rusqlite::Result<Vec<String>> {
    use rusqlite::OptionalExtension;
    let mut stmt = c.prepare_cached(&format!("SELECT bssid, ap_mac FROM vap_stats{} WHERE bssid > ?1 ORDER BY bssid LIMIT 1", TIERS[tier].0))?;
    let (mut out, mut after) = (Vec::new(), String::new());
    while let Some((bssid, on)) = stmt.query_row([&after], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))).optional()? {
        if on.as_deref() == Some(ap) {
            out.push(bssid.clone());
        }
        after = bssid;
    }
    Ok(out)
}

fn band_ok(band: &Option<String>, radio: &str) -> bool {
    band.as_deref().is_none_or(|b| b == "all" || b == radio)
}

/// How long a view's read is reused, per tier (of the window, see [`window`]):
/// the raw tier grows with each report, the roll-ups every five minutes.
const MEMO_SECS: [u64; 3] = [15, 60, 300];

/// A memoised read: its result and when it was read, once read. Whoever finds
/// it empty reads it; the others asking meanwhile wait for that read.
type Slot = std::sync::Arc<tokio::sync::OnceCell<(std::time::Instant, std::sync::Arc<dyn std::any::Any + Send + Sync>)>>;

/// What the views last read, by view and query (when its slot was made, and
/// the slot): several tabs, and each tab's refresh every minute, ask for the
/// same windows again. Kept in `AppState`.
#[derive(Default)]
pub struct Memo(std::sync::Mutex<HashMap<String, (std::time::Instant, Slot)>>);

/// [`read`] from `db` for `view`, reusing what the same query read less than
/// [`MEMO_SECS`] ago (the window then ends that much earlier). Queries made
/// while the same query is being read wait for that read rather than read again.
pub(crate) async fn memo_read<T: Send + Sync + 'static>(
    s: &AppState,
    db: Db,
    view: &str,
    q: &RangeQuery,
    tier: usize,
    f: impl FnOnce(&Connection) -> anyhow::Result<T> + Send + 'static,
) -> Result<std::sync::Arc<T>, ApiError> {
    let RangeQuery { range, from, to, band, mac } = q;
    let key = format!("{view}|{range:?}|{from:?}|{to:?}|{band:?}|{mac:?}");
    let ttl = std::time::Duration::from_secs(MEMO_SECS[tier]);
    // The slot being read or read recently enough, else a new one.
    let slot = {
        let mut m = s.memo.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match m.get(&key) {
            Some((_, slot)) if slot.get().is_none_or(|(at, _)| at.elapsed() < ttl) => slot.clone(),
            _ => {
                m.remove(&key);
                // A slot left empty (its read failed or was given up) goes too, after a while.
                m.retain(|_, (made, slot)| slot.get().map_or(*made, |(at, _)| *at).elapsed().as_secs() < MEMO_SECS[2]);
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

/// GET /api/site/activity: Wi-Fi traffic, retries, clients and multicast,
/// plus airtime (channel use and interference), bucketed.
pub async fn activity(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<std::sync::Arc<Value>>, ApiError> {
    let (from, to, tier) = window(&q);
    let bucket = bucket_for(to - from, tier);
    let band = q.band.clone();
    let ap = q.mac.as_ref().map(|m| m.to_ascii_lowercase());
    let result = memo_read(&s, Db::Metrics, "activity", &q, tier, move |c| {
        // VAP counters: bytes, packets, retries, multicast, drops; gauge: clients.
        const COLS: &[&str] = &[
            "tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_retries", "tx_mcast", "rx_mcast", "tx_dropped", "num_sta", "tx_bcast", "rx_bcast",
            "wifi_tx_attempts", "wifi_tx_dropped",
        ];
        let [tx_bytes, rx_bytes, tx_packets, rx_packets, tx_mcast, rx_mcast, tx_bcast, rx_bcast, tx_dropped, num_sta] =
            cols_at(COLS, ["tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_mcast", "rx_mcast", "tx_bcast", "rx_bcast", "tx_dropped", "num_sta"]);
        let [retries, attempts, wifi_dropped] = cols_at(COLS, RETRY_COLS);
        // One AP's SSIDs by their BSSIDs, the table's key (`ap_mac` has no index).
        let bssids = ap.as_deref().map(|a| bssids_of(c, tier, a)).transpose()?;
        let only = bssids.as_deref().map(|b| Only::In("bssid", b));
        let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["radio"], cols: COLS, only }, tier, from, to)?;
        // bucket -> per-bssid accumulators
        #[derive(Default, Clone)]
        struct Acc {
            down: f64,
            up: f64,
            pkts: f64,
            rx_pkts: f64,
            retries: f64,
            attempts: f64,
            wifi_dropped: f64,
            dropped: f64,
            mcast: f64,
            clients: f64,
            n: f64,
        }
        let mut per: BTreeMap<Ts, HashMap<&str, Acc>> = BTreeMap::new();
        for (bssid, (ex, samples)) in &vaps {
            if !band_ok(&band, &ex[0]) {
                continue;
            }
            for d in deltas(samples, from) {
                let a = per.entry(d.ts - d.ts % bucket).or_default().entry(bssid.as_str()).or_default();
                let g = |i: usize| d.rate(i).unwrap_or(0.0);
                a.down += g(tx_bytes);
                a.up += g(rx_bytes);
                a.pkts += g(tx_packets);
                a.rx_pkts += g(rx_packets);
                // Multicast and broadcast, both directions.
                a.mcast += g(tx_mcast) + g(rx_mcast) + g(tx_bcast) + g(rx_bcast);
                a.dropped += g(tx_dropped);
                // Intervals without attempt counters (data from older versions) are skipped.
                if let (Some(r), Some(at)) = (d.rate(retries), d.rate(attempts)) {
                    a.retries += r;
                    a.attempts += at;
                    a.wifi_dropped += g(wifi_dropped);
                }
                a.clients += d.now(num_sta).unwrap_or(0.0);
                a.n += 1.0;
            }
        }
        let mut ts = Vec::new();
        let (mut down, mut up, mut retry, mut clients, mut mcast) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let (mut tx_pps, mut rx_pps, mut dropped) = (Vec::new(), Vec::new(), Vec::new());
        for (b, m) in &per {
            ts.push(*b);
            // Average per VAP within the bucket, then sum across VAPs (in one pass).
            let t = m.values().fold(Acc::default(), |mut t, a| {
                let n = a.n.max(1.0);
                t.down += a.down / n;
                t.up += a.up / n;
                t.pkts += a.pkts / n;
                t.rx_pkts += a.rx_pkts / n;
                t.retries += a.retries / n;
                t.attempts += a.attempts / n;
                t.wifi_dropped += a.wifi_dropped / n;
                t.dropped += a.dropped / n;
                t.mcast += a.mcast / n;
                t.clients += a.clients / n;
                t
            });
            let (d, u, p, r, mc, cl) = (t.down, t.up, t.pkts, t.retries, t.mcast, t.clients);
            let (rp, dr, at, wd) = (t.rx_pkts, t.dropped, t.attempts, t.wifi_dropped);
            tx_pps.push(p);
            rx_pps.push(rp);
            dropped.push(if p + dr > 0.0 { Some(100.0 * dr / (p + dr)) } else { None });
            down.push(d * 8.0);
            up.push(u * 8.0);
            // Same definitions as the retry buckets and the AP pages.
            retry.push(if r + at + wd > 0.0 { Some(100.0 * r / (r + at + wd)) } else { None });
            mcast.push(if p + rp > 0.0 { Some((100.0 * mc / (p + rp)).min(100.0)) } else { None });
            clients.push(cl);
        }

        // Airtime from the radios: averages across radios per bucket.
        let spec = Spec { table: "radio_stats", key: "mac || '/' || radio", extra: &["radio"], cols: &["cu_total", "cu_interf", "cu_self_rx", "cu_self_tx"], only: ap.as_deref().map(|a| Only::Is("mac", a)) };
        let radios = load(c, spec, tier, from, to)?;
        let mut air: BTreeMap<Ts, Vec<[f64; 4]>> = BTreeMap::new();
        for (ex, samples) in radios.values() {
            if !band_ok(&band, &ex[0]) {
                continue;
            }
            for (t, v) in samples.since(from) {
                let b = t - t % bucket;
                let g = |i: usize| v[i].unwrap_or(0.0);
                air.entry(b).or_default().push([g(0), g(1), g(2), g(3)]);
            }
        }
        let air_ts: Vec<Ts> = air.keys().copied().collect();
        let avg = |i: usize| -> Vec<f64> { air.values().map(|v| v.iter().map(|x| x[i]).sum::<f64>() / v.len().max(1) as f64).collect() };
        let total = avg(0);
        let external = avg(1);
        let own_rx = avg(2);
        let own_tx = avg(3);
        let internal: Vec<f64> = own_rx.iter().zip(&own_tx).map(|(a, b)| a + b).collect();
        Ok(json!({
            "bucket": bucket,
            "activity": {
                "ts": ts, "download_bps": down, "upload_bps": up, "tx_retry_pct": retry, "clients": clients, "multicast_pct": mcast,
                "tx_pps": tx_pps, "rx_pps": rx_pps, "tx_dropped_pct": dropped,
            },
            "airtime": { "ts": air_ts, "total": total, "external_interference": external, "own_traffic": internal, "own_rx": own_rx, "own_tx": own_tx },
        }))
    })
    .await?;
    Ok(Json(result))
}

/// Bytes moved per key over the window (sum of counter deltas), from the
/// `[tx, rx]` columns.
fn totals(samples: &Samples, [tx, rx]: [usize; 2], from: Ts) -> (f64, f64) {
    deltas(samples, from).fold((0.0, 0.0), |(d, u), x| (d + x.inc(tx).unwrap_or(0.0), u + x.inc(rx).unwrap_or(0.0)))
}

/// GET /api/site/top: APs and clients by traffic over the window.
pub async fn top(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let ap = q.mac.as_ref().map(|m| m.to_ascii_lowercase());
    let got = memo_read(&s, Db::Metrics, "top", &q, tier, move |c| {
        // One AP's page lists only its clients: the APs are left out.
        let mut aps: HashMap<String, (f64, f64)> = HashMap::new();
        if ap.is_none() {
            let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac"], cols: &BYTE_COLS, only: None }, tier, from, to)?;
            for (ex, samples) in vaps.values() {
                let (d, u) = totals(samples, [0, 1], from);
                let e = aps.entry(ex[0].clone()).or_default();
                e.0 += d;
                e.1 += u;
            }
        }
        // Per client and AP, so a client's traffic counts towards the AP it was on.
        let spec = Spec { table: "client_stats", key: "mac || '/' || coalesce(ap_mac, '')", extra: &[], cols: &BYTE_COLS, only: ap.as_deref().map(|a| Only::Is("ap_mac", a)) };
        let cl = load(c, spec, tier, from, to)?;
        let mut per_client: HashMap<String, (f64, f64)> = HashMap::new();
        for (k, (_, s)) in &cl {
            let mac = k.split_once('/').map_or(k.as_str(), |(m, _)| m);
            let (d, u) = totals(s, [0, 1], from);
            let e = per_client.entry(mac.to_string()).or_default();
            e.0 += d;
            e.1 += u;
        }
        // Most traffic first (by MAC among equals); the 25 busiest clients.
        let by_total = |a: &(String, f64, f64), b: &(String, f64, f64)| (b.1 + b.2).total_cmp(&(a.1 + a.2)).then_with(|| a.0.cmp(&b.0));
        let mut aps: Vec<(String, f64, f64)> = aps.into_iter().map(|(m, (d, u))| (m, d, u)).collect();
        aps.sort_by(by_total);
        let mut clients: Vec<(String, f64, f64)> = per_client.into_iter().filter(|(_, (d, u))| d + u > 0.0).map(|(m, (d, u))| (m, d, u)).collect();
        clients.sort_by(by_total);
        clients.truncate(25);
        Ok((aps, clients))
    })
    .await?;
    let (aps, clients) = &*got;
    let live = s.live.read().unwrap();
    let ap_list: Vec<Value> = aps.iter().map(|(mac, d, u)| json!({ "name": ap_name(&live, mac), "mac": mac, "download_bytes": d, "upload_bytes": u })).collect();
    let cl_list: Vec<Value> = clients
        .iter()
        .map(|(mac, d, u)| {
            let m: Option<inform::Mac> = mac.parse().ok();
            let view = m.and_then(|m| live.clients.get(&m));
            json!({
                "mac": mac, "name": client_name(&live, m), "connected": view.is_some_and(|c| c.connected),
                "vendor": s.vendors.lookup_str(mac), "download_bytes": d, "upload_bytes": u,
            })
        })
        .collect();
    Ok(Json(json!({ "aps": ap_list, "clients": cl_list })))
}

/// Adds an interval's retries, attempts and drops (`at`: their columns) to
/// `t`; an interval without attempt counters (data from older versions) is
/// skipped. False when skipped.
fn add_retries(t: &mut [f64; 3], d: &Delta, at: [usize; 3]) -> bool {
    let (Some(r), Some(a)) = (d.inc(at[0]), d.inc(at[1])) else { return false };
    t[0] += r;
    t[1] += a;
    t[2] += d.inc(at[2]).unwrap_or(0.0);
    true
}

/// Retries, attempts and drops summed per (AP, band) from SSID counters
/// (`at`: their columns; the text columns are AP and band).
pub(crate) fn retry_totals(vaps: &Loaded, at: [usize; 3], from: Ts) -> HashMap<(&str, &str), [f64; 3]> {
    let mut out: HashMap<(&str, &str), [f64; 3]> = HashMap::new();
    for (ex, samples) in vaps.values() {
        let (mut t, mut any) = ([0.0; 3], false);
        for d in deltas(samples, from) {
            any |= add_retries(&mut t, &d, at);
        }
        if any {
            let e = out.entry((ex[0].as_str(), ex[1].as_str())).or_default();
            for (e, x) in e.iter_mut().zip(t) {
                *e += x;
            }
        }
    }
    out
}

/// TX retry rate as the share of all transmissions: retries / (retries + attempts + dropped).
pub(crate) fn retry_pct([r, a, d]: [f64; 3]) -> f64 {
    let all = r + a + d;
    if all > 0.0 { 100.0 * r / all } else { 0.0 }
}

/// The counters TX retry rates come from, in the order `retry_totals` reads them.
pub(crate) const RETRY_COLS: [&str; 3] = ["tx_retries", "wifi_tx_attempts", "wifi_tx_dropped"];
/// Where they are when only they are loaded.
pub(crate) const RETRY_AT: [usize; 3] = [0, 1, 2];
/// Bytes both ways, in the order `totals` reads them.
const BYTE_COLS: [&str; 2] = ["tx_bytes", "rx_bytes"];
const DENSITY_COLS: &[&str] = &["tx_bytes", "rx_bytes", "tx_retries", "wifi_tx_attempts", "wifi_tx_dropped"];

/// GET /api/site/density: how well each AP's weakest clients hear it. Per
/// report, the average signal of the weaker half of an AP's clients (per
/// band and overall), averaged over the window.
pub async fn density(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let suffix = TIERS[tier].0;
    // Worked out where the data is read, off the async workers and the live lock.
    let aps = memo_read(&s, Db::Metrics, "density", &q, tier, move |c| {
        let mut stmt = c.prepare_cached(&format!("SELECT ts, ap_mac, radio, signal FROM client_stats{suffix} WHERE ts >= ?1 AND ts <= ?2 AND signal < 0 AND ap_mac IS NOT NULL"))?;
        let signals = stmt
            .query_map([from, to], |r| Ok((r.get::<_, Ts>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, f64>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: DENSITY_COLS, only: None }, tier, from, to)?;
        Ok(density_of(signals, &vaps, from))
    })
    .await?;
    let live = s.live.read().unwrap();
    let list: Vec<Value> = aps.iter().map(|(mac, groups)| json!({ "name": ap_name(&live, mac), "mac": mac, "bands": groups })).collect();
    Ok(Json(json!({ "aps": list })))
}

/// [`density`] per AP, from client signals (ts, AP, band, signal) and the VAPs' counters.
fn density_of(signals: Vec<(Ts, String, Option<String>, f64)>, vaps: &Loaded, from: Ts) -> Vec<(String, Vec<Value>)> {
    use std::borrow::Cow;
    const ALL: Cow<str> = Cow::Borrowed("all");
    // ap -> band -> per report time -> client signals
    type Reports = BTreeMap<Ts, Vec<f64>>;
    let mut per: BTreeMap<String, BTreeMap<Cow<str>, Reports>> = BTreeMap::new();
    for (ts, ap, radio, sig) in signals {
        let bands = per.entry(ap).or_default();
        bands.entry(ALL).or_default().entry(ts).or_default().push(sig);
        if let Some(r) = radio {
            bands.entry(Cow::Owned(r)).or_default().entry(ts).or_default().push(sig);
        }
    }
    // Traffic share per band among APs, and retries.
    let at = cols_at(DENSITY_COLS, BYTE_COLS);
    let mut bytes: HashMap<(&str, &str), f64> = HashMap::new();
    for (ex, samples) in vaps.values() {
        let (d, u) = totals(samples, at, from);
        for band in ["all", ex[1].as_str()] {
            *bytes.entry((ex[0].as_str(), band)).or_default() += d + u;
        }
    }
    let mut retries = retry_totals(vaps, cols_at(DENSITY_COLS, RETRY_COLS), from);
    let per_band: Vec<(&str, [f64; 3])> = retries.iter().map(|((ap, _), t)| (*ap, *t)).collect();
    for (ap, t) in per_band {
        let e = retries.entry((ap, "all")).or_default();
        for (e, x) in e.iter_mut().zip(t) {
            *e += x;
        }
    }
    let mut band_total: HashMap<&str, f64> = HashMap::new();
    for ((_, b), v) in &bytes {
        *band_total.entry(b).or_default() += v;
    }
    let mut out = Vec::new();
    for (ap, bands) in per {
        let mut groups = Vec::new();
        for (band, reports) in bands {
            // Each report's signals: all of them averaged, then the weaker half.
            let (mut sum, mut n) = (0.0, 0);
            let mut weakest = Vec::with_capacity(reports.len());
            let count = reports.len();
            for mut sigs in reports.into_values() {
                for x in &sigs {
                    sum += x;
                }
                n += sigs.len();
                sigs.sort_by(f64::total_cmp);
                let half = (sigs.len() / 2).max(1);
                weakest.push(sigs[..half].iter().sum::<f64>() / half as f64);
            }
            let traffic = bytes.get(&(ap.as_str(), band.as_ref())).copied().unwrap_or(0.0);
            let total = band_total.get(band.as_ref()).copied().unwrap_or(0.0);
            let retry = retries.get(&(ap.as_str(), band.as_ref())).map(|r| retry_pct(*r));
            groups.push(json!({
                "band": band,
                "weakest_signal": (weakest.iter().sum::<f64>() / weakest.len().max(1) as f64).round(),
                "signal_avg": (sum / n.max(1) as f64).round(),
                "clients": ((n as f64 / count.max(1) as f64) * 10.0).round() / 10.0,
                "traffic_pct": if total > 0.0 { 100.0 * traffic / total } else { 0.0 },
                "tx_retry_pct": retry,
            }));
        }
        out.push((ap, groups));
    }
    out
}

/// GET /api/site/retries: each AP radio's TX retry rate over the window.
pub async fn retries(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let spec = Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: &RETRY_COLS, only: None };
    // By AP and band.
    let totals = memo_read(&s, Db::Metrics, "retries", &q, tier, move |c| {
        let vaps = load(c, spec, tier, from, to)?;
        let mut totals: Vec<((String, String), [f64; 3])> = retry_totals(&vaps, RETRY_AT, from).into_iter().map(|((ap, band), t)| ((ap.to_string(), band.to_string()), t)).collect();
        totals.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(totals)
    })
    .await?;
    let live = s.live.read().unwrap();
    let out: Vec<Value> = totals
        .iter()
        .map(|((ap, band), t)| {
            json!({ "name": ap_name(&live, ap), "mac": ap, "radio": band, "tx_retry_pct": retry_pct(*t), "retries": t[0], "attempts": t[1], "dropped": t[2] })
        })
        .collect();
    Ok(Json(Value::Array(out)))
}

/// GET /api/site/multicast: multicast and broadcast by traffic type over time
/// (all APs, or one with `mac`), and the 25 clients with the most multicast
/// traffic. `tx` is what the APs delivered to clients, `rx` what clients sent.
pub async fn multicast(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let bucket = bucket_for(to - from, tier);
    let ap = q.mac.as_ref().map(|m| m.to_ascii_lowercase());
    let got = memo_read(&s, Db::Metrics, "multicast", &q, tier, move |c| {
        let (suffix, step) = (TIERS[tier].0, TIERS[tier].1);
        // From a little before the window: what each sample covers starts before it.
        let (one, mut params) = (if ap.is_some() { " AND mac = ?3" } else { "" }, vec![Sql::Integer(from - if step > 0 { step } else { MCAST_GAP }), Sql::Integer(to)]);
        params.extend(ap.clone().map(Sql::Text));
        let mut stmt = c.prepare_cached(&format!(
            "SELECT mac, type, ts, tx_pps, rx_pps, tx_bytes_ps, rx_bytes_ps FROM mcast_stats{suffix} WHERE ts >= ?1 AND ts <= ?2{one} ORDER BY mac, type, ts"
        ))?;
        let rows = stmt
            .query_map(params_from_iter(params), |r| {
                let rate = |i: usize| r.get::<_, Option<f64>>(i).map(|v| v.unwrap_or(0.0));
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Ts>(2)?, [rate(3)?, rate(4)?, rate(5)?, rate(6)?]))
            })?
            .collect::<rusqlite::Result<Vec<McastRow>>>()?;
        let (ts, types) = mcast_types(&rows, from, to, bucket, step);
        let cl = load(
            c,
            // Per client, AP and network: counters restart when a client moves.
            Spec {
                table: "client_stats",
                key: "mac || '/' || coalesce(ap_mac, '') || '/' || coalesce(bssid, '')",
                extra: &[],
                cols: &["mcast_tx_pkts", "mcast_rx_pkts", "mcast_tx_bytes", "mcast_rx_bytes"],
                only: ap.as_deref().map(|a| Only::Is("ap_mac", a)),
            },
            tier,
            from,
            to,
        )?;
        let mut per: HashMap<&str, [f64; 4]> = HashMap::new();
        for (k, (_, smp)) in &cl {
            let e = per.entry(k.split('/').next().unwrap_or_default()).or_default();
            for d in deltas(smp, from) {
                for (i, a) in e.iter_mut().enumerate() {
                    *a += d.inc(i).unwrap_or(0.0);
                }
            }
        }
        // Most packets first (by MAC among equals).
        let mut clients: Vec<(String, [f64; 4])> = per.into_iter().filter(|(_, t)| t[0] + t[1] > 0.0).map(|(m, t)| (m.to_string(), t)).collect();
        clients.sort_by(|a, b| (b.1[0] + b.1[1]).total_cmp(&(a.1[0] + a.1[1])).then_with(|| a.0.cmp(&b.0)));
        clients.truncate(25);
        Ok((ts, types, clients))
    })
    .await?;
    let (ts, types, clients) = &*got;
    let live = s.live.read().unwrap();
    let list: Vec<Value> = clients
        .iter()
        .map(|(mac, t)| {
            let m: Option<inform::Mac> = mac.parse().ok();
            let view = m.and_then(|m| live.clients.get(&m));
            let mc = view.and_then(|v| v.sample.multicast.as_ref());
            json!({
                "mac": mac, "name": client_name(&live, m), "vendor": s.vendors.lookup_str(mac),
                "connected": view.is_some_and(|c| c.connected), "ap": view.and_then(|v| ap_name_of(&live, &v.sample.ap_mac)), "radio": view.and_then(|c| c.sample.radio.clone()),
                "tx_pkts": t[0].round(), "rx_pkts": t[1].round(), "tx_bytes": t[2].round(), "rx_bytes": t[3].round(),
                "services": mc.map(|m| m.services.clone()).unwrap_or_default(),
                "delivery": mc.and_then(|m| m.delivery()),
                "memberships": mc.map_or(0, |m| m.memberships.len()),
            })
        })
        .collect();
    Ok(Json(json!({ "bucket": bucket, "ts": ts, "types": types, "clients": list })))
}

/// The longest interval the engine works a multicast rate out over: a raw
/// sample covers at most this long before it.
const MCAST_GAP: Ts = 120;

/// One AP's multicast sample of one type: (AP, type, time, [tx pps, rx pps,
/// tx bytes/s, rx bytes/s]).
type McastRow = (String, String, Ts, [f64; 4]);

/// The bucket times, and per type the packet rates each way per bucket (the
/// average per AP within the bucket, summed over APs) and the packets and
/// bytes over the window, from the samples ordered by AP, type and time.
/// A total counts each sample's rate over the time it covers within the
/// window: a raw sample (`step` 0) the time since the one before it (at most
/// [`MCAST_GAP`]; the first of a series, with nothing before it, none), a
/// rolled-up one its `step`-second bucket. Samples before `from` only count
/// for the part of the window they cover.
fn mcast_types(rows: &[McastRow], from: Ts, to: Ts, bucket: Ts, step: Ts) -> (Vec<Ts>, serde_json::Map<String, Value>) {
    // type -> bucket -> AP -> (sum of rates, samples)
    type PerAp<'a> = HashMap<&'a str, ([f64; 4], f64)>;
    let mut acc: BTreeMap<&str, BTreeMap<Ts, PerAp>> = BTreeMap::new();
    let mut totals: HashMap<&str, [f64; 4]> = HashMap::new();
    for (i, (mac, kind, ts, r)) in rows.iter().enumerate() {
        let prev = i.checked_sub(1).map(|j| &rows[j]).filter(|p| p.0 == *mac && p.1 == *kind).map(|p| p.2);
        let (start, end) = if step > 0 { (*ts, ts + step) } else { (prev.map_or(*ts, |p| p.max(ts - MCAST_GAP)), *ts) };
        let covered = (end.min(to) - start.max(from)).max(0) as f64;
        for (a, b) in totals.entry(kind.as_str()).or_default().iter_mut().zip(r) {
            *a += b * covered;
        }
        if *ts < from {
            continue;
        }
        let e = acc.entry(kind.as_str()).or_default().entry(ts - ts % bucket).or_default().entry(mac.as_str()).or_default();
        for (a, b) in e.0.iter_mut().zip(r) {
            *a += b;
        }
        e.1 += 1.0;
    }
    let ts: Vec<Ts> = acc.values().flat_map(|b| b.keys().copied()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    let mut types = serde_json::Map::new();
    for (kind, buckets) in &acc {
        // Average per AP within the bucket, summed over APs.
        let series = |i: usize| -> Vec<f64> { ts.iter().map(|t| buckets.get(t).map_or(0.0, |aps| aps.values().map(|(r, n)| r[i] / n.max(1.0)).sum::<f64>())).collect() };
        let total = totals.get(kind).copied().unwrap_or_default();
        types.insert(
            kind.to_string(),
            json!({ "tx_pps": series(0), "rx_pps": series(1), "tx_pkts": total[0].round(), "rx_pkts": total[1].round(), "tx_bytes": total[2].round(), "rx_bytes": total[3].round() }),
        );
    }
    (ts, types)
}

/// Non-secret settings of a network from the imported controller settings.
fn wlan_settings(state: Option<&Value>, essid: &str) -> Value {
    use crate::settings::{docs, id_of};
    let Some(state) = state else { return Value::Null };
    let Some(w) = docs(state, "wlanconf").find(|w| w["name"].as_str() == Some(essid)) else { return Value::Null };
    let network = w["networkconf_id"].as_str().and_then(|id| docs(state, "networkconf").find(|n| id_of(n).as_deref() == Some(id))).and_then(|n| n["name"].as_str());
    let security = crate::settings::security_label(w);
    json!({
        "enabled": w["enabled"].as_bool().unwrap_or(true), "security": security, "hidden": w["hide_ssid"].as_bool().unwrap_or(false),
        "guest": w["is_guest"].as_bool().unwrap_or(false), "network": network,
        "vlan": if w["vlan_enabled"].as_bool() == Some(true) { w["vlan"].clone() } else { Value::Null },
        "bands": w["wlan_bands"].clone(), "fast_roaming": w["fast_roaming_enabled"].as_bool().unwrap_or(false),
        "bss_transition": w["bss_transition"].as_bool().unwrap_or(false), "pmf": w["pmf_mode"].as_str(),
    })
}

/// GET /api/wlans: each Wi-Fi network (SSID): where it is broadcast, its
/// clients now, its experience score (unweighted mean of its SSIDs' scores,
/// as the official controller shows it), and over the window: peak clients,
/// traffic, TX retries, multicast share, client signal and a time series.
pub async fn wlans(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let bucket = bucket_for(to - from, tier);
    // The history, summed up per network where it is read.
    let per = memo_read(&s, Db::Metrics, "wlans", &q, tier, move |c| {
        let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["essid"], cols: WLAN_COLS, only: None }, tier, from, to)?;
        Ok(wlan_history(&vaps, from, bucket))
    })
    .await?;
    // How our own SSIDs are heard over the air (our APs scan each other).
    let own: Vec<Sql> = own_bssids(&s.live.read().unwrap()).map(|(_, v)| Sql::Text(v.bssid.clone())).collect();
    let on_air: HashMap<String, String> = if own.is_empty() {
        HashMap::new()
    } else {
        read(&s.store, Db::Config, move |c| {
            let marks = vec!["?"; own.len()].join(", ");
            let rows = c
                .prepare(&format!("SELECT bssid, security FROM neighbors WHERE security IS NOT NULL AND bssid IN ({marks}) ORDER BY last_seen"))?
                .query_map(params_from_iter(own), |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows.into_iter().collect())
        })
        .await?
    };
    // Now: per network, the APs and bands broadcasting it, clients and scores;
    // copied, so that the live lock is not held while the list is made.
    // essid -> (where it is broadcast, bands, experience scores, APs)
    type Now = (Vec<Value>, std::collections::BTreeSet<String>, Vec<f64>, usize);
    let (mut now, connected, state) = {
        let live = s.live.read().unwrap();
        let mut now: BTreeMap<String, Now> = BTreeMap::new();
        for (mac, d) in &live.devices {
            for (i, v) in d.snapshot.vaps.iter().enumerate() {
                let Some(e) = v.essid.as_deref().filter(|e| !e.is_empty()) else { continue };
                let n = now.entry(e.to_string()).or_default();
                n.0.push(json!({ "ap": mac, "name": d.snapshot.ap.hostname, "radio": v.radio, "channel": v.channel, "bssid": v.bssid, "clients": v.num_sta, "online": d.online }));
                if let Some(r) = &v.radio {
                    n.1.insert(r.clone());
                }
                if let Some(x) = v.satisfaction.filter(|x| *x >= 0 && v.num_sta.unwrap_or(0) > 0) {
                    n.2.push(x as f64);
                }
                // An AP counts once, at its first SSID of the network.
                if !d.snapshot.vaps[..i].iter().any(|w| w.essid == v.essid) {
                    n.3 += 1;
                }
            }
        }
        // The clients connected now, per network (each client is listed once).
        let mut connected: HashMap<&str, usize> = HashMap::new();
        for e in live.clients.values().filter(|c| c.connected).filter_map(|c| c.sample.essid.as_deref()) {
            *connected.entry(e).or_default() += 1;
        }
        let connected: HashMap<String, usize> = connected.into_iter().map(|(e, n)| (e.to_string(), n)).collect();
        (now, connected, live.state.clone())
    };
    let mut names: std::collections::BTreeSet<String> = per.keys().cloned().collect();
    names.extend(now.keys().cloned());
    let mean = |v: &[f64]| (!v.is_empty()).then(|| (v.iter().sum::<f64>() / v.len() as f64).round());
    let list: Vec<Value> = names
        .into_iter()
        .map(|essid| {
            let (bss, bands, scores, ap_count) = now.remove(&essid).unwrap_or_default();
            let clients = connected.get(&essid).copied().unwrap_or(0);
            let agg = per.get(&essid);
            let (ts, series_clients, down_bps, up_bps, peak) = agg.map_or((vec![], vec![], vec![], vec![], 0.0), |a| {
                let mut ts = vec![];
                let (mut cl, mut dn, mut up) = (vec![], vec![], vec![]);
                for (t, m) in &a.series {
                    ts.push(*t);
                    let (c, d, u) = m.values().map(Bucket::averages).fold((0.0, 0.0, 0.0), |s, x| (s.0 + x.0, s.1 + x.1, s.2 + x.2));
                    cl.push(c);
                    dn.push(d * 8.0);
                    up.push(u * 8.0);
                }
                let peak = cl.iter().copied().fold(0.0, f64::max);
                (ts, cl, dn, up, peak)
            });
            let retry = agg.map(|a| a.retry).filter(|t| t.iter().sum::<f64>() > 0.0).map(retry_pct);
            let heard = bss.iter().find_map(|b| b["bssid"].as_str().and_then(|x| on_air.get(x)).cloned());
            json!({
                "essid": essid,
                "settings": wlan_settings(state.as_deref(), &essid),
                "security_on_air": heard,
                "broadcast": bss,
                "bands": bands,
                "ap_count": ap_count,
                "clients": clients,
                "peak_clients": peak.round().max(clients as f64),
                "satisfaction": mean(&scores),
                "satisfaction_avg": agg.and_then(|a| a.sat.get()).map(f64::round),
                "signal_avg": agg.and_then(|a| a.sig.get()).map(f64::round),
                "download_bytes": agg.map_or(0.0, |a| a.down), "upload_bytes": agg.map_or(0.0, |a| a.up),
                "tx_retry_pct": retry,
                "multicast_pct": agg.filter(|a| a.pkts > 0.0).map(|a| (100.0 * a.mcast / a.pkts).min(100.0)),
                "series": { "ts": ts, "clients": series_clients, "download_bps": down_bps, "upload_bps": up_bps },
            })
        })
        .collect();
    Ok(Json(json!({ "bucket": bucket, "wlans": list })))
}

/// What `wlans` loads per VAP.
const WLAN_COLS: &[&str] = &[
    "tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_mcast", "rx_mcast", "tx_bcast", "rx_bcast", "tx_retries", "wifi_tx_attempts", "wifi_tx_dropped",
    "num_sta", "satisfaction", "avg_client_signal",
];

/// One SSID in a bucket of [`WlanAgg::series`].
#[derive(Default, Clone, Copy)]
struct Bucket {
    /// Clients, summed over its samples.
    clients: f64,
    samples: f64,
    /// Bytes per second each way, summed over its intervals.
    down: f64,
    up: f64,
    intervals: f64,
}

impl Bucket {
    /// Average clients, and bytes per second each way.
    fn averages(&self) -> (f64, f64, f64) {
        let i = self.intervals.max(1.0);
        (self.clients / self.samples.max(1.0), self.down / i, self.up / i)
    }
}

/// A running mean: (sum, count).
#[derive(Default, Clone, Copy)]
struct Mean(f64, usize);

impl Mean {
    fn add(&mut self, x: f64) {
        self.0 += x;
        self.1 += 1;
    }

    /// None without values.
    fn get(self) -> Option<f64> {
        (self.1 > 0).then(|| self.0 / self.1 as f64)
    }
}

/// One network's history in [`wlans`].
#[derive(Default)]
struct WlanAgg {
    down: f64,
    up: f64,
    pkts: f64,
    mcast: f64,
    sat: Mean,
    sig: Mean,
    /// bucket -> SSID (its place among the VAPs loaded) -> its share
    series: BTreeMap<Ts, HashMap<usize, Bucket>>,
    /// Retries, attempts and drops over all its SSIDs.
    retry: [f64; 3],
}

/// The VAPs' history ([`WLAN_COLS`], with the network name) summed up per network.
fn wlan_history(vaps: &Loaded, from: Ts, bucket: Ts) -> BTreeMap<String, WlanAgg> {
    let [tx_bytes, rx_bytes, tx_packets, rx_packets, tx_mcast, rx_mcast, tx_bcast, rx_bcast, num_sta, satisfaction, signal] =
        cols_at(WLAN_COLS, ["tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_mcast", "rx_mcast", "tx_bcast", "rx_bcast", "num_sta", "satisfaction", "avg_client_signal"]);
    let retries = cols_at(WLAN_COLS, RETRY_COLS);
    let mut per: BTreeMap<String, WlanAgg> = BTreeMap::new();
    for (vap, (ex, samples)) in vaps.values().enumerate() {
        let essid = &ex[0];
        if essid.is_empty() {
            continue;
        }
        if !per.contains_key(essid) {
            per.insert(essid.clone(), WlanAgg::default());
        }
        let a = per.get_mut(essid).expect("just added");
        for d in deltas(samples, from) {
            let g = |i: usize| d.inc(i).unwrap_or(0.0);
            a.down += g(tx_bytes);
            a.up += g(rx_bytes);
            a.pkts += g(tx_packets) + g(rx_packets);
            a.mcast += g(tx_mcast) + g(rx_mcast) + g(tx_bcast) + g(rx_bcast);
            let e = a.series.entry(d.ts - d.ts % bucket).or_default().entry(vap).or_default();
            e.down += d.rate(tx_bytes).unwrap_or(0.0);
            e.up += d.rate(rx_bytes).unwrap_or(0.0);
            e.intervals += 1.0;
            add_retries(&mut a.retry, &d, retries);
        }
        for (t, v) in samples.since(from) {
            let e = a.series.entry(t - t % bucket).or_default().entry(vap).or_default();
            e.clients += v[num_sta].unwrap_or(0.0);
            e.samples += 1.0;
            if let Some(x) = v[satisfaction].filter(|x| *x >= 0.0) {
                a.sat.add(x);
            }
            if let Some(x) = v[signal].filter(|x| *x < -10.0) {
                a.sig.add(x);
            }
        }
    }
    per
}

/// What `radios` loads per VAP.
const RADIO_VAP_COLS: &[&str] = &["tx_bytes", "rx_bytes", "avg_client_signal", "tx_retries", "wifi_tx_attempts", "wifi_tx_dropped"];

/// One radio's averages over the window, as `radios` lists them.
#[derive(Default)]
struct RadioAvg {
    utilization: Option<f64>,
    interference: Option<f64>,
    retry_pct: Option<f64>,
    /// Bytes both ways over all its SSIDs.
    usage: f64,
    signal: Mean,
}

/// GET /api/rf/radios: each AP radio with its settings now and its averages
/// over the window (interference, utilisation, traffic, retries, signal).
pub async fn radios(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    // By `mac/radio`, worked out where the data is read.
    let avgs = memo_read(&s, Db::Metrics, "radios", &q, tier, move |c| {
        let mut out: HashMap<String, RadioAvg> = HashMap::new();
        // Airtime: SQLite averages each radio's samples in the window.
        let sql = format!("SELECT mac || '/' || radio, AVG(cu_total), AVG(cu_interf) FROM radio_stats{} WHERE ts >= ?1 AND ts <= ?2 GROUP BY mac, radio", TIERS[tier].0);
        let mut stmt = c.prepare_cached(&sql)?;
        let mut rows = stmt.query([from, to])?;
        while let Some(r) = rows.next()? {
            let e = out.entry(r.get(0)?).or_default();
            (e.utilization, e.interference) = (r.get(1)?, r.get(2)?);
        }
        // Retries come from the VAPs: the radio-level counters stay at 0 on some models.
        let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: RADIO_VAP_COLS, only: None }, tier, from, to)?;
        for ((ap, band), t) in retry_totals(&vaps, cols_at(RADIO_VAP_COLS, RETRY_COLS), from) {
            out.entry(format!("{ap}/{band}")).or_default().retry_pct = Some(retry_pct(t));
        }
        // Traffic and client signal per radio.
        let [tx, rx, signal] = cols_at(RADIO_VAP_COLS, ["tx_bytes", "rx_bytes", "avg_client_signal"]);
        for (ex, samples) in vaps.values() {
            let e = out.entry(format!("{}/{}", ex[0], ex[1])).or_default();
            for d in deltas(samples, from) {
                e.usage += d.inc(tx).unwrap_or(0.0) + d.inc(rx).unwrap_or(0.0);
            }
            // The AP reports 0 or -1 when no client is connected.
            for x in samples.since(from).filter_map(|(_, v)| v[signal]).filter(|v| *v < -10.0) {
                e.signal.add(x);
            }
        }
        Ok(out)
    })
    .await?;
    let live = s.live.read().unwrap();
    let mut out = Vec::new();
    for (mac, d) in &live.devices {
        let mac_s = mac.to_string();
        for r in &d.snapshot.radios {
            let a = avgs.get(&format!("{mac_s}/{}", r.radio));
            out.push(json!({
                "mac": mac, "name": d.snapshot.ap.hostname, "radio": r.radio, "channel": r.channel, "bw": r.bw,
                "tx_power": r.tx_power, "eirp": r.tx_power.zip(r.antenna_gain).map(|(p, g)| p + g),
                "clients": r.num_sta, "noise_floor": r.noise_floor,
                "avg_utilization": a.and_then(|a| a.utilization), "avg_interference": a.and_then(|a| a.interference), "tx_retry_pct": a.and_then(|a| a.retry_pct),
                "usage_bytes": a.map_or(0.0, |a| a.usage),
                "avg_client_signal": a.and_then(|a| a.signal.get()),
            }));
        }
    }
    Ok(Json(Value::Array(out)))
}

#[derive(Deserialize)]
pub struct NeighborQuery {
    band: Option<String>,
    /// Only networks heard within this many seconds (default one day).
    range: Option<Ts>,
    /// Only our APs' signal to each other (`neighbors` comes back empty).
    #[serde(default)]
    links_only: bool,
    /// Only the networks heard (`own_links` comes back empty).
    #[serde(default)]
    neighbors_only: bool,
}

/// A network one of our APs heard, as `/api/rf/neighbors` lists it.
#[derive(Serialize)]
struct Neighbor<'a> {
    bssid: String,
    ap_mac: String,
    radio: Option<String>,
    essid: Option<String>,
    channel: Option<i64>,
    bw: Option<i64>,
    center_freq: Option<i64>,
    security: Option<String>,
    signal: Option<i64>,
    best_signal: Option<i64>,
    is_unifi: bool,
    ap_name: Option<String>,
    model: Option<String>,
    first_seen: Ts,
    last_seen: Ts,
    /// The name of the AP that hears it best.
    nearest_ap: Option<String>,
    vendor: Option<&'a str>,
}

/// One of our APs heard by another, with the strongest signal heard.
#[derive(Serialize)]
struct OwnLink {
    from: String,
    from_name: Option<String>,
    to: String,
    to_name: Option<String>,
    radio: Option<String>,
    signal: Option<i64>,
}

/// GET /api/rf/neighbors: networks heard by our APs, the AP hearing each best,
/// and our own APs' signal to each other (AP density), once per pair of APs
/// and band; either list alone with `links_only` or `neighbors_only`.
pub async fn neighbors(State(s): State<AppState>, Query(q): Query<NeighborQuery>) -> Result<Json<Value>, ApiError> {
    let since = clock::now_ts() - q.range.unwrap_or(86400).clamp(600, 30 * 86400);
    let band = q.band.clone();
    // Our APs' signal to each other only: the rows of our own BSSIDs (the table's key) are enough.
    let only: Option<Vec<Sql>> = q.links_only.then(|| own_bssids(&s.live.read().unwrap()).map(|(_, v)| Sql::Text(v.bssid.clone())).collect());
    let rows = read(&s.store, Db::Config, move |c| {
        if only.as_ref().is_some_and(Vec::is_empty) {
            return Ok(Vec::new());
        }
        let mut cond = "last_seen >= ?1".to_string();
        let mut params = vec![Sql::Integer(since)];
        if let Some(b) = band.filter(|b| b != "all") {
            params.push(Sql::Text(b));
            cond.push_str(" AND radio = ?2");
        }
        if let Some(own) = only {
            let marks: Vec<String> = (params.len() + 1..=params.len() + own.len()).map(|i| format!("?{i}")).collect();
            cond.push_str(&format!(" AND bssid IN ({})", marks.join(", ")));
            params.extend(own);
        }
        let sql = format!(
            "SELECT bssid, ap_mac, radio, essid, channel, bw, center_freq, security, signal, best_signal, is_unifi, ap_name, model, first_seen, last_seen FROM neighbors WHERE {cond}"
        );
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(params), |r| {
                Ok(Neighbor {
                    bssid: r.get(0)?, ap_mac: r.get(1)?, radio: r.get(2)?, essid: r.get(3)?, channel: r.get(4)?, bw: r.get(5)?, center_freq: r.get(6)?,
                    security: r.get(7)?, signal: r.get(8)?, best_signal: r.get(9)?, is_unifi: r.get::<_, i64>(10)? != 0, ap_name: r.get(11)?, model: r.get(12)?,
                    first_seen: r.get(13)?, last_seen: r.get(14)?, nearest_ap: None, vendor: None,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    // Our own BSSIDs (to tell our APs apart from the neighbours) and our APs' names, copied
    // so that the live lock is not held while the lists are made.
    let (own, names) = {
        let live = s.live.read().unwrap();
        let own: HashMap<String, (String, Option<String>)> = own_bssids(&live).map(|(m, v)| (v.bssid.clone(), (m.to_string(), v.radio.clone()))).collect();
        let names: HashMap<String, String> = live.devices.iter().filter_map(|(m, d)| Some((m.to_string(), d.snapshot.ap.hostname.clone()?))).collect();
        (own, names)
    };
    let name = |mac: &str| names.get(mac).cloned();
    let signal = |n: &Neighbor| n.signal.unwrap_or(-200);
    let mut by_bssid: BTreeMap<String, Neighbor> = BTreeMap::new();
    // (from, to, band) -> strongest signal: an AP has a BSSID per SSID.
    let mut links: BTreeMap<(String, &str, Option<&str>), Option<i64>> = BTreeMap::new();
    for r in rows {
        if let Some((owner, radio)) = own.get(&r.bssid) {
            // One of our APs heard another of ours.
            if *owner != r.ap_mac && !q.neighbors_only {
                let e = links.entry((r.ap_mac, owner, radio.as_deref())).or_insert(r.signal);
                *e = (*e).max(r.signal);
            }
            continue;
        }
        if !q.links_only && by_bssid.get(&r.bssid).is_none_or(|cur| signal(&r) > signal(cur)) {
            by_bssid.insert(r.bssid.clone(), r);
        }
    }
    let mut list: Vec<Neighbor> = by_bssid.into_values().collect();
    for n in &mut list {
        n.nearest_ap = name(&n.ap_mac);
        n.vendor = s.vendors.lookup_str(&n.bssid);
    }
    list.sort_by_key(|n| -signal(n));
    let links: Vec<OwnLink> = links
        .into_iter()
        .map(|((from, to, radio), signal)| OwnLink { from_name: name(&from), to_name: name(to), from, to: to.to_string(), radio: radio.map(str::to_string), signal })
        .collect();
    Ok(Json(json!({ "neighbors": list, "own_links": links })))
}

#[derive(Deserialize)]
pub struct PlanQuery {
    band: Option<String>,
    /// Consider DFS channels on 5 GHz (radar can force the AP off them).
    dfs: Option<bool>,
}

/// A candidate channel block: its primary channel and frequency span (MHz).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Block {
    primary: i64,
    width: i64,
    lo: f64,
    hi: f64,
}

fn block(radio: &str, primary: i64, width: i64) -> Block {
    if radio == "ng" {
        let c = 2407.0 + 5.0 * primary as f64;
        return Block { primary, width, lo: c - 10.0, hi: c + 10.0 };
    }
    // 5 GHz: channels are grouped by width from these group starts.
    let starts: &[i64] = match width {
        w if w >= 160 => &[36, 100],
        80 => &[36, 52, 100, 116, 132, 149],
        40 => &[36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157],
        _ => &[],
    };
    let span = (width / 20).max(1);
    let first = starts.iter().copied().rfind(|s| primary >= *s && primary < s + span * 4).unwrap_or(primary);
    let lo = 5000.0 + 5.0 * first as f64 - 10.0;
    Block { primary, width, lo, hi: lo + width as f64 }
}

fn overlap(a: &Block, lo: f64, hi: f64) -> bool {
    a.lo < hi && lo < a.hi
}

/// Weight of a signal: dB above the noise floor, so loud networks dominate.
fn weight(signal: f64) -> f64 {
    (signal + 95.0).max(0.0)
}

/// Candidate blocks. `available` is the AP's own list of channel blocks for its
/// country and width (from its `spectrum_table`); without it a generic list is used.
fn candidates(radio: &str, width: i64, dfs: bool, available: Option<&[i64]>) -> Vec<Block> {
    if radio == "ng" {
        return [1, 6, 11]
            .into_iter()
            .filter(|c| available.is_none_or(|a| a.contains(c)))
            .map(|c| block("ng", c, 20))
            .collect();
    }
    if let Some(a) = available.filter(|a| !a.is_empty()) {
        return a.iter().copied().filter(|c| dfs || !is_dfs(*c)).map(|c| block(radio, c, width)).collect();
    }
    let mut chans: Vec<i64> = vec![36, 40, 44, 48, 149, 153, 157, 161];
    if dfs {
        chans.extend([52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]);
    }
    // One candidate per aligned block (its first channel as primary).
    let mut out: Vec<Block> = Vec::new();
    for c in chans {
        let b = block(radio, c, width);
        if !out.iter().any(|o| (o.lo - b.lo).abs() < 1.0) {
            out.push(b);
        }
    }
    out
}

/// Candidate blocks made only of `allowed` channels (every 20 MHz part of a
/// wide block must be allowed), one per block.
fn allowed_blocks(radio: &str, width: i64, allowed: &[i64]) -> Vec<Block> {
    if radio == "ng" {
        return allowed.iter().map(|c| block("ng", *c, 20)).collect();
    }
    let mut out: Vec<Block> = Vec::new();
    for c in allowed {
        let b = block(radio, *c, width);
        let first = ((b.lo + 10.0 - 5000.0) / 5.0).round() as i64;
        let parts: Vec<i64> = (0..(width / 20).max(1)).map(|i| first + 4 * i).collect();
        if parts.iter().all(|p| allowed.contains(p)) && !out.iter().any(|o| (o.lo - b.lo).abs() < 1.0) {
            out.push(block(radio, first, width));
        }
    }
    out
}

/// GET /api/rf/channel-plan: a suggested channel per AP for one band, from
/// the networks each AP hears, our APs' signal to each other, and measured
/// interference. Suggestions only: nothing is applied.
pub async fn channel_plan(State(s): State<AppState>, Query(q): Query<PlanQuery>) -> Result<Json<Plan>, ApiError> {
    let radio = q.band.clone().unwrap_or_else(|| "na".into());
    let dfs = q.dfs.unwrap_or(false);
    let (allowed, pinned) = {
        let live = s.live.read().unwrap();
        (crate::channelai::allowed(live.state.as_deref(), &radio, dfs), crate::channelai::pinned(&live, &radio))
    };
    Ok(Json(compute_plan(&s, radio, dfs, allowed, pinned).await?))
}

/// A channel plan for one band.
#[derive(Debug, Serialize)]
pub struct Plan {
    pub band: String,
    pub dfs: bool,
    /// The channels the plan could use; `None`: any.
    pub allowed: Option<Vec<i64>>,
    pub plan: Vec<PlanEntry>,
    pub current_total: f64,
    pub suggested_total: f64,
    /// Worth applying: clearly better, or an AP must move.
    pub accepted: bool,
}

/// One AP in a channel plan.
#[derive(Debug, Serialize)]
pub struct PlanEntry {
    pub mac: String,
    pub name: Option<String>,
    pub width: i64,
    pub clients: i64,
    pub current_channel: i64,
    pub current_score: f64,
    pub current_reasons: Vec<String>,
    pub suggested_channel: i64,
    pub suggested_score: f64,
    /// Only for an AP that moves.
    pub suggested_reasons: Vec<String>,
    pub change: bool,
    pub pinned: bool,
    /// It moves because its channel is no longer allowed.
    pub not_allowed: bool,
}

/// An AP radio as the plan sees it.
struct PlanAp {
    mac: String,
    name: Option<String>,
    /// The block it is on now.
    current: Block,
    width: i64,
    clients: i64,
    /// Channel blocks the AP lists as available (its country and width).
    available: Option<Vec<i64>>,
    /// The primary channels the site's country allows this AP at the width in
    /// its settings, indoors or outdoors as it is set (what `set_channels`
    /// checks a plan against); `None`: no rules known, or no settings.
    legal: Option<Vec<i64>>,
}

/// A network an AP hears (not one of ours): its name, span and signal.
struct Heard {
    essid: Option<String>,
    lo: f64,
    hi: f64,
    signal: f64,
}

/// The channel plan for one band (`ng` or `na`). `allowed` limits the
/// channels (the Channel AI settings; `None`: every channel the AP or the band
/// offers), `pinned` APs keep their channel. A plan only moves APs when it is
/// clearly better overall (by more than 10%), or when an AP is on a channel no
/// longer allowed.
pub async fn compute_plan(s: &AppState, radio: String, dfs: bool, allowed: Option<Vec<i64>>, pinned: Vec<String>) -> Result<Plan, ApiError> {
    // The channel blocks are worked out for 2.4 and 5 GHz only.
    if !matches!(radio.as_str(), "ng" | "na") {
        return Err(ApiError(axum::http::StatusCode::BAD_REQUEST, "band must be ng or na".into()));
    }
    let since = clock::now_ts() - 7 * 86400;
    let r2 = radio.clone();
    let (neigh, spectrum) = read(&s.store, Db::Config, move |c| {
        let mut stmt = c.prepare("SELECT ap_mac, bssid, essid, center_freq, bw, signal FROM neighbors WHERE radio = ?1 AND last_seen >= ?2")?;
        let n = stmt
            .query_map(rusqlite::params![r2, since], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, Option<f64>>(4)?, r.get::<_, Option<f64>>(5)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Scans as recent as the networks heard.
        let mut stmt = c.prepare("SELECT ap_mac, channel, width, interference, utilization FROM spectrum WHERE radio = ?1 AND ts >= ?2")?;
        let sp = stmt
            .query_map(rusqlite::params![r2, since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, Option<f64>>(4)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((n, sp))
    })
    .await?;
    // What the plan needs from `live`, copied so the lock is not held while it is worked out.
    let (aps, own_bssids) = {
        let live = s.live.read().unwrap();
        let state = live.state.as_deref();
        let country = state.and_then(crate::settings::country);
        let aps: Vec<PlanAp> = live
            .devices
            .iter()
            .filter_map(|(m, d)| {
                let r = d.snapshot.radios.iter().find(|r| r.radio == radio)?;
                let ch = r.channel?;
                let width = if radio == "ng" { 20 } else { r.bw.unwrap_or(80) };
                let available = live.raw_informs.get(m).and_then(|p| {
                    let rt = crate::settings::inform_radio(p, &radio)?;
                    let list: Vec<i64> = rt["spectrum_table"]
                        .as_array()?
                        .iter()
                        .filter(|c| radio == "ng" || c["width"].as_i64() == Some(width))
                        .filter_map(|c| c["channel"].as_i64())
                        .collect();
                    (!list.is_empty()).then_some(list)
                });
                // As `set_channels` judges a channel: at the radio's width in the settings, not the one reported.
                let legal = state.and_then(|st| {
                    let doc = crate::adopt::device_doc(st, m)?;
                    let at = crate::settings::inform_radio(doc, &radio).map_or(width, |r| crate::settings::num(&r["ht"]).unwrap_or(20));
                    crate::settings::legal_channels(country, &radio, at, crate::settings::outdoor(st, doc))
                });
                Some(PlanAp { mac: m.to_string(), name: d.snapshot.ap.hostname.clone(), current: block(&radio, ch, width), width, clients: r.num_sta, available, legal })
            })
            .collect();
        // Our APs' BSSIDs on this band, to separate own signal from neighbours.
        let own: HashMap<String, String> =
            own_bssids(&live).filter(|(_, v)| v.radio.as_deref() == Some(radio.as_str())).map(|(m, v)| (v.bssid.clone(), m.to_string())).collect();
        (aps, own)
    };
    let work = move || plan_channels(radio, dfs, allowed, pinned, aps, own_bssids, neigh, spectrum);
    Ok(tokio::task::spawn_blocking(work).await?)
}

type NeighborRow = (String, String, Option<String>, Option<f64>, Option<f64>, Option<f64>);
type SpectrumRow = (String, i64, Option<i64>, Option<f64>, Option<f64>);

/// The greedy search behind [`compute_plan`], on data copied out of `live`.
/// APs are known by their place in `aps`.
#[allow(clippy::too_many_arguments)] // the inputs of one computation, passed once
fn plan_channels(
    radio: String,
    dfs: bool,
    allowed: Option<Vec<i64>>,
    pinned: Vec<String>,
    aps: Vec<PlanAp>,
    own_bssids: HashMap<String, String>,
    neigh: Vec<NeighborRow>,
    spectrum: Vec<SpectrumRow>,
) -> Plan {
    let n = aps.len();
    let index: HashMap<&str, usize> = aps.iter().enumerate().map(|(i, a)| (a.mac.as_str(), i)).collect();
    // AP-to-AP signal (strongest seen either way), and what each AP hears of the neighbours.
    let mut ap_signal: Vec<Vec<Option<f64>>> = vec![vec![None; n]; n];
    let mut heard: Vec<Vec<Heard>> = (0..n).map(|_| Vec::new()).collect();
    for (heard_by, bssid, essid, cf, bw, sig) in neigh {
        let Some(&by) = index.get(heard_by.as_str()) else { continue };
        match own_bssids.get(&bssid) {
            Some(owner) => {
                if let (Some(sig), Some(&of)) = (sig, index.get(owner.as_str())) {
                    for (a, b) in [(by, of), (of, by)] {
                        let e = &mut ap_signal[a][b];
                        *e = Some(e.map_or(sig, |s| s.max(sig)));
                    }
                }
            }
            None => {
                let (Some(cf), Some(signal)) = (cf, sig) else { continue };
                let half = bw.unwrap_or(20.0) / 2.0;
                heard[by].push(Heard { essid, lo: cf - half, hi: cf + half, signal });
            }
        }
    }
    // Measured load per AP: the channel blocks and what each costs.
    let mut measured: Vec<Vec<(Block, f64)>> = (0..n).map(|_| Vec::new()).collect();
    for (m, ch, width, interference, util) in spectrum {
        let Some(&i) = index.get(m.as_str()) else { continue };
        let load = util.unwrap_or(0.0) * 0.5 + interference.map_or(0.0, |i| weight(i) * 0.5);
        measured[i].push((block(&radio, ch, width.unwrap_or(20)), load));
    }
    // Each AP's candidate blocks, worked out once: among the allowed ones, only
    // those the AP lists and the country allows it, so that the plan can be applied.
    let cands: Vec<Vec<Block>> = aps
        .iter()
        .map(|ap| {
            let mut c = match &allowed {
                Some(a) => allowed_blocks(&radio, ap.width, a),
                None => candidates(&radio, ap.width, dfs, ap.available.as_deref()),
            };
            c.retain(|b| ap.available.as_ref().is_none_or(|a| a.contains(&b.primary)) && ap.legal.as_ref().is_none_or(|l| l.contains(&b.primary)));
            c
        })
        .collect();
    let is_pinned: Vec<bool> = aps.iter().map(|ap| pinned.contains(&ap.mac)).collect();
    // What AP `i` would put up with on block `b`, the others placed as in `placed`
    // (its own entry there is ignored), with (weight, reason) per contribution when `why`.
    let contributions = |i: usize, b: &Block, placed: &[Block], mut why: Option<&mut Vec<(f64, String)>>| -> f64 {
        let mut total = 0.0;
        for h in &heard[i] {
            if overlap(b, h.lo, h.hi) {
                let w = weight(h.signal);
                total += w;
                if let Some(why) = why.as_deref_mut() {
                    why.push((w, format!("{} ({:.0} dBm)", h.essid.as_deref().unwrap_or("hidden network"), h.signal)));
                }
            }
        }
        for (o, ob) in placed.iter().enumerate() {
            if o == i || !overlap(b, ob.lo, ob.hi) {
                continue;
            }
            let sig = ap_signal[i][o].unwrap_or(-75.0);
            let w = 2.0 * weight(sig);
            total += w;
            if let Some(why) = why.as_deref_mut() {
                why.push((w, format!("your AP {} ({sig:.0} dBm)", aps[o].name.as_deref().unwrap_or(&aps[o].mac))));
            }
        }
        for (sb, load) in &measured[i] {
            if overlap(b, sb.lo, sb.hi) {
                total += load;
            }
        }
        total
    };
    let cost = |i: usize, b: &Block, placed: &[Block]| contributions(i, b, placed, None);
    // The cost with the four biggest reasons, for the plan shown.
    let explain = |i: usize, b: &Block, placed: &[Block]| -> (f64, Vec<String>) {
        let mut reasons = Vec::new();
        let total = contributions(i, b, placed, Some(&mut reasons));
        reasons.sort_by(|a, b| b.0.total_cmp(&a.0));
        (total, reasons.into_iter().take(4).map(|r| r.1).collect())
    };
    // Greedy: busiest AP first, then a second pass with everyone placed.
    let mut order: Vec<usize> = (0..n).filter(|i| !is_pinned[*i]).collect();
    order.sort_by_key(|i| -aps[*i].clients);
    let current: Vec<Block> = aps.iter().map(|a| a.current).collect();
    let mut assigned = current.clone();
    for _ in 0..2 {
        for &i in &order {
            let best = cands[i].iter().map(|b| (cost(i, b, &assigned), *b)).min_by(|a, b| a.0.total_cmp(&b.0));
            if let Some((_, b)) = best {
                assigned[i] = b;
            }
        }
    }
    // Which APs move, and whether because their channel is no longer allowed
    // (otherwise they are clearly better off elsewhere).
    let mut evict: Vec<Option<bool>> = vec![None; n];
    let mut fin = current.clone();
    for (i, ap) in aps.iter().enumerate() {
        let (cur, sug) = (ap.current, assigned[i]);
        if is_pinned[i] || cur.primary == sug.primary {
            continue;
        }
        let ev = !cands[i].iter().any(|b| (b.lo - cur.lo).abs() < 1.0 && (b.hi - cur.hi).abs() < 1.0);
        if ev || cost(i, &sug, &assigned) + 5.0 < cost(i, &cur, &assigned) * 0.8 {
            fin[i] = sug;
            evict[i] = Some(ev);
        }
    }
    let total = |m: &[Block]| -> f64 { m.iter().enumerate().map(|(i, b)| cost(i, b, m)).sum() };
    let (current_total, final_total) = (total(&current), total(&fin));
    let accepted = evict.contains(&Some(true)) || (evict.iter().any(Option::is_some) && final_total * 1.1 < current_total);
    // A plan not worth applying suggests leaving every AP where it is, and is scored as that.
    let suggested_total = if accepted { final_total } else { current_total };
    if !accepted {
        fin = current.clone();
        evict = vec![None; n];
    }
    let plan: Vec<PlanEntry> = aps
        .iter()
        .enumerate()
        .map(|(i, ap)| {
            let (cur_score, cur_reasons) = explain(i, &ap.current, &current);
            let change = evict[i].is_some();
            // The reasons for a suggestion are only shown for an AP that moves.
            let (sug_score, sug_reasons) = if change { explain(i, &fin[i], &fin) } else { (cost(i, &fin[i], &fin), Vec::new()) };
            PlanEntry {
                mac: ap.mac.clone(),
                name: ap.name.clone(),
                width: ap.width,
                clients: ap.clients,
                current_channel: ap.current.primary,
                current_score: cur_score.round(),
                current_reasons: cur_reasons,
                suggested_channel: fin[i].primary,
                suggested_score: sug_score.round(),
                suggested_reasons: sug_reasons,
                change,
                pinned: is_pinned[i],
                not_allowed: evict[i].unwrap_or(false),
            }
        })
        .collect();
    Plan { band: radio, dfs, allowed, plan, current_total: current_total.round(), suggested_total: suggested_total.round(), accepted }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::TestDir;

    #[test]
    fn channel_blocks_and_overlap() {
        let b = block("na", 44, 80); // 36-48 block
        assert_eq!((b.lo, b.hi), (5170.0, 5250.0));
        assert_eq!(block("na", 36, 80).lo, b.lo, "same 80 MHz block");
        assert!(overlap(&b, 5210.0 - 10.0, 5210.0 + 10.0));
        assert!(!overlap(&b, 5290.0 - 40.0, 5290.0 + 40.0), "52-64 block is next door");
        let one = block("ng", 1, 20);
        assert!(overlap(&one, 2427.0 - 10.0, 2427.0 + 10.0), "channel 4 overlaps 1");
        assert!(!overlap(&one, 2437.0 - 10.0, 2437.0 + 10.0), "channel 6 does not");
        assert_eq!(candidates("na", 80, false, None).len(), 2, "generic: 36-48 and 149-161 without DFS");
        assert_eq!(candidates("na", 80, true, None).len(), 6);
        assert_eq!(candidates("ng", 20, false, None).iter().map(|b| b.primary).collect::<Vec<_>>(), vec![1, 6, 11]);
        // What a U6-Mesh in Germany lists at 80 MHz: 36, 52, 100, 116.
        let eu = [36, 52, 100, 116];
        assert_eq!(candidates("na", 80, false, Some(&eu)).iter().map(|b| b.primary).collect::<Vec<_>>(), vec![36]);
        assert_eq!(candidates("na", 80, true, Some(&eu)).len(), 4);
        // Allowed lists (Channel AI): a wide block needs every 20 MHz part allowed.
        let low = [36, 40, 44, 48];
        assert_eq!(allowed_blocks("na", 40, &low).iter().map(|b| b.primary).collect::<Vec<_>>(), vec![36, 44]);
        assert_eq!(allowed_blocks("na", 80, &low).iter().map(|b| b.primary).collect::<Vec<_>>(), vec![36]);
        assert!(allowed_blocks("na", 160, &low).is_empty(), "36-64 needs 52-64 too");
        assert_eq!(allowed_blocks("na", 80, &[36, 40, 44]).len(), 0);
        assert_eq!(allowed_blocks("ng", 20, &[1, 6, 11]).len(), 3);
    }

    #[test]
    fn two_aps_that_hear_each_other_are_split() {
        let ap = |mac: &str, ch: i64, clients: i64| PlanAp { mac: mac.into(), name: Some(format!("AP {mac}")), current: block("ng", ch, 20), width: 20, clients, available: None, legal: None };
        let aps = vec![ap("a", 6, 5), ap("b", 6, 1)];
        let own = HashMap::from([("bss-a".to_string(), "a".to_string()), ("bss-b".to_string(), "b".to_string())]);
        // Each hears the other loudly, and "a" hears a neighbour on channel 1.
        let neigh = vec![
            ("a".to_string(), "bss-b".to_string(), None, None, None, Some(-50.0)),
            ("b".to_string(), "bss-a".to_string(), None, None, None, Some(-50.0)),
            ("a".to_string(), "x".to_string(), Some("Next door".to_string()), Some(2412.0), Some(20.0), Some(-60.0)),
        ];
        let plan = plan_channels("ng".into(), false, None, vec![], aps, own, neigh, vec![]);
        assert!(plan.accepted, "{plan:?}");
        let ch: HashMap<&str, i64> = plan.plan.iter().map(|p| (p.mac.as_str(), p.suggested_channel)).collect();
        assert_ne!(ch["a"], ch["b"]);
        assert_ne!(ch["a"], 1, "a keeps off its neighbour");
        let a = plan.plan.iter().find(|p| p.mac == "a").unwrap();
        assert_eq!(a.current_reasons, ["your AP AP b (-50 dBm)"]);
    }

    #[test]
    fn plans_use_only_channels_the_ap_lists_and_may_use_where_it_stands() {
        // Channel AI allows every channel Germany has at 80 MHz, DFS included.
        let allowed = crate::settings::legal_channels(Some(276), "na", 80, false);
        let ap = |mac: &str, clients: i64, available: Option<Vec<i64>>, outdoor: bool| PlanAp {
            mac: mac.into(), name: None, current: block("na", 36, 80), width: 80, clients, available,
            legal: crate::settings::legal_channels(Some(276), "na", 80, outdoor),
        };
        // "in" hears a loud neighbour on 36-48 and lists only 36 and 116; without its list it would take 52.
        // "out" is outdoors, where 36-64 are not allowed, so it must leave 36.
        let aps = vec![ap("in", 5, Some(vec![36, 116]), false), ap("out", 1, None, true)];
        let neigh = vec![("in".to_string(), "x".to_string(), Some("Next door".to_string()), Some(5210.0), Some(80.0), Some(-40.0))];
        let plan = plan_channels("na".into(), true, allowed, vec![], aps, HashMap::new(), neigh, vec![]);
        assert!(plan.accepted, "{plan:?}");
        let to: HashMap<&str, (i64, bool)> = plan.plan.iter().map(|p| (p.mac.as_str(), (p.suggested_channel, p.not_allowed))).collect();
        assert_eq!((to["in"], to["out"]), ((116, false), (100, true)));
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
        // A week ago reads the five-minute tier; a day 60 days back reads hourly.
        assert_eq!(window(&q(None, Some(now - 7 * 86400), Some(now - 6 * 86400))).2, 1);
        assert_eq!(window(&q(None, Some(now - 60 * 86400), Some(now - 59 * 86400))).2, 2);
    }

    #[test]
    fn retries_use_attempts_and_ignore_counter_restarts() {
        let s = |t, r, a, d| (t, vec![Some(r), Some(a), Some(d)]);
        let samples = vec![s(0, 100.0, 1000.0, 0.0), s(10, 130.0, 1100.0, 10.0), s(20, 5.0, 20.0, 0.0), s(30, 25.0, 120.0, 0.0)];
        let mut vaps: Loaded = BTreeMap::new();
        vaps.insert("bss".into(), (vec!["ap".into(), "na".into()], Samples::from_rows(samples)));
        let t = retry_totals(&vaps, RETRY_AT, 0)[&("ap", "na")];
        // 30+20 retries, 100+100 attempts, 10 dropped; the restart at t=20 adds nothing.
        assert_eq!(t, [50.0, 200.0, 10.0]);
        assert!((retry_pct(t) - 100.0 * 50.0 / 260.0).abs() < 1e-9);
        assert_eq!(retry_pct([0.0, 0.0, 0.0]), 0.0);
        // Older rows without attempt counters are left out rather than read as 100 %.
        let mut vaps: Loaded = BTreeMap::new();
        vaps.insert("bss".into(), (vec!["ap".into(), "na".into()], Samples::from_rows(vec![(0, vec![Some(1.0), None, None]), (10, vec![Some(9.0), None, None])])));
        assert!(retry_totals(&vaps, RETRY_AT, 0).is_empty());
    }

    #[test]
    fn network_throughput_is_averaged_over_intervals_not_samples() {
        // A new SSID: three reports in the bucket, so two intervals of 100 bytes/s down.
        let row = |t: Ts, tx: f64| {
            let mut v = vec![None; WLAN_COLS.len()];
            v[col(WLAN_COLS, "tx_bytes")] = Some(tx);
            v[col(WLAN_COLS, "num_sta")] = Some(3.0);
            (t, v)
        };
        let mut vaps: Loaded = BTreeMap::new();
        vaps.insert("bss".into(), (vec!["Home".into()], Samples::from_rows(vec![row(0, 0.0), row(10, 1000.0), row(20, 2000.0)])));
        let per = wlan_history(&vaps, 0, 60);
        let b = per["Home"].series[&0][&0];
        assert_eq!(b.averages(), (3.0, 100.0, 0.0));
        assert_eq!(per["Home"].down, 2000.0);
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
        // Only intervals ending in the window; a gauge is read at the end of one.
        assert_eq!(deltas(&samples, 20).map(|d| d.now(0)).collect::<Vec<_>>(), [Some(50.0), Some(80.0), Some(100.0)]);
        assert_eq!(cols_at(&["a", "b", "c"], ["c", "a"]), [2, 0]);
    }

    #[test]
    fn multicast_totals_count_the_time_each_sample_covers_in_the_window() {
        let row = |ap: &str, ts: Ts, tx: f64| (ap.to_string(), "mdns".to_string(), ts, [tx, 0.0, 10.0 * tx, 0.0]);
        // Raw samples: one before the window (it only starts the next one's interval), the
        // next covering the window's first 10 s, one 5 s later, one 285 s after that (a
        // rate covers 120 s at most), and another AP's first sample (nothing before it).
        let rows = [row("a", 890, 9.0), row("a", 1010, 1.0), row("a", 1015, 2.0), row("a", 1300, 3.0), row("b", 1500, 5.0)];
        let (ts, types) = mcast_types(&rows, 1000, 1600, 60, 0);
        assert_eq!(ts, [960, 1260, 1500]);
        let m = &types["mdns"];
        assert_eq!(m["tx_pps"], json!([1.5, 3.0, 5.0]));
        assert_eq!((m["tx_pkts"].as_f64(), m["tx_bytes"].as_f64(), m["rx_pkts"].as_f64()), (Some(10.0 + 10.0 + 360.0), Some(3800.0), Some(0.0)));
        // Rolled up: each covers its five minutes, the first and last clipped to the window.
        let rows = [row("a", 900, 1.0), row("a", 1200, 2.0), row("a", 1500, 4.0)];
        let (ts, types) = mcast_types(&rows, 1000, 1600, 300, 300);
        assert_eq!(ts, [1200, 1500]);
        assert_eq!((types["mdns"]["tx_pps"].clone(), types["mdns"]["tx_pkts"].as_f64()), (json!([2.0, 4.0]), Some(200.0 + 600.0 + 400.0)));
    }

    #[test]
    fn wlan_settings_from_an_import() {
        let state = json!({
            "wlanconf": [{ "name": "Home", "security": "wpapsk", "wpa_mode": "wpa2", "wpa3_support": true, "wpa3_transition": true,
                "networkconf_id": "abc", "hide_ssid": false, "vlan_enabled": false, "fast_roaming_enabled": true, "wlan_bands": ["5g"] },
                { "name": "Guest", "security": "open", "is_guest": true, "vlan_enabled": true, "vlan": "20" }],
            "networkconf": [{ "_id": { "$oid": "abc" }, "name": "LAN" }],
        });
        let h = wlan_settings(Some(&state), "Home");
        assert_eq!((h["security"].as_str(), h["network"].as_str(), h["vlan"].is_null(), h["fast_roaming"].as_bool()), (Some("WPA2/WPA3 Personal"), Some("LAN"), true, Some(true)));
        let g = wlan_settings(Some(&state), "Guest");
        assert_eq!((g["security"].as_str(), g["guest"].as_bool(), g["vlan"].as_str()), (Some("Open"), Some(true), Some("20")));
        assert!(wlan_settings(Some(&state), "Other").is_null());
    }

    /// The views' output on a synthetic site, pinned so that reworking how they
    /// are computed cannot change what they show. Run with `APCTL_WRITE_PIN=1`
    /// to write the expected output again (after a deliberate change).
    mod pin {
        use super::*;
        use crate::engine::{ClientView, DeviceView, SharedLive};

        const A1: &str = "02:00:00:00:00:a1";
        const A2: &str = "02:00:00:00:00:a2";
        /// (BSSID, AP, network, band)
        const BSS: [(&str, &str, &str, &str); 5] = [
            ("02:00:00:00:01:01", A1, "Home", "ng"),
            ("02:00:00:00:01:02", A1, "Home", "na"),
            ("02:00:00:00:01:03", A1, "IoT", "na"),
            ("02:00:00:00:02:01", A2, "Home", "ng"),
            ("02:00:00:00:02:02", A2, "Home", "na"),
        ];
        const C1: &str = "02:00:00:00:10:01";
        const C2: &str = "02:00:00:00:10:02";
        const C3: &str = "02:00:00:00:10:03";

        /// A small deterministic generator, so the site is the same every run.
        struct Rng(u64);

        impl Rng {
            fn next(&mut self, below: i64) -> i64 {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                ((self.0 >> 33) % below as u64) as i64
            }
        }

        fn insert(c: &Connection, table: &str, cols: &[&str], rows: Vec<Vec<Sql>>) {
            let sql = format!("INSERT INTO {table} ({}) VALUES ({})", cols.join(", "), vec!["?"; cols.len()].join(", "));
            for r in rows {
                c.execute(&sql, params_from_iter(r)).unwrap();
            }
        }

        fn int(v: i64) -> Sql {
            Sql::Integer(v)
        }

        fn text(v: &str) -> Sql {
            Sql::Text(v.into())
        }

        /// The site: two APs reporting for a little over an hour before `base + 3600`.
        fn site() -> (AppState, Ts, TestDir) {
            let now = clock::now_ts();
            let base = now - now % 3600 - 3600;
            let dir = TestDir::new("insights-pin");
            let (store, writer) = store::Store::open(&dir).unwrap();
            let m = Connection::open(dir.join("metrics.db")).unwrap();
            let mut rng = Rng(7);
            // Per SSID: cumulative counters, a restart (the second), rows without attempt
            // counters (the third), unreported scores and signals (the fourth), a missing
            // report (the fifth).
            const VAP_COLS: &[&str] = &[
                "bssid", "ts", "ap_mac", "essid", "radio", "num_sta", "satisfaction", "avg_client_signal", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                "tx_retries", "tx_dropped", "tx_mcast", "rx_mcast", "wifi_tx_attempts", "wifi_tx_dropped", "tx_bcast", "rx_bcast",
            ];
            let mut rows = Vec::new();
            for (i, (bssid, ap, essid, radio)) in BSS.iter().enumerate() {
                let mut cum = [0i64; 12];
                for k in 0..13i64 {
                    if i == 4 && k == 5 {
                        continue;
                    }
                    if i == 1 && k == 6 {
                        cum = [0; 12];
                    }
                    let scale = [900_000, 3_000_000, 4000, 6000, 900, 20, 300, 400, 5000, 30, 200, 300];
                    for (c, s) in cum.iter_mut().zip(scale) {
                        *c += rng.next(s);
                    }
                    let ts = base - 50 + k * 300 + (i as i64 * 17) % 40;
                    let satisfaction = if i == 3 && k % 2 == 0 { -1 } else { 50 + rng.next(50) };
                    let signal = if i == 3 && k % 3 == 0 { 0 } else { -40 - rng.next(40) };
                    let attempts = |v: i64| if i == 2 && k < 4 { Sql::Null } else { int(v) };
                    let mut r = vec![text(bssid), int(ts), text(ap), text(essid), text(radio), int(rng.next(10)), int(satisfaction), int(signal)];
                    r.extend(cum[..8].iter().map(|v| int(*v)));
                    r.extend([attempts(cum[8] * 3), attempts(cum[9]), int(cum[10]), int(cum[11])]);
                    rows.push(r);
                }
            }
            insert(&m, "vap_stats", VAP_COLS, rows);
            const RADIO_COLS: &[&str] = &["mac", "radio", "ts", "channel", "bw", "cu_total", "cu_self_rx", "cu_self_tx", "cu_interf", "num_sta", "tx_packets", "tx_retries"];
            let mut rows = Vec::new();
            for (j, (ap, radio)) in [(A1, "ng"), (A1, "na"), (A2, "ng"), (A2, "na")].into_iter().enumerate() {
                let (mut pk, mut re) = (0, 0);
                for k in 0..13i64 {
                    pk += rng.next(5000);
                    re += rng.next(500);
                    let (rx, tx) = (rng.next(20), rng.next(20));
                    rows.push(vec![
                        text(ap), text(radio), int(base - 40 + k * 300 + j as i64 * 7), int(if radio == "ng" { 6 } else { 44 }), int(if radio == "ng" { 20 } else { 80 }),
                        int(rx + tx + rng.next(40)), int(rx), int(tx), int(rng.next(30)), int(rng.next(8)), int(pk), int(re),
                    ]);
                }
            }
            insert(&m, "radio_stats", RADIO_COLS, rows);
            // Clients: one moves from the first AP to the second half way (its counters restart).
            const CLIENT_COLS: &[&str] = &[
                "mac", "ts", "ap_mac", "bssid", "essid", "radio", "signal", "tx_bytes", "rx_bytes", "mcast_tx_pkts", "mcast_rx_pkts", "mcast_tx_bytes", "mcast_rx_bytes",
            ];
            let mut rows = Vec::new();
            for (j, mac) in [C1, C2, C3].into_iter().enumerate() {
                let mut cum = [0i64; 6];
                for k in 0..13i64 {
                    let at = match (j, k) {
                        (0, k) if k < 7 => 0,
                        (0, 7) => {
                            cum = [0; 6];
                            4
                        }
                        (0, _) => 4,
                        (1, _) => 1,
                        _ => 3,
                    };
                    for (c, s) in cum.iter_mut().zip([2_000_000, 500_000, 40, 30, 4000, 3000]) {
                        *c += rng.next(s);
                    }
                    let (bssid, ap, essid, radio) = BSS[at];
                    let signal = if j == 2 && k % 4 == 0 { Sql::Null } else { int(-50 - rng.next(30)) };
                    let mcast = |v: i64| if j == 0 { Sql::Null } else { int(v) };
                    rows.push(vec![
                        text(mac), int(base - 30 + k * 300 + j as i64 * 11), text(ap), text(bssid), text(essid), text(radio), signal, int(cum[0]), int(cum[1]),
                        mcast(cum[2]), mcast(cum[3]), mcast(cum[4]), mcast(cum[5]),
                    ]);
                }
            }
            insert(&m, "client_stats", CLIENT_COLS, rows);
            // Multicast rates per AP and type; the second AP misses a report.
            let mut rows = Vec::new();
            for (j, ap) in [A1, A2].into_iter().enumerate() {
                for kind in ["mdns", "ssdp"] {
                    for k in (0..13i64).filter(|k| j == 0 || *k != 4) {
                        let mut r = vec![text(ap), text(kind), int(base - 20 + k * 300 + j as i64 * 13)];
                        r.extend((0..5).map(|_| Sql::Real(rng.next(500) as f64 / 10.0)));
                        rows.push(r);
                    }
                }
            }
            insert(&m, "mcast_stats", &["mac", "type", "ts", "tx_pps", "rx_pps", "tx_bytes_ps", "rx_bytes_ps", "clients"], rows);
            let c = Connection::open(dir.join("config.db")).unwrap();
            let spectrum = [(A1, "na", 36, 80, 30, 20), (A1, "na", 52, 80, 5, 2), (A1, "ng", 1, 20, 50, 40), (A1, "ng", 6, 20, 20, 10), (A2, "na", 36, 80, 40, 10), (A2, "ng", 11, 20, 60, 30)];
            let rows = spectrum.iter().map(|(ap, r, ch, w, u, i)| vec![text(ap), text(r), int(*ch), int(*w), int(*u), int(*i), int(2), int(base + 100)]).collect();
            insert(&c, "spectrum", &["ap_mac", "radio", "channel", "width", "utilization", "interference", "other_bss_count", "ts"], rows);
            let heard = [
                (BSS[4].0, A1, "na", "Home", 44, 80, 5210, -60),
                (BSS[0].0, A2, "ng", "Home", 6, 20, 2437, -65),
                (BSS[3].0, A1, "ng", "Home", 1, 20, 2412, -70),
                ("02:aa:00:00:00:01", A1, "ng", "Neighbour", 6, 20, 2437, -55),
                ("02:aa:00:00:00:02", A2, "na", "Other", 36, 40, 5190, -70),
                ("02:aa:00:00:00:03", A1, "na", "Far", 149, 80, 5775, -80),
            ];
            let rows = heard
                .iter()
                .map(|(b, ap, r, e, ch, bw, cf, sig)| vec![text(b), text(ap), text(r), text(e), int(*ch), int(*bw), int(*cf), text("WPA2-Personal"), int(*sig), int(*sig), int(base - 86400), int(base + 3000)])
                .collect();
            insert(&c, "neighbors", &["bssid", "ap_mac", "radio", "essid", "channel", "bw", "center_freq", "security", "signal", "best_signal", "first_seen", "last_seen"], rows);

            // What the APs report now.
            let live: SharedLive = Default::default();
            {
                let mut l = live.write().unwrap();
                for (ap, name, ch_ng, ch_na) in [(A1, "Hall", 6, 44), (A2, "Attic", 1, 36)] {
                    let vaps: Vec<Value> = BSS
                        .iter()
                        .filter(|b| b.1 == ap)
                        .map(|(bssid, _, essid, radio)| {
                            let sta: Vec<Value> = match *bssid {
                                b if b == BSS[0].0 => vec![json!({ "mac": C1, "signal": -61 })],
                                b if b == BSS[1].0 => vec![json!({ "mac": C2, "signal": -55 })],
                                b if b == BSS[3].0 => vec![json!({ "mac": C3, "signal": -70 })],
                                _ => vec![],
                            };
                            let ch = if *radio == "ng" { ch_ng } else { ch_na };
                            json!({ "bssid": bssid, "essid": essid, "radio": radio, "channel": ch, "bw": if *radio == "ng" { 20 } else { 80 }, "tx_power": 20,
                                "num_sta": sta.len(), "satisfaction": 90, "usage": "user", "sta_table": sta })
                        })
                        .collect();
                    let radios = json!([
                        { "radio": "ng", "name": "wifi0", "athstats": { "cu_total": 30, "cu_interf": 10, "cu_self_rx": 5, "cu_self_tx": 5, "noise_floor": -95 } },
                        { "radio": "na", "name": "wifi1", "athstats": { "cu_total": 20, "cu_interf": 5, "cu_self_rx": 5, "cu_self_tx": 5, "noise_floor": -96 } },
                    ]);
                    let p = json!({ "mac": ap, "hostname": name, "radio_table": radios, "vap_table": vaps });
                    let snapshot = crate::model::parse(base, &p).unwrap();
                    let mac: inform::Mac = ap.parse().unwrap();
                    for c in &snapshot.clients {
                        l.clients.insert(c.mac, ClientView { sample: c.clone(), connected: true, first_seen: 0, last_seen: base });
                    }
                    let d = DeviceView {
                        snapshot, online: true, first_seen: 0, last_seen: base, peer: "x".into(), interval: 10,
                        last_full_inform: base, last_config_push: None,
                    };
                    l.devices.insert(mac, d);
                    let mut raw = p.clone();
                    raw["radio_table"][1]["spectrum_table"] = json!([{ "channel": 36, "width": 80 }, { "channel": 52, "width": 80 }, { "channel": 100, "width": 80 }]);
                    l.raw_informs.insert(mac, std::sync::Arc::new(raw));
                }
                l.state = Some(std::sync::Arc::new(json!({
                    "devices": [{ "mac": A1, "site_id": "s1" }, { "mac": A2, "site_id": "s1" }],
                    "wlanconf": [{ "name": "Home", "security": "wpapsk", "wpa_mode": "wpa2", "networkconf_id": "n1", "site_id": "s1" }],
                    "networkconf": [{ "_id": "n1", "name": "LAN", "site_id": "s1" }],
                })));
            }
            let auth = std::sync::Arc::new(crate::auth::Auth::new(Default::default(), &store, writer.clone(), Default::default()).unwrap());
            let (engine, _) = tokio::sync::mpsc::channel(1);
            let (tx, _) = tokio::sync::broadcast::channel(1);
            let s = AppState::new(crate::api::AppStateInner {
                backups: crate::backup::Backups::new(dir.to_path_buf(), None),
                store, vendors: Default::default(), renderer: crate::dryrun::apcfg_renderer("10.6.106".into()), auth, engine, live, tx, started: 0, source: "none".into(),
                active: false, writer, inform_url: None, memo: Default::default(), threat_acks: Default::default(),
            });
            (s, base, dir)
        }

        /// Times as offsets from `base`, so the output does not depend on the day.
        fn rebase(v: &mut Value, base: Ts) {
            match v {
                Value::Object(m) => {
                    for (k, x) in m.iter_mut() {
                        match (k.as_str(), &mut *x) {
                            ("ts", Value::Number(n)) => *x = json!(n.as_i64().unwrap() - base),
                            ("ts", Value::Array(a)) => a.iter_mut().for_each(|t| *t = json!(t.as_i64().unwrap() - base)),
                            _ => rebase(x, base),
                        }
                    }
                }
                Value::Array(a) => a.iter_mut().for_each(|x| rebase(x, base)),
                _ => {}
            }
        }

        /// Equal, numbers to within rounding (sums may be added up in another order).
        fn same(a: &Value, b: &Value, at: &str) -> Result<(), String> {
            match (a, b) {
                (Value::Number(x), Value::Number(y)) => {
                    let (x, y) = (x.as_f64().unwrap(), y.as_f64().unwrap());
                    if (x - y).abs() <= 1e-9 * x.abs().max(y.abs()).max(1.0) { Ok(()) } else { Err(format!("{at}: {x} != {y}")) }
                }
                (Value::Array(x), Value::Array(y)) if x.len() == y.len() => x.iter().zip(y).enumerate().try_for_each(|(i, (x, y))| same(x, y, &format!("{at}[{i}]"))),
                (Value::Object(x), Value::Object(y)) if x.len() == y.len() => {
                    x.iter().try_for_each(|(k, v)| y.get(k).ok_or_else(|| format!("{at}.{k} missing")).and_then(|w| same(v, w, &format!("{at}.{k}"))))
                }
                _ if a == b => Ok(()),
                _ => Err(format!("{at}: {a} != {b}")),
            }
        }

        fn ok<T>(r: Result<Json<T>, ApiError>) -> T {
            r.unwrap_or_else(|e| panic!("{}", e.1)).0
        }

        async fn outputs() -> Value {
            let (s, base, _dir) = site();
            let q = |band: Option<&str>, mac: Option<&str>| Query(RangeQuery { range: None, from: Some(base), to: Some(base + 3600), band: band.map(Into::into), mac: mac.map(Into::into) });
            let plan = |band: &str, dfs: bool| Query(PlanQuery { band: Some(band.into()), dfs: Some(dfs) });
            let st = || State(s.clone());
            let mut out = json!({
                "activity": ok(activity(st(), q(None, None)).await),
                "activity_na": ok(activity(st(), q(Some("na"), None)).await),
                "activity_a1": ok(activity(st(), q(None, Some(A1))).await),
                "top": ok(top(st(), q(None, None)).await),
                "top_a2": ok(top(st(), q(None, Some(A2))).await),
                "density": ok(density(st(), q(None, None)).await),
                "retries": ok(retries(st(), q(None, None)).await),
                "multicast": ok(multicast(st(), q(None, None)).await),
                "multicast_a2": ok(multicast(st(), q(None, Some(A2))).await),
                "wlans": ok(wlans(st(), q(None, None)).await),
                "radios": ok(radios(st(), q(None, None)).await),
                "plan_ng": json!(ok(channel_plan(st(), plan("ng", false)).await)),
                "plan_na": json!(ok(channel_plan(st(), plan("na", true)).await)),
            });
            rebase(&mut out, base);
            out
        }

        #[tokio::test]
        async fn views_are_unchanged() {
            let out = outputs().await;
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/testdata/insights-pin.json");
            if std::env::var_os("APCTL_WRITE_PIN").is_some() {
                std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
                std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
                return;
            }
            let expected: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            for (k, v) in expected.as_object().unwrap() {
                if let Err(e) = same(&out[k], v, k) {
                    panic!("{e}");
                }
            }
            assert_eq!(out.as_object().unwrap().len(), expected.as_object().unwrap().len());
        }

        #[tokio::test]
        async fn a_repeated_query_is_answered_from_memory() {
            let (s, base, dir) = site();
            let q = |range| Query(RangeQuery { range, from: Some(base), to: Some(base + 3600), band: None, mac: None });
            let first = ok(retries(State(s.clone()), q(None)).await);
            Connection::open(dir.join("metrics.db")).unwrap().execute("DELETE FROM vap_stats", []).unwrap();
            assert_eq!(ok(retries(State(s.clone()), q(None)).await), first, "read again within the time it is kept");
            assert_eq!(ok(retries(State(s), q(Some(600))).await), json!([]), "another query reads the database");
        }

        #[tokio::test]
        async fn a_query_asked_again_while_it_is_read_is_read_once() {
            let (s, base, _dir) = site();
            static READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let q = RangeQuery { range: None, from: Some(base), to: Some(base + 3600), band: None, mac: None };
            let one = || {
                memo_read(&s, Db::Metrics, "read-once", &q, 0, |_| {
                    READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    Ok(7)
                })
            };
            let (a, b, c) = tokio::join!(one(), one(), one());
            assert_eq!((*a.ok().unwrap(), *b.ok().unwrap(), *c.ok().unwrap()), (7, 7, 7));
            assert_eq!(READS.load(std::sync::atomic::Ordering::Relaxed), 1);
        }

        #[tokio::test]
        async fn our_aps_hearing_each_other_are_listed_once_per_band() {
            let (s, base, dir) = site();
            // A2 hears both of A1's 5 GHz SSIDs.
            let c = Connection::open(dir.join("config.db")).unwrap();
            let row = |bssid: &str, sig: i64| vec![text(bssid), text(A2), text("na"), text("x"), int(44), int(80), int(5210), int(sig), int(base - 60), int(base)];
            insert(&c, "neighbors", &["bssid", "ap_mac", "radio", "essid", "channel", "bw", "center_freq", "signal", "first_seen", "last_seen"], vec![row(BSS[1].0, -62), row(BSS[2].0, -58)]);
            let q = Query(NeighborQuery { band: None, range: Some(30 * 86400), links_only: false, neighbors_only: false });
            let out = ok(neighbors(State(s.clone()), q).await);
            let links: Vec<(&str, &str, &str, i64)> = out["own_links"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| (l["from"].as_str().unwrap(), l["to"].as_str().unwrap(), l["radio"].as_str().unwrap(), l["signal"].as_i64().unwrap()))
                .collect();
            assert_eq!(links, [(A1, A2, "na", -60), (A1, A2, "ng", -70), (A2, A1, "na", -58), (A2, A1, "ng", -65)]);
            let names: Vec<&str> = out["neighbors"].as_array().unwrap().iter().map(|n| n["essid"].as_str().unwrap()).collect();
            assert_eq!(names, ["Neighbour", "Other", "Far"], "strongest first");
            let q = Query(NeighborQuery { band: None, range: Some(30 * 86400), links_only: true, neighbors_only: false });
            let only = ok(neighbors(State(s.clone()), q).await);
            assert_eq!((only["neighbors"].as_array().unwrap().len(), &only["own_links"]), (0, &out["own_links"]));
            let q = Query(NeighborQuery { band: None, range: Some(30 * 86400), links_only: false, neighbors_only: true });
            let only = ok(neighbors(State(s), q).await);
            assert_eq!((&only["neighbors"], only["own_links"].as_array().unwrap().len()), (&out["neighbors"], 0));
        }

        #[tokio::test]
        async fn plans_leave_out_old_scans() {
            let (s, base, dir) = site();
            let before = json!(ok(channel_plan(State(s.clone()), Query(PlanQuery { band: Some("na".into()), dfs: Some(true) })).await));
            // A scan from long ago saying the channel the plan picks for A2 is full.
            let c = Connection::open(dir.join("config.db")).unwrap();
            let row = vec![text(A2), text("na"), int(52), int(80), int(100), int(100), int(9), int(base - 8 * 86400)];
            insert(&c, "spectrum", &["ap_mac", "radio", "channel", "width", "utilization", "interference", "other_bss_count", "ts"], vec![row]);
            let after = json!(ok(channel_plan(State(s), Query(PlanQuery { band: Some("na".into()), dfs: Some(true) })).await));
            assert_eq!(before, after);
        }

        #[tokio::test]
        async fn an_outdoor_ap_is_planned_onto_channels_it_may_use_outdoors() {
            let (s, _, _dir) = site();
            {
                let mut live = s.live.write().unwrap();
                let mut state = live.state.as_deref().unwrap().clone();
                state["setting"] = json!([{ "key": "country", "code": "276", "site_id": "s1" }]);
                state["devices"][1]["outdoor_mode_override"] = json!("on");
                state["devices"][1]["radio_table"] = json!([{ "radio": "na", "channel": 36, "ht": 80 }]);
                live.state = Some(std::sync::Arc::new(state));
            }
            // A2 sits on 36, which Germany allows indoors only; of what it lists (36, 52, 100) only 100 is left.
            let plan = ok(channel_plan(State(s), Query(PlanQuery { band: Some("na".into()), dfs: Some(true) })).await);
            let a2 = plan.plan.iter().find(|p| p.mac == A2).unwrap();
            assert_eq!((a2.current_channel, a2.suggested_channel, a2.not_allowed), (36, 100, true));
            let a1 = plan.plan.iter().find(|p| p.mac == A1).unwrap();
            assert!(!a1.not_allowed, "indoors, 36-48 is fine");
        }
    }
}
