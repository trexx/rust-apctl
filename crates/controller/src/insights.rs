//! Site-wide and RF views: activity, airtime, top APs and clients, retry
//! rates, connection success, the radio overview and neighbouring networks.

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::Json;
use axum::extract::{Query, State};
use rusqlite::Connection;
use rusqlite::params_from_iter;
use rusqlite::types::Value as Sql;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};
use crate::channelai::is_dfs;
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
    let now = store::now_ts();
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

pub async fn read<T: Send + 'static>(s: &AppState, db: Db, f: impl FnOnce(&Connection) -> anyhow::Result<T> + Send + 'static) -> Result<T, ApiError> {
    let store = s.store.clone();
    tokio::task::spawn_blocking(move || store.read(db, f)).await.map_err(|e| ApiError::internal(e.to_string()))?.map_err(ApiError::from)
}

/// Per-key series of counter values -> per-second rates between consecutive
/// samples. A counter that went down (restarted) counts nothing for that
/// interval, as in [`increases`] and in the official controller, which takes
/// the new value as its next baseline.
struct Rates {
    /// (ts, seconds since previous sample, per-field rate)
    points: Vec<(Ts, f64, Vec<Option<f64>>)>,
}

fn rates(samples: &[(Ts, Vec<Option<f64>>)]) -> Rates {
    let mut points = Vec::new();
    for w in samples.windows(2) {
        let ((pt, pv), (t, v)) = (&w[0], &w[1]);
        let dt = (t - pt) as f64;
        if dt <= 0.0 || dt > 3600.0 * 2.0 {
            continue; // a gap: no rate across it
        }
        let r = v.iter().zip(pv).map(|(c, p)| match (c, p) {
            (Some(c), Some(p)) => Some((c - p).max(0.0) / dt),
            _ => None,
        });
        points.push((*t, dt, r.collect()));
    }
    Rates { points }
}

/// Samples of one series: (ts, values in the requested column order).
pub(crate) type Samples = Vec<(Ts, Vec<Option<f64>>)>;
/// Per key: its text columns and its samples.
pub(crate) type Loaded = BTreeMap<String, (Vec<String>, Samples)>;

/// What to load from a metrics table.
pub(crate) struct Spec<'a> {
    pub table: &'a str,
    /// SQL expression for the series key.
    pub key: &'a str,
    /// Text columns returned with each key.
    pub extra: &'a [&'a str],
    /// Numeric columns.
    pub cols: &'a [&'a str],
}

/// Where a column is in a column list (a list the caller wrote, so a miss is a bug).
fn col(cols: &[&str], name: &str) -> usize {
    cols.iter().position(|c| *c == name).unwrap_or_else(|| panic!("{name} is not among the loaded columns"))
}

/// The samples with only the named columns, in that order.
fn pick(samples: &Samples, cols: &[&str], names: &[&str]) -> Samples {
    let at: Vec<usize> = names.iter().map(|n| col(cols, n)).collect();
    samples.iter().map(|(t, v)| (*t, at.iter().map(|i| v[*i]).collect())).collect()
}

/// An AP's name (its host name), if it is reporting.
pub(crate) fn ap_name(live: &Live, mac: &str) -> Option<String> {
    mac.parse().ok().and_then(|m| live.devices.get(&m)).and_then(|d| d.snapshot.ap.hostname.clone())
}

/// A client's name: the alias given in apctl, else the host name it reports.
fn client_name(live: &Live, mac: Option<inform::Mac>) -> Option<String> {
    let mac = mac?;
    live.aliases.get(&mac).and_then(|a| a.alias.clone()).or_else(|| live.clients.get(&mac).and_then(|c| c.sample.hostname.clone()))
}

/// Loads a metrics table's samples in range, grouped by key.
pub(crate) fn load(c: &Connection, spec: Spec, tier: usize, from: Ts, to: Ts) -> anyhow::Result<Loaded> {
    let Spec { table, key, extra, cols } = spec;
    let suffix = TIERS[tier].0;
    // One sample before the window so the first rate in range is known.
    let sql = format!(
        "SELECT {key}, ts, {}{}{} FROM {table}{suffix} WHERE ts >= ?1 - ?3 AND ts <= ?2 ORDER BY ts",
        extra.join(", "),
        if extra.is_empty() { "" } else { ", " },
        cols.join(", ")
    );
    let step = TIERS[tier].1.max(30) * 2;
    // In time order (the `ts` index, no sort); the map groups them per key.
    let mut stmt = c.prepare(&sql)?;
    let mut out: Loaded = BTreeMap::new();
    let mut rows = stmt.query(rusqlite::params![from, to, step])?;
    while let Some(r) = rows.next()? {
        let k: String = r.get(0)?;
        let ts: Ts = r.get(1)?;
        let ex: Vec<String> = (0..extra.len()).map(|i| r.get::<_, Option<String>>(2 + i).map(|v| v.unwrap_or_default())).collect::<rusqlite::Result<_>>()?;
        let vals: Vec<Option<f64>> = (0..cols.len()).map(|i| r.get::<_, Option<f64>>(2 + extra.len() + i)).collect::<rusqlite::Result<_>>()?;
        let e = out.entry(k).or_default();
        // The text columns of the latest sample.
        e.0 = ex;
        e.1.push((ts, vals));
    }
    Ok(out)
}

fn band_ok(band: &Option<String>, radio: &str) -> bool {
    band.as_deref().is_none_or(|b| b == "all" || b == radio)
}

/// GET /api/site/activity: Wi-Fi traffic, retries, clients and multicast,
/// plus airtime (channel use and interference), bucketed.
pub async fn activity(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let bucket = bucket_for(to - from, tier);
    let band = q.band.clone();
    let ap = q.mac.as_ref().map(|m| m.to_ascii_lowercase());
    let result = read(&s, Db::Metrics, move |c| {
        let ap_ok = |mac: &str| ap.as_deref().is_none_or(|a| a == mac);
        // VAP counters: bytes, packets, retries, multicast, drops; gauge: clients.
        const COLS: &[&str] = &[
            "tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_retries", "tx_mcast", "rx_mcast", "tx_dropped", "num_sta", "tx_bcast", "rx_bcast",
            "wifi_tx_attempts", "wifi_tx_dropped",
        ];
        let i = |name: &str| col(COLS, name);
        let [tx_bytes, rx_bytes, tx_packets, rx_packets, tx_mcast, rx_mcast, tx_bcast, rx_bcast, tx_dropped, num_sta] =
            ["tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_mcast", "rx_mcast", "tx_bcast", "rx_bcast", "tx_dropped", "num_sta"].map(i);
        let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["radio", "ap_mac"], cols: COLS }, tier, from, to)?;
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
        let mut per: BTreeMap<Ts, HashMap<String, Acc>> = BTreeMap::new();
        for (bssid, (ex, samples)) in &vaps {
            if !band_ok(&band, &ex[0]) || !ap_ok(&ex[1]) {
                continue;
            }
            // Rates of every column (the client count's is not used).
            let r = rates(samples);
            let inc: HashMap<Ts, Vec<Option<f64>>> = increases(&pick(samples, COLS, RETRY_COLS), from).into_iter().collect();
            let clients: HashMap<Ts, f64> = samples.iter().filter_map(|(t, v)| v[num_sta].map(|n| (*t, n))).collect();
            for (t, dt, v) in r.points.iter().filter(|p| p.0 >= from) {
                let b = t - t % bucket;
                let a = per.entry(b).or_default().entry(bssid.clone()).or_default();
                let g = |i: usize| v[i].unwrap_or(0.0);
                a.down += g(tx_bytes);
                a.up += g(rx_bytes);
                a.pkts += g(tx_packets);
                a.rx_pkts += g(rx_packets);
                // Multicast and broadcast, both directions.
                a.mcast += g(tx_mcast) + g(rx_mcast) + g(tx_bcast) + g(rx_bcast);
                a.dropped += g(tx_dropped);
                if let Some(d) = inc.get(t)
                    && let (Some(r), Some(at)) = (d[0], d[1])
                {
                    a.retries += r / dt;
                    a.attempts += at / dt;
                    a.wifi_dropped += d[2].unwrap_or(0.0) / dt;
                }
                a.clients += clients.get(t).copied().unwrap_or(0.0);
                a.n += 1.0;
            }
        }
        let mut ts = Vec::new();
        let (mut down, mut up, mut retry, mut clients, mut mcast) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let (mut tx_pps, mut rx_pps, mut dropped) = (Vec::new(), Vec::new(), Vec::new());
        for (b, m) in &per {
            ts.push(*b);
            // Average per VAP within the bucket, then sum across VAPs.
            let sum = |f: &dyn Fn(&Acc) -> f64| m.values().map(|a| f(a) / a.n.max(1.0)).sum::<f64>();
            let (d, u, p, r, mc, cl) = (sum(&|a| a.down), sum(&|a| a.up), sum(&|a| a.pkts), sum(&|a| a.retries), sum(&|a| a.mcast), sum(&|a| a.clients));
            let (rp, dr) = (sum(&|a| a.rx_pkts), sum(&|a| a.dropped));
            let (at, wd) = (sum(&|a| a.attempts), sum(&|a| a.wifi_dropped));
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
        let radios = load(c, Spec { table: "radio_stats", key: "mac || '/' || radio", extra: &["radio", "mac"], cols: &["cu_total", "cu_interf", "cu_self_rx", "cu_self_tx"] }, tier, from, to)?;
        let mut air: BTreeMap<Ts, Vec<[f64; 4]>> = BTreeMap::new();
        for (ex, samples) in radios.values() {
            if !band_ok(&band, &ex[0]) || !ap_ok(&ex[1]) {
                continue;
            }
            for (t, v) in samples.iter().filter(|p| p.0 >= from) {
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

/// Bytes moved per key over the window (sum of counter deltas).
fn totals(samples: &[(Ts, Vec<Option<f64>>)], from: Ts) -> (f64, f64) {
    let r = rates(samples);
    r.points.iter().filter(|p| p.0 >= from).fold((0.0, 0.0), |(d, u), (_, dt, v)| (d + v[0].unwrap_or(0.0) * dt, u + v[1].unwrap_or(0.0) * dt))
}

/// GET /api/site/top: APs and clients by traffic over the window.
pub async fn top(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let ap = q.mac.as_ref().map(|m| m.to_ascii_lowercase());
    let (aps, clients) = read(&s, Db::Metrics, move |c| {
        let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac"], cols: &["tx_bytes", "rx_bytes"] }, tier, from, to)?;
        let mut aps: HashMap<String, (f64, f64)> = HashMap::new();
        for (ex, samples) in vaps.values() {
            let (d, u) = totals(samples, from);
            let e = aps.entry(ex[0].clone()).or_default();
            e.0 += d;
            e.1 += u;
        }
        // Per client and AP, so a client's traffic counts towards the AP it was on.
        let cl = load(c, Spec { table: "client_stats", key: "mac || '/' || coalesce(ap_mac, '')", extra: &[], cols: &["tx_bytes", "rx_bytes"] }, tier, from, to)?;
        let mut per_client: HashMap<String, (f64, f64)> = HashMap::new();
        for (k, (_, s)) in &cl {
            let (mac, on) = k.split_once('/').unwrap_or((k, ""));
            if ap.as_deref().is_some_and(|a| a != on) {
                continue;
            }
            let (d, u) = totals(s, from);
            let e = per_client.entry(mac.to_string()).or_default();
            e.0 += d;
            e.1 += u;
        }
        let clients: Vec<(String, f64, f64)> = per_client.into_iter().map(|(m, (d, u))| (m, d, u)).collect();
        Ok((aps, clients))
    })
    .await?;
    let live = s.live.read().unwrap();
    // Most traffic first.
    let by_total = |a: &Value, b: &Value| {
        let t = |x: &Value| x["download_bytes"].as_f64().unwrap_or(0.0) + x["upload_bytes"].as_f64().unwrap_or(0.0);
        t(b).total_cmp(&t(a))
    };
    let mut ap_list: Vec<Value> = aps.into_iter().map(|(mac, (d, u))| json!({ "name": ap_name(&live, &mac), "mac": mac, "download_bytes": d, "upload_bytes": u })).collect();
    ap_list.sort_by(by_total);
    let mut cl_list: Vec<Value> = clients
        .into_iter()
        .filter(|(_, d, u)| d + u > 0.0)
        .map(|(mac, d, u)| {
            let m: Option<inform::Mac> = mac.parse().ok();
            let view = m.and_then(|m| live.clients.get(&m));
            json!({
                "mac": mac, "name": client_name(&live, m), "connected": view.is_some_and(|c| c.connected),
                "vendor": s.vendors.lookup_str(&mac), "download_bytes": d, "upload_bytes": u,
            })
        })
        .collect();
    cl_list.sort_by(by_total);
    cl_list.truncate(25);
    Ok(Json(json!({ "aps": ap_list, "clients": cl_list })))
}

/// Increases between consecutive samples, per field; a counter that went down
/// (restarted) contributes nothing, and nothing is counted across long gaps.
fn increases(samples: &[(Ts, Vec<Option<f64>>)], from: Ts) -> Vec<(Ts, Vec<Option<f64>>)> {
    samples
        .windows(2)
        .filter(|w| w[1].0 >= from && w[1].0 > w[0].0 && w[1].0 - w[0].0 <= 2 * 3600)
        .map(|w| (w[1].0, w[1].1.iter().zip(&w[0].1).map(|(c, p)| c.zip(*p).map(|(c, p)| (c - p).max(0.0))).collect()))
        .collect()
}

/// Retries, attempts and drops summed per (AP, band) from SSID counters.
/// Intervals without attempt counters (data from older versions) are skipped.
pub(crate) fn retry_totals(vaps: &Loaded, from: Ts) -> HashMap<(String, String), [f64; 3]> {
    let mut out: HashMap<(String, String), [f64; 3]> = HashMap::new();
    for (ex, samples) in vaps.values() {
        for (_, d) in increases(samples, from) {
            if let (Some(r), Some(a)) = (d[0], d[1]) {
                let e = out.entry((ex[0].clone(), ex[1].clone())).or_default();
                e[0] += r;
                e[1] += a;
                e[2] += d[2].unwrap_or(0.0);
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
pub(crate) const RETRY_COLS: &[&str] = &["tx_retries", "wifi_tx_attempts", "wifi_tx_dropped"];
/// Bytes both ways, in the order `totals` reads them.
const BYTE_COLS: &[&str] = &["tx_bytes", "rx_bytes"];
const DENSITY_COLS: &[&str] = &["tx_bytes", "rx_bytes", "tx_retries", "wifi_tx_attempts", "wifi_tx_dropped"];

/// GET /api/site/density: how well each AP's weakest clients hear it. Per
/// report, the average signal of the weaker half of an AP's clients (per
/// band and overall), averaged over the window.
pub async fn density(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let suffix = TIERS[tier].0;
    let (signals, vaps) = read(&s, Db::Metrics, move |c| {
        let mut stmt = c.prepare(&format!("SELECT ts, ap_mac, radio, signal FROM client_stats{suffix} WHERE ts >= ?1 AND ts <= ?2 AND signal < 0 AND ap_mac IS NOT NULL"))?;
        let rows = stmt
            .query_map([from, to], |r| Ok((r.get::<_, Ts>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, f64>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let v = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: DENSITY_COLS }, tier, from, to)?;
        Ok((rows, v))
    })
    .await?;
    // (ap, band) -> per report time -> client signals
    let mut per: BTreeMap<(String, String), BTreeMap<Ts, Vec<f64>>> = BTreeMap::new();
    for (ts, ap, radio, sig) in signals {
        per.entry((ap.clone(), "all".into())).or_default().entry(ts).or_default().push(sig);
        if let Some(r) = radio {
            per.entry((ap, r)).or_default().entry(ts).or_default().push(sig);
        }
    }
    // Traffic share per band among APs, and retries.
    let mut bytes: HashMap<(String, String), f64> = HashMap::new();
    for (ex, samples) in vaps.values() {
        let (d, u) = totals(&pick(samples, DENSITY_COLS, BYTE_COLS), from);
        for band in ["all", ex[1].as_str()] {
            *bytes.entry((ex[0].clone(), band.to_string())).or_default() += d + u;
        }
    }
    let retries = {
        let only: Loaded = vaps.iter().map(|(k, (ex, smp))| (k.clone(), (ex.clone(), pick(smp, DENSITY_COLS, RETRY_COLS)))).collect();
        let mut r = retry_totals(&only, from);
        let all: Vec<((String, String), [f64; 3])> = r.iter().map(|(k, v)| (k.clone(), *v)).collect();
        for ((ap, _), v) in all {
            let e = r.entry((ap, "all".into())).or_default();
            for i in 0..3 {
                e[i] += v[i];
            }
        }
        r
    };
    let mut band_total: HashMap<String, f64> = HashMap::new();
    for ((_, b), v) in &bytes {
        *band_total.entry(b.clone()).or_default() += v;
    }
    let live = s.live.read().unwrap();
    let mut aps: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for ((ap, band), reports) in &per {
        let weakest: Vec<f64> = reports
            .values()
            .map(|sigs| {
                let mut v = sigs.clone();
                v.sort_by(f64::total_cmp);
                let n = (v.len() / 2).max(1);
                v[..n].iter().sum::<f64>() / n as f64
            })
            .collect();
        let all: Vec<f64> = reports.values().flatten().copied().collect();
        let clients = reports.values().map(Vec::len).sum::<usize>() as f64 / reports.len().max(1) as f64;
        let traffic = bytes.get(&(ap.clone(), band.clone())).copied().unwrap_or(0.0);
        let total = band_total.get(band).copied().unwrap_or(0.0);
        aps.entry(ap.clone()).or_default().push(json!({
            "band": band,
            "weakest_signal": (weakest.iter().sum::<f64>() / weakest.len().max(1) as f64).round(),
            "signal_avg": (all.iter().sum::<f64>() / all.len().max(1) as f64).round(),
            "clients": (clients * 10.0).round() / 10.0,
            "traffic_pct": if total > 0.0 { 100.0 * traffic / total } else { 0.0 },
            "tx_retry_pct": retries.get(&(ap.clone(), band.clone())).map(|r| retry_pct(*r)),
        }));
    }
    let list: Vec<Value> = aps.into_iter().map(|(mac, groups)| json!({ "name": ap_name(&live, &mac), "mac": mac, "bands": groups })).collect();
    Ok(Json(json!({ "aps": list })))
}

/// GET /api/site/retries: each AP radio's TX retry rate over the window.
pub async fn retries(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let vaps = read(&s, Db::Metrics, move |c| load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: RETRY_COLS }, tier, from, to)).await?;
    let totals = retry_totals(&vaps, from);
    let live = s.live.read().unwrap();
    let mut out: Vec<Value> = totals
        .into_iter()
        .map(|((ap, band), t)| {
            json!({ "name": ap_name(&live, &ap), "mac": ap, "radio": band, "tx_retry_pct": retry_pct(t), "retries": t[0], "attempts": t[1], "dropped": t[2] })
        })
        .collect();
    out.sort_by(|a, b| a["mac"].as_str().cmp(&b["mac"].as_str()).then(a["radio"].as_str().cmp(&b["radio"].as_str())));
    Ok(Json(Value::Array(out)))
}

/// GET /api/site/multicast: multicast and broadcast by traffic type over time
/// (all APs, or one with `mac`), and the clients by multicast traffic. `tx` is
/// what the APs delivered to clients, `rx` what clients sent.
pub async fn multicast(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let bucket = bucket_for(to - from, tier);
    let ap = q.mac.as_ref().map(|m| m.to_ascii_lowercase());
    let ap2 = ap.clone();
    let (samples, clients) = read(&s, Db::Metrics, move |c| {
        let suffix = TIERS[tier].0;
        let mut stmt = c.prepare(&format!("SELECT mac, type, ts, tx_pps, rx_pps, tx_bytes_ps, rx_bytes_ps FROM mcast_stats{suffix} WHERE ts >= ?1 AND ts <= ?2"))?;
        let rows = stmt
            .query_map([from, to], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Ts>(2)?, [0, 1, 2, 3].map(|i| r.get::<_, Option<f64>>(3 + i).ok().flatten().unwrap_or(0.0))))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let cl = load(
            c,
            // Per client, AP and network: counters restart when a client moves.
            Spec {
                table: "client_stats",
                key: "mac || '/' || coalesce(ap_mac, '') || '/' || coalesce(bssid, '')",
                extra: &[],
                cols: &["mcast_tx_pkts", "mcast_rx_pkts", "mcast_tx_bytes", "mcast_rx_bytes"],
            },
            tier,
            from,
            to,
        )?;
        let mut per: HashMap<String, [f64; 4]> = HashMap::new();
        for (k, (_, smp)) in &cl {
            let mut parts = k.split('/');
            let (mac, on) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
            if ap2.as_deref().is_some_and(|a| a != on) {
                continue;
            }
            let e = per.entry(mac.to_string()).or_default();
            for (_, d) in increases(smp, from) {
                for (a, b) in e.iter_mut().zip(&d) {
                    *a += b.unwrap_or(0.0);
                }
            }
        }
        Ok((rows, per))
    })
    .await?;
    // type -> bucket -> AP -> (sum of rates, samples)
    type PerAp = HashMap<String, ([f64; 4], f64)>;
    let mut acc: BTreeMap<String, BTreeMap<Ts, PerAp>> = BTreeMap::new();
    for (mac, kind, ts, r) in samples {
        if ap.as_deref().is_some_and(|a| a != mac) || ts < from {
            continue;
        }
        let e = acc.entry(kind).or_default().entry(ts - ts % bucket).or_default().entry(mac).or_default();
        for (a, b) in e.0.iter_mut().zip(r) {
            *a += b;
        }
        e.1 += 1.0;
    }
    let ts: Vec<Ts> = acc.values().flat_map(|b| b.keys().copied()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    let mut types = serde_json::Map::new();
    for (kind, buckets) in &acc {
        let mut series = [Vec::new(), Vec::new()];
        let mut total = [0.0f64; 4];
        for t in &ts {
            // Average per AP within the bucket, summed over APs.
            let sum = |i: usize| buckets.get(t).map_or(0.0, |aps| aps.values().map(|(r, n)| r[i] / n.max(1.0)).sum::<f64>());
            series[0].push(sum(0));
            series[1].push(sum(1));
            for (i, x) in total.iter_mut().enumerate() {
                *x += sum(i) * bucket as f64;
            }
        }
        types.insert(
            kind.clone(),
            json!({ "tx_pps": series[0], "rx_pps": series[1], "tx_pkts": total[0].round(), "rx_pkts": total[1].round(), "tx_bytes": total[2].round(), "rx_bytes": total[3].round() }),
        );
    }
    let live = s.live.read().unwrap();
    let mut list: Vec<Value> = clients
        .into_iter()
        .filter(|(_, t)| t[0] + t[1] > 0.0)
        .map(|(mac, t)| {
            let m: Option<inform::Mac> = mac.parse().ok();
            let view = m.and_then(|m| live.clients.get(&m));
            let mc = view.and_then(|v| v.sample.multicast.as_ref());
            let ap_name = view.and_then(|v| live.devices.get(&v.sample.ap_mac)).and_then(|d| d.snapshot.ap.hostname.clone());
            json!({
                "mac": mac, "name": client_name(&live, m), "vendor": s.vendors.lookup_str(&mac),
                "connected": view.is_some_and(|c| c.connected), "ap": ap_name, "radio": view.and_then(|c| c.sample.radio.clone()),
                "tx_pkts": t[0].round(), "rx_pkts": t[1].round(), "tx_bytes": t[2].round(), "rx_bytes": t[3].round(),
                "services": mc.map(|m| m.services.clone()).unwrap_or_default(),
                "delivery": mc.and_then(|m| m.delivery()),
                "memberships": mc.map_or(0, |m| m.memberships.len()),
            })
        })
        .collect();
    list.sort_by(|a, b| {
        let t = |x: &Value| x["tx_pkts"].as_f64().unwrap_or(0.0) + x["rx_pkts"].as_f64().unwrap_or(0.0);
        t(b).total_cmp(&t(a))
    });
    Ok(Json(json!({ "bucket": bucket, "ts": ts, "types": types, "clients": list })))
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
    const COLS: &[&str] = &[
        "tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_mcast", "rx_mcast", "tx_bcast", "rx_bcast", "tx_retries", "wifi_tx_attempts", "wifi_tx_dropped",
        "num_sta", "satisfaction", "avg_client_signal",
    ];
    let i = |name: &str| col(COLS, name);
    let [tx_bytes, rx_bytes, tx_packets, rx_packets, tx_mcast, rx_mcast, tx_bcast, rx_bcast, num_sta, satisfaction, signal] =
        ["tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_mcast", "rx_mcast", "tx_bcast", "rx_bcast", "num_sta", "satisfaction", "avg_client_signal"].map(i);
    let vaps = read(&s, Db::Metrics, move |c| load(c, Spec { table: "vap_stats", key: "bssid", extra: &["essid", "ap_mac", "radio"], cols: COLS }, tier, from, to)).await?;
    type Bucket = (f64, f64, f64, f64);
    struct Agg {
        down: f64,
        up: f64,
        pkts: f64,
        mcast: f64,
        sat: Vec<f64>,
        sig: Vec<f64>,
        // bucket -> bssid -> (clients sum, samples, down bytes/s, up bytes/s)
        series: BTreeMap<Ts, HashMap<String, Bucket>>,
        retry: Loaded,
    }
    let mut per: BTreeMap<String, Agg> = BTreeMap::new();
    for (bssid, (ex, samples)) in &vaps {
        let essid = ex[0].clone();
        if essid.is_empty() {
            continue;
        }
        let a = per.entry(essid.clone()).or_insert_with(|| Agg {
            down: 0.0,
            up: 0.0,
            pkts: 0.0,
            mcast: 0.0,
            sat: vec![],
            sig: vec![],
            series: BTreeMap::new(),
            retry: BTreeMap::new(),
        });
        // Rates of every column (only the traffic counters' are used).
        let r = rates(samples);
        for (t, dt, v) in r.points.iter().filter(|p| p.0 >= from) {
            let g = |i: usize| v[i].unwrap_or(0.0);
            a.down += g(tx_bytes) * dt;
            a.up += g(rx_bytes) * dt;
            a.pkts += (g(tx_packets) + g(rx_packets)) * dt;
            a.mcast += (g(tx_mcast) + g(rx_mcast) + g(tx_bcast) + g(rx_bcast)) * dt;
            let e = a.series.entry(t - t % bucket).or_default().entry(bssid.clone()).or_default();
            e.2 += g(tx_bytes);
            e.3 += g(rx_bytes);
        }
        for (t, v) in samples.iter().filter(|p| p.0 >= from) {
            let e = a.series.entry(t - t % bucket).or_default().entry(bssid.clone()).or_default();
            e.0 += v[num_sta].unwrap_or(0.0);
            e.1 += 1.0;
            if let Some(x) = v[satisfaction].filter(|x| *x >= 0.0) {
                a.sat.push(x);
            }
            if let Some(x) = v[signal].filter(|x| *x < -10.0) {
                a.sig.push(x);
            }
        }
        a.retry.insert(bssid.clone(), (vec![essid.clone(), "all".into()], pick(samples, COLS, RETRY_COLS)));
    }
    // How our own SSIDs are heard over the air (our APs scan each other).
    let own: Vec<Sql> = s.live.read().unwrap().devices.values().flat_map(|d| d.snapshot.vaps.iter().map(|v| Sql::Text(v.bssid.clone()))).collect();
    let on_air: HashMap<String, String> = if own.is_empty() {
        HashMap::new()
    } else {
        read(&s, Db::Config, move |c| {
            let marks = vec!["?"; own.len()].join(", ");
            let rows = c
                .prepare(&format!("SELECT bssid, security FROM neighbors WHERE security IS NOT NULL AND bssid IN ({marks}) ORDER BY last_seen"))?
                .query_map(params_from_iter(own), |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows.into_iter().collect())
        })
        .await?
    };
    let live = s.live.read().unwrap();
    let state = live.state.clone();
    // Now: per network, the APs and bands broadcasting it, clients and scores.
    // essid -> (where it is broadcast, bands, experience scores)
    type Now = (Vec<Value>, std::collections::BTreeSet<String>, Vec<f64>);
    let mut now: BTreeMap<String, Now> = BTreeMap::new();
    for (mac, d) in &live.devices {
        for v in &d.snapshot.vaps {
            let Some(e) = v.essid.clone().filter(|e| !e.is_empty()) else { continue };
            let n = now.entry(e).or_default();
            n.0.push(json!({ "ap": mac, "name": d.snapshot.ap.hostname, "radio": v.radio, "channel": v.channel, "bssid": v.bssid, "clients": v.num_sta, "online": d.online }));
            if let Some(r) = &v.radio {
                n.1.insert(r.clone());
            }
            if let Some(x) = v.satisfaction.filter(|x| *x >= 0 && v.num_sta.unwrap_or(0) > 0) {
                n.2.push(x as f64);
            }
        }
    }
    let connected: Vec<&crate::engine::ClientView> = live.clients.values().filter(|c| c.connected).collect();
    let mut names: std::collections::BTreeSet<String> = per.keys().cloned().collect();
    names.extend(now.keys().cloned());
    let mean = |v: &[f64]| (!v.is_empty()).then(|| (v.iter().sum::<f64>() / v.len() as f64).round());
    let list: Vec<Value> = names
        .into_iter()
        .map(|essid| {
            let (bss, bands, scores) = now.remove(&essid).unwrap_or_default();
            let clients = connected.iter().filter(|c| c.sample.essid.as_deref() == Some(essid.as_str())).map(|c| c.sample.mac).collect::<HashSet<_>>().len();
            let agg = per.get(&essid);
            let (ts, series_clients, down_bps, up_bps, peak) = agg.map_or((vec![], vec![], vec![], vec![], 0.0), |a| {
                let mut ts = vec![];
                let (mut cl, mut dn, mut up) = (vec![], vec![], vec![]);
                for (t, m) in &a.series {
                    ts.push(*t);
                    cl.push(m.values().map(|x| x.0 / x.1.max(1.0)).sum::<f64>());
                    dn.push(m.values().map(|x| x.2 / x.1.max(1.0)).sum::<f64>() * 8.0);
                    up.push(m.values().map(|x| x.3 / x.1.max(1.0)).sum::<f64>() * 8.0);
                }
                let peak = cl.iter().copied().fold(0.0, f64::max);
                (ts, cl, dn, up, peak)
            });
            let retry = agg
                .and_then(|a| retry_totals(&a.retry, from).into_values().reduce(|x, y| [x[0] + y[0], x[1] + y[1], x[2] + y[2]]))
                .filter(|t| t.iter().sum::<f64>() > 0.0)
                .map(retry_pct);
            let heard = bss.iter().find_map(|b| b["bssid"].as_str().and_then(|x| on_air.get(x)).cloned());
            json!({
                "essid": essid,
                "settings": wlan_settings(state.as_deref(), &essid),
                "security_on_air": heard,
                "broadcast": bss,
                "bands": bands,
                "ap_count": bss.iter().filter_map(|b| b["ap"].as_str()).collect::<HashSet<_>>().len(),
                "clients": clients,
                "peak_clients": peak.round().max(clients as f64),
                "satisfaction": mean(&scores),
                "satisfaction_avg": agg.and_then(|a| mean(&a.sat)),
                "signal_avg": agg.and_then(|a| mean(&a.sig)),
                "download_bytes": agg.map_or(0.0, |a| a.down), "upload_bytes": agg.map_or(0.0, |a| a.up),
                "tx_retry_pct": retry,
                "multicast_pct": agg.filter(|a| a.pkts > 0.0).map(|a| (100.0 * a.mcast / a.pkts).min(100.0)),
                "series": { "ts": ts, "clients": series_clients, "download_bps": down_bps, "upload_bps": up_bps },
            })
        })
        .collect();
    Ok(Json(json!({ "bucket": bucket, "wlans": list })))
}

/// What `radios` loads per VAP.
const RADIO_VAP_COLS: &[&str] = &["tx_bytes", "rx_bytes", "avg_client_signal", "tx_retries", "wifi_tx_attempts", "wifi_tx_dropped"];

/// GET /api/rf/radios: each AP radio with its settings now and its averages
/// over the window (interference, utilisation, traffic, retries, signal).
pub async fn radios(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let (rstats, vstats) = read(&s, Db::Metrics, move |c| {
        let r = load(c, Spec { table: "radio_stats", key: "mac || '/' || radio", extra: &[], cols: &["cu_total", "cu_interf"] }, tier, from, to)?;
        // Retries come from the VAPs: the radio-level counters stay at 0 on some models.
        let v = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: RADIO_VAP_COLS }, tier, from, to)?;
        Ok((r, v))
    })
    .await?;
    let spectrum_rows = read(&s, Db::Config, |c| {
        let mut stmt = c.prepare("SELECT ap_mac, radio, channel, width, utilization, interference, other_bss_count, ts FROM spectrum")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, json!({
                    "channel": r.get::<_, i64>(2)?, "width": r.get::<_, Option<i64>>(3)?, "utilization": r.get::<_, Option<i64>>(4)?,
                    "interference": r.get::<_, Option<i64>>(5)?, "other_bss_count": r.get::<_, Option<i64>>(6)?, "ts": r.get::<_, i64>(7)?,
                })))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    let retry: HashMap<(String, String), [f64; 3]> = {
        let only: Loaded = vstats.iter().map(|(k, (ex, smp))| (k.clone(), (ex.clone(), pick(smp, RADIO_VAP_COLS, RETRY_COLS)))).collect();
        retry_totals(&only, from)
    };
    // Traffic and client signal per (AP, band), and the spectrum rows, grouped once.
    let signal = col(RADIO_VAP_COLS, "avg_client_signal");
    let mut vap_use: HashMap<(&str, &str), (f64, Vec<f64>)> = HashMap::new();
    for (ex, samples) in vstats.values() {
        let e = vap_use.entry((ex[0].as_str(), ex[1].as_str())).or_default();
        let rr = rates(&pick(samples, RADIO_VAP_COLS, BYTE_COLS));
        for (_, dt, v) in rr.points.iter().filter(|x| x.0 >= from) {
            e.0 += (v[0].unwrap_or(0.0) + v[1].unwrap_or(0.0)) * dt;
        }
        // The AP reports 0 or -1 when no client is connected.
        e.1.extend(samples.iter().filter(|p| p.0 >= from).filter_map(|p| p.1[signal]).filter(|v| *v < -10.0));
    }
    let mut spectrum: HashMap<(&str, &str), Vec<&Value>> = HashMap::new();
    for (m, rd, v) in &spectrum_rows {
        spectrum.entry((m.as_str(), rd.as_str())).or_default().push(v);
    }
    let live = s.live.read().unwrap();
    let mut out = Vec::new();
    for (mac, d) in &live.devices {
        let mac_s = mac.to_string();
        for r in &d.snapshot.radios {
            let key = format!("{mac}/{}", r.radio);
            let (avg_cu, avg_interf) = match rstats.get(&key) {
                Some((_, samples)) => {
                    let inr: Vec<&(Ts, Vec<Option<f64>>)> = samples.iter().filter(|p| p.0 >= from).collect();
                    let avg = |i: usize| {
                        let v: Vec<f64> = inr.iter().filter_map(|p| p.1[i]).collect();
                        (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64)
                    };
                    (avg(0), avg(1))
                }
                None => (None, None),
            };
            let (usage, signals) = vap_use.get(&(mac_s.as_str(), r.radio.as_str())).map_or((0.0, &[][..]), |(u, s)| (*u, s.as_slice()));
            let retry_pct = retry.get(&(mac_s.clone(), r.radio.clone())).map(|t| retry_pct(*t));
            let spec = spectrum.get(&(mac_s.as_str(), r.radio.as_str())).cloned().unwrap_or_default();
            out.push(json!({
                "mac": mac, "name": d.snapshot.ap.hostname, "radio": r.radio, "channel": r.channel, "bw": r.bw,
                "tx_power": r.tx_power, "eirp": r.tx_power.zip(r.antenna_gain).map(|(p, g)| p + g),
                "min_txpower": r.min_txpower, "max_txpower": r.max_txpower,
                "clients": r.num_sta, "cu_total_now": r.cu_total, "noise_floor": r.noise_floor,
                "avg_utilization": avg_cu, "avg_interference": avg_interf, "tx_retry_pct": retry_pct,
                "usage_bytes": usage,
                "avg_client_signal": (!signals.is_empty()).then(|| signals.iter().sum::<f64>() / signals.len() as f64),
                "spectrum": spec,
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
}

/// GET /api/rf/neighbors: networks heard by our APs, the AP hearing each best,
/// and our own APs' signal to each other (AP density).
pub async fn neighbors(State(s): State<AppState>, Query(q): Query<NeighborQuery>) -> Result<Json<Value>, ApiError> {
    let since = store::now_ts() - q.range.unwrap_or(86400).clamp(600, 30 * 86400);
    let band = q.band.clone();
    let rows = read(&s, Db::Config, move |c| {
        let mut cond = "last_seen >= ?1".to_string();
        let mut params = vec![Sql::Integer(since)];
        if let Some(b) = band.filter(|b| b != "all") {
            params.push(Sql::Text(b));
            cond.push_str(" AND radio = ?2");
        }
        let sql = format!(
            "SELECT bssid, ap_mac, radio, essid, channel, bw, center_freq, security, signal, best_signal, is_unifi, ap_name, model, first_seen, last_seen FROM neighbors WHERE {cond}"
        );
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(params), |r| {
                Ok(json!({
                    "bssid": r.get::<_, String>(0)?, "ap_mac": r.get::<_, String>(1)?, "radio": r.get::<_, Option<String>>(2)?,
                    "essid": r.get::<_, Option<String>>(3)?, "channel": r.get::<_, Option<i64>>(4)?, "bw": r.get::<_, Option<i64>>(5)?,
                    "center_freq": r.get::<_, Option<i64>>(6)?, "security": r.get::<_, Option<String>>(7)?, "signal": r.get::<_, Option<i64>>(8)?,
                    "best_signal": r.get::<_, Option<i64>>(9)?, "is_unifi": r.get::<_, i64>(10)? != 0, "ap_name": r.get::<_, Option<String>>(11)?,
                    "model": r.get::<_, Option<String>>(12)?, "first_seen": r.get::<_, i64>(13)?, "last_seen": r.get::<_, i64>(14)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    let live = s.live.read().unwrap();
    // Our own BSSIDs, to tell our APs apart from the neighbours.
    let own: HashMap<String, (inform::Mac, Option<String>)> = live
        .devices
        .iter()
        .flat_map(|(m, d)| d.snapshot.vaps.iter().map(move |v| (v.bssid.to_ascii_lowercase(), (*m, v.radio.clone()))))
        .collect();
    let name_of = |m: &str| ap_name(&live, m);
    let mut by_bssid: BTreeMap<String, Value> = BTreeMap::new();
    let mut links = Vec::new();
    for r in rows {
        let bssid = r["bssid"].as_str().unwrap_or("").to_string();
        if let Some((owner, radio)) = own.get(&bssid) {
            // One of our APs heard another of ours.
            if owner.to_string() != r["ap_mac"].as_str().unwrap_or("") {
                links.push(json!({
                    "from": r["ap_mac"], "from_name": name_of(r["ap_mac"].as_str().unwrap_or("")),
                    "to": owner.to_string(), "to_name": name_of(&owner.to_string()), "radio": radio, "signal": r["signal"],
                }));
            }
            continue;
        }
        let better = by_bssid.get(&bssid).is_none_or(|cur| r["signal"].as_i64().unwrap_or(-200) > cur["signal"].as_i64().unwrap_or(-200));
        if better {
            let mut v = r.clone();
            v["nearest_ap"] = json!(name_of(r["ap_mac"].as_str().unwrap_or("")));
            v["vendor"] = json!(s.vendors.lookup_str(&bssid));
            by_bssid.insert(bssid, v);
        }
    }
    let mut list: Vec<Value> = by_bssid.into_values().collect();
    list.sort_by_key(|v| -v["signal"].as_i64().unwrap_or(-200));
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
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for c in chans {
        let b = block(radio, c, width);
        if !seen.iter().any(|s: &(f64, f64)| (s.0 - b.lo).abs() < 1.0) {
            seen.push((b.lo, b.hi));
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
    pub current_channel: Option<i64>,
    pub current_score: Option<f64>,
    pub current_reasons: Option<Vec<String>>,
    pub suggested_channel: Option<i64>,
    pub suggested_score: Option<f64>,
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
    current: Option<Block>,
    width: i64,
    clients: i64,
    /// Channel blocks the AP lists as available (its country and width).
    available: Option<Vec<i64>>,
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
    let since = store::now_ts() - 7 * 86400;
    let r2 = radio.clone();
    let (neigh, spectrum) = read(s, Db::Config, move |c| {
        let mut stmt = c.prepare("SELECT ap_mac, bssid, essid, center_freq, bw, signal FROM neighbors WHERE radio = ?1 AND last_seen >= ?2")?;
        let n = stmt
            .query_map(rusqlite::params![r2, since], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, Option<f64>>(4)?, r.get::<_, Option<f64>>(5)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut stmt = c.prepare("SELECT ap_mac, channel, width, interference, utilization FROM spectrum WHERE radio = ?1")?;
        let sp = stmt
            .query_map([r2], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, Option<f64>>(4)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((n, sp))
    })
    .await?;
    // What the plan needs from `live`, copied so the lock is not held while it is worked out.
    let (aps, own_bssids) = {
        let live = s.live.read().unwrap();
        let aps: Vec<PlanAp> = live
            .devices
            .iter()
            .filter_map(|(m, d)| {
                let r = d.snapshot.radios.iter().find(|r| r.radio == radio)?;
                let ch = r.channel?;
                let width = if radio == "ng" { 20 } else { r.bw.unwrap_or(80) };
                let available = live.raw_informs.get(m).and_then(|p| {
                    let rt = p["radio_table"].as_array()?.iter().find(|x| x["radio"].as_str() == Some(radio.as_str()))?;
                    let list: Vec<i64> = rt["spectrum_table"]
                        .as_array()?
                        .iter()
                        .filter(|c| radio == "ng" || c["width"].as_i64() == Some(width))
                        .filter_map(|c| c["channel"].as_i64())
                        .collect();
                    (!list.is_empty()).then_some(list)
                });
                Some(PlanAp { mac: m.to_string(), name: d.snapshot.ap.hostname.clone(), current: Some(block(&radio, ch, width)), width, clients: r.num_sta, available })
            })
            .collect();
        // Our APs' BSSIDs on this band, to separate own signal from neighbours.
        let own: HashMap<String, String> = live
            .devices
            .iter()
            .flat_map(|(m, d)| d.snapshot.vaps.iter().filter(|v| v.radio.as_deref() == Some(radio.as_str())).map(move |v| (v.bssid.to_ascii_lowercase(), m.to_string())))
            .collect();
        (aps, own)
    };
    let work = move || plan_channels(radio, dfs, allowed, pinned, aps, own_bssids, neigh, spectrum);
    tokio::task::spawn_blocking(work).await.map_err(|e| ApiError::internal(e.to_string()))
}

type NeighborRow = (String, String, Option<String>, Option<f64>, Option<f64>, Option<f64>);
type SpectrumRow = (String, i64, Option<i64>, Option<f64>, Option<f64>);

/// The greedy search behind [`compute_plan`], on data copied out of `live`.
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
    // AP-to-AP signal (strongest seen either way), and what each AP hears of the neighbours.
    let mut ap_signal: HashMap<(String, String), f64> = HashMap::new();
    let mut heard: HashMap<String, Vec<Heard>> = HashMap::new();
    for (heard_by, bssid, essid, cf, bw, sig) in neigh {
        match own_bssids.get(&bssid) {
            Some(owner) => {
                if let Some(sig) = sig {
                    for k in [(heard_by.clone(), owner.clone()), (owner.clone(), heard_by.clone())] {
                        let e = ap_signal.entry(k).or_insert(-200.0);
                        *e = e.max(sig);
                    }
                }
            }
            None => {
                let (Some(cf), Some(signal)) = (cf, sig) else { continue };
                let half = bw.unwrap_or(20.0) / 2.0;
                heard.entry(heard_by).or_default().push(Heard { essid, lo: cf - half, hi: cf + half, signal });
            }
        }
    }
    // Measured load per AP: the channel blocks and what each costs.
    let mut measured: HashMap<String, Vec<(Block, f64)>> = HashMap::new();
    for (m, ch, width, interference, util) in spectrum {
        let load = util.unwrap_or(0.0) * 0.5 + interference.map_or(0.0, |i| weight(i) * 0.5);
        measured.entry(m).or_default().push((block(&radio, ch, width.unwrap_or(20)), load));
    }
    let names: HashMap<&str, &str> = aps.iter().filter_map(|a| Some((a.mac.as_str(), a.name.as_deref()?))).collect();
    let no_neighbours = Vec::new();
    // What the AP would put up with on block `b`, the others placed as in `assigned`
    // (its own entry there is ignored), with (weight, reason) per contribution when `why`.
    let contributions = |ap: &PlanAp, b: &Block, assigned: &HashMap<String, Block>, mut why: Option<&mut Vec<(f64, String)>>| -> f64 {
        let mut total = 0.0;
        for n in heard.get(&ap.mac).unwrap_or(&no_neighbours) {
            if overlap(b, n.lo, n.hi) {
                let w = weight(n.signal);
                total += w;
                if let Some(why) = why.as_deref_mut() {
                    why.push((w, format!("{} ({:.0} dBm)", n.essid.as_deref().unwrap_or("hidden network"), n.signal)));
                }
            }
        }
        for (other, ob) in assigned {
            if other != &ap.mac && overlap(b, ob.lo, ob.hi) {
                let sig = ap_signal.get(&(ap.mac.clone(), other.clone())).copied().unwrap_or(-75.0);
                let w = 2.0 * weight(sig);
                total += w;
                if let Some(why) = why.as_deref_mut() {
                    why.push((w, format!("your AP {} ({sig:.0} dBm)", names.get(other.as_str()).copied().unwrap_or(other))));
                }
            }
        }
        for (sb, load) in measured.get(&ap.mac).into_iter().flatten() {
            if overlap(b, sb.lo, sb.hi) {
                total += load;
            }
        }
        total
    };
    let cost = |ap: &PlanAp, b: &Block, assigned: &HashMap<String, Block>| contributions(ap, b, assigned, None);
    // The cost with the four biggest reasons, for the plan shown.
    let explain = |ap: &PlanAp, b: &Block, assigned: &HashMap<String, Block>| -> (f64, Vec<String>) {
        let mut reasons = Vec::new();
        let total = contributions(ap, b, assigned, Some(&mut reasons));
        reasons.sort_by(|a, b| b.0.total_cmp(&a.0));
        (total, reasons.into_iter().take(4).map(|r| r.1).collect())
    };
    let cands = |ap: &PlanAp| match &allowed {
        Some(a) => allowed_blocks(&radio, ap.width, a),
        None => candidates(&radio, ap.width, dfs, ap.available.as_deref()),
    };
    let is_pinned = |ap: &PlanAp| pinned.contains(&ap.mac);
    // Greedy: busiest AP first, then a second pass with everyone placed.
    let mut order: Vec<&PlanAp> = aps.iter().filter(|a| !is_pinned(a)).collect();
    order.sort_by_key(|a| -a.clients);
    let current: HashMap<String, Block> = aps.iter().filter_map(|a| a.current.map(|c| (a.mac.clone(), c))).collect();
    let mut assigned = current.clone();
    for _ in 0..2 {
        for ap in &order {
            let best = cands(ap).into_iter().map(|b| (cost(ap, &b, &assigned), b)).min_by(|a, b| a.0.total_cmp(&b.0));
            if let Some((_, b)) = best {
                assigned.insert(ap.mac.clone(), b);
            }
        }
    }
    // Which APs move: on a channel no longer allowed, or clearly better off elsewhere.
    let mut evict: HashMap<String, bool> = HashMap::new();
    let mut fin = current.clone();
    for ap in &aps {
        let (Some(cur), Some(sug)) = (ap.current, assigned.get(&ap.mac).copied()) else { continue };
        if is_pinned(ap) || cur.primary == sug.primary {
            continue;
        }
        let ev = !cands(ap).iter().any(|b| (b.lo - cur.lo).abs() < 1.0 && (b.hi - cur.hi).abs() < 1.0);
        if ev || cost(ap, &sug, &assigned) + 5.0 < cost(ap, &cur, &assigned) * 0.8 {
            fin.insert(ap.mac.clone(), sug);
            evict.insert(ap.mac.clone(), ev);
        }
    }
    let total = |m: &HashMap<String, Block>| -> f64 { aps.iter().filter_map(|ap| m.get(&ap.mac).map(|b| cost(ap, b, m))).sum() };
    let (current_total, final_total) = (total(&current), total(&fin));
    let accepted = evict.values().any(|e| *e) || (!evict.is_empty() && final_total * 1.1 < current_total);
    if !accepted {
        fin = current.clone();
        evict.clear();
    }
    let plan: Vec<PlanEntry> = aps
        .iter()
        .map(|ap| {
            let cur = ap.current.map(|b| explain(ap, &b, &current));
            let change = evict.contains_key(&ap.mac);
            let sug = fin.get(&ap.mac).map(|b| (b.primary, explain(ap, b, &fin)));
            PlanEntry {
                mac: ap.mac.clone(),
                name: ap.name.clone(),
                width: ap.width,
                clients: ap.clients,
                current_channel: ap.current.map(|c| c.primary),
                current_score: cur.as_ref().map(|c| c.0.round()),
                current_reasons: cur.map(|c| c.1),
                suggested_channel: sug.as_ref().map(|s| s.0),
                suggested_score: sug.as_ref().map(|s| s.1.0.round()),
                suggested_reasons: if change { sug.map(|s| s.1.1).unwrap_or_default() } else { vec![] },
                change,
                pinned: is_pinned(ap),
                not_allowed: evict.get(&ap.mac).copied().unwrap_or(false),
            }
        })
        .collect();
    Plan { band: radio, dfs, allowed, plan, current_total: current_total.round(), suggested_total: final_total.round(), accepted }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let ap = |mac: &str, ch: i64, clients: i64| PlanAp { mac: mac.into(), name: Some(format!("AP {mac}")), current: Some(block("ng", ch, 20)), width: 20, clients, available: None };
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
        let ch: HashMap<&str, Option<i64>> = plan.plan.iter().map(|p| (p.mac.as_str(), p.suggested_channel)).collect();
        assert_ne!(ch["a"], ch["b"]);
        assert_ne!(ch["a"], Some(1), "a keeps off its neighbour");
        let a = plan.plan.iter().find(|p| p.mac == "a").unwrap();
        assert_eq!(a.current_reasons.as_deref(), Some(&["your AP AP b (-50 dBm)".to_string()][..]));
    }

    #[test]
    fn windows_are_clamped() {
        let q = |range, from, to| RangeQuery { range, from, to, band: None, mac: None };
        let now = store::now_ts();
        let (f, t, _) = window(&q(Some(3600), None, None));
        assert!(t - f == 3600 && t >= now);
        // An explicit window wins over `range`, and cannot end in the future.
        let (f, t, _) = window(&q(Some(3600), Some(now - 7200), Some(now + 999)));
        assert_eq!(t - f, 7200);
        assert!(t <= store::now_ts());
        // Too short a window is widened backwards to ten minutes.
        let (f, t, _) = window(&q(None, Some(now - 100), Some(now - 60)));
        assert_eq!((t, t - f), (now - 60, 600));
        // `to` alone: `range` back from it; extreme values neither overflow nor leave the bounds.
        let (f, t, _) = window(&q(Some(3600), None, Some(now - 7200)));
        assert_eq!((t, t - f), (now - 7200, 3600));
        let (f, t, _) = window(&q(None, Some(i64::MIN), Some(i64::MIN)));
        assert_eq!((f, t), (-400 * 86400, 0));
        let (f, t, _) = window(&q(Some(i64::MAX), Some(i64::MAX), Some(i64::MAX)));
        assert!(t <= store::now_ts() && t - f == 600);
        // A week ago reads the five-minute tier; a day 60 days back reads hourly.
        assert_eq!(window(&q(None, Some(now - 7 * 86400), Some(now - 6 * 86400))).2, 1);
        assert_eq!(window(&q(None, Some(now - 60 * 86400), Some(now - 59 * 86400))).2, 2);
    }

    #[test]
    fn retries_use_attempts_and_ignore_counter_restarts() {
        let s = |t, r, a, d| (t, vec![Some(r), Some(a), Some(d)]);
        let samples = vec![s(0, 100.0, 1000.0, 0.0), s(10, 130.0, 1100.0, 10.0), s(20, 5.0, 20.0, 0.0), s(30, 25.0, 120.0, 0.0)];
        let mut vaps: Loaded = BTreeMap::new();
        vaps.insert("bss".into(), (vec!["ap".into(), "na".into()], samples));
        let t = retry_totals(&vaps, 0)[&("ap".to_string(), "na".to_string())];
        // 30+20 retries, 100+100 attempts, 10 dropped; the restart at t=20 adds nothing.
        assert_eq!(t, [50.0, 200.0, 10.0]);
        assert!((retry_pct(t) - 100.0 * 50.0 / 260.0).abs() < 1e-9);
        assert_eq!(retry_pct([0.0, 0.0, 0.0]), 0.0);
        // Older rows without attempt counters are left out rather than read as 100 %.
        let mut vaps: Loaded = BTreeMap::new();
        vaps.insert("bss".into(), (vec!["ap".into(), "na".into()], vec![(0, vec![Some(1.0), None, None]), (10, vec![Some(9.0), None, None])]));
        assert!(retry_totals(&vaps, 0).is_empty());
    }

    #[test]
    fn rates_count_nothing_across_a_counter_restart() {
        let r = rates(&[(0, vec![Some(100.0)]), (10, vec![Some(200.0)]), (20, vec![Some(50.0)]), (30, vec![Some(80.0)])]);
        assert_eq!(r.points.iter().map(|p| p.2[0]).collect::<Vec<_>>(), [Some(10.0), Some(0.0), Some(3.0)]);
    }

    #[test]
    fn columns_are_picked_by_name() {
        let samples: Samples = vec![(5, vec![Some(1.0), Some(2.0), None])];
        assert_eq!(pick(&samples, &["a", "b", "c"], &["c", "a"]), vec![(5, vec![None, Some(1.0)])]);
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
}
