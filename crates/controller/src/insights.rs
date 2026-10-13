//! Site-wide and RF views: activity, airtime, top APs and clients, retry
//! rates, connection success, the radio overview and neighbouring networks.

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::{Query, State};
use rusqlite::Connection;
use rusqlite::params_from_iter;
use rusqlite::types::Value as Sql;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, AppState};
use crate::model::Ts;
use crate::store::{self, Db, TIERS};

#[derive(Deserialize)]
pub struct RangeQuery {
    /// Seconds back from now (default one day).
    range: Option<Ts>,
    /// An explicit window instead of `range` (Unix seconds).
    from: Option<Ts>,
    to: Option<Ts>,
    /// `ng`, `na` or `6e`; all bands when absent.
    band: Option<String>,
    /// One AP only (activity).
    mac: Option<String>,
}

/// The requested window, at least ten minutes and at most 400 days long,
/// ending no later than now; and the storage tier to read it from.
fn window(q: &RangeQuery) -> (Ts, Ts, usize) {
    let now = store::now_ts();
    let (from, to) = match (q.from, q.to) {
        (Some(from), to) => {
            let to = to.unwrap_or(now).min(now);
            (from.clamp(to - 400 * 86400, to - 600), to)
        }
        _ => (now - q.range.unwrap_or(86400).clamp(600, 400 * 86400), now),
    };
    (from, to, store::tier_for(from, to, now))
}

/// Bucket width for charts: a few hundred points whatever the range.
fn bucket_for(range: Ts, tier: usize) -> Ts {
    let min = TIERS[tier].1.max(60);
    let target = (range / 288).max(min);
    [60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 86400].into_iter().find(|b| *b >= target).unwrap_or(86400)
}

async fn read<T: Send + 'static>(s: &AppState, db: Db, f: impl FnOnce(&Connection) -> anyhow::Result<T> + Send + 'static) -> Result<T, ApiError> {
    let store = s.store.clone();
    tokio::task::spawn_blocking(move || store.read(db, f)).await.map_err(|e| ApiError::internal(e.to_string()))?.map_err(ApiError::from)
}

/// Per-key series of counter values -> per-second rates between consecutive
/// samples (a smaller value means the counter reset: the new value is the delta).
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
            (Some(c), Some(p)) => Some(if c >= p { (c - p) / dt } else { c / dt }),
            _ => None,
        });
        points.push((*t, dt, r.collect()));
    }
    Rates { points }
}

/// Samples of one series: (ts, values in the requested column order).
type Samples = Vec<(Ts, Vec<Option<f64>>)>;
/// Per key: its text columns and its samples.
type Loaded = BTreeMap<String, (Vec<String>, Samples)>;

/// What to load from a metrics table.
struct Spec<'a> {
    table: &'a str,
    /// SQL expression for the series key.
    key: &'a str,
    /// Text columns returned with each key.
    extra: &'a [&'a str],
    /// Numeric columns.
    cols: &'a [&'a str],
}

/// Loads a metrics table's samples in range, grouped by key.
fn load(c: &Connection, spec: Spec, tier: usize, from: Ts, to: Ts) -> anyhow::Result<Loaded> {
    let Spec { table, key, extra, cols } = spec;
    let suffix = TIERS[tier].0;
    // One sample before the window so the first rate in range is known.
    let sql = format!(
        "SELECT {key}, ts, {}{}{} FROM {table}{suffix} WHERE ts >= ?1 - ?3 AND ts <= ?2 ORDER BY {key}, ts",
        extra.join(", "),
        if extra.is_empty() { "" } else { ", " },
        cols.join(", ")
    );
    let step = TIERS[tier].1.max(30) * 2;
    let mut stmt = c.prepare(&sql)?;
    let mut out: Loaded = BTreeMap::new();
    let mut rows = stmt.query(rusqlite::params![from, to, step])?;
    while let Some(r) = rows.next()? {
        let k: String = r.get(0)?;
        let ts: Ts = r.get(1)?;
        let ex: Vec<String> = (0..extra.len()).map(|i| r.get::<_, Option<String>>(2 + i).map(|v| v.unwrap_or_default())).collect::<rusqlite::Result<_>>()?;
        let vals: Vec<Option<f64>> = (0..cols.len()).map(|i| r.get::<_, Option<f64>>(2 + extra.len() + i)).collect::<rusqlite::Result<_>>()?;
        let e = out.entry(k).or_insert_with(|| (ex.clone(), Vec::new()));
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
        let vaps = load(
            c,
            Spec {
                table: "vap_stats",
                key: "bssid",
                extra: &["radio", "ap_mac"],
                cols: &[
                    "tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_retries", "tx_mcast", "rx_mcast", "tx_dropped", "num_sta", "tx_bcast", "rx_bcast",
                    "wifi_tx_attempts", "wifi_tx_dropped",
                ],
            },
            tier,
            from,
            to,
        )?;
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
            let counters = |v: &Vec<Option<f64>>| [&v[..8], &v[9..]].concat();
            let r = rates(&samples.iter().map(|(t, v)| (*t, counters(v))).collect::<Vec<_>>());
            // Retries need positive increases only (a restarted counter adds nothing).
            let inc: HashMap<Ts, Vec<Option<f64>>> = increases(&samples.iter().map(|(t, v)| (*t, vec![v[4], v[11], v[12]])).collect::<Vec<_>>(), from).into_iter().collect();
            let clients: HashMap<Ts, f64> = samples.iter().filter_map(|(t, v)| v[8].map(|n| (*t, n))).collect();
            for (t, dt, v) in r.points.iter().filter(|p| p.0 >= from) {
                let b = t - t % bucket;
                let a = per.entry(b).or_default().entry(bssid.clone()).or_default();
                let g = |i: usize| v[i].unwrap_or(0.0);
                a.down += g(0);
                a.up += g(1);
                a.pkts += g(2);
                a.rx_pkts += g(3);
                // Multicast and broadcast, both directions.
                a.mcast += g(5) + g(6) + g(8) + g(9);
                a.dropped += g(7);
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
    let mut ap_list: Vec<Value> = aps
        .into_iter()
        .map(|(mac, (d, u))| {
            let name = mac.parse().ok().and_then(|m| live.devices.get(&m)).and_then(|d| d.snapshot.ap.hostname.clone());
            json!({ "mac": mac, "name": name, "download_bytes": d, "upload_bytes": u })
        })
        .collect();
    ap_list.sort_by(|a, b| (b["download_bytes"].as_f64().unwrap_or(0.0) + b["upload_bytes"].as_f64().unwrap_or(0.0)).total_cmp(&(a["download_bytes"].as_f64().unwrap_or(0.0) + a["upload_bytes"].as_f64().unwrap_or(0.0))));
    let mut cl_list: Vec<Value> = clients
        .into_iter()
        .filter(|(_, d, u)| d + u > 0.0)
        .map(|(mac, d, u)| {
            let m: Option<inform::Mac> = mac.parse().ok();
            let view = m.and_then(|m| live.clients.get(&m));
            let alias = m.and_then(|m| live.aliases.get(&m)).and_then(|a| a.alias.clone());
            json!({
                "mac": mac, "name": alias.or(view.and_then(|c| c.sample.hostname.clone())), "connected": view.is_some_and(|c| c.connected),
                "vendor": s.vendors.lookup_str(&mac), "download_bytes": d, "upload_bytes": u,
            })
        })
        .collect();
    cl_list.sort_by(|a, b| (b["download_bytes"].as_f64().unwrap_or(0.0) + b["upload_bytes"].as_f64().unwrap_or(0.0)).total_cmp(&(a["download_bytes"].as_f64().unwrap_or(0.0) + a["upload_bytes"].as_f64().unwrap_or(0.0))));
    cl_list.truncate(25);
    Ok(Json(json!({ "aps": ap_list, "clients": cl_list })))
}

/// Connection stages in the order a client passes them.
const STAGES: [&str; 6] = ["association", "authentication", "dhcp", "dns", "traffic", "success"];

/// One connection-tracking notification from an AP.
#[derive(Debug, Clone)]
pub struct ConnEvent {
    pub ts: Ts,
    pub ap: String,
    pub client: String,
    pub radio: Option<String>,
    pub event_type: String,
    pub n: Value,
}

fn num_of(n: &Value, k: &str) -> Option<f64> {
    n[k].as_f64().or_else(|| n[k].as_str().and_then(|v| v.parse().ok()))
}

/// How far an attempt got: 1 association .. 5 traffic, 6 success; None when it
/// tells nothing (or failed on a signal too weak to blame the network).
fn stage_reached(e: &ConnEvent) -> Option<usize> {
    let n = &e.n;
    let pos = |k: &str| num_of(n, k).is_some_and(|v| v > 0.0);
    let is = |k: &str, v: &str| n[k].as_str() == Some(v);
    let t = e.event_type.as_str();
    let success = t != "failure"
        && ((t == "soft failure" && n["ip_assign_type"].as_str().is_some_and(|v| v.starts_with("roam")))
            || (n.get("traffic_delta").is_none() && is("dns_resp_seen", "yes"))
            || (pos("traffic_delta") && pos("dns_responses")));
    let failed = [
        pos("assoc_failures"),
        pos("auth_failures") || pos("wpa_auth_failures") || is("radius_auth_status", "failure"),
        pos("ip_failures"),
        pos("dns_timeouts") || is("dns_resp_seen", "no"),
        pos("traffic_failures"),
    ];
    if success {
        return Some(6);
    }
    let rssi = num_of(n, "auth_rssi").or_else(|| num_of(n, "avg_rssi"));
    if rssi.is_some_and(|r| r < -75.0) {
        return None;
    }
    failed.iter().rposition(|f| *f).map(|i| i + 1)
}

/// Connection success per client: each client counts once, at the furthest
/// stage any of its attempts reached. A later "fixup" for the same attempt
/// (AP, client and event id, within ten minutes) replaces the failure.
pub fn connectivity_stats(mut events: Vec<ConnEvent>, band: Option<&str>) -> Value {
    events.retain(|e| matches!(e.event_type.as_str(), "failure" | "soft failure" | "success" | "fixup"));
    events.retain(|e| band.is_none_or(|b| e.radio.as_deref() == Some(b)));
    events.sort_by_key(|e| e.ts);
    let mut merged: Vec<ConnEvent> = Vec::new();
    for e in events {
        if e.event_type == "fixup"
            && let Some(id) = e.n.get("event_id").filter(|v| !v.is_null())
            && let Some(prev) = merged.iter_mut().rev().find(|p| {
                p.ap == e.ap && p.client == e.client && p.n.get("event_id") == Some(id) && e.ts - p.ts <= 600 && p.event_type.contains("failure")
            })
        {
            if let (Some(a), Some(b)) = (prev.n.as_object_mut(), e.n.as_object()) {
                for (k, v) in b {
                    a.insert(k.clone(), v.clone());
                }
            }
            prev.event_type = "fixup".into();
            continue;
        }
        merged.push(e);
    }
    let mut attempts = 0u64;
    let mut furthest: BTreeMap<&str, usize> = BTreeMap::new();
    let mut timings: [Vec<f64>; 3] = Default::default();
    for e in &merged {
        let Some(stage) = stage_reached(e) else { continue };
        attempts += 1;
        let f = furthest.entry(e.client.as_str()).or_insert(0);
        *f = (*f).max(stage);
        if stage == 6 {
            for (i, k) in ["assoc_delta", "wpa_auth_delta", "ip_delta"].iter().enumerate() {
                if let Some(us) = num_of(&e.n, k).filter(|v| *v > 0.0) {
                    timings[i].push(us / 1000.0);
                }
            }
        }
    }
    let clients = furthest.len();
    let pct = |past: usize| (clients > 0).then(|| (100.0 * furthest.values().filter(|s| **s > past).count() as f64 / clients as f64).round());
    let median = |v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v.get(v.len() / 2).map(|x| x.round())
    };
    let [mut a, mut b, mut c] = timings;
    json!({
        "attempts": attempts,
        "clients": clients,
        "failed_clients": furthest.values().filter(|s| **s < 6).count(),
        "association_pct": pct(1), "authentication_pct": pct(2), "dhcp_pct": pct(3), "dns_pct": pct(4),
        "success_pct": pct(5),
        "failed_at": STAGES.iter().take(5).enumerate().map(|(i, k)| (k.to_string(), json!(furthest.values().filter(|s| **s == i + 1).count()))).collect::<serde_json::Map<_, _>>(),
        "median_ms": { "association": median(&mut a), "authentication": median(&mut b), "dhcp": median(&mut c) },
    })
}

/// GET /api/site/connectivity: connection success per client and stage, for
/// all bands and each band.
pub async fn connectivity(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, _) = window(&q);
    let events = read(&s, Db::Config, move |c| {
        let mut stmt = c.prepare(
            "SELECT ts, ap_mac, client_mac, radio, event_type, detail, ip_assign_type, dns_responses, dns_timeouts, rssi FROM connections WHERE ts >= ?1 AND ts <= ?2",
        )?;
        let rows = stmt
            .query_map([from, to], |r| {
                let detail: Option<String> = r.get(5)?;
                // Rows from before the full notification was kept: rebuild what we can.
                let n = detail.and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_else(|| {
                    json!({
                        "ip_assign_type": r.get::<_, Option<String>>(6).ok().flatten(),
                        "dns_responses": r.get::<_, Option<i64>>(7).ok().flatten(),
                        "dns_timeouts": r.get::<_, Option<i64>>(8).ok().flatten(),
                        "avg_rssi": r.get::<_, Option<i64>>(9).ok().flatten(),
                    })
                });
                Ok(ConnEvent { ts: r.get(0)?, ap: r.get(1)?, client: r.get(2)?, radio: r.get(3)?, event_type: r.get(4)?, n })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    let mut bands = serde_json::Map::new();
    for b in [None, Some("ng"), Some("na"), Some("6e")] {
        let v = connectivity_stats(events.clone(), b);
        if b.is_none() || v["attempts"].as_u64().unwrap_or(0) > 0 {
            bands.insert(b.unwrap_or("all").into(), v);
        }
    }
    Ok(Json(json!({ "bands": bands })))
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
fn retry_totals(vaps: &Loaded, from: Ts) -> HashMap<(String, String), [f64; 3]> {
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
fn retry_pct([r, a, d]: [f64; 3]) -> f64 {
    let all = r + a + d;
    if all > 0.0 { 100.0 * r / all } else { 0.0 }
}

const RETRY_COLS: &[&str] = &["tx_retries", "wifi_tx_attempts", "wifi_tx_dropped"];

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
        let mut cols = vec!["tx_bytes", "rx_bytes"];
        cols.extend_from_slice(RETRY_COLS);
        let v = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: &cols }, tier, from, to)?;
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
        let (d, u) = totals(&samples.iter().map(|(t, v)| (*t, v[..2].to_vec())).collect::<Vec<_>>(), from);
        for band in ["all", ex[1].as_str()] {
            *bytes.entry((ex[0].clone(), band.to_string())).or_default() += d + u;
        }
    }
    let retries = {
        let only: Loaded = vaps.iter().map(|(k, (ex, smp))| (k.clone(), (ex.clone(), smp.iter().map(|(t, v)| (*t, v[2..5].to_vec())).collect()))).collect();
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
    let name_of = |mac: &str| mac.parse().ok().and_then(|m| live.devices.get(&m)).and_then(|d| d.snapshot.ap.hostname.clone());
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
    let list: Vec<Value> = aps.into_iter().map(|(mac, groups)| json!({ "mac": mac, "name": name_of(&mac), "bands": groups })).collect();
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
            let name = ap.parse().ok().and_then(|m| live.devices.get(&m)).and_then(|d| d.snapshot.ap.hostname.clone());
            json!({ "mac": ap, "name": name, "radio": band, "tx_retry_pct": retry_pct(t), "retries": t[0], "attempts": t[1], "dropped": t[2] })
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
            Spec { table: "client_stats", key: "mac || '/' || coalesce(ap_mac, '')", extra: &[], cols: &["mcast_tx_pkts", "mcast_rx_pkts", "mcast_tx_bytes", "mcast_rx_bytes"] },
            tier,
            from,
            to,
        )?;
        let mut per: HashMap<String, [f64; 4]> = HashMap::new();
        for (k, (_, smp)) in &cl {
            let (mac, on) = k.split_once('/').unwrap_or((k, ""));
            if ap2.as_deref().is_some_and(|a| a != on) {
                continue;
            }
            let e = per.entry(mac.to_string()).or_default();
            for (_, dt, v) in rates(smp).points.iter().filter(|p| p.0 >= from) {
                for i in 0..4 {
                    e[i] += v[i].unwrap_or(0.0) * dt;
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
            let alias = m.and_then(|m| live.aliases.get(&m)).and_then(|a| a.alias.clone());
            let mc = view.and_then(|v| v.sample.multicast.as_ref());
            let ap_name = view.and_then(|v| live.devices.get(&v.sample.ap_mac)).and_then(|d| d.snapshot.ap.hostname.clone());
            json!({
                "mac": mac, "name": alias.or(view.and_then(|c| c.sample.hostname.clone())), "vendor": s.vendors.lookup_str(&mac),
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

/// GET /api/rf/radios: each AP radio with its settings now and its averages
/// over the window (interference, utilisation, traffic, retries, signal).
pub async fn radios(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, to, tier) = window(&q);
    let (rstats, vstats) = read(&s, Db::Metrics, move |c| {
        let r = load(c, Spec { table: "radio_stats", key: "mac || '/' || radio", extra: &[], cols: &["cu_total", "cu_interf"] }, tier, from, to)?;
        // Retries come from the VAPs: the radio-level counters stay at 0 on some models.
        let v = load(
            c,
            Spec {
                table: "vap_stats",
                key: "bssid",
                extra: &["ap_mac", "radio"],
                cols: &["tx_bytes", "rx_bytes", "avg_client_signal", "tx_retries", "wifi_tx_attempts", "wifi_tx_dropped"],
            },
            tier,
            from,
            to,
        )?;
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
        let only: Loaded = vstats.iter().map(|(k, (ex, smp))| (k.clone(), (ex.clone(), smp.iter().map(|(t, v)| (*t, v[3..6].to_vec())).collect()))).collect();
        retry_totals(&only, from)
    };
    let live = s.live.read().unwrap();
    let mut out = Vec::new();
    for (mac, d) in &live.devices {
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
            let mut usage = 0.0;
            let mut signals = Vec::new();
            for (ex, samples) in vstats.values() {
                if ex[0] == mac.to_string() && ex[1] == r.radio {
                    let rr = rates(&samples.iter().map(|(t, v)| (*t, v[..2].to_vec())).collect::<Vec<_>>());
                    for (_, dt, v) in rr.points.iter().filter(|x| x.0 >= from) {
                        usage += (v[0].unwrap_or(0.0) + v[1].unwrap_or(0.0)) * dt;
                    }
                    // The AP reports 0 or -1 when no client is connected.
                    signals.extend(samples.iter().filter(|p| p.0 >= from).filter_map(|p| p.1[2]).filter(|v| *v < -10.0));
                }
            }
            let retry_pct = retry.get(&(mac.to_string(), r.radio.clone())).map(|t| retry_pct(*t));
            let spec: Vec<&Value> = spectrum_rows.iter().filter(|(m, rd, _)| *m == mac.to_string() && *rd == r.radio).map(|x| &x.2).collect();
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
    let name_of = |m: &str| m.parse().ok().and_then(|m: inform::Mac| live.devices.get(&m)).and_then(|d| d.snapshot.ap.hostname.clone());
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

fn is_dfs(ch: i64) -> bool {
    (52..=144).contains(&ch)
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

/// GET /api/rf/channel-plan: a suggested channel per AP for one band, from
/// the networks each AP hears, our APs' signal to each other, and measured
/// interference. Suggestions only: nothing is applied.
pub async fn channel_plan(State(s): State<AppState>, Query(q): Query<PlanQuery>) -> Result<Json<Value>, ApiError> {
    let radio = q.band.clone().unwrap_or_else(|| "na".into());
    let dfs = q.dfs.unwrap_or(false);
    let since = store::now_ts() - 7 * 86400;
    let r2 = radio.clone();
    let (neigh, spectrum) = read(&s, Db::Config, move |c| {
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
    let live = s.live.read().unwrap();
    struct Ap {
        mac: String,
        name: Option<String>,
        current: Option<Block>,
        width: i64,
        clients: i64,
        /// Channel blocks the AP lists as available (its country and width).
        available: Option<Vec<i64>>,
    }
    let aps: Vec<Ap> = live
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
            Some(Ap { mac: m.to_string(), name: d.snapshot.ap.hostname.clone(), current: Some(block(&radio, ch, width)), width, clients: r.num_sta, available })
        })
        .collect();
    // Our APs' BSSIDs on this band, to separate own signal from neighbours.
    let own_bssids: HashMap<String, String> = live
        .devices
        .iter()
        .flat_map(|(m, d)| d.snapshot.vaps.iter().filter(|v| v.radio.as_deref() == Some(radio.as_str())).map(move |v| (v.bssid.to_ascii_lowercase(), m.to_string())))
        .collect();
    // AP-to-AP signal (strongest seen either way).
    let mut ap_signal: HashMap<(String, String), f64> = HashMap::new();
    for (heard_by, bssid, _, _, _, sig) in &neigh {
        if let (Some(owner), Some(sig)) = (own_bssids.get(bssid), sig) {
            for k in [(heard_by.clone(), owner.clone()), (owner.clone(), heard_by.clone())] {
                let e = ap_signal.entry(k).or_insert(-200.0);
                *e = e.max(*sig);
            }
        }
    }
    let cost = |ap: &Ap, b: &Block, assigned: &HashMap<String, Block>| -> (f64, Vec<String>) {
        let mut total = 0.0;
        let mut reasons: Vec<(f64, String)> = Vec::new();
        for (heard_by, bssid, essid, cf, bw, sig) in &neigh {
            if heard_by != &ap.mac || own_bssids.contains_key(bssid) {
                continue;
            }
            let (Some(cf), Some(sig)) = (cf, sig) else { continue };
            let half = bw.unwrap_or(20.0) / 2.0;
            if overlap(b, cf - half, cf + half) {
                let w = weight(*sig);
                total += w;
                reasons.push((w, format!("{} ({sig:.0} dBm)", essid.clone().unwrap_or_else(|| "hidden network".into()))));
            }
        }
        for (other, ob) in assigned {
            if other != &ap.mac && overlap(b, ob.lo, ob.hi) {
                let sig = ap_signal.get(&(ap.mac.clone(), other.clone())).copied().unwrap_or(-75.0);
                let w = 2.0 * weight(sig);
                total += w;
                let name = aps.iter().find(|a| &a.mac == other).and_then(|a| a.name.clone()).unwrap_or_else(|| other.clone());
                reasons.push((w, format!("your AP {name} ({sig:.0} dBm)")));
            }
        }
        for (m, ch, width, interference, util) in &spectrum {
            if m != &ap.mac {
                continue;
            }
            let sb = block(&radio, *ch, width.unwrap_or(20));
            if overlap(b, sb.lo, sb.hi) {
                total += util.unwrap_or(0.0) * 0.5 + interference.map_or(0.0, |i| weight(i) * 0.5);
            }
        }
        reasons.sort_by(|a, b| b.0.total_cmp(&a.0));
        (total, reasons.into_iter().take(4).map(|r| r.1).collect())
    };
    // Greedy: busiest AP first, then a second pass with everyone placed.
    let mut order: Vec<&Ap> = aps.iter().collect();
    order.sort_by_key(|a| -a.clients);
    let mut assigned: HashMap<String, Block> = aps.iter().filter_map(|a| a.current.map(|c| (a.mac.clone(), c))).collect();
    for _ in 0..2 {
        for ap in &order {
            let best = candidates(&radio, ap.width, dfs, ap.available.as_deref())
                .into_iter()
                .map(|b| (cost(ap, &b, &assigned).0, b))
                .min_by(|a, b| a.0.total_cmp(&b.0));
            if let Some((_, b)) = best {
                assigned.insert(ap.mac.clone(), b);
            }
        }
    }
    let plan: Vec<Value> = aps
        .iter()
        .map(|ap| {
            let others: HashMap<String, Block> = assigned.iter().filter(|(m, _)| *m != &ap.mac).map(|(m, b)| (m.clone(), *b)).collect();
            let current = ap.current.map(|b| cost(ap, &b, &others));
            let suggested = assigned[&ap.mac];
            let (s_cost, s_reasons) = cost(ap, &suggested, &others);
            let cur_cost = current.as_ref().map_or(f64::MAX, |c| c.0);
            // Only worth a change when clearly better (avoid churn for small gains).
            let change = ap.current.is_some_and(|c| c.primary != suggested.primary) && s_cost + 5.0 < cur_cost * 0.8;
            json!({
                "mac": ap.mac, "name": ap.name, "width": ap.width, "clients": ap.clients,
                "current_channel": ap.current.map(|c| c.primary), "current_score": current.as_ref().map(|c| c.0.round()),
                "current_reasons": current.map(|c| c.1),
                "suggested_channel": if change { suggested.primary } else { ap.current.map_or(suggested.primary, |c| c.primary) },
                "suggested_score": if change { s_cost.round() } else { cur_cost.round() },
                "suggested_reasons": if change { s_reasons } else { vec![] },
                "change": change,
            })
        })
        .collect();
    Ok(Json(json!({ "band": radio, "dfs": dfs, "plan": plan })))
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
        // A week ago reads the five-minute tier; a day 60 days back reads hourly.
        assert_eq!(window(&q(None, Some(now - 7 * 86400), Some(now - 6 * 86400))).2, 1);
        assert_eq!(window(&q(None, Some(now - 60 * 86400), Some(now - 59 * 86400))).2, 2);
    }

    fn conn(ts: Ts, client: &str, event_type: &str, n: Value) -> ConnEvent {
        ConnEvent { ts, ap: "ap".into(), client: client.into(), radio: Some("na".into()), event_type: event_type.into(), n }
    }

    #[test]
    fn connectivity_counts_clients_at_their_furthest_stage() {
        let ok = json!({ "traffic_delta": 120000, "dns_responses": 1, "dns_resp_seen": "yes" });
        let events = vec![
            // a: failed DHCP, then connected: counts as a success.
            conn(10, "a", "failure", json!({ "ip_failures": 1, "auth_rssi": -60 })),
            conn(20, "a", "success", ok.clone()),
            // b: failed at DNS only.
            conn(10, "b", "failure", json!({ "dns_timeouts": 2, "auth_rssi": -60 })),
            // c: a roam reported as a soft failure is a success.
            conn(10, "c", "soft failure", json!({ "ip_assign_type": "roamed" })),
            // d: failed authentication on a weak signal: not the network's fault, ignored.
            conn(10, "d", "failure", json!({ "auth_failures": 1, "auth_rssi": -82 })),
            // e: association events are not attempts.
            conn(10, "e", "association", json!({})),
        ];
        let v = connectivity_stats(events, None);
        assert_eq!(v["attempts"], 4);
        assert_eq!(v["clients"], 3);
        assert_eq!(v["failed_clients"], 1);
        assert_eq!((v["association_pct"].as_f64(), v["dhcp_pct"].as_f64(), v["dns_pct"].as_f64()), (Some(100.0), Some(100.0), Some(67.0)));
        assert_eq!(v["success_pct"].as_f64(), Some(67.0));
        assert_eq!(v["failed_at"]["dns"], 1);
    }

    #[test]
    fn a_fixup_turns_a_failure_into_a_success() {
        let fail = conn(100, "a", "failure", json!({ "event_id": 7, "dns_timeouts": 1, "auth_rssi": -50 }));
        let fixup = conn(160, "a", "fixup", json!({ "event_id": 7, "dns_timeouts": 0, "dns_responses": 3, "traffic_delta": 90000 }));
        let v = connectivity_stats(vec![fail.clone(), fixup.clone()], None);
        assert_eq!((v["attempts"].as_u64(), v["success_pct"].as_f64()), (Some(1), Some(100.0)));
        // Too late (over ten minutes) to merge: the failure stands, the fixup is its own success.
        let mut late = fixup;
        late.ts = 1000;
        let v = connectivity_stats(vec![fail, late], None);
        assert_eq!(v["attempts"], 2);
        // Band filter.
        assert_eq!(connectivity_stats(vec![conn(1, "a", "success", json!({ "dns_resp_seen": "yes" }))], Some("ng"))["clients"], 0);
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
}
