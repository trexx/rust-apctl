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
    /// `ng`, `na` or `6e`; all bands when absent.
    band: Option<String>,
}

fn window(q: &RangeQuery) -> (Ts, Ts, usize) {
    let now = store::now_ts();
    let range = q.range.unwrap_or(86400).clamp(600, 400 * 86400);
    let from = now - range;
    (from, now, store::tier_for(from, now, now))
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
    let result = read(&s, Db::Metrics, move |c| {
        // VAP counters: bytes, packets, retries, multicast; gauges: clients.
        let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["radio"], cols: &["tx_bytes", "rx_bytes", "tx_packets", "rx_packets", "tx_retries", "tx_mcast", "rx_mcast", "num_sta"] }, tier, from, to)?;
        // bucket -> per-bssid accumulators
        #[derive(Default, Clone)]
        struct Acc {
            down: f64,
            up: f64,
            pkts: f64,
            retries: f64,
            mcast: f64,
            clients: f64,
            n: f64,
        }
        let mut per: BTreeMap<Ts, HashMap<String, Acc>> = BTreeMap::new();
        for (bssid, (ex, samples)) in &vaps {
            if !band_ok(&band, &ex[0]) {
                continue;
            }
            let r = rates(&samples.iter().map(|(t, v)| (*t, v[..7].to_vec())).collect::<Vec<_>>());
            let clients: HashMap<Ts, f64> = samples.iter().filter_map(|(t, v)| v[7].map(|n| (*t, n))).collect();
            for (t, _, v) in r.points.iter().filter(|p| p.0 >= from) {
                let b = t - t % bucket;
                let a = per.entry(b).or_default().entry(bssid.clone()).or_default();
                let g = |i: usize| v[i].unwrap_or(0.0);
                a.down += g(0);
                a.up += g(1);
                a.pkts += g(2);
                a.retries += g(4);
                a.mcast += g(5) + g(6);
                a.clients += clients.get(t).copied().unwrap_or(0.0);
                a.n += 1.0;
                let _ = g(3);
            }
        }
        let mut ts = Vec::new();
        let (mut down, mut up, mut retry, mut clients, mut mcast) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (b, m) in &per {
            ts.push(*b);
            // Average per VAP within the bucket, then sum across VAPs.
            let sum = |f: &dyn Fn(&Acc) -> f64| m.values().map(|a| f(a) / a.n.max(1.0)).sum::<f64>();
            let (d, u, p, r, mc, cl) = (sum(&|a| a.down), sum(&|a| a.up), sum(&|a| a.pkts), sum(&|a| a.retries), sum(&|a| a.mcast), sum(&|a| a.clients));
            down.push(d * 8.0);
            up.push(u * 8.0);
            retry.push(if p > 0.0 { Some(100.0 * r / (p + r)) } else { None });
            mcast.push(if p > 0.0 { Some((100.0 * mc / p).min(100.0)) } else { None });
            clients.push(cl);
        }

        // Airtime from the radios: averages across radios per bucket.
        let radios = load(c, Spec { table: "radio_stats", key: "mac || '/' || radio", extra: &["radio"], cols: &["cu_total", "cu_interf", "cu_self_rx", "cu_self_tx"] }, tier, from, to)?;
        let mut air: BTreeMap<Ts, Vec<[f64; 4]>> = BTreeMap::new();
        for (ex, samples) in radios.values() {
            if !band_ok(&band, &ex[0]) {
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
        let internal: Vec<f64> = avg(2).iter().zip(avg(3)).map(|(a, b)| a + b).collect();
        Ok(json!({
            "bucket": bucket,
            "activity": { "ts": ts, "download_bps": down, "upload_bps": up, "tx_retry_pct": retry, "clients": clients, "multicast_pct": mcast },
            "airtime": { "ts": air_ts, "total": total, "external_interference": external, "own_traffic": internal },
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
    let (aps, clients) = read(&s, Db::Metrics, move |c| {
        let vaps = load(c, Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac"], cols: &["tx_bytes", "rx_bytes"] }, tier, from, to)?;
        let mut aps: HashMap<String, (f64, f64)> = HashMap::new();
        for (ex, samples) in vaps.values() {
            let (d, u) = totals(samples, from);
            let e = aps.entry(ex[0].clone()).or_default();
            e.0 += d;
            e.1 += u;
        }
        let cl = load(c, Spec { table: "client_stats", key: "mac", extra: &[], cols: &["tx_bytes", "rx_bytes"] }, tier, from, to)?;
        let clients: Vec<(String, f64, f64)> = cl.iter().map(|(m, (_, s))| {
            let (d, u) = totals(s, from);
            (m.clone(), d, u)
        }).collect();
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

/// GET /api/site/connectivity: share of connection attempts that passed each stage.
pub async fn connectivity(State(s): State<AppState>, Query(q): Query<RangeQuery>) -> Result<Json<Value>, ApiError> {
    let (from, _, _) = window(&q);
    let band = q.band.clone();
    let rows = read(&s, Db::Config, move |c| {
        let mut stmt = c.prepare(
            "SELECT event_type, radio, ip_assign_type, ip_ms, dns_responses, dns_timeouts, reason, auth_ms, assoc_ms FROM connections WHERE ts >= ?1",
        )?;
        let rows = stmt
            .query_map([from], |r| {
                Ok((
                    r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<i64>>(4)?, r.get::<_, Option<i64>>(5)?, r.get::<_, Option<String>>(6)?, r.get::<_, Option<i64>>(7)?,
                    r.get::<_, Option<i64>>(8)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .await?;
    // (ok, failed) per stage. Successful attempts pass every stage they report;
    // failures count against the stage their reason names.
    let mut stages: BTreeMap<&str, (u64, u64)> = ["association", "authentication", "dhcp", "dns"].into_iter().map(|k| (k, (0, 0))).collect();
    let mut timings: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    for (event, radio, ip_type, ip_ms, dns_ok, dns_to, reason, auth_ms, assoc_ms) in rows {
        if radio.as_deref().is_some_and(|r| !band_ok(&band, r)) {
            continue;
        }
        let reason = reason.unwrap_or_default().to_ascii_lowercase();
        match event.as_str() {
            "success" => {
                for k in ["association", "authentication"] {
                    stages.get_mut(k).unwrap().0 += 1;
                }
                if ip_type.as_deref() == Some("dhcp") {
                    stages.get_mut("dhcp").unwrap().0 += 1;
                }
                if dns_ok.unwrap_or(0) > 0 || dns_to == Some(0) {
                    stages.get_mut("dns").unwrap().0 += 1;
                }
                if dns_to.unwrap_or(0) > 0 {
                    stages.get_mut("dns").unwrap().1 += 1;
                }
                for (k, v) in [("association", assoc_ms), ("authentication", auth_ms), ("dhcp", ip_ms)] {
                    if let Some(v) = v {
                        timings.entry(k).or_default().push(v);
                    }
                }
            }
            e if e.contains("failure") && !reason.contains("roam") => {
                let stage = if reason.contains("auth") || reason.contains("key") || reason.contains("psk") {
                    "authentication"
                } else if reason.contains("dhcp") || reason.contains("ip") {
                    "dhcp"
                } else if reason.contains("dns") {
                    "dns"
                } else {
                    "association"
                };
                stages.get_mut(stage).unwrap().1 += 1;
            }
            _ => {}
        }
    }
    let median = |v: &mut Vec<i64>| -> Option<i64> {
        v.sort();
        v.get(v.len() / 2).copied()
    };
    let out: Vec<Value> = stages
        .iter()
        .map(|(k, (ok, fail))| {
            let total = ok + fail;
            json!({
                "stage": k, "ok": ok, "failed": fail,
                "success_pct": if total > 0 { Some(100.0 * *ok as f64 / total as f64) } else { None },
                "median_ms": timings.get_mut(*k).and_then(median),
            })
        })
        .collect();
    Ok(Json(json!({ "stages": out })))
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
            Spec { table: "vap_stats", key: "bssid", extra: &["ap_mac", "radio"], cols: &["tx_bytes", "rx_bytes", "tx_packets", "tx_retries", "avg_client_signal"] },
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
            let (mut usage, mut packets, mut retries) = (0.0, 0.0, 0.0);
            let mut signals = Vec::new();
            for (ex, samples) in vstats.values() {
                if ex[0] == mac.to_string() && ex[1] == r.radio {
                    let rr = rates(&samples.iter().map(|(t, v)| (*t, v[..4].to_vec())).collect::<Vec<_>>());
                    for (_, dt, v) in rr.points.iter().filter(|x| x.0 >= from) {
                        usage += (v[0].unwrap_or(0.0) + v[1].unwrap_or(0.0)) * dt;
                        packets += v[2].unwrap_or(0.0) * dt;
                        retries += v[3].unwrap_or(0.0) * dt;
                    }
                    // The AP reports 0 or -1 when no client is connected.
                    signals.extend(samples.iter().filter(|p| p.0 >= from).filter_map(|p| p.1[4]).filter(|v| *v < -10.0));
                }
            }
            let retry_pct = (packets > 0.0).then(|| 100.0 * retries / (packets + retries));
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
}
