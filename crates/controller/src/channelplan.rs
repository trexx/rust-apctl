//! The channel planner: a suggested channel per AP for one band, from the
//! networks each AP hears, our APs' signal to each other, and measured
//! interference. Channel AI applies its plans (see `channelai`).

use std::collections::HashMap;

use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::api::{ApiError, AppState, Json, Query, read};
use crate::channelai::is_dfs;
use crate::clock;
use crate::series::own_bssids;
use crate::store::Db;

#[derive(Deserialize)]
pub struct PlanQuery {
    pub(crate) band: Option<String>,
    /// Consider DFS channels on 5 GHz (radar can force the AP off them).
    pub(crate) dfs: Option<bool>,
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
        return Err(ApiError::bad("band must be ng or na"));
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
}
