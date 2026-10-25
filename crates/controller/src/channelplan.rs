//! The channel planner: a suggested channel per AP for one band, from the
//! networks each AP hears, our APs' signal to each other, and measured
//! interference. Channel AI applies its plans (see `channelai`).

use std::collections::{HashMap, HashSet};

use axum::extract::State;
use inform::Mac;
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

/// What an AP measured of a block's air, from its survey (`(block, load)` per
/// entry). Each entry measures the air around its own centre, overlapping
/// neighbours' included, so a sum over every entry that overlaps the block
/// would count the same air several times, and more often in the middle of a
/// band (on 2.4 GHz, seven entries overlap channel 6, four channel 1). The
/// entries within the block (at 20 MHz, its own) are averaged; when none is
/// (an entry wider than the block), those that overlap it.
fn measured_load(b: &Block, measured: &[(Block, f64)]) -> f64 {
    let mean = |pick: &dyn Fn(&Block) -> bool| {
        let (sum, n) = measured.iter().filter(|(sb, _)| pick(sb)).fold((0.0, 0), |(s, n), (_, l)| (s + l, n + 1));
        (n > 0).then(|| sum / f64::from(n))
    };
    mean(&|sb| b.lo <= sb.lo && sb.hi <= b.hi).or_else(|| mean(&|sb| overlap(b, sb.lo, sb.hi))).unwrap_or(0.0)
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
        if (0..(width / 20).max(1)).all(|i| allowed.contains(&(first + 4 * i))) && !out.iter().any(|o| (o.lo - b.lo).abs() < 1.0) {
            out.push(Block { primary: first, ..b });
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
/// offers), `pinned` APs keep their channel. An AP on a channel no longer
/// allowed moves; any other moves only when clearly better off there, and
/// those moves are made only when the plan is better overall by more than 10%
/// than making just the ones that must be made.
pub async fn compute_plan(s: &AppState, radio: String, dfs: bool, allowed: Option<Vec<i64>>, pinned: HashSet<Mac>) -> Result<Plan, ApiError> {
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
        // The APs' records in the settings, found once (the first of a MAC listed twice, as `device_doc` finds it).
        let mut docs: HashMap<Mac, &serde_json::Value> = HashMap::new();
        for d in state.into_iter().flat_map(|st| crate::settings::docs(st, "devices")) {
            if let Some(m) = crate::settings::doc_mac(&d["mac"]) {
                docs.entry(m).or_insert(d);
            }
        }
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
                // As `set_channels` judges a channel: at the width its settings run the radio at, not the one reported.
                let legal = state.and_then(|st| {
                    let doc = *docs.get(m)?;
                    let at = crate::settings::inform_radio(doc, &radio).map_or(width, |r| crate::settings::radio_width(st, r));
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
    pinned: HashSet<Mac>,
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
    let is_pinned: Vec<bool> = aps.iter().map(|ap| ap.mac.parse().is_ok_and(|m: Mac| pinned.contains(&m))).collect();
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
        total + measured_load(b, &measured[i])
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
    let greedy = |movers: &[usize], mut placed: Vec<Block>| -> Vec<Block> {
        for _ in 0..2 {
            for &i in movers {
                if let Some((_, b)) = cands[i].iter().map(|b| (cost(i, b, &placed), *b)).min_by(|a, b| a.0.total_cmp(&b.0)) {
                    placed[i] = b;
                }
            }
        }
        placed
    };
    let mut order: Vec<usize> = (0..n).filter(|i| !is_pinned[*i]).collect();
    order.sort_by_key(|i| -aps[*i].clients);
    let current: Vec<Block> = aps.iter().map(|a| a.current).collect();
    // APs that must move: their channel is not one the settings allow (the
    // whole block at a wider width) or the country allows, and there is one
    // that is. A channel the planner would not pick itself (13, 165) may stay.
    let same = |a: &Block, b: &Block| (a.lo - b.lo).abs() < 1.0 && (a.hi - b.hi).abs() < 1.0;
    let must: Vec<bool> = aps
        .iter()
        .enumerate()
        .map(|(i, ap)| {
            let allowed_here = allowed.as_ref().is_none_or(|a| allowed_blocks(&radio, ap.width, a).iter().any(|b| same(b, &ap.current)));
            let legal_here = ap.legal.as_ref().is_none_or(|l| l.contains(&ap.current.primary));
            !is_pinned[i] && !cands[i].is_empty() && !(allowed_here && legal_here)
        })
        .collect();
    let moved = |plan: &[Block], i: usize| plan[i].primary != current[i].primary;
    // Every other AP moves only when clearly better off (by more than 20%,
    // and 5) with the others where the plan leaves them. A move given up can
    // spoil another (an AP taking a channel that one was to leave), so they
    // are judged again, the worst given up first, until every move left pays.
    let mut fin = greedy(&order, current.clone());
    loop {
        let worst = (0..n)
            .filter(|&i| !must[i] && moved(&fin, i))
            .map(|i| (cost(i, &fin[i], &fin) + 5.0 - cost(i, &current[i], &fin) * 0.8, i))
            .filter(|(short, _)| *short >= 0.0)
            .max_by(|a, b| a.0.total_cmp(&b.0));
        let Some((_, i)) = worst else { break };
        fin[i] = current[i];
    }
    // The other moves are made only when the plan is better overall by more
    // than 10% than making just the ones that must be made.
    let must_order: Vec<usize> = order.iter().copied().filter(|i| must[*i]).collect();
    let forced = if must_order.is_empty() { current.clone() } else { greedy(&must_order, current.clone()) };
    let total = |m: &[Block]| -> f64 { m.iter().enumerate().map(|(i, b)| cost(i, b, m)).sum() };
    let current_total = total(&current);
    let optional = (0..n).any(|i| !must[i] && moved(&fin, i));
    if !(optional && total(&fin) * 1.1 < total(&forced)) {
        fin = forced;
    }
    // A plan that moves nothing suggests leaving every AP where it is, and is scored as that.
    let accepted = (0..n).any(|i| moved(&fin, i));
    let suggested_total = if accepted { total(&fin) } else { current_total };
    let evict: Vec<Option<bool>> = (0..n).map(|i| moved(&fin, i).then_some(must[i])).collect();
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
        let plan = plan_channels("ng".into(), false, None, HashSet::new(), aps, own, neigh, vec![]);
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
        let plan = plan_channels("na".into(), true, allowed, HashSet::new(), aps, HashMap::new(), neigh, vec![]);
        assert!(plan.accepted, "{plan:?}");
        let to: HashMap<&str, (i64, bool)> = plan.plan.iter().map(|p| (p.mac.as_str(), (p.suggested_channel, p.not_allowed))).collect();
        assert_eq!((to["in"], to["out"]), ((116, false), (100, true)));
    }

    /// A 2.4 GHz AP for a plan: hearing no AP of ours, so taken to be 75 dBm from each.
    fn ng_ap(mac: &str, ch: i64, clients: i64) -> PlanAp {
        PlanAp { mac: mac.into(), name: None, current: block("ng", ch, 20), width: 20, clients, available: None, legal: None }
    }

    /// A network `by` hears on a 2.4 GHz channel.
    fn ng_neighbour(by: &str, ch: i64, signal: f64) -> NeighborRow {
        (by.into(), format!("{by}-{ch}"), Some(format!("Net {ch}")), Some(2407.0 + 5.0 * ch as f64), Some(20.0), Some(signal))
    }

    #[test]
    fn an_ap_moves_onto_a_channel_only_when_the_one_there_leaves() {
        // "i" is crowded on 1 and 11 and would take 6 were "j" to leave it; "j"
        // would do a little better on 1, not enough to move. "k" sits on 13,
        // which the settings no longer allow, so the plan is applied.
        let aps = vec![ng_ap("i", 1, 5), ng_ap("j", 6, 2), ng_ap("k", 13, 1)];
        let neigh = vec![ng_neighbour("i", 1, -45.0), ng_neighbour("i", 11, -45.0), ng_neighbour("j", 1, -60.0), ng_neighbour("j", 11, -50.0), ng_neighbour("k", 1, -40.0), ng_neighbour("k", 6, -40.0)];
        let plan = plan_channels("ng".into(), false, Some(vec![1, 6, 11]), HashSet::new(), aps, HashMap::new(), neigh, vec![]);
        assert!(plan.accepted, "{plan:?}");
        let to: HashMap<&str, (i64, bool)> = plan.plan.iter().map(|p| (p.mac.as_str(), (p.suggested_channel, p.change))).collect();
        assert_eq!(to["k"], (11, true), "{plan:?}");
        assert_eq!((to["i"], to["j"]), ((1, false), (6, false)), "j stays, so i stays off its channel: {plan:?}");
    }

    #[test]
    fn a_survey_counts_each_blocks_air_once() {
        // The same air everywhere, as a 2.4 GHz scan reports it (13 channels at 20 MHz).
        let survey: Vec<(Block, f64)> = (1..=13).map(|c| (block("ng", c, 20), 12.5)).collect();
        for ch in [1, 6, 11, 13] {
            assert_eq!(measured_load(&block("ng", ch, 20), &survey), 12.5, "channel {ch}");
        }
        // A busy channel 6 shows on 6, not on 1 or 11.
        let mut busy = survey.clone();
        busy[5].1 = 40.0;
        assert_eq!((measured_load(&block("ng", 6, 20), &busy), measured_load(&block("ng", 1, 20), &busy)), (40.0, 12.5));
        // 20 MHz entries in an 80 MHz block are averaged; an 80 MHz entry stands for its 20 MHz parts.
        let na: Vec<(Block, f64)> = [(36, 10.0), (40, 20.0), (44, 30.0), (48, 40.0)].map(|(c, l)| (block("na", c, 20), l)).into();
        assert_eq!(measured_load(&block("na", 36, 80), &na), 25.0);
        assert_eq!(measured_load(&block("na", 40, 20), &[(block("na", 36, 80), 30.0)]), 30.0);
        assert_eq!(measured_load(&block("na", 149, 80), &na), 0.0, "nothing measured there");
        // So an AP on 6 alone in an even environment stays there.
        let spectrum: Vec<SpectrumRow> = (1..=13).map(|c| ("a".to_string(), c, Some(20), Some(-80.0), Some(10.0))).collect();
        let plan = plan_channels("ng".into(), false, None, HashSet::new(), vec![ng_ap("a", 6, 3)], HashMap::new(), vec![], spectrum);
        assert!(!plan.accepted && !plan.plan[0].change, "{plan:?}");
    }

    #[test]
    fn a_channel_the_planner_would_not_pick_is_left_unless_not_allowed() {
        // Channel 13 is not among the planner's own 1, 6 and 11, nor 165 among
        // its 5 GHz blocks; nothing is better elsewhere, so neither moves.
        let plan = plan_channels("ng".into(), false, None, HashSet::new(), vec![ng_ap("a", 13, 1)], HashMap::new(), vec![], vec![]);
        assert!(!plan.accepted && !plan.plan[0].change && !plan.plan[0].not_allowed, "{plan:?}");
        let ap = PlanAp { mac: "b".into(), name: None, current: block("na", 165, 20), width: 20, clients: 1, available: None, legal: crate::settings::legal_channels(Some(840), "na", 20, false) };
        let plan = plan_channels("na".into(), false, None, HashSet::new(), vec![ap], HashMap::new(), vec![], vec![]);
        assert!(!plan.accepted && !plan.plan[0].change, "{plan:?}");
        // Settings that leave 13 out move it.
        let plan = plan_channels("ng".into(), false, Some(vec![1, 6, 11]), HashSet::new(), vec![ng_ap("a", 13, 1)], HashMap::new(), vec![], vec![]);
        assert!(plan.accepted && plan.plan[0].change && plan.plan[0].not_allowed, "{plan:?}");
    }
}
