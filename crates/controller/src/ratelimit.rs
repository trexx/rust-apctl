//! Per-client speed limits. A client with a user group of its own, different
//! from its SSID's, is limited by a command to the AP it is on, as the official
//! controller does it:
//! `{"_type":"cmd","cmd":"rate-update","mac","dl_max","dl_min":64,"ul_max","ul_min":64}`
//! (kbps, -1 unlimited). It is sent when the client connects, roams to another
//! AP or associates again (its uptime drops, as when it changes band on the same
//! AP), and again when its limit or the group changes; when the client's own limit is removed,
//! its SSID's limit is sent instead. SSID-wide limits are in the config (`apcfg`).

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use inform::Mac;
use serde_json::{Value, json};

use crate::api::AppState;
use crate::engine::Live;
use crate::settings::{doc_mac, docs, id_of};

/// What was last sent for a client.
struct Sent {
    ap: Mac,
    essid: String,
    /// (down, up) kbps.
    limit: (i64, i64),
    /// The client's association uptime when last looked at: a drop is a new association.
    uptime: Option<i64>,
}

/// What the limits depend on in the settings, worked out again only when they
/// change (every change replaces the settings' Arc).
#[derive(Default)]
struct Groups {
    /// The settings these were read from, by address: the Weak keeps the
    /// address from being reused without keeping old settings alive.
    state: Weak<Value>,
    /// The clients with a group of their own (their first entry in the site's), and that group.
    own: HashMap<Mac, String>,
    /// Each SSID's group as the config applies it (see `apcfg::ssid_usergroup`), by
    /// name (the first SSID of that name): none when the site has no Default group.
    ssid: HashMap<String, Option<String>>,
    default: Option<String>,
    /// (down, up) kbps per group.
    limits: HashMap<String, (i64, i64)>,
}

impl Groups {
    fn refresh(&mut self, state: &Arc<Value>) {
        if std::ptr::eq(self.state.as_ptr(), Arc::as_ptr(state)) {
            return;
        }
        let mut g = Groups { state: Arc::downgrade(state), default: crate::settings::default_usergroup(state), ..Default::default() };
        let mut own = HashMap::new();
        for c in docs(state, "clients") {
            if let Some(mac) = doc_mac(&c["mac"]) {
                own.entry(mac).or_insert_with(|| c["usergroup_id"].as_str().filter(|id| !id.is_empty()).map(str::to_string));
            }
        }
        g.own = own.into_iter().filter_map(|(mac, group)| Some((mac, group?))).collect();
        let site = crate::settings::site_id(state).unwrap_or_default();
        for w in docs(state, "wlanconf") {
            if let Some(name) = w["name"].as_str() {
                // No group, an empty id or one naming no group is the Default group, as in the config.
                g.ssid.entry(name.to_string()).or_insert_with(|| apcfg::ssid_usergroup(state, site, w).and_then(id_of));
            }
        }
        for u in docs(state, "usergroup") {
            if let Some(id) = id_of(u) {
                g.limits.entry(id).or_insert(apcfg::usergroup_limits(u));
            }
        }
        *self = g;
    }

    /// The limits a connected client should get by command: its own group's
    /// when that differs from its SSID's, else (if a command was sent
    /// `before`) the SSID's.
    fn wanted(&self, client: &Mac, essid: &str, before: bool) -> Option<(i64, i64)> {
        let own = self.own.get(client).map(String::as_str);
        // Most clients have no group of their own and were never sent one.
        if own.is_none() && !before {
            return None;
        }
        let ssid_group = self.ssid.get(essid).and_then(Option::as_deref).or(self.default.as_deref());
        // A group missing from the settings (as after an import) counts as none.
        match own.filter(|g| Some(*g) != ssid_group).and_then(|g| self.limits.get(g)) {
            Some(limit) => Some(*limit),
            // Back to the SSID's limit, but only to undo an earlier command.
            None if before => Some(ssid_group.and_then(|g| self.limits.get(g).copied()).unwrap_or((-1, -1))),
            None => None,
        }
    }
}

/// What the watcher keeps between ticks.
#[derive(Default)]
struct Limits {
    sent: HashMap<Mac, Sent>,
    groups: Groups,
}

/// The commands due now, as (AP, command); updates what was sent.
fn due(live: &Live, l: &mut Limits) -> Vec<(Mac, Value)> {
    let Some(state) = &live.state else { return Vec::new() };
    l.groups.refresh(state);
    // The usual case: no client has a group of its own, and none was ever limited.
    if l.groups.own.is_empty() && l.sent.is_empty() {
        return Vec::new();
    }
    l.sent.retain(|m, _| live.connected.contains(m));
    // Only a client with a group of its own, or one sent a command before, can need one.
    let own = &l.groups.own;
    let candidates: Vec<Mac> = own.keys().chain(l.sent.keys().filter(|m| !own.contains_key(*m))).copied().collect();
    let mut out = Vec::new();
    for client in &candidates {
        let Some(c) = live.clients.get(client).filter(|c| c.connected) else { continue };
        let (ap, essid, uptime) = (c.sample.ap_mac, c.sample.essid.as_deref().unwrap_or_default(), c.sample.uptime);
        let before = l.sent.get(client);
        // A roam, a new association on the same AP (as the official controller
        // tells by a drop in uptime) or an SSID change starts afresh: the AP
        // has forgotten earlier commands.
        let reassociated = |b: &Sent| matches!((b.uptime, uptime), (Some(was), Some(now)) if now < was);
        let same_place = before.is_some_and(|b| b.ap == ap && b.essid == essid && !reassociated(b));
        let Some(limit) = l.groups.wanted(client, essid, same_place) else {
            l.sent.remove(client);
            continue;
        };
        if same_place && before.is_some_and(|b| b.limit == limit) {
            if let Some(b) = l.sent.get_mut(client) {
                b.uptime = uptime;
            }
            continue;
        }
        let (down, up) = limit;
        out.push((ap, json!({ "_type": "cmd", "cmd": "rate-update", "mac": client.to_string(), "dl_max": down, "dl_min": 64, "ul_max": up, "ul_min": 64 })));
        tracing::info!("{client}: speed limit down {down} up {up} kbps via {ap}");
        l.sent.insert(*client, Sent { ap, essid: essid.to_string(), limit, uptime });
    }
    out
}

/// Queues the commands due now and updates what was sent.
#[cfg(test)]
fn tick(live: &mut Live, l: &mut Limits) {
    for (ap, cmd) in due(live, l) {
        crate::actions::queue(live, ap, cmd);
    }
}

/// Keeps per-client limits in force (active mode only).
pub fn spawn(s: AppState) {
    if !s.active {
        return;
    }
    tokio::spawn(async move {
        let mut limits = Limits::default();
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            // Worked out under the read lock; the write lock only to queue.
            let cmds = due(&s.live.read().unwrap(), &mut limits);
            if !cmds.is_empty() {
                let mut live = s.live.write().unwrap();
                for (ap, cmd) in cmds {
                    crate::actions::queue(&mut live, ap, cmd);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ClientView;

    const AP1: &str = "02:00:00:00:00:01";
    const AP2: &str = "02:00:00:00:00:02";
    const C: &str = "aa:bb:cc:00:00:01";

    fn live(client_group: Option<&str>) -> Live {
        let mut live = Live::default();
        let mut clients = vec![];
        if let Some(g) = client_group {
            clients.push(json!({ "mac": C, "usergroup_id": g }));
        }
        live.state = Some(std::sync::Arc::new(json!({
            "usergroup": [
                { "_id": "def", "name": "Default", "attr_hidden_id": "Default", "qos_rate_max_down": -1, "qos_rate_max_up": -1 },
                { "_id": "slow", "name": "Slow", "qos_rate_max_down": 2000, "qos_rate_max_up": 500 },
            ],
            "wlanconf": [{ "name": "Home", "usergroup_id": "def" }],
            "clients": clients,
        })));
        let sample = crate::model::ClientSample { mac: C.parse().unwrap(), ap_mac: AP1.parse().unwrap(), essid: Some("Home".into()), ..Default::default() };
        live.put_client(ClientView { sample: std::sync::Arc::new(sample), connected: true, first_seen: 0, last_seen: 0 });
        live
    }

    fn sent_to(live: &mut Live, ap: &str) -> Vec<Value> {
        let ap: Mac = ap.parse().unwrap();
        std::iter::from_fn(|| crate::actions::next(live, &ap)).collect()
    }

    #[test]
    fn a_clients_own_limit_is_sent_once_then_again_after_a_roam() {
        let mut live = live(Some("slow"));
        let mut sent = Limits::default();
        tick(&mut live, &mut sent);
        let cmds = sent_to(&mut live, AP1);
        assert_eq!(cmds.len(), 1);
        assert_eq!((cmds[0]["cmd"].as_str(), cmds[0]["dl_max"].as_i64(), cmds[0]["ul_max"].as_i64(), cmds[0]["mac"].as_str()), (Some("rate-update"), Some(2000), Some(500), Some(C)));
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty(), "not repeated");
        assert_eq!(Arc::strong_count(live.state.as_ref().unwrap()), 1, "what was read of the settings does not keep them");
        std::sync::Arc::make_mut(&mut live.clients.get_mut(&C.parse().unwrap()).unwrap().sample).ap_mac = AP2.parse().unwrap();
        tick(&mut live, &mut sent);
        assert_eq!(sent_to(&mut live, AP2).len(), 1, "the new AP gets it");
    }

    #[test]
    fn a_new_association_on_the_same_ap_is_sent_the_limit_again() {
        let mut live = live(Some("slow"));
        let set = |live: &mut Live, uptime, radio: &str| {
            let s = std::sync::Arc::make_mut(&mut live.clients.get_mut(&C.parse().unwrap()).unwrap().sample);
            (s.uptime, s.radio) = (Some(uptime), Some(radio.into()));
        };
        set(&mut live, 100, "na");
        let mut sent = Limits::default();
        tick(&mut live, &mut sent);
        assert_eq!(sent_to(&mut live, AP1).len(), 1);
        set(&mut live, 400, "na");
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty(), "still the same association");
        // Off to the other band (or back after a moment away): its uptime starts again.
        set(&mut live, 3, "ng");
        tick(&mut live, &mut sent);
        assert_eq!(sent_to(&mut live, AP1).len(), 1, "the AP is told again");
        set(&mut live, 20, "ng");
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty());
    }

    #[test]
    fn removing_the_limit_restores_the_ssids() {
        let mut live = live(Some("slow"));
        let mut sent = Limits::default();
        tick(&mut live, &mut sent);
        sent_to(&mut live, AP1);
        let mut state = (**live.state.as_ref().unwrap()).clone();
        state["clients"][0]["usergroup_id"] = Value::Null;
        live.state = Some(std::sync::Arc::new(state));
        tick(&mut live, &mut sent);
        let cmds = sent_to(&mut live, AP1);
        assert_eq!((cmds.len(), cmds[0]["dl_max"].as_i64()), (1, Some(-1)));
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty());
    }

    #[test]
    fn a_client_whose_group_is_gone_gets_the_ssids_limit_back() {
        let mut live = live(Some("slow"));
        let mut sent = Limits::default();
        tick(&mut live, &mut sent);
        sent_to(&mut live, AP1);
        let mut state = (**live.state.as_ref().unwrap()).clone();
        state["clients"][0]["usergroup_id"] = json!("imported-elsewhere");
        live.state = Some(std::sync::Arc::new(state));
        tick(&mut live, &mut sent);
        let cmds = sent_to(&mut live, AP1);
        assert_eq!((cmds.len(), cmds[0]["dl_max"].as_i64()), (1, Some(-1)));
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty());
        // Never limited: nothing to undo.
        let mut live = self::live(Some("imported-elsewhere"));
        tick(&mut live, &mut Limits::default());
        assert!(sent_to(&mut live, AP1).is_empty());
    }

    #[test]
    fn an_ssid_with_an_empty_or_unknown_group_has_the_default_groups_limit() {
        // As the config applies it: an empty id or one naming no group is the Default
        // group, and a limit stored as text or as a whole float is still a limit.
        for (ssid_group, limit) in [("", json!(8000)), ("deleted", json!("8000")), ("", json!(8000.0))] {
            let mut live = live(Some("slow"));
            let mut state = (**live.state.as_ref().unwrap()).clone();
            state["usergroup"][0]["qos_rate_max_down"] = limit;
            state["wlanconf"][0]["usergroup_id"] = json!(ssid_group);
            live.state = Some(std::sync::Arc::new(state.clone()));
            let mut sent = Limits::default();
            tick(&mut live, &mut sent);
            sent_to(&mut live, AP1);
            state["clients"][0]["usergroup_id"] = Value::Null;
            live.state = Some(std::sync::Arc::new(state));
            tick(&mut live, &mut sent);
            assert_eq!(sent_to(&mut live, AP1)[0]["dl_max"].as_i64(), Some(8000), "{ssid_group:?}");
        }
    }

    #[test]
    fn only_the_sites_client_entries_count() {
        // Another site's entry for the client (first in the list) gives it no limit here.
        let mut live = live(Some("slow"));
        let mut state = (**live.state.as_ref().unwrap()).clone();
        state["devices"] = json!([{ "mac": AP1, "site_id": "s1" }]);
        state["clients"] = json!([{ "mac": C, "usergroup_id": "slow", "site_id": "s2" }, { "mac": C.to_uppercase(), "site_id": "s1" }]);
        live.state = Some(std::sync::Arc::new(state.clone()));
        tick(&mut live, &mut Limits::default());
        assert!(sent_to(&mut live, AP1).is_empty());
        // The site's own entry does, whichever way it writes the MAC.
        state["clients"][1]["usergroup_id"] = json!("slow");
        live.state = Some(std::sync::Arc::new(state));
        tick(&mut live, &mut Limits::default());
        assert_eq!(sent_to(&mut live, AP1).len(), 1);
    }

    #[test]
    fn clients_without_their_own_limit_get_no_command() {
        let mut live = live(None);
        let mut sent = Limits::default();
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty());
        // Same group as the SSID: nothing to do either.
        let mut live = self::live(Some("def"));
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty());
    }
}
