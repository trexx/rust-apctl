//! Per-client speed limits. A client with a user group of its own, different
//! from its SSID's, is limited by a command to the AP it is on, as the official
//! controller does it:
//! `{"_type":"cmd","cmd":"rate-update","mac","dl_max","dl_min":64,"ul_max","ul_min":64}`
//! (kbps, -1 unlimited). It is sent when the client connects or roams, and again
//! when its limit or the group changes; when the client's own limit is removed,
//! its SSID's limit is sent instead. SSID-wide limits are in the config (`apcfg`).

use std::collections::HashMap;
use std::time::Duration;

use inform::Mac;
use serde_json::{Value, json};

use crate::api::AppState;
use crate::engine::Live;
use crate::settings::{docs, id_of};

/// What was last sent for a client: the AP, the SSID and the limits.
type Sent = HashMap<Mac, (Mac, String, (i64, i64))>;

fn limits(state: &Value, group: &str) -> Option<(i64, i64)> {
    let g = docs(state, "usergroup").find(|g| id_of(g).as_deref() == Some(group))?;
    Some((g["qos_rate_max_down"].as_i64().unwrap_or(-1), g["qos_rate_max_up"].as_i64().unwrap_or(-1)))
}

/// The limits a connected client should get by command: its own group's when
/// that differs from its SSID's, else (if a command was sent before) the SSID's.
fn wanted(state: &Value, client: &Mac, essid: &str, before: bool) -> Option<(i64, i64)> {
    let own = state["clients"]
        .as_array()?
        .iter()
        .find(|c| c["mac"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(&client.to_string())))
        .and_then(|c| c["usergroup_id"].as_str())
        .filter(|g| !g.is_empty());
    let ssid_group = docs(state, "wlanconf").find(|w| w["name"].as_str() == Some(essid)).and_then(|w| w["usergroup_id"].as_str()).map(str::to_string).or_else(|| crate::settings::default_usergroup(state));
    match own {
        Some(g) if Some(g) != ssid_group.as_deref() => limits(state, g),
        // Back to the SSID's limit, but only to undo an earlier command.
        _ if before => Some(ssid_group.and_then(|g| limits(state, &g)).unwrap_or((-1, -1))),
        _ => None,
    }
}

/// Queues the commands due now and updates `sent`.
pub fn tick(live: &mut Live, sent: &mut Sent) {
    let Some(state) = live.state.clone() else { return };
    let connected: Vec<(Mac, Mac, String)> = live.clients.iter().filter(|(_, c)| c.connected).map(|(m, c)| (*m, c.sample.ap_mac, c.sample.essid.clone().unwrap_or_default())).collect();
    sent.retain(|m, _| connected.iter().any(|c| c.0 == *m));
    for (client, ap, essid) in connected {
        let before = sent.get(&client);
        // A roam or SSID change starts afresh: the new AP knows nothing of earlier commands.
        let same_place = before.is_some_and(|b| b.0 == ap && b.1 == essid);
        let Some(limit) = wanted(&state, &client, &essid, same_place) else {
            sent.remove(&client);
            continue;
        };
        if same_place && before.is_some_and(|b| b.2 == limit) {
            continue;
        }
        let (down, up) = limit;
        crate::actions::queue(live, ap, json!({ "_type": "cmd", "cmd": "rate-update", "mac": client.to_string(), "dl_max": down, "dl_min": 64, "ul_max": up, "ul_min": 64 }));
        tracing::info!("{client}: speed limit down {down} up {up} kbps via {ap}");
        sent.insert(client, (ap, essid, limit));
    }
}

/// Keeps per-client limits in force (active mode only).
pub fn spawn(s: AppState) {
    if !s.active {
        return;
    }
    tokio::spawn(async move {
        let mut sent = Sent::new();
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            tick(&mut s.live.write().unwrap(), &mut sent);
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
        live.clients.insert(C.parse().unwrap(), ClientView { sample, connected: true, first_seen: 0, last_seen: 0 });
        live
    }

    fn sent_to(live: &mut Live, ap: &str) -> Vec<Value> {
        let ap: Mac = ap.parse().unwrap();
        std::iter::from_fn(|| crate::actions::next(live, &ap)).collect()
    }

    #[test]
    fn a_clients_own_limit_is_sent_once_then_again_after_a_roam() {
        let mut live = live(Some("slow"));
        let mut sent = Sent::new();
        tick(&mut live, &mut sent);
        let cmds = sent_to(&mut live, AP1);
        assert_eq!(cmds.len(), 1);
        assert_eq!((cmds[0]["cmd"].as_str(), cmds[0]["dl_max"].as_i64(), cmds[0]["ul_max"].as_i64(), cmds[0]["mac"].as_str()), (Some("rate-update"), Some(2000), Some(500), Some(C)));
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty(), "not repeated");
        live.clients.get_mut(&C.parse().unwrap()).unwrap().sample.ap_mac = AP2.parse().unwrap();
        tick(&mut live, &mut sent);
        assert_eq!(sent_to(&mut live, AP2).len(), 1, "the new AP gets it");
    }

    #[test]
    fn removing_the_limit_restores_the_ssids() {
        let mut live = live(Some("slow"));
        let mut sent = Sent::new();
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
    fn clients_without_their_own_limit_get_no_command() {
        let mut live = live(None);
        let mut sent = Sent::new();
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty());
        // Same group as the SSID: nothing to do either.
        let mut live = self::live(Some("def"));
        tick(&mut live, &mut sent);
        assert!(sent_to(&mut live, AP1).is_empty());
    }
}
