//! Persistent index allocation (the official controller's `config_meta` collection).
//!
//! Section numbers (`aaa.N`, `wireless.N`), VAP interface names, `netconf.N` and bridge
//! (port) indices are sticky: an entry that still exists keeps its numbers, new entries
//! take the lowest free ones, and entries that disappeared free theirs. So deleting a
//! WLAN leaves a gap instead of renumbering everything after it.

use serde_json::{Value, json};

use crate::Ctx;
use crate::json::{arr, int_of, mac_eq, str_of};

#[derive(Clone)]
struct Wifi {
    id: String,
    radio: String,
    device_name: String,
    vap_index: u32,
    on_radio: u32,
    section: u32,
    first_on_radio: bool,
}

/// Where one deployed VAP lives.
#[derive(Clone, Debug)]
pub struct WifiSlot {
    pub section: u32,
    pub device_name: String,
    pub on_radio: u32,
    pub first_on_radio: bool,
}

#[derive(Default)]
pub struct Meta {
    doc_id: Option<Value>,
    flags: i64,
    old_wifi: Vec<Wifi>,
    old_netconf: Vec<(String, u32)>,
    old_bridges: Vec<(String, u32)>,
    old_ports: Vec<(String, String, u32)>,
    wifi: Vec<Wifi>,
    netconf: Vec<(String, u32)>,
    bridges: Vec<(String, u32)>,
    ports: Vec<(String, String, u32)>,
}

fn lowest_free(used: impl Iterator<Item = u32> + Clone, min: u32) -> u32 {
    (min..).find(|n| !used.clone().any(|u| u == *n)).unwrap_or(min)
}

fn num(v: &Value, key: &str) -> u32 {
    int_of(v, key).unwrap_or(0).max(0) as u32
}

impl Meta {
    /// `flags` are the device flags the numbering was made for (1 = QCA "v2" VAP names);
    /// a stored document made under other flags is ignored.
    pub fn load(ctx: &Ctx, flags: i64) -> Meta {
        let doc = arr(ctx.state, "config_meta").iter().find(|d| {
            str_of(d, "mac").is_some_and(|m| mac_eq(m, &ctx.mac))
                && str_of(d, "site_id").is_none_or(|s| s == ctx.site_id)
        });
        let mut meta = Meta { flags, ..Meta::default() };
        let Some(doc) = doc else { return meta };
        meta.doc_id = doc.get("_id").cloned();
        if int_of(doc, "flags").unwrap_or(0) != flags {
            return meta;
        }
        let s = |v: &Value, k: &str| str_of(v, k).unwrap_or_default().to_string();
        meta.old_wifi = arr(doc, "wireless")
            .iter()
            .filter(|w| int_of(w, "flags").unwrap_or(0) == 0 && !crate::json::flag(w, "station_mode", false))
            .map(|w| Wifi {
                id: s(w, "id_or_name"),
                radio: s(w, "radio_name"),
                device_name: s(w, "device_name"),
                vap_index: num(w, "vap_index"),
                on_radio: num(w, "vap_index_on_radio"),
                section: num(w, "section_index"),
                first_on_radio: crate::json::flag(w, "first_on_radio", false),
            })
            .collect();
        meta.old_netconf = arr(doc, "netconf").iter().map(|n| (s(n, "device_name"), num(n, "section_index"))).collect();
        meta.old_bridges = arr(doc, "bridge_index").iter().map(|b| (s(b, "bridge_name"), num(b, "section_index"))).collect();
        meta.old_ports = arr(doc, "bridge_port")
            .iter()
            .map(|p| (s(p, "bridge_name"), s(p, "device_name"), num(p, "port_index")))
            .collect();
        meta
    }

    /// Allocates the VAPs `(wlan id, radio name)` in deploy order. `name` builds an
    /// interface name from radio name and global VAP index.
    pub fn wireless(&mut self, wanted: &[(String, String)], name: impl Fn(&str, u32) -> String) -> Vec<WifiSlot> {
        let mut kept: Vec<Option<Wifi>> = wanted
            .iter()
            .map(|(id, radio)| {
                let pos = self.old_wifi.iter().position(|w| &w.id == id && &w.radio == radio)?;
                Some(self.old_wifi.remove(pos))
            })
            .collect();
        let mut taken: Vec<Wifi> = kept.iter().flatten().cloned().collect();
        for (slot, (id, radio)) in kept.iter_mut().zip(wanted) {
            if slot.is_some() {
                continue;
            }
            let section = lowest_free(taken.iter().map(|w| w.section), 1);
            let vap_index = lowest_free(taken.iter().map(|w| w.vap_index), 0);
            let on_radio = lowest_free(taken.iter().filter(|w| &w.radio == radio).map(|w| w.on_radio), 0);
            let w = Wifi {
                id: id.clone(),
                radio: radio.clone(),
                device_name: name(radio, vap_index),
                vap_index,
                on_radio,
                section,
                first_on_radio: on_radio == 0,
            };
            taken.push(w.clone());
            *slot = Some(w);
        }
        self.wifi = kept.into_iter().flatten().collect();
        self.wifi
            .iter()
            .map(|w| WifiSlot {
                section: w.section,
                device_name: w.device_name.clone(),
                on_radio: w.on_radio,
                first_on_radio: w.first_on_radio,
            })
            .collect()
    }

    fn keyed(old: &[(String, u32)], names: &[String]) -> Vec<(String, u32)> {
        let mut out: Vec<(String, Option<u32>)> =
            names.iter().map(|n| (n.clone(), old.iter().find(|(o, _)| o == n).map(|(_, i)| *i))).collect();
        for i in 0..out.len() {
            if out[i].1.is_none() {
                let free = lowest_free(out.iter().filter_map(|(_, i)| *i), 1);
                out[i].1 = Some(free);
            }
        }
        out.into_iter().map(|(n, i)| (n, i.unwrap_or(1))).collect()
    }

    /// `netconf.N` indices for interfaces in output order.
    pub fn netconf(&mut self, names: &[String]) -> Vec<u32> {
        self.netconf = Self::keyed(&self.old_netconf, names);
        self.netconf.iter().map(|(_, i)| *i).collect()
    }

    /// `bridge.N` indices for bridges in output order.
    pub fn bridges(&mut self, names: &[String]) -> Vec<u32> {
        self.bridges = Self::keyed(&self.old_bridges, names);
        self.bridges.iter().map(|(_, i)| *i).collect()
    }

    /// Port indices of one bridge's ports, given in insertion order. Ports that already
    /// had an index come first (in insertion order), then the newly numbered ones; that
    /// is the order the official controller writes them in.
    pub fn ports(&mut self, bridge: &str, devs: &[String]) -> Vec<(String, u32)> {
        let mut known = Vec::new();
        let mut fresh = Vec::new();
        for dev in devs {
            match self.old_ports.iter().find(|(b, d, _)| b == bridge && d == dev) {
                Some((_, _, i)) => known.push((dev.clone(), *i)),
                None => fresh.push(dev.clone()),
            }
        }
        for dev in fresh {
            let i = lowest_free(known.iter().map(|(_, i)| *i), 1);
            known.push((dev, i));
        }
        self.ports.extend(known.iter().map(|(d, i)| (bridge.to_string(), d.clone(), *i)));
        known
    }

    pub fn to_doc(&self, site_id: &str, mac: &str) -> Value {
        let mut doc = json!({
            "site_id": site_id,
            "mac": mac,
            "wireless": self.wifi.iter().map(|w| json!({
                "id_or_name": w.id,
                "radio_name": w.radio,
                "device_name": w.device_name,
                "vap_index": w.vap_index,
                "vap_index_on_radio": w.on_radio,
                "section_index": w.section,
                "flags": 0,
                "first_on_radio": w.first_on_radio,
                "station_mode": false,
            })).collect::<Vec<_>>(),
            "bridge_port": self.ports.iter().map(|(b, d, i)| json!({
                "bridge_name": b, "device_name": d, "port_index": i,
            })).collect::<Vec<_>>(),
            "bridge_index": self.bridges.iter().map(|(b, i)| json!({
                "bridge_name": b, "section_index": i,
            })).collect::<Vec<_>>(),
            "netconf": self.netconf.iter().map(|(d, i)| json!({
                "device_name": d, "section_index": i,
            })).collect::<Vec<_>>(),
            "flags": self.flags,
        });
        if let (Some(id), Some(obj)) = (&self.doc_id, doc.as_object_mut()) {
            obj.insert("_id".into(), id.clone());
        }
        doc
    }
}
