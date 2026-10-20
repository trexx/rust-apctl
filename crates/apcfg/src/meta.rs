//! Persistent index allocation (the official controller's `config_meta` collection).
//!
//! Section numbers (`aaa.N`, `wireless.N`), VAP interface names, `netconf.N` and bridge
//! (port) indices are sticky: an entry that still exists keeps its numbers, new entries
//! take the lowest free ones, and entries that disappeared free theirs. So deleting a
//! WLAN leaves a gap instead of renumbering everything after it.

use std::collections::HashSet;

use serde_json::{Value, json};

use crate::Ctx;
use crate::json::{arr, int_of, mac_eq, str_of};

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
    /// Section numbers of every stored VAP, those of VAPs this render drops included.
    old_sections: Vec<u32>,
    old_netconf: Vec<(String, u32)>,
    old_bridges: Vec<(String, u32)>,
    old_ports: Vec<(String, String, u32)>,
    wifi: Vec<Wifi>,
    netconf: Vec<(String, u32)>,
    bridges: Vec<(String, u32)>,
    ports: Vec<(String, String, u32)>,
}

/// Keeps the number of each entry that had one, and gives the others, in order, the lowest
/// numbers from `min` up that no entry has.
fn allocate(old: impl IntoIterator<Item = Option<u32>>, min: u32) -> Vec<u32> {
    allocate_besides(old, min, [])
}

/// [`allocate`], also leaving out the numbers in `taken`.
fn allocate_besides(old: impl IntoIterator<Item = Option<u32>>, min: u32, taken: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let old: Vec<Option<u32>> = old.into_iter().collect();
    let used: HashSet<u32> = old.iter().flatten().copied().chain(taken).collect();
    let mut free = min;
    old.into_iter()
        .map(|n| {
            n.unwrap_or_else(|| {
                // Numbers handed out only go up, so the search goes on from the last one.
                while used.contains(&free) {
                    free += 1;
                }
                free += 1;
                free - 1
            })
        })
        .collect()
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
        meta.old_sections = arr(doc, "wireless").iter().map(|w| num(w, "section_index")).collect();
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
    ///
    /// A new VAP's section number is one no stored VAP had, not even one leaving in this
    /// render; VAP and on-radio indices only avoid those of the VAPs that stay. On each
    /// radio exactly one VAP is `first_on_radio` (it gets the radio's main lines): the
    /// one at on-radio index 0 if there is one, else the only one already marked, else
    /// the one with the lowest index.
    pub fn wireless(&mut self, wanted: &[(&str, &str)], name: impl Fn(&str, u32) -> String) -> Vec<WifiSlot> {
        let kept: Vec<Option<Wifi>> = wanted
            .iter()
            .map(|(id, radio)| {
                let pos = self.old_wifi.iter().position(|w| w.id == *id && w.radio == *radio)?;
                Some(self.old_wifi.remove(pos))
            })
            .collect();
        let sections = allocate_besides(kept.iter().map(|w| w.as_ref().map(|w| w.section)), 1, self.old_sections.iter().copied());
        let vap_indices = allocate(kept.iter().map(|w| w.as_ref().map(|w| w.vap_index)), 0);
        // Numbered per radio.
        let mut on_radio = vec![0; wanted.len()];
        let mut radios: Vec<&str> = wanted.iter().map(|(_, radio)| *radio).collect();
        radios.sort_unstable();
        radios.dedup();
        for &radio in &radios {
            let at: Vec<usize> = (0..wanted.len()).filter(|&i| wanted[i].1 == radio).collect();
            let nums = allocate(at.iter().map(|&i| kept[i].as_ref().map(|w| w.on_radio)), 0);
            for (i, n) in at.into_iter().zip(nums) {
                on_radio[i] = n;
            }
        }
        self.wifi = kept
            .into_iter()
            .zip(wanted)
            .enumerate()
            .map(|(i, (w, (id, radio)))| {
                w.unwrap_or_else(|| Wifi {
                    id: id.to_string(),
                    radio: radio.to_string(),
                    device_name: name(radio, vap_indices[i]),
                    vap_index: vap_indices[i],
                    on_radio: on_radio[i],
                    section: sections[i],
                    first_on_radio: false,
                })
            })
            .collect();
        for radio in radios {
            let on = || self.wifi.iter().filter(|w| w.radio == radio);
            let main = if on().any(|w| w.on_radio == 0) {
                0
            } else if on().filter(|w| w.first_on_radio).count() == 1 {
                continue;
            } else {
                on().map(|w| w.on_radio).min().unwrap_or(0)
            };
            for w in self.wifi.iter_mut().filter(|w| w.radio == radio) {
                w.first_on_radio = w.on_radio == main;
            }
        }
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

    fn keyed(old: &[(String, u32)], names: &[impl AsRef<str>]) -> Vec<(String, u32)> {
        let nums = allocate(names.iter().map(|n| old.iter().find(|(o, _)| o == n.as_ref()).map(|(_, i)| *i)), 1);
        names.iter().zip(nums).map(|(n, i)| (n.as_ref().to_string(), i)).collect()
    }

    /// `netconf.N` indices for interfaces in output order.
    pub fn netconf(&mut self, names: &[&str]) -> Vec<u32> {
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
    pub fn ports<'d>(&mut self, bridge: &str, devs: &'d [String]) -> Vec<(&'d str, u32)> {
        let old: Vec<Option<u32>> =
            devs.iter().map(|dev| self.old_ports.iter().find(|(b, d, _)| b == bridge && d == dev).map(|(_, _, i)| *i)).collect();
        let nums = allocate(old.iter().copied(), 1);
        let mut out = Vec::with_capacity(devs.len());
        for fresh in [false, true] {
            out.extend(devs.iter().zip(&old).zip(&nums).filter(|((_, o), _)| o.is_none() == fresh).map(|((d, _), &i)| (d.as_str(), i)));
        }
        self.ports.extend(out.iter().map(|&(d, i)| (bridge.to_string(), d.to_string(), i)));
        out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_numbers_are_kept_and_new_ones_fill_the_gaps() {
        assert_eq!(allocate([Some(2), None, Some(4), None, None], 1), vec![2, 1, 4, 3, 5]);
        assert_eq!(allocate([None, Some(0), None, Some(0)], 0), vec![1, 0, 2, 0]);
        assert_eq!(allocate([None, None], 1), vec![1, 2]);
    }

    /// A stored VAP: `(wlan id, radio, on-radio index, section, first_on_radio)`.
    fn stored(vaps: &[(&str, &str, u32, u32, bool)]) -> Meta {
        let old_wifi: Vec<Wifi> = vaps
            .iter()
            .enumerate()
            .map(|(i, &(id, radio, on_radio, section, first_on_radio))| Wifi {
                id: id.into(),
                radio: radio.into(),
                device_name: format!("{radio}ap{i}"),
                vap_index: i as u32,
                on_radio,
                section,
                first_on_radio,
            })
            .collect();
        Meta { old_sections: old_wifi.iter().map(|w| w.section).collect(), old_wifi, ..Meta::default() }
    }

    /// `(on-radio index, section, first_on_radio)` of each wanted VAP.
    fn slots(meta: &mut Meta, wanted: &[(&str, &str)]) -> Vec<(u32, u32, bool)> {
        meta.wireless(wanted, |radio, k| format!("{radio}ap{k}")).iter().map(|s| (s.on_radio, s.section, s.first_on_radio)).collect()
    }

    #[test]
    fn the_vap_at_index_0_or_else_the_lowest_one_is_first_on_its_radio() {
        // The radio's first SSID is deleted: B, at on-radio index 1, takes over the main lines.
        let mut meta = stored(&[("a", "wifi0", 0, 1, true), ("b", "wifi0", 1, 2, false), ("b", "wifi1", 0, 3, true)]);
        assert_eq!(slots(&mut meta, &[("b", "wifi0"), ("b", "wifi1")]), [(1, 2, true), (0, 3, true)]);
        // A single marked VAP not at index 0 stays marked.
        let mut meta = stored(&[("b", "wifi0", 1, 2, true), ("c", "wifi0", 2, 3, false)]);
        assert_eq!(slots(&mut meta, &[("b", "wifi0"), ("c", "wifi0")]), [(1, 2, true), (2, 3, false)]);
        // A new VAP at index 0 takes the mark from it, so only one VAP has it.
        let mut meta = stored(&[("b", "wifi0", 1, 2, true)]);
        assert_eq!(slots(&mut meta, &[("b", "wifi0"), ("n", "wifi0")]), [(1, 2, false), (0, 1, true)]);
        // None or several marked and no index 0: the lowest index.
        let mut meta = stored(&[("b", "wifi0", 2, 2, true), ("c", "wifi0", 1, 3, true)]);
        assert_eq!(slots(&mut meta, &[("b", "wifi0"), ("c", "wifi0")]), [(2, 2, false), (1, 3, true)]);
        let mut meta = stored(&[("b", "wifi0", 2, 2, false), ("c", "wifi0", 1, 3, false)]);
        assert_eq!(slots(&mut meta, &[("b", "wifi0"), ("c", "wifi0")]), [(2, 2, false), (1, 3, true)]);
    }

    #[test]
    fn a_new_vap_skips_the_section_of_a_vap_leaving_in_the_same_render() {
        // A moves from 2.4 to 5 GHz: its new VAP does not reuse section 1, which it leaves.
        let mut meta = stored(&[("a", "wifi0", 0, 1, true), ("b", "wifi0", 1, 2, false), ("b", "wifi1", 0, 3, true)]);
        assert_eq!(slots(&mut meta, &[("a", "wifi1"), ("b", "wifi0"), ("b", "wifi1")]), [(1, 4, false), (1, 2, true), (0, 3, true)]);
        // The next render frees it.
        let mut meta = stored(&[("a", "wifi1", 1, 4, false), ("b", "wifi0", 1, 2, true), ("b", "wifi1", 0, 3, true)]);
        assert_eq!(slots(&mut meta, &[("a", "wifi1"), ("b", "wifi0"), ("b", "wifi1"), ("c", "wifi0")]), [(1, 4, false), (1, 2, false), (0, 3, true), (0, 1, true)]);
    }
}
