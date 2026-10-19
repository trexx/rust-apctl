//! Bridges, VLAN subinterfaces, `netconf` and the ebtables rules that keep tagged
//! frames off untagged VAPs.

use std::borrow::Cow;

use anyhow::{Result, bail};
use serde_json::Value;

use crate::{Cap, Ctx};
use crate::cfg::{Cfg, Prefix};
use crate::json::{flag, int_of, oid, str_of};
use crate::meta::Meta;
use crate::wlan::{Radio, Vap, dynamic_vlan, network_vlan, vlan_id};

pub struct Bridge {
    pub name: String,
    /// `None` for the untagged (management) bridge.
    pub vlan: Option<u16>,
    pub ports: Vec<String>,
}

pub struct Net {
    pub eth: Vec<String>,
    pub bridges: Vec<Bridge>,
    /// VLANs carried on the trunk, in order of first use.
    pub vlans: Vec<u16>,
    pub ebtables: Vec<String>,
}

pub fn bridge_name(vlan: Option<u16>) -> String {
    vlan.map_or_else(|| "br0".to_string(), |v| format!("br0.{v}"))
}

/// The VLAN a WLAN's clients are tagged with, if any.
pub fn wlan_vlan(ctx: &Ctx, w: &Value) -> Option<u16> {
    if matches!(str_of(w, "security"), Some("wpaeap")) && dynamic_vlan(ctx, w) != 0 {
        return None;
    }
    if let Some(vlan) = network_vlan(ctx, str_of(w, "networkconf_id")) {
        return Some(vlan);
    }
    if flag(w, "vlan_enabled", false) {
        return int_of(w, "vlan").and_then(vlan_id);
    }
    None
}

/// The AP's `config_network` when it has a static address.
pub fn static_ip<'a>(ctx: &Ctx<'a>) -> Option<&'a Value> {
    ctx.device.get("config_network").filter(|cn| str_of(cn, "type") == Some("static"))
}

pub fn build(ctx: &Ctx, radios: &[Radio], vaps: &[Vap]) -> Result<Net> {
    // A tagged management VLAN changes which bridge carries the AP's own address;
    // until that is implemented, refuse rather than cut the AP off.
    if let Some(net) = str_of(ctx.device, "mgmt_network_id").and_then(|id| ctx.network(id))
        && flag(net, "vlan_enabled", false)
        && str_of(net, "attr_hidden_id") != Some("LAN")
    {
        bail!("management VLAN on network {} is not supported", oid(net).unwrap_or_default());
    }
    let mut eth = vec!["eth0".to_string()];
    if ctx.inform.is_some_and(|i| flag(i, "has_eth1", false)) {
        eth.push("eth1".to_string());
    }
    let mut bridges = vec![Bridge { name: bridge_name(None), vlan: None, ports: eth.clone() }];
    let mut vlans: Vec<u16> = Vec::new();
    let mut ebtables = Vec::new();
    for vap in vaps {
        let vlan = vap.vlan;
        if radios[vap.radio].disabled {
            continue;
        }
        let pos = match bridges.iter().position(|b| b.vlan == vlan) {
            Some(p) => p,
            None => {
                bridges.push(Bridge { name: bridge_name(vlan), vlan, ports: Vec::new() });
                bridges.len() - 1
            }
        };
        bridges[pos].ports.push(vap.dev().to_string());
        if let Some(v) = vlan
            && !vlans.contains(&v)
        {
            vlans.push(v);
        }
        if vlan.is_some() || flag(&vap.w, "is_guest", false) {
            ebtables.push(format!("-t broute -A BROUTING -i {} -p 802_1Q -j DROP", vap.dev()));
        }
    }
    for v in &vlans {
        let b = bridges.iter_mut().find(|b| b.vlan == Some(*v)).expect("bridge exists for every VLAN");
        b.ports.extend(eth.iter().map(|e| format!("{e}.{v}")));
        ebtables.push(format!("-t broute -A BROUTING --vlan-id {v} -p 802_1Q -j DROP"));
    }
    Ok(Net { eth, bridges, vlans, ebtables })
}

pub fn render_vlan(c: &mut Cfg, net: &Net) {
    c.header("vlan");
    if net.vlans.is_empty() {
        c.set("vlan.status", "disabled");
        return;
    }
    c.set("vlan.status", "enabled");
    let mut k = 0;
    for v in &net.vlans {
        for dev in &net.eth {
            k += 1;
            c.set(format_args!("vlan.{k}.devname"), dev);
            c.set(format_args!("vlan.{k}.id"), v);
        }
    }
}

pub fn render_bridge(c: &mut Cfg, net: &Net, meta: &mut Meta) {
    c.header("bridge");
    // There is always the untagged bridge.
    c.set("bridge.status", "enabled");
    let names: Vec<&str> = net.bridges.iter().map(|b| b.name.as_str()).collect();
    let indices = meta.bridges(&names);
    for (b, i) in net.bridges.iter().zip(indices) {
        c.set(format_args!("bridge.{i}.devname"), &b.name);
        c.set(format_args!("bridge.{i}.fd"), 1);
        c.set(format_args!("bridge.{i}.stp.status"), "disabled");
        for (dev, p) in meta.ports(&b.name, &b.ports) {
            c.set(format_args!("bridge.{i}.port.{p}.devname"), dev);
        }
    }
}

pub fn render_netconf(c: &mut Cfg, ctx: &Ctx, net: &Net, radios: &[Radio], vaps: &[Vap], meta: &mut Meta) {
    c.header("netconf");
    c.set("netconf.status", "enabled");
    enum Kind {
        Bridge,
        Eth,
        Vap { disabled: bool },
        Sub,
    }
    let mut ifaces: Vec<(Cow<str>, Kind)> = Vec::new();
    ifaces.extend(net.bridges.iter().map(|b| (Cow::Borrowed(b.name.as_str()), Kind::Bridge)));
    ifaces.extend(net.eth.iter().map(|e| (Cow::Borrowed(e.as_str()), Kind::Eth)));
    // A VAP shows as disabled only while the AP still reports it (stored vap_table) and
    // its radio is switched off.
    let reported = |dev: &str| {
        ctx.inform
            .and_then(|i| i.get("vap_table"))
            .and_then(|t| t.as_array())
            .is_some_and(|t| t.iter().any(|v| str_of(v, "name") == Some(dev)))
    };
    for v in vaps {
        let disabled = radios[v.radio].disabled && reported(v.dev());
        ifaces.push((Cow::Borrowed(v.dev()), Kind::Vap { disabled }));
    }
    for v in &net.vlans {
        ifaces.extend(net.eth.iter().map(|e| (Cow::Owned(format!("{e}.{v}")), Kind::Sub)));
    }
    let names: Vec<&str> = ifaces.iter().map(|(n, _)| n.as_ref()).collect();
    let indices = meta.netconf(&names);
    let static_ip = static_ip(ctx);
    // VAPs are brought up by hostapd on APs that run it for every SSID.
    let hostapd_up = ctx.caps.has(Cap::HostapdVaps);
    for ((name, kind), n) in ifaces.iter().zip(indices) {
        let k = Prefix::new("netconf", n as usize);
        let mgmt = name == "br0";
        c.set(k.at("status"), if matches!(kind, Kind::Vap { disabled: true }) { "disabled" } else { "enabled" });
        c.set(k.at("devname"), name);
        let cn = static_ip.filter(|_| mgmt);
        c.set(k.at("ip"), cn.and_then(|cn| str_of(cn, "ip")).unwrap_or("0.0.0.0"));
        c.set(k.at("autoip.status"), "disabled");
        if let Some(cn) = cn {
            c.opt(k.at("netmask"), str_of(cn, "netmask"));
        }
        if matches!(kind, Kind::Eth | Kind::Vap { .. }) {
            c.set(k.at("promisc"), "enabled");
        }
        let up = !(matches!(kind, Kind::Vap { .. }) && hostapd_up);
        c.set(k.at("up"), if up { "enabled" } else { "disabled" });
    }
}

pub fn render_ebtables(c: &mut Cfg, net: &Net) {
    c.header("ebtables");
    if net.ebtables.is_empty() {
        c.set("ebtables.status", "disabled");
        return;
    }
    c.set("ebtables.status", "enabled");
    c.set("ebtables.add_vlan.status", "disabled");
    for (i, rule) in net.ebtables.iter().enumerate() {
        c.set(format_args!("ebtables.{}.cmd", i + 1), rule);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::WifiSlot;
    use crate::wlan::Band;
    use crate::{Controller, Input};
    use serde_json::json;

    /// The trunk VLANs and each VAP's bridge for these WLANs, which can name the
    /// networks `n<i>`, tagged with the `vlan` values given.
    fn trunk(network_vlans: &[Value], wlans: &[Value]) -> (Vec<u16>, Vec<String>) {
        let mac = "02:00:00:00:00:01";
        let networks: Vec<Value> =
            network_vlans.iter().enumerate().map(|(i, v)| json!({ "_id": format!("n{i}"), "site_id": "s", "vlan_enabled": true, "vlan": v })).collect();
        let state = json!({ "sites": [{ "_id": "s" }], "devices": [{ "mac": mac, "site_id": "s", "type": "uap" }], "networkconf": networks });
        let controller = Controller::default();
        let ctx = Ctx::new(&Input { state: &state, device_mac: mac, inform: None, cfgversion: "1", controller: &controller }).unwrap();
        let doc = json!({ "name": "wifi0", "radio": "ng" });
        let radios = [Radio { idx: 1, name: "wifi0", band: Band::Ng, doc: &doc, disabled: false }];
        let vaps: Vec<Vap> = wlans
            .iter()
            .enumerate()
            .map(|(i, w)| Vap {
                id: crate::wlan::wlan_id(w),
                w: Cow::Borrowed(w),
                radio: 0,
                slot: WifiSlot { section: i as u32 + 1, device_name: format!("ath{i}"), on_radio: i as u32, first_on_radio: i == 0 },
                vlan: wlan_vlan(&ctx, w),
            })
            .collect();
        let net = build(&ctx, &radios, &vaps).unwrap();
        (net.vlans, vaps.iter().map(|v| bridge_name(v.vlan)).collect())
    }

    #[test]
    fn vlans_outside_the_valid_range_are_untagged() {
        let network_vlans = [json!(0), json!(1), json!(4095), json!(-3), json!(10), json!("20"), json!(4094), json!(2)];
        let wlans: Vec<Value> = (0..network_vlans.len()).map(|i| json!({ "networkconf_id": format!("n{i}") })).collect();
        let (vlans, bridges) = trunk(&network_vlans, &wlans);
        assert_eq!(vlans, [10, 20, 4094, 2]);
        assert_eq!(bridges, ["br0", "br0", "br0", "br0", "br0.10", "br0.20", "br0.4094", "br0.2"]);
        // The same for a WLAN's own VLAN.
        let wlans: Vec<Value> = [0, 1, 4095, 30].iter().map(|v| json!({ "vlan_enabled": true, "vlan": v })).collect();
        assert_eq!(trunk(&[], &wlans), (vec![30], ["br0", "br0", "br0", "br0.30"].map(String::from).to_vec()));
    }
}
