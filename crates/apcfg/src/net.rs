//! Bridges, VLAN subinterfaces, `netconf` and the ebtables rules that keep tagged
//! frames off untagged VAPs.

use anyhow::{Result, bail};
use serde_json::Value;

use crate::Ctx;
use crate::cfg::{Cfg, Prefix};
use crate::json::{flag, int_of, oid, str_of};
use crate::meta::Meta;
use crate::wlan::{Radio, Vap, dynamic_vlan, network_vlan};

pub struct Bridge {
    pub name: String,
    /// 0 for the management bridge.
    pub vlan: i64,
    pub ports: Vec<String>,
}

pub struct Net {
    pub eth: Vec<String>,
    pub bridges: Vec<Bridge>,
    /// VLANs carried on the trunk, in order of first use.
    pub vlans: Vec<i64>,
    /// Bridge name for each VAP (by index into the VAP list).
    pub vap_bridge: Vec<String>,
    pub ebtables: Vec<String>,
}

fn bridge_name(vlan: i64) -> String {
    if vlan == 0 { "br0".to_string() } else { format!("br0.{vlan}") }
}

/// The VLAN a WLAN's clients are tagged with, if any.
fn wlan_vlan(ctx: &Ctx, vap: &Vap) -> Option<i64> {
    let w: &Value = &vap.w;
    if matches!(str_of(w, "security"), Some("wpaeap")) && dynamic_vlan(ctx, w) != 0 {
        return None;
    }
    let net = str_of(w, "networkconf_id").and_then(|id| ctx.network(id));
    if net.is_some_and(|n| flag(n, "vlan_enabled", false)) {
        return Some(network_vlan(ctx, str_of(w, "networkconf_id")));
    }
    if flag(w, "vlan_enabled", false) {
        return int_of(w, "vlan");
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
    let mut bridges = vec![Bridge { name: bridge_name(0), vlan: 0, ports: eth.clone() }];
    let mut vlans: Vec<i64> = Vec::new();
    let mut vap_bridge = Vec::new();
    let mut ebtables = Vec::new();
    for vap in vaps {
        let vlan = wlan_vlan(ctx, vap);
        let tag = vlan.unwrap_or(0);
        vap_bridge.push(bridge_name(tag));
        if radios[vap.radio].disabled {
            continue;
        }
        let pos = match bridges.iter().position(|b| b.vlan == tag) {
            Some(p) => p,
            None => {
                bridges.push(Bridge { name: bridge_name(tag), vlan: tag, ports: Vec::new() });
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
        let b = bridges.iter_mut().find(|b| b.vlan == *v).expect("bridge exists for every VLAN");
        b.ports.extend(eth.iter().map(|e| format!("{e}.{v}")));
        ebtables.push(format!("-t broute -A BROUTING --vlan-id {v} -p 802_1Q -j DROP"));
    }
    Ok(Net { eth, bridges, vlans, vap_bridge, ebtables })
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
    if net.bridges.is_empty() {
        c.set("bridge.status", "disabled");
        return;
    }
    c.set("bridge.status", "enabled");
    let names: Vec<String> = net.bridges.iter().map(|b| b.name.clone()).collect();
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
    let mut ifaces: Vec<(String, Kind)> = Vec::new();
    ifaces.extend(net.bridges.iter().map(|b| (b.name.clone(), Kind::Bridge)));
    ifaces.extend(net.eth.iter().map(|e| (e.clone(), Kind::Eth)));
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
        ifaces.push((v.dev().to_string(), Kind::Vap { disabled }));
    }
    for v in &net.vlans {
        ifaces.extend(net.eth.iter().map(|e| (format!("{e}.{v}"), Kind::Sub)));
    }
    let names: Vec<String> = ifaces.iter().map(|(n, _)| n.clone()).collect();
    let indices = meta.netconf(&names);
    let static_ip = static_ip(ctx);
    // VAPs are brought up by hostapd on APs that run it for every SSID.
    let hostapd_up = crate::bit(ctx.caps.wifi, 13);
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
