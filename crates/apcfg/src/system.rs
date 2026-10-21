//! `system_cfg`: all sections, in the official controller's order.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use anyhow::{Result, bail};
use serde_json::Value;

use crate::cfg::{Cfg, Prefix};
use crate::javahash::hash_set_order;
use crate::json::{Text, arr, flag, int_of, mac_eq, on_off, override_of, str_list, str_of, text_of};
use crate::meta::Meta;
use crate::net::{self, Net};
use crate::wlan::{self, Band, Radio, Vap, network_vlan};
use crate::{Cap, Ctx, LED, mgmt, tz};

pub fn render(ctx: &Ctx) -> Result<(String, Value)> {
    let caps = ctx.caps;
    let qca_v2 = caps.has(Cap::QcaV2);
    let mut meta = Meta::load(ctx, i64::from(qca_v2));
    let radios = wlan::radios(ctx);
    let wanted = wlan::deploy(ctx, &radios);
    let keys: Vec<(&str, &str)> = wanted.iter().map(|(id, _, r)| (*id, radios[*r].name)).collect();
    let slots = meta.wireless(&keys, |radio, k| if qca_v2 { format!("{radio}ap{k}") } else { format!("ath{k}") });
    let vaps: Vec<Vap> = wanted
        .into_iter()
        .zip(slots)
        .map(|((id, w, radio), slot)| {
            let vlan = net::wlan_vlan(ctx, &w);
            Vap { id, security: wlan::Security::of(&w), w, radio, slot, vlan }
        })
        .collect();
    let net = net::build(ctx, &radios, &vaps)?;

    // A typical system_cfg is 10-20 KB.
    let mut c = Cfg::with_capacity(16 << 10);
    unifi(&mut c, ctx);
    system(&mut c, ctx);
    users(&mut c, ctx)?;
    if caps.any(LED) {
        ledbar(&mut c, ctx);
    }
    wireless(&mut c, ctx, &radios, &vaps);
    c.header("connectivity");
    // Meshing (connectivity enabled) is not implemented: no uplink or downlink VAPs.
    c.set("connectivity.status", "disabled");
    net::render_vlan(&mut c, &net);
    net::render_bridge(&mut c, &net, &mut meta);
    if caps.has(Cap::Marks) {
        c.header("mark");
        for (i, (name, bits, shift, location)) in
            [("guest", 2, 30, "skb"), ("vapid", 5, 11, "ubnt"), ("associd", 11, 0, "ubnt")].iter().enumerate()
        {
            let i = i + 1;
            c.set(format_args!("mark.{i}.name"), name);
            c.set(format_args!("mark.{i}.bits"), bits);
            c.set(format_args!("mark.{i}.shift"), shift);
            c.set(format_args!("mark.{i}.location"), location);
        }
    }
    qos(&mut c, ctx, &radios, &vaps);
    net::render_netconf(&mut c, ctx, &net, &radios, &vaps, &mut meta);
    mac_acl(&mut c, ctx, &vaps);
    addressing(&mut c, ctx);
    net::render_ebtables(&mut c, &net);
    c.header("iptables");
    c.set("iptables.status", "disabled");
    c.set("ip6tables.status", "disabled");
    for s in ["redirector", "ipset", "dnsmasq"] {
        c.header(s);
        c.set(format_args!("{s}.status"), "disabled");
    }
    syslog(&mut c, ctx);
    sshd(&mut c, ctx);
    snmp(&mut c, ctx);
    ntp(&mut c, ctx);
    switch(&mut c, ctx);
    if caps.has(Cap::MdnsProxy) {
        mdns(&mut c, ctx, &vaps, &net);
    }
    if caps.has(Cap::PathMonitor) {
        c.header("pathmon");
        c.set("pathmon.status", "enabled");
        c.set("pathmon.interval", 5);
        c.set("pathmon.timeout", 1000);
        c.set("pathmon.ema_samples", 60);
        c.set("pathmon.size", 56);
        c.set("pathmon.target.1.type", "gateway");
        c.set("pathmon.target.2.type", "uplink");
    }
    cron(&mut c, ctx, &radios, &vaps);
    c.header("DPI Fingerprint");
    c.header("misc");
    Ok((c.finish(), meta.to_doc(ctx.site_id, &ctx.mac)))
}

fn unifi(c: &mut Cfg, ctx: &Ctx) {
    let ctl = ctx.controller;
    let mgmt = ctx.mgmt;
    c.header("unifi");
    c.set("unifi.version", &ctl.version);
    c.set("unifi.anonymous_controller_id", &ctl.reporter_uuid);
    c.opt("unifi.anonymous_site_id", str_of(ctx.site, "anonymous_id"));
    c.set("unifi.reporterid", &ctl.reporter_uuid);
    c.set("unifi.siteid", ctx.site_id);
    let idp = flag(mgmt, "unifi_idp_enabled", true);
    c.set("unifi.idp", on_off(idp));
    if idp {
        c.set("unifi.mcip", "239.254.127.63");
        c.opt("unifi.key", str_of(mgmt, "x_mgmt_key"));
    }
    c.set("unifi.feature.always_send_crash_logs", "enabled");
    let mut parts = ctl.version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    let cap = match (major, minor) {
        (0..=2, _) => 0,
        (3, 0..=2) => 3,
        _ => 7,
    };
    c.set("unifi.cfgcap_info", format_args!("0x{cap:x}"));
}

fn system(c: &mut Cfg, ctx: &Ctx) {
    c.header("system");
    let analytics = flag(ctx.super_mgmt, "enable_analytics", true);
    c.set("system.analytics.status", on_off(analytics));
    let zone = str_of(ctx.setting("locale"), "timezone").unwrap_or("UTC");
    if let Some(posix) = tz::posix(zone) {
        c.set("system.timezone", posix);
        c.set("locale.timezone", posix);
    }
    if str_of(ctx.device, "resetbtn_enabled").is_some_and(|v| v != "on") {
        c.set("system.resetbtn", "disabled");
    }
}

fn users(c: &mut Cfg, ctx: &Ctx) -> Result<()> {
    let mgmt = ctx.mgmt;
    // The crypt(3) hash is random-salted, so it is an input: the controller stores it
    // next to the password (as the official one caches it in the same field).
    let field = if ctx.caps.has(Cap::Sha512Passwd) { "x_ssh_sha512passwd" } else { "x_ssh_md5passwd" };
    let Some(hash) = str_of(mgmt, field) else {
        bail!("setting[mgmt].{field} is missing: store a crypt(3) hash of the SSH password there");
    };
    c.header("users");
    c.set("users.status", "enabled");
    c.set("users.1.name", ctx.ssh_username());
    c.set("users.1.password", hash);
    c.set("users.1.status", "enabled");
    c.set("users.2.name", "nobody");
    c.set("users.2.password", "x");
    c.set("users.2.shell", "/bin/false");
    c.set("users.2.status", "enabled");
    Ok(())
}

fn ledbar(c: &mut Cfg, ctx: &Ctx) {
    let on = mgmt::led_enabled(ctx);
    c.set("ledbar.status", on_off(on));
    c.set("ledbar.persistent", "true");
    if on {
        let pct = int_of(ctx.device, "led_override_color_brightness").unwrap_or(100).clamp(0, 100);
        c.set("ledbar.brightness", 255 * pct / 100);
        c.set("ledbar.active", 3);
        if ctx.caps.has(Cap::LedColor) {
            let hex = str_of(ctx.device, "led_override_color").unwrap_or("#0000FF").trim_start_matches('#');
            let rgb = u32::from_str_radix(hex, 16).unwrap_or(0xff);
            c.set("ledbar.color.1.color", 3);
            c.set("ledbar.color.1.r", rgb >> 16 & 0xff);
            c.set("ledbar.color.1.g", rgb >> 8 & 0xff);
            c.set("ledbar.color.1.b", rgb & 0xff);
        }
    }
}

fn wireless(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap]) {
    let caps = ctx.caps;
    c.header("wlans (radio)");
    let mut any_stamgr = false;
    if radios.is_empty() {
        c.set("radio.status", "disabled");
        c.header("no wlan provisioned as no radio found");
    } else {
        c.set("radio.status", "enabled");
        c.set("radio.countrycode", &ctx.country);
        c.set("aaa.status", "enabled");
        c.set("wireless.status", "enabled");
        let outdoor = override_of(ctx.device, "outdoor_mode_override", flag(ctx.mgmt, "outdoor_mode_enabled", false));
        c.set("radio.outdoor", on_off(outdoor));
        any_stamgr = wlan::render_radios(c, ctx, radios, vaps);
        for v in vaps {
            wlan::render_vap(c, ctx, radios, vaps, v);
        }
    }
    let conn = ctx.setting("connectivity");
    c.header("mesh");
    if caps.has(Cap::Mesh) {
        c.set("mesh.status", "enabled");
        c.set("mesh.version", 3);
        c.opt("mesh.essid", str_of(conn, "x_mesh_essid"));
        c.opt("mesh.psk", str_of(conn, "x_mesh_psk"));
        c.opt("mesh.serial1", str_of(ctx.device, "mesh_uplink_1"));
        c.opt("mesh.serial2", str_of(ctx.device, "mesh_uplink_2"));
    } else {
        c.set("mesh.status", "disabled");
    }
    if caps.has(Cap::BandSteering) {
        bandsteering(c, ctx, radios, vaps);
    }
    if caps.has(Cap::AirtimeFairness) {
        c.header("airtime fairness");
        c.set("atf.status", "enabled");
        c.set("atf.mode", on_off(flag(ctx.device, "atf_enabled", false)));
    }
    c.header("stamgr");
    if any_stamgr {
        c.set("stamgr.status", "enabled");
        c.set("stamgr.interval", 1);
    } else {
        c.set("stamgr.status", "disabled");
    }
}

fn bandsteering(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap]) {
    c.header("bandsteering");
    let mode = str_of(ctx.device, "bandsteering_mode").unwrap_or("off");
    if !flag(ctx.mgmt, "advanced_feature_enabled", false) || mode == "off" {
        c.set("bandsteering.status", "disabled");
        return;
    }
    c.set("bandsteering.status", "enabled");
    c.set("bandsteering.mode", mode);
    if !ctx.caps.has(Cap::BandSteeringPairs) {
        return;
    }
    let mut k = 0;
    for ng in vaps.iter().filter(|v| radios[v.radio].band == Band::Ng) {
        if let Some(na) = vaps.iter().find(|v| radios[v.radio].band == Band::Na && v.id == ng.id) {
            k += 1;
            c.set(format_args!("bandsteering.{k}.status"), "enabled");
            c.set(format_args!("bandsteering.{k}.vap.1.devname"), ng.dev());
            c.set(format_args!("bandsteering.{k}.vap.2.devname"), na.dev());
        }
    }
}

/// One VAP's MAC ACL: device, policy and `(mac, type)` entries.
type AclBlock<'a> = (&'a str, &'a str, Vec<(&'a str, &'static str)>);

/// MACs are written and compared as stored, as the official controller does (the
/// settings editor stores them lower case).
fn mac_acl(c: &mut Cfg, ctx: &Ctx, vaps: &[Vap]) {
    // Clients pinned ("lock to AP") to some other AP may not join this one, while that AP
    // is known and available: a lock to an AP that is offline (`fixed_ap_available` false)
    // or not in the state is not enforced, so its clients can use the other APs meanwhile.
    let available = |ap: &str| {
        arr(ctx.state, "devices").iter().find(|device| str_of(device, "mac").is_some_and(|m| mac_eq(m, ap))).is_some_and(|device| flag(device, "fixed_ap_available", true))
    };
    let locked_elsewhere = hash_set_order(
        ctx.site_docs("clients")
            .filter(|u| flag(u, "fixed_ap_enabled", false))
            .filter(|u| str_of(u, "fixed_ap_mac").is_some_and(|m| !m.is_empty() && !mac_eq(m, &ctx.mac) && available(m)))
            .filter_map(|u| str_of(u, "mac")),
    );
    let locked: HashSet<&str> = locked_elsewhere.iter().copied().collect();
    let mut blocks: Vec<AclBlock> = Vec::new();
    for v in vaps {
        let filtering = flag(&v.w, "mac_filter_enabled", false);
        if !filtering && locked_elsewhere.is_empty() {
            continue;
        }
        let policy = if filtering { str_of(&v.w, "mac_filter_policy").unwrap_or("deny") } else { "deny" };
        let entries: Vec<(&str, &'static str)> = if !filtering {
            locked_elsewhere.iter().map(|&m| (m, "lock2ap")).collect()
        } else {
            // The user's list once per MAC, first occurrence kept.
            let mut listed = HashSet::new();
            let user: Vec<&str> = str_list(&v.w, "mac_filter_list").filter(|m| listed.insert(*m)).collect();
            match policy {
                "allow" => user.into_iter().filter(|m| !locked.contains(m)).map(|m| (m, "user")).collect(),
                // Both lists grouped by MAC (the user's entry kept) in a Java HashMap's order.
                "deny" => hash_set_order(user.into_iter().chain(locked_elsewhere.iter().copied()))
                    .into_iter()
                    .map(|m| (m, if listed.contains(m) { "user" } else { "lock2ap" }))
                    .collect(),
                // An unknown policy: the official controller logs it and lists nothing.
                _ => Vec::new(),
            }
        };
        blocks.push((v.dev(), policy, entries));
    }
    c.header("mac acl");
    c.set("macacl.status", on_off(!blocks.is_empty()));
    for (k, (dev, policy, entries)) in blocks.iter().enumerate() {
        let k = k + 1;
        c.set(format_args!("macacl.{k}.status"), "enabled");
        c.set(format_args!("macacl.{k}.devname"), dev);
        c.set(format_args!("macacl.{k}.acl.status"), "enabled");
        c.set(format_args!("macacl.{k}.acl.policy"), policy);
        for (j, (mac, kind)) in entries.iter().enumerate() {
            let j = j + 1;
            c.set(format_args!("macacl.{k}.acl.{j}.status"), "enabled");
            c.set(format_args!("macacl.{k}.acl.{j}.mac"), mac);
            c.set(format_args!("macacl.{k}.acl.{j}.type"), kind);
        }
    }
}

/// The AP's host name: device name reduced to `[0-9A-Za-z-]`, `+` spelled out.
pub fn hostname(name: &str) -> String {
    let (body, end) = name.strip_suffix('+').map_or((name, ""), |b| (b, "-Plus"));
    let mut s = String::with_capacity(name.len() + end.len());
    for ch in body.chars() {
        match ch {
            '+' => s.push_str("-Plus-"),
            _ if ch.is_ascii_alphanumeric() || ch == '-' => s.push(ch),
            _ => {}
        }
    }
    s.push_str(end);
    // ASCII only from here: bytes are characters.
    s.drain(..s.len() - s.trim_start_matches('-').len());
    s.truncate(31);
    s
}

/// `dhcpc`, `route` and `resolv`.
fn addressing(c: &mut Cfg, ctx: &Ctx) {
    let static_ip = net::static_ip(ctx);
    let is_static = static_ip.is_some();
    let cn = |key: &str| static_ip.and_then(|cn| str_of(cn, key));
    c.header("dhcpc");
    c.set("dhcpc.status", "enabled");
    if !is_static {
        c.set("dhcpc.1.status", "enabled");
        c.set("dhcpc.1.devname", "br0");
    }
    c.header("route");
    if is_static {
        c.set("route.1.status", "enabled");
        c.set("route.1.devname", "br0");
        c.set("route.1.ip", "0.0.0.0");
        c.opt("route.1.gateway", cn("gateway"));
    }
    c.set("route.status", "enabled");
    c.header("resolv");
    c.set("resolv.status", "enabled");
    let name = str_of(ctx.device, "name").map(hostname).filter(|h| !h.is_empty());
    c.opt("resolv.host.1.name", name);
    for (i, key) in [(1, "dns1"), (2, "dns2")] {
        let dns = cn(key).filter(|d| !d.is_empty());
        match dns {
            Some(ip) => c.set(format_args!("resolv.nameserver.{i}.ip"), ip),
            None => c.set(format_args!("resolv.nameserver.{i}.status"), "disabled"),
        }
    }
    if is_static {
        c.opt("resolv.search", cn("dnssuffix").filter(|s| !s.is_empty()));
    }
}

fn syslog(c: &mut Cfg, ctx: &Ctx) {
    let s = ctx.setting("rsyslogd");
    let enabled = flag(s, "enabled", false);
    // "To this controller" counts only while remote syslog is on: switched off, the
    // stored `this_controller` is kept but sends nothing.
    let this = enabled && flag(s, "this_controller", false);
    let encrypted_only = flag(s, "this_controller_encrypted_only", false);
    if this && encrypted_only && !ctx.caps.has(Cap::EncryptedSyslog) {
        return;
    }
    let wants_ap_logs = flag(s, "log_all_contents", false) || str_list(s, "contents").any(|c| c == "access_points");
    if enabled && !this && !wants_ap_logs {
        return;
    }
    // Logs for this controller go to the address the AP itself informs to.
    let port = ctx.controller.syslog_port.to_string();
    let to_controller = (ctx.inform_str("inform_ip"), Some(Text::Str(&port)));
    c.header("syslog");
    c.set("syslog.status", "enabled");
    c.set("syslog.level", if enabled && flag(s, "debug", false) { 8 } else { 7 });
    if this {
        c.set("syslog.remote.encrypt", "enabled");
        c.opt("syslog.remote.key", str_of(ctx.device, "syslog_key"));
    }
    if enabled {
        let (ip, port) = if this { to_controller } else { (str_of(s, "ip"), text_of(s, "port")) };
        c.opt("syslog.remote.ip", ip);
        c.opt("syslog.remote.port", port);
        c.set("syslog.remote.status", "enabled");
    }
    if this || flag(s, "netconsole_enabled", false) {
        let (host, port) = if this { to_controller } else { (str_of(s, "netconsole_host"), text_of(s, "netconsole_port")) };
        c.opt("netconsole.host", host);
        c.opt("netconsole.port", port);
        c.set("netconsole.status", "enabled");
    }
}

fn sshd(c: &mut Cfg, ctx: &Ctx) {
    let mgmt = ctx.mgmt;
    c.header("sshd");
    if !flag(mgmt, "x_ssh_enabled", true) {
        c.set("sshd.status", "disabled");
        c.set("sshd.1.status", "enabled");
        c.set("sshd.1.ifname", "lo");
        return;
    }
    c.set("sshd.status", "enabled");
    c.set("sshd.auth.passwd", on_off(flag(mgmt, "x_ssh_auth_password_enabled", true)));
    for (i, key) in arr(mgmt, "x_ssh_keys").iter().enumerate() {
        let k = Prefix::new("sshd.auth.key", i + 1);
        c.set(k.at("status"), "enabled");
        c.opt(k.at("value"), str_of(key, "key"));
        c.opt(k.at("type"), str_of(key, "type"));
        c.opt(k.at("comment"), str_of(key, "comment").or(str_of(key, "name")));
    }
    if !flag(mgmt, "x_ssh_bind_wildcard", false) {
        c.set("sshd.1.status", "enabled");
        c.set("sshd.1.ifname", "br0");
    }
}

/// `snmp.*`, no section header, nothing at all while SNMP is off. v1/v2c goes
/// to every AP, v3 only to one with [`Cap::SnmpV3`]; the community is cut to 256 characters.
fn snmp(c: &mut Cfg, ctx: &Ctx) {
    let s = ctx.setting("snmp");
    let v1 = flag(s, "enabled", false);
    let v3 = flag(s, "enabledV3", false) && ctx.caps.has(Cap::SnmpV3);
    if !v1 && !v3 {
        return;
    }
    c.set("snmp.status", "enabled");
    c.set("snmp.version", match (v1, v3) {
        (true, true) => "all",
        (true, false) => "1_2c",
        _ => "3",
    });
    c.opt("snmp.location", str_of(ctx.device, "snmp_location").filter(|l| !l.is_empty()));
    c.opt("snmp.contact", str_of(ctx.device, "snmp_contact").filter(|l| !l.is_empty()));
    if v1 {
        c.set("snmp.community", str_of(s, "community").unwrap_or("public").chars().take(256).collect::<String>());
    }
    if v3 {
        c.set("snmp.user.1.name", str_of(s, "username").unwrap_or(""));
        c.set("snmp.user.1.password", str_of(s, "x_password").unwrap_or(""));
    }
}

fn ntp(c: &mut Cfg, ctx: &Ctx) {
    let s = ctx.setting("ntp");
    let looks_like_host =
        |h: &&str| !h.is_empty() && h.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':'));
    let servers: Vec<&str> =
        ["ntp_server_1", "ntp_server_2", "ntp_server_3", "ntp_server_4"].iter().filter_map(|k| str_of(s, k)).filter(looks_like_host).collect();
    c.header("ntpclient");
    if servers.is_empty() {
        c.set("ntpclient.status", "disabled");
        return;
    }
    c.set("ntpclient.status", "enabled");
    for (i, server) in servers.iter().enumerate() {
        c.set(format_args!("ntpclient.{}.status", i + 1), "enabled");
        c.set(format_args!("ntpclient.{}.server", i + 1), server);
    }
}

/// Most switch ports any UniFi device has (the 48-port switches' 52).
const MAX_PORTS: i64 = 52;

fn switch(c: &mut Cfg, ctx: &Ctx) {
    c.header("switch");
    if !ctx.caps.has(Cap::Switch) {
        return;
    }
    c.set("switch.status", "disabled");
    c.set("switch.vlan.status", on_off(flag(ctx.device, "switch_vlan_enabled", false)));
    c.set("switch.jumboframes", on_off(flag(ctx.device, "jumboframe_enabled", false)));
    c.set("switch.dot1x.status", "disabled");
    // The ports of all its interfaces, as the AP reported them. Imported numbers can be
    // anything, and no UniFi device has more than 52 ports.
    let ports = arr(ctx.device, "ethernet_table").iter().filter_map(|e| int_of(e, "num_port")).map(|n| n.clamp(0, MAX_PORTS)).fold(0, i64::saturating_add).clamp(1, MAX_PORTS) as usize;
    // The first override for a port decides its name.
    let mut overrides: Vec<Option<&Value>> = vec![None; ports + 1];
    for p in arr(ctx.device, "port_overrides") {
        if let Some(slot) = int_of(p, "port_idx").and_then(|i| usize::try_from(i).ok()).filter(|&i| i >= 1).and_then(|i| overrides.get_mut(i))
            && slot.is_none()
        {
            *slot = Some(p);
        }
    }
    for (i, p) in overrides.iter().enumerate().skip(1) {
        match p.and_then(|p| str_of(p, "name")) {
            Some(name) => c.set(format_args!("switch.port.{i}.name"), name),
            None => c.set(format_args!("switch.port.{i}.name"), format_args!("Port {i}")),
        }
        c.set(format_args!("switch.port.{i}.opmode"), "switch");
    }
}

/// The predefined mDNS service codes and the DNS-SD service types behind each, in
/// the official controller's order (the "auto" list follows it). Within a code the
/// official order comes from a Java set and can change between its restarts; the AP
/// does not care. Two-type codes are listed the way the captured controller iterated
/// them (Chromecast), larger ones sorted.
pub const MDNS_SERVICES: &[(&str, &str, &[&str])] = &[
    ("amazon_devices", "Amazon devices", &["_amazonecho-remote._tcp", "_amzn-wplay._tcp.local", "_workstation._tcp.local"]),
    ("android_tv_remote", "Android TV Remote", &["_androidtvremote._tcp.local"]),
    ("apple_airDrop", "Apple AirDrop", &["_airdrop._tcp.local"]),
    ("apple_airPlay", "Apple AirPlay", &["_airplay._tcp.local", "_appletv-v2._tcp.local", "_companion-link._tcp.local", "_raop._tcp.local"]),
    ("apple_file_sharing", "Apple file sharing", &["_afpovertcp._tcp.local"]),
    ("apple_iChat", "Apple iChat", &["_ichat._tcp.local", "_presence._tcp.local"]),
    (
        "apple_iTunes",
        "Apple iTunes",
        &["_apple-mobdev._tcp.local", "_apple-mobdev2._tcp.local", "_atc._tcp.local", "_daap._tcp.local", "_dacp._tcp.local", "_home-sharing._tcp.local"],
    ),
    ("aqara", "Aqara", &["_aqara._tcp.local", "_aqara-setup._tcp.local"]),
    ("bose", "Bose", &["_bose._tcp.local"]),
    ("dns_service_discovery", "DNS service discovery", &["_dns-sd._udp.local"]),
    ("ftp_servers", "FTP servers", &["_sftp-ssh._tcp.local", "_ftp._tcp.local"]),
    ("google_chromecast", "Google Chromecast", &["_googlezone._tcp.local", "_googlecast._tcp.local"]),
    ("homeKit", "HomeKit", &["_hap._tcp.local", "_homekit._tcp.local"]),
    ("matter_network", "Matter", &["_matter._tcp", "_matter_gateway._tcp", "_matterc._udp", "_matterd._udp"]),
    ("philips_hue", "Philips Hue", &["_philipshue._tcp.local"]),
    (
        "printers",
        "Printers",
        &[
            "_canon-bjnp1._tcp.local", "_fax-ipp._tcp.local", "_http._tcp.local", "_http_alt._tcp.local", "_ica-networking._tcp.local",
            "_ica-networking2._tcp.local", "_ipp._tcp.local", "_ipp-tls._tcp.local", "_ipps._tcp.local", "_ippusb._tcp.local",
            "_pdl-datastream._tcp.local", "_printer._tcp.local", "_ptp._tcp.local", "_riousbprint._tcp.local", "_scan-target._tcp.local",
            "_scanner._tcp.local",
        ],
    ),
    ("roku", "Roku", &["_rsp._tcp.local", "_roku._tcp.local"]),
    ("scanners", "Scanners", &["_scan-target._tcp.local", "_scanner._tcp", "_uscan._tcp.local", "_uscans._tcp.local"]),
    ("shelly", "Shelly", &["_shelly._tcp.local"]),
    ("sonos", "Sonos", &["_sonos._tcp.local"]),
    ("spotify_connect", "Spotify Connect", &["_spotify-connect._tcp.local"]),
    ("ssh_servers", "SSH servers", &["_ssh._tcp.local"]),
    ("time_capsule", "Time Capsule", &["_adisk._tcp.local"]),
    ("web_servers", "Web servers", &["_https._tcp.local", "_http._tcp.local"]),
    ("windows_file_sharing_samba", "Windows file sharing (Samba)", &["_smbdirect._tcp.local", "_smb._tcp.local"]),
];

fn mdns_services(code: &str) -> &'static [&'static str] {
    MDNS_SERVICES.iter().find(|(c, _, _)| *c == code).map_or(&[], |(_, _, s)| s)
}

/// What "auto" mode filters for: every code's types, each code's sorted, in table
/// order (a type in two codes is listed twice, as the official controller does).
/// Built once.
fn mdns_auto_services() -> &'static [&'static str] {
    static AUTO: OnceLock<Vec<&'static str>> = OnceLock::new();
    AUTO.get_or_init(|| {
        MDNS_SERVICES
            .iter()
            .flat_map(|(_, _, types)| {
                let mut t: Vec<&str> = types.to_vec();
                t.sort_unstable();
                t
            })
            .collect()
    })
}

struct MdnsEntry<'a> {
    networks: Vec<Option<&'a str>>,
    mode: &'a str,
    services: Cow<'a, [&'a str]>,
}

fn entry_services(e: &Value) -> Vec<&str> {
    let mut out: Vec<&str> = arr(e, "predefined_services").iter().filter_map(|s| str_of(s, "code")).flat_map(mdns_services).copied().collect();
    for s in arr(e, "custom_services") {
        out.extend(s.as_str().or_else(|| str_of(s, "address")).or_else(|| str_of(s, "name")));
    }
    out
}

fn mdns(c: &mut Cfg, ctx: &Ctx, vaps: &[Vap], net: &Net) {
    let groups = wlan::ap_groups(ctx);
    let applies = |e: &Value| match str_of(e, "ap_scope_mode").unwrap_or("all") {
        "all" => true,
        "specific" => str_list(e, "ap_macs").any(|m| mac_eq(m, &ctx.mac)),
        "group" => wlan::in_groups(e, &groups),
        _ => false,
    };
    // One VAP per WLAN stands for all of its radios.
    let mut wlans: Vec<&Vap> = Vec::new();
    for v in vaps {
        if !wlans.iter().any(|o| o.id == v.id) && matches!(str_of(&v.w, "mdns_proxy_mode"), Some("auto" | "custom")) {
            wlans.push(v);
        }
    }
    if wlans.is_empty() {
        return;
    }
    c.set("mdns_sd.status", "enabled");
    let isolation = wlans.iter().any(|v| {
        str_of(&v.w, "mdns_proxy_mode") == Some("custom")
            && arr(&v.w, "mdns_proxy_custom").iter().any(|e| applies(e) && flag(e, "isolation_enabled", false))
    });
    if isolation {
        c.set("mdns_sd.ap_mode", "enabled");
    }
    let bridge_of_vlan = |vlan: Option<u16>| net.bridges.iter().find(|b| b.vlan == vlan).map(net::Bridge::name);
    let (mut f, mut p) = (0, 0);
    for wv in wlans {
        let w: &Value = &wv.w;
        let devs: Vec<&str> = vaps.iter().filter(|v| v.id == wv.id).map(Vap::dev).collect();
        let own = str_of(w, "networkconf_id");
        let mut entries: Vec<MdnsEntry> = Vec::new();
        if str_of(w, "mdns_proxy_mode") == Some("custom") {
            // Each entry with its services, worked out once.
            let custom: Vec<(&Value, Vec<&str>)> = arr(w, "mdns_proxy_custom").iter().filter(|e| applies(e)).map(|e| (e, entry_services(e))).collect();
            let lists_own = custom.iter().any(|(e, _)| own.is_some_and(|o| str_list(e, "networkconf_ids").any(|n| n == o)));
            if !lists_own {
                let all = custom.iter().any(|(e, _)| str_of(e, "services_mode") == Some("all"));
                let mut union: Vec<&str> = Vec::new();
                for &s in custom.iter().flat_map(|(_, services)| services) {
                    if !union.contains(&s) {
                        union.push(s);
                    }
                }
                entries.push(MdnsEntry { networks: vec![own], mode: if all { "all" } else { "specific" }, services: Cow::Owned(union) });
            }
            entries.extend(custom.into_iter().map(|(e, services)| MdnsEntry {
                networks: str_list(e, "networkconf_ids").map(Some).collect(),
                mode: str_of(e, "services_mode").unwrap_or("all"),
                services: Cow::Owned(services),
            }));
        } else {
            entries.push(MdnsEntry { networks: vec![own], mode: "specific", services: Cow::Borrowed(mdns_auto_services()) });
        }
        let own_bridge = bridge_of_vlan(network_vlan(ctx.state, ctx.site_id, own));
        for e in entries {
            let others: Vec<net::BridgeName> = e
                .networks
                .iter()
                .filter(|n| **n != own)
                .filter_map(|n| bridge_of_vlan(network_vlan(ctx.state, ctx.site_id, *n)))
                .filter(|b| Some(*b) != own_bridge)
                .collect();
            if let (false, Some(own_bridge)) = (others.is_empty(), own_bridge) {
                p += 1;
                c.set(format_args!("mdns_sd.proxy.{p}.status"), "enabled");
                c.set(format_args!("mdns_sd.proxy.{p}.dst.1.devname"), own_bridge);
                for (i, b) in others.iter().enumerate() {
                    c.set(format_args!("mdns_sd.proxy.{p}.src.{}.devname", i + 1), b);
                }
            }
            for n in &e.networks {
                f += 1;
                // An untagged network is VLAN 1 here.
                c.set(format_args!("mdns_sd.filter.{f}.vlan"), network_vlan(ctx.state, ctx.site_id, *n).unwrap_or(1));
                c.set(format_args!("mdns_sd.filter.{f}.policy"), if e.mode == "all" { "allow" } else { "deny" });
                for (i, d) in devs.iter().enumerate() {
                    c.set(format_args!("mdns_sd.filter.{f}.dst.{}.devname", i + 1), d);
                }
                if e.mode == "specific" {
                    for (i, s) in e.services.iter().enumerate() {
                        c.set(format_args!("mdns_sd.filter.{f}.service.{}.name", i + 1), s);
                    }
                }
            }
        }
    }
}

/// 5 GHz channels that need radar detection (DFS).
fn is_dfs_channel(ch: i64) -> bool {
    (52..=144).contains(&ch)
}

/// A user group's speed limits as the render reads them: `(down, up)` in kbps from
/// `qos_rate_max_down`/`qos_rate_max_up` (numbers or numeric strings); -1, or a missing
/// or unreadable value, is unlimited (-1).
pub fn usergroup_limits(g: &Value) -> (i64, i64) {
    (int_of(g, "qos_rate_max_down").unwrap_or(-1), int_of(g, "qos_rate_max_up").unwrap_or(-1))
}

/// The user group (speed limit) a WLAN's clients get, as the render resolves it: the
/// site's group its `usergroup_id` names, else (no id, an empty one, or one naming no
/// group of the site) the site's Default group (`attr_hidden_id` "Default"); `None`
/// when the site has no such group either. `site_id` is the WLAN's site.
pub fn ssid_usergroup<'a>(state: &'a Value, site_id: &str, w: &Value) -> Option<&'a Value> {
    let groups = || crate::site_docs(state, site_id, "usergroup");
    str_of(w, "usergroup_id")
        .and_then(|id| groups().find(|g| crate::json::oid(g) == Some(id)))
        .or_else(|| groups().find(|g| str_of(g, "attr_hidden_id") == Some("Default")))
}

/// The most a radio can carry (Mbps), the ceiling used for "unlimited". The
/// official controller takes it from its model table; this estimates it per
/// spatial stream (150 at 2.4 GHz, 600 for Wi-Fi 6 / 433 for Wi-Fi 5 at
/// 5 GHz), which gives the table's 300 and 2400 for a U6-Mesh. `nss` comes from
/// the AP's inform: one beyond the 16 streams any radio may have is taken as 16.
fn radio_max_mbps(r: &Radio) -> i64 {
    let nss = int_of(r.doc, "nss").unwrap_or(2).clamp(1, 16);
    let per_stream = match r.band {
        Band::Ng => 150,
        _ if flag(r.doc, "is_11ax", false) => 600,
        _ => 433,
    };
    per_stream * nss
}

/// Speed limits (user groups). On only when some group on the site limits
/// anything: each VAP is shaped to its WLAN's group (the default group when
/// it has none), downlink on the VAP and uplink on each wired uplink. Per-client
/// limits are not here: they go to the AP as `rate-update` commands.
fn qos(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap]) {
    c.header("qos");
    if !ctx.site_docs("usergroup").any(|g| usergroup_limits(g) != (-1, -1)) || vaps.is_empty() {
        c.set("qos.status", "disabled");
        return;
    }
    c.set("qos.status", "enabled");
    c.set("qos.mode", 1);
    // Wired uplinks: the AP's ports, else the interface it reports as its uplink.
    let mut uplinks: Vec<&str> =
        ctx.inform.and_then(|p| p["port_table"].as_array()).into_iter().flatten().filter_map(|p| str_of(p, "ifname")).collect();
    if uplinks.is_empty() {
        uplinks.push(ctx.inform_str("uplink").filter(|u| u.starts_with("eth")).unwrap_or("eth0"));
    }
    let mut k = 0;
    for u in &uplinks {
        k += 1;
        c.set(format_args!("qos.if.{k}.devname"), u);
        c.set(format_args!("qos.if.{k}.devspeed"), 1000);
        c.set(format_args!("qos.if.{k}.type"), "uplink");
    }
    for v in vaps {
        k += 1;
        c.set(format_args!("qos.if.{k}.devname"), v.dev());
        c.set(format_args!("qos.if.{k}.devspeed"), radio_max_mbps(&radios[v.radio]));
    }
    for (i, v) in vaps.iter().enumerate() {
        let m = i + 1;
        let (down, up) = ssid_usergroup(ctx.state, ctx.site_id, &v.w).map_or((-1, -1), usergroup_limits);
        let ceiling = radio_max_mbps(&radios[v.radio]);
        c.set(format_args!("qos.vap.{m}.id"), m);
        c.set(format_args!("qos.vap.{m}.devname"), v.dev());
        c.set(format_args!("qos.vap.{m}.dwnlink.minspeed"), if down > 0 { down } else { ceiling });
        if down > 0 {
            c.set(format_args!("qos.vap.{m}.dwnlink.maxspeed"), down);
        }
        for (j, u) in uplinks.iter().enumerate() {
            let j = j + 1;
            c.set(format_args!("qos.vap.{m}.uplink.{j}.devname"), u);
            c.set(format_args!("qos.vap.{m}.uplink.{j}.minspeed"), if up > 0 { up } else { ceiling });
            if up > 0 {
                c.set(format_args!("qos.vap.{m}.uplink.{j}.maxspeed"), up);
            }
        }
    }
}

fn cron(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap]) {
    let schedules = vaps.iter().any(|v| !arr(&v.w, "schedule_with_duration").is_empty());
    let fcc = ctx.country == "840" || ctx.country == "124";
    let dfs = radios.iter().any(|r| {
        r.band == Band::Na
            && flag(r.doc, if fcc { "has_fccdfs" } else { "has_dfs" }, false)
            && int_of(r.doc, "channel").is_some_and(is_dfs_channel)
    });
    let k11 = vaps.iter().any(|v| flag(&v.w, "fast_roaming_enabled", false));
    let jobs: Vec<(&str, &str)> = [
        (schedules, ("1-59/5 * * * *", "syswrapper.sh schedule-action")),
        (dfs, ("0 2 * * *", "syswrapper.sh dfs-reset")),
        (k11, ("0 4 * * *", "syswrapper.sh 11k-scan")),
    ]
    .into_iter()
    .filter_map(|(on, job)| on.then_some(job))
    .collect();
    if jobs.is_empty() {
        return;
    }
    c.header("cron");
    c.set("cron.status", "enabled");
    c.set("cron.1.status", "enabled");
    c.set("cron.1.user", ctx.ssh_username());
    for (j, (schedule, cmd)) in jobs.iter().enumerate() {
        let j = j + 1;
        c.set(format_args!("cron.1.job.{j}.status"), "enabled");
        c.set(format_args!("cron.1.job.{j}.schedule"), schedule);
        c.set(format_args!("cron.1.job.{j}.cmd"), cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Controller, Input};
    use serde_json::json;

    fn switch_lines(ethernet_table: Value, port_overrides: Value) -> Vec<String> {
        let mac = "02:00:00:00:00:01";
        let state = json!({ "sites": [{ "_id": "s" }], "devices": [
            { "mac": mac, "site_id": "s", "type": "uap", "fw_caps": 16, "ethernet_table": ethernet_table, "port_overrides": port_overrides },
        ]});
        let controller = Controller::default();
        let ctx = Ctx::new(&Input { state: &state, device_mac: mac, inform: None, cfgversion: "1", controller: &controller }).unwrap();
        let mut c = Cfg::default();
        switch(&mut c, &ctx);
        c.finish().lines().filter(|l| l.starts_with("switch.port.")).map(str::to_string).collect()
    }

    fn syslog_lines(rsyslogd: Value) -> String {
        syslog_lines_for(rsyslogd, &Controller::default())
    }

    fn syslog_lines_for(rsyslogd: Value, controller: &Controller) -> String {
        let mac = "02:00:00:00:00:01";
        let mut rsyslogd = rsyslogd;
        rsyslogd["key"] = json!("rsyslogd");
        let state = json!({ "sites": [{ "_id": "s" }], "setting": [rsyslogd], "devices": [{ "mac": mac, "site_id": "s", "type": "uap", "syslog_key": "k" }] });
        let inform = json!({ "inform_ip": "192.0.2.1" });
        let ctx = Ctx::new(&Input { state: &state, device_mac: mac, inform: Some(&inform), cfgversion: "1", controller }).unwrap();
        let mut c = Cfg::default();
        syslog(&mut c, &ctx);
        c.finish()
    }

    /// Remote syslog switched off keeps its "this controller" choice stored, but sends
    /// neither the encrypted syslog nor the netconsole toward the controller.
    #[test]
    fn syslog_off_sends_nothing_to_this_controller() {
        let on = syslog_lines(json!({ "enabled": true, "this_controller": true }));
        assert!(on.contains("syslog.remote.encrypt=enabled\nsyslog.remote.key=k\n") && on.contains("netconsole.host=192.0.2.1\n"), "{on}");
        let off = syslog_lines(json!({ "enabled": false, "this_controller": true }));
        assert_eq!(off, "# syslog\nsyslog.status=enabled\nsyslog.level=7\n");
        let off_netconsole = syslog_lines(json!({ "enabled": false, "this_controller": true, "netconsole_enabled": true, "netconsole_host": "192.0.2.9", "netconsole_port": "6666" }));
        assert!(off_netconsole.ends_with("syslog.level=7\nnetconsole.host=192.0.2.9\nnetconsole.port=6666\nnetconsole.status=enabled\n"), "{off_netconsole}");
    }

    /// "To this controller" names the port the controller takes syslog on.
    #[test]
    fn syslog_to_this_controller_uses_its_port() {
        let on = json!({ "enabled": true, "this_controller": true });
        let official = syslog_lines(on.clone());
        assert!(official.contains("syslog.remote.ip=192.0.2.1\nsyslog.remote.port=5514\n") && official.contains("netconsole.port=5514\n"), "{official}");
        let ours = syslog_lines_for(on, &Controller { syslog_port: 1514, ..Default::default() });
        assert!(ours.contains("syslog.remote.port=1514\n") && ours.contains("netconsole.port=1514\n") && !ours.contains("5514"), "{ours}");
    }

    #[test]
    fn switch_ports_are_clamped_and_named_by_their_first_override() {
        let overrides = json!([
            { "port_idx": 2, "name": "Desk" }, { "port_idx": 2, "name": "later" }, { "port_idx": 3 }, { "port_idx": 3, "name": "unnamed first" },
            { "port_idx": -1, "name": "x" }, { "port_idx": 0, "name": "x" }, { "port_idx": 1_000_000, "name": "x" },
        ]);
        let lines = switch_lines(json!([{ "num_port": 3 }]), overrides.clone());
        assert_eq!(lines, [
            "switch.port.1.name=Port 1", "switch.port.1.opmode=switch", "switch.port.2.name=Desk", "switch.port.2.opmode=switch",
            "switch.port.3.name=Port 3", "switch.port.3.opmode=switch",
        ]);
        for huge in [json!([{ "num_port": 1_000_000_000 }, { "num_port": 2 }]), json!([{ "num_port": i64::MAX }, { "num_port": i64::MAX }])] {
            let lines = switch_lines(huge, overrides.clone());
            assert_eq!((lines.len(), lines.last().map(String::as_str)), (2 * 52, Some("switch.port.52.opmode=switch")));
        }
        assert_eq!(switch_lines(json!([{ "num_port": -5 }, { "num_port": 2 }]), json!([])).len(), 2 * 2);
        assert_eq!(switch_lines(json!([]), json!([])), ["switch.port.1.name=Port 1", "switch.port.1.opmode=switch"]);
    }

    #[test]
    fn a_radio_reporting_absurd_streams_is_capped() {
        let max = |doc: Value, band| radio_max_mbps(&Radio { idx: 1, name: "wifi0", band, doc: &doc, disabled: false });
        assert_eq!((max(json!({ "nss": 2 }), Band::Ng), max(json!({ "nss": 4, "is_11ax": true }), Band::Na)), (300, 2400));
        assert_eq!(max(json!({}), Band::Na), 866, "two streams when the AP does not say");
        assert_eq!(max(json!({ "nss": i64::MAX, "is_11ax": true }), Band::Na), 16 * 600);
        assert_eq!(max(json!({ "nss": -3 }), Band::Ng), 150);
    }

    #[test]
    fn hostnames() {
        assert_eq!(hostname("Garage AP"), "GarageAP");
        assert_eq!(hostname("U6+"), "U6-Plus");
        assert_eq!(hostname("-a+b"), "a-Plus-b");
        assert_eq!(hostname("a++"), "a-Plus--Plus");
        assert_eq!(hostname("+"), "Plus");
        assert_eq!(hostname("--Büro Süd/2"), "BroSd2");
        assert_eq!(hostname(&"x".repeat(40)), "x".repeat(31));
        assert_eq!(hostname("ü+"), "Plus");
    }
}
