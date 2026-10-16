//! `system_cfg`: all sections, in the official controller's order.

use anyhow::{Result, bail};
use serde_json::Value;

use crate::cfg::Cfg;
use crate::javahash::hash_set_order;
use crate::json::{arr, flag, int_of, mac_eq, on_off, str_list, str_of, text_of};
use crate::meta::Meta;
use crate::net::{self, Net};
use crate::wlan::{self, Radio, Vap, network_vlan, wlan_id};
use crate::{Ctx, bit, mgmt, tz};

pub fn render(ctx: &Ctx) -> Result<(String, Value)> {
    let caps = ctx.caps;
    let qca_v2 = bit(caps.wifi, 29);
    let mut meta = Meta::load(ctx, i64::from(qca_v2));
    let radios = wlan::radios(ctx);
    let wanted = wlan::deploy(ctx, &radios);
    let keys: Vec<(String, String)> = wanted.iter().map(|(w, r)| (wlan_id(w).to_string(), radios[*r].name.clone())).collect();
    let slots = meta.wireless(&keys, |radio, k| if qca_v2 { format!("{radio}ap{k}") } else { format!("ath{k}") });
    let vaps: Vec<Vap> =
        wanted.into_iter().zip(slots).zip(keys).map(|(((w, radio), slot), (id, _))| Vap { id, w, radio, slot }).collect();
    let net = net::build(ctx, &radios, &vaps)?;

    let mut c = Cfg::default();
    unifi(&mut c, ctx);
    system(&mut c, ctx);
    users(&mut c, ctx)?;
    if bit(caps.hw, 1) || bit(caps.hw, 14) {
        ledbar(&mut c, ctx);
    }
    wireless(&mut c, ctx, &radios, &vaps, &net);
    c.header("connectivity");
    // Meshing (connectivity enabled) is not implemented: no uplink or downlink VAPs.
    c.set("connectivity.status", "disabled");
    net::render_vlan(&mut c, &net);
    net::render_bridge(&mut c, &net, &mut meta);
    if bit(caps.wifi, 19) {
        c.header("mark");
        for (i, (name, bits, shift, location)) in
            [("guest", 2, 30, "skb"), ("vapid", 5, 11, "ubnt"), ("associd", 11, 0, "ubnt")].iter().enumerate()
        {
            let i = i + 1;
            c.set(format!("mark.{i}.name"), name);
            c.set(format!("mark.{i}.bits"), bits);
            c.set(format!("mark.{i}.shift"), shift);
            c.set(format!("mark.{i}.location"), location);
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
        c.set(format!("{s}.status"), "disabled");
    }
    syslog(&mut c, ctx);
    sshd(&mut c, ctx);
    snmp(&mut c, ctx);
    ntp(&mut c, ctx);
    switch(&mut c, ctx);
    if bit(caps.fw2, 28) {
        mdns(&mut c, ctx, &vaps, &net);
    }
    if bit(caps.fw3, 6) {
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
    Ok((c.finish(), meta.to_doc(&ctx.site_id, &ctx.mac)))
}

fn unifi(c: &mut Cfg, ctx: &Ctx) {
    let ctl = ctx.controller;
    let mgmt = ctx.setting("mgmt");
    c.header("unifi");
    c.set("unifi.version", &ctl.version);
    c.set("unifi.anonymous_controller_id", &ctl.reporter_uuid);
    c.opt("unifi.anonymous_site_id", str_of(ctx.site, "anonymous_id"));
    c.set("unifi.reporterid", &ctl.reporter_uuid);
    c.set("unifi.siteid", &ctx.site_id);
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
    c.set("unifi.cfgcap_info", format!("0x{cap:x}"));
}

fn system(c: &mut Cfg, ctx: &Ctx) {
    c.header("system");
    let analytics = flag(ctx.setting("super_mgmt"), "enable_analytics", true);
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
    let mgmt = ctx.setting("mgmt");
    // The crypt(3) hash is random-salted, so it is an input: the controller stores it
    // next to the password (as the official one caches it in the same field).
    let field = if bit(ctx.caps.fw, 10) { "x_ssh_sha512passwd" } else { "x_ssh_md5passwd" };
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
        if bit(ctx.caps.hw, 1) {
            let hex = str_of(ctx.device, "led_override_color").unwrap_or("#0000FF").trim_start_matches('#');
            let rgb = u32::from_str_radix(hex, 16).unwrap_or(0xff);
            c.set("ledbar.color.1.color", 3);
            c.set("ledbar.color.1.r", rgb >> 16 & 0xff);
            c.set("ledbar.color.1.g", rgb >> 8 & 0xff);
            c.set("ledbar.color.1.b", rgb & 0xff);
        }
    }
}

fn wireless(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap], net: &Net) {
    let caps = ctx.caps;
    c.header("wlans (radio)");
    let mut any_stamgr = false;
    if radios.is_empty() {
        c.set("radio.status", "disabled");
        c.header("no wlan provisioned as no radio found");
    } else {
        c.set("radio.status", "enabled");
        c.set("radio.countrycode", wlan::country(ctx));
        c.set("aaa.status", "enabled");
        c.set("wireless.status", "enabled");
        let outdoor = match str_of(ctx.device, "outdoor_mode_override") {
            Some("on") => true,
            Some("off") => false,
            _ => flag(ctx.setting("mgmt"), "outdoor_mode_enabled", false),
        };
        c.set("radio.outdoor", on_off(outdoor));
        any_stamgr = wlan::render_radios(c, ctx, radios, vaps);
        for i in 0..vaps.len() {
            wlan::render_vap(c, ctx, radios, vaps, i, &net.vap_bridge[i]);
        }
    }
    let conn = ctx.setting("connectivity");
    c.header("mesh");
    if bit(caps.wifi, 11) {
        c.set("mesh.status", "enabled");
        c.set("mesh.version", 3);
        c.opt("mesh.essid", str_of(conn, "x_mesh_essid"));
        c.opt("mesh.psk", str_of(conn, "x_mesh_psk"));
        c.opt("mesh.serial1", str_of(ctx.device, "mesh_uplink_1"));
        c.opt("mesh.serial2", str_of(ctx.device, "mesh_uplink_2"));
    } else {
        c.set("mesh.status", "disabled");
    }
    if bit(caps.wifi, 2) {
        bandsteering(c, ctx, radios, vaps);
    }
    if bit(caps.wifi, 5) {
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
    if !flag(ctx.setting("mgmt"), "advanced_feature_enabled", false) || mode == "off" {
        c.set("bandsteering.status", "disabled");
        return;
    }
    c.set("bandsteering.status", "enabled");
    c.set("bandsteering.mode", mode);
    if !bit(ctx.caps.wifi, 3) {
        return;
    }
    let mut k = 0;
    for ng in vaps.iter().filter(|v| radios[v.radio].band == "ng") {
        if let Some(na) = vaps.iter().find(|v| radios[v.radio].band == "na" && v.id == ng.id) {
            k += 1;
            c.set(format!("bandsteering.{k}.status"), "enabled");
            c.set(format!("bandsteering.{k}.vap.1.devname"), ng.dev());
            c.set(format!("bandsteering.{k}.vap.2.devname"), na.dev());
        }
    }
}

/// One VAP's MAC ACL: device, policy and `(mac, type)` entries.
type AclBlock<'a> = (&'a str, &'a str, Vec<(String, &'static str)>);

fn mac_acl(c: &mut Cfg, ctx: &Ctx, vaps: &[Vap]) {
    // Clients pinned ("lock to AP") to some other AP may not join this one.
    let locked_elsewhere: Vec<String> = arr(ctx.state, "clients")
        .iter()
        .filter(|u| str_of(u, "site_id").is_none_or(|s| s == ctx.site_id))
        .filter(|u| flag(u, "fixed_ap_enabled", false))
        .filter(|u| str_of(u, "fixed_ap_mac").is_some_and(|m| !mac_eq(m, &ctx.mac)))
        .filter_map(|u| str_of(u, "mac"))
        .map(str::to_ascii_lowercase)
        .collect();
    let locked_elsewhere = hash_set_order(&locked_elsewhere);
    let mut blocks: Vec<AclBlock> = Vec::new();
    for v in vaps {
        let filtering = flag(&v.w, "mac_filter_enabled", false);
        if !filtering && locked_elsewhere.is_empty() {
            continue;
        }
        let policy = if filtering { str_of(&v.w, "mac_filter_policy").unwrap_or("deny") } else { "deny" };
        let mut entries: Vec<(String, &'static str)> = Vec::new();
        if filtering {
            entries.extend(
                str_list(&v.w, "mac_filter_list")
                    .iter()
                    .map(|m| m.to_ascii_lowercase())
                    .filter(|m| policy != "allow" || !locked_elsewhere.contains(m))
                    .map(|m| (m, "user")),
            );
        }
        if policy == "deny" {
            for m in &locked_elsewhere {
                if !entries.iter().any(|(e, _)| e == m) {
                    entries.push((m.clone(), "lock2ap"));
                }
            }
        }
        blocks.push((v.dev(), policy, entries));
    }
    c.header("mac acl");
    c.set("macacl.status", on_off(!blocks.is_empty()));
    for (k, (dev, policy, entries)) in blocks.iter().enumerate() {
        let k = k + 1;
        c.set(format!("macacl.{k}.status"), "enabled");
        c.set(format!("macacl.{k}.devname"), dev);
        c.set(format!("macacl.{k}.acl.status"), "enabled");
        c.set(format!("macacl.{k}.acl.policy"), policy);
        for (j, (mac, kind)) in entries.iter().enumerate() {
            let j = j + 1;
            c.set(format!("macacl.{k}.acl.{j}.status"), "enabled");
            c.set(format!("macacl.{k}.acl.{j}.mac"), mac);
            c.set(format!("macacl.{k}.acl.{j}.type"), kind);
        }
    }
}

/// The AP's host name: device name reduced to `[0-9A-Za-z-]`, `+` spelled out.
pub fn hostname(name: &str) -> String {
    let mut s = name.to_string();
    if let Some(stripped) = s.strip_suffix('+') {
        s = format!("{stripped}-Plus");
    }
    s = s.replace('+', "-Plus-");
    let s: String = s.chars().filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-').collect();
    s.trim_start_matches('-').chars().take(31).collect()
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
    for i in 1..=2 {
        let dns = cn(&format!("dns{i}")).filter(|d| !d.is_empty());
        match dns {
            Some(ip) => c.set(format!("resolv.nameserver.{i}.ip"), ip),
            None => c.set(format!("resolv.nameserver.{i}.status"), "disabled"),
        }
    }
    if is_static {
        c.opt("resolv.search", cn("dnssuffix").filter(|s| !s.is_empty()));
    }
}

fn syslog(c: &mut Cfg, ctx: &Ctx) {
    let s = ctx.setting("rsyslogd");
    let enabled = flag(s, "enabled", false);
    let this = flag(s, "this_controller", false);
    let encrypted_only = flag(s, "this_controller_encrypted_only", false);
    if enabled && this && encrypted_only && !bit(ctx.caps.fw, 24) {
        return;
    }
    let wants_ap_logs = flag(s, "log_all_contents", false) || str_list(s, "contents").contains(&"access_points");
    if enabled && !this && !wants_ap_logs {
        return;
    }
    let controller_ip = ctx.controller.syslog_ip.clone().or_else(|| ctx.inform_str("inform_ip").map(str::to_string));
    c.header("syslog");
    c.set("syslog.status", "enabled");
    c.set("syslog.level", if enabled && flag(s, "debug", false) { 8 } else { 7 });
    if this {
        c.set("syslog.remote.encrypt", "enabled");
        c.opt("syslog.remote.key", str_of(ctx.device, "syslog_key"));
    }
    if enabled {
        let (ip, port) = if this {
            (controller_ip.clone(), Some("5514".to_string()))
        } else {
            (str_of(s, "ip").map(str::to_string), text_of(s, "port"))
        };
        c.opt("syslog.remote.ip", ip);
        c.opt("syslog.remote.port", port);
        c.set("syslog.remote.status", "enabled");
    }
    if this || flag(s, "netconsole_enabled", false) {
        let (host, port) = if this {
            (controller_ip, Some("5514".to_string()))
        } else {
            (str_of(s, "netconsole_host").map(str::to_string), text_of(s, "netconsole_port"))
        };
        c.opt("netconsole.host", host);
        c.opt("netconsole.port", port);
        c.set("netconsole.status", "enabled");
    }
}

fn sshd(c: &mut Cfg, ctx: &Ctx) {
    let mgmt = ctx.setting("mgmt");
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
        let k = |s: &str| format!("sshd.auth.key.{}.{s}", i + 1);
        c.set(k("status"), "enabled");
        c.opt(k("value"), str_of(key, "key"));
        c.opt(k("type"), str_of(key, "type"));
        c.opt(k("comment"), str_of(key, "comment").or(str_of(key, "name")));
    }
    if !flag(mgmt, "x_ssh_bind_wildcard", false) {
        c.set("sshd.1.status", "enabled");
        c.set("sshd.1.ifname", "br0");
    }
}

/// `snmp.*`, no section header, nothing at all while SNMP is off. v3 needs
/// firmware capability bit 14; the community is cut to 256 characters.
fn snmp(c: &mut Cfg, ctx: &Ctx) {
    let s = ctx.setting("snmp");
    let v1 = flag(s, "enabled", false);
    let v3 = flag(s, "enabledV3", false) && bit(ctx.caps.fw, 14);
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
        (1..=4).filter_map(|i| str_of(s, &format!("ntp_server_{i}"))).filter(looks_like_host).collect();
    c.header("ntpclient");
    if servers.is_empty() {
        c.set("ntpclient.status", "disabled");
        return;
    }
    c.set("ntpclient.status", "enabled");
    for (i, server) in servers.iter().enumerate() {
        c.set(format!("ntpclient.{}.status", i + 1), "enabled");
        c.set(format!("ntpclient.{}.server", i + 1), server);
    }
}

fn switch(c: &mut Cfg, ctx: &Ctx) {
    c.header("switch");
    if !bit(ctx.caps.fw, 4) {
        return;
    }
    c.set("switch.status", "disabled");
    c.set("switch.vlan.status", on_off(flag(ctx.device, "switch_vlan_enabled", false)));
    c.set("switch.jumboframes", on_off(flag(ctx.device, "jumboframe_enabled", false)));
    c.set("switch.dot1x.status", "disabled");
    let ports: i64 = arr(ctx.device, "ethernet_table").iter().filter_map(|e| int_of(e, "num_port")).sum();
    for i in 1..=ports.max(1) {
        let name = arr(ctx.device, "port_overrides")
            .iter()
            .find(|p| int_of(p, "port_idx") == Some(i))
            .and_then(|p| str_of(p, "name"))
            .map_or_else(|| format!("Port {i}"), str::to_string);
        c.set(format!("switch.port.{i}.name"), name);
        c.set(format!("switch.port.{i}.opmode"), "switch");
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
fn mdns_auto_services() -> Vec<String> {
    MDNS_SERVICES
        .iter()
        .flat_map(|(_, _, types)| {
            let mut t: Vec<&str> = types.to_vec();
            t.sort_unstable();
            t
        })
        .map(str::to_string)
        .collect()
}

struct MdnsEntry {
    networks: Vec<Option<String>>,
    mode: String,
    services: Vec<String>,
}

fn entry_services(e: &Value) -> Vec<String> {
    let mut out: Vec<String> = arr(e, "predefined_services")
        .iter()
        .filter_map(|s| str_of(s, "code"))
        .flat_map(mdns_services)
        .map(|s| s.to_string())
        .collect();
    for s in arr(e, "custom_services") {
        let name = s.as_str().or_else(|| str_of(s, "address")).or_else(|| str_of(s, "name"));
        out.extend(name.map(str::to_string));
    }
    out
}

fn mdns(c: &mut Cfg, ctx: &Ctx, vaps: &[Vap], net: &Net) {
    let groups = wlan::ap_groups(ctx);
    let applies = |e: &Value| match str_of(e, "ap_scope_mode").unwrap_or("all") {
        "all" => true,
        "specific" => str_list(e, "ap_macs").iter().any(|m| mac_eq(m, &ctx.mac)),
        "group" => str_list(e, "ap_group_ids").iter().any(|g| groups.iter().any(|m| m == g)),
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
    let bridge_of_vlan = |vlan: i64| {
        let tag = if vlan == 1 { 0 } else { vlan };
        net.bridges.iter().find(|b| b.vlan == tag).map(|b| b.name.clone())
    };
    let (mut f, mut p) = (0, 0);
    for wv in wlans {
        let w = &wv.w;
        let devs: Vec<&str> = vaps.iter().filter(|v| v.id == wv.id).map(Vap::dev).collect();
        let own = str_of(w, "networkconf_id").map(str::to_string);
        let mut entries: Vec<MdnsEntry> = Vec::new();
        if str_of(w, "mdns_proxy_mode") == Some("custom") {
            let custom: Vec<&Value> = arr(w, "mdns_proxy_custom").iter().filter(|e| applies(e)).collect();
            let lists_own =
                custom.iter().any(|e| own.as_deref().is_some_and(|o| str_list(e, "networkconf_ids").contains(&o)));
            if !lists_own {
                let all = custom.iter().any(|e| str_of(e, "services_mode") == Some("all"));
                let mut union: Vec<String> = Vec::new();
                for s in custom.iter().flat_map(|e| entry_services(e)) {
                    if !union.contains(&s) {
                        union.push(s);
                    }
                }
                entries.push(MdnsEntry {
                    networks: vec![own.clone()],
                    mode: if all { "all" } else { "specific" }.to_string(),
                    services: union,
                });
            }
            entries.extend(custom.iter().map(|e| MdnsEntry {
                networks: str_list(e, "networkconf_ids").into_iter().map(|n| Some(n.to_string())).collect(),
                mode: str_of(e, "services_mode").unwrap_or("all").to_string(),
                services: entry_services(e),
            }));
        } else {
            entries.push(MdnsEntry { networks: vec![own.clone()], mode: "specific".into(), services: mdns_auto_services() });
        }
        let own_bridge = bridge_of_vlan(network_vlan(ctx, own.as_deref()));
        for e in entries {
            let others: Vec<String> = e
                .networks
                .iter()
                .filter(|n| **n != own)
                .filter_map(|n| bridge_of_vlan(network_vlan(ctx, n.as_deref())))
                .filter(|b| Some(b) != own_bridge.as_ref())
                .collect();
            if let (false, Some(own_bridge)) = (others.is_empty(), &own_bridge) {
                p += 1;
                c.set(format!("mdns_sd.proxy.{p}.status"), "enabled");
                c.set(format!("mdns_sd.proxy.{p}.dst.1.devname"), own_bridge);
                for (i, b) in others.iter().enumerate() {
                    c.set(format!("mdns_sd.proxy.{p}.src.{}.devname", i + 1), b);
                }
            }
            for n in &e.networks {
                f += 1;
                c.set(format!("mdns_sd.filter.{f}.vlan"), network_vlan(ctx, n.as_deref()));
                c.set(format!("mdns_sd.filter.{f}.policy"), if e.mode == "all" { "allow" } else { "deny" });
                for (i, d) in devs.iter().enumerate() {
                    c.set(format!("mdns_sd.filter.{f}.dst.{}.devname", i + 1), d);
                }
                if e.mode == "specific" {
                    for (i, s) in e.services.iter().enumerate() {
                        c.set(format!("mdns_sd.filter.{f}.service.{}.name", i + 1), s);
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

/// A user group's limits (kbps; -1 or missing: unlimited).
fn limits(g: &Value) -> (i64, i64) {
    (int_of(g, "qos_rate_max_down").unwrap_or(-1), int_of(g, "qos_rate_max_up").unwrap_or(-1))
}

/// The most a radio can carry (Mbps), the ceiling used for "unlimited". The
/// official controller takes it from its model table; this estimates it per
/// spatial stream (150 at 2.4 GHz, 600 for Wi-Fi 6 / 433 for Wi-Fi 5 at
/// 5 GHz), which gives the table's 300 and 2400 for a U6-Mesh.
fn radio_max_mbps(r: &Radio) -> i64 {
    let nss = int_of(r.doc, "nss").unwrap_or(2).max(1);
    let per_stream = match r.band.as_str() {
        "ng" => 150,
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
    let groups: Vec<&Value> = ctx.site_docs("usergroup").collect();
    if !groups.iter().any(|g| limits(g) != (-1, -1)) || vaps.is_empty() {
        c.set("qos.status", "disabled");
        return;
    }
    c.set("qos.status", "enabled");
    c.set("qos.mode", 1);
    // Wired uplinks: the AP's ports, else the interface it reports as its uplink.
    let mut uplinks: Vec<String> = ctx
        .inform
        .and_then(|p| p["port_table"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| str_of(p, "ifname").map(str::to_string))
        .collect();
    if uplinks.is_empty() {
        uplinks.push(ctx.inform_str("uplink").filter(|u| u.starts_with("eth")).unwrap_or("eth0").to_string());
    }
    let mut k = 0;
    for u in &uplinks {
        k += 1;
        c.set(format!("qos.if.{k}.devname"), u);
        c.set(format!("qos.if.{k}.devspeed"), 1000);
        c.set(format!("qos.if.{k}.type"), "uplink");
    }
    for v in vaps {
        k += 1;
        c.set(format!("qos.if.{k}.devname"), v.dev());
        c.set(format!("qos.if.{k}.devspeed"), radio_max_mbps(&radios[v.radio]));
    }
    let default = groups.iter().find(|g| str_of(g, "attr_hidden_id") == Some("Default")).copied();
    for (i, v) in vaps.iter().enumerate() {
        let m = i + 1;
        let group = str_of(&v.w, "usergroup_id").and_then(|id| groups.iter().find(|g| crate::json::oid(g) == Some(id)).copied()).or(default);
        let (down, up) = group.map_or((-1, -1), limits);
        let ceiling = radio_max_mbps(&radios[v.radio]);
        c.set(format!("qos.vap.{m}.id"), m);
        c.set(format!("qos.vap.{m}.devname"), v.dev());
        c.set(format!("qos.vap.{m}.dwnlink.minspeed"), if down > 0 { down } else { ceiling });
        if down > 0 {
            c.set(format!("qos.vap.{m}.dwnlink.maxspeed"), down);
        }
        for (j, u) in uplinks.iter().enumerate() {
            let j = j + 1;
            c.set(format!("qos.vap.{m}.uplink.{j}.devname"), u);
            c.set(format!("qos.vap.{m}.uplink.{j}.minspeed"), if up > 0 { up } else { ceiling });
            if up > 0 {
                c.set(format!("qos.vap.{m}.uplink.{j}.maxspeed"), up);
            }
        }
    }
}

fn cron(c: &mut Cfg, ctx: &Ctx, radios: &[Radio], vaps: &[Vap]) {
    let schedules = vaps.iter().any(|v| !arr(&v.w, "schedule_with_duration").is_empty());
    let country = wlan::country(ctx);
    let fcc = country == "840" || country == "124";
    let dfs = radios.iter().any(|r| {
        r.band == "na"
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
        c.set(format!("cron.1.job.{j}.status"), "enabled");
        c.set(format!("cron.1.job.{j}.schedule"), schedule);
        c.set(format!("cron.1.job.{j}.cmd"), cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::hostname;

    #[test]
    fn hostnames() {
        assert_eq!(hostname("Garage AP"), "GarageAP");
        assert_eq!(hostname("U6+"), "U6-Plus");
        assert_eq!(hostname("-a+b"), "a-Plus-b");
    }
}
