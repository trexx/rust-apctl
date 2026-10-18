//! `mgmt_cfg`: how the AP reaches the controller.

use crate::Ctx;
use crate::cfg::Cfg;
use crate::json::{flag, override_of, str_of};

/// `scheme://host[:port][/path]` split into host and port.
fn host_port(url: &str) -> Option<(&str, Option<u16>)> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    // Bracketed IPv6 literal: the host keeps its brackets.
    if authority.starts_with('[') {
        let end = authority.find(']')? + 1;
        let port = authority[end..].strip_prefix(':').and_then(|p| p.parse().ok());
        return Some((&authority[..end], port));
    }
    Some(match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()),
        None => (authority, None),
    })
}

/// Where the AP should reach the controller, as the official controller resolves it.
struct Address<'a> {
    host: &'a str,
    /// The inform port.
    port: u16,
    /// A pending migration (`migrate_inform_url`) supplied the address.
    migrating: bool,
}

/// The host and inform port the AP should use, first match wins for each:
/// - a pending migration, when `migrate_inform_url` is a URL with a host (not null or
///   empty): its host and port;
/// - the host only: the "override inform host" hostname, when that is not blank;
/// - the device's stored inform URL: its host and port;
/// - the controller's own host and inform port.
///
/// A URL that names no port means 80, the http default.
fn address<'a>(ctx: &Ctx<'a>) -> Address<'a> {
    let url = |key| str_of(ctx.device, key).and_then(host_port).map(|(h, p)| (h, p.unwrap_or(80)));
    if let Some((host, port)) = url("migrate_inform_url") {
        return Address { host, port, migrating: true };
    }
    let stored = url("inform_url");
    let override_host = flag(ctx.super_mgmt, "override_inform_host", false)
        .then(|| str_of(ctx.setting("super_identity"), "hostname").unwrap_or("example-domain.ui.com"))
        .filter(|h| !h.trim().is_empty());
    Address {
        host: override_host.or(stored.map(|(h, _)| h)).unwrap_or(&ctx.controller.host),
        port: stored.map_or(ctx.controller.inform_port, |(_, p)| p),
        migrating: false,
    }
}

/// Whether the AP shows its LED, from the device override and the site default.
pub fn led_enabled(ctx: &Ctx) -> bool {
    if flag(ctx.device, "disabled", false) {
        return false;
    }
    override_of(ctx.device, "led_override", flag(ctx.mgmt, "led_enabled", true))
}

pub fn render(ctx: &Ctx) -> String {
    let c = ctx.controller;
    let Address { host, port: inform_port, migrating } = address(ctx);
    let site_name = str_of(ctx.site, "name").unwrap_or("default");

    let mut out = Cfg::default();
    out.set("capability", "notif,notif-assoc-stat");
    out.set("selfrun_guest_mode", "pass");
    out.set("cfgversion", ctx.cfgversion);
    out.set("led_enabled", led_enabled(ctx));
    out.set("stun_url", format_args!("stun://{host}:{}/", c.stun_port));
    let https = if c.https_port == 443 { String::new() } else { format!(":{}", c.https_port) };
    out.set("mgmt_url", format_args!("https://{host}{https}/manage/site/{site_name}"));
    // The key is only resent while the AP still authenticates with an older one.
    if let (Some(key), Some(used)) = (str_of(ctx.device, "x_authkey"), str_of(ctx.device, "x_inform_authkey"))
        && key != used
    {
        out.set("authkey", key);
    }
    // Sent with the override on even when its hostname is blank, as the official
    // controller does: the AP is then pointed at the host it already uses.
    if flag(ctx.super_mgmt, "override_inform_host", false) || migrating {
        out.set("inform_url", format_args!("http://{host}:{inform_port}/inform"));
    }
    out.set("use_aes_gcm", "true");
    out.set("report_crash", "true");
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Controller, Input};
    use serde_json::{Value, json};

    /// The `mgmt_cfg` of an AP with these extra device fields and settings documents.
    fn mgmt_cfg(device: Value, settings: Value, controller: &Controller) -> String {
        let mac = "02:00:00:00:00:01";
        let mut doc = json!({ "mac": mac, "site_id": "s", "type": "uap" });
        doc.as_object_mut().unwrap().extend(device.as_object().unwrap().clone());
        let state = json!({ "sites": [{ "_id": "s", "name": "default" }], "devices": [doc], "setting": settings });
        let ctx = Ctx::new(&Input { state: &state, device_mac: mac, inform: None, cfgversion: "1", controller }).unwrap();
        render(&ctx)
    }

    fn line(cfg: &str, key: &str) -> Option<String> {
        cfg.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix('=')).map(str::to_string)
    }

    fn inform_url_line(migrate: Value) -> Option<String> {
        let controller = Controller { host: "unifi.example.net".into(), ..Default::default() };
        line(&mgmt_cfg(json!({ "migrate_inform_url": migrate }), json!([]), &controller), "inform_url")
    }

    #[test]
    fn inform_url_is_sent_only_for_a_real_migration() {
        assert_eq!(inform_url_line(json!("http://new.example.net:8080/inform")).as_deref(), Some("http://new.example.net:8080/inform"));
        for none in [json!(null), json!(""), json!("http:///inform"), json!(3)] {
            assert_eq!(inform_url_line(none.clone()), None, "{none}");
        }
    }

    #[test]
    fn a_migration_brings_its_own_port() {
        let controller = Controller { host: "unifi.example.net".into(), ..Default::default() };
        let device = |migrate: &str| json!({ "inform_url": "http://old.example.net:8080/inform", "migrate_inform_url": migrate });
        let cfg = mgmt_cfg(device("http://new.example.net:8088/inform"), json!([]), &controller);
        assert_eq!(line(&cfg, "inform_url").as_deref(), Some("http://new.example.net:8088/inform"));
        assert_eq!(line(&cfg, "stun_url").as_deref(), Some("stun://new.example.net:3478/"));
        // No port in the URL is the http default, not the controller's or the stored URL's.
        let cfg = mgmt_cfg(device("http://new.example.net/inform"), json!([]), &controller);
        assert_eq!(line(&cfg, "inform_url").as_deref(), Some("http://new.example.net:80/inform"));
    }

    #[test]
    fn a_blank_override_hostname_is_ignored() {
        let controller = Controller { host: "unifi.example.net".into(), inform_port: 8081, ..Default::default() };
        for blank in ["", "  "] {
            let settings = json!([{ "key": "super_mgmt", "override_inform_host": true }, { "key": "super_identity", "hostname": blank }]);
            let cfg = mgmt_cfg(json!({ "inform_url": "http://known.example.net:8080/inform" }), settings.clone(), &controller);
            assert_eq!(line(&cfg, "stun_url").as_deref(), Some("stun://known.example.net:3478/"), "{blank:?}");
            assert_eq!(line(&cfg, "inform_url").as_deref(), Some("http://known.example.net:8080/inform"), "{blank:?}");
            let cfg = mgmt_cfg(json!({}), settings, &controller);
            assert_eq!(line(&cfg, "inform_url").as_deref(), Some("http://unifi.example.net:8081/inform"), "{blank:?}");
        }
        // A set hostname wins over the stored URL's host, but the port is still the stored URL's.
        let settings = json!([{ "key": "super_mgmt", "override_inform_host": true }, { "key": "super_identity", "hostname": "ctl.example.net" }]);
        let cfg = mgmt_cfg(json!({ "inform_url": "http://known.example.net/inform" }), settings, &controller);
        assert_eq!(line(&cfg, "inform_url").as_deref(), Some("http://ctl.example.net:80/inform"));
    }

    #[test]
    fn the_controllers_ports_reach_the_urls() {
        let controller = Controller { host: "unifi.example.net".into(), inform_port: 8081, https_port: 443, stun_port: 3479, ..Default::default() };
        let settings = json!([{ "key": "super_mgmt", "override_inform_host": true }, { "key": "super_identity", "hostname": "ctl.example.net" }]);
        let cfg = mgmt_cfg(json!({}), settings, &controller);
        assert_eq!(line(&cfg, "stun_url").as_deref(), Some("stun://ctl.example.net:3479/"));
        assert_eq!(line(&cfg, "mgmt_url").as_deref(), Some("https://ctl.example.net/manage/site/default"), "443 is left out");
        assert_eq!(line(&cfg, "inform_url").as_deref(), Some("http://ctl.example.net:8081/inform"));
        let cfg = mgmt_cfg(json!({}), json!([]), &Controller { https_port: 8444, ..Default::default() });
        assert_eq!(line(&cfg, "mgmt_url").as_deref(), Some("https://unifi:8444/manage/site/default"));
    }

    #[test]
    fn splits_urls() {
        assert_eq!(host_port("http://a.b:8080/inform"), Some(("a.b", Some(8080))));
        assert_eq!(host_port("https://a.b"), Some(("a.b", None)));
        assert_eq!(host_port("stun://[fd00::1]:3478/"), Some(("[fd00::1]", Some(3478))));
        assert_eq!(host_port("http://[fd00::1]/inform"), Some(("[fd00::1]", None)));
        assert_eq!(host_port("http://[fd00::1/inform"), None, "an unclosed bracket");
    }
}
