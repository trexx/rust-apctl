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

/// The host of a pending migration: `migrate_inform_url`, when that is a URL with a
/// host (not null or empty).
fn migration_host<'a>(ctx: &Ctx<'a>) -> Option<&'a str> {
    str_of(ctx.device, "migrate_inform_url").and_then(host_port).map(|(h, _)| h)
}

/// The host the AP should use for the controller, first match wins: a pending
/// migration URL (`migration`, from [`migration_host`]), the "override inform host"
/// hostname, the host of the device's stored inform URL, the controller's own host.
fn inform_host<'a>(ctx: &Ctx<'a>, migration: Option<&'a str>) -> &'a str {
    let override_host = flag(ctx.super_mgmt, "override_inform_host", false)
        .then(|| str_of(ctx.setting("super_identity"), "hostname").unwrap_or("example-domain.ui.com"));
    migration
        .or(override_host)
        .or_else(|| str_of(ctx.device, "inform_url").and_then(host_port).map(|(h, _)| h))
        .unwrap_or(&ctx.controller.host)
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
    let migration = migration_host(ctx);
    let host = inform_host(ctx, migration);
    let port_of = |url: &str| host_port(url).and_then(|(_, p)| p);
    let inform_port = str_of(ctx.device, "inform_url").and_then(port_of).unwrap_or(c.inform_port);
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
    if flag(ctx.super_mgmt, "override_inform_host", false) || migration.is_some() {
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
