//! `mgmt_cfg`: how the AP reaches the controller.

use crate::Ctx;
use crate::cfg::Cfg;
use crate::json::{flag, override_of, str_of};

/// `scheme://host[:port][/path]` split into host and port.
fn host_port(url: &str) -> Option<(String, Option<u16>)> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    // Bracketed IPv6 literal.
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
        return Some((format!("[{host}]"), port));
    }
    Some(match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()),
        None => (authority.to_string(), None),
    })
}

/// The host the AP should use for the controller, first match wins: a pending
/// migration URL, the "override inform host" hostname, the host of the device's stored
/// inform URL, the controller's own inform URL.
fn inform_host(ctx: &Ctx) -> String {
    let override_host = flag(ctx.super_mgmt, "override_inform_host", false)
        .then(|| str_of(ctx.setting("super_identity"), "hostname").unwrap_or("example-domain.ui.com"));
    [str_of(ctx.device, "migrate_inform_url").and_then(host_port).map(|(h, _)| h), override_host.map(str::to_string)]
        .into_iter()
        .flatten()
        .chain(str_of(ctx.device, "inform_url").and_then(host_port).map(|(h, _)| h))
        .chain(host_port(&ctx.controller.inform_url).map(|(h, _)| h))
        .next()
        .unwrap_or_default()
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
    let host = inform_host(ctx);
    let port_of = |url: &str| host_port(url).and_then(|(_, p)| p);
    let stun_port = port_of(&c.stun_url).unwrap_or(3478);
    let https_port = port_of(&c.mgmt_url).unwrap_or(8443);
    let inform_port = str_of(ctx.device, "inform_url").and_then(port_of).or_else(|| port_of(&c.inform_url)).unwrap_or(8080);
    let site_name = str_of(ctx.site, "name").unwrap_or("default");

    let mut out = Cfg::default();
    out.set("capability", "notif,notif-assoc-stat");
    out.set("selfrun_guest_mode", "pass");
    out.set("cfgversion", ctx.cfgversion);
    out.set("led_enabled", led_enabled(ctx));
    out.set("stun_url", format_args!("stun://{host}:{stun_port}/"));
    let https = if https_port == 443 { String::new() } else { format!(":{https_port}") };
    out.set("mgmt_url", format_args!("https://{host}{https}/manage/site/{site_name}"));
    // The key is only resent while the AP still authenticates with an older one.
    if let (Some(key), Some(used)) = (str_of(ctx.device, "x_authkey"), str_of(ctx.device, "x_inform_authkey"))
        && key != used
    {
        out.set("authkey", key);
    }
    if flag(ctx.super_mgmt, "override_inform_host", false) || ctx.device.get("migrate_inform_url").is_some() {
        out.set("inform_url", format_args!("http://{host}:{inform_port}/inform"));
    }
    out.set("use_aes_gcm", "true");
    out.set("report_crash", "true");
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::host_port;

    #[test]
    fn splits_urls() {
        assert_eq!(host_port("http://a.b:8080/inform"), Some(("a.b".into(), Some(8080))));
        assert_eq!(host_port("https://a.b"), Some(("a.b".into(), None)));
        assert_eq!(host_port("stun://[fd00::1]:3478/"), Some(("[fd00::1]".into(), Some(3478))));
    }
}
