//! Turns decoded payloads from a real network into shareable test fixtures.
//!
//! Every identifying or secret value is replaced with a stable fake: the same
//! input always maps to the same output within one run, so diffs between
//! fixtures stay meaningful. After rewriting, the output is scanned for every
//! original value that was replaced; any survivor aborts the run.
//!
//! It fails closed: a string field passes (with the identifiers inside it rewritten)
//! only when it is on the allow-list of fields holding settings, states, versions and
//! the like ([`PASS`], [`PASS_AT`], `--keep`), or when its value is a number or a bare
//! identifier. Any other value is replaced whole as text people wrote (`text-N`), and
//! the run lists those fields. Everything under a secret key is a secret, however
//! deeply nested; host names in URLs are replaced unless `--domain` covers them; object
//! keys that are identifiers are rewritten like values.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;

use wire::cfgdiff;

/// What a fake stands for: it decides the fake's shape, and how the leak check looks
/// for the original.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Kind {
    Secret,
    SshKey,
    Mac,
    Uuid,
    Hex,
    Ipv4,
    Ipv6,
    Domain,
    /// Hostnames and device names.
    Name,
    Ssid,
    /// Names people gave clients.
    Alias,
    /// mDNS service names with a device ID in them.
    Service,
    Fingerprint,
    Qrid,
    /// Client manufacturers.
    Vendor,
    /// Binary UUIDs, base64 encoded.
    Uuid64,
    /// Text people wrote (notes, descriptions, SNMP location), and any field not on
    /// the allow-list.
    Text,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Secret => "secret",
            Kind::SshKey => "ssh key",
            Kind::Mac => "mac",
            Kind::Uuid => "uuid",
            Kind::Hex => "hex",
            Kind::Ipv4 => "ipv4",
            Kind::Ipv6 => "ipv6",
            Kind::Domain => "domain",
            Kind::Name => "name",
            Kind::Ssid => "ssid",
            Kind::Alias => "alias",
            Kind::Service => "service",
            Kind::Fingerprint => "fingerprint",
            Kind::Qrid => "qrid",
            Kind::Vendor => "vendor",
            Kind::Uuid64 => "uuid64",
            Kind::Text => "text",
        }
    }

    /// How the leak check recognises an original of `len` bytes, if it looks at all.
    fn rule(self, len: usize) -> Option<Rule> {
        match self {
            // Secrets are looked for even when short; long ones anywhere at all.
            Kind::Secret | Kind::SshKey if len < 3 => None,
            Kind::Secret | Kind::SshKey if len >= 8 => Some(Rule::Anywhere),
            Kind::Secret | Kind::SshKey => Some(Rule::Alnum),
            Kind::Ipv4 => Some(Rule::Ipv4),
            Kind::Ipv6 => Some(Rule::Ipv6),
            Kind::Domain => Some(Rule::Word),
            // Names and SSIDs under 4 characters ("tv", "Mac") collide with ordinary
            // words such as the JSON key "mac"; they identify nothing.
            _ if len < 4 => None,
            _ => Some(Rule::Word),
        }
    }
}

/// Where an original found in the output counts as a leak.
#[derive(Clone, Copy, Debug)]
enum Rule {
    Anywhere,
    /// A whole word: names inside longer identifiers (a hostname inside an mDNS
    /// service code, `google_chromecast`) are not leaks.
    Word,
    /// Not next to a letter or digit (a short secret inside an ordinary word is not one).
    Alnum,
    /// A whole word that is not part of a longer dotted number (an OID, a version).
    Ipv4,
    /// A whole word that is not part of a longer colon-separated one.
    Ipv6,
}

impl Rule {
    fn leaks(self, text: &[u8], a: usize, b: usize) -> bool {
        let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        match self {
            Rule::Anywhere => true,
            Rule::Word => stands_alone(text, a, b, word),
            Rule::Alnum => stands_alone(text, a, b, |c| c.is_ascii_alphanumeric()),
            Rule::Ipv4 => stands_alone(text, a, b, word) && !in_longer_dotted(text, a, b),
            Rule::Ipv6 => stands_alone(text, a, b, |c| word(c) || c == b':'),
        }
    }
}

/// Whether `text[a..b]` has no word character (by `word`) right before or after it.
fn stands_alone(text: &[u8], a: usize, b: usize, word: impl Fn(u8) -> bool) -> bool {
    !text[..a].last().is_some_and(|&c| word(c)) && !text.get(b).is_some_and(|&c| word(c))
}

/// A field's names, lowercased, as the allow-lists and `--keep` know it.
struct Names {
    key: String,
    /// A config key's last word that is not a number; a JSON key itself.
    last: String,
    /// A config key with its numbers as `n`; a JSON key with its parent (`radio_table.name`).
    at: String,
}

impl Names {
    /// `key` is a JSON key inside the object or array under `parent`, or a dotted config key.
    fn new(parent: &str, key: &str) -> Self {
        let k = key.to_ascii_lowercase();
        let number = |w: &str| w.bytes().all(|b| b.is_ascii_digit());
        let (last, at) = if k.contains('.') {
            (k.rsplit('.').find(|w| !number(w)).unwrap_or(&k).to_string(), k.split('.').map(|w| if number(w) { "n" } else { w }).collect::<Vec<_>>().join("."))
        } else {
            (k.clone(), if parent.is_empty() { k.clone() } else { format!("{}.{k}", parent.to_ascii_lowercase()) })
        };
        Names { key: k, last, at }
    }
}

/// Fields (JSON keys, or the last word of a config key) whose values pass: settings,
/// states, modes, versions, interface and model names. Identifiers inside them are
/// still rewritten.
const PASS: &[&str] = &[
    // Inform and reply payloads.
    "_type", "architecture", "assoc_status", "auth_algo", "auth_rssi", "auth_utc", "band", "board_rev", "bomrev", "bomrev_id",
    "bootrom_version", "bridge_name", "bssid", "cfgversion", "cmd", "country_code", "cpu", "event_id", "event_type", "family", "fw_version",
    "gateway_ip", "group_ip", "hash_id", "id", "include_blocks", "inform_ip", "inform_url", "interval", "ip", "ipv6", "ipv6_addresses",
    "kernel_version", "keyid", "last_error_str", "loadavg_1", "loadavg_15", "loadavg_5", "mac", "md5", "mem", "message_type", "model",
    "model_display", "netmask", "notif_reason", "op", "radio", "radio_name", "reason", "reboot_type", "required_version", "resolved",
    "security", "serial", "server_time_in_utc", "state", "timestamp", "type", "uplink", "uptime", "uptime_str", "url", "usage", "vap",
    "version",
    // MongoDB extended JSON.
    "$date", "$numberlong", "$oid", "subtype",
    // Controller settings (an import snapshot).
    "action", "advanced_filtering_preference", "analytics_disapproved_for", "ap_group_mode", "ap_scope_mode", "attr_hidden_id",
    "attr_no_delete", "auth", "auto_channel_presets_type", "autobackup_cron_expr", "autobackup_timezone", "available_controller_channels",
    "available_firmware_channels", "bc_filter_list", "broadcasting_aps", "channel", "channel_width", "channels_6e", "channels_na",
    "channels_ng", "code", "countries", "cron_expr", "data_retention_setting_preference", "default_security_posture", "device_auth",
    "device_macs", "dhcpd_ip_1", "dhcpd_ip_2", "dhcpd_ip_3", "dhcpd_start", "dhcpd_stop", "dhcpd_unifi_controller", "dhcpd_wins_1",
    "dhcpd_wins_2", "dhcpdv6_start", "dhcpdv6_stop", "dns_assistance_mode", "dns_assistance_servers", "dot1x_fallback_networkconf_id",
    "dtim_mode", "enabled_for", "failover_querier", "fastleave_for_network_ids", "firmware_channel", "gateway_type", "ht", "ht_modes_na",
    "ht_modes_ng", "ikev2_reauthentication_method", "ip_subnet", "ips_mode", "ipv6_client_address_assignment", "ipv6_interface_type",
    "ipv6_pd_interface", "ipv6_pd_start", "ipv6_pd_stop", "ipv6_ra_priority", "ipv6_setting_preference", "key", "layout_preference",
    "led_override", "live_chat", "live_updates", "mac_filter_list", "mac_filter_policy", "mdns_proxy_mode", "mgmt_network_id",
    "minrate_setting_preference", "mode", "mss_clamp", "multicast_suppressor_mode", "netconsole_port", "network_ids", "networkconf_id",
    "networkgroup", "optimize", "pmf_cipher", "pmf_mode", "port", "portal_customized_bg_color", "portal_customized_bg_type",
    "portal_customized_box_color", "portal_customized_box_text_color", "portal_customized_button_color",
    "portal_customized_button_text_color", "portal_customized_languages", "portal_customized_link_color",
    "portal_customized_logo_position", "portal_customized_text_color", "primary_dns_server", "primary_querier", "purpose", "querier_mode",
    "querier_subscription_mode", "radios", "radius_macacl_format", "radiusprofile_id", "raw_color_hex", "restricted_subnet_1",
    "restricted_subnet_2", "restricted_subnet_3", "secondary_dns_server", "server_names", "services_mode", "setting_preference", "site_id", "source",
    "stp_version", "subscription_mode", "template_engine", "timeout_setting_preference", "timezone", "traffic_direction",
    "tx_power_mode", "uplink_type", "usergroup_id", "wlan_band", "wlan_bands", "wlangroup_id_na", "wlangroup_id_ng", "wpa_enc",
    "wpa_mode",
    // The last word of system_cfg and mgmt_cfg keys.
    "11k", "acktimeout", "acsdfs", "active", "addmtikie", "advertise_ap_name", "always_send_crash_logs", "anonymous_controller_id",
    "anonymous_site_id", "antenna", "anti_clogging", "ap_mode", "auth_cache", "authmode", "auto", "autowds", "b", "beacon_rate",
    "bga_filter", "bits", "blklst", "brightness", "bss_transition", "bypass_types", "capability", "cfgcap_info", "cipher", "clksel",
    "color", "country_beacon", "countrycode", "devname", "driver", "dtim_period", "dynamic_vlan", "eapol_version", "element_adopt",
    "ema_samples", "enable", "enabled", "encrypt", "enhance", "enhanced_192", "fd", "forbiasauto", "g", "gain", "green_ap",
    "group_rekey", "has_groups", "hide_ssid", "idp", "ieee_mode", "ifname", "inspect", "iot", "is_guest", "jumboframes", "l2_isolation",
    "led_enabled", "level", "log_level", "max_sens", "maxsta", "mcast", "mcastrate", "mcip", "mcs", "mgmt", "mgmt_rate", "mgmt_url",
    "minrate_below_disable", "minrate_data", "minrssi_backoff", "nameserver", "no2ghz_oui", "none", "opmode", "outdoor", "p2p",
    "p2p_cross_connect", "pairwise", "parent", "persistent", "phyname", "policy", "promisc", "proxy_arp", "pureg", "puren", "qbssload",
    "r", "report_crash", "reporterid", "resetbtn", "rfscan", "route", "rssi", "schedule", "schedule_enabled", "schedule_invert",
    "selfrun_guest_mode", "servers", "shell", "shift", "siteid", "size", "status", "stun_url", "support", "suppressor", "sync",
    "tdls_prohibit", "threshold", "timeout", "transition", "txpower", "txpower_mode", "uapsd", "up", "use_aes_gcm", "verbose", "vlan",
    "vport", "vwire", "wds", "wmm", "wpa",
];

/// Fields that pass only in one place: a JSON key inside the object or array under
/// another key (`radio_table.name`), or a whole config key with its numbers as `n`.
const PASS_AT: &[&str] = &[
    "antenna_table.name", "athstats.name", "bridge_port.device_name", "ethernet_table.name", "if_table.name", "radio_table.name",
    "sites.name", "vap_table.name", "widgets.name", "wireless.device_name", "mark.n.location", "mark.n.name",
    // The kind of an administrator's SSH key ("ssh-ed25519"), under the secret x_ssh_keys.
    "x_ssh_keys.type",
];

/// Numeric settings under keys that look secret (`sae_` is one of the marks): numbers
/// under any other secret key are replaced too.
const SECRET_LOOKING_NUMBERS: &[&str] = &["sae_anti_clogging", "sae_groups", "sae_sync"];

/// Hosts in URLs that say nothing about the network: the APs' factory default inform
/// host, and the names reserved for examples and tests.
const HARMLESS_HOSTS: &[&str] = &["unifi", "localhost"];
const HARMLESS_DOMAINS: &[&str] = &["example", "example.com", "example.net", "example.org", "invalid", "localhost", "test"];

/// Fields known to hold text people wrote: always replaced, without being listed as
/// unknown at the end of a run.
const TEXT: &[&str] = &[
    "comment", "contact", "desc", "location", "name", "note", "snmp_contact", "snmp_location",
    // Domains and hosts the network uses (NTP servers can be the ISP's).
    "domain", "domain_name", "ntp_server_1", "ntp_server_2", "ntp_server_3", "ntp_server_4", "server",
    // The guest portal's texts.
    "portal_customized_authentication_text", "portal_customized_button_text", "portal_customized_success_text", "portal_customized_title",
    "portal_customized_welcome_text",
];

/// [`PASS`], [`PASS_AT`] and [`TEXT`] as sets: every field of every file is looked up in them.
static PASS_SET: LazyLock<HashSet<&str>> = LazyLock::new(|| PASS.iter().copied().collect());
static PASS_AT_SET: LazyLock<HashSet<&str>> = LazyLock::new(|| PASS_AT.iter().copied().collect());
static TEXT_SET: LazyLock<HashSet<&str>> = LazyLock::new(|| TEXT.iter().copied().collect());

const KEEP_MACS: [&str; 2] = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"];

/// The fakes handed out so far: original -> fake, per kind, and how many distinct
/// originals each kind has (a map also holds other spellings of some).
#[derive(Default)]
struct Fakes {
    maps: BTreeMap<Kind, BTreeMap<String, String>>,
    counts: BTreeMap<Kind, usize>,
}

impl Fakes {
    /// The fake for `original`, made by `make` from its number (from 1) on first sight.
    fn get(&mut self, kind: Kind, original: &str, make: impl FnOnce(usize) -> String) -> String {
        let map = self.maps.entry(kind).or_default();
        if let Some(f) = map.get(original) {
            return f.clone();
        }
        let n = self.counts.entry(kind).or_default();
        *n += 1;
        let f = make(*n);
        map.insert(original.to_string(), f.clone());
        f
    }

    /// Records another spelling of an original that already has `fake`, so the leak
    /// check looks for it too.
    fn also(&mut self, kind: Kind, spelling: &str, fake: &str) {
        self.maps.entry(kind).or_default().entry(spelling.to_string()).or_insert_with(|| fake.to_string());
    }

    fn len(&self, kind: Kind) -> usize {
        self.counts.get(&kind).copied().unwrap_or(0)
    }

    fn mac(&mut self, mac: &str) -> String {
        let lower = mac.to_ascii_lowercase();
        if KEEP_MACS.contains(&lower.as_str()) {
            return lower;
        }
        // Locally administered unicast range, numbered by first appearance.
        self.get(Kind::Mac, &lower, |n| format!("02:00:00:00:{:02x}:{:02x}", n >> 8, n & 0xff))
    }

    /// A MAC spelled any other way (without separators as in serial numbers, with dashes,
    /// in Cisco's dotted groups), its fake spelled the same way and in the same case.
    fn any_mac(&mut self, spelled: &str) -> String {
        let hex: String = spelled.chars().filter(char::is_ascii_hexdigit).collect();
        let fake = self.mac(&colon_mac(&hex)).replace(':', "");
        let mut digits = fake.chars();
        let out: String = spelled.chars().map(|c| if c.is_ascii_hexdigit() { digits.next().unwrap_or(c) } else { c }).collect();
        if spelled.chars().any(|c| c.is_ascii_uppercase()) { out.to_ascii_uppercase() } else { out }
    }

    fn knows_mac(&self, mac: &str) -> bool {
        self.maps.get(&Kind::Mac).is_some_and(|m| m.contains_key(mac))
    }
}

pub struct Sanitizer {
    fakes: Fakes,
    /// A MAC with colons.
    mac: Regex,
    /// A MAC with dashes or in dotted groups of four.
    mac_other: Regex,
    mac_bare: Regex,
    uuid: Regex,
    hex: Regex,
    ipv6: Regex,
    ipv4: Regex,
    /// A whole value that is a number, a boolean or a bare identifier.
    plain: Regex,
    /// A whole object key that is an identifier: a MAC with separators, a UUID, long
    /// hex or an IPv4 address (bare MACs and IPv6 addresses are told apart in code).
    id_key: Regex,
    /// Domain suffixes to replace (e.g. the controller's DNS name), lowercased.
    domains: Vec<String>,
    /// Extra fields to pass (`--keep`), lowercased.
    keep: HashSet<String>,
    /// Known hostnames, SSIDs, hosts and the domains, found in any ASCII case, with each
    /// pattern's fake, and the sizes of the maps they were built from (the maps only grow).
    known: Option<(AhoCorasick, Vec<String>)>,
    known_sizes: (usize, usize, usize),
    /// The first pass, which only learns names: they are not looked for inside other
    /// values until it is over, so the matcher is built once rather than at every name.
    learning: bool,
    /// Short identifier-like values (lowercased) that passed whole in an allow-listed
    /// field: settings words such as "default" or "auto". The same value elsewhere is
    /// kept too.
    kept: HashSet<String>,
    /// Fields not on the allow-list whose values were replaced as text.
    unlisted: BTreeSet<String>,
    /// The field each text original was first seen in, for the leak check's message.
    text_fields: HashMap<String, String>,
}

impl Sanitizer {
    pub fn new(domains: Vec<String>, keep: Vec<String>) -> Self {
        let mut fakes = Fakes::default();
        let domains: Vec<String> = domains.into_iter().filter(|d| !d.is_empty()).map(|d| d.to_ascii_lowercase()).collect();
        for d in &domains {
            fakes.get(Kind::Domain, d, |_| "example.net".into());
        }
        Sanitizer {
            fakes,
            mac: Regex::new(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b").unwrap(),
            mac_other: Regex::new(r"(?i)\b(?:[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\b").unwrap(),
            mac_bare: Regex::new(r"(?i)\b[0-9a-f]{12}\b").unwrap(),
            uuid: Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap(),
            hex: Regex::new(r"(?i)\b[0-9a-f]{16,}\b").unwrap(),
            // Broad: anything with two colons between hex groups, with `::` and an
            // embedded IPv4 address; what parses as an address is one.
            ipv6: Regex::new(r"(?i)(?:[0-9a-f]{0,4}:){2,7}(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-f]{0,4})").unwrap(),
            ipv4: Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap(),
            plain: Regex::new(
                r"(?i)^(?:-?[0-9]+(?:\.[0-9]+)*(?:/[0-9]{1,3})?|true|false|0x[0-9a-f]+|[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$",
            )
            .unwrap(),
            id_key: Regex::new(
                r"(?i)^(?:[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})$",
            )
            .unwrap(),
            domains,
            keep: keep.into_iter().map(|k| k.to_ascii_lowercase()).collect(),
            known: None,
            known_sizes: (usize::MAX, 0, 0),
            learning: false,
            kept: HashSet::new(),
            unlisted: BTreeSet::new(),
            text_fields: HashMap::new(),
        }
    }

    /// Hostnames and SSIDs learned from their own fields, and hosts and domains, can also
    /// appear inside other values (e.g. `resolv.host.1.name`), in any case. Rebuilt only
    /// when a map grew, and not while learning.
    fn refresh_known(&mut self) {
        let sizes = (self.fakes.len(Kind::Name), self.fakes.len(Kind::Ssid), self.fakes.len(Kind::Domain));
        if self.learning || sizes == self.known_sizes {
            return;
        }
        self.known_sizes = sizes;
        let (patterns, fakes): (Vec<&str>, Vec<String>) = [Kind::Name, Kind::Ssid, Kind::Domain]
            .iter()
            .filter_map(|k| self.fakes.maps.get(k).map(|m| (*k, m)))
            .flat_map(|(k, m)| m.iter().filter(move |(o, _)| k == Kind::Domain || o.len() >= 4).map(|(o, f)| (o.as_str(), f.clone())))
            .unzip();
        self.known = (!patterns.is_empty()).then(|| (AhoCorasick::builder().ascii_case_insensitive(true).build(&patterns).expect("literal patterns"), fakes));
    }

    /// Replaces the known names in `s` where they are whole words, as the leak check looks
    /// for them: a name that contains another is replaced whole.
    fn replace_known(&self, s: &str) -> String {
        let Some((finder, fakes)) = &self.known else { return s.to_string() };
        let mut found: Vec<(usize, usize, usize)> = finder
            .find_overlapping_iter(s)
            .filter(|m| Rule::Word.leaks(s.as_bytes(), m.start(), m.end()))
            .map(|m| (m.start(), m.end(), m.pattern().as_usize()))
            .collect();
        if found.is_empty() {
            return s.to_string();
        }
        found.sort_by_key(|&(a, b, p)| (a, std::cmp::Reverse(b), p));
        let mut out = String::with_capacity(s.len());
        let mut last = 0;
        for (a, b, p) in found {
            if a >= last {
                out.push_str(&s[last..a]);
                out.push_str(&fakes[p]);
                last = b;
            }
        }
        out.push_str(&s[last..]);
        out
    }

    /// Rewrites identifiers that can appear inside any string value.
    fn scrub(&mut self, s: &str) -> String {
        self.refresh_known();
        let out = self.replace_known(s);
        self.scrub_ids(out)
    }

    /// Rewrites MACs, UUIDs, long hex and the addresses that say where a network is.
    fn scrub_ids(&mut self, mut out: String) -> String {
        let fakes = &mut self.fakes;
        out = replace_all(&self.uuid, &out, |m| fakes.get(Kind::Uuid, &m.to_ascii_lowercase(), |n| format!("00000000-0000-4000-8000-{n:012x}")));
        out = replace_all(&self.mac, &out, |m| fakes.mac(m));
        out = replace_all(&self.mac_other, &out, |m| fakes.any_mac(m));
        // A bare 12-hex string is only treated as a MAC when we already know that MAC
        // (serial numbers on these APs are the MAC without colons).
        out = replace_all(&self.mac_bare, &out, |m| if fakes.knows_mac(&colon_mac(m)) { fakes.any_mac(m) } else { m.to_string() });
        out = replace_all(&self.hex, &out, |m| {
            let len = m.len();
            fakes.get(Kind::Hex, &m.to_ascii_lowercase(), |n| format!("{n:0len$x}"))
        });
        out = scrub_ipv6(&self.ipv6, &out, fakes);
        // Public IPv4 addresses (the WAN address, the ISP's DNS servers) likewise;
        // private ones say nothing about where the network is.
        let mut ipv4 = String::with_capacity(out.len());
        let mut last = 0;
        for m in self.ipv4.find_iter(&out) {
            let (a, b) = (m.start(), m.end());
            if is_public_ipv4(m.as_str()) && !in_longer_dotted(out.as_bytes(), a, b) {
                ipv4.push_str(&out[last..a]);
                ipv4.push_str(&fakes.get(Kind::Ipv4, m.as_str(), fake_ipv4));
                last = b;
            }
        }
        if last > 0 {
            ipv4.push_str(&out[last..]);
            out = ipv4;
        }
        out
    }

    /// Value for a field: `key` is a JSON key inside the object or array under
    /// `parent`, or a dotted config key. `under_secret`: some key above it is secret.
    fn field(&mut self, parent: &str, key: &str, under_secret: bool, value: &str) -> String {
        if value.is_empty() {
            return String::new();
        }
        let names = Names::new(parent, key);
        let kept = self.kept_field(&names);
        let secret = self.is_secret_field(&names, under_secret);
        let Names { key: k, last, at } = names;
        if at == "sshd.auth.key.n.value" || at == "x_ssh_keys.key" {
            // The administrator's SSH public keys.
            self.fakes.get(Kind::SshKey, value, |n| format!("ssh-ed25519 AAAAfake{n}"))
        } else if secret
            // The device SSH account name (stored as x_ssh_username in the controller).
            || (k.starts_with("users.") && last == "name")
            || (k.starts_with("cron.") && last == "user")
        {
            self.fakes.get(Kind::Secret, value, |n| format!("secret-{n}"))
        } else if matches!(last.as_str(), "serial" | "serialno" | "serial_no") && is_bare_mac(value) {
            // Serial numbers are the device's MAC without colons, including those
            // of neighbouring APs in scan results: their real BSSIDs follow from them.
            self.fakes.any_mac(value)
        } else if last == "fingerprint" {
            // SSH host key fingerprints identify the device.
            self.fakes.get(Kind::Fingerprint, value, |n| format!("SHA256:fingerprint-{n}"))
        } else if last == "qrid" {
            self.fakes.get(Kind::Qrid, value, |n| format!("qrid-{n}"))
        } else if last == "oui" {
            // Manufacturer names of clients profile the household.
            self.fakes.get(Kind::Vendor, value, |n| format!("vendor-{n}"))
        } else if last == "base64" {
            // Binary UUIDs (`external_id`) as MongoDB exports them.
            self.fakes.get(Kind::Uuid64, value, |n| format!("{n:0>22}=="))
        } else if matches!(last.as_str(), "ssid" | "essid") || at == "wlanconf.name" {
            self.fakes.get(Kind::Ssid, value, |n| format!("ssid-{n}"))
        } else if matches!(last.as_str(), "hostname" | "ap_name") || at == "devices.name" || at == "resolv.host.n.name" {
            // Hostnames, and the names of APs (which they also go by).
            self.fakes.get(Kind::Name, value, |n| format!("name-{n}"))
        } else if at == "mdns_sd.filter.n.service.n.name" {
            self.service(value)
        } else if kept {
            self.remember_kept(value);
            self.scrub(value)
        } else if PASS_SET.contains(last.as_str()) || PASS_AT_SET.contains(at.as_str()) {
            self.remember_kept(value);
            let value = self.url_hosts(value);
            self.scrub(&value)
        } else if !TEXT_SET.contains(last.as_str()) && (self.is_plain(value) || self.kept.contains(&value.to_lowercase())) {
            self.scrub(value)
        } else {
            if !TEXT_SET.contains(last.as_str()) {
                self.unlisted.insert(at.clone());
            }
            self.text_fields.entry(value.to_string()).or_insert(at);
            self.fakes.get(Kind::Text, value, |n| format!("text-{n}"))
        }
    }

    /// Whether `--keep` names a field.
    fn kept_field(&self, names: &Names) -> bool {
        self.keep.contains(&names.last) || self.keep.contains(&names.at)
    }

    /// Whether a field's value is a secret: its key is one, or a key above it is
    /// (`under_secret`) and neither a field of its own ([`PASS_AT`]) nor `--keep` passes it.
    fn is_secret_field(&self, names: &Names, under_secret: bool) -> bool {
        is_secret_key(&names.key) || (under_secret && !PASS_AT_SET.contains(names.at.as_str()) && !self.kept_field(names))
    }

    /// Whether a number is a secret (a PIN, a numeric passphrase) where a string would
    /// be one, unless it is a numeric setting that only looks secret.
    fn is_secret_number(&self, parent: &str, key: &str, under_secret: bool) -> bool {
        let names = Names::new(parent, key);
        !SECRET_LOOKING_NUMBERS.contains(&names.last.as_str()) && self.is_secret_field(&names, under_secret)
    }

    /// Remembers a value an allow-listed field passed, if it is a short identifier-like
    /// settings word: longer ones (an error message, a URL) can hold anything.
    fn remember_kept(&mut self, value: &str) {
        if value.len() <= 24 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            self.kept.insert(value.to_ascii_lowercase());
        }
    }

    /// Replaces the host names in the URLs in `value` (`inform_url` and the like),
    /// unless `--domain` covers them or they say nothing about the network. Addresses
    /// are left to [`Self::scrub`]; credentials before an `@` are secrets.
    fn url_hosts(&mut self, value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        let mut rest = value;
        while let Some(i) = rest.find("://") {
            let (head, tail) = rest.split_at(i + 3);
            out.push_str(head);
            let end = tail.find(|c: char| matches!(c, '/' | '?' | '#' | '"' | '\'') || c.is_whitespace()).unwrap_or(tail.len());
            let (mut authority, after) = tail.split_at(end);
            if let Some((userinfo, host)) = authority.rsplit_once('@') {
                out.push_str(&self.fakes.get(Kind::Secret, userinfo, |n| format!("secret-{n}")));
                out.push('@');
                authority = host;
            }
            let (host, port) = match authority.rfind(':') {
                Some(c) if !authority.starts_with('[') || authority[..c].ends_with(']') => authority.split_at(c),
                _ => (authority, ""),
            };
            let lower = host.to_ascii_lowercase();
            let covered = |d: &str| lower == d || lower.strip_suffix(d).is_some_and(|sub| sub.ends_with('.'));
            let harmless = host.is_empty()
                || host.starts_with('[')
                || host.parse::<Ipv4Addr>().is_ok()
                || HARMLESS_HOSTS.contains(&lower.as_str())
                || HARMLESS_DOMAINS.iter().copied().chain(self.domains.iter().map(String::as_str)).any(covered);
            if harmless {
                out.push_str(host);
            } else {
                out.push_str(&self.fakes.get(Kind::Domain, &lower, |n| format!("host-{n}.example.net")));
            }
            out.push_str(port);
            rest = after;
        }
        out.push_str(rest);
        out
    }

    /// An object key, rewritten when it is an identifier (`sta_stats` keyed by MAC):
    /// keys are not checked against any list.
    fn object_key(&mut self, key: &str) -> String {
        if is_bare_mac(key) {
            self.fakes.any_mac(key)
        } else if self.id_key.is_match(key) || key.parse::<Ipv6Addr>().is_ok() {
            self.scrub_ids(key.to_string())
        } else {
            key.to_string()
        }
    }

    /// A number, a boolean, or one identifier (MAC, UUID, long hex, IP address) that
    /// [`Self::scrub`] rewrites: harmless from any field.
    fn is_plain(&self, value: &str) -> bool {
        self.plain.is_match(value) || value.parse::<Ipv6Addr>().is_ok()
    }

    /// An mDNS service name a client announced or a filter names: device IDs hide in
    /// them (`_FC9F5ED42C8A._tcp.local`); plain service types are kept.
    fn service(&mut self, name: &str) -> String {
        if is_service_type(name) {
            name.to_string()
        } else {
            self.fakes.get(Kind::Service, name, |n| format!("_service-{n}._tcp.local"))
        }
    }

    /// Rewrites a `key=value` config blob line by line.
    fn cfg(&mut self, blob: &str) -> String {
        blob.lines()
            .map(|l| match l.split_once('=') {
                Some((k, v)) => format!("{k}={}", self.field("", k, false, v)),
                None => self.scrub(l),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn json(&mut self, v: &Value) -> Value {
        self.json_at("", "", false, v)
    }

    /// `parent` is the key of the enclosing object or array (e.g. `clients`).
    /// `under_secret`: some key above `key` is secret.
    fn json_at(&mut self, parent: &str, key: &str, under_secret: bool, v: &Value) -> Value {
        let secret = under_secret || is_secret_key(key);
        match v {
            Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (self.object_key(k), self.json_at(key, k, secret, v))).collect()),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.json_at(parent, key, under_secret, x)).collect()),
            Value::Number(n) if secret && self.is_secret_number(parent, key, under_secret) => {
                Value::String(self.fakes.get(Kind::Secret, &n.to_string(), |n| format!("secret-{n}")))
            }
            Value::String(s) if key.ends_with("_cfg") => Value::String(self.cfg(s)),
            // Names people gave their devices in the other controller.
            Value::String(s) if key == "name" && (parent == "clients" || parent == "user") && !s.is_empty() => {
                Value::String(self.fakes.get(Kind::Alias, s, |n| format!("alias-{n}")))
            }
            Value::String(s) if key == "name" && parent == "services" => Value::String(self.service(s)),
            Value::String(s) => Value::String(self.field(parent, key, under_secret, s)),
            other => other.clone(),
        }
    }

    /// A `--save` file name: its MAC (12 hex digits between `_`) is always replaced,
    /// whether or not a payload held it (a reply never holds its own AP's MAC).
    pub fn file_name(&mut self, name: &str) -> String {
        // `_` is a regex word character, so `\b` would not split `_7845583c52bc_`.
        name.split('_')
            .map(|part| if is_bare_mac(part) { self.fakes.any_mac(part) } else { self.scrub(part) })
            .collect::<Vec<_>>()
            .join("_")
    }

    /// Fails if any original value we replaced still appears in `text`.
    #[cfg(test)]
    pub fn check_clean(&self, text: &str, what: &str) -> Result<()> {
        self.leak_check().check(text, what)
    }

    /// The replaced values to look for, prepared once for checking many texts.
    pub fn leak_check(&self) -> LeakCheck {
        let mut originals = Vec::new();
        let mut leaks = Vec::new();
        for (&kind, map) in &self.fakes.maps {
            for original in map.keys() {
                let Some(rule) = kind.rule(original.len()) else { continue };
                // A value first replaced as text that a later field kept is a setting word.
                if kind == Kind::Text && self.kept.contains(&original.to_lowercase()) {
                    continue;
                }
                let field = (kind == Kind::Text).then(|| self.text_fields.get(original).cloned()).flatten();
                originals.push(original.clone());
                leaks.push(Leak { kind, rule, len: original.len(), field: field.clone() });
                // MACs also appear without colons (serial numbers, file names), with
                // dashes, and in dotted groups of four.
                if kind == Kind::Mac {
                    let bare = original.replace(':', "");
                    let dotted = format!("{}.{}.{}", &bare[..4], &bare[4..8], &bare[8..]);
                    for spelling in [original.replace(':', "-"), bare, dotted] {
                        originals.push(spelling);
                        leaks.push(Leak { kind, rule: Rule::Anywhere, len: original.len(), field: field.clone() });
                    }
                }
            }
        }
        let finder = AhoCorasick::builder().ascii_case_insensitive(true).build(&originals).expect("literal patterns");
        LeakCheck { finder, leaks }
    }

    /// The fields not on the allow-list whose values were replaced as text.
    pub fn unlisted(&self) -> impl Iterator<Item = &str> {
        self.unlisted.iter().map(String::as_str)
    }
}

/// One original the leak check looks for.
struct Leak {
    kind: Kind,
    rule: Rule,
    len: usize,
    /// The field a text value came from.
    field: Option<String>,
}

/// The original values a sanitiser replaced, found in one pass over a text.
pub struct LeakCheck {
    finder: AhoCorasick,
    leaks: Vec<Leak>,
}

impl LeakCheck {
    /// Fails if any of the originals still appears in `text`.
    pub fn check(&self, text: &str, what: &str) -> Result<()> {
        let bytes = text.as_bytes();
        for m in self.finder.find_overlapping_iter(text) {
            let leak = &self.leaks[m.pattern().as_usize()];
            if leak.rule.leaks(bytes, m.start(), m.end()) {
                match &leak.field {
                    Some(f) => bail!(
                        "{what}: a text value of field {f} ({} chars) survived sanitising (if {f} holds nothing personal, pass --keep {f})",
                        leak.len
                    ),
                    None => bail!("{what}: a {} value ({} chars) survived sanitising", leak.kind.label(), leak.len),
                }
            }
        }
        Ok(())
    }
}

/// A key holding a secret. A bare `key` field names a settings document (`"key":
/// "country"`); only dotted config keys ending in `.key` hold secrets.
fn is_secret_key(key: &str) -> bool {
    cfgdiff::is_secret(key) && !key.eq_ignore_ascii_case("key")
}

/// Whether `s` is one whole MAC: with colons or dashes, in dotted groups of four, or bare.
fn is_mac(s: &str) -> bool {
    let b = s.as_bytes();
    let hex = |r: &[u8]| r.iter().all(u8::is_ascii_hexdigit);
    match b.len() {
        12 => is_bare_mac(s),
        14 => b[4] == b'.' && b[9] == b'.' && b.chunks(5).all(|c| hex(&c[..4])),
        17 => matches!(b[2], b':' | b'-') && b.chunks(3).all(|c| hex(&c[..2]) && c.get(2).is_none_or(|&sep| sep == b[2])),
        _ => false,
    }
}

/// Whether `s` is a MAC without separators: 12 hex digits.
fn is_bare_mac(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `aabbccddeeff` (any case) as `aa:bb:cc:dd:ee:ff`.
fn colon_mac(bare: &str) -> String {
    bare.to_ascii_lowercase().as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":")
}

/// Replaces the IPv6 addresses in `s` that tell where a network is or which device it
/// is. Kept are documentation addresses, those in `::/96` (loopback, unspecified, and
/// suffixes such as a DHCPv6 range's `::2`) and multicast groups other than
/// solicited-node ones (which end in an interface ID's last 24 bits). Link-local ones
/// are replaced too: their EUI-64 interface ID is the MAC. Times (`12:34:56`) and MACs
/// match `re` but do not parse as addresses.
fn scrub_ipv6(re: &Regex, s: &str, fakes: &mut Fakes) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for m in re.find_iter(s) {
        let (a, mut b) = (m.start(), m.end());
        let mut ip = m.as_str().parse::<Ipv6Addr>();
        // A colon right after an address (`fe80::1: up`) is not part of it.
        let trimmed = ip.is_err() && m.as_str().ends_with(':') && !m.as_str().ends_with("::");
        if trimmed {
            b -= 1;
            ip = s[a..b].parse();
        }
        let Ok(ip) = ip else { continue };
        let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let alone = !bytes[..a].last().is_some_and(|&c| word(c) || c == b':') && !bytes.get(b).is_some_and(|&c| word(c) || (c == b':' && !trimmed));
        let seg = ip.segments();
        let [s0, s1, ..] = seg;
        let documentation = (s0 == 0x2001 && s1 == 0x0db8) || s0 & 0xfff0 == 0x3ff0;
        let suffix = seg[..6] == [0; 6];
        let solicited_node = seg[..6] == [0xff02, 0, 0, 0, 0, 1] && seg[6] & 0xff00 == 0xff00;
        if !alone || documentation || suffix || (ip.is_multicast() && !solicited_node) {
            continue;
        }
        let link_local = ip.is_unicast_link_local();
        let fake = fakes.get(Kind::Ipv6, &ip.to_string(), |n| if link_local { format!("fe80::db8:{n:x}") } else { format!("2001:db8::{n:x}") });
        fakes.also(Kind::Ipv6, &s[a..b].to_ascii_lowercase(), &fake);
        out.push_str(&s[last..a]);
        out.push_str(&fake);
        last = b;
    }
    out.push_str(&s[last..]);
    out
}

/// A plain mDNS service type such as `_googlecast._tcp.local`, with no device ID in it.
fn is_service_type(name: &str) -> bool {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let id_like = |l: &str| {
        let l = l.trim_start_matches('_');
        l.len() >= 6 && l.chars().all(|c| c.is_ascii_hexdigit())
    };
    matches!(labels.as_slice(), [service, proto, "local"] if service.starts_with('_') && matches!(*proto, "_tcp" | "_udp"))
        && labels.iter().all(|l| !id_like(l) && *l == l.to_ascii_lowercase())
}

/// An IPv4 address that tells where a network is: not private, loopback, link-local,
/// multicast or reserved (netmasks such as 255.255.255.0 are reserved), nor one of
/// the documentation and benchmarking ranges the fakes come from.
fn is_public_ipv4(s: &str) -> bool {
    let Ok(ip) = s.parse::<Ipv4Addr>() else { return false };
    let [a, b, ..] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        || (a == 198 && (b == 18 || b == 19)))
}

/// The `n`-th (from 1) public IPv4 address's fake: the documentation ranges, then the
/// benchmarking range.
fn fake_ipv4(n: usize) -> String {
    let i = n - 1;
    match ["192.0.2", "198.51.100", "203.0.113"].get(i / 254) {
        Some(net) => format!("{net}.{}", i % 254 + 1),
        None => {
            let j = i - 3 * 254;
            format!("198.{}.{}.{}", 18 + j / (256 * 254) % 2, j / 254 % 256, j % 254 + 1)
        }
    }
}

/// Whether the address-shaped `text[a..b]` is part of a longer dotted number (an SNMP
/// OID, a version such as 1.2.3.4.5), which is not an address.
fn in_longer_dotted(text: &[u8], a: usize, b: usize) -> bool {
    let (before, after) = (&text[..a], &text[b..]);
    matches!(before, [.., d, b'.'] if d.is_ascii_digit()) || matches!(after, [b'.', d, ..] if d.is_ascii_digit())
}

fn replace_all(re: &Regex, s: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for m in re.find_iter(s) {
        out.push_str(&s[last..m.start()]);
        out.push_str(&f(m.as_str()));
        last = m.end();
    }
    out.push_str(&s[last..]);
    out
}

/// Sanitises the named JSON files from `input` into `output`. `keep` names more fields
/// to pass (as `field`, `parent.field` or a config key with its numbers as `n`).
pub fn run(input: &Path, output: &Path, files: &[String], domains: Vec<String>, seed_macs: &[String], keep: Vec<String>) -> Result<()> {
    let mut s = Sanitizer::new(domains, keep);
    // Seed known device MACs first so they get the lowest, stable fake numbers.
    for m in seed_macs {
        if !is_mac(m) {
            bail!("--device {m} is not a MAC address");
        }
        s.fakes.any_mac(m);
    }
    std::fs::create_dir_all(output)?;
    let mut docs = Vec::new();
    for name in files {
        let path = input.join(name);
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let v: Value = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        docs.push((name, v));
    }
    // First pass only learns the hostnames, SSIDs, hosts, kept setting words and the
    // MACs in the file names, so the second pass can also replace them where they
    // show up inside unrelated values.
    s.learning = true;
    for (_, v) in &docs {
        s.json(v);
    }
    for (name, _) in &docs {
        s.file_name(name);
    }
    s.learning = false;
    s.unlisted.clear();
    let mut written = Vec::new();
    for (name, v) in &docs {
        let clean = serde_json::to_string_pretty(&s.json(v))? + "\n";
        let out_name = s.file_name(name);
        written.push((output.join(&out_name), clean));
    }
    // Check everything against the final maps, so values first seen in a later
    // file are also caught in earlier ones.
    let leaks = s.leak_check();
    for (path, text) in &written {
        leaks.check(text, &path.display().to_string())?;
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        leaks.check(&name, &format!("file name {name}"))?;
    }
    for (path, text) in written {
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    for (kind, n) in &s.fakes.counts {
        eprintln!("replaced {n} distinct {} values", kind.label());
    }
    let unlisted: Vec<&str> = s.unlisted().collect();
    if !unlisted.is_empty() {
        eprintln!(
            "replaced as text, not being on the allow-list: {} (pass --keep <field> for those that hold nothing personal)",
            unlisted.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn replaces_identifiers_consistently_and_checks_for_leaks() {
        let mut s = Sanitizer::new(vec!["home.example.org".into()], Vec::new());
        let v = json!({
            "mac": "78:45:58:3c:52:bc",
            "serial": "7845583C52BC",
            "hostname": "kitchen-tv",
            "inform_url": "http://unifi.home.example.org:8080/inform",
            "x_authkey": "00112233445566778899aabbccddeeff",
            "system_cfg": "users.1.name=admin42\ncron.1.user=admin42\naaa.1.ssid=My Home\naaa.1.wpa.psk=hunter22\nwireless.1.bcfilt.1.mac=ff:ff:ff:ff:ff:ff\nwireless.2.bcfilt.1.mac=78:45:58:3c:52:bc\nunifi.siteid=6a1b2c3d4e5f60718293a4b5",
            "vap_table": [{"essid": "My Home", "sta_table": [{"mac": "AA:BB:CC:DD:EE:FF", "multicast": {"services": [
                {"name": "_googlecast._tcp.local"}, {"name": "_A1B2C3D4E5F6._tcp.local"}, {"name": "_77AB12CD._sub._googlecast._tcp"}]}}]}],
            "radio_table": [{"scan_table": [{"bssid": "f6:92:bf:22:33:44", "serialno": "F492BF223344"}]}],
            "fingerprint": "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            "qrid": "Xy7Qa",
            "clients": [{ "oui": "Example Devices Ltd", "mac": "00:11:22:33:44:55" }],
            "external_id": { "$binary": { "base64": "qR9+x3ytPgeIyDW5NH4lkw==", "subType": "04" } },
        });
        let out = s.json(&v);
        let text = out.to_string();
        assert_eq!(out["mac"], "02:00:00:00:00:01");
        assert_eq!(out["serial"], "020000000001");
        assert_eq!(out["hostname"], "name-1");
        assert_eq!(out["inform_url"], "http://unifi.example.net:8080/inform");
        assert_eq!(out["x_authkey"], "secret-1");
        assert_eq!(out["vap_table"][0]["essid"], "ssid-1");
        let cfg = out["system_cfg"].as_str().unwrap();
        assert!(cfg.contains("aaa.1.ssid=ssid-1"), "{cfg}");
        assert!(cfg.contains("users.1.name=secret-2") && cfg.contains("cron.1.user=secret-2"), "{cfg}");
        assert!(cfg.contains("aaa.1.wpa.psk=secret-3"));
        assert!(cfg.contains("bcfilt.1.mac=ff:ff:ff:ff:ff:ff"));
        assert!(cfg.contains("bcfilt.1.mac=02:00:00:00:00:01"));
        assert!(!cfg.contains("6a1b2c3d"));
        let services = &out["vap_table"][0]["sta_table"][0]["multicast"]["services"];
        assert_eq!(services[0]["name"], "_googlecast._tcp.local", "a plain service type is kept");
        assert_eq!(services[1]["name"], "_service-1._tcp.local");
        assert_eq!(services[2]["name"], "_service-2._tcp.local");
        let serial = out["radio_table"][0]["scan_table"][0]["serialno"].as_str().unwrap();
        assert!(serial.starts_with("020000000") && serial.chars().all(|c| !c.is_ascii_lowercase()), "a neighbour's serial: {serial}");
        assert_eq!(out["fingerprint"], "SHA256:fingerprint-1");
        assert_eq!(out["qrid"], "qrid-1");
        assert_eq!(out["clients"][0]["oui"], "vendor-1");
        assert_ne!(out["external_id"]["$binary"]["base64"], "qR9+x3ytPgeIyDW5NH4lkw==");
        assert_eq!(out["external_id"]["$binary"]["subType"], "04");
        s.check_clean(&text, "test").unwrap();
        assert!(s.check_clean("contains hunter22", "leak").is_err());
        assert_eq!(s.file_name("t_7845583c52bc_x.json"), "t_020000000001_x.json");
        assert_eq!(s.json(&json!({ "key": "country" }))["key"], "country", "a settings document's name");
        let v = s.json(&json!({ "clients": [{ "name": "Dad's phone" }], "wlanconf": [{ "name": "My Home" }] }));
        assert_eq!(v["clients"][0]["name"], "alias-1");
        assert_eq!(v["wlanconf"][0]["name"], "ssid-1", "a WLAN's name is its SSID");
        assert_eq!(s.scrub("host kitchen-tv.lan"), "host name-1.lan");
    }

    #[test]
    fn the_leak_check_matches_whole_words_and_short_secrets_alone() {
        let mut s = Sanitizer::new(Vec::new(), Vec::new());
        s.json(&json!({ "hostname": "chromecast", "x_passphrase": "test", "wan_ip": "9.9.9.9", "system_cfg": "aaa.1.wpa.psk=longsecret1" }));
        for clean in ["code: google_chromecast", "_googlecast._tcp", "testdata/x", "oid 1.9.9.9.9", "dns 9.9.9.99"] {
            assert!(s.check_clean(clean, "clean").is_ok(), "{clean}");
        }
        for leak in ["ssid=Chromecast", "ssid=test\n", "dns 9.9.9.9", "xLONGSECRET1x"] {
            assert!(s.check_clean(leak, "leak").is_err(), "{leak}");
        }
    }

    #[test]
    fn identifying_free_text_is_replaced() {
        let mut s = Sanitizer::new(Vec::new(), Vec::new());
        let v = json!({
            "sites": [{ "name": "default", "desc": "Smith family" }],
            "setting": [{ "key": "mgmt", "x_ssh_keys": [{ "name": "laptop", "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef", "comment": "sam@laptop.home", "type": "ssh-ed25519" }] }],
            "devices": [{ "name": "Living Room", "snmp_location": "Hauptstrasse 5", "snmp_contact": "+49 30 1234567" }],
            "clients": [{ "note": "Grandma's tablet", "noted": true }],
            "wlanconf": [{ "name": "Smith WiFi", "security": "wpapsk" }],
            "inform": { "hostname": "Living Room", "lldp_table": [{ "chassis_descr": "Office switch by the desk" }], "port_table": [{ "name": "Port 1" }] },
            "system_cfg": "sshd.auth.key.1.status=enabled\nsshd.auth.key.1.value=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef\nsshd.auth.key.1.type=ssh-ed25519\nsshd.auth.key.1.comment=sam@laptop.home\nsnmp.location=Hauptstrasse 5\nsnmp.contact=+49 30 1234567\nmark.1.name=guest\nmark.1.location=skb\nresolv.host.1.name=Living Room\nswitch.port.1.name=Port 1",
        });
        let out = s.json(&v);
        assert_eq!(out["sites"][0]["name"], "default");
        assert_eq!(out["sites"][0]["desc"], "text-1");
        let key = &out["setting"][0]["x_ssh_keys"][0];
        // Everything under x_ssh_keys is a secret, but for the key itself and its kind.
        assert_eq!((key["name"].as_str(), key["key"].as_str(), key["comment"].as_str(), key["type"].as_str()), (Some("secret-1"), Some("ssh-ed25519 AAAAfake1"), Some("secret-2"), Some("ssh-ed25519")));
        assert_eq!(out["devices"][0]["name"], "name-1");
        assert_eq!(out["inform"]["hostname"], "name-1", "an AP's name and hostname are one");
        assert_eq!(out["clients"][0]["note"], "text-4");
        assert_eq!(out["wlanconf"][0]["name"], "ssid-1");
        assert_eq!(out["wlanconf"][0]["security"], "wpapsk");
        let cfg = out["system_cfg"].as_str().unwrap();
        for line in ["sshd.auth.key.1.status=enabled", "sshd.auth.key.1.value=ssh-ed25519 AAAAfake1", "sshd.auth.key.1.type=ssh-ed25519",
                     "sshd.auth.key.1.comment=text-7", "snmp.location=text-2", "snmp.contact=text-3", "mark.1.name=guest", "mark.1.location=skb",
                     "resolv.host.1.name=name-1"] {
            assert!(cfg.lines().any(|l| l == line), "{line} in {cfg}");
        }
        let text = out.to_string();
        for private in ["Smith", "AAAAC3Nz", "sam@laptop", "Hauptstrasse", "1234567", "Grandma", "Office switch", "Living Room"] {
            assert!(!text.contains(private), "{private} in {text}");
        }
        s.check_clean(&text, "test").unwrap();
        assert_eq!(s.unlisted().collect::<Vec<_>>(), ["lldp_table.chassis_descr"], "unknown fields are listed; known text fields are not");
        assert!(s.check_clean("desc: smith FAMILY", "leak").is_err(), "text is looked for in any case");
    }

    #[test]
    fn fields_off_the_allow_list_pass_only_plain_values_or_when_kept() {
        let mut s = Sanitizer::new(Vec::new(), vec!["custom_mode".into()]);
        let v = json!({
            "new_counter": "12345", "new_flag": "true", "new_mac": "78:45:58:3c:52:bc", "new_ip": "81.2.69.160",
            "mode": "auto", "new_mode": "auto", "new_words": "something new", "custom_mode": "turbo boost",
        });
        let out = s.json(&v);
        assert_eq!((&out["new_counter"], &out["new_flag"], &out["new_mac"], &out["new_ip"]), (&json!("12345"), &json!("true"), &json!("02:00:00:00:00:01"), &json!("192.0.2.1")));
        assert_eq!(out["new_mode"], "auto", "a value an allow-listed field holds is a setting word");
        assert_eq!(out["new_words"], "text-1");
        assert_eq!(out["custom_mode"], "turbo boost", "--keep");
        assert_eq!(s.unlisted().collect::<Vec<_>>(), ["new_words"]);
        let err = s.check_clean("x: something new", "leak").unwrap_err().to_string();
        assert!(err.contains("--keep new_words"), "{err}");
    }

    #[test]
    fn names_ssids_and_domains_are_replaced_in_any_case() {
        let mut s = Sanitizer::new(vec!["Home.Example.org".into()], Vec::new());
        s.json(&json!({ "hostname": "kitchen-tv", "essid": "My Home" }));
        assert_eq!(s.scrub("Kitchen-TV.home.example.ORG and my home"), "name-1.example.net and ssid-1");
        let out = s.json(&json!({ "inform_url": "http://UNIFI.HOME.EXAMPLE.ORG:8080/inform" }));
        assert_eq!(out["inform_url"], "http://UNIFI.example.net:8080/inform");
        assert!(s.check_clean("url unifi.home.example.org", "leak").is_err(), "the domain is looked for");
        s.check_clean(&out.to_string(), "test").unwrap();
    }

    #[test]
    fn ipv6_addresses_are_parsed_and_only_harmless_ones_kept() {
        let mut s = Sanitizer::new(Vec::new(), Vec::new());
        let v = json!({
            "ipv6_addresses": ["2a02:8071::1", "2a02:8071:abcd::1", "2A02:8071:0:0:0:0:0:1", "fe80::7a45:58ff:fe3c:52bc", "fe80:0000:0000:0000:7a45:58ff:fe3c:52bc",
                               "::1", "::", "2001:db8::42", "::ffff:81.2.69.160", "::2", "ff02::1:2", "ff02::1:ff3c:52bc"],
            "uptime": "12:34:56",
            "mac": "aa:bb:cc:dd:ee:ff",
            "last_error_str": "addr 2a02:8071::5: up, scope fe80::1%br0",
        });
        let out = s.json(&v);
        let ips: Vec<&str> = out["ipv6_addresses"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(ips, ["2001:db8::1", "2001:db8::2", "2001:db8::1", "fe80::db8:3", "fe80::db8:3", "::1", "::", "2001:db8::42", "2001:db8::4", "::2", "ff02::1:2", "2001:db8::5"]);
        assert_eq!(out["uptime"], "12:34:56", "a time is not an address");
        assert_eq!(out["mac"], "02:00:00:00:00:01");
        assert_eq!(out["last_error_str"], "addr 2001:db8::6: up, scope fe80::db8:7%br0");
        s.check_clean(&out.to_string(), "test").unwrap();
        for leak in ["via 2a02:8071::1 ok", "FE80::7A45:58FF:FE3C:52BC", "[2a02:8071:abcd::1]:443"] {
            assert!(s.check_clean(leak, "leak").is_err(), "{leak}");
        }
        assert!(s.check_clean("2a02:8071::1:5", "longer").is_ok());
    }

    #[test]
    fn public_ipv4_addresses_become_documentation_addresses() {
        let mut s = Sanitizer::new(Vec::new(), vec!["kept".into()]);
        let v = json!({
            "wan_ip": "81.2.69.160",
            "dns": ["81.2.69.160", "9.9.9.9", "192.168.1.1", "10.0.0.2", "172.16.4.4", "127.0.0.1", "169.254.1.1"],
            "system_cfg": "resolv.nameserver.1=9.9.9.9\nnet.netmask=255.255.255.0\nmcast=239.255.255.250\nroute=0.0.0.0",
            "kept": ["1.3.6.1.4.1.41112", "version 4.3.2.1.5", "192.0.2.7", "8.8.8.8x", "300.1.1.1"],
            "inform_url": "http://81.2.69.160:8080/inform",
        });
        let out = s.json(&v);
        assert_eq!(out["wan_ip"], "192.0.2.1");
        assert_eq!(out["dns"], json!(["192.0.2.1", "192.0.2.2", "192.168.1.1", "10.0.0.2", "172.16.4.4", "127.0.0.1", "169.254.1.1"]));
        assert_eq!(out["system_cfg"], "resolv.nameserver.1=192.0.2.2\nnet.netmask=255.255.255.0\nmcast=239.255.255.250\nroute=0.0.0.0");
        assert_eq!(out["kept"], v["kept"]);
        assert_eq!(out["inform_url"], "http://192.0.2.1:8080/inform");
        s.check_clean(&out.to_string(), "test").unwrap();
        assert!(s.check_clean("dns 9.9.9.9", "leak").is_err());
        assert!(s.check_clean("oid 1.9.9.9.9", "not an address").is_ok());
        assert_eq!((fake_ipv4(254), fake_ipv4(255), fake_ipv4(763), fake_ipv4(763 + 254)), ("192.0.2.254".into(), "198.51.100.1".into(), "198.18.0.1".into(), "198.18.1.1".into()));
    }

    #[test]
    fn a_saved_file_name_loses_its_mac_even_when_no_payload_holds_it() {
        let dir = std::env::temp_dir().join(format!("informdump-sanitize-{}", std::process::id()));
        let (input, output) = (dir.join("in"), dir.join("out"));
        std::fs::create_dir_all(&input).unwrap();
        let name = "2026-10-12T184427.187Z_000002_7845583c52bc_reply-setparam.json";
        let reply = json!({ "_type": "setparam", "system_cfg": "wireless.1.devname=7845583C52BC\nmgmt.servers.1.url=http://unifi.smith.lan:8080/inform" });
        std::fs::write(input.join(name), reply.to_string()).unwrap();
        let result = run(&input, &output, &[name.to_string()], Vec::new(), &[], Vec::new());
        let written: Vec<String> = std::fs::read_dir(&output).map(|d| d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
        let text = written.first().map(|f| std::fs::read_to_string(output.join(f)).unwrap()).unwrap_or_default();
        let bad_device = run(&input, &dir.join("out2"), &[name.to_string()], Vec::new(), &["78:45:58:3c:52".into()], Vec::new());
        std::fs::remove_dir_all(&dir).ok();
        result.unwrap();
        assert_eq!(written, ["2026-10-12T184427.187Z_000002_020000000001_reply-setparam.json"]);
        assert!(text.contains("devname=020000000001") && text.contains("http://host-1.example.net:8080/inform"), "{text}");
        assert!(bad_device.is_err_and(|e| e.to_string().contains("is not a MAC")));
        assert!(["78:45:58:3c:52:bc", "78-45-58-3C-52-BC", "7845.583c.52bc", "7845583C52BC"].iter().all(|m| is_mac(m)));
        assert!(!["78:45-58:3c:52:bc", "7845.583c-52bc", "7845583c52b", "78:45:58:3c:52:bg", "192.168.100.200"].iter().any(|m| is_mac(m)));
    }

    #[test]
    fn hosts_in_urls_are_replaced_unless_a_domain_covers_them() {
        let mut s = Sanitizer::new(vec!["home.example.org".into()], vec!["stun_url".into()]);
        let v = json!({
            "inform_url": "http://unifi.smith.lan:8080/inform",
            "url": "https://admin:hunter22@NAS.smith.lan/fw.bin",
            "mgmt_url": "http://unifi:8080/inform http://[2a02:8071::1]:8080/x http://81.2.69.160/ http://unifi.home.example.org/",
            "stun_url": "stun://stun.smith.lan:3478/",
            "last_error_str": "lost unifi.smith.lan",
        });
        let out = s.json(&v);
        assert_eq!(out["inform_url"], "http://host-2.example.net:8080/inform");
        assert_eq!(out["url"], "https://secret-1@host-3.example.net/fw.bin");
        assert_eq!(out["mgmt_url"], "http://unifi:8080/inform http://[2001:db8::1]:8080/x http://192.0.2.1/ http://unifi.example.net/");
        assert_eq!(out["stun_url"], "stun://stun.smith.lan:3478/", "--keep vouches for the field");
        s.check_clean(&out["url"].to_string(), "url").unwrap();
        assert!(s.check_clean("on unifi.smith.lan", "leak").is_err(), "a replaced host is looked for");
        // A learned host is replaced wherever it shows up, once names are looked for.
        assert_eq!(s.scrub("lost unifi.smith.lan"), "lost host-2.example.net");
        // A long value an allow-listed field passed is no setting word: the same value
        // elsewhere is text, and where it passed, the leak check finds it.
        let mut s = Sanitizer::new(Vec::new(), Vec::new());
        let out = s.json(&json!({ "last_error_str": "Smith family router", "new_words": "Smith family router", "mode": "auto", "new_mode": "auto" }));
        assert_eq!((&out["new_words"], &out["new_mode"]), (&json!("text-1"), &json!("auto")));
        assert!(s.check_clean(&out.to_string(), "fail closed").is_err());
    }

    #[test]
    fn everything_under_a_secret_key_and_identifier_keys_are_replaced() {
        let mut s = Sanitizer::new(Vec::new(), Vec::new());
        let v = json!({
            "x_secret": { "inner": "s3cret-value", "list": ["a1b2c3d4e5"], "pin": 123456, "on": true },
            "psk": 87654321,
            "sae_groups": [19, 20], "sae_anti_clogging": 5,
            "sta_stats": { "78:45:58:3c:52:bc": 1, "AA-BB-CC-DD-EE-FF": 2, "7845583c52bc": 3, "81.2.69.160": 4, "2a02:8071::1": 5,
                           "6f1c0e52-2b8a-4c3e-9d4f-0a1b2c3d4e5f": 6, "10.0.0.1": 7, "na": 8 },
        });
        let out = s.json(&v);
        assert_eq!(out["x_secret"], json!({ "inner": "secret-1", "list": ["secret-2"], "pin": "secret-3", "on": true }));
        assert_eq!(out["psk"], "secret-4");
        assert_eq!((&out["sae_groups"], &out["sae_anti_clogging"]), (&json!([19, 20]), &json!(5)), "numeric settings that only look secret");
        let keys: Vec<&str> = out["sta_stats"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["02:00:00:00:00:01", "02-00-00-00-00-02", "020000000001", "192.0.2.1", "2001:db8::1", "00000000-0000-4000-8000-000000000001", "10.0.0.1", "na"]);
        s.check_clean(&out.to_string(), "test").unwrap();
        assert!(s.check_clean("pin 123456", "leak").is_err());
    }

    #[test]
    fn a_number_under_a_secret_key_passes_where_a_string_would() {
        let mut s = Sanitizer::new(Vec::new(), vec!["x_radius.port".into(), "x_passphrase".into()]);
        let v = json!({ "x_radius": { "port": 1812, "pin": 4321, "ip": "10.0.0.1" }, "x_passphrase": 12345678, "SAE_Groups": [19, 20] });
        let out = s.json(&v);
        assert_eq!(out["x_radius"], json!({ "port": 1812, "pin": "secret-1", "ip": "secret-2" }), "--keep as parent.field");
        assert_eq!(out["x_passphrase"], "secret-3", "--keep does not pass a secret key's own value, number or string");
        assert_eq!(out["SAE_Groups"], json!([19, 20]), "in any case");
    }

    #[test]
    fn macs_with_dashes_or_dots_are_rewritten_and_looked_for() {
        let mut s = Sanitizer::new(Vec::new(), Vec::new());
        let out = s.json(&json!({ "last_error_str": "seen aa-bb-cc-dd-ee-01 and AABB.CCDD.EE02", "new_mac": "AA-BB-CC-DD-EE-03", "mac": "aa:bb:cc:dd:ee:01" }));
        assert_eq!(out["last_error_str"], "seen 02-00-00-00-00-01 and 0200.0000.0002");
        assert_eq!(out["new_mac"], "02-00-00-00-00-03", "a lone MAC is plain from any field");
        assert_eq!(out["mac"], "02:00:00:00:00:01", "one MAC however it is spelled");
        s.check_clean(&out.to_string(), "test").unwrap();
        for leak in ["x aabb.ccdd.ee01 x", "AA-BB-CC-DD-EE-02", "aa:bb:cc:dd:ee:03", "AABBCCDDEE03"] {
            assert!(s.check_clean(leak, "leak").is_err(), "{leak}");
        }
    }

    #[test]
    fn names_are_replaced_as_whole_words_and_not_looked_for_while_learning() {
        let mut s = Sanitizer::new(Vec::new(), Vec::new());
        s.learning = true;
        s.json(&json!({ "hostname": "office", "essid": "Home" }));
        assert!(s.known.is_none(), "not built while learning");
        s.learning = false;
        assert_eq!(s.scrub("office officejet back-office office_2 HOME HomeKit"), "name-1 officejet back-name-1 office_2 ssid-1 HomeKit");
        let out = s.json(&json!({ "model_display": "U6 Mesh", "inform_url": "http://unifi:8080/inform" }));
        assert_eq!((&out["model_display"], &out["inform_url"]), (&json!("U6 Mesh"), &json!("http://unifi:8080/inform")));
    }
}
