//! Decodes inform HTTP bodies and prints what happened, including config diffs.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use inform::Mac;
use serde_json::{Value, json};
use wire::capture::{HttpEvent, Micros};
use wire::decode::Decoded;
use wire::exchange::{InformEvent, Pairer};
use wire::keys::KeyStore;

use wire::cfgdiff;

pub struct Options {
    /// Print every message. Otherwise noop replies and repeat informs are hidden.
    pub all: bool,
    /// Print full decoded JSON for each shown message.
    pub full: bool,
    /// Emit one JSON object per message instead of text.
    pub json: bool,
    /// Directory to save each decoded payload into (unredacted).
    pub save: Option<PathBuf>,
    /// Mask passwords, PSKs and keys in printed output.
    pub redact: bool,
}

#[derive(Default)]
struct DeviceState {
    seen: bool,
    /// The last value of each of `CFG_FIELDS`.
    cfg: [Option<String>; CFG_FIELDS.len()],
}

pub struct Reporter {
    keys: KeyStore,
    opts: Options,
    pairer: Pairer,
    devices: HashMap<Mac, DeviceState>,
    seq: u64,
    /// The `--save` directory exists (it is created on the first save).
    save_dir_ready: bool,
}

const CFG_FIELDS: [&str; 2] = ["mgmt_cfg", "system_cfg"];

impl Reporter {
    pub fn new(keys: KeyStore, opts: Options) -> Self {
        Reporter { keys, opts, pairer: Pairer::default(), devices: HashMap::new(), seq: 0, save_dir_ready: false }
    }

    pub fn handle(&mut self, ev: HttpEvent) {
        match self.pairer.handle(&self.keys, ev) {
            Some(InformEvent::Inform { ts, peer, decoded, .. }) => self.request(&peer, ts, decoded),
            Some(InformEvent::Reply { ts, mac, status, decoded: None }) => {
                if self.opts.all {
                    self.line(ts, mac, "<-", &format!("HTTP {status} (empty body)"));
                }
            }
            Some(InformEvent::Reply { ts, mac, status, decoded: Some(decoded) }) => {
                self.response(ts, mac, status, decoded)
            }
            None => {}
        }
    }

    fn request(&mut self, peer: &str, ts: Micros, decoded: Result<Decoded>) {
        let d = match decoded {
            Ok(d) => d,
            Err(e) => return self.line(ts, None, "->", &format!("inform from {peer} undecodable: {e:#}")),
        };
        let mac = d.header.mac;
        let state = self.devices.entry(mac).or_default();
        let first = !state.seen;
        state.seen = true;
        self.save(ts, mac, "inform", &d.payload);
        if self.opts.json {
            return self.emit_json(ts, mac, "inform", d, None);
        }
        if !(self.opts.all || first) {
            return;
        }
        let p = &d.payload;
        let mut summary = vec![format!("inform {:?} key={:?}", d.header.flags, d.key)];
        for field in ["hostname", "model", "version", "state", "cfgversion", "uptime", "default"] {
            if let Some(v) = p.get(field) {
                summary.push(format!("{field}={}", scalar(v)));
            }
        }
        if let Some(n) = count_clients(p) {
            summary.push(format!("clients={n}"));
        }
        if first {
            summary.push(format!("from={peer} (first seen)"));
        }
        self.line(ts, Some(mac), "->", &summary.join(" "));
        if self.opts.full {
            println!("{}", self.printable(p));
        }
    }

    fn response(&mut self, ts: Micros, mac_hint: Option<Mac>, status: u16, decoded: Result<Decoded>) {
        let d = match decoded {
            Ok(d) => d,
            Err(e) => return self.line(ts, mac_hint, "<-", &format!("HTTP {status} reply undecodable: {e:#}")),
        };
        let mac = mac_hint.unwrap_or(d.header.mac);
        let kind = d.payload.get("_type").and_then(Value::as_str).unwrap_or("?").to_string();
        self.save(ts, mac, &format!("reply-{kind}"), &d.payload);

        // Config diffs are tracked even when the message itself is not printed.
        let state = self.devices.entry(mac).or_default();
        let configs: Vec<(&str, Option<String>, &str)> = CFG_FIELDS
            .iter()
            .zip(&mut state.cfg)
            .filter_map(|(&field, last)| {
                let new = d.payload.get(field).and_then(Value::as_str)?;
                Some((field, last.replace(new.to_string()), new))
            })
            .collect();
        let diffs: Vec<_> =
            configs.iter().map(|(field, old, new)| (*field, old.as_deref().map(|old| cfgdiff::diff(old, new)), new.lines().count())).collect();

        if self.opts.json {
            let rendered: Value = diffs
                .iter()
                .filter_map(|(f, diff, _)| diff.as_ref().map(|d| (f.to_string(), json!(d.render("", self.opts.redact)))))
                .collect::<serde_json::Map<_, _>>()
                .into();
            return self.emit_json(ts, mac, &format!("reply-{kind}"), d, Some(rendered));
        }
        if kind == "noop" && !self.opts.all {
            return;
        }

        let mut summary = vec![format!("{kind} {:?} key={:?}", d.header.flags, d.key)];
        for field in ["interval", "cfgversion", "cmd", "version", "url"] {
            if let Some(v) = d.payload.get(field) {
                summary.push(format!("{field}={}", scalar(v)));
            }
        }
        if kind == "setparam" {
            let others: Vec<&str> = d
                .payload
                .as_object()
                .map(|o| o.keys().map(String::as_str).filter(|k| !k.starts_with('_') && !CFG_FIELDS.contains(k)).collect())
                .unwrap_or_default();
            if !others.is_empty() {
                summary.push(format!("other_fields=[{}]", others.join(",")));
            }
        }
        self.line(ts, Some(mac), "<-", &summary.join(" "));
        for (field, diff, lines) in diffs {
            match diff {
                None => println!("    {field}: first seen, {lines} lines (use --full to print)"),
                Some(d) if d.is_empty() => println!("    {field}: unchanged"),
                Some(d) => {
                    println!("    {field}: {} added, {} removed, {} changed", d.added.len(), d.removed.len(), d.changed.len());
                    print!("{}", d.render("      ", self.opts.redact));
                }
            }
        }
        if self.opts.full {
            println!("{}", self.printable(&d.payload));
        }
    }

    /// Pretty JSON for printing, with secrets masked unless redaction is off.
    fn printable(&self, v: &Value) -> String {
        if self.opts.redact { pretty(&redact_json(v)) } else { pretty(v) }
    }

    fn emit_json(&self, ts: Micros, mac: Mac, kind: &str, d: Decoded, diffs: Option<Value>) {
        let mut obj = json!({
            "ts": format_ts(ts),
            "mac": mac.to_string(),
            "kind": kind,
            "flags": format!("{:?}", d.header.flags),
            "key": format!("{:?}", d.key),
            "payload": if self.opts.redact { redact_json(&d.payload) } else { d.payload },
        });
        if let Some(diffs) = diffs {
            obj["diffs"] = diffs;
        }
        println!("{obj}");
    }

    /// Saves a payload unredacted (authkeys, PSKs): owner-only directory and files.
    fn save(&mut self, ts: Micros, mac: Mac, kind: &str, payload: &Value) {
        let Some(dir) = &self.opts.save else { return };
        self.seq += 1;
        let path = dir.join(save_name(ts, self.seq, mac, kind));
        // If it cannot be created, writing the file says why.
        self.save_dir_ready = self.save_dir_ready || crate::create_private_dir(dir).is_ok();
        // Always a new file: a name already taken (by an earlier run, or by someone else
        // in a shared directory) is not written through.
        let result = crate::create_private(&path, pretty(payload).as_bytes()).with_context(|| format!("saving {}", path.display()));
        if let Err(e) = result {
            eprintln!("warning: {e:#}");
        }
    }

    fn line(&self, ts: Micros, mac: Option<Mac>, dir: &str, text: &str) {
        let mac = mac.map(|m| m.to_string()).unwrap_or_else(|| "??:??:??:??:??:??".into());
        println!("{} {mac} {dir} {text}", format_ts(ts));
    }
}

/// The `--save` file name of a message. `kind` comes from the decoded reply (its
/// `_type`), which whoever sent it chose: only letters, digits, `_` and `-` are kept,
/// so it cannot name another directory, and it is cut short.
fn save_name(ts: Micros, seq: u64, mac: Mac, kind: &str) -> String {
    let kind: String = kind.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')).take(40).collect();
    format!("{}_{seq:06}_{}_{kind}.json", format_ts(ts).replace(':', ""), mac.to_string().replace(':', ""))
}

/// Masks secret fields, including secret lines inside `*_cfg` blobs. Under a secret
/// key every string is masked, however deeply it is nested (`x_ssh_keys: [{...}]`).
fn redact_json(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| {
                    let v = match v {
                        Value::String(s) if k.ends_with("_cfg") => Value::String(cfgdiff::redact(s)),
                        secret if cfgdiff::is_secret(k) => redact_all(secret),
                        other => redact_json(other),
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(redact_json).collect()),
        other => other.clone(),
    }
}

/// Every string in `v` masked.
fn redact_all(v: &Value) -> Value {
    match v {
        Value::String(_) => Value::String("<redacted>".into()),
        Value::Array(a) => Value::Array(a.iter().map(redact_all).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), redact_all(v))).collect()),
        other => other.clone(),
    }
}

fn count_clients(p: &Value) -> Option<usize> {
    let vaps = p.get("vap_table")?.as_array()?;
    Some(vaps.iter().filter_map(|v| v.get("sta_table")?.as_array().map(Vec::len)).sum())
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

/// Formats microseconds since the epoch as an RFC 3339 UTC timestamp with milliseconds.
pub fn format_ts(ts: Micros) -> String {
    let secs = ts.div_euclid(1_000_000);
    let millis = ts.rem_euclid(1_000_000) / 1000;
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = wire::civil_from_days(secs.div_euclid(86_400));
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_names_keep_only_safe_characters() {
        let mac: Mac = "02:00:00:00:00:01".parse().unwrap();
        let ts = 1_791_840_601_123_456;
        assert_eq!(save_name(ts, 7, mac, "reply-setparam"), "2026-10-12T213001.123Z_000007_020000000001_reply-setparam.json");
        assert_eq!(save_name(ts, 7, mac, "reply-../../x/\u{1b}[2J.y"), "2026-10-12T213001.123Z_000007_020000000001_reply-x2Jy.json");
        assert_eq!(save_name(ts, 7, mac, &format!("reply-{}", "a".repeat(500))).len(), "2026-10-12T213001.123Z_000007_020000000001_.json".len() + 40);
    }

    #[test]
    fn secrets_are_masked_in_arrays_and_objects_too() {
        let v = json!({
            "x_passphrase": "hunter22",
            "x_ssh_keys": [{ "key": "ssh-ed25519 AAAAC3Nz", "comment": "me@laptop", "date": 7 }],
            "psk": ["one", "two"],
            "radio_table": [{ "name": "wifi0", "x_secret": { "inner": "s3cret" } }],
            "system_cfg": "aaa.1.wpa.psk=hunter22\nradio.1.channel=36",
        });
        let out = redact_json(&v);
        assert_eq!(out["x_passphrase"], "<redacted>");
        assert_eq!(out["x_ssh_keys"], json!([{ "key": "<redacted>", "comment": "<redacted>", "date": 7 }]));
        assert_eq!(out["psk"], json!(["<redacted>", "<redacted>"]));
        assert_eq!(out["radio_table"], json!([{ "name": "wifi0", "x_secret": { "inner": "<redacted>" } }]));
        assert!(!out.to_string().contains("hunter22") && out["system_cfg"].as_str().unwrap().contains("radio.1.channel=36"));
    }

    #[test]
    fn formats_timestamps() {
        assert_eq!(format_ts(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_ts(1_791_840_601_123_456), "2026-10-12T21:30:01.123Z");
    }
}
