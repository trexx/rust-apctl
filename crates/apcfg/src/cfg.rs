//! Line-oriented builder for `key=value` config text.
//!
//! Every line goes through here, so this is where values from the settings (SSIDs,
//! names, passphrases, imported or typed by a user) are kept to one line: control
//! characters are dropped from keys and values. A `\n` inside a value would otherwise
//! start a line of its own on the AP (a cron job, a user's password). Dropping them
//! cannot fail and changes nothing for well-formed settings; the AP could not use a
//! value with a line break in it anyway.
//!
//! Keys are written straight into the output: callers pass a [`Prefix`] key or
//! `format_args!`, not a formatted `String` (a render writes several hundred lines,
//! for every AP each time the settings change).

use std::fmt::{self, Display, Write};

#[derive(Default)]
pub struct Cfg {
    out: String,
}

impl Cfg {
    pub fn with_capacity(bytes: usize) -> Cfg {
        Cfg { out: String::with_capacity(bytes) }
    }

    /// A `# name` section comment.
    pub fn header(&mut self, name: &str) {
        let start = self.out.len();
        self.out.push_str("# ");
        self.out.push_str(name);
        self.end_line(start);
    }

    pub fn set(&mut self, key: impl Display, value: impl Display) {
        let start = self.out.len();
        let _ = write!(self.out, "{key}={value}");
        self.end_line(start);
    }

    /// Writes the line only when there is a value.
    pub fn opt(&mut self, key: impl Display, value: Option<impl Display>) {
        if let Some(v) = value {
            self.set(key, v);
        }
    }

    pub fn finish(self) -> String {
        self.out
    }

    /// Drops control characters from the line started at `start` and ends it.
    fn end_line(&mut self, start: usize) {
        if self.out[start..].contains(char::is_control) {
            let line: String = self.out[start..].chars().filter(|c| !c.is_control()).collect();
            self.out.truncate(start);
            self.out.push_str(&line);
        }
        self.out.push('\n');
    }
}

/// The start of the keys of a numbered section, `section.n.` (`radio.1.`, `aaa.3.`).
/// It displays as that, so `format_args!("{p}virtual.{o}.mode")` builds a longer key.
#[derive(Clone, Copy)]
pub struct Prefix<'a> {
    section: &'a str,
    n: usize,
}

impl<'a> Prefix<'a> {
    pub fn new(section: &'a str, n: usize) -> Prefix<'a> {
        Prefix { section, n }
    }

    /// The key `section.n.key`.
    pub fn at<'k>(self, key: &'k str) -> Key<'a, 'k> {
        Key { prefix: self, key }
    }
}

impl Display for Prefix<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.", self.section, self.n)
    }
}

/// A key in a [`Prefix`]'s section.
pub struct Key<'a, 'k> {
    prefix: Prefix<'a>,
    key: &'k str,
}

impl Display for Key<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.prefix, self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_cannot_add_lines() {
        let mut c = Cfg::default();
        c.header("users");
        c.set("aaa.1.ssid", "Home\nusers.1.password=x\r\ncron.1.job.1.cmd=reboot");
        c.set("aaa.1.\nwpa.psk", "a\tb\u{7f}c\u{85}d");
        c.set("aaa.1.id", 3);
        let p = Prefix::new("aaa", 2);
        c.set(p.at("ssid"), "Guest\r\n");
        c.set(format_args!("{p}sae.psk.{}.psk", 1), "x\ny");
        c.opt(p.at("none"), None::<&str>);
        assert_eq!(
            c.finish(),
            "# users\naaa.1.ssid=Homeusers.1.password=xcron.1.job.1.cmd=reboot\naaa.1.wpa.psk=abcd\naaa.1.id=3\naaa.2.ssid=Guest\naaa.2.sae.psk.1.psk=xy\n"
        );
    }
}
