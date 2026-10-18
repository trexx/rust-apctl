//! Manufacturer names from the IEEE MAC address registry (`oui.csv`,
//! https://standards-oui.ieee.org/oui/oui.csv), for clients and neighbouring
//! networks.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use inform::Mac;

/// What a locally administered (randomised) address is listed as.
const PRIVATE: &str = "Private (randomised)";

#[derive(Default)]
pub struct Vendors(HashMap<u32, String>);

/// The fields of one CSV line, honouring double quotes, one at a time (the
/// registry's last field, the address, is not needed and so never copied).
fn fields(line: &str) -> impl Iterator<Item = String> + '_ {
    let mut chars = line.chars().peekable();
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let (mut cur, mut quoted) = (String::new(), false);
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    cur.push('"');
                    chars.next();
                }
                '"' => quoted = !quoted,
                ',' if !quoted => return Some(cur),
                _ => cur.push(c),
            }
        }
        done = true;
        Some(cur)
    })
}

impl Vendors {
    pub fn load(path: &Path) -> Result<Vendors> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut map = HashMap::new();
        for line in text.lines().skip(1) {
            let mut f = fields(line);
            if let (Some(registry), Some(prefix), Some(name)) = (f.next(), f.next(), f.next())
                && registry == "MA-L"
                && let Ok(prefix) = u32::from_str_radix(prefix.trim(), 16) {
                    map.insert(prefix, name.trim().to_string());
                }
        }
        Ok(Vendors(map))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The manufacturer for a MAC. Locally administered addresses (random MACs
    /// used by phones and laptops for privacy) have no registered owner.
    pub fn lookup(&self, mac: &Mac) -> Option<&str> {
        let b = mac.0;
        if b[0] & 0x02 != 0 {
            return Some(PRIVATE);
        }
        self.0.get(&(u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]))).map(String::as_str)
    }

    pub fn lookup_str(&self, mac: &str) -> Option<&str> {
        mac.parse::<Mac>().ok().and_then(|m| self.lookup(&m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::TestDir;

    #[test]
    fn parses_the_registry_format() {
        let dir = TestDir::new("oui");
        let file = dir.join("oui.csv");
        std::fs::write(
            &file,
            "Registry,Assignment,Organization Name,Organization Address\n\
             MA-L,784558,Ubiquiti Inc,\"685 Third Avenue, 27th Floor New York\"\n\
             MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Ning Qiao Road\"\n",
        )
        .unwrap();
        let v = Vendors::load(&file).unwrap();
        assert_eq!(v.lookup_str("78:45:58:3c:52:bc"), Some("Ubiquiti Inc"));
        assert_eq!(v.lookup_str("28:6f:b9:00:00:01"), Some("Nokia Shanghai Bell Co., Ltd."));
        assert_eq!(v.lookup_str("86:00:00:00:00:06"), Some("Private (randomised)"));
        assert_eq!(v.lookup_str("00:00:01:00:00:00"), None);
    }
}
