//! Manufacturer names from the IEEE MAC address registry (`oui.csv`,
//! https://standards-oui.ieee.org/oui/oui.csv), for clients and neighbouring
//! networks.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use inform::Mac;

/// What a locally administered (randomised) address is listed as.
const PRIVATE: &str = "Private (randomised)";

/// Each prefix's name, as an index into the distinct names (a large
/// manufacturer has hundreds of prefixes).
#[derive(Default)]
pub struct Vendors {
    by_prefix: HashMap<u32, u32>,
    names: Vec<Box<str>>,
}

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
        let (mut v, mut index) = (Vendors::default(), HashMap::<String, u32>::new());
        for line in text.lines().skip(1) {
            let mut f = fields(line);
            if let (Some(registry), Some(prefix), Some(name)) = (f.next(), f.next(), f.next())
                && registry == "MA-L"
                && let Ok(prefix) = u32::from_str_radix(prefix.trim(), 16) {
                    let name = name.trim();
                    let i = match index.get(name) {
                        Some(i) => *i,
                        None => {
                            let i = u32::try_from(v.names.len())?;
                            v.names.push(name.into());
                            index.insert(name.to_string(), i);
                            i
                        }
                    };
                    v.by_prefix.insert(prefix, i);
                }
        }
        Ok(v)
    }

    pub fn len(&self) -> usize {
        self.by_prefix.len()
    }

    /// The manufacturer for a MAC. Locally administered addresses (random MACs
    /// used by phones and laptops for privacy) have no registered owner.
    pub fn lookup(&self, mac: &Mac) -> Option<&str> {
        let b = mac.0;
        if b[0] & 0x02 != 0 {
            return Some(PRIVATE);
        }
        self.by_prefix.get(&(u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]))).map(|&i| &*self.names[i as usize])
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
             MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Ning Qiao Road\"\n\
             MA-L,0418D6,Ubiquiti Inc ,\"685 Third Avenue\"\n",
        )
        .unwrap();
        let v = Vendors::load(&file).unwrap();
        assert_eq!(v.lookup_str("78:45:58:3c:52:bc"), Some("Ubiquiti Inc"));
        assert_eq!((v.lookup_str("04:18:d6:00:00:01"), v.len(), v.names.len()), (Some("Ubiquiti Inc"), 3, 2), "a name kept once");
        assert_eq!(v.lookup_str("28:6f:b9:00:00:01"), Some("Nokia Shanghai Bell Co., Ltd."));
        assert_eq!(v.lookup_str("86:00:00:00:00:06"), Some("Private (randomised)"));
        assert_eq!(v.lookup_str("00:00:01:00:00:00"), None);
    }
}
