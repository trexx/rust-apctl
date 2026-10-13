//! Line-oriented builder for `key=value` config text.

use std::fmt::Display;

#[derive(Default)]
pub struct Cfg {
    out: String,
}

impl Cfg {
    /// A `# name` section comment.
    pub fn header(&mut self, name: &str) {
        self.out.push_str("# ");
        self.out.push_str(name);
        self.out.push('\n');
    }

    pub fn set(&mut self, key: impl AsRef<str>, value: impl Display) {
        use std::fmt::Write;
        let _ = writeln!(self.out, "{}={value}", key.as_ref());
    }

    /// Writes the line only when there is a value.
    pub fn opt(&mut self, key: impl AsRef<str>, value: Option<impl Display>) {
        if let Some(v) = value {
            self.set(key, v);
        }
    }

    pub fn finish(self) -> String {
        self.out
    }
}
