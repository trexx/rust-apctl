//! Lenient accessors for the controller's MongoDB documents.
//!
//! The official controller is loose about types: the same field can be stored as a
//! number in one document and as a numeric string in another (`"ht": "20"` next to
//! `"ht": 80`). Every accessor here accepts both.

use serde_json::Value;

pub fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// A boolean field: `true`/`false`, or the strings `"true"`/`"false"`; `None` when
/// missing or anything else.
pub fn bool_of(v: &Value, key: &str) -> Option<bool> {
    match v.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s == "true" => Some(true),
        Value::String(s) if s == "false" => Some(false),
        _ => None,
    }
}

/// `bool_of` with a default for missing or unreadable values.
pub fn flag(v: &Value, key: &str, default: bool) -> bool {
    bool_of(v, key).unwrap_or(default)
}

/// An integer field: an integer, a float without a fraction (`2000.0`) or a numeric
/// string (`"20"`); `None` when missing or anything else.
pub fn int_of(v: &Value, key: &str) -> Option<i64> {
    as_int(v.get(key)?)
}

pub fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A scalar as it appears in a config line (`9`, `auto`, `true`), borrowed: it is
/// written straight into the output.
#[derive(Clone, Copy, Debug)]
pub enum Text<'a> {
    /// A string, number or boolean from a document.
    Value(&'a Value),
    /// A default.
    Str(&'a str),
}

impl Text<'_> {
    /// Whether this is the string `s` (a number never is).
    pub fn is(self, s: &str) -> bool {
        match self {
            Text::Value(Value::String(v)) => v == s,
            Text::Str(v) => v == s,
            Text::Value(_) => false,
        }
    }
}

impl std::fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Text::Value(Value::String(s)) => f.write_str(s),
            Text::Str(s) => f.write_str(s),
            // Numbers and booleans display as in JSON: `9`, `-1.5`, `true`.
            Text::Value(v) => write!(f, "{v}"),
        }
    }
}

/// A scalar rendered the way it appears in a config line (`9`, `auto`, `true`).
pub fn text_of<'a>(v: &'a Value, key: &str) -> Option<Text<'a>> {
    as_text(v.get(key)?)
}

/// [`text_of`] for a value at hand (an array element).
pub fn as_text(v: &Value) -> Option<Text<'_>> {
    matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_)).then_some(Text::Value(v))
}

pub fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// The strings of an array field (anything else in it is skipped).
pub fn str_list<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a str> + use<'a> {
    arr(v, key).iter().filter_map(Value::as_str)
}

/// A document id, either `{"_id": {"$oid": "..."}}` (extended JSON) or a plain string.
pub fn oid(v: &Value) -> Option<&str> {
    match v.get("_id")? {
        Value::String(s) => Some(s),
        Value::Object(o) => o.get("$oid").and_then(Value::as_str),
        _ => None,
    }
}

/// A device's `on`/`off` override of a site-wide setting; anything else follows the site.
pub fn override_of(device: &Value, key: &str, site: bool) -> bool {
    match str_of(device, key) {
        Some("on") => true,
        Some("off") => false,
        _ => site,
    }
}

pub fn on_off(b: bool) -> &'static str {
    if b { "enabled" } else { "disabled" }
}

pub fn mac_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalars_read_as_config_text() {
        let v = json!({ "s": "auto", "n": 9, "f": -1.5, "b": true, "o": {} });
        let text = |k| text_of(&v, k).map(|t| t.to_string());
        assert_eq!([text("s"), text("n"), text("f"), text("b"), text("o"), text("x")], [Some("auto".into()), Some("9".into()), Some("-1.5".into()), Some("true".into()), None, None]);
        assert!(text_of(&v, "s").unwrap().is("auto") && !text_of(&json!({ "n": 6 }), "n").unwrap().is("6") && Text::Str("0").is("0"));
    }
}
