//! Lenient accessors for the controller's MongoDB documents.
//!
//! The official controller is loose about types: the same field can be stored as a
//! number in one document and as a numeric string in another (`"ht": "20"` next to
//! `"ht": 80`). Every accessor here accepts both.

use serde_json::Value;

pub fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

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

/// A scalar rendered the way it appears in a config line (`9`, `auto`, `true`).
pub fn text_of(v: &Value, key: &str) -> Option<String> {
    as_text(v.get(key)?)
}

/// [`text_of`] for a value at hand (an array element).
pub fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

pub fn str_list<'a>(v: &'a Value, key: &str) -> Vec<&'a str> {
    arr(v, key).iter().filter_map(Value::as_str).collect()
}

/// A document id, either `{"_id": {"$oid": "..."}}` (extended JSON) or a plain string.
pub fn oid(v: &Value) -> Option<&str> {
    match v.get("_id")? {
        Value::String(s) => Some(s),
        Value::Object(o) => o.get("$oid").and_then(Value::as_str),
        _ => None,
    }
}

pub fn on_off(b: bool) -> &'static str {
    if b { "enabled" } else { "disabled" }
}

pub fn mac_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
