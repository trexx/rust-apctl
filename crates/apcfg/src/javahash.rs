//! Iteration order of a Java `HashSet<String>`.
//!
//! The official controller collects some lists (channel blacklists, broadcast filter
//! MACs) in a `HashSet` and writes them in its iteration order. That order is fully
//! determined by `String.hashCode()` and the table size, so it can be reproduced:
//! elements are visited by bucket (`(h ^ h >>> 16) & (capacity - 1)`), and within a
//! bucket in insertion order (resizing keeps the relative order of the entries that stay
//! together). Treeified buckets (8+ collisions in a table of 64+) are not modelled.

/// `String.hashCode()` over UTF-16 code units.
fn string_hash(s: &str) -> u32 {
    s.encode_utf16().fold(0u32, |h, c| h.wrapping_mul(31).wrapping_add(u32::from(c)))
}

/// Deduplicates `items` (first occurrence wins) and returns them in the order a
/// default-constructed `HashSet` filled one element at a time would iterate them.
pub fn hash_set_order<S: AsRef<str>>(items: &[S]) -> Vec<&str> {
    let mut unique: Vec<&str> = Vec::new();
    for s in items {
        if !unique.contains(&s.as_ref()) {
            unique.push(s.as_ref());
        }
    }
    // Default capacity 16, load factor 0.75: the table doubles once size exceeds 3/4.
    let mut capacity = 16usize;
    while unique.len() * 4 > capacity * 3 {
        capacity *= 2;
    }
    let bucket = |s: &str| {
        let h = string_hash(s);
        ((h ^ (h >> 16)) as usize) & (capacity - 1)
    };
    unique.sort_by_key(|s| bucket(s)); // stable: insertion order within a bucket
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_captured_channel_blacklist() {
        // radio_ai.channels_blacklist for 2.4 GHz, in stored order, and the `blklst`
        // value the official controller sent for it.
        let stored = ["2", "3", "4", "5", "7", "8", "9", "10", "12", "13", "14"];
        assert_eq!(hash_set_order(&stored).join(","), "12,2,13,3,14,4,5,7,8,9,10");
    }

    #[test]
    fn hash_matches_java() {
        assert_eq!(string_hash(""), 0);
        assert_eq!(string_hash("12"), 1569);
        assert_eq!(string_hash("hello"), 99162322);
    }
}
