//! Order-preserving JSON template patching and JS literal extraction helpers.
//!
//! Anti-bot edge verifiers frequently check the exact serialization order of
//! JSON keys (e.g. requiring `"ver"` first) as well as float formatting. These
//! helpers patch fields in-place inside a raw JSON string without re-sorting keys.

use serde_json::Value;

/// Replace `"<key>":"<old>"` with `"<key>":"<new_val>"` in-place while preserving
/// the exact surrounding JSON key order and formatting.
pub fn patch_json_str(json_str: &str, key: &str, new_val: &str) -> String {
    if new_val.is_empty() {
        return json_str.to_owned();
    }
    let needle = format!("\"{key}\":\"");
    let Some(start) = json_str.find(&needle) else {
        return json_str.to_owned();
    };
    let val_start = start + needle.len();
    let bytes = json_str.as_bytes();
    let mut idx = val_start;
    while idx < bytes.len() {
        if bytes[idx] == b'\\' {
            idx += 2;
            continue;
        }
        if bytes[idx] == b'"' {
            let escaped =
                serde_json::to_string(new_val).unwrap_or_else(|_| format!("\"{new_val}\""));
            let inner = &escaped[1..escaped.len() - 1];
            let mut out = String::with_capacity(json_str.len() + inner.len());
            out.push_str(&json_str[..val_start]);
            out.push_str(inner);
            out.push_str(&json_str[idx..]);
            return out;
        }
        idx += 1;
    }
    json_str.to_owned()
}

/// Parse a JavaScript array literal of single- or double-quoted strings
/// (supporting `\xNN`, `\uNNNN`, `\v`, `\0`, and standard escapes).
pub fn parse_js_string_array(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let n = bytes.len();
    while i < n && bytes[i] != b'[' {
        i += 1;
    }
    if i >= n {
        return out;
    }
    i += 1;
    while i < n {
        while i < n && matches!(bytes[i], b' ' | b',' | b'\r' | b'\n' | b'\t') {
            i += 1;
        }
        if i >= n || bytes[i] == b']' {
            break;
        }
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            break;
        }
        i += 1;
        let mut s = String::new();
        while i < n && bytes[i] != quote {
            if bytes[i] == b'\\' && i + 1 < n {
                i += 1;
                match bytes[i] {
                    b'n' => s.push('\n'),
                    b'r' => s.push('\r'),
                    b't' => s.push('\t'),
                    b'b' => s.push('\u{0008}'),
                    b'f' => s.push('\u{000c}'),
                    b'v' => s.push('\u{000b}'),
                    b'0' => s.push('\0'),
                    b'x' if i + 2 < n => {
                        if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
                            && let Ok(code) = u8::from_str_radix(hex, 16)
                        {
                            s.push(code as char);
                            i += 2;
                        }
                    }
                    b'u' if i + 4 < n => {
                        if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 5])
                            && let Ok(code) = u32::from_str_radix(hex, 16)
                            && let Some(ch) = char::from_u32(code)
                        {
                            s.push(ch);
                            i += 4;
                        }
                    }
                    other => s.push(other as char),
                }
            } else {
                s.push(bytes[i] as char);
            }
            i += 1;
        }
        i += 1;
        out.push(s);
    }
    out
}

/// Extract the last path segment or the `nth_from_last` path segment of a URL or path.
pub fn url_path_segment_from_end(url_or_path: &str, nth_from_last: usize) -> Option<&str> {
    let path = url_or_path.split('?').next().unwrap_or(url_or_path);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() >= nth_from_last && nth_from_last > 0 {
        Some(segments[segments.len() - nth_from_last])
    } else {
        None
    }
}

/// Ensure a JSON string has the given string field patched for every key in `patches`.
pub fn patch_json_fields(mut json_str: String, patches: &[(&str, &str)]) -> String {
    for &(key, value) in patches {
        json_str = patch_json_str(&json_str, key, value);
    }
    json_str
}

/// Replace a scalar numeric/boolean field `"<key>":<old>` with `"<key>":<raw_val>`
/// while preserving surrounding JSON key order.
pub fn patch_json_raw(json_str: &str, key: &str, raw_val: &str) -> String {
    if raw_val.is_empty() {
        return json_str.to_owned();
    }
    let needle = format!("\"{key}\":");
    let Some(start) = json_str.find(&needle) else {
        return json_str.to_owned();
    };
    let val_start = start + needle.len();
    let bytes = json_str.as_bytes();
    if val_start >= bytes.len() || matches!(bytes[val_start], b'"' | b'{' | b'[') {
        return json_str.to_owned();
    }
    let mut idx = val_start;
    while idx < bytes.len() && !matches!(bytes[idx], b',' | b'}' | b']') {
        idx += 1;
    }
    let mut out = String::with_capacity(json_str.len() + raw_val.len());
    out.push_str(&json_str[..val_start]);
    out.push_str(raw_val);
    out.push_str(&json_str[idx..]);
    out
}

/// Patch multiple scalar numeric/boolean fields in-place.
pub fn patch_json_raw_fields(mut json_str: String, patches: &[(&str, &str)]) -> String {
    for &(key, value) in patches {
        json_str = patch_json_raw(&json_str, key, value);
    }
    json_str
}

/// Validate that `text` parses as a JSON object while keeping its raw string intact.
pub fn is_valid_json_object(text: &str) -> bool {
    text.starts_with('{')
        && text.ends_with('}')
        && serde_json::from_str::<Value>(text).is_ok_and(|v| v.is_object())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_json_strings_and_scalars_without_reordering_keys() {
        let raw = r#"{"ver":"old","z":1,"pur":"https://a.test/","a":2}"#;
        let patched = patch_json_fields(
            raw.to_owned(),
            &[("ver", "new_ver"), ("pur", "https://b.test/path")],
        );
        let patched = patch_json_raw_fields(patched, &[("z", "1800"), ("a", "1169")]);
        assert_eq!(
            patched,
            r#"{"ver":"new_ver","z":1800,"pur":"https://b.test/path","a":1169}"#
        );
        assert!(is_valid_json_object(&patched));
    }

    #[test]
    fn parses_escaped_js_string_arrays() {
        let arr = parse_js_string_array(r#"['a\x41', "b\vc\n"]"#);
        assert_eq!(arr, vec!["aA", "b\u{000b}c\n"]);
    }
}
