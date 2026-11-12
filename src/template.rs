//! Order-preserving JSON template patching and JS literal extraction helpers.
//!
//! Many payload schemas depend on exact serialization order of JSON keys
//! (e.g. requiring `"ver"` first) as well as float formatting. These helpers
//! patch fields in-place inside a raw JSON string without re-sorting keys.

use serde_json::Value;

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

fn scan_json_string(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn scan_json_value(bytes: &[u8], start: usize) -> usize {
    match bytes[start] {
        b'"' => scan_json_string(bytes, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut i = start;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => i = scan_json_string(bytes, i),
                    b'{' | b'[' => {
                        depth += 1;
                        i += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        i += 1;
                        if depth == 0 {
                            return i;
                        }
                    }
                    _ => i += 1,
                }
            }
            bytes.len()
        }
        _ => {
            let mut i = start;
            while i < bytes.len()
                && !matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',' | b'}' | b']')
            {
                i += 1;
            }
            i
        }
    }
}

fn locate_top_level_field(json_str: &str, key: &str) -> Result<(usize, usize), String> {
    let parsed: Value = serde_json::from_str(json_str).map_err(|e| format!("invalid JSON: {e}"))?;
    if !parsed.is_object() {
        return Err("JSON root must be an object".to_owned());
    }
    let bytes = json_str.as_bytes();
    let mut i = skip_ws(bytes, 0);
    i = skip_ws(bytes, i + 1); // skip '{'

    let mut matched_span: Option<(usize, usize)> = None;
    while i < bytes.len() && bytes[i] != b'}' {
        let key_start = i;
        let key_end = scan_json_string(bytes, key_start);
        let decoded_key: String = serde_json::from_str(&json_str[key_start..key_end])
            .map_err(|e| format!("invalid JSON key: {e}"))?;

        i = skip_ws(bytes, key_end);
        i = skip_ws(bytes, i + 1); // skip ':'

        let val_start = i;
        let val_end = scan_json_value(bytes, val_start);

        if decoded_key == key {
            if matched_span.is_some() {
                return Err(format!("duplicate top-level key {key:?}"));
            }
            matched_span = Some((val_start, val_end));
        }

        i = skip_ws(bytes, val_end);
        if i < bytes.len() && bytes[i] == b',' {
            i = skip_ws(bytes, i + 1);
        }
    }

    matched_span.ok_or_else(|| format!("missing top-level key {key:?}"))
}

/// Replace top-level string field `"<key>":"<old>"` with `"<key>":"<new_val>"` in-place
/// while preserving all bytes outside the replaced value token.
pub fn patch_json_str(json_str: &str, key: &str, new_val: &str) -> Result<String, String> {
    let (val_start, val_end) = locate_top_level_field(json_str, key)?;
    if json_str.as_bytes()[val_start] != b'"' {
        return Err(format!("top-level key {key:?} is not a string field"));
    }
    let escaped = serde_json::to_string(new_val)
        .map_err(|e| format!("failed to encode string replacement: {e}"))?;
    let mut out = String::with_capacity(json_str.len() - (val_end - val_start) + escaped.len());
    out.push_str(&json_str[..val_start]);
    out.push_str(&escaped);
    out.push_str(&json_str[val_end..]);
    Ok(out)
}

fn parse_hex4(bytes: &[u8], start: usize) -> Result<u32, String> {
    if start + 4 > bytes.len() {
        return Err("truncated \\uXXXX escape in JS string literal".to_owned());
    }
    let hex = std::str::from_utf8(&bytes[start..start + 4])
        .map_err(|_| "invalid \\uXXXX escape in JS string literal".to_owned())?;
    u32::from_str_radix(hex, 16).map_err(|_| format!("invalid hex in \\u{hex}"))
}

/// Parse the first JavaScript array literal of single- or double-quoted strings
/// found in `text` (supporting literal UTF-8, `\xNN`, `\uNNNN` including UTF-16
/// surrogate pairs, `\u{...}`, `\v`, `\0`, standard escapes, escaped quotes/slashes,
/// and backslash line continuations).
///
/// Note: This is a lightweight array extractor rather than a full JS lexer; it starts
/// at the first `'['` character in `text`.
pub fn parse_js_string_array(text: &str) -> Result<Vec<String>, String> {
    let Some(open_bracket) = text.find('[') else {
        return Err("no opening '[' found in input".to_owned());
    };
    let rest = &text[open_bracket + 1..];
    let bytes = rest.as_bytes();
    let n = bytes.len();
    let mut i = skip_ws(bytes, 0);
    if i < n && bytes[i] == b']' {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    loop {
        if i >= n {
            return Err("unterminated JS array: missing closing ']'".to_owned());
        }
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            return Err(format!(
                "expected quoted string element at byte offset {}",
                open_bracket + 1 + i
            ));
        }
        i += 1;
        let mut s = String::new();
        loop {
            if i >= n {
                return Err("unterminated string literal in JS array".to_owned());
            }
            let b = bytes[i];
            if b == quote {
                i += 1;
                break;
            }
            if b == b'\n' || b == b'\r' {
                return Err("unescaped newline in JS string literal".to_owned());
            }
            if b == b'\\' {
                i += 1;
                if i >= n {
                    return Err("trailing backslash in JS string literal".to_owned());
                }
                match bytes[i] {
                    b'n' => {
                        s.push('\n');
                        i += 1;
                    }
                    b'r' => {
                        s.push('\r');
                        i += 1;
                    }
                    b't' => {
                        s.push('\t');
                        i += 1;
                    }
                    b'b' => {
                        s.push('\u{0008}');
                        i += 1;
                    }
                    b'f' => {
                        s.push('\u{000c}');
                        i += 1;
                    }
                    b'v' => {
                        s.push('\u{000b}');
                        i += 1;
                    }
                    b'0' => {
                        if i + 1 < n && bytes[i + 1].is_ascii_digit() {
                            return Err("octal escape sequences are not supported".to_owned());
                        }
                        s.push('\0');
                        i += 1;
                    }
                    b'\'' => {
                        s.push('\'');
                        i += 1;
                    }
                    b'"' => {
                        s.push('"');
                        i += 1;
                    }
                    b'\\' => {
                        s.push('\\');
                        i += 1;
                    }
                    b'/' => {
                        s.push('/');
                        i += 1;
                    }
                    b'\n' => {
                        i += 1;
                    }
                    b'\r' => {
                        i += 1;
                        if i < n && bytes[i] == b'\n' {
                            i += 1;
                        }
                    }
                    b'x' => {
                        i += 1;
                        if i + 2 > n {
                            return Err("truncated \\x escape in JS string literal".to_owned());
                        }
                        let hex = std::str::from_utf8(&bytes[i..i + 2])
                            .map_err(|_| "invalid \\x escape in JS string literal".to_owned())?;
                        let code = u8::from_str_radix(hex, 16)
                            .map_err(|_| format!("invalid hex in \\x{hex}"))?;
                        s.push(code as char);
                        i += 2;
                    }
                    b'u' => {
                        i += 1;
                        if i < n && bytes[i] == b'{' {
                            i += 1;
                            let hex_start = i;
                            while i < n && bytes[i] != b'}' {
                                i += 1;
                            }
                            if i >= n || i == hex_start || i - hex_start > 6 {
                                return Err(
                                    "invalid \\u{...} escape in JS string literal".to_owned()
                                );
                            }
                            let hex = std::str::from_utf8(&bytes[hex_start..i])
                                .map_err(|_| "invalid \\u{...} escape".to_owned())?;
                            let code = u32::from_str_radix(hex, 16)
                                .map_err(|_| format!("invalid hex in \\u{{{hex}}}"))?;
                            let ch = char::from_u32(code)
                                .ok_or_else(|| format!("invalid Unicode scalar \\u{{{hex}}}"))?;
                            s.push(ch);
                            i += 1;
                        } else {
                            let code = parse_hex4(bytes, i)?;
                            i += 4;
                            if (0xD800..=0xDBFF).contains(&code) {
                                if i + 6 > n || bytes[i] != b'\\' || bytes[i + 1] != b'u' {
                                    return Err(format!(
                                        "unpaired high surrogate \\u{code:04X} in JS string literal"
                                    ));
                                }
                                let low = parse_hex4(bytes, i + 2)?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(format!(
                                        "high surrogate \\u{code:04X} followed by non-low surrogate \\u{low:04X}"
                                    ));
                                }
                                i += 6;
                                let combined = 0x10000 + (((code - 0xD800) << 10) | (low - 0xDC00));
                                let ch = char::from_u32(combined)
                                    .ok_or_else(|| "invalid surrogate pair".to_owned())?;
                                s.push(ch);
                            } else if (0xDC00..=0xDFFF).contains(&code) {
                                return Err(format!(
                                    "unpaired low surrogate \\u{code:04X} in JS string literal"
                                ));
                            } else {
                                let ch = char::from_u32(code).ok_or_else(|| {
                                    format!("invalid Unicode escape \\u{code:04X}")
                                })?;
                                s.push(ch);
                            }
                        }
                    }
                    _ => {
                        let ch = rest[i..].chars().next().unwrap();
                        if matches!(ch, '\u{2028}' | '\u{2029}') {
                            i += ch.len_utf8();
                        } else {
                            return Err(format!(
                                "unsupported escape sequence \\{ch} in JS string literal"
                            ));
                        }
                    }
                }
            } else {
                let ch = rest[i..].chars().next().unwrap();
                s.push(ch);
                i += ch.len_utf8();
            }
        }
        out.push(s);

        i = skip_ws(bytes, i);
        if i >= n {
            return Err("unterminated JS array: missing closing ']'".to_owned());
        }
        if bytes[i] == b']' {
            return Ok(out);
        }
        if bytes[i] != b',' {
            return Err(format!(
                "expected ',' or ']' after array element at byte offset {}",
                open_bracket + 1 + i
            ));
        }
        i = skip_ws(bytes, i + 1);
        if i < n && bytes[i] == b']' {
            return Ok(out);
        }
    }
}

/// Extract the last path segment or the `nth_from_last` (1-indexed) path segment
/// of a URL or path, stripping query strings, fragments, and any URL scheme/authority.
pub fn url_path_segment_from_end(url_or_path: &str, nth_from_last: usize) -> Option<&str> {
    let idx = nth_from_last.checked_sub(1)?;
    let without_qf = url_or_path.split(['?', '#']).next().unwrap_or(url_or_path);
    let path = if let Some((scheme, rest)) = without_qf.split_once("://")
        && !scheme.is_empty()
        && !scheme.contains('/')
    {
        rest.split_once('/').map_or("", |(_, p)| p)
    } else if let Some(rest) = without_qf.strip_prefix("//") {
        rest.split_once('/').map_or("", |(_, p)| p)
    } else {
        without_qf
    };
    path.split('/').filter(|s| !s.is_empty()).rev().nth(idx)
}

/// Ensure a JSON object string has the given top-level string field patched for every key in `patches`.
pub fn patch_json_fields(mut json_str: String, patches: &[(&str, &str)]) -> Result<String, String> {
    if patches.is_empty() && !is_valid_json_object(&json_str) {
        return Err("input is not a valid JSON object".to_owned());
    }
    for &(key, value) in patches {
        json_str = patch_json_str(&json_str, key, value)?;
    }
    Ok(json_str)
}

/// Replace a top-level scalar numeric/boolean/null field `"<key>":<old>` with `"<key>":<raw_val>`
/// while preserving all bytes outside the replaced value token.
pub fn patch_json_raw(json_str: &str, key: &str, raw_val: &str) -> Result<String, String> {
    let parsed_raw: Value = serde_json::from_str(raw_val)
        .map_err(|e| format!("invalid raw JSON replacement {raw_val:?}: {e}"))?;
    if !matches!(parsed_raw, Value::Number(_) | Value::Bool(_) | Value::Null) {
        return Err(format!(
            "raw replacement for {key:?} must be a JSON number, boolean, or null scalar"
        ));
    }
    let (val_start, val_end) = locate_top_level_field(json_str, key)?;
    if matches!(json_str.as_bytes()[val_start], b'"' | b'{' | b'[') {
        return Err(format!(
            "top-level key {key:?} is not a scalar number, boolean, or null field"
        ));
    }
    let mut out = String::with_capacity(json_str.len() - (val_end - val_start) + raw_val.len());
    out.push_str(&json_str[..val_start]);
    out.push_str(raw_val);
    out.push_str(&json_str[val_end..]);
    Ok(out)
}

/// Patch multiple top-level scalar numeric/boolean/null fields in-place.
pub fn patch_json_raw_fields(
    mut json_str: String,
    patches: &[(&str, &str)],
) -> Result<String, String> {
    if patches.is_empty() && !is_valid_json_object(&json_str) {
        return Err("input is not a valid JSON object".to_owned());
    }
    for &(key, value) in patches {
        json_str = patch_json_raw(&json_str, key, value)?;
    }
    Ok(json_str)
}

/// Validate that `text` parses as a JSON object (allowing surrounding JSON whitespace).
pub fn is_valid_json_object(text: &str) -> bool {
    serde_json::from_str::<Value>(text).is_ok_and(|v| v.is_object())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_json_strings_and_scalars_preserving_formatting_and_empty_values() {
        let raw = "  {\n  \"nested\" : { \"ver\" : \"inner\" },\n  \"embed\" : \"\\\"ver\\\":\\\"fake\\\"\",\n  \"\\u0076er\" : \"old\",\n  \"z\" : 1.000,\n  \"flag\" : false,\n  \"nil\" : null,\n  \"pur\" : \"https://a.test/\"\n}\n";
        let patched = patch_json_fields(
            raw.to_owned(),
            &[("ver", ""), ("pur", "https://b.test/\"q\"\n")],
        )
        .unwrap();
        let patched =
            patch_json_raw_fields(patched, &[("z", "1800.50"), ("flag", "true"), ("nil", "0")])
                .unwrap();
        assert_eq!(
            patched,
            "  {\n  \"nested\" : { \"ver\" : \"inner\" },\n  \"embed\" : \"\\\"ver\\\":\\\"fake\\\"\",\n  \"\\u0076er\" : \"\",\n  \"z\" : 1800.50,\n  \"flag\" : true,\n  \"nil\" : 0,\n  \"pur\" : \"https://b.test/\\\"q\\\"\\n\"\n}\n"
        );
        assert!(is_valid_json_object(&patched));
    }

    #[test]
    fn rejects_invalid_json_missing_duplicate_or_wrong_type_fields() {
        // Malformed JSON and non-object roots
        assert!(!is_valid_json_object("[1, 2]"));
        assert!(patch_json_str("{\"a\":1", "a", "x").is_err());
        assert!(patch_json_str("[\"a\"]", "a", "x").is_err());

        // Missing or only-nested key
        assert!(patch_json_str(r#"{"nested":{"ver":"old"}}"#, "ver", "new").is_err());

        // Duplicate selected top-level key
        assert!(patch_json_str(r#"{"ver":"a","ver":"b"}"#, "ver", "c").is_err());
        assert!(patch_json_raw(r#"{"z":1,"z":2}"#, "z", "3").is_err());

        // Whitespace + object/array/string field corruption regression in patch_json_raw
        let with_obj = r#"{"obj": {"a": 1, "b": 2}, "arr": [1, 2], "s": "txt", "n": 1}"#;
        assert!(patch_json_raw(with_obj, "obj", "42").is_err());
        assert!(patch_json_raw(with_obj, "arr", "42").is_err());
        assert!(patch_json_raw(with_obj, "s", "42").is_err());
        assert!(patch_json_str(with_obj, "n", "str").is_err());
        assert!(patch_json_str(with_obj, "obj", "str").is_err());

        // Invalid raw replacements (empty, string, object, array, injection)
        assert!(patch_json_raw(with_obj, "n", "").is_err());
        assert!(patch_json_raw(with_obj, "n", r#""str""#).is_err());
        assert!(patch_json_raw(with_obj, "n", "{}").is_err());
        assert!(patch_json_raw(with_obj, "n", "[]").is_err());
        assert!(patch_json_raw(with_obj, "n", r#"1, "injected": 2"#).is_err());
    }

    #[test]
    fn parses_js_string_array_utf8_surrogates_escapes_and_rejects_malformed() {
        let js = "var _0x1 = ['a\\x41', \"b\\vc\\n\\0\", 'café 🦀', \"\\uD83D\\uDE80\\u{1F600}\", 'it\\'s \\\"ok\\\" \\\\ \\/ \\\njoined\\\r\nline', ];";
        let arr = parse_js_string_array(js).unwrap();
        assert_eq!(
            arr,
            vec![
                "aA",
                "b\u{000b}c\n\0",
                "café 🦀",
                "🚀😀",
                "it's \"ok\" \\ / joinedline",
            ]
        );
        assert_eq!(parse_js_string_array("[]").unwrap(), Vec::<String>::new());

        // Malformed / truncated inputs must error instead of returning partial output
        assert!(parse_js_string_array("no array here").is_err());
        assert!(parse_js_string_array("['a', 'b'").is_err());
        assert!(parse_js_string_array("['a', 'unterminated]").is_err());
        assert!(parse_js_string_array("['a' 'b']").is_err());
        assert!(parse_js_string_array("['a', 123]").is_err());
        assert!(parse_js_string_array(r#"["\x4G"]"#).is_err());
        assert!(parse_js_string_array(r#"["\uD83D"]"#).is_err());
        assert!(parse_js_string_array(r#"["\uD83D\u0041"]"#).is_err());
        assert!(parse_js_string_array(r#"["\uDE80"]"#).is_err());
        assert!(parse_js_string_array("[\"unescaped\nnewline\"]").is_err());
    }

    #[test]
    fn extracts_url_path_segments_excluding_host_query_and_fragment() {
        assert_eq!(
            url_path_segment_from_end("https://example.com/a/b/c?x=1#frag", 1),
            Some("c")
        );
        assert_eq!(
            url_path_segment_from_end("https://example.com/a/b#frag?x=1", 2),
            Some("a")
        );
        assert_eq!(
            url_path_segment_from_end("https://example.com/a/b", 3),
            None
        );
        assert_eq!(url_path_segment_from_end("https://example.com/", 1), None);
        assert_eq!(
            url_path_segment_from_end("https://example.com#frag", 1),
            None
        );
        assert_eq!(url_path_segment_from_end("//cdn.example.com/x", 2), None);
        assert_eq!(url_path_segment_from_end("/a/b/c#frag", 1), Some("c"));
        assert_eq!(url_path_segment_from_end("/a/b/c", 0), None);
    }
}
