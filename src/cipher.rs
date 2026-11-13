//! Reusable cipher, permutation, Caesar rotation, and checksum primitives.

/// 92-character printable ASCII alphabet (`32..=126` excluding `"`, `'`, and `\`).
pub const ALPHABET_92: [u8; 92] = build_alphabet_92();

const fn build_alphabet_92() -> [u8; 92] {
    let mut table = [0u8; 92];
    let mut out = 0;
    let mut code = 32u8;
    while code <= 126 {
        if code != b'"' && code != b'\'' && code != b'\\' {
            table[out] = code;
            out += 1;
        }
        code += 1;
    }
    table
}

/// One 23-bit LCG step (`(state * 65793 + 4282663) & 0x7fffff`).
#[inline]
pub fn step_lcg23(state: u32) -> u32 {
    (state.wrapping_mul(65_793).wrapping_add(4_282_663)) & 0x7f_ffff
}

/// 16-bit draw from a 23-bit LCG state.
#[inline]
pub fn draw_lcg23(state: u32) -> u16 {
    ((state >> 8) & 0xffff) as u16
}

#[inline]
fn index_of_92(byte: u8) -> Option<usize> {
    ALPHABET_92.iter().position(|&candidate| candidate == byte)
}

/// Substitute (encode) with `key` over [`ALPHABET_92`].
/// Non-alphabet bytes (including UTF-8) are preserved; the LCG advances per byte.
pub fn substitute_92(text: &str, key: u32) -> String {
    let mut state = key;
    let mut out = text.as_bytes().to_vec();
    for byte in &mut out {
        *byte = match index_of_92(*byte) {
            Some(index) => {
                let shift = (draw_lcg23(state) % ALPHABET_92.len() as u16) as usize;
                ALPHABET_92[(index + shift) % ALPHABET_92.len()]
            }
            None => *byte,
        };
        state = step_lcg23(state);
    }
    String::from_utf8(out).expect("ASCII substitution preserves UTF-8")
}

/// Undo [`substitute_92`].
pub fn desubstitute_92(text: &str, key: u32) -> String {
    let mut state = key;
    let mut out = text.as_bytes().to_vec();
    for byte in &mut out {
        *byte = match index_of_92(*byte) {
            Some(index) => {
                let shift = (draw_lcg23(state) % ALPHABET_92.len() as u16) as usize;
                ALPHABET_92[(index + ALPHABET_92.len() - shift) % ALPHABET_92.len()]
            }
            None => *byte,
        };
        state = step_lcg23(state);
    }
    String::from_utf8(out).expect("ASCII substitution preserves UTF-8")
}

/// Substitute over [`ALPHABET_92`], advancing the LCG per UTF-16 code unit,
/// as in a JavaScript `charAt` loop. Non-alphabet characters are preserved.
///
/// BMP characters consume one step; supplementary characters consume two.
/// Use [`substitute_92`] for protocols that advance per UTF-8 byte instead.
pub fn substitute_92_utf16(text: &str, key: u32) -> String {
    substitute_utf16::<false>(text, key)
}

/// Undo [`substitute_92_utf16`] with the same UTF-16 state progression.
pub fn desubstitute_92_utf16(text: &str, key: u32) -> String {
    substitute_utf16::<true>(text, key)
}

fn substitute_utf16<const INVERSE: bool>(text: &str, key: u32) -> String {
    let mut state = key;
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let rotated = if ch.is_ascii()
            && let Some(index) = index_of_92(ch as u8)
        {
            let shift = (draw_lcg23(state) % ALPHABET_92.len() as u16) as usize;
            let shift = if INVERSE {
                ALPHABET_92.len() - shift
            } else {
                shift
            };
            ALPHABET_92[(index + shift) % ALPHABET_92.len()] as char
        } else {
            ch
        };
        out.push(rotated);
        state = step_lcg23(state);
        if ch.len_utf16() == 2 {
            state = step_lcg23(state);
        }
    }
    out
}

/// Swap index pairs produced by `count` draws of the 23-bit LCG.
pub fn swaps_lcg23(count: usize, key: u32) -> Vec<(usize, usize)> {
    let mut pairs = Vec::with_capacity(count);
    let mut state = key;
    for _ in 0..count {
        let first = (draw_lcg23(state) as usize) % count.max(1);
        state = step_lcg23(state);
        let second = (draw_lcg23(state) as usize) % count.max(1);
        state = step_lcg23(state);
        pairs.push((first, second));
    }
    pairs
}

/// Apply the LCG permutation to `parts` (encoding direction).
pub fn permute(parts: &[String], key: u32) -> Vec<String> {
    let mut out = parts.to_vec();
    for (first, second) in swaps_lcg23(out.len(), key) {
        out.swap(first, second);
    }
    out
}

/// Replay the LCG permutation backwards (decoding direction).
pub fn unpermute(parts: &[String], key: u32) -> Vec<String> {
    let mut out = parts.to_vec();
    let mut pairs = swaps_lcg23(out.len(), key);
    pairs.reverse();
    for (first, second) in pairs {
        out.swap(first, second);
    }
    out
}

/// Split `text` on `sep`, permute with `key`, and rejoin.
pub fn permute_join(text: &str, sep: char, key: u32) -> String {
    let parts: Vec<String> = text.split(sep).map(str::to_owned).collect();
    permute(&parts, key).join(&sep.to_string())
}

/// Inverse of [`permute_join`].
pub fn unpermute_join(text: &str, sep: char, key: u32) -> String {
    let parts: Vec<String> = text.split(sep).map(str::to_owned).collect();
    unpermute(&parts, key).join(&sep.to_string())
}

/// Rotate characters in `text` that appear in `alphabet` by `shift`.
pub fn caesar_shift(text: &str, alphabet: &[u8], shift: isize) -> String {
    if alphabet.is_empty() {
        return text.to_owned();
    }
    let len = alphabet.len() as isize;
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii()
            && let Some(pos) = alphabet.iter().position(|&b| b == ch as u8)
        {
            let next = (pos as isize + shift).rem_euclid(len) as usize;
            out.push(alphabet[next] as char);
        } else {
            out.push(ch);
        }
    }
    out
}

/// XOR `input` bytes against `key` repeated cyclically starting at `offset`.
pub fn xor_cyclic(input: &[u8], key: &[u8], offset: usize) -> Vec<u8> {
    if key.is_empty() {
        return input.to_vec();
    }
    input
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[(i + offset) % key.len()])
        .collect()
}

/// Sum of ASCII byte values (< 128) in `text`.
pub fn ascii_sum(text: &str) -> u32 {
    text.bytes().filter(|&b| b < 128).map(u32::from).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_and_permutation_round_trip() {
        let plain = r#"{"ver":"tok","a":1,"b":"hello:world"}"#;
        let shuf = permute_join(plain, ':', 65_914);
        let enc = substitute_92(&shuf, 4_000_000);
        let unsub = desubstitute_92(&enc, 4_000_000);
        assert_eq!(unpermute_join(&unsub, ':', 65_914), plain);
    }

    #[test]
    fn substitution_preserves_unicode_and_ascii_wire_format() {
        let text = "café 😀 e\u{301} 中文 : quotes '\"\\\n";
        for key in [0, 42, 4_000_000, u32::MAX] {
            let encoded = substitute_92(text, key);
            assert_eq!(encoded.len(), text.len());
            assert_eq!(desubstitute_92(&encoded, key), text);
            let shuffled = permute_join(text, ':', key);
            assert_eq!(
                unpermute_join(
                    &desubstitute_92(&substitute_92(&shuffled, key), key),
                    ':',
                    key
                ),
                text
            );
        }
        assert_eq!(substitute_92("abc", 0), "aR[");
        assert_eq!(substitute_92("", 42), "");
    }

    #[test]
    fn utf16_substitution_matches_javascript_for_bmp_characters() {
        for (plain, encoded) in [("aéb", "FéP"), ("a\u{301}z", "F\u{301}i")] {
            assert_eq!(substitute_92_utf16(plain, 4_538_946), encoded);
            assert_eq!(desubstitute_92_utf16(encoded, 4_538_946), plain);
        }
    }

    #[test]
    fn utf16_substitution_consumes_both_surrogates() {
        assert_eq!(substitute_92_utf16("a🙂b", 4_538_946), "F🙂Q");
        assert_eq!(desubstitute_92_utf16("F🙂Q", 4_538_946), "a🙂b");
    }

    #[test]
    fn utf16_and_byte_substitution_keep_distinct_contracts() {
        let plain = "a’b é🙂z";
        // Fixed outputs from JavaScript UTF-16 and the original byte API.
        assert_eq!(substitute_92_utf16(plain, 4_538_946), "F’Poé🙂}");
        assert_eq!(desubstitute_92_utf16("F’Poé🙂}", 4_538_946), plain);
        assert_eq!(substitute_92(plain, 4_538_946), "F’M6é🙂x");
        assert_eq!(desubstitute_92("F’M6é🙂x", 4_538_946), plain);
    }

    #[test]
    fn utf16_substitution_matches_the_byte_api_for_all_ascii() {
        let ascii: String = (0..=127).map(char::from).collect();
        for key in [0, 42, 4_538_946, u32::MAX] {
            assert_eq!(substitute_92_utf16(&ascii, key), substitute_92(&ascii, key));
            assert_eq!(
                desubstitute_92_utf16(&ascii, key),
                desubstitute_92(&ascii, key)
            );
            assert_eq!(substitute_92_utf16("", key), "");
            assert_eq!(desubstitute_92_utf16("", key), "");
        }
    }

    #[test]
    fn utf16_substitution_preserves_unicode_boundaries_and_roundtrips() {
        let plain = "\0a\u{7f}\u{80}\u{d7ff}\u{e000}\u{ffff}\u{10000}\u{10ffff}z'\"\\";
        for key in [0, 42, 4_538_946, u32::MAX] {
            let encoded = substitute_92_utf16(plain, key);
            assert_eq!(encoded.len(), plain.len());
            assert_eq!(desubstitute_92_utf16(&encoded, key), plain);
            assert_eq!(
                encoded
                    .chars()
                    .filter(|ch| !ch.is_ascii())
                    .collect::<String>(),
                plain
                    .chars()
                    .filter(|ch| !ch.is_ascii())
                    .collect::<String>(),
            );
        }
    }

    #[test]
    fn caesar_and_xor_round_trip() {
        let alpha = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let shifted = caesar_shift("MacIntel156", alpha, 8);
        assert_eq!(caesar_shift(&shifted, alpha, -8), "MacIntel156");
        let xored = xor_cyclic(b"hello", b"key", 1);
        assert_eq!(xor_cyclic(&xored, b"key", 1), b"hello");
    }
}
