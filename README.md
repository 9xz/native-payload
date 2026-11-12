# native-payload

Provider-agnostic Rust SDK for constructing browser telemetry payloads natively—no JS engine, no headless browser.

## Install

```toml
[dependencies]
native-payload = { git = "https://github.com/9xz/native-payload" }
```

## Quickstart

```rust
use native_payload::{
    biometrics::{MouseTrajectory, SessionClock, divisors_pair_string},
    cipher::{desubstitute_92, permute_join, substitute_92, unpermute_join},
    profile::{DesktopOs, DeviceProfile},
    template::{patch_json_fields, patch_json_raw_fields},
};

// 1. Deterministically sample a realistic desktop Chrome profile for a session
//    (baked-in empirical distributions—no external files, Node, or browser needed).
let profile = DeviceProfile::for_session("user-session-42");
let headers = profile.navigation_headers();
// Explicit presets/OS targeting also available:
// DeviceProfile::generate_for_os(42, DesktopOs::Windows, "156"), chrome_macos("156"), etc.
// 2. Generate coherent clock buckets and simulated input trajectories
let clock = SessionClock::new(1_794_499_443_877, 1_539);
let mouse = MouseTrajectory::generate(42, 1_260, 20);
let ajr = divisors_pair_string(clock.elapsed_ms);

// 3. Patch a JSON payload template in-place without reordering keys
let template = r#"{"ver":"old","swi":0,"pur":"https://old.example/"}"#;
let payload = patch_json_fields(
    template.to_owned(),
    &[("ver", "v3_token"), ("pur", "https://example.com/")],
).expect("valid string fields");
let payload = patch_json_raw_fields(payload, &[("swi", &profile.screen.width.to_string())])
    .expect("valid scalar field");

// 4. Permute and cipher
let wire = substitute_92(&permute_join(&payload, ':', 65_914), 4_000_000);
let plain = unpermute_join(&desubstitute_92(&wire, 4_000_000), ':', 65_914);
assert_eq!(plain, payload);
assert_eq!(ajr, "1,1539,3,513,9,171");
assert_eq!(mouse.samples.len(), 21);
assert_eq!(headers.len(), 12);
```

## Built-in fingerprint generation

`DeviceProfile` ships empirical desktop Chrome distributions (`Windows`, `macOS`, `Linux`)
distilled from `fingerprint-generator@2.1.90` directly inside the Rust crate—no Node runtime,
no external CLI, and no JSON pool files to manage:

- `DeviceProfile::for_session(session_id)`: hashes `session_id` with SHA-256 so the same session
  always receives the exact same OS, screen/window geometry, GPU vendor/renderer, CPU/RAM counts,
  Client Hints, and ordered HTTP headers across restarts.
- `DeviceProfile::generate(seed)`: deterministic sampling from a `u64` seed weighted by desktop OS share.
- `DeviceProfile::generate_for_os(seed, os, chrome_major)`: deterministic sampling constrained to
  `DesktopOs::Windows`, `DesktopOs::MacOs`, or `DesktopOs::Linux` and a specific Chrome major version.
- `profile.navigation_headers()` / `profile.sec_ch_ua()` / `profile.client_hints`: matching HTTP
  navigation headers in Chrome wire order and coherent `navigator.userAgentData` values (e.g. Apple
  Silicon `arm` vs Intel `x86` matched to the sampled Mac GPU).
- `DeviceProfile::from_capture_json(&value)`: load and validate a real-browser snapshot JSON when
  comparing against or replaying a specific captured machine.

## Modules

| Module | API |
| --- | --- |
| `profile` | `DeviceProfile::for_session`, `generate`, `generate_for_os`, `chrome_macos`, `chrome_windows`, `chrome_linux`, `from_capture_json`, `navigation_headers`, `sec_ch_ua`, `fingerprint_id`, `ua_ascii_sum`, `webgl_sha256_hex`, `DesktopOs`, `ClientHints` |
| `biometrics` | `SessionClock` (`hal`, `hz1`, `dd2`), `MouseTrajectory::generate`, `XorShift64`, `divisors_pair_string` |
| `template` | `patch_json_str`, `patch_json_fields`, `patch_json_raw`, `patch_json_raw_fields`, `parse_js_string_array`, `url_path_segment_from_end` |
| `cipher` | `step_lcg23`, `draw_lcg23`, `substitute_92`, `desubstitute_92`, `permute_join`, `unpermute_join`, `caesar_shift`, `xor_cyclic`, `ascii_sum` |

## Contracts and limits

- Presets are synthetic Chrome desktop profiles, not captured devices or proof of browser authenticity. Choose an OS explicitly; `Default` uses macOS. Load captures for device-specific values rather than randomly mixing fingerprint fields.
- Captures require a nonempty `ua` and object-valued `navigator`, `screen`, and `window`. Supported desktop OSes are macOS, Windows, and Linux; contradictory OS values and incorrectly typed fields are rejected. Optional fields inherit from the matching OS preset. All presets use UTC; provide both `timeZone` and `timezoneOffset` (minutes, as returned by `Date.getTimezoneOffset()`) for another timezone. `devicePixelRatio` can be supplied at the root or in `window`.
- JSON patchers return `Result<String, String>`. They patch existing **top-level** fields, preserving surrounding bytes and key order. Empty strings are valid replacements. Missing/duplicate target keys, malformed input, and incompatible value types are errors. Raw replacements must be JSON numbers, booleans, or `null`.
- `parse_js_string_array` returns `Result<Vec<String>, String>` and decodes literal Unicode and UTF-16 surrogate pairs. It extracts a string-only array literal, not arbitrary JavaScript expressions.
- Substitution preserves UTF-8 and advances its PRNG per byte. These reversible ciphers are protocol obfuscation, **not encryption**.
- Mouse paths are deterministic seeded minimum-jerk simulations with varying coordinates and timing. They are not recorded human input or guaranteed to pass behavioral checks.

## Checks

```sh
cargo test
```
