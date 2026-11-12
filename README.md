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
    profile::DeviceProfile,
    template::{patch_json_fields, patch_json_raw_fields},
};

// 1. Load a browser profile (built-in or from a captured snapshot JSON)
let profile = DeviceProfile::chrome_macos("156");

// 2. Generate coherent clock buckets and human input trajectories
let clock = SessionClock::new(1_794_499_443_877, 1_539);
let mouse = MouseTrajectory::generate(42, 1_260, 20);
let ajr = divisors_pair_string(clock.elapsed_ms);

// 3. Patch a JSON payload template in-place without reordering keys
let template = r#"{"ver":"old","swi":0,"pur":"https://old.example/"}"#;
let payload = patch_json_fields(
    template.to_owned(),
    &[("ver", "v3_token"), ("pur", "https://example.com/")],
);
let payload = patch_json_raw_fields(payload, &[("swi", &profile.screen.width.to_string())]);

// 4. Permute and cipher
let wire = substitute_92(&permute_join(&payload, ':', 65_914), 4_000_000);
let plain = unpermute_join(&desubstitute_92(&wire, 4_000_000), ':', 65_914);
assert_eq!(plain, payload);
assert_eq!(ajr, "1,1539,3,513,9,171");
assert_eq!(mouse.samples.len(), 21);
```

## Modules

| Module | API |
| --- | --- |
| `profile` | `DeviceProfile::chrome_macos`, `DeviceProfile::from_capture_json`, `ua_ascii_sum`, `webgl_sha256_hex` |
| `biometrics` | `SessionClock` (`hal`, `hz1`, `dd2`), `MouseTrajectory::generate`, `XorShift64`, `divisors_pair_string` |
| `template` | `patch_json_str`, `patch_json_fields`, `patch_json_raw`, `patch_json_raw_fields`, `parse_js_string_array`, `url_path_segment_from_end` |
| `cipher` | `step_lcg23`, `draw_lcg23`, `substitute_92`, `desubstitute_92`, `permute_join`, `unpermute_join`, `caesar_shift`, `xor_cyclic`, `ascii_sum` |
