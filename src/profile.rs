//! Built-in empirical desktop Chrome fingerprint generator, OS presets, and capture loader.

use std::fmt::Write as _;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::biometrics::XorShift64;
use crate::cipher::ascii_sum;
use crate::profile_data::{self, OsDistribution};

/// Screen geometry reported by `window.screen`.
#[derive(Debug, Clone, PartialEq)]
pub struct ScreenGeometry {
    pub width: u32,
    pub height: u32,
    pub avail_width: u32,
    pub avail_height: u32,
    pub color_depth: u32,
    pub pixel_depth: u32,
    pub device_pixel_ratio: f64,
}

/// Window viewport and outer frame dimensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowGeometry {
    pub inner_width: u32,
    pub inner_height: u32,
    pub outer_width: u32,
    pub outer_height: u32,
}

/// WebGL unmasked vendor and renderer strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebGlInfo {
    pub vendor: String,
    pub renderer: String,
}

/// Supported desktop operating systems for Chrome fingerprint generation and presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopOs {
    MacOs,
    Windows,
    Linux,
}

/// High-entropy User-Agent Client Hints (`navigator.userAgentData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHints {
    pub architecture: String,
    pub bitness: String,
    pub platform_version: String,
    pub ua_full_version: String,
}

/// Normalized browser device profile usable across anti-bot payload builders.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceProfile {
    pub user_agent: String,
    pub chrome_major: String,
    pub platform: String,
    pub os_platform: String,
    pub language: String,
    pub languages: Vec<String>,
    pub timezone: String,
    pub timezone_offset_min: i32,
    pub hardware_concurrency: u32,
    pub device_memory: u32,
    pub plugins_len: u32,
    pub product: String,
    pub product_sub: String,
    pub screen: ScreenGeometry,
    pub window: WindowGeometry,
    pub webgl: WebGlInfo,
    pub client_hints: ClientHints,
    pub raw: Option<Value>,
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self::chrome_macos("156")
    }
}

impl DeviceProfile {
    /// Deterministically sample a realistic desktop Chrome profile for `session_id`.
    ///
    /// Hashes `session_id` with SHA-256 so the same session ID always receives the
    /// exact same coherent OS, screen/window geometry, GPU, CPU/RAM counts, and
    /// Client Hints without external files or runtime state.
    pub fn for_session(session_id: &str) -> Self {
        let digest = Sha256::digest(session_id.as_bytes());
        let seed = u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ]);
        Self::generate(seed)
    }

    /// Deterministically sample a desktop Chrome `"156"` profile from `seed`,
    /// weighted by empirical desktop OS share (Windows, macOS, Linux).
    pub fn generate(seed: u64) -> Self {
        let mut rng = XorShift64::new(seed);
        let &(os, _) = pick_weighted(&mut rng, profile_data::OS_WEIGHTS, |entry| entry.1);
        Self::generate_from_rng(&mut rng, os, "156")
    }

    /// Deterministically sample a desktop Chrome profile constrained to `os` and `chrome_major`.
    pub fn generate_for_os(seed: u64, os: DesktopOs, chrome_major: &str) -> Self {
        let mut rng = XorShift64::new(seed);
        Self::generate_from_rng(&mut rng, os, chrome_major)
    }

    fn generate_from_rng(rng: &mut XorShift64, os: DesktopOs, chrome_major: &str) -> Self {
        let (dist, user_agent, platform, os_platform) = match os {
            DesktopOs::MacOs => (
                &profile_data::MACOS,
                format!(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_major}.0.0.0 Safari/537.36"
                ),
                "MacIntel",
                "macOS",
            ),
            DesktopOs::Windows => (
                &profile_data::WINDOWS,
                format!(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_major}.0.0.0 Safari/537.36"
                ),
                "Win32",
                "Windows",
            ),
            DesktopOs::Linux => (
                &profile_data::LINUX,
                format!(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_major}.0.0.0 Safari/537.36"
                ),
                "Linux x86_64",
                "Linux",
            ),
        };
        Self::sample_distribution(
            rng,
            dist,
            os,
            chrome_major,
            user_agent,
            platform,
            os_platform,
        )
    }

    fn sample_distribution(
        rng: &mut XorShift64,
        dist: &OsDistribution,
        os: DesktopOs,
        chrome_major: &str,
        user_agent: String,
        platform: &str,
        os_platform: &str,
    ) -> Self {
        let scr = pick_weighted(rng, dist.screens, |s| s.weight);
        let &(vendor, renderer, _) = pick_weighted(rng, dist.gpus, |g| g.2);
        let &(cores, _) = pick_weighted(rng, dist.cores, |c| c.1);
        let &(memory, _) = pick_weighted(rng, dist.memory, |m| m.1);
        let &(plat_ver, _) = pick_weighted(rng, dist.platform_versions, |p| p.1);
        let &(build_suffix, _) = pick_weighted(rng, dist.chrome_builds, |b| b.1);
        let architecture = infer_architecture(os, vendor, renderer);

        Self {
            user_agent,
            chrome_major: chrome_major.to_owned(),
            platform: platform.to_owned(),
            os_platform: os_platform.to_owned(),
            language: "en-US".to_owned(),
            languages: vec!["en-US".to_owned(), "en".to_owned()],
            timezone: "UTC".to_owned(),
            timezone_offset_min: 0,
            hardware_concurrency: cores,
            device_memory: memory,
            plugins_len: 5,
            product: "Gecko".to_owned(),
            product_sub: "20030107".to_owned(),
            screen: ScreenGeometry {
                width: scr.width,
                height: scr.height,
                avail_width: scr.avail_width,
                avail_height: scr.avail_height,
                color_depth: scr.color_depth,
                pixel_depth: scr.color_depth,
                device_pixel_ratio: scr.dpr,
            },
            window: WindowGeometry {
                inner_width: scr.inner_width,
                inner_height: scr.inner_height,
                outer_width: scr.outer_width,
                outer_height: scr.outer_height,
            },
            webgl: WebGlInfo {
                vendor: vendor.to_owned(),
                renderer: renderer.to_owned(),
            },
            client_hints: ClientHints {
                architecture: architecture.to_owned(),
                bitness: "64".to_owned(),
                platform_version: plat_ver.to_owned(),
                ua_full_version: format!("{chrome_major}.{build_suffix}"),
            },
            raw: None,
        }
    }

    /// Standard desktop Chrome on macOS Apple Silicon profile.
    pub fn chrome_macos(major: &str) -> Self {
        let user_agent = format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        );
        Self {
            user_agent,
            chrome_major: major.to_owned(),
            platform: "MacIntel".to_owned(),
            os_platform: "macOS".to_owned(),
            language: "en-US".to_owned(),
            languages: vec!["en-US".to_owned(), "en".to_owned()],
            timezone: "UTC".to_owned(),
            timezone_offset_min: 0,
            hardware_concurrency: 16,
            device_memory: 8,
            plugins_len: 5,
            product: "Gecko".to_owned(),
            product_sub: "20030107".to_owned(),
            screen: ScreenGeometry {
                width: 1800,
                height: 1169,
                avail_width: 1800,
                avail_height: 1080,
                color_depth: 30,
                pixel_depth: 30,
                device_pixel_ratio: 2.0,
            },
            window: WindowGeometry {
                inner_width: 682,
                inner_height: 817,
                outer_width: 1370,
                outer_height: 943,
            },
            webgl: WebGlInfo {
                vendor: "Google Inc. (Apple)".to_owned(),
                renderer: "ANGLE (Apple, ANGLE Metal Renderer: Apple M4 Max, Unspecified Version)"
                    .to_owned(),
            },
            client_hints: ClientHints {
                architecture: "arm".to_owned(),
                bitness: "64".to_owned(),
                platform_version: "26.6.2".to_owned(),
                ua_full_version: format!("{major}.0.8078.80"),
            },
            raw: None,
        }
    }

    /// Standard desktop Chrome on 64-bit Windows 10/11 profile.
    pub fn chrome_windows(major: &str) -> Self {
        let user_agent = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        );
        Self {
            user_agent,
            chrome_major: major.to_owned(),
            platform: "Win32".to_owned(),
            os_platform: "Windows".to_owned(),
            language: "en-US".to_owned(),
            languages: vec!["en-US".to_owned(), "en".to_owned()],
            timezone: "UTC".to_owned(),
            timezone_offset_min: 0,
            hardware_concurrency: 8,
            device_memory: 8,
            plugins_len: 5,
            product: "Gecko".to_owned(),
            product_sub: "20030107".to_owned(),
            screen: ScreenGeometry {
                width: 1920,
                height: 1080,
                avail_width: 1920,
                avail_height: 1040,
                color_depth: 24,
                pixel_depth: 24,
                device_pixel_ratio: 1.0,
            },
            window: WindowGeometry {
                inner_width: 1366,
                inner_height: 768,
                outer_width: 1382,
                outer_height: 856,
            },
            webgl: WebGlInfo {
                vendor: "Google Inc. (NVIDIA)".to_owned(),
                renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"
                    .to_owned(),
            },
            client_hints: ClientHints {
                architecture: "x86".to_owned(),
                bitness: "64".to_owned(),
                platform_version: "19.0.0".to_owned(),
                ua_full_version: format!("{major}.0.8078.80"),
            },
            raw: None,
        }
    }

    /// Standard desktop Chrome on x86_64 Linux profile.
    pub fn chrome_linux(major: &str) -> Self {
        let user_agent = format!(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        );
        Self {
            user_agent,
            chrome_major: major.to_owned(),
            platform: "Linux x86_64".to_owned(),
            os_platform: "Linux".to_owned(),
            language: "en-US".to_owned(),
            languages: vec!["en-US".to_owned(), "en".to_owned()],
            timezone: "UTC".to_owned(),
            timezone_offset_min: 0,
            hardware_concurrency: 12,
            device_memory: 8,
            plugins_len: 5,
            product: "Gecko".to_owned(),
            product_sub: "20030107".to_owned(),
            screen: ScreenGeometry {
                width: 2560,
                height: 1440,
                avail_width: 2560,
                avail_height: 1413,
                color_depth: 24,
                pixel_depth: 24,
                device_pixel_ratio: 1.0,
            },
            window: WindowGeometry {
                inner_width: 1600,
                inner_height: 900,
                outer_width: 1600,
                outer_height: 985,
            },
            webgl: WebGlInfo {
                vendor: "Google Inc. (Mesa)".to_owned(),
                renderer: "ANGLE (Mesa, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)"
                    .to_owned(),
            },
            client_hints: ClientHints {
                architecture: "x86".to_owned(),
                bitness: "64".to_owned(),
                platform_version: String::new(),
                ua_full_version: format!("{major}.0.8078.79"),
            },
            raw: None,
        }
    }

    /// Parse a recorded browser environment snapshot JSON.
    ///
    /// Missing optional fields are filled from the matching desktop OS preset (`macOS`, `Windows`,
    /// or `Linux`) derived from `ua` and `navigator.platform`. If `timeZone` differs from `UTC`,
    /// an explicit numeric `timezoneOffset` is required, and a non-zero `timezoneOffset` may not
    /// be paired with `UTC`.
    pub fn from_capture_json(value: &Value) -> Result<Self, String> {
        let root = value
            .as_object()
            .ok_or_else(|| "snapshot must be a JSON object".to_owned())?;

        let ua = root
            .get("ua")
            .ok_or_else(|| "snapshot is missing `ua`".to_owned())
            .and_then(|v| parse_str(v, "ua"))?;
        let nav = parse_obj(value, "navigator")?;
        let scr = parse_obj(value, "screen")?;
        let win = parse_obj(value, "window")?;

        let ua_major = extract_chrome_major(&ua)
            .ok_or_else(|| "`ua` must identify a supported desktop Chrome version".to_owned())?;
        let chrome_major = match root.get("chromeVersion") {
            Some(v) => {
                let major = parse_str(v, "chromeVersion")?;
                if major != ua_major {
                    return Err("`chromeVersion` conflicts with the version in `ua`".to_owned());
                }
                major
            }
            None => ua_major,
        };

        let supplied_platform = nav
            .get("platform")
            .map(|v| parse_str(v, "navigator.platform"))
            .transpose()?;
        let os = detect_os(&ua, supplied_platform.as_deref())?;

        let mut base = match os {
            DesktopOs::MacOs => Self::chrome_macos(&chrome_major),
            DesktopOs::Windows => Self::chrome_windows(&chrome_major),
            DesktopOs::Linux => Self::chrome_linux(&chrome_major),
        };
        base.user_agent = ua;
        if let Some(p) = supplied_platform {
            base.platform = p;
        }

        let language = nav
            .get("language")
            .map(|v| parse_str(v, "navigator.language"))
            .transpose()?;
        let languages = match nav.get("languages") {
            None => None,
            Some(v) => {
                let arr = v
                    .as_array()
                    .ok_or_else(|| "`navigator.languages` must be an array".to_owned())?;
                if arr.is_empty() {
                    return Err("`navigator.languages` must not be empty".to_owned());
                }
                Some(
                    arr.iter()
                        .map(|item| parse_str(item, "navigator.languages[]"))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
        };
        match (language, languages) {
            (Some(lang), Some(langs)) => {
                if langs[0] != lang {
                    return Err(format!(
                        "`navigator.language` (`{lang}`) conflicts with `navigator.languages[0]` (`{}`)",
                        langs[0]
                    ));
                }
                base.language = lang;
                base.languages = langs;
            }
            (Some(lang), None) => {
                base.languages = vec![lang.clone()];
                base.language = lang;
            }
            (None, Some(langs)) => {
                base.language = langs[0].clone();
                base.languages = langs;
            }
            (None, None) => {}
        }

        if let Some(prod) = nav.get("product") {
            base.product = parse_str(prod, "navigator.product")?;
        }
        if let Some(prod_sub) = nav.get("productSub") {
            base.product_sub = parse_str(prod_sub, "navigator.productSub")?;
        }
        if let Some(hc) = nav.get("hardwareConcurrency") {
            let n = parse_u32(hc, "navigator.hardwareConcurrency")?;
            if n == 0 {
                return Err("`navigator.hardwareConcurrency` must be > 0".to_owned());
            }
            base.hardware_concurrency = n;
        }
        if let Some(dm) = nav.get("deviceMemory") {
            let n = parse_u32(dm, "navigator.deviceMemory")?;
            if n == 0 {
                return Err("`navigator.deviceMemory` must be > 0".to_owned());
            }
            base.device_memory = n;
        }

        let plugins_arr_len = match nav.get("plugins") {
            None => None,
            Some(v) => {
                let arr = v
                    .as_array()
                    .ok_or_else(|| "`navigator.plugins` must be an array".to_owned())?;
                Some(
                    u32::try_from(arr.len())
                        .map_err(|_| "`navigator.plugins` length overflows u32".to_owned())?,
                )
            }
        };
        let plugins_length = nav
            .get("pluginsLength")
            .map(|v| parse_u32(v, "navigator.pluginsLength"))
            .transpose()?;
        match (plugins_arr_len, plugins_length) {
            (Some(a), Some(b)) if a != b => {
                return Err(
                    "conflicting `navigator.plugins` and `navigator.pluginsLength`".to_owned(),
                );
            }
            (Some(n), _) | (None, Some(n)) => base.plugins_len = n,
            (None, None) => {}
        }

        let tz = root
            .get("timeZone")
            .map(|v| parse_str(v, "timeZone"))
            .transpose()?;
        let tz_offset = match root.get("timezoneOffset") {
            None => None,
            Some(v) => {
                let n = v
                    .as_i64()
                    .ok_or_else(|| "`timezoneOffset` must be an integer".to_owned())?;
                let off =
                    i32::try_from(n).map_err(|_| format!("`timezoneOffset` overflows i32: {n}"))?;
                if !(-840..=840).contains(&off) {
                    return Err(format!(
                        "`timezoneOffset` {off} is out of valid range (-840..=840)"
                    ));
                }
                Some(off)
            }
        };
        if let Some(tz_name) = tz {
            base.timezone = tz_name;
        }
        let is_utc = matches!(
            base.timezone.as_str(),
            "UTC" | "Etc/UTC" | "GMT" | "Etc/GMT"
        );
        match (is_utc, tz_offset) {
            (true, Some(off)) if off != 0 => {
                return Err(format!(
                    "UTC `timeZone` (`{}`) contradicts non-zero `timezoneOffset` {off}",
                    base.timezone
                ));
            }
            (false, None) => {
                return Err(format!(
                    "`timeZone` `{}` requires explicit `timezoneOffset`",
                    base.timezone
                ));
            }
            (_, Some(off)) => base.timezone_offset_min = off,
            (true, None) => {}
        }

        if let Some(w) = scr.get("width") {
            base.screen.width = parse_u32(w, "screen.width")?;
        }
        if let Some(h) = scr.get("height") {
            base.screen.height = parse_u32(h, "screen.height")?;
        }
        if let Some(aw) = scr.get("availWidth") {
            base.screen.avail_width = parse_u32(aw, "screen.availWidth")?;
        }
        if let Some(ah) = scr.get("availHeight") {
            base.screen.avail_height = parse_u32(ah, "screen.availHeight")?;
        }
        if let Some(cd) = scr.get("colorDepth") {
            base.screen.color_depth = parse_u32(cd, "screen.colorDepth")?;
        }
        if let Some(pd) = scr.get("pixelDepth") {
            base.screen.pixel_depth = parse_u32(pd, "screen.pixelDepth")?;
        }

        let root_dpr = root
            .get("devicePixelRatio")
            .map(|v| parse_dpr(v, "devicePixelRatio"))
            .transpose()?;
        let win_dpr = win
            .get("devicePixelRatio")
            .map(|v| parse_dpr(v, "window.devicePixelRatio"))
            .transpose()?;
        match (root_dpr, win_dpr) {
            (Some(a), Some(b)) if (a - b).abs() > f64::EPSILON => {
                return Err(
                    "conflicting `devicePixelRatio` and `window.devicePixelRatio`".to_owned(),
                );
            }
            (Some(dpr), _) | (None, Some(dpr)) => base.screen.device_pixel_ratio = dpr,
            (None, None) => {}
        }

        if let Some(iw) = win.get("innerWidth") {
            base.window.inner_width = parse_u32(iw, "window.innerWidth")?;
        }
        if let Some(ih) = win.get("innerHeight") {
            base.window.inner_height = parse_u32(ih, "window.innerHeight")?;
        }
        if let Some(ow) = win.get("outerWidth") {
            base.window.outer_width = parse_u32(ow, "window.outerWidth")?;
        }
        if let Some(oh) = win.get("outerHeight") {
            base.window.outer_height = parse_u32(oh, "window.outerHeight")?;
        }

        if let Some(wgl_val) = root.get("webgl") {
            let wgl = wgl_val
                .as_object()
                .ok_or_else(|| "`webgl` must be a JSON object".to_owned())?;
            if let Some(v) = wgl.get("vendor") {
                base.webgl.vendor = parse_str(v, "webgl.vendor")?;
            }
            if let Some(r) = wgl.get("renderer") {
                base.webgl.renderer = parse_str(r, "webgl.renderer")?;
            }
        }
        base.client_hints.architecture =
            infer_architecture(os, &base.webgl.vendor, &base.webgl.renderer).to_owned();
        if let Some(uad_val) = nav.get("userAgentData")
            && !uad_val.is_null()
        {
            let uad = uad_val
                .as_object()
                .ok_or_else(|| "`navigator.userAgentData` must be a JSON object".to_owned())?;
            if let Some(mob) = uad.get("mobile") {
                let is_mob = mob.as_bool().ok_or_else(|| {
                    "`navigator.userAgentData.mobile` must be a boolean".to_owned()
                })?;
                if is_mob {
                    return Err("`navigator.userAgentData.mobile` must be false".to_owned());
                }
            }
            if let Some(plat) = uad.get("platform") {
                let p = parse_str(plat, "navigator.userAgentData.platform")?;
                if p != base.os_platform {
                    return Err(format!(
                        "`navigator.userAgentData.platform` (`{p}`) conflicts with `{}`",
                        base.os_platform
                    ));
                }
            }
            if let Some(arch) = uad.get("architecture") {
                base.client_hints.architecture =
                    parse_str(arch, "navigator.userAgentData.architecture")?;
            }
            if let Some(bits) = uad.get("bitness") {
                base.client_hints.bitness = parse_str(bits, "navigator.userAgentData.bitness")?;
            }
            if let Some(pv) = uad.get("platformVersion") {
                let s = pv.as_str().ok_or_else(|| {
                    "`navigator.userAgentData.platformVersion` must be a string".to_owned()
                })?;
                base.client_hints.platform_version = s.to_owned();
            }
            if let Some(fv) = uad.get("uaFullVersion") {
                let s = parse_str(fv, "navigator.userAgentData.uaFullVersion")?;
                if s.split('.').next() != Some(base.chrome_major.as_str()) {
                    return Err(format!(
                        "`navigator.userAgentData.uaFullVersion` (`{s}`) conflicts with Chrome major `{}`",
                        base.chrome_major
                    ));
                }
                base.client_hints.ua_full_version = s;
            }
        }

        base.raw = Some(value.clone());
        Ok(base)
    }

    /// Structured `sec-ch-ua` Client Hint header value matching `chrome_major`.
    pub fn sec_ch_ua(&self) -> String {
        let m = &self.chrome_major;
        format!("\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"{m}\", \"Google Chrome\";v=\"{m}\"")
    }

    /// `accept-language` header value derived from `self.languages`.
    pub fn accept_language(&self) -> String {
        let mut out = String::new();
        for (idx, lang) in self.languages.iter().enumerate() {
            if idx == 0 {
                out.push_str(lang);
            } else {
                let q = (10usize.saturating_sub(idx)).max(1);
                if q == 10 {
                    let _ = write!(out, ",{lang}");
                } else {
                    let _ = write!(out, ",{lang};q=0.{q}");
                }
            }
        }
        if out.is_empty() {
            out.push_str(&self.language);
        }
        out
    }

    /// Matching Chrome navigation HTTP headers in standard HTTP/2 wire order.
    pub fn navigation_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            ("sec-ch-ua", self.sec_ch_ua()),
            ("sec-ch-ua-mobile", "?0".to_owned()),
            ("sec-ch-ua-platform", format!("\"{}\"", self.os_platform)),
            ("upgrade-insecure-requests", "1".to_owned()),
            ("user-agent", self.user_agent.clone()),
            (
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_owned(),
            ),
            ("sec-fetch-site", "none".to_owned()),
            ("sec-fetch-mode", "navigate".to_owned()),
            ("sec-fetch-user", "?1".to_owned()),
            ("sec-fetch-dest", "document".to_owned()),
            ("accept-encoding", "gzip, deflate, br, zstd".to_owned()),
            ("accept-language", self.accept_language()),
        ]
    }

    /// Deterministic SHA-256 hex digest of normalized profile fields (excluding `raw`).
    pub fn fingerprint_id(&self) -> String {
        let mut hasher = Sha256::new();
        let push_str = |h: &mut Sha256, s: &str| {
            h.update((s.len() as u64).to_le_bytes());
            h.update(s.as_bytes());
        };
        push_str(&mut hasher, &self.user_agent);
        push_str(&mut hasher, &self.chrome_major);
        push_str(&mut hasher, &self.platform);
        push_str(&mut hasher, &self.os_platform);
        push_str(&mut hasher, &self.language);
        hasher.update((self.languages.len() as u64).to_le_bytes());
        for lang in &self.languages {
            push_str(&mut hasher, lang);
        }
        push_str(&mut hasher, &self.timezone);
        hasher.update(self.timezone_offset_min.to_le_bytes());
        hasher.update(self.hardware_concurrency.to_le_bytes());
        hasher.update(self.device_memory.to_le_bytes());
        hasher.update(self.plugins_len.to_le_bytes());
        push_str(&mut hasher, &self.product);
        push_str(&mut hasher, &self.product_sub);
        for n in [
            self.screen.width,
            self.screen.height,
            self.screen.avail_width,
            self.screen.avail_height,
            self.screen.color_depth,
            self.screen.pixel_depth,
            self.window.inner_width,
            self.window.inner_height,
            self.window.outer_width,
            self.window.outer_height,
        ] {
            hasher.update(n.to_le_bytes());
        }
        let dpr = if self.screen.device_pixel_ratio == 0.0 {
            0.0
        } else {
            self.screen.device_pixel_ratio
        };
        hasher.update(dpr.to_bits().to_le_bytes());
        push_str(&mut hasher, &self.webgl.vendor);
        push_str(&mut hasher, &self.webgl.renderer);
        push_str(&mut hasher, &self.client_hints.architecture);
        push_str(&mut hasher, &self.client_hints.bitness);
        push_str(&mut hasher, &self.client_hints.platform_version);
        push_str(&mut hasher, &self.client_hints.ua_full_version);
        let digest = hasher.finalize();
        let mut out = String::with_capacity(64);
        for byte in digest {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// ASCII byte sum of `user_agent` (`ucs` in v3 sensors).
    pub fn ua_ascii_sum(&self) -> u32 {
        ascii_sum(&self.user_agent)
    }

    /// Lowercase hex SHA-256 of the WebGL vendor + renderer pair.
    pub fn webgl_sha256_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.webgl.vendor.as_bytes());
        hasher.update(b"|");
        hasher.update(self.webgl.renderer.as_bytes());
        let digest = hasher.finalize();
        let mut out = String::with_capacity(64);
        for byte in digest {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

fn pick_weighted<'a, T>(
    rng: &mut XorShift64,
    items: &'a [T],
    weight_of: impl Fn(&T) -> u32,
) -> &'a T {
    let total: u64 = items.iter().map(|item| u64::from(weight_of(item))).sum();
    let mut target = rng.next_u64() % total;
    for item in items {
        let w = u64::from(weight_of(item));
        if target < w {
            return item;
        }
        target -= w;
    }
    &items[items.len() - 1]
}

fn infer_architecture(os: DesktopOs, vendor: &str, renderer: &str) -> &'static str {
    match os {
        DesktopOs::MacOs if vendor.contains("(Apple)") || renderer.contains("Apple M") => "arm",
        _ => "x86",
    }
}

fn extract_chrome_major(ua: &str) -> Option<String> {
    let rest = ua.split("Chrome/").nth(1)?;
    let major = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    (!major.is_empty()).then(|| major.to_owned())
}

fn detect_os(ua: &str, platform: Option<&str>) -> Result<DesktopOs, String> {
    let lower = ua.to_ascii_lowercase();
    if ["android", "iphone", "ipad", "ipod", "cros"]
        .iter()
        .any(|t| lower.contains(t))
    {
        return Err(format!("unsupported non-desktop OS in `ua`: `{ua}`"));
    }
    let ua_os = match (
        lower.contains("macintosh") || lower.contains("mac os x"),
        lower.contains("windows nt") || lower.contains("win64") || lower.contains("win32"),
        lower.contains("linux"),
    ) {
        (true, false, false) => Some(DesktopOs::MacOs),
        (false, true, false) => Some(DesktopOs::Windows),
        (false, false, true) => Some(DesktopOs::Linux),
        (false, false, false) => None,
        _ => return Err(format!("contradictory OS tokens in `ua`: `{ua}`")),
    };
    let plat_os = match platform {
        None => None,
        Some(p) => {
            let pl = p.to_ascii_lowercase();
            if ["iphone", "ipad", "ipod", "arm", "android"]
                .iter()
                .any(|t| pl.contains(t))
            {
                return Err(format!("unsupported `navigator.platform`: `{p}`"));
            }
            if pl.starts_with("mac") {
                Some(DesktopOs::MacOs)
            } else if pl.starts_with("win") {
                Some(DesktopOs::Windows)
            } else if pl.starts_with("linux") {
                Some(DesktopOs::Linux)
            } else {
                return Err(format!("unsupported `navigator.platform`: `{p}`"));
            }
        }
    };
    match (ua_os, plat_os) {
        (Some(u), Some(p)) if u == p => Ok(u),
        (Some(_), Some(_)) => Err(format!(
            "contradictory `ua` (`{ua}`) and `navigator.platform` (`{}`)",
            platform.unwrap_or_default()
        )),
        (Some(u), None) => Ok(u),
        (None, Some(p)) => Ok(p),
        (None, None) => Err(
            "cannot determine supported desktop OS from `ua` or `navigator.platform`".to_owned(),
        ),
    }
}

fn parse_obj<'a>(root: &'a Value, key: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    root.get(key)
        .ok_or_else(|| format!("snapshot is missing `{key}`"))?
        .as_object()
        .ok_or_else(|| format!("`{key}` must be a JSON object"))
}

fn parse_str(val: &Value, label: &str) -> Result<String, String> {
    let s = val
        .as_str()
        .ok_or_else(|| format!("`{label}` must be a string"))?;
    if s.trim().is_empty() {
        return Err(format!("`{label}` must not be empty"));
    }
    Ok(s.to_owned())
}

fn parse_u32(val: &Value, label: &str) -> Result<u32, String> {
    let n = val
        .as_u64()
        .ok_or_else(|| format!("`{label}` must be a non-negative integer"))?;
    u32::try_from(n).map_err(|_| format!("`{label}` overflows u32: {n}"))
}

fn parse_dpr(val: &Value, label: &str) -> Result<f64, String> {
    let dpr = val
        .as_f64()
        .ok_or_else(|| format!("`{label}` must be a finite positive number"))?;
    if !dpr.is_finite() || dpr <= 0.0 {
        return Err(format!("`{label}` must be a finite positive number"));
    }
    Ok(dpr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn presets_are_distinct_and_coherent() {
        let mac = DeviceProfile::chrome_macos("156");
        let win = DeviceProfile::chrome_windows("156");
        let lin = DeviceProfile::chrome_linux("156");

        assert_eq!(
            (&mac.platform[..], &mac.os_platform[..]),
            ("MacIntel", "macOS")
        );
        assert_eq!(
            (&win.platform[..], &win.os_platform[..]),
            ("Win32", "Windows")
        );
        assert_eq!(
            (&lin.platform[..], &lin.os_platform[..]),
            ("Linux x86_64", "Linux")
        );
        assert_ne!(mac.webgl_sha256_hex(), win.webgl_sha256_hex());
        assert_ne!(win.webgl_sha256_hex(), lin.webgl_sha256_hex());
    }

    #[test]
    fn builtin_generator_is_deterministic_diverse_and_hardware_coherent() {
        let s1 = DeviceProfile::for_session("session-alpha");
        let s2 = DeviceProfile::for_session("session-alpha");
        assert_eq!(s1, s2);
        assert_eq!(s1.fingerprint_id(), s2.fingerprint_id());

        let mut ids = std::collections::BTreeSet::new();
        let mut os_seen = std::collections::BTreeSet::new();
        for idx in 0..300u64 {
            let p = DeviceProfile::for_session(&format!("sess-{idx}"));
            ids.insert(p.fingerprint_id());
            os_seen.insert(p.os_platform.clone());

            assert!(p.screen.width >= 1024 && p.screen.height >= 640);
            assert!(p.screen.avail_width <= p.screen.width);
            assert!(p.screen.avail_height <= p.screen.height);
            assert!(p.window.inner_width > 0 && p.window.inner_width <= p.window.outer_width);
            assert!(p.window.inner_height > 0 && p.window.inner_height <= p.window.outer_height);
            assert!(!p.webgl.renderer.contains("SwiftShader"));
            assert!(!p.webgl.renderer.contains("Adreno"));
            assert!(!p.webgl.renderer.contains("Mali-"));

            if p.os_platform == "macOS" {
                let expected_arch = if p.webgl.vendor.contains("(Apple)") {
                    "arm"
                } else {
                    "x86"
                };
                assert_eq!(p.client_hints.architecture, expected_arch);
            } else {
                assert_eq!(p.client_hints.architecture, "x86");
            }

            let hdrs = p.navigation_headers();
            assert_eq!(hdrs.len(), 12);
            assert_eq!(hdrs[0].0, "sec-ch-ua");
            assert_eq!(
                hdrs[2],
                ("sec-ch-ua-platform", format!("\"{}\"", p.os_platform))
            );
            assert_eq!(hdrs[4], ("user-agent", p.user_agent.clone()));
            assert_eq!(hdrs[11], ("accept-language", "en-US,en;q=0.9".to_owned()));
        }

        assert!(
            ids.len() > 280,
            "expected high diversity, got {}",
            ids.len()
        );
        assert_eq!(
            os_seen.len(),
            3,
            "expected Windows, macOS, and Linux coverage"
        );

        let custom = DeviceProfile::generate_for_os(99, DesktopOs::Linux, "157");
        assert_eq!(custom.os_platform, "Linux");
        assert_eq!(custom.chrome_major, "157");
        assert!(custom.user_agent.contains("Chrome/157.0.0.0"));
        assert!(custom.client_hints.ua_full_version.starts_with("157."));
        assert!(custom.sec_ch_ua().contains("\"157\""));
    }

    #[test]
    fn parses_capture_snapshot_and_derives_os_defaults_without_macos_leakage() {
        let win_raw = json!({
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/155.0.0.0 Safari/537.36",
            "devicePixelRatio": 1.25,
            "timeZone": "America/New_York",
            "timezoneOffset": 300,
            "navigator": {
                "platform": "Win32",
                "language": "de-DE",
                "hardwareConcurrency": 16,
                "deviceMemory": 16,
                "plugins": ["PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer"],
                "product": "Gecko",
                "productSub": "20030107"
            },
            "screen": {"width": 2560, "height": 1440},
            "window": {"innerWidth": 1920, "innerHeight": 1000}
        });
        let win = DeviceProfile::from_capture_json(&win_raw).expect("valid windows capture");
        assert_eq!(win.chrome_major, "155");
        assert_eq!(win.os_platform, "Windows");
        assert_eq!(win.language, "de-DE");
        assert_eq!(win.languages, vec!["de-DE"]);
        assert_eq!(win.timezone, "America/New_York");
        assert_eq!(win.timezone_offset_min, 300);
        assert_eq!(win.plugins_len, 3);
        assert_eq!(win.screen.device_pixel_ratio, 1.25);
        assert_eq!(win.webgl, DeviceProfile::chrome_windows("155").webgl);

        let lin_raw = json!({
            "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/154.0.0.0 Safari/537.36",
            "navigator": {
                "languages": ["fr-FR", "fr"],
                "pluginsLength": 2,
                "productSub": "20100101"
            },
            "screen": {"width": 1920, "height": 1080},
            "window": {"innerWidth": 1280, "innerHeight": 720, "devicePixelRatio": 1.5},
            "webgl": {"vendor": "Google Inc. (AMD)", "renderer": "ANGLE (AMD, Radeon RX 6800, OpenGL 4.6)"}
        });
        let lin = DeviceProfile::from_capture_json(&lin_raw).expect("valid linux capture");
        assert_eq!(lin.os_platform, "Linux");
        assert_eq!(lin.language, "fr-FR");
        assert_eq!(lin.plugins_len, 2);
        assert_eq!(lin.product_sub, "20100101");
        assert_eq!(lin.screen.device_pixel_ratio, 1.5);
        assert_eq!(lin.webgl.vendor, "Google Inc. (AMD)");
        assert_eq!(lin.ua_ascii_sum(), ascii_sum(&lin.user_agent));
    }

    #[test]
    fn rejects_invalid_captures() {
        let valid_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/156.0.0.0";
        for bad in [
            json!(null),
            json!({"ua": null, "navigator": {}, "screen": {}, "window": {}}),
            json!({"ua": "", "navigator": {}, "screen": {}, "window": {}}),
            json!({"ua": valid_ua, "navigator": null, "screen": {}, "window": {}}),
            json!({"ua": valid_ua, "navigator": {}, "screen": null, "window": {}}),
            json!({"ua": valid_ua, "navigator": {}, "screen": {}, "window": []}),
            json!({
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/156.0.0.0",
                "navigator": {"platform": "MacIntel"},
                "screen": {},
                "window": {}
            }),
            json!({
                "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
                "navigator": {"platform": "iPhone"},
                "screen": {},
                "window": {}
            }),
            json!({"ua": "Mozilla/5.0 Chrome/156.0.0.0", "navigator": {}, "screen": {}, "window": {}}),
            json!({"ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15", "navigator": {}, "screen": {}, "window": {}}),
            json!({"ua": valid_ua, "chromeVersion": "155", "navigator": {}, "screen": {}, "window": {}}),
            json!({
                "ua": valid_ua,
                "navigator": {"hardwareConcurrency": (u32::MAX as u64) + 1},
                "screen": {},
                "window": {}
            }),
            json!({
                "ua": valid_ua,
                "devicePixelRatio": 0.0,
                "navigator": {},
                "screen": {},
                "window": {}
            }),
            json!({
                "ua": valid_ua,
                "timeZone": "Europe/Berlin",
                "navigator": {},
                "screen": {},
                "window": {}
            }),
            json!({
                "ua": valid_ua,
                "timezoneOffset": 300,
                "navigator": {},
                "screen": {},
                "window": {}
            }),
            json!({
                "ua": valid_ua,
                "navigator": {"language": "de-DE", "languages": ["fr-FR", "fr"]},
                "screen": {},
                "window": {}
            }),
        ] {
            assert!(
                DeviceProfile::from_capture_json(&bad).is_err(),
                "expected error for {bad}"
            );
        }
    }
}
