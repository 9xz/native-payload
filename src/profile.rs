//! Provider-agnostic browser device profile (`captures/*.json`) loader and fingerprint model.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cipher::ascii_sum;

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
    pub raw: Option<Value>,
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self::chrome_macos("156")
    }
}

impl DeviceProfile {
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
            timezone: "America/Los_Angeles".to_owned(),
            timezone_offset_min: 480,
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
            raw: None,
        }
    }

    /// Parse a recorded browser environment JSON (`tools/capture-env.js`).
    pub fn from_capture_json(value: &Value) -> Result<Self, String> {
        if !value.is_object() {
            return Err("snapshot must be a JSON object".to_owned());
        }
        for key in ["ua", "navigator", "screen", "window"] {
            if value.get(key).is_none() {
                return Err(format!("snapshot is missing `{key}`"));
            }
        }
        let ua = value["ua"]
            .as_str()
            .unwrap_or(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
            )
            .to_owned();
        let chrome_major = value
            .get("chromeVersion")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                ua.split("Chrome/")
                    .nth(1)
                    .and_then(|rest| rest.split('.').next())
                    .unwrap_or("156")
                    .to_owned()
            });
        let nav = &value["navigator"];
        let scr = &value["screen"];
        let win = &value["window"];
        let wgl = &value["webgl"];

        let mut base = Self::chrome_macos(&chrome_major);
        base.user_agent = ua;
        if let Some(p) = nav.get("platform").and_then(Value::as_str) {
            base.platform = p.to_owned();
        }
        if let Some(l) = nav.get("language").and_then(Value::as_str) {
            base.language = l.to_owned();
        }
        if let Some(arr) = nav.get("languages").and_then(Value::as_array) {
            let langs: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
            if !langs.is_empty() {
                base.languages = langs;
            }
        }
        if let Some(tz) = value.get("timeZone").and_then(Value::as_str) {
            base.timezone = tz.to_owned();
        }
        if let Some(hc) = nav.get("hardwareConcurrency").and_then(Value::as_u64) {
            base.hardware_concurrency = hc as u32;
        }
        if let Some(dm) = nav.get("deviceMemory").and_then(Value::as_u64) {
            base.device_memory = dm as u32;
        }
        if let Some(w) = scr.get("width").and_then(Value::as_u64) {
            base.screen.width = w as u32;
        }
        if let Some(h) = scr.get("height").and_then(Value::as_u64) {
            base.screen.height = h as u32;
        }
        if let Some(aw) = scr.get("availWidth").and_then(Value::as_u64) {
            base.screen.avail_width = aw as u32;
        }
        if let Some(ah) = scr.get("availHeight").and_then(Value::as_u64) {
            base.screen.avail_height = ah as u32;
        }
        if let Some(cd) = scr.get("colorDepth").and_then(Value::as_u64) {
            base.screen.color_depth = cd as u32;
        }
        if let Some(pd) = scr.get("pixelDepth").and_then(Value::as_u64) {
            base.screen.pixel_depth = pd as u32;
        }
        if let Some(iw) = win.get("innerWidth").and_then(Value::as_u64) {
            base.window.inner_width = iw as u32;
        }
        if let Some(ih) = win.get("innerHeight").and_then(Value::as_u64) {
            base.window.inner_height = ih as u32;
        }
        if let Some(ow) = win.get("outerWidth").and_then(Value::as_u64) {
            base.window.outer_width = ow as u32;
        }
        if let Some(oh) = win.get("outerHeight").and_then(Value::as_u64) {
            base.window.outer_height = oh as u32;
        }
        if let Some(v) = wgl.get("vendor").and_then(Value::as_str) {
            base.webgl.vendor = v.to_owned();
        }
        if let Some(r) = wgl.get("renderer").and_then(Value::as_str) {
            base.webgl.renderer = r.to_owned();
        }
        base.raw = Some(value.clone());
        Ok(base)
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
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_capture_snapshot_and_computes_ua_sum() {
        let raw = json!({
            "ua": "Mozilla/5.0 Chrome/156.0.0.0",
            "navigator": {"platform": "MacIntel", "hardwareConcurrency": 12},
            "screen": {"width": 1728, "height": 1117},
            "window": {"innerWidth": 1280, "innerHeight": 800}
        });
        let profile = DeviceProfile::from_capture_json(&raw).expect("valid");
        assert_eq!(profile.chrome_major, "156");
        assert_eq!(profile.hardware_concurrency, 12);
        assert_eq!(profile.screen.width, 1728);
        assert_eq!(
            profile.ua_ascii_sum(),
            ascii_sum("Mozilla/5.0 Chrome/156.0.0.0")
        );
    }
}
