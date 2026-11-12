//! Provider-agnostic synthetic human biometrics, clock buckets, and trajectories.

/// Deterministic 64-bit XorShift PRNG for reproducible trajectory synthesis.
#[derive(Debug, Clone)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn range_u32(&mut self, low: u32, high: u32) -> u32 {
        if low >= high {
            return low;
        }
        low + (self.next_u64() as u32) % (high - low)
    }
}

/// Coherent session timestamp and derived clock buckets.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionClock {
    pub start_ts_ms: u64,
    pub elapsed_ms: u64,
}

impl SessionClock {
    pub fn new(start_ts_ms: u64, elapsed_ms: u64) -> Self {
        Self {
            start_ts_ms,
            elapsed_ms,
        }
    }

    /// Half-timestamp (`start_ts_ms / 2.0`).
    pub fn hal(&self) -> f64 {
        self.start_ts_ms as f64 / 2.0
    }

    /// ~68-minute bucket (`floor(start_ts_ms / 4_064_256)`).
    pub fn hz1(&self) -> u64 {
        self.start_ts_ms / 4_064_256
    }

    /// ~26-hour bucket (`floor(start_ts_ms / 93_477_888)`).
    pub fn dd2(&self) -> u64 {
        self.start_ts_ms / 93_477_888
    }
}

/// Factor pair string (`"1,N,d2,N/d2,..."`, up to 6 entries) used in `ajr` checks.
pub fn divisors_pair_string(value: u64) -> String {
    if value == 0 {
        return String::new();
    }
    let mut pairs = Vec::with_capacity(6);
    let limit = (value as f64).sqrt() as u64;
    let mut d = 1u64;
    while d <= limit && pairs.len() < 6 {
        if value.is_multiple_of(d) {
            pairs.push(d.to_string());
            if d * d != value && pairs.len() < 6 {
                pairs.push((value / d).to_string());
            }
        }
        d += 1;
    }
    pairs.join(",")
}

/// One synthetic pointer/mouse event sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MouseSample {
    pub index: usize,
    pub event_type: u8,
    pub dt_ms: u64,
    pub x: i32,
    pub y: i32,
    pub button: Option<i32>,
}

/// Synthetic human mouse trajectory and aggregate metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MouseTrajectory {
    pub samples: Vec<MouseSample>,
    pub encoded: String,
    pub mevl: u64,
    pub tovl: u64,
}

impl MouseTrajectory {
    /// Generate a realistic `moves`-step trajectory followed by a click.
    pub fn generate(seed: u64, start_dt_ms: u64, moves: usize) -> Self {
        let mut rng = XorShift64::new(seed);
        let mut dt = start_dt_ms;
        let mut samples = Vec::with_capacity(moves + 1);
        let mut encoded = String::new();
        let mut sum_metric = 0u64;

        for idx in 0..moves {
            dt += u64::from(rng.range_u32(15, 31));
            let x = 184 + (idx as i32) * 17;
            let y = 227 + ((idx % 7) as i32) * 19;
            samples.push(MouseSample {
                index: idx,
                event_type: 1,
                dt_ms: dt,
                x,
                y,
                button: None,
            });
            encoded.push_str(&format!("{idx},1,{dt},{x},{y};"));
            sum_metric += dt + (x as u64) + (y as u64);
        }
        dt += u64::from(rng.range_u32(18, 25));
        let click_x = 184 + (moves as i32) * 16 + 6;
        let click_y = 347;
        samples.push(MouseSample {
            index: moves,
            event_type: 3,
            dt_ms: dt,
            x: click_x,
            y: click_y,
            button: Some(-1),
        });
        encoded.push_str(&format!("{moves},3,{dt},{click_x},{click_y},-1;"));
        sum_metric += dt + (click_x as u64) + (click_y as u64);

        Self {
            samples,
            encoded,
            mevl: sum_metric,
            tovl: sum_metric + 78,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divisors_and_trajectory_are_deterministic() {
        assert_eq!(divisors_pair_string(1004), "1,1004,2,502,4,251");
        let traj = MouseTrajectory::generate(42, 1260, 20);
        assert_eq!(traj.samples.len(), 21);
        assert!(traj.encoded.ends_with(",-1;"));
        assert!(traj.tovl > traj.mevl);
    }
}
