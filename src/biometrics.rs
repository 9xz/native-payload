//! Provider-agnostic synthetic pointer trajectories, clock buckets, and divisor tuples.

use std::fmt::Write as _;

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
    let mut d = 1u64;
    while d <= value / d && pairs.len() < 6 {
        if value.is_multiple_of(d) {
            pairs.push(d.to_string());
            let q = value / d;
            if d != q && pairs.len() < 6 {
                pairs.push(q.to_string());
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

/// Synthetic pointer trajectory and aggregate metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MouseTrajectory {
    pub samples: Vec<MouseSample>,
    pub encoded: String,
    pub mevl: u64,
    pub tovl: u64,
}

impl MouseTrajectory {
    /// Generate a deterministic minimum-jerk `moves`-step trajectory followed by a click.
    ///
    /// # Panics
    /// Panics if `moves`, timestamps, or aggregate metrics overflow.
    pub fn generate(seed: u64, start_dt_ms: u64, moves: usize) -> Self {
        let total_samples = moves.checked_add(1).expect("moves count overflow");
        let mut rng = XorShift64::new(seed);
        let mut dt = start_dt_ms;
        let mut samples = Vec::with_capacity(total_samples);
        let mut encoded = String::with_capacity(total_samples.saturating_mul(24));
        let mut sum_metric = 0u64;

        let start_x = rng.range_u32(40, 640) as i32;
        let start_y = rng.range_u32(40, 480) as i32;
        let mut end_x = rng.range_u32(120, 1180) as i32;
        let mut end_y = rng.range_u32(80, 760) as i32;
        if (end_x - start_x).abs() + (end_y - start_y).abs() < 80 {
            end_x = if end_x + 180 <= 1180 {
                end_x + 180
            } else {
                end_x - 180
            };
            end_y = if end_y + 120 <= 760 {
                end_y + 120
            } else {
                end_y - 120
            };
        }

        let dx = f64::from(end_x - start_x);
        let dy = f64::from(end_y - start_y);
        let dist = dx.hypot(dy).max(1.0);
        let nx = -dy / dist;
        let ny = dx / dist;
        let bend_sign = if (rng.next_u64() & 1) == 0 { 1.0 } else { -1.0 };
        let bend_mag = f64::from(rng.range_u32(12, 65)) * bend_sign;
        let step_ms = u64::from(rng.range_u32(8, 25));

        for idx in 0..moves {
            dt = dt
                .checked_add(step_ms)
                .expect("trajectory timestamp overflow");
            let (x, y) = if moves == 1 {
                (end_x, end_y)
            } else {
                let t = (idx as f64) / ((moves - 1) as f64);
                let s = t * t * t * (10.0 + t * (-15.0 + 6.0 * t));
                let arc = 4.0 * s * (1.0 - s) * bend_mag;
                let px = f64::from(start_x) + dx * s + nx * arc;
                let py = f64::from(start_y) + dy * s + ny * arc;
                (
                    (px.round() as i32).clamp(1, 4096),
                    (py.round() as i32).clamp(1, 4096),
                )
            };
            samples.push(MouseSample {
                index: idx,
                event_type: 1,
                dt_ms: dt,
                x,
                y,
                button: None,
            });
            let _ = write!(encoded, "{idx},1,{dt},{x},{y};");
            let sample_metric = dt
                .checked_add(u64::try_from(x).expect("non-negative x coordinate"))
                .and_then(|v| v.checked_add(u64::try_from(y).expect("non-negative y coordinate")))
                .expect("trajectory metric overflow");
            sum_metric = sum_metric
                .checked_add(sample_metric)
                .expect("trajectory metric overflow");
        }

        dt = dt
            .checked_add(u64::from(rng.range_u32(12, 32)))
            .expect("trajectory timestamp overflow");
        let (click_x, click_y) = samples
            .last()
            .map_or((end_x, end_y), |last| (last.x, last.y));
        samples.push(MouseSample {
            index: moves,
            event_type: 3,
            dt_ms: dt,
            x: click_x,
            y: click_y,
            button: Some(-1),
        });
        let _ = write!(encoded, "{moves},3,{dt},{click_x},{click_y},-1;");
        let click_metric = dt
            .checked_add(u64::try_from(click_x).expect("non-negative click_x"))
            .and_then(|v| v.checked_add(u64::try_from(click_y).expect("non-negative click_y")))
            .expect("trajectory metric overflow");
        sum_metric = sum_metric
            .checked_add(click_metric)
            .expect("trajectory metric overflow");
        let tovl = sum_metric
            .checked_add(78)
            .expect("trajectory tovl overflow");

        Self {
            samples,
            encoded,
            mevl: sum_metric,
            tovl,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divisors_handles_zero_squares_and_large_integers() {
        assert_eq!(divisors_pair_string(0), "");
        assert_eq!(divisors_pair_string(1), "1");
        assert_eq!(divisors_pair_string(36), "1,36,2,18,3,12");
        assert_eq!(divisors_pair_string(49), "1,49,7");
        assert_eq!(divisors_pair_string(1004), "1,1004,2,502,4,251");
        // Above f64's exact-integer range, use exact factor pairs.
        let n = u64::MAX;
        assert_eq!(
            divisors_pair_string(n),
            format!("1,{n},3,{},5,{}", n / 3, n / 5)
        );
    }

    #[test]
    fn trajectory_is_deterministic_and_varies_with_seed() {
        let a1 = MouseTrajectory::generate(42, 1260, 20);
        let a2 = MouseTrajectory::generate(42, 1260, 20);
        let b = MouseTrajectory::generate(99, 1260, 20);

        assert_eq!(a1, a2);
        assert_ne!(a1.samples, b.samples);
        assert_ne!(
            (a1.samples[0].x, a1.samples[0].y),
            (b.samples[0].x, b.samples[0].y)
        );
        assert_ne!(
            (a1.samples[20].x, a1.samples[20].y),
            (b.samples[20].x, b.samples[20].y)
        );
    }

    #[test]
    fn trajectory_eases_at_both_endpoints() {
        let trajectory = MouseTrajectory::generate(42, 0, 101);
        let distance = |a: &MouseSample, b: &MouseSample| (a.x - b.x).abs() + (a.y - b.y).abs();
        let samples = &trajectory.samples;
        let middle = distance(&samples[49], &samples[50]);
        assert!(distance(&samples[0], &samples[1]) < middle);
        assert!(distance(&samples[99], &samples[100]) < middle);
        let interval = samples[1].dt_ms - samples[0].dt_ms;
        assert!(
            samples[..101]
                .windows(2)
                .all(|pair| pair[1].dt_ms - pair[0].dt_ms == interval)
        );
    }

    #[test]
    fn trajectory_timestamps_monotonic_and_click_matches_endpoint() {
        let traj = MouseTrajectory::generate(7, 500, 16);
        assert_eq!(traj.samples.len(), 17);

        let mut prev_dt = 500;
        for (i, s) in traj.samples.iter().enumerate() {
            assert_eq!(s.index, i);
            assert!(s.dt_ms > prev_dt);
            assert!((1..=4096).contains(&s.x));
            assert!((1..=4096).contains(&s.y));
            prev_dt = s.dt_ms;
        }

        let last_move = &traj.samples[15];
        let click = &traj.samples[16];
        assert_eq!(last_move.event_type, 1);
        assert_eq!(last_move.button, None);
        assert_eq!(click.event_type, 3);
        assert_eq!(click.button, Some(-1));
        assert_eq!((click.x, click.y), (last_move.x, last_move.y));
    }

    #[test]
    fn trajectory_handles_zero_and_one_move_bounds() {
        let zero = MouseTrajectory::generate(123, 100, 0);
        assert_eq!(zero.samples.len(), 1);
        assert_eq!(zero.samples[0].index, 0);
        assert_eq!(zero.samples[0].event_type, 3);
        assert_eq!(zero.samples[0].button, Some(-1));
        assert!(zero.samples[0].dt_ms > 100);

        let one = MouseTrajectory::generate(123, 100, 1);
        assert_eq!(one.samples.len(), 2);
        assert_eq!(one.samples[0].event_type, 1);
        assert_eq!(one.samples[1].event_type, 3);
        assert_eq!(
            (one.samples[0].x, one.samples[0].y),
            (one.samples[1].x, one.samples[1].y)
        );
        assert!(one.samples[1].dt_ms > one.samples[0].dt_ms);
    }

    #[test]
    fn trajectory_encoding_and_aggregates_match_samples() {
        let traj = MouseTrajectory::generate(2026, 900, 12);
        let mut expected_encoded = String::new();
        let mut expected_mevl = 0u64;
        for s in &traj.samples {
            match s.button {
                None => {
                    let _ = write!(
                        expected_encoded,
                        "{},{},{},{},{};",
                        s.index, s.event_type, s.dt_ms, s.x, s.y
                    );
                }
                Some(btn) => {
                    let _ = write!(
                        expected_encoded,
                        "{},{},{},{},{},{btn};",
                        s.index, s.event_type, s.dt_ms, s.x, s.y
                    );
                }
            }
            expected_mevl += s.dt_ms + (s.x as u64) + (s.y as u64);
        }
        assert_eq!(traj.encoded, expected_encoded);
        assert_eq!(traj.mevl, expected_mevl);
        assert_eq!(traj.tovl, expected_mevl + 78);
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn trajectory_panics_on_timestamp_overflow() {
        let _ = MouseTrajectory::generate(1, u64::MAX - 5, 1);
    }
}
