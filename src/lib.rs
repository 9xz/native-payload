//! Provider-agnostic native browser payload construction primitives.
//!
//! This crate extracts the reusable building blocks needed to construct
//! anti-bot / telemetry payloads natively in Rust without a JavaScript engine:
//! - [`profile`]: Browser device profile normalization (`captures/*.json`), User-Agent
//!   and Client-Hint derivation, screen/window geometry, and WebGL/canvas digests.
//! - [`biometrics`]: Deterministic session clocks, time buckets, divisor tuples,
//!   and minimum-jerk human mouse/pointer trajectories.
//! - [`template`]: Order-preserving JSON field patching (preserving exact provider
//!   key order and float formatting) and JS literal extraction helpers.
//! - [`cipher`]: 23-bit LCG, 92-char printable ASCII substitution, Fisher-Yates
//!   token permutation, Caesar rotation, and cyclic XOR.

pub mod biometrics;
pub mod cipher;
pub mod profile;
pub mod template;
