//! Provider-agnostic native browser payload construction primitives.
//!
//! This crate extracts the reusable building blocks needed to construct
//! anti-bot / telemetry payloads natively in Rust without a JavaScript engine:
//! - [`profile`]: Built-in empirical desktop Chrome fingerprint generator,
//!   OS presets, real-browser capture loader, Client Hints, ordered headers,
//!   and WebGL/UA digests.
//! - [`biometrics`]: Deterministic session clocks, time buckets, divisor tuples,
//!   and seeded minimum-jerk mouse/pointer trajectories.
//! - [`template`]: Fallible, order-preserving top-level JSON field patching
//!   and Unicode-aware JavaScript string-array extraction.
//! - [`cipher`]: 23-bit LCG, 92-char printable ASCII substitution,
//!   token-swap permutation, Caesar rotation, and cyclic XOR.

pub mod biometrics;
pub mod cipher;
pub mod profile;
pub(crate) mod profile_data;
pub mod template;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme_doctests {}
