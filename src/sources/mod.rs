//! Per-platform fetchers. Every source produces `(location, text)`
//! pairs for the [`crate::detector`] engine.

pub mod local;
pub mod github;
pub mod slack;
