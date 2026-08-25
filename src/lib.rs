//! netinspect: read-only network diagnostics.
//!
//! The crate is split at one seam. `sys` turns whatever the operating system
//! exposes into the `model::Snapshot`; everything else — `render`, and the
//! probes and lookups that follow — works on that model and never touches a
//! platform API. See `AGENTS.md`.

pub mod cli;
pub mod model;
pub mod parse;
pub mod probe;
pub mod public;
pub mod render;
pub mod sys;
pub mod update;
