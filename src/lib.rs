//! netinspect: read-only network diagnostics.
//!
//! The crate is split at one seam. `sys` turns whatever the operating system
//! exposes into the `model::Snapshot`; everything else — `render`, and the
//! probes and lookups that follow — works on that model and never touches a
//! platform API. See `AGENTS.md`.

/// Choose the TLS crypto provider for this process.
///
/// rustls refuses to guess when more than one is available, and picking
/// `ring` over the default `aws-lc-rs` is what keeps a bundled C crypto
/// library out of a diagnostic tool that opens two TLS connections. Idempotent
/// and safe to call from every entry point that builds a client.
pub fn install_crypto_provider() {
    // An error means one is already installed, which is the desired state.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub mod cli;
pub mod container;
pub mod model;
pub mod parse;
pub mod probe;
pub mod public;
pub mod render;
pub mod sys;
pub mod update;
