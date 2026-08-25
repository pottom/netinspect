//! The platform layer.
//!
//! This is the only subtree that may contain `cfg(target_os = ...)` or
//! `unsafe`. Everything above this boundary is written against `&dyn Platform`
//! and compiles unchanged on any target — including a target with no backend
//! at all, which is what `unsupported` exists to prove.
//!
//! See `src/sys/AGENTS.md` for the contract.

use anyhow::Result;

use crate::model::{
    DnsConfig, Family, FirewallState, Interface, Route, SocketFilter, SocketTable, WifiDetail,
};

#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(target_os = "macos"))]
mod unsupported;

/// How much the platform layer may spend on best-effort fallbacks that are not
/// supported APIs. See spec 6.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HelperPolicy {
    /// No subprocess is spawned under any circumstance.
    Disabled,
    /// The fast candidates only. This is the default.
    #[default]
    Fast,
    /// Also allow candidates that take seconds.
    Slow,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformConfig {
    pub helpers: HelperPolicy,
}

/// Every method returns a piece of the `Snapshot` model and nothing else.
///
/// Callers must tolerate `Ok(None)` and empty vectors: a field one platform
/// cannot fill is not an exceptional case, it is the normal shape of this
/// problem. No method takes or returns a platform handle, file descriptor, or
/// raw buffer — if a caller ever needs one, the abstraction has leaked.
// The trait is the full contract from the start; `routes`, `sockets` and
// `firewall` gain callers in later milestones.
#[allow(dead_code)]
pub trait Platform {
    fn interfaces(&self) -> Result<Vec<Interface>>;
    fn dns_config(&self) -> Result<DnsConfig>;
    fn routes(&self, family: Option<Family>) -> Result<Vec<Route>>;
    fn sockets(&self, filter: SocketFilter) -> Result<SocketTable>;
    fn firewall(&self) -> Result<FirewallState>;
    fn wifi(&self, iface: &str) -> Result<Option<WifiDetail>>;
}

/// Who is running this process.
///
/// It lives here rather than at the call site because it is a syscall, and
/// `tests/guards.rs` keeps `unsafe` inside this subtree — which is exactly how
/// this ended up in the right place.
pub fn current_uid() -> u32 {
    // Safety: getuid cannot fail and touches no memory we own.
    unsafe { libc::getuid() }
}

/// Select the backend for this target. Called once at startup.
#[cfg(target_os = "macos")]
pub fn platform(config: PlatformConfig) -> Box<dyn Platform> {
    Box::new(macos::MacOs::new(config))
}

#[cfg(not(target_os = "macos"))]
pub fn platform(config: PlatformConfig) -> Box<dyn Platform> {
    Box::new(unsupported::Unsupported::new(config))
}
