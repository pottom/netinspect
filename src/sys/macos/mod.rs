//! The macOS backend. See `src/sys/macos/AGENTS.md`.

mod cf;
mod dns;
mod firewall;
mod interfaces;
mod routes;
mod scan_record;
mod services;
mod sockets;
mod ssid_helper;
mod sysinfo;
mod vpn;
mod wifi;

use anyhow::{Context, Result};
use system_configuration::dynamic_store::SCDynamicStore;

use crate::model::{
    DnsConfig, Family, FirewallState, Interface, Route, SocketFilter, SocketTable, WifiDetail,
};
use crate::sys::{Platform, PlatformConfig};

/// `removexattr(2)` for `com.apple.quarantine`.
///
/// A binary that arrived over the network carries this flag, and Gatekeeper
/// refuses it on first launch. Its absence is success, so "no such attribute"
/// counts as done.
pub fn strip_quarantine(path: &std::path::Path) -> bool {
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    let name = c"com.apple.quarantine";
    // Safety: two NUL-terminated strings and no flags; the call writes nothing
    // through either pointer.
    let rc = unsafe { libc::removexattr(path.as_ptr(), name.as_ptr(), 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOATTR)
}

pub struct MacOs {
    config: PlatformConfig,
}

impl MacOs {
    pub fn new(config: PlatformConfig) -> Self {
        Self { config }
    }

    fn store(&self) -> Result<SCDynamicStore> {
        cf::open_store().context("could not open a session against SCDynamicStore")
    }
}

impl Platform for MacOs {
    fn interfaces(&self) -> Result<Vec<Interface>> {
        let store = self.store()?;
        interfaces::collect(&store, self.config.helpers)
    }

    fn dns_config(&self) -> Result<DnsConfig> {
        Ok(dns::collect(&self.store()?))
    }
    fn routes(&self, family: Option<Family>) -> Result<Vec<Route>> {
        routes::collect(family)
    }
    fn sockets(&self, filter: SocketFilter) -> Result<SocketTable> {
        sockets::collect(filter)
    }
    fn firewall(&self) -> Result<FirewallState> {
        Ok(firewall::collect())
    }

    fn wifi(&self, iface: &str) -> Result<Option<WifiDetail>> {
        Ok(wifi::collect(&self.store()?, iface, self.config.helpers))
    }
}
