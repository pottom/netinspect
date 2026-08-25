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


