//! Backend for targets that have none yet.
//!
//! This exists so the portable core keeps compiling on a target with no
//! platform code. That is not a courtesy — it is how the claim in spec 2.1
//! ("portable by construction") is checked mechanically rather than believed.
//! A Linux backend is an addition beside this file, not a rewrite above it.

use anyhow::{bail, Result};

use crate::model::{
    DnsConfig, Family, FirewallState, Interface, Route, SocketFilter, SocketTable, WifiDetail,
};
use crate::sys::{Platform, PlatformConfig};

pub struct Unsupported;

impl Unsupported {
    pub fn new(_config: PlatformConfig) -> Self {
        Self
    }
}

const MSG: &str = "no platform backend is built for this target";

impl Platform for Unsupported {
    fn interfaces(&self) -> Result<Vec<Interface>> {
        bail!(MSG)
    }
    fn dns_config(&self) -> Result<DnsConfig> {
        bail!(MSG)
    }
    fn routes(&self, _family: Option<Family>) -> Result<Vec<Route>> {
        bail!(MSG)
    }
    fn sockets(&self, _filter: SocketFilter) -> Result<SocketTable> {
        bail!(MSG)
    }
    fn firewall(&self) -> Result<FirewallState> {
        bail!(MSG)
    }
    fn wifi(&self, _iface: &str) -> Result<Option<WifiDetail>> {
        bail!(MSG)
    }
}
