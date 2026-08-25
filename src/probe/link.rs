//! Stage 1 — link.
//!
//! No I/O: the answer is already in the `Snapshot`. An interface with a
//! carrier and a usable address is the precondition for every stage after it,
//! so failing here means nothing downstream can be attributed to anything.

use std::net::IpAddr;

use crate::model::Interface;

/// True when some active interface holds an address that can carry traffic off
/// this machine.
pub fn probe(interfaces: &[Interface]) -> bool {
    interfaces.iter().any(|iface| {
        iface.is_active()
            && iface
                .ipv4
                .iter()
                .map(|a| a.address.as_str())
                .chain(iface.ipv6.iter().map(|a| a.address.as_str()))
                .any(carries_traffic)
    })
}

/// Deliberately not `reach::classify`. That function answers "who can reach
/// this address", and by that measure a link-local address is on the LAN. The
/// question here is different: can this address carry traffic to a gateway? A
/// self-assigned 169.254 address means DHCP never answered, so the interface is
/// up and the machine can reach nothing — and reporting a link would blame the
/// gateway stage for something that failed here.
fn carries_traffic(address: &str) -> bool {
    let Ok(address) = address.split('%').next().unwrap_or(address).parse::<IpAddr>() else {
        return false;
    };
    match address {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => {
            let link_local = v6.segments()[0] & 0xffc0 == 0xfe80;
            !v6.is_loopback() && !link_local && !v6.is_unspecified()
        }
    }
}

/// The gateway of the interface owning the default route.
pub fn default_gateway(interfaces: &[Interface]) -> Option<IpAddr> {
    interfaces
        .iter()
        .filter(|iface| iface.is_default_route)
        .find_map(|iface| iface.gateway.as_deref())
        .and_then(|gateway| gateway.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AddressSource, InterfaceKind, InterfaceStatus, Ipv4Entry, Ipv6Entry, Ipv6Scope,
    };

    fn interface(status: InterfaceStatus) -> Interface {
        Interface {
            name: "en0".to_owned(),
            display_name: None,
            kind: InterfaceKind::Wifi,
            status,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            gateway: None,
            mac: None,
            mtu: None,
            dhcp: None,
            wifi: None,
            vpn: None,
            is_default_route: false,
        }
    }

    fn v4(address: &str) -> Ipv4Entry {
        Ipv4Entry {
            address: address.to_owned(),
            prefix_len: 24,
            source: AddressSource::Dhcp,
        }
    }

    #[test]
    fn a_routable_address_on_an_active_interface_is_a_link() {
        let mut iface = interface(InterfaceStatus::Connected);
        iface.ipv4.push(v4("192.168.1.24"));
        assert!(probe(&[iface]));
    }

    #[test]
    fn a_self_assigned_address_is_not_a_link() {
        // 169.254/16 means DHCP never answered. The interface is up and the
        // machine can reach nothing; reporting a link would blame the gateway
        // stage for something that failed here.
        let mut iface = interface(InterfaceStatus::Connected);
        iface.ipv4.push(v4("169.254.13.1"));
        assert!(!probe(&[iface]));
    }

    #[test]
    fn a_link_local_ipv6_alone_is_not_a_link() {
        let mut iface = interface(InterfaceStatus::Connected);
        iface.ipv6.push(Ipv6Entry {
            address: "fe80::1".to_owned(),
            prefix_len: 64,
            scope: Ipv6Scope::Link,
        });
        assert!(!probe(&[iface]));
    }

    #[test]
    fn an_inactive_interface_does_not_count_however_addressed() {
        let mut iface = interface(InterfaceStatus::NoCable);
        iface.ipv4.push(v4("192.168.1.24"));
        assert!(!probe(&[iface]));
    }

    #[test]
    fn a_unique_local_ipv6_does_carry_traffic() {
        // fc00::/7 is a real routable prefix inside a network, unlike fe80::.
        let mut iface = interface(InterfaceStatus::Connected);
        iface.ipv6.push(Ipv6Entry {
            address: "fd07:b51a:cc66::1".to_owned(),
            prefix_len: 64,
            scope: Ipv6Scope::Global,
        });
        assert!(probe(&[iface]));
    }

    #[test]
    fn the_gateway_comes_from_the_default_route_owner() {
        let mut other = interface(InterfaceStatus::Connected);
        other.gateway = Some("10.0.0.1".to_owned());
        let mut owner = interface(InterfaceStatus::Connected);
        owner.is_default_route = true;
        owner.gateway = Some("192.168.1.1".to_owned());

        let found = default_gateway(&[other, owner]).unwrap();
        assert_eq!(found.to_string(), "192.168.1.1");
    }

    #[test]
    fn no_default_route_means_no_gateway() {
        assert_eq!(default_gateway(&[interface(InterfaceStatus::Connected)]), None);
    }
}
