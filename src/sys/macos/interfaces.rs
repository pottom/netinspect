//! Interface enumeration.
//!
//! Addresses and flags come from `getifaddrs`, which Linux shares verbatim.
//! Everything layered on top — the display name, the carrier state, the address
//! source — comes from `SCDynamicStore` and is macOS-only. The split is
//! deliberate: the shared call stays shared.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use system_configuration::dynamic_store::SCDynamicStore;

use super::cf::{self, Value};
use super::services::{self, Service};
use super::sysinfo;
use super::vpn;
use super::wifi;
use crate::model::{
    AddressSource, DhcpLease, Interface, InterfaceKind, InterfaceStatus, Ipv4Entry, Ipv6Entry,
    Ipv6Scope,
};
use crate::sys::HelperPolicy;

/// Raw per-interface facts, before any macOS-specific enrichment. This is the
/// part a Linux backend would produce with the same `getifaddrs` call.
struct Raw {
    flags: InterfaceFlags,
    ipv4: Vec<(Ipv4Addr, u8)>,
    ipv6: Vec<(Ipv6Addr, u8)>,
    mac: Option<String>,
}

impl Default for Raw {
    fn default() -> Self {
        Self {
            flags: InterfaceFlags::empty(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            mac: None,
        }
    }
}

pub fn collect(store: &SCDynamicStore, policy: HelperPolicy) -> anyhow::Result<Vec<Interface>> {
    let raw = enumerate()?;
    let services = services::load(store);
    let primary = primary_interfaces(store);

    let mut interfaces: Vec<Interface> = raw
        .into_iter()
        .map(|(name, raw)| build(store, &services, &primary, policy, name, raw))
        .collect();

    sort_interfaces(&mut interfaces);
    Ok(interfaces)
}

fn enumerate() -> anyhow::Result<BTreeMap<String, Raw>> {
    let mut map: BTreeMap<String, Raw> = BTreeMap::new();

    for ifaddr in getifaddrs()? {
        let entry = map.entry(ifaddr.interface_name.clone()).or_default();
        entry.flags = ifaddr.flags;

        let Some(address) = ifaddr.address.as_ref() else {
            continue;
        };

        if let Some(v4) = address.as_sockaddr_in() {
            let prefix = ifaddr
                .netmask
                .as_ref()
                .and_then(|m| m.as_sockaddr_in())
                .map(|m| m.ip().to_bits().count_ones() as u8)
                .unwrap_or(32);
            entry.ipv4.push((v4.ip(), prefix));
        } else if let Some(v6) = address.as_sockaddr_in6() {
            let prefix = ifaddr
                .netmask
                .as_ref()
                .and_then(|m| m.as_sockaddr_in6())
                .map(|m| prefix_len_v6(m.ip()))
                .unwrap_or(128);
            entry.ipv6.push((strip_embedded_scope(v6.ip()), prefix));
        } else if let Some(link) = address.as_link_addr() {
            entry.mac = link.addr().map(format_mac);
        }
    }

    Ok(map)
}

#[allow(clippy::too_many_arguments)]
fn build(
    store: &SCDynamicStore,
    services: &[Service],
    primary: &Primary,
    policy: HelperPolicy,
    name: String,
    raw: Raw,
) -> Interface {
    let service = services::for_device(services, &name);
    let kind = classify(&name, raw.flags, service.and_then(|s| s.hardware.as_deref()));
    let link_active = link_active(store, &name);
    let has_address = !raw.ipv4.is_empty() || !raw.ipv6.is_empty();
    let has_routable = raw.ipv4.iter().any(|(a, _)| !a.is_link_local())
        || raw.ipv6.iter().any(|(a, _)| !is_link_local_v6(*a));
    let status = status_of(kind, raw.flags, link_active, has_address, has_routable);

    let source = address_source(service);
    let ipv4 = raw
        .ipv4
        .iter()
        .map(|(addr, prefix)| Ipv4Entry {
            address: addr.to_string(),
            prefix_len: *prefix,
            source: if addr.is_link_local() {
                AddressSource::Linklocal
            } else {
                source
            },
        })
        .collect();
    let ipv6 = raw
        .ipv6
        .iter()
        .map(|(addr, prefix)| Ipv6Entry {
            address: addr.to_string(),
            prefix_len: *prefix,
            scope: if is_link_local_v6(*addr) {
                Ipv6Scope::Link
            } else {
                Ipv6Scope::Global
            },
        })
        .collect();

    let is_default_route = primary.v4.as_deref() == Some(&name) || primary.v6.as_deref() == Some(&name);
    let gateway = if primary.v4.as_deref() == Some(&name) {
        primary.router_v4.clone()
    } else if primary.v6.as_deref() == Some(&name) {
        primary.router_v6.clone()
    } else {
        // Per-interface gateways come from the routing table, which lands with
        // the `routes` subcommand.
        None
    };

    Interface {
        display_name: display_name(service, kind),
        kind,
        status,
        ipv4,
        ipv6,
        gateway,
        mac: raw.mac,
        mtu: sysinfo::mtu(&name),
        dhcp: (source == AddressSource::Dhcp).then(dhcp_lease),
        wifi: if kind == InterfaceKind::Wifi {
            wifi::collect(store, &name, policy)
        } else {
            None
        },
        vpn: (kind == InterfaceKind::Vpn).then(|| vpn::detail(&name, service)),
        is_default_route,
        name,
    }
}

/// macOS 15+ exposes no readable lease: `State:/Network/Interface/<if>/DHCP` is
/// gone and `/var/db/dhcpclient/leases` is root-only. The address source is
/// still known; the expiry simply is not.
fn dhcp_lease() -> DhcpLease {
    DhcpLease {
        expires_at: None,
        seconds_remaining: None,
    }
}

// ---------------------------------------------------------------------------
// Dynamic store lookups
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Primary {
    v4: Option<String>,
    v6: Option<String>,
    router_v4: Option<String>,
    router_v6: Option<String>,
}

fn primary_interfaces(store: &SCDynamicStore) -> Primary {
    let v4 = cf::read(store, "State:/Network/Global/IPv4");
    let v6 = cf::read(store, "State:/Network/Global/IPv6");
    let field = |v: &Option<Value>, key: &str| {
        v.as_ref()
            .and_then(|d| d.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    Primary {
        v4: field(&v4, "PrimaryInterface"),
        v6: field(&v6, "PrimaryInterface"),
        router_v4: field(&v4, "Router"),
        router_v6: field(&v6, "Router"),
    }
}

/// Carrier state. `None` when the interface has no link key at all, which is
/// the normal answer for virtual interfaces.
fn link_active(store: &SCDynamicStore, iface: &str) -> Option<bool> {
    match cf::read(store, &format!("State:/Network/Interface/{iface}/Link"))?.get("Active")? {
        Value::Bool(active) => Some(*active),
        Value::Int(active) => Some(*active != 0),
        _ => None,
    }
}

fn address_source(service: Option<&Service>) -> AddressSource {
    match service.and_then(|s| s.config_method_v4.as_deref()) {
        Some("DHCP") | Some("BOOTP") => AddressSource::Dhcp,
        Some("LinkLocal") => AddressSource::Linklocal,
        // Absent configuration is reported as manual rather than guessed at.
        _ => AddressSource::Manual,
    }
}

/// The name the user would recognise from System Settings. `None` when there is
/// no configured service, which is how the renderer tells a real interface from
/// a kernel-internal one.
fn display_name(service: Option<&Service>, kind: InterfaceKind) -> Option<String> {
    if let Some(user_name) = service.and_then(|s| s.user_name.as_deref()) {
        return Some(user_name.to_owned());
    }
    match kind {
        InterfaceKind::Loopback => Some("Loopback".to_owned()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Pure transformations — the testable part
// ---------------------------------------------------------------------------

/// Classify by combining the flags, the configured hardware string, and the
/// name prefix. No single one of the three is sufficient.
fn classify(name: &str, flags: InterfaceFlags, hardware: Option<&str>) -> InterfaceKind {
    if flags.contains(InterfaceFlags::IFF_LOOPBACK) || name.starts_with("lo") {
        return InterfaceKind::Loopback;
    }
    if name.starts_with("utun") || name.starts_with("ipsec") || name.starts_with("ppp") {
        return InterfaceKind::Vpn;
    }
    if name.starts_with("bridge") {
        return InterfaceKind::Bridge;
    }
    match hardware {
        Some("AirPort") => InterfaceKind::Wifi,
        Some("Ethernet") | Some("FireWire") => InterfaceKind::Ethernet,
        Some("IPSec") | Some("L2TP") | Some("PPP") => InterfaceKind::Vpn,
        _ => InterfaceKind::Other,
    }
}

/// A physical interface with a carrier is "connected"; a virtual one that is up
/// is merely "up". The distinction is what makes the report readable at a
/// glance.
fn status_of(
    kind: InterfaceKind,
    flags: InterfaceFlags,
    link_active: Option<bool>,
    has_address: bool,
    has_routable_address: bool,
) -> InterfaceStatus {
    if !flags.contains(InterfaceFlags::IFF_UP) {
        return InterfaceStatus::Disabled;
    }
    if kind == InterfaceKind::Loopback {
        return InterfaceStatus::Up;
    }
    if matches!(kind, InterfaceKind::Wifi | InterfaceKind::Ethernet) {
        if link_active == Some(false) {
            return InterfaceStatus::NoCable;
        }
        if !has_address {
            return InterfaceStatus::Inactive;
        }
        return InterfaceStatus::Connected;
    }
    // A tunnel carrying only a link-local address is idle, not up. macOS keeps
    // ten or more of those around; calling them all "up" would bury the one
    // that is actually carrying traffic.
    if has_routable_address {
        InterfaceStatus::Up
    } else {
        InterfaceStatus::Inactive
    }
}

/// Never sort by name — sort by what the user came to find out: the interface
/// owning the default route, then other active interfaces, then VPNs, then
/// inactive ones (DESIGN.md §4.2).
fn sort_interfaces(interfaces: &mut [Interface]) {
    interfaces.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.name.cmp(&b.name)));
}

fn rank(iface: &Interface) -> (u8, u8) {
    if !iface.is_active() {
        return (3, 0);
    }
    let group = if iface.is_default_route {
        0
    } else if iface.kind == InterfaceKind::Vpn {
        2
    } else {
        1
    };
    (group, 0)
}

fn format_mac(bytes: [u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn prefix_len_v6(mask: Ipv6Addr) -> u8 {
    mask.segments().iter().map(|s| s.count_ones() as u8).sum()
}

fn is_link_local_v6(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// macOS embeds the interface index in bytes 2–3 of a link-local address (the
/// KAME convention), so `getifaddrs` hands back `fe80:6::…` for what the user
/// knows as `fe80::…`. Strip it; the interface is already named by the row.
fn strip_embedded_scope(addr: Ipv6Addr) -> Ipv6Addr {
    if !is_link_local_v6(addr) {
        return addr;
    }
    let mut segments = addr.segments();
    segments[1] = 0;
    Ipv6Addr::from(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UP: InterfaceFlags = InterfaceFlags::IFF_UP;

    #[test]
    fn classifies_by_name_before_hardware() {
        // bridge0 is configured as Ethernet hardware but is a bridge.
        assert_eq!(classify("bridge0", UP, Some("Ethernet")), InterfaceKind::Bridge);
        assert_eq!(classify("utun3", UP, None), InterfaceKind::Vpn);
        assert_eq!(classify("en0", UP, Some("AirPort")), InterfaceKind::Wifi);
        assert_eq!(classify("en5", UP, Some("Ethernet")), InterfaceKind::Ethernet);
        // No service and no recognisable prefix: honestly "other".
        assert_eq!(classify("awdl0", UP, None), InterfaceKind::Other);
        assert_eq!(
            classify("lo0", UP | InterfaceFlags::IFF_LOOPBACK, None),
            InterfaceKind::Loopback
        );
    }

    #[test]
    fn physical_and_virtual_interfaces_read_differently() {
        assert_eq!(
            status_of(InterfaceKind::Wifi, UP, Some(true), true, true),
            InterfaceStatus::Connected
        );
        assert_eq!(
            status_of(InterfaceKind::Ethernet, UP, Some(false), false, false),
            InterfaceStatus::NoCable
        );
        assert_eq!(
            status_of(InterfaceKind::Ethernet, UP, None, false, false),
            InterfaceStatus::Inactive
        );
        // A tunnel with a routable address is up, not "connected".
        assert_eq!(
            status_of(InterfaceKind::Vpn, UP, None, true, true),
            InterfaceStatus::Up
        );
        assert_eq!(
            status_of(InterfaceKind::Vpn, UP, None, false, false),
            InterfaceStatus::Inactive
        );
        // Link-local only: an idle system tunnel, not a live one.
        assert_eq!(
            status_of(InterfaceKind::Vpn, UP, None, true, false),
            InterfaceStatus::Inactive
        );
        assert_eq!(
            status_of(InterfaceKind::Wifi, InterfaceFlags::empty(), Some(true), true, true),
            InterfaceStatus::Disabled
        );
    }

    #[test]
    fn strips_the_kame_scope_id() {
        let embedded: Ipv6Addr = "fe80:6::1c4d:8a2f:9b01:3e77".parse().unwrap();
        assert_eq!(
            strip_embedded_scope(embedded).to_string(),
            "fe80::1c4d:8a2f:9b01:3e77"
        );
        // A global address must be left exactly as it is.
        let global: Ipv6Addr = "2001:db8:6::1".parse().unwrap();
        assert_eq!(strip_embedded_scope(global), global);
    }

    #[test]
    fn prefix_lengths_come_from_the_netmask() {
        assert_eq!(prefix_len_v6("ffff:ffff:ffff:ffff::".parse().unwrap()), 64);
        assert_eq!(prefix_len_v6(Ipv6Addr::UNSPECIFIED), 0);
        assert_eq!(Ipv4Addr::new(255, 255, 255, 0).to_bits().count_ones(), 24);
    }

    #[test]
    fn formats_a_mac() {
        assert_eq!(
            format_mac([0xa4, 0x83, 0xe7, 0x2d, 0x11, 0x9c]),
            "a4:83:e7:2d:11:9c"
        );
    }
}
