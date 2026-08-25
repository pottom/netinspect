//! Address classification — the one function behind the colour system.
//!
//! `DESIGN.md` §2.1: one function, used by every renderer, no local
//! exceptions. Hue answers exactly one question, *how far away can this be
//! touched from*, so this is the only place that decides it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::theme::Role;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Only this machine can reach it.
    Local,
    /// This network can reach it.
    Lan,
    /// The open internet is involved.
    Public,
}

impl Reach {
    pub fn role(self) -> Role {
        match self {
            Reach::Local => Role::Local,
            Reach::Lan => Role::Lan,
            Reach::Public => Role::Public,
        }
    }

    /// The word that carries this distinction when colour is gone.
    pub fn group_title(self) -> &'static str {
        match self {
            Reach::Local => "this machine only",
            Reach::Lan => "bound to one interface",
            Reach::Public => "reachable from the network",
        }
    }
}

/// Classify a rendered address. Accepts a bare address, one carrying a prefix
/// (`192.168.1.24/24`), a scoped IPv6 address (`fe80::1%en0`), or a routing
/// table's interface reference (`link#12`).
///
/// Anything unparseable is `Public`: a security readout must assume the worse
/// of two readings rather than quietly downgrade an address it did not
/// understand.
pub fn classify(address: &str) -> Reach {
    let text = address
        .split('/')
        .next()
        .unwrap_or(address)
        .split('%')
        .next()
        .unwrap_or(address)
        .trim();

    // A route scoped to an interface never leaves this network.
    if text.starts_with("link#") {
        return Reach::Lan;
    }

    match text.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => classify_v4(v4),
        Ok(IpAddr::V6(v6)) => classify_v6(v6),
        Err(_) => Reach::Public,
    }
}

fn classify_v4(addr: Ipv4Addr) -> Reach {
    if addr.is_loopback() {
        return Reach::Local;
    }
    let [a, b, ..] = addr.octets();
    let carrier_grade_nat = a == 100 && (64..128).contains(&b);
    if addr.is_private() || addr.is_link_local() || addr.is_multicast() || carrier_grade_nat {
        return Reach::Lan;
    }
    // 0.0.0.0 is a wildcard bind: internet-facing whenever any interface has a
    // routable address, so it is read as public.
    Reach::Public
}

fn classify_v6(addr: Ipv6Addr) -> Reach {
    if addr.is_loopback() {
        return Reach::Local;
    }
    let unique_local = addr.segments()[0] & 0xfe00 == 0xfc00;
    let link_local = addr.segments()[0] & 0xffc0 == 0xfe80;
    if link_local || unique_local || addr.is_multicast() {
        return Reach::Lan;
    }
    Reach::Public
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_local() {
        assert_eq!(classify("127.0.0.1"), Reach::Local);
        assert_eq!(classify("127.0.0.1/8"), Reach::Local);
        assert_eq!(classify("127.4.5.6"), Reach::Local);
        assert_eq!(classify("::1"), Reach::Local);
        assert_eq!(classify("::1/128"), Reach::Local);
    }

    #[test]
    fn private_ranges_are_lan() {
        for address in [
            "10.7.0.4",
            "10.7.0.4/32",
            "172.16.3.1",
            "172.31.255.254",
            "192.168.1.24/24",
            "169.254.13.1",
            "224.0.0.251",
        ] {
            assert_eq!(classify(address), Reach::Lan, "{address}");
        }
    }

    #[test]
    fn carrier_grade_nat_is_lan_not_public() {
        // 100.64/10 is the shared address space an ISP NATs behind. It is not
        // the open internet, and calling it public would misread a very common
        // home setup.
        assert_eq!(classify("100.64.0.1"), Reach::Lan);
        assert_eq!(classify("100.127.255.254"), Reach::Lan);
        // The boundaries either side are ordinary public space.
        assert_eq!(classify("100.63.255.255"), Reach::Public);
        assert_eq!(classify("100.128.0.0"), Reach::Public);
    }

    #[test]
    fn ipv6_link_local_and_unique_local_are_lan() {
        assert_eq!(classify("fe80::1c4d:8a2f:9b01:3e77"), Reach::Lan);
        assert_eq!(classify("fe80::1%en0"), Reach::Lan);
        assert_eq!(classify("fd07:b51a:cc66::1/64"), Reach::Lan);
        assert_eq!(classify("ff02::1"), Reach::Lan);
        assert_eq!(classify("2001:db8::1"), Reach::Public);
    }

    #[test]
    fn a_wildcard_bind_reads_as_public() {
        // The whole point of the exposure readout. A wildcard bind is
        // internet-facing whenever an interface has a routable address, so it
        // must never be coloured as if it were harmless.
        assert_eq!(classify("0.0.0.0"), Reach::Public);
        assert_eq!(classify("::"), Reach::Public);
    }

    #[test]
    fn interface_scoped_routes_are_lan() {
        assert_eq!(classify("link#12"), Reach::Lan);
        assert_eq!(classify("link#1"), Reach::Lan);
    }

    #[test]
    fn something_unparseable_errs_towards_public() {
        assert_eq!(classify(""), Reach::Public);
        assert_eq!(classify("not an address"), Reach::Public);
    }

    #[test]
    fn public_addresses_are_public() {
        assert_eq!(classify("84.21.7.113"), Reach::Public);
        assert_eq!(classify("1.1.1.1"), Reach::Public);
        assert_eq!(classify("51.75.12.9"), Reach::Public);
    }
}
