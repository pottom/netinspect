//! The public address, and what can honestly be said about it.
//!
//! This is the only part of netinspect that tells a third party anything. It
//! sends this machine's IP to one provider and nothing else, it is disabled by
//! `--no-lookup` or `NETINSPECT_NO_LOOKUP=1`, and the answer is cached so a
//! repeated run does not repeat the disclosure.
//!
//! Portable: it talks to the network through the same `HttpClient` trait the
//! probes use, so it runs against a mock with no sockets involved.

pub mod cache;

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::model::{Interface, InterfaceKind, PublicAddress};
use crate::probe::HttpClient;

/// The provider. Named here rather than buried in a request so that changing
/// who is told about this machine is a visible edit.
pub const DEFAULT_ENDPOINT: &str = "https://ipinfo.io";

/// What the provider said, before any interpretation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub ip: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
}

impl Observation {
    fn address_only(ip: String) -> Self {
        Observation {
            ip,
            city: None,
            region: None,
            country: None,
            latitude: None,
            longitude: None,
            timezone: None,
            asn: None,
            org: None,
        }
    }
}

/// What was seen with no VPN up. Without one of these there is nothing to
/// compare against, and the tool says nothing about whether a tunnel is
/// carrying the traffic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub asn: Option<String>,
    pub country: Option<String>,
    pub observed_at_unix: i64,
}

/// Where to ask. `NETINSPECT_GEO_ENDPOINT` overrides it for a managed machine
/// that runs its own.
pub fn endpoint() -> String {
    std::env::var("NETINSPECT_GEO_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned())
        .trim_end_matches('/')
        .to_owned()
}

pub fn lookup_disabled() -> bool {
    matches!(
        std::env::var("NETINSPECT_NO_LOOKUP").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Ask the provider. On a rate limit, fall back to the plain-address endpoint
/// at the same provider: the address alone is still worth having, and falling
/// back to a *different* provider would tell a second party about this machine
/// to work around the first one being busy.
pub async fn lookup(
    client: &dyn HttpClient,
    endpoint: &str,
    timeout: Duration,
) -> Option<Observation> {
    let reply = client.get(&format!("{endpoint}/json"), timeout).await.ok()?;
    match reply.status {
        200 => parse_json(&reply.body),
        429 => {
            let reply = client.get(&format!("{endpoint}/ip"), timeout).await.ok()?;
            (reply.status == 200).then(|| parse_plain(&reply.body))?
        }
        _ => None,
    }
}

/// The provider's JSON, reduced to what the report uses. Everything is
/// optional: a provider that stops returning a field must not take the address
/// down with it.
fn parse_json(body: &str) -> Option<Observation> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .filter(|s| !s.is_empty())
    };

    let ip = text("ip")?;
    let (latitude, longitude) = match text("loc").as_deref().and_then(parse_loc) {
        Some((lat, lon)) => (Some(lat), Some(lon)),
        None => (None, None),
    };
    let (asn, org) = split_org(text("org").as_deref());

    Some(Observation {
        ip,
        city: text("city"),
        region: text("region"),
        country: text("country"),
        latitude,
        longitude,
        timezone: text("timezone"),
        asn,
        org,
    })
}

fn parse_plain(body: &str) -> Option<Observation> {
    let ip = body.trim();
    ip.parse::<IpAddr>()
        .ok()
        .map(|ip| Observation::address_only(ip.to_string()))
}

fn parse_loc(loc: &str) -> Option<(f64, f64)> {
    let (lat, lon) = loc.split_once(',')?;
    Some((lat.trim().parse().ok()?, lon.trim().parse().ok()?))
}

/// `"AS20845 DIGI Tavkozlesi es Szolgaltato Kft."` → the number and the name.
/// A provider that returns only a name keeps it.
fn split_org(org: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(org) = org else {
        return (None, None);
    };
    let Some((head, rest)) = org.split_once(' ') else {
        return (None, Some(org.to_owned()));
    };
    let looks_like_asn = head.len() > 2
        && head.starts_with("AS")
        && head[2..].chars().all(|c| c.is_ascii_digit());
    if looks_like_asn {
        (Some(head.to_owned()), Some(rest.trim().to_owned()))
    } else {
        (None, Some(org.to_owned()))
    }
}

/// What a cached answer was valid for. A change here invalidates it before the
/// TTL does: the address is a property of the route out, not of the clock.
pub fn fingerprint(interfaces: &[Interface]) -> String {
    let default_route = interfaces
        .iter()
        .find(|iface| iface.is_default_route)
        .map(|iface| {
            format!(
                "{}@{}",
                iface.name,
                iface.gateway.as_deref().unwrap_or("none")
            )
        })
        .unwrap_or_else(|| "none".to_owned());

    let mut tunnels: Vec<&str> = interfaces
        .iter()
        .filter(|iface| iface.kind == InterfaceKind::Vpn && iface.is_active())
        .map(|iface| iface.name.as_str())
        .collect();
    tunnels.sort_unstable();

    format!("{default_route}|{}", tunnels.join(","))
}

pub fn vpn_active(interfaces: &[Interface]) -> bool {
    interfaces
        .iter()
        .any(|iface| iface.kind == InterfaceKind::Vpn && iface.is_active())
}

/// Turn an observation into the report's view of it.
pub fn assemble(
    observation: &Observation,
    baseline: Option<&Baseline>,
    system_timezone: Option<&str>,
    vpn_active: bool,
    cached_at: Option<String>,
) -> PublicAddress {
    let ip: Option<IpAddr> = observation.ip.parse().ok();
    PublicAddress {
        ipv4: ip.filter(IpAddr::is_ipv4).map(|ip| ip.to_string()),
        ipv6: ip.filter(IpAddr::is_ipv6).map(|ip| ip.to_string()),
        asn: observation.asn.clone(),
        org: observation.org.clone(),
        city: observation.city.clone(),
        region: observation.region.clone(),
        country: observation.country.clone(),
        latitude: observation.latitude,
        longitude: observation.longitude,
        // The provider does not report one. Saying nothing beats inventing a
        // radius around someone's location.
        accuracy_km: None,
        timezone: observation.timezone.clone(),
        timezone_matches_system: match (&observation.timezone, system_timezone) {
            (Some(theirs), Some(ours)) => Some(theirs == ours),
            _ => None,
        },
        via_vpn: via_vpn(vpn_active, observation.asn.as_deref(), baseline),
        cached_at,
    }
}

/// Is the traffic actually going through the tunnel?
///
/// `None` means the question cannot be answered, and that is the usual case:
/// with no VPN up there is nothing to ask, and with no record of what this
/// machine looks like *without* one there is nothing to compare against.
/// Guessing here would either raise a false alarm or, worse, quietly reassure.
fn via_vpn(vpn_active: bool, asn: Option<&str>, baseline: Option<&Baseline>) -> Option<bool> {
    if !vpn_active {
        return None;
    }
    let baseline = baseline?.asn.as_deref()?;
    // The same network as with the tunnel down means the tunnel is not
    // carrying this traffic.
    Some(asn? != baseline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{InterfaceStatus, Ipv4Entry, AddressSource};

    const IPINFO: &str = r#"{
        "ip": "84.21.7.113",
        "hostname": "example.pool.telekom.hu",
        "city": "Budapest",
        "region": "Budapest",
        "country": "HU",
        "loc": "47.4980,19.0400",
        "org": "AS5483 Magyar Telekom",
        "postal": "1007",
        "timezone": "Europe/Budapest"
    }"#;

    #[test]
    fn the_provider_response_is_reduced_to_what_the_report_uses() {
        let observed = parse_json(IPINFO).unwrap();
        assert_eq!(observed.ip, "84.21.7.113");
        assert_eq!(observed.city.as_deref(), Some("Budapest"));
        assert_eq!(observed.country.as_deref(), Some("HU"));
        assert_eq!(observed.latitude, Some(47.4980));
        assert_eq!(observed.longitude, Some(19.0400));
        assert_eq!(observed.asn.as_deref(), Some("AS5483"));
        assert_eq!(observed.org.as_deref(), Some("Magyar Telekom"));
        assert_eq!(observed.timezone.as_deref(), Some("Europe/Budapest"));
    }

    #[test]
    fn a_missing_field_does_not_take_the_address_down_with_it() {
        let observed = parse_json(r#"{"ip":"1.2.3.4"}"#).unwrap();
        assert_eq!(observed.ip, "1.2.3.4");
        assert!(observed.city.is_none());
        assert!(observed.asn.is_none());
        // No address at all is the only thing worth failing on.
        assert!(parse_json(r#"{"city":"Budapest"}"#).is_none());
        assert!(parse_json("not json").is_none());
    }

    #[test]
    fn an_org_without_an_asn_keeps_its_name() {
        assert_eq!(
            split_org(Some("AS5483 Magyar Telekom")),
            (Some("AS5483".to_owned()), Some("Magyar Telekom".to_owned()))
        );
        assert_eq!(
            split_org(Some("Some Provider Ltd")),
            (None, Some("Some Provider Ltd".to_owned()))
        );
        assert_eq!(split_org(Some("ASNotANumber Thing")).0, None);
        assert_eq!(split_org(None), (None, None));
    }

    #[test]
    fn the_plain_fallback_accepts_only_an_address() {
        assert_eq!(parse_plain("84.21.7.113\n").unwrap().ip, "84.21.7.113");
        assert_eq!(parse_plain("2001:db8::1").unwrap().ip, "2001:db8::1");
        assert!(parse_plain("rate limited").is_none());
    }

    fn baseline(asn: &str) -> Baseline {
        Baseline {
            asn: Some(asn.to_owned()),
            country: Some("HU".to_owned()),
            observed_at_unix: 0,
        }
    }

    #[test]
    fn a_tunnel_that_changes_the_network_is_carrying_the_traffic() {
        assert_eq!(via_vpn(true, Some("AS9009"), Some(&baseline("AS5483"))), Some(true));
    }

    #[test]
    fn the_same_network_with_a_tunnel_up_is_a_leak() {
        assert_eq!(via_vpn(true, Some("AS5483"), Some(&baseline("AS5483"))), Some(false));
    }

    #[test]
    fn without_evidence_the_question_goes_unanswered() {
        // No tunnel: nothing to ask.
        assert_eq!(via_vpn(false, Some("AS5483"), Some(&baseline("AS5483"))), None);
        // Never seen this machine without a tunnel: nothing to compare to.
        assert_eq!(via_vpn(true, Some("AS9009"), None), None);
        // The provider did not say which network.
        assert_eq!(via_vpn(true, None, Some(&baseline("AS5483"))), None);
        // A baseline with no ASN is not a baseline.
        let empty = Baseline {
            asn: None,
            country: None,
            observed_at_unix: 0,
        };
        assert_eq!(via_vpn(true, Some("AS9009"), Some(&empty)), None);
    }

    #[test]
    fn the_timezone_is_compared_only_when_both_are_known() {
        let observed = parse_json(IPINFO).unwrap();
        let matching = assemble(&observed, None, Some("Europe/Budapest"), false, None);
        assert_eq!(matching.timezone_matches_system, Some(true));

        let differing = assemble(&observed, None, Some("America/New_York"), false, None);
        assert_eq!(differing.timezone_matches_system, Some(false));

        // An unknown system zone is not a mismatch.
        let unknown = assemble(&observed, None, None, false, None);
        assert_eq!(unknown.timezone_matches_system, None);
    }

    #[test]
    fn an_address_lands_in_the_field_for_its_family() {
        let v4 = assemble(&Observation::address_only("1.2.3.4".to_owned()), None, None, false, None);
        assert_eq!(v4.ipv4.as_deref(), Some("1.2.3.4"));
        assert!(v4.ipv6.is_none());

        let v6 = assemble(
            &Observation::address_only("2001:db8::1".to_owned()),
            None,
            None,
            false,
            None,
        );
        assert!(v6.ipv4.is_none());
        assert_eq!(v6.ipv6.as_deref(), Some("2001:db8::1"));
    }

    fn interface(name: &str, kind: InterfaceKind, active: bool, default: bool) -> Interface {
        Interface {
            name: name.to_owned(),
            display_name: None,
            kind,
            status: if active {
                InterfaceStatus::Up
            } else {
                InterfaceStatus::Inactive
            },
            ipv4: vec![Ipv4Entry {
                address: "10.0.0.1".to_owned(),
                prefix_len: 24,
                source: AddressSource::Dhcp,
            }],
            ipv6: Vec::new(),
            gateway: default.then(|| "192.168.1.1".to_owned()),
            mac: None,
            mtu: None,
            dhcp: None,
            wifi: None,
            vpn: None,
            is_default_route: default,
        }
    }

    #[test]
    fn the_fingerprint_changes_when_the_route_out_does() {
        let wifi = interface("en0", InterfaceKind::Wifi, true, true);
        let base = fingerprint(std::slice::from_ref(&wifi));

        // A tunnel coming up is a different route out, whatever the clock says.
        let with_vpn = fingerprint(&[wifi.clone(), interface("utun4", InterfaceKind::Vpn, true, false)]);
        assert_ne!(base, with_vpn);

        // An idle tunnel is not.
        let idle = fingerprint(&[wifi.clone(), interface("utun9", InterfaceKind::Vpn, false, false)]);
        assert_eq!(base, idle);

        // A different gateway on the same interface is a different network.
        let mut moved = wifi.clone();
        moved.gateway = Some("10.0.0.1".to_owned());
        assert_ne!(base, fingerprint(&[moved]));
    }

    #[test]
    fn tunnel_order_does_not_change_the_fingerprint() {
        let wifi = interface("en0", InterfaceKind::Wifi, true, true);
        let a = interface("utun4", InterfaceKind::Vpn, true, false);
        let b = interface("utun7", InterfaceKind::Vpn, true, false);
        assert_eq!(
            fingerprint(&[wifi.clone(), a.clone(), b.clone()]),
            fingerprint(&[wifi, b, a])
        );
    }
}
