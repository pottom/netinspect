//! The staged reachability ladder.
//!
//! Four stages, each gated on the previous succeeding, so a failure is
//! attributed to the first thing that actually broke rather than to everything
//! downstream of it. Stages after a failure are **not attempted**, which is a
//! different fact from "failed" and is reported as such — `DESIGN.md` calls
//! this the single most common way a CLI lies about what it knows.
//!
//! Portable: the stages talk to the network through three small traits, so the
//! whole ladder runs against a mock with no sockets involved.

pub mod gateway;
pub mod http;
pub mod link;
pub mod net;
pub mod resolve;

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::model::{
    CaptivePortal, DnsConfig, HttpStage, Interface, Reachability, ReachabilityState, Stage,
};

/// The name every stage past `gateway` is asked about. Apple's captive portal
/// endpoint is the one every macOS machine already queries, so using it adds no
/// new party to the conversation.
pub const PROBE_HOST: &str = "captive.apple.com";
pub const PROBE_URL: &str = "http://captive.apple.com/hotspot-detect.html";
/// A second, unrelated name. If both resolve to the same address, something is
/// answering every query — a captive portal, before the HTTP stage says so.
pub const CONTROL_HOST: &str = "example.com";

/// Port 53 is the one thing a router is most likely to answer on, and a refused
/// connection proves reachability just as well as an accepted one.
const GATEWAY_PORT: u16 = 53;
const GATEWAY_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("timed out")]
    Timeout,
    #[error("{0}")]
    Failed(String),
}

/// A reply reduced to the three things captive portal detection needs.
#[derive(Debug, Clone)]
pub struct HttpReply {
    pub status: u16,
    pub location: Option<String>,
    pub body: String,
}

#[async_trait::async_trait]
pub trait Connector: Send + Sync {
    /// True when the address answered at all. A refused connection counts:
    /// an RST proves the host is there, which is the question being asked.
    async fn reachable(&self, address: SocketAddr, timeout: Duration) -> bool;
}

#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(
        &self,
        servers: &[IpAddr],
        name: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, ProbeError>;
}

#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// GET with redirects **disabled** — a redirect is the answer, not
    /// something to follow.
    async fn get(&self, url: &str, timeout: Duration) -> Result<HttpReply, ProbeError>;
}

pub struct Ladder<'a> {
    pub connector: &'a dyn Connector,
    pub resolver: &'a dyn Resolver,
    pub http: &'a dyn HttpClient,
    /// Per-probe timeout.
    pub timeout: Duration,
}

impl Ladder<'_> {
    /// The whole ladder must finish inside this, not four times the per-probe
    /// timeout. Stage budgets are carved out of it so all four stages are
    /// still attempted on a slow network.
    fn budget(&self) -> Duration {
        GATEWAY_TIMEOUT + self.timeout
    }

    pub async fn run(&self, interfaces: &[Interface], dns: &DnsConfig) -> Reachability {
        let deadline = Instant::now() + self.budget();
        let remaining = || deadline.saturating_duration_since(Instant::now());

        let mut report = Reachability {
            link: None,
            gateway: None,
            dns: None,
            http: None,
            state: ReachabilityState::Unknown,
            captive_portal: None,
        };

        // 1 — link. No I/O, so no timing.
        let has_link = link::probe(interfaces);
        report.link = Some(Stage {
            ok: has_link,
            ms: None,
        });
        if !has_link {
            report.state = ReachabilityState::LinkDown;
            return report;
        }

        // 2 — gateway.
        let Some(gateway) = link::default_gateway(interfaces) else {
            // No default route: nothing downstream can be attributed, so say
            // that rather than blaming DNS for it.
            report.gateway = Some(Stage { ok: false, ms: None });
            report.state = ReachabilityState::GatewayUnreachable;
            return report;
        };
        let gateway_budget = GATEWAY_TIMEOUT.min(remaining());
        let (ok, elapsed) = timed(bounded(
            gateway_budget,
            self.connector
                .reachable(SocketAddr::new(gateway, GATEWAY_PORT), gateway_budget),
            false,
        ))
        .await;
        report.gateway = Some(Stage {
            ok,
            ms: Some(elapsed),
        });
        if !ok {
            report.state = ReachabilityState::GatewayUnreachable;
            return report;
        }

        // 3 — dns. Half the remaining budget, so the HTTP stage is always
        // reached rather than being squeezed out by a slow resolver.
        let dns_budget = self.timeout.min(remaining() / 2);
        let started = Instant::now();
        let outcome = bounded(
            dns_budget,
            resolve::probe(self.resolver, &dns.servers, dns_budget),
            resolve::Outcome {
                resolved: false,
                every_name_one_address: false,
            },
        )
        .await;
        let elapsed = started.elapsed().as_millis() as u64;
        report.dns = Some(Stage {
            ok: outcome.resolved,
            ms: Some(elapsed),
        });
        if !outcome.resolved {
            report.state = ReachabilityState::DnsFailure;
            return report;
        }

        // 4 — http.
        let http_budget = remaining();
        let started = Instant::now();
        let reply = bounded(
            http_budget,
            self.http.get(PROBE_URL, http_budget),
            Err(ProbeError::Timeout),
        )
        .await;
        let elapsed = started.elapsed().as_millis() as u64;

        let verdict = http::classify(reply.as_ref(), outcome.every_name_one_address);
        report.http = Some(HttpStage {
            ok: verdict.reached,
            ms: Some(elapsed),
            status: reply.as_ref().ok().map(|r| r.status),
        });
        report.state = verdict.state;
        report.captive_portal = verdict.login_url.map(|login_url| CaptivePortal { login_url });
        report
    }
}

/// Hold every stage to its budget here rather than trusting the implementation
/// to honour the timeout it was handed. A collaborator that stalls is exactly
/// the case the overall bound exists for, so the bound cannot depend on it.
async fn bounded<T, F: std::future::Future<Output = T>>(
    budget: Duration,
    future: F,
    on_timeout: T,
) -> T {
    match tokio::time::timeout(budget, future).await {
        Ok(value) => value,
        Err(_) => on_timeout,
    }
}

async fn timed<F: std::future::Future<Output = bool>>(future: F) -> (bool, u64) {
    let started = Instant::now();
    let ok = future.await;
    (ok, started.elapsed().as_millis() as u64)
}

/// The exit code `check` reports for a state (spec §11).
pub fn exit_code(state: ReachabilityState) -> i32 {
    match state {
        ReachabilityState::Online => 0,
        ReachabilityState::LinkDown => 10,
        ReachabilityState::GatewayUnreachable => 11,
        ReachabilityState::DnsFailure => 12,
        ReachabilityState::CaptivePortal => 13,
        // Nothing was determined; that is not a claim about the network.
        ReachabilityState::Unknown => 1,
    }
}

#[cfg(test)]
pub mod mock;

#[cfg(test)]
mod tests {
    use super::mock::MockNetwork;
    use super::*;
    use crate::model::{
        AddressSource, InterfaceKind, InterfaceStatus, Ipv4Entry,
    };

    fn dns() -> DnsConfig {
        DnsConfig {
            servers: vec!["192.168.1.1".parse().unwrap()],
            search_domains: Vec::new(),
            proxy: None,
            split_dns_scopes: 0,
        }
    }

    fn interfaces(with_gateway: bool, with_address: bool) -> Vec<Interface> {
        vec![Interface {
            name: "en0".to_owned(),
            display_name: Some("Wi-Fi".to_owned()),
            kind: InterfaceKind::Wifi,
            status: InterfaceStatus::Connected,
            ipv4: if with_address {
                vec![Ipv4Entry {
                    address: "192.168.1.24".to_owned(),
                    prefix_len: 24,
                    source: AddressSource::Dhcp,
                }]
            } else {
                Vec::new()
            },
            ipv6: Vec::new(),
            gateway: with_gateway.then(|| "192.168.1.1".to_owned()),
            mac: None,
            mtu: None,
            dhcp: None,
            wifi: None,
            vpn: None,
            is_default_route: true,
        }]
    }

    async fn run(net: &MockNetwork, interfaces: &[Interface]) -> Reachability {
        Ladder {
            connector: net,
            resolver: net,
            http: net,
            timeout: Duration::from_millis(2000),
        }
        .run(interfaces, &dns())
        .await
    }

    #[tokio::test]
    async fn a_204_is_online() {
        let report = run(&MockNetwork::online(), &interfaces(true, true)).await;
        assert_eq!(report.state, ReachabilityState::Online);
        assert!(report.captive_portal.is_none());
        assert!(report.http.unwrap().ok);
    }

    #[tokio::test]
    async fn a_redirect_is_a_captive_portal() {
        let report = run(&MockNetwork::redirect(), &interfaces(true, true)).await;
        assert_eq!(report.state, ReachabilityState::CaptivePortal);
        assert_eq!(
            report.captive_portal.unwrap().login_url,
            "http://wifi.example.net/login"
        );
    }

    #[tokio::test]
    async fn a_200_that_is_not_apples_page_is_a_captive_portal() {
        let report = run(&MockNetwork::interception(), &interfaces(true, true)).await;
        assert_eq!(report.state, ReachabilityState::CaptivePortal);
        // With no Location header the request URL is the best guess available.
        assert_eq!(report.captive_portal.unwrap().login_url, PROBE_URL);
    }

    #[tokio::test]
    async fn a_blocked_port_80_is_still_online() {
        // DNS answered, so the internet is reachable; something is filtering
        // web traffic. Calling this "offline" would be wrong.
        let report = run(&MockNetwork::http_blocked(), &interfaces(true, true)).await;
        assert_eq!(report.state, ReachabilityState::Online);
        assert!(!report.http.unwrap().ok, "the stage itself did not succeed");
    }

    #[tokio::test]
    async fn stages_after_a_failure_are_not_attempted() {
        let report = run(&MockNetwork::dns_broken(), &interfaces(true, true)).await;
        assert_eq!(report.state, ReachabilityState::DnsFailure);
        assert!(report.dns.is_some_and(|s| !s.ok));
        // Not attempted is None, never Some(ok: false): saying "failed" about
        // something we never tried is the lie this whole design avoids.
        assert!(report.http.is_none());
    }

    #[tokio::test]
    async fn an_unreachable_gateway_stops_the_ladder() {
        let report = run(&MockNetwork::gateway_down(), &interfaces(true, true)).await;
        assert_eq!(report.state, ReachabilityState::GatewayUnreachable);
        assert!(report.dns.is_none());
        assert!(report.http.is_none());
    }

    #[tokio::test]
    async fn no_address_is_link_down_and_probes_nothing() {
        let report = run(&MockNetwork::online(), &interfaces(true, false)).await;
        assert_eq!(report.state, ReachabilityState::LinkDown);
        assert!(report.gateway.is_none());
        assert!(report.dns.is_none());
        assert!(report.http.is_none());
    }

    #[tokio::test]
    async fn every_name_resolving_alike_is_a_portal_before_http_says_so() {
        // The cheap extra signal: a resolver answering every question with the
        // same address is intercepting, whatever the HTTP stage returns.
        let report = run(&MockNetwork::hijacked_dns(), &interfaces(true, true)).await;
        assert_eq!(report.state, ReachabilityState::CaptivePortal);
    }

    #[tokio::test]
    async fn a_stalling_network_cannot_overrun_the_budget() {
        // The whole point of the bound: an implementation that ignores its
        // timeout must not be able to hang the report.
        let timeout = Duration::from_millis(120);
        let started = Instant::now();
        let report = Ladder {
            connector: &MockNetwork::stalling(),
            resolver: &MockNetwork::stalling(),
            http: &MockNetwork::stalling(),
            timeout,
        }
        .run(&interfaces(true, true), &dns())
        .await;

        let budget = GATEWAY_TIMEOUT + timeout;
        assert!(
            started.elapsed() < budget + Duration::from_millis(150),
            "took {:?}, budget {:?}",
            started.elapsed(),
            budget
        );
        // A gateway that never answered is unreachable, and nothing past it
        // was attempted.
        assert_eq!(report.state, ReachabilityState::GatewayUnreachable);
    }

    #[test]
    fn the_budget_is_the_sum_of_two_stages_not_four() {
        let ladder = Ladder {
            connector: &MockNetwork::online(),
            resolver: &MockNetwork::online(),
            http: &MockNetwork::online(),
            timeout: Duration::from_millis(2000),
        };
        assert_eq!(ladder.budget(), Duration::from_millis(2500));
    }

    #[test]
    fn exit_codes_match_the_specification() {
        assert_eq!(exit_code(ReachabilityState::Online), 0);
        assert_eq!(exit_code(ReachabilityState::LinkDown), 10);
        assert_eq!(exit_code(ReachabilityState::GatewayUnreachable), 11);
        assert_eq!(exit_code(ReachabilityState::DnsFailure), 12);
        assert_eq!(exit_code(ReachabilityState::CaptivePortal), 13);
    }
}
