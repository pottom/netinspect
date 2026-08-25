//! Stage 3 — DNS.
//!
//! Resolves the probe host against the resolvers the system is actually
//! configured with, not whatever the process would use by default. A second,
//! unrelated name goes out at the same time: a resolver that answers every
//! question with one address is intercepting, and that is worth knowing before
//! the HTTP stage confirms it.

use std::net::IpAddr;
use std::time::Duration;

use super::{Resolver, CONTROL_HOST, PROBE_HOST};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub resolved: bool,
    /// Two unrelated names came back with the same address.
    pub every_name_one_address: bool,
}

pub async fn probe(resolver: &dyn Resolver, servers: &[String], timeout: Duration) -> Outcome {
    let servers: Vec<IpAddr> = servers.iter().filter_map(|s| s.parse().ok()).collect();
    if servers.is_empty() {
        // Nothing configured to ask. That is a DNS failure, not a silent pass.
        return Outcome {
            resolved: false,
            every_name_one_address: false,
        };
    }

    // Concurrently, so the extra signal costs no wall-clock time.
    let (probe, control) = tokio::join!(
        resolver.resolve(&servers, PROBE_HOST, timeout),
        resolver.resolve(&servers, CONTROL_HOST, timeout),
    );

    let Ok(probe) = probe else {
        return Outcome {
            resolved: false,
            every_name_one_address: false,
        };
    };
    if probe.is_empty() {
        return Outcome {
            resolved: false,
            every_name_one_address: false,
        };
    }

    Outcome {
        resolved: true,
        every_name_one_address: control.is_ok_and(|control| same_answer(&probe, &control)),
    }
}

/// Two unrelated names sharing every address they resolve to.
fn same_answer(a: &[IpAddr], b: &[IpAddr]) -> bool {
    !a.is_empty() && !b.is_empty() && a.iter().all(|address| b.contains(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn one_address_for_everything_is_interception() {
        assert!(same_answer(&[ip("10.0.0.1")], &[ip("10.0.0.1")]));
    }

    #[test]
    fn ordinary_answers_differ() {
        assert!(!same_answer(&[ip("17.253.144.10")], &[ip("93.184.216.34")]));
        // An empty answer proves nothing either way.
        assert!(!same_answer(&[], &[ip("10.0.0.1")]));
        assert!(!same_answer(&[ip("10.0.0.1")], &[]));
    }

    #[test]
    fn a_shared_cdn_address_still_counts_only_when_every_address_matches() {
        // A name with two addresses, one shared with the control: not enough.
        assert!(!same_answer(
            &[ip("10.0.0.1"), ip("10.0.0.2")],
            &[ip("10.0.0.1")]
        ));
    }
}
