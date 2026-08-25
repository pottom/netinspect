//! Resolver configuration from `SCDynamicStore`.
//!
//! `/etc/resolv.conf` is deliberately not read: on macOS it is a compatibility
//! shim and does not reflect per-interface resolvers.

use system_configuration::dynamic_store::SCDynamicStore;

use super::cf::{self, Value};
use crate::model::DnsConfig;

pub fn collect(store: &SCDynamicStore) -> DnsConfig {
    let global = cf::read(store, "State:/Network/Global/DNS");

    let servers = global
        .as_ref()
        .and_then(|v| v.get("ServerAddresses"))
        .map(Value::string_list)
        .unwrap_or_default();
    let search_domains = global
        .as_ref()
        .and_then(|v| v.get("SearchDomains"))
        .map(Value::string_list)
        .unwrap_or_default();

    DnsConfig {
        servers,
        search_domains,
        proxy: proxy_summary(store),
        split_dns_scopes: scoped_resolver_count(store),
    }
}

/// A one-line description of the active proxy, or `None` for a direct
/// connection. Only enabled proxies are reported — macOS keeps stale host and
/// port values around for disabled ones.
fn proxy_summary(store: &SCDynamicStore) -> Option<String> {
    let proxies = cf::read(store, "State:/Network/Global/Proxies")?;

    if proxies.get("ProxyAutoConfigEnable").and_then(Value::as_i64) == Some(1) {
        if let Some(url) = proxies
            .get("ProxyAutoConfigURLString")
            .and_then(Value::as_str)
        {
            return Some(format!("pac {url}"));
        }
        return Some("pac".to_owned());
    }

    let mut parts = Vec::new();
    for (enable, host, port, label) in [
        ("HTTPEnable", "HTTPProxy", "HTTPPort", "http"),
        ("HTTPSEnable", "HTTPSProxy", "HTTPSPort", "https"),
        ("SOCKSEnable", "SOCKSProxy", "SOCKSPort", "socks"),
    ] {
        if proxies.get(enable).and_then(Value::as_i64) != Some(1) {
            continue;
        }
        match (
            proxies.get(host).and_then(Value::as_str),
            proxies.get(port).and_then(Value::as_i64),
        ) {
            (Some(h), Some(p)) => parts.push(format!("{label} {h}:{p}")),
            (Some(h), None) => parts.push(format!("{label} {h}")),
            _ => parts.push(label.to_owned()),
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("  ·  "))
    }
}

/// How many services carry their own resolver. More than one means split DNS,
/// which is the normal state with a VPN up.
fn scoped_resolver_count(store: &SCDynamicStore) -> u32 {
    cf::read_keys(store, "State:/Network/Service/.*/DNS")
        .iter()
        .filter(|key| has_service_id(key))
        .count() as u32
}

/// `State:/Network/Service//DNS` (empty id) is a placeholder, not a scope.
fn has_service_id(key: &str) -> bool {
    key.strip_prefix("State:/Network/Service/")
        .and_then(|rest| rest.strip_suffix("/DNS"))
        .is_some_and(|id| !id.is_empty())
}

#[cfg(test)]
mod tests {
    use super::has_service_id;

    #[test]
    fn ignores_the_empty_service_placeholder() {
        assert!(has_service_id("State:/Network/Service/utun4/DNS"));
        assert!(!has_service_id("State:/Network/Service//DNS"));
        assert!(!has_service_id("State:/Network/Global/DNS"));
    }
}
