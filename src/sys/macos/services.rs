//! Configured network services, read from `Setup:/Network/Service/<id>/…`.
//!
//! One key family answers three questions at once: which BSD device a service
//! is bound to, what the user calls it in System Settings, and how its
//! addresses are configured. That is why this backend does not go through
//! `SCPreferences`/`SCNetworkService` at all.

use system_configuration::dynamic_store::SCDynamicStore;

use super::cf::{self, Value};

#[derive(Debug, Clone)]
pub struct Service {
    pub device: String,
    /// The name shown in System Settings, e.g. "Wi-Fi".
    pub user_name: Option<String>,
    /// `AirPort`, `Ethernet`, … — a hint for kind classification.
    pub hardware: Option<String>,
    pub config_method_v4: Option<String>,
}

/// Load every configured service, keyed by BSD device name.
pub fn load(store: &SCDynamicStore) -> Vec<Service> {
    let mut services = Vec::new();
    for key in cf::read_keys(store, "Setup:/Network/Service/.*/Interface") {
        let Some(id) = service_id(&key) else { continue };
        let Some(iface) = cf::read(store, &key) else {
            continue;
        };
        let Some(device) = iface.get("DeviceName").and_then(Value::as_str) else {
            continue;
        };
        services.push(Service {
            device: device.to_owned(),
            user_name: iface
                .get("UserDefinedName")
                .and_then(Value::as_str)
                .map(str::to_owned),
            hardware: iface
                .get("Hardware")
                .and_then(Value::as_str)
                .map(str::to_owned),
            config_method_v4: config_method(store, &id, "IPv4"),
        });
    }
    services
}

/// Find the service describing a BSD device.
pub fn for_device<'a>(services: &'a [Service], device: &str) -> Option<&'a Service> {
    services.iter().find(|s| s.device == device)
}

fn config_method(store: &SCDynamicStore, id: &str, family: &str) -> Option<String> {
    let key = format!("Setup:/Network/Service/{id}/{family}");
    cf::read(store, &key)?
        .get("ConfigMethod")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// `Setup:/Network/Service/<id>/Interface` → `<id>`.
fn service_id(key: &str) -> Option<String> {
    let rest = key.strip_prefix("Setup:/Network/Service/")?;
    let id = rest.strip_suffix("/Interface")?;
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some(id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::service_id;

    #[test]
    fn extracts_service_id() {
        assert_eq!(
            service_id("Setup:/Network/Service/ABC-123/Interface").as_deref(),
            Some("ABC-123")
        );
        assert_eq!(service_id("Setup:/Network/Service//Interface"), None);
        assert_eq!(service_id("State:/Network/Global/IPv4"), None);
        assert_eq!(service_id("Setup:/Network/Service/A/B/Interface"), None);
    }
}
