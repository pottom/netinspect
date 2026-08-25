//! Tunnel classification (spec 6.5).
//!
//! macOS does not publish a tunnel's protocol anywhere reliable: a `utun`
//! created by a NetworkExtension carries no service `Type`, and there are no
//! `IPSec`/`VPN` keys in the dynamic store for it. Two signals do exist, and
//! neither covers the general case:
//!
//! * WireGuard's userspace implementations leave a control socket under
//!   `/var/run/wireguard/`.
//! * A service configured the old way names its protocol in its `Interface`
//!   dictionary.
//!
//! When neither answers, the protocol is reported as unknown. The tunnel's
//! presence is still worth showing, which is why this never fails the run.

use std::path::Path;

use super::services::Service;
use crate::model::VpnDetail;

const WIREGUARD_RUN_DIR: &str = "/var/run/wireguard";

pub fn detail(iface: &str, service: Option<&Service>) -> VpnDetail {
    VpnDetail {
        protocol: protocol(Path::new(WIREGUARD_RUN_DIR), iface, service),
        // The endpoint and handshake age live behind the WireGuard control
        // socket, which needs a uapi conversation rather than a stat.
        endpoint: None,
        last_handshake_seconds: None,
    }
}

fn protocol(wireguard_dir: &Path, iface: &str, service: Option<&Service>) -> Option<String> {
    if wireguard_dir.join(format!("{iface}.sock")).exists() {
        return Some("WireGuard".to_owned());
    }
    match service.and_then(|s| s.hardware.as_deref()) {
        Some("IPSec") => Some("IPSec".to_owned()),
        Some("L2TP") => Some("L2TP".to_owned()),
        Some("PPP") => Some("PPP".to_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(hardware: &str) -> Service {
        Service {
            device: "utun3".to_owned(),
            user_name: None,
            hardware: Some(hardware.to_owned()),
            config_method_v4: None,
        }
    }

    #[test]
    fn a_wireguard_socket_identifies_the_tunnel() {
        let dir = std::env::temp_dir().join("netinspect-vpn-test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("utun7.sock"), b"").unwrap();

        assert_eq!(protocol(&dir, "utun7", None).as_deref(), Some("WireGuard"));
        assert_eq!(protocol(&dir, "utun8", None), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn falls_back_to_the_configured_service_type() {
        let missing = Path::new("/nonexistent/wireguard");
        assert_eq!(
            protocol(missing, "utun3", Some(&service("IPSec"))).as_deref(),
            Some("IPSec")
        );
        // An unrecognised type is unknown, not guessed at.
        assert_eq!(protocol(missing, "utun3", Some(&service("Ethernet"))), None);
        assert_eq!(protocol(missing, "utun3", None), None);
    }
}
