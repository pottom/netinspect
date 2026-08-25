//! Wi-Fi radio detail.
//!
//! CoreWLAN is the supported path and yields RSSI, PHY mode and transmit rate.
//! The SSID is a different story: from macOS 14 it requires Location Services
//! authorization, which an unbundled CLI cannot obtain, so `ssid()` returns
//! `nil`. Two fallbacks follow, in order of how much they can be trusted:
//!
//! 1. `CachedScanRecord` in the dynamic store — native, undocumented (see
//!    `scan_record`).
//! 2. The subprocess ladder in `ssid_helper` — opt-out, and gated on the same
//!    privacy wall, so usually empty too.
//!
//! Whichever answers, the source is recorded and shown to the user. Nobody
//! should have to guess whether a value came from a supported API or a scraped
//! command.
//!
//! On Linux the same data comes from nl80211 with no permission prompt, so that
//! backend will simply fill in the SSID this one leaves empty. The `Snapshot`
//! type does not change.

use objc2_core_wlan::{CWPHYMode, CWWiFiClient};
use objc2_foundation::NSString;
use system_configuration::dynamic_store::SCDynamicStore;

use super::cf::{self, Value};
use super::scan_record;
use super::ssid_helper;
use crate::model::{SsidSource, WifiDetail};
use crate::sys::HelperPolicy;

/// Collect what can be read for one interface. `None` when the interface is
/// not a Wi-Fi interface at all — the renderer then omits the row rather than
/// printing "unknown", and the run never fails because of it.
pub fn collect(store: &SCDynamicStore, iface: &str, policy: HelperPolicy) -> Option<WifiDetail> {
    let radio = radio_detail(iface)?;

    let (ssid, ssid_source) = match radio.ssid {
        Some(ssid) => (Some(ssid), Some(SsidSource::CoreWlan)),
        None => resolve_ssid(store, iface, policy),
    };

    Some(WifiDetail {
        ssid,
        ssid_source,
        rssi_dbm: radio.rssi_dbm,
        phy_mode: radio.phy_mode,
        rate_mbps: radio.rate_mbps,
    })
}

fn resolve_ssid(
    store: &SCDynamicStore,
    iface: &str,
    policy: HelperPolicy,
) -> (Option<String>, Option<SsidSource>) {
    if let Some(ssid) = ssid_from_store(store, iface) {
        return (Some(ssid), Some(SsidSource::DynamicStore));
    }
    match ssid_helper::ssid(iface, policy) {
        Some((ssid, source)) => (Some(ssid), Some(source)),
        None => (None, None),
    }
}

/// `SSID_STR` is blanked by the privacy gating on macOS 14+, but the scan
/// record next to it is not — yet.
fn ssid_from_store(store: &SCDynamicStore, iface: &str) -> Option<String> {
    let airport = cf::read(store, &format!("State:/Network/Interface/{iface}/AirPort"))?;

    if let Some(ssid) = airport.get("SSID_STR").and_then(Value::as_str) {
        if !ssid.is_empty() {
            return Some(ssid.to_owned());
        }
    }
    let blob = airport.get("CachedScanRecord").and_then(Value::as_data)?;
    scan_record::ssid_from_scan_record(blob)
}

struct RadioDetail {
    ssid: Option<String>,
    rssi_dbm: Option<i32>,
    phy_mode: Option<String>,
    rate_mbps: Option<u32>,
}

/// Everything CoreWLAN will tell an unbundled binary.
fn radio_detail(iface: &str) -> Option<RadioDetail> {
    // Safety: plain Objective-C property reads on objects owned by the shared
    // client. Every accessor is documented to return nil or zero rather than
    // raising when the interface is not associated.
    unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let interface = client.interfaceWithName(Some(&NSString::from_str(iface)))?;

        let rssi = interface.rssiValue();
        let rate = interface.transmitRate();

        Some(RadioDetail {
            ssid: interface
                .ssid()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty()),
            // Zero means "not associated", not "0 dBm".
            rssi_dbm: (rssi != 0).then_some(rssi as i32),
            phy_mode: phy_mode_name(interface.activePHYMode()),
            rate_mbps: (rate > 0.0).then_some(rate as u32),
        })
    }
}

fn phy_mode_name(mode: CWPHYMode) -> Option<String> {
    let name = match mode.0 {
        1 => "802.11a",
        2 => "802.11b",
        3 => "802.11g",
        4 => "802.11n",
        5 => "802.11ac",
        6 => "802.11ax",
        _ => return None,
    };
    Some(name.to_owned())
}
