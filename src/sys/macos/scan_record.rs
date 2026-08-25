//! SSID recovery from the `CachedScanRecord` blob.
//!
//! `State:/Network/Interface/<if>/AirPort` carries a `CachedScanRecord` binary
//! plist holding an `NSKeyedArchiver` graph that describes the scan result for
//! the network the interface joined. On macOS 14+ the neighbouring `SSID_STR`
//! key is blanked by the privacy gating, but this blob is not — so it is the
//! last native (non-subprocess) source of the SSID.
//!
//! It is undocumented and Apple may blank it too. Every failure path here
//! returns `None` quietly; nothing in this file may panic or surface an error.

use plist::Value as Plist;

/// Pull the SSID out of a `CachedScanRecord` blob, if it is in there.
pub fn ssid_from_scan_record(blob: &[u8]) -> Option<String> {
    let root = plist::from_bytes::<Plist>(blob).ok()?;
    let objects = root.as_dictionary()?.get("$objects")?.as_array()?;

    for object in objects {
        let Some(dict) = object.as_dictionary() else {
            continue;
        };
        let (Some(keys), Some(values)) = (
            dict.get("NS.keys").and_then(Plist::as_array),
            dict.get("NS.objects").and_then(Plist::as_array),
        ) else {
            continue;
        };

        for (key, value) in keys.iter().zip(values) {
            if resolve_string(objects, key).as_deref() != Some("SSID_STR") {
                continue;
            }
            if let Some(ssid) = resolve_string(objects, value) {
                if !ssid.is_empty() {
                    return Some(ssid);
                }
            }
        }
    }
    None
}

/// Follow a `CF$UID` reference into `$objects` and read it as a string.
fn resolve_string(objects: &[Plist], reference: &Plist) -> Option<String> {
    let index = reference.as_uid()?.get() as usize;
    objects.get(index)?.as_string().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_none_not_a_panic() {
        assert_eq!(ssid_from_scan_record(b""), None);
        assert_eq!(ssid_from_scan_record(b"not a plist at all"), None);
        assert_eq!(ssid_from_scan_record(&[0u8; 512]), None);
    }
}
