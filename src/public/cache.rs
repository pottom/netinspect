//! The geo cache.
//!
//! Two jobs, and the second is the reason it exists at all. It keeps a repeated
//! run from repeating the disclosure to the provider, and it remembers what
//! this machine looks like with no tunnel up — which is the only way the leak
//! check in `via_vpn` has anything to compare against.
//!
//! Written with mode `0600`: it records where this machine is.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{Baseline, Observation};

/// How long an answer is worth reusing. The address rarely changes inside it,
/// and the fingerprint catches the times it does.
pub const TTL_SECONDS: i64 = 15 * 60;

const FILE: &str = "geo.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cache {
    pub schema: u32,
    /// What `observation` was valid for.
    pub fingerprint: String,
    pub fetched_at_unix: i64,
    pub observation: Observation,
    /// What this machine looks like with no tunnel up.
    pub baseline: Option<Baseline>,
}

/// `NETINSPECT_CACHE_DIR`, then `XDG_CACHE_HOME/netinspect`, then
/// `~/.cache/netinspect`.
pub fn directory() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("NETINSPECT_CACHE_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(dir).join("netinspect"));
    }
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".cache").join("netinspect"))
}

pub fn load(directory: &Path) -> Option<Cache> {
    let text = std::fs::read_to_string(directory.join(FILE)).ok()?;
    let cache: Cache = serde_json::from_str(&text).ok()?;
    // A cache written by a future version is not one this version understands.
    (cache.schema == 1).then_some(cache)
}

pub fn store(directory: &Path, cache: &Cache) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)?;
    let text = serde_json::to_string(cache)?;

    // Create with the mode already set rather than relaxing it afterwards:
    // between the two there would be a moment where it is world-readable.
    let path = directory.join(FILE);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(text.as_bytes())?;
    // An existing file keeps its old mode, so set it explicitly too.
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(())
}

/// Whether a cached answer still describes this machine. The fingerprint is
/// checked first: a changed route out invalidates it however recent it is.
pub fn is_fresh(cache: &Cache, fingerprint: &str, now_unix: i64) -> bool {
    if cache.fingerprint != fingerprint {
        return false;
    }
    let age = now_unix - cache.fetched_at_unix;
    (0..TTL_SECONDS).contains(&age)
}

/// The baseline to carry forward. A fresh observation taken with no tunnel up
/// becomes the new one; otherwise whatever was already known stands.
pub fn baseline_after(
    previous: Option<Baseline>,
    observation: &Observation,
    vpn_active: bool,
    now_unix: i64,
) -> Option<Baseline> {
    if vpn_active {
        return previous;
    }
    Some(Baseline {
        asn: observation.asn.clone(),
        country: observation.country.clone(),
        observed_at_unix: now_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(asn: &str) -> Observation {
        Observation {
            ip: "84.21.7.113".to_owned(),
            city: Some("Budapest".to_owned()),
            region: None,
            country: Some("HU".to_owned()),
            latitude: None,
            longitude: None,
            timezone: Some("Europe/Budapest".to_owned()),
            asn: Some(asn.to_owned()),
            org: Some("Magyar Telekom".to_owned()),
        }
    }

    fn cache(fingerprint: &str, fetched_at_unix: i64) -> Cache {
        Cache {
            schema: 1,
            fingerprint: fingerprint.to_owned(),
            fetched_at_unix,
            observation: observation("AS5483"),
            baseline: None,
        }
    }

    #[test]
    fn a_changed_route_invalidates_a_fresh_answer() {
        let cache = cache("en0@192.168.1.1|", 1000);
        assert!(is_fresh(&cache, "en0@192.168.1.1|", 1000));
        // Same second, different route out: the address is a property of the
        // route, not of the clock.
        assert!(!is_fresh(&cache, "en0@192.168.1.1|utun4", 1000));
    }

    #[test]
    fn an_answer_expires_and_a_clock_that_went_backwards_is_not_trusted() {
        let cache = cache("en0", 1000);
        assert!(is_fresh(&cache, "en0", 1000 + TTL_SECONDS - 1));
        assert!(!is_fresh(&cache, "en0", 1000 + TTL_SECONDS));
        // A cache stamped in the future is a clock change, not a fresh answer.
        assert!(!is_fresh(&cache, "en0", 999));
    }

    #[test]
    fn the_baseline_only_records_what_was_seen_without_a_tunnel() {
        let taken = baseline_after(None, &observation("AS5483"), false, 100).unwrap();
        assert_eq!(taken.asn.as_deref(), Some("AS5483"));
        assert_eq!(taken.observed_at_unix, 100);

        // With a tunnel up the observation says nothing about this machine's
        // own network, so the previous baseline must survive untouched.
        let kept = baseline_after(Some(taken.clone()), &observation("AS9009"), true, 200);
        assert_eq!(kept, Some(taken));

        // And with no previous one, a tunnelled observation must not become
        // the baseline the leak check compares against.
        assert_eq!(baseline_after(None, &observation("AS9009"), true, 200), None);
    }

    #[test]
    fn a_round_trip_keeps_the_answer_and_the_file_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!("netinspect-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);

        let mut written = cache("en0@192.168.1.1|", 4242);
        written.baseline = Some(Baseline {
            asn: Some("AS5483".to_owned()),
            country: Some("HU".to_owned()),
            observed_at_unix: 4000,
        });
        store(&directory, &written).unwrap();

        assert_eq!(load(&directory).as_ref(), Some(&written));

        // It records where this machine is; nobody else on the box needs it.
        let mode = std::fs::metadata(directory.join(FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "geo.json is {:o}", mode & 0o777);

        // Writing again over an existing file must not relax it.
        store(&directory, &written).unwrap();
        let mode = std::fs::metadata(directory.join(FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn an_unreadable_or_foreign_cache_is_simply_absent() {
        assert!(load(Path::new("/nonexistent/netinspect")).is_none());

        let directory = std::env::temp_dir().join(format!("netinspect-bad-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(FILE), "{ not json").unwrap();
        assert!(load(&directory).is_none());

        // A cache from a version that knows more than this one does.
        std::fs::write(directory.join(FILE), r#"{"schema":9,"fingerprint":"","fetched_at_unix":0,"observation":{"ip":"1.2.3.4","city":null,"region":null,"country":null,"latitude":null,"longitude":null,"timezone":null,"asn":null,"org":null},"baseline":null}"#).unwrap();
        assert!(load(&directory).is_none());

        std::fs::remove_dir_all(&directory).ok();
    }
}
