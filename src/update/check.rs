//! The background update check.
//!
//! Two rules from spec 10.1, and both are about not getting in the way:
//! the check happens at most once a day, and it **never blocks output**. The
//! footer is rendered from whatever the cache already knows; the refresh
//! happens after the report is on screen.
//!
//! If the check has never run, no footer is printed at all. A first invocation
//! that pauses to ask a server about itself would be a bad first impression.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::UpdateInfo;
use crate::update::version::{compare, Offer};

pub const INTERVAL_SECONDS: i64 = 24 * 60 * 60;

const FILE: &str = "update.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub schema: u32,
    pub checked_at_unix: i64,
    /// The newest release seen. `None` means the last check failed, which is
    /// worth recording so it is not retried on every run.
    pub latest: Option<String>,
}

pub fn disabled() -> bool {
    matches!(
        std::env::var("NETINSPECT_NO_UPDATE_CHECK").as_deref(),
        Ok("1") | Ok("true")
    )
}

pub fn load(directory: &Path) -> Option<Check> {
    let text = std::fs::read_to_string(directory.join(FILE)).ok()?;
    let check: Check = serde_json::from_str(&text).ok()?;
    (check.schema == 1).then_some(check)
}

pub fn store(directory: &Path, check: &Check) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)?;
    std::fs::write(directory.join(FILE), serde_json::to_string(check)?)
}

pub fn path(directory: &Path) -> PathBuf {
    directory.join(FILE)
}

/// Whether to ask again. A clock that has gone backwards is a reason to check,
/// not a reason to wait a day.
pub fn due(check: Option<&Check>, now_unix: i64) -> bool {
    match check {
        None => true,
        Some(check) => !(0..INTERVAL_SECONDS).contains(&(now_unix - check.checked_at_unix)),
    }
}

/// What the footer should say, from what is already known.
///
/// `None` for a check that has never run, one that failed, or a release that
/// is not an upgrade — the report says nothing rather than something empty.
pub fn footer(check: Option<&Check>, current: &str) -> Option<UpdateInfo> {
    let latest = check?.latest.as_deref()?;
    match compare(latest, current) {
        Offer::Upgrade => Some(UpdateInfo {
            current: current.to_owned(),
            latest: Some(latest.trim_start_matches('v').to_owned()),
            available: true,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(checked_at_unix: i64, latest: Option<&str>) -> Check {
        Check {
            schema: 1,
            checked_at_unix,
            latest: latest.map(str::to_owned),
        }
    }

    #[test]
    fn the_first_invocation_says_nothing_and_asks() {
        // No footer before anything is known, and the check is due.
        assert!(footer(None, "0.3.1").is_none());
        assert!(due(None, 1_000_000));
    }

    #[test]
    fn the_check_happens_at_most_once_a_day() {
        let last = check(1_000_000, Some("0.4.0"));
        assert!(!due(Some(&last), 1_000_000));
        assert!(!due(Some(&last), 1_000_000 + INTERVAL_SECONDS - 1));
        assert!(due(Some(&last), 1_000_000 + INTERVAL_SECONDS));
        // A clock that went backwards is a reason to check, not to wait.
        assert!(due(Some(&last), 999_999));
    }

    #[test]
    fn only_a_newer_release_produces_a_footer() {
        let newer = check(0, Some("v0.4.0"));
        let info = footer(Some(&newer), "0.3.1").expect("an upgrade");
        assert!(info.available);
        // Stored with the `v`, reported without: the model holds bare semver.
        assert_eq!(info.latest.as_deref(), Some("0.4.0"));

        assert!(footer(Some(&check(0, Some("0.3.1"))), "0.3.1").is_none());
        assert!(footer(Some(&check(0, Some("0.2.0"))), "0.3.1").is_none());
        // A failed check says nothing rather than something empty.
        assert!(footer(Some(&check(0, None)), "0.3.1").is_none());
        // And a pre-release is never pushed at anyone.
        assert!(footer(Some(&check(0, Some("1.0.0-rc.1"))), "0.3.1").is_none());
    }

    #[test]
    fn a_round_trip_survives_and_a_foreign_file_does_not() {
        let directory =
            std::env::temp_dir().join(format!("netinspect-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);

        let written = check(4242, Some("v0.4.0"));
        store(&directory, &written).unwrap();
        assert_eq!(load(&directory), Some(written));

        std::fs::write(
            path(&directory),
            r#"{"schema":9,"checked_at_unix":0,"latest":null}"#,
        )
        .unwrap();
        assert_eq!(load(&directory), None);

        std::fs::write(path(&directory), "{ not json").unwrap();
        assert_eq!(load(&directory), None);

        std::fs::remove_dir_all(&directory).ok();
    }
}
