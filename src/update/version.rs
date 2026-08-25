//! Comparing releases.
//!
//! Deliberately small: three numbers and nothing else. A pre-release is never
//! offered as an upgrade, because someone who wants one will ask for it by
//! name rather than be moved onto it by a background check.

use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    /// `v0.4.0`, `0.4.0`, `0.4.0-rc.1` — the `v` is optional and anything
    /// after the numbers marks a pre-release.
    pub fn parse(text: &str) -> Option<(Self, bool)> {
        let text = text.trim();
        let text = text.strip_prefix('v').unwrap_or(text);
        let (numbers, prerelease) = match text.find(['-', '+']) {
            Some(at) => (&text[..at], true),
            None => (text, false),
        };

        let mut parts = numbers.split('.');
        let mut next = || parts.next()?.parse::<u64>().ok();
        let version = Version {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        // A fourth component is not a version this understands.
        if parts.next().is_some() {
            return None;
        }
        Some((version, prerelease))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What an available release means for the version that is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Upgrade,
    /// Already running it.
    Current,
    /// The release is older. Never taken without `--force`.
    Downgrade,
    /// A pre-release, or something that does not parse.
    NotOffered,
}

pub fn compare(latest: &str, current: &str) -> Offer {
    let (Some((latest, prerelease)), Some((current, _))) =
        (Version::parse(latest), Version::parse(current))
    else {
        return Offer::NotOffered;
    };
    if prerelease {
        return Offer::NotOffered;
    }
    match latest.cmp(&current) {
        Ordering::Greater => Offer::Upgrade,
        Ordering::Equal => Offer::Current,
        Ordering::Less => Offer::Downgrade,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leading_v_is_optional() {
        assert_eq!(
            Version::parse("v1.2.3").unwrap().0,
            Version {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
        assert_eq!(
            Version::parse("1.2.3").unwrap().0,
            Version {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
        assert_eq!(Version::parse(" 1.2.3 ").unwrap().0.to_string(), "1.2.3");
    }

    #[test]
    fn anything_that_is_not_three_numbers_is_not_a_version() {
        assert!(Version::parse("1.2").is_none());
        assert!(Version::parse("1.2.3.4").is_none());
        assert!(Version::parse("latest").is_none());
        assert!(Version::parse("").is_none());
        assert!(Version::parse("1.2.x").is_none());
    }

    #[test]
    fn versions_compare_by_number_not_by_string() {
        // The string comparison every tool gets wrong once: "0.10.0" < "0.9.0".
        assert_eq!(compare("0.10.0", "0.9.0"), Offer::Upgrade);
        assert_eq!(compare("0.9.0", "0.10.0"), Offer::Downgrade);
        assert_eq!(compare("1.0.0", "0.99.99"), Offer::Upgrade);
    }

    #[test]
    fn the_same_version_is_not_an_upgrade() {
        assert_eq!(compare("v0.3.1", "0.3.1"), Offer::Current);
    }

    /// A background check must not move anyone onto a pre-release. Someone who
    /// wants one will ask for it by name.
    #[test]
    fn a_prerelease_is_never_offered() {
        assert_eq!(compare("1.0.0-rc.1", "0.9.0"), Offer::NotOffered);
        assert_eq!(compare("1.0.0+build.7", "0.9.0"), Offer::NotOffered);
        // But running one is fine, and the next stable release upgrades it.
        assert_eq!(compare("1.0.0", "1.0.0-rc.1"), Offer::Current);
        assert_eq!(compare("1.0.1", "1.0.0-rc.1"), Offer::Upgrade);
    }

    #[test]
    fn something_unparseable_is_not_offered_rather_than_assumed() {
        assert_eq!(compare("nightly", "0.3.1"), Offer::NotOffered);
        assert_eq!(compare("0.4.0", "not-a-version"), Offer::NotOffered);
    }
}
