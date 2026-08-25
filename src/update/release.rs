//! Finding out what the latest release is.
//!
//! The parsing is pure so the shape of a GitHub response is pinned by a test
//! rather than by whatever the API happened to return the day this was written.

use anyhow::{bail, Context, Result};

/// Where releases come from. Changing this changes who can hand this machine a
/// new binary, so it is a visible constant rather than a buried string.
pub const RELEASES_URL: &str = "https://api.github.com/repos/pottom/netinspect/releases/latest";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub assets: Vec<Asset>,
}

impl Release {
    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|asset| asset.name == name)
    }
}

/// The archive this build would install, by target triple.
pub fn archive_name(version: &str, target: &str) -> String {
    format!("netinspect-{version}-{target}.tar.gz")
}

/// The triple this binary was built for.
pub fn target_triple() -> &'static str {
    // Set by build.rs from the target Cargo is building for.
    env!("NETINSPECT_TARGET")
}

pub fn parse(body: &str) -> Result<Release> {
    let value: serde_json::Value =
        serde_json::from_str(body).context("the release listing is not JSON")?;

    let tag = value
        .get("tag_name")
        .and_then(|tag| tag.as_str())
        .filter(|tag| !tag.is_empty())
        .context("the release listing has no tag")?
        .to_owned();

    let assets = value
        .get("assets")
        .and_then(|assets| assets.as_array())
        .map(|assets| {
            assets
                .iter()
                .filter_map(|asset| {
                    Some(Asset {
                        name: asset.get("name")?.as_str()?.to_owned(),
                        url: asset.get("browser_download_url")?.as_str()?.to_owned(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if assets.is_empty() {
        bail!("release {tag} has no downloadable assets");
    }
    Ok(Release { tag, assets })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{
        "tag_name": "v0.4.0",
        "name": "0.4.0",
        "assets": [
            {
                "name": "netinspect-0.4.0-aarch64-apple-darwin.tar.gz",
                "browser_download_url": "https://example.test/a.tar.gz"
            },
            {
                "name": "netinspect-0.4.0-aarch64-apple-darwin.tar.gz.minisig",
                "browser_download_url": "https://example.test/a.tar.gz.minisig"
            },
            {
                "name": "SHA256SUMS",
                "browser_download_url": "https://example.test/SHA256SUMS"
            }
        ]
    }"#;

    #[test]
    fn a_release_yields_its_tag_and_assets() {
        let release = parse(BODY).unwrap();
        assert_eq!(release.tag, "v0.4.0");
        assert_eq!(release.assets.len(), 3);
        assert_eq!(
            release.asset("SHA256SUMS").unwrap().url,
            "https://example.test/SHA256SUMS"
        );
        assert!(release.asset("nothing").is_none());
    }

    #[test]
    fn the_archive_name_follows_the_release_convention() {
        assert_eq!(
            archive_name("0.4.0", "aarch64-apple-darwin"),
            "netinspect-0.4.0-aarch64-apple-darwin.tar.gz"
        );
    }

    #[test]
    fn a_release_with_nothing_to_download_is_an_error() {
        assert!(parse(r#"{"tag_name":"v0.4.0","assets":[]}"#).is_err());
        assert!(parse(r#"{"assets":[{"name":"a","browser_download_url":"u"}]}"#).is_err());
        assert!(parse("not json").is_err());
    }

    #[test]
    fn an_asset_missing_a_url_is_skipped_not_invented() {
        let body = r#"{"tag_name":"v1","assets":[
            {"name":"broken"},
            {"name":"good","browser_download_url":"https://example.test/g"}
        ]}"#;
        let release = parse(body).unwrap();
        assert_eq!(release.assets.len(), 1);
        assert_eq!(release.assets[0].name, "good");
    }
}
