//! Replacing this binary with a newer one.
//!
//! See `src/update/AGENTS.md`. The order of operations in `install` is a
//! security property, not a style choice.

pub mod archive;
pub mod check;
pub mod install;
pub mod release;
pub mod verify;
pub mod version;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use install::Installation;
use version::Offer;

/// How long any single request may take. An update is not urgent enough to
/// hang on.
const TIMEOUT: Duration = Duration::from_secs(30);

/// What happened, so the caller can say it in words rather than a status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Updated {
        from: String,
        to: String,
    },
    AlreadyCurrent(String),
    /// A package manager owns this copy. Fighting it over its own files is how
    /// a machine ends up in a state nobody can explain.
    Managed {
        path: PathBuf,
        hint: String,
    },
    /// **Never offer to escalate.** Say where it is and stop.
    NotWritable(PathBuf),
    /// This build has no signing key, so it cannot check what it downloads.
    Unverifiable,
}

/// Replace this binary with the latest release.
///
/// The order is the whole point and is not rearrangeable: resolve, refuse a
/// downgrade, download, check the digest, check the signature, and only then
/// put anything in place. Every failure returns before the target is touched.
pub fn run(current_version: &str, force: bool, verbose: bool) -> Result<Outcome> {
    let executable = std::env::current_exe().context("this binary has no path")?;
    match install::locate(&executable) {
        Installation::Homebrew(path) => {
            return Ok(Outcome::Managed {
                path,
                hint: "run `brew upgrade netinspect`".to_owned(),
            })
        }
        Installation::NotWritable(path) => return Ok(Outcome::NotWritable(path)),
        Installation::Direct(_) => {}
    }
    if !verify::signing_key_configured() {
        return Ok(Outcome::Unverifiable);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("netinspect/", env!("CARGO_PKG_VERSION")))
        .timeout(TIMEOUT)
        .build()?;

    // 1 — what is the latest release, and is it one we want?
    let listing = runtime.block_on(text(&client, release::RELEASES_URL))?;
    let latest = release::parse(&listing)?;
    let tag = latest.tag.trim_start_matches('v').to_owned();

    match version::compare(&latest.tag, current_version) {
        Offer::Current => return Ok(Outcome::AlreadyCurrent(current_version.to_owned())),
        Offer::Downgrade | Offer::NotOffered if !force => {
            bail!(
                "the latest release is {} and this is {current_version}; pass --force to install it anyway",
                latest.tag
            )
        }
        _ => {}
    }

    let archive_name = release::archive_name(&tag, release::target_triple());
    let archive_asset = latest
        .asset(&archive_name)
        .with_context(|| format!("release {} has no {archive_name}", latest.tag))?;
    let signature_asset = latest
        .asset(&format!("{archive_name}.minisig"))
        .with_context(|| format!("release {} has no signature for {archive_name}", latest.tag))?;
    let sums_asset = latest
        .asset("SHA256SUMS")
        .with_context(|| format!("release {} has no SHA256SUMS", latest.tag))?;

    if verbose {
        eprintln!("netinspect: downloading {archive_name}");
    }

    // 2 — fetch everything before touching anything.
    let archive = runtime.block_on(bytes(&client, &archive_asset.url))?;
    let sums = runtime.block_on(text(&client, &sums_asset.url))?;
    let signature = runtime.block_on(text(&client, &signature_asset.url))?;

    // 3 — a corrupted download, then 4 — a substituted one. Only the second is
    // a security property, and its key is compiled in, never fetched.
    verify::verify_checksum(&archive, &sums, &archive_name)?;
    verify::verify_signature(verify::PUBLIC_KEY, &archive, &signature)?;

    // 5 — and only now does anything land next to the running binary.
    let binary = archive::extract(&archive, "netinspect")?;
    install::replace(&executable, &binary)?;

    Ok(Outcome::Updated {
        from: current_version.to_owned(),
        to: tag,
    })
}

async fn text(client: &reqwest::Client, url: &str) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("{url} answered {status}");
    }
    response
        .text()
        .await
        .with_context(|| format!("could not read {url}"))
}

async fn bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("{url} answered {status}");
    }
    Ok(response
        .bytes()
        .await
        .with_context(|| format!("could not read {url}"))?
        .to_vec())
}

impl Outcome {
    /// What to print. Each of these is the whole message; none of them
    /// suggests running anything with `sudo`.
    pub fn message(&self) -> String {
        match self {
            Outcome::Updated { from, to } => format!("updated from v{from} to v{to}"),
            Outcome::AlreadyCurrent(version) => format!("v{version} is the latest release"),
            Outcome::Managed { path, hint } => {
                format!(
                    "{} was installed by a package manager — {hint}",
                    path.display()
                )
            }
            Outcome::NotWritable(path) => {
                format!("{} is not writable by this user", path.display())
            }
            Outcome::Unverifiable => {
                "this build has no release signing key compiled in, so it cannot check what it \
                 downloads; see docs/RELEASING.md"
                    .to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_outcome_says_something_and_none_of_them_says_sudo() {
        let outcomes = [
            Outcome::Updated {
                from: "0.3.1".to_owned(),
                to: "0.4.0".to_owned(),
            },
            Outcome::AlreadyCurrent("0.4.0".to_owned()),
            Outcome::Managed {
                path: PathBuf::from("/opt/homebrew/bin/netinspect"),
                hint: "run `brew upgrade netinspect`".to_owned(),
            },
            Outcome::NotWritable(PathBuf::from("/usr/local/bin/netinspect")),
            Outcome::Unverifiable,
        ];
        for outcome in outcomes {
            let message = outcome.message();
            assert!(!message.is_empty());
            // Offering to escalate is how a diagnostic tool talks someone into
            // running it as root.
            assert!(!message.contains("sudo"), "{message}");
        }
    }

    #[test]
    fn a_managed_install_names_the_package_manager_rather_than_the_error() {
        let outcome = Outcome::Managed {
            path: PathBuf::from("/opt/homebrew/bin/netinspect"),
            hint: "run `brew upgrade netinspect`".to_owned(),
        };
        assert!(outcome.message().contains("brew upgrade netinspect"));
    }
}
