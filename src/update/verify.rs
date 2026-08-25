//! Checking that a downloaded archive is the one that was published.
//!
//! Both checks are pure functions over bytes, which is the point: everything
//! that decides whether a binary is trustworthy can be exercised without a
//! network, a filesystem, or a release.
//!
//! The order matters and is not an accident. The checksum catches a truncated
//! or corrupted download; the signature catches a *substituted* one. Only the
//! second is a security property, and it is verified against a key compiled
//! into this binary — **never one fetched over the network**, which would just
//! be asking the attacker to bring their own.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// The release signing key, compiled in.
///
/// Empty in a build that has not been given one. `update` then refuses rather
/// than skipping the check: an unverified update path is worse than none.
/// See `docs/RELEASING.md`.
pub const PUBLIC_KEY: &str = "";

pub fn signing_key_configured() -> bool {
    !PUBLIC_KEY.trim().is_empty()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Find a file's expected digest in a `SHA256SUMS` listing.
///
/// The format is coreutils': a hex digest, two spaces, then the name, possibly
/// with a `*` marking binary mode.
pub fn expected_digest(listing: &str, filename: &str) -> Option<String> {
    listing.lines().find_map(|line| {
        let (digest, name) = line.split_once("  ").or_else(|| line.split_once(" *"))?;
        let name = name.trim();
        // Compare on the base name: a listing may carry paths.
        let base = name.rsplit('/').next().unwrap_or(name);
        (base == filename && digest.len() == 64).then(|| digest.trim().to_ascii_lowercase())
    })
}

pub fn verify_checksum(archive: &[u8], listing: &str, filename: &str) -> Result<()> {
    let expected = expected_digest(listing, filename)
        .with_context(|| format!("{filename} is not listed in SHA256SUMS"))?;
    let actual = sha256_hex(archive);
    if actual != expected {
        bail!("{filename} does not match its published checksum");
    }
    Ok(())
}

/// Verify a minisign signature over the archive.
pub fn verify_signature(public_key: &str, archive: &[u8], signature: &str) -> Result<()> {
    if public_key.trim().is_empty() {
        bail!("this build has no release signing key compiled in");
    }
    let key = minisign_verify::PublicKey::decode(public_key.trim())
        .context("the compiled-in release signing key is not a minisign key")?;
    let signature = minisign_verify::Signature::decode(signature)
        .context("the release signature could not be read")?;
    key.verify(archive, &signature, false)
        .map_err(|error| anyhow::anyhow!("the release signature does not verify: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  netinspect-0.4.0-aarch64-apple-darwin.tar.gz
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  netinspect-0.4.0-x86_64-apple-darwin.tar.gz
";

    #[test]
    fn a_digest_is_found_by_its_file_name() {
        assert_eq!(
            expected_digest(LISTING, "netinspect-0.4.0-aarch64-apple-darwin.tar.gz").as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(expected_digest(LISTING, "something-else.tar.gz"), None);
    }

    #[test]
    fn a_listing_with_paths_or_binary_markers_still_reads() {
        let listing = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *dist/netinspect.tar.gz\n";
        assert!(expected_digest(listing, "netinspect.tar.gz").is_some());
    }

    #[test]
    fn a_truncated_download_fails_its_checksum() {
        let archive = b"the published bytes";
        let listing = format!("{}  netinspect.tar.gz\n", sha256_hex(archive));

        assert!(verify_checksum(archive, &listing, "netinspect.tar.gz").is_ok());
        assert!(verify_checksum(b"the published byte", &listing, "netinspect.tar.gz").is_err());
        // A name that is not in the listing is a failure, not a pass.
        assert!(verify_checksum(archive, &listing, "other.tar.gz").is_err());
    }

    /// A build with no key must refuse rather than skip the check. Skipping is
    /// how an update path stops being a security boundary at all.
    #[test]
    fn a_build_without_a_key_refuses_to_verify() {
        assert!(verify_signature("", b"anything", "anything").is_err());
        assert!(verify_signature("   ", b"anything", "anything").is_err());
    }

    #[test]
    fn a_signature_from_another_key_does_not_verify() {
        let ours = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let theirs = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let archive = b"the published bytes";

        let signature = minisign::sign(None, &theirs.sk, &archive[..], None, None)
            .unwrap()
            .to_string();

        assert!(verify_signature(&ours.pk.to_box().unwrap().to_string(), archive, &signature).is_err());
    }

    #[test]
    fn the_published_bytes_verify_and_a_changed_byte_does_not() {
        let keys = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let public = keys.pk.to_box().unwrap().to_string();
        let archive = b"the published bytes".to_vec();
        let signature = minisign::sign(None, &keys.sk, &archive[..], None, None)
            .unwrap()
            .to_string();

        verify_signature(&public, &archive, &signature).expect("the real thing verifies");

        let mut tampered = archive.clone();
        tampered[0] ^= 1;
        assert!(verify_signature(&public, &tampered, &signature).is_err());
    }
}
