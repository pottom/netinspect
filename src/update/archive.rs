//! Getting the binary back out of a release archive.
//!
//! Pure over bytes, and deliberately suspicious: an archive is attacker-shaped
//! input until the signature has been checked, and even afterwards a release
//! built wrong should fail loudly rather than write something unexpected.

use std::io::Read;

use anyhow::{bail, Context, Result};

/// Nothing this project ships is anywhere near this large. A gzip bomb that
/// expands to fill the disk is the failure mode being closed off.
const MAX_UNPACKED: u64 = 64 * 1024 * 1024;

/// Pull one named file out of a `.tar.gz`.
///
/// Matching is on the base name, so it does not matter whether the release is
/// packed flat or inside a directory. Paths are never used to decide where
/// anything goes — this returns bytes, and the caller decides where they land.
pub fn extract(archive: &[u8], wanted: &str) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(decoder.take(MAX_UNPACKED));

    for entry in tar.entries().context("the archive could not be read")? {
        let mut entry = entry.context("the archive is damaged")?;
        let path = entry.path().context("an archive entry has no usable name")?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if name != wanted {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            bail!("{wanted} in the archive is not a regular file");
        }

        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .context("the archive entry could not be read")?;
        if bytes.is_empty() {
            bail!("{wanted} in the archive is empty");
        }
        return Ok(bytes);
    }
    bail!("the archive does not contain {wanted}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, *bytes).unwrap();
        }
        let tar = builder.into_inner().unwrap();

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn the_binary_comes_out_whole() {
        let bytes = archive(&[("netinspect", b"the new binary")]);
        assert_eq!(extract(&bytes, "netinspect").unwrap(), b"the new binary");
    }

    #[test]
    fn it_does_not_matter_how_the_release_was_packed() {
        // Flat, or inside a directory: the base name is what identifies it.
        let nested = archive(&[
            ("netinspect-0.4.0/README.md", b"docs" as &[u8]),
            ("netinspect-0.4.0/netinspect", b"the new binary"),
        ]);
        assert_eq!(extract(&nested, "netinspect").unwrap(), b"the new binary");
    }

    #[test]
    fn an_archive_without_the_binary_is_an_error_not_an_empty_result() {
        let bytes = archive(&[("README.md", b"docs")]);
        assert!(extract(&bytes, "netinspect").is_err());
    }

    #[test]
    fn an_empty_entry_is_refused() {
        // Renaming an empty file over the running binary would leave the
        // machine with no working tool and no error to explain it.
        let bytes = archive(&[("netinspect", b"")]);
        assert!(extract(&bytes, "netinspect").is_err());
    }

    #[test]
    fn garbage_is_an_error_and_never_a_panic() {
        assert!(extract(b"", "netinspect").is_err());
        assert!(extract(b"not a gzip stream at all", "netinspect").is_err());
        // A valid gzip stream that is not a tar.
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"just some bytes").unwrap();
        assert!(extract(&encoder.finish().unwrap(), "netinspect").is_err());
    }
}
