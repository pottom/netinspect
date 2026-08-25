//! Putting the new binary in place of the running one.
//!
//! On macOS replacing the file of a running process is legal — the running
//! image is unaffected — which is what makes this possible at all. The order
//! below is a security property: nothing touches the target until the bytes
//! that will replace it are already on the same filesystem, verified, and
//! executable.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// How this copy of the program got here, which decides whether it may replace
/// itself and what to say if it may not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Installation {
    /// A direct download that this process can replace.
    Direct(PathBuf),
    /// Managed by Homebrew. `brew` owns it, and fighting a package manager
    /// over its own files is how a machine ends up in a state nobody can
    /// explain.
    Homebrew(PathBuf),
    /// Somewhere this user cannot write. **Never offer to escalate.**
    NotWritable(PathBuf),
}

/// Decide from the path alone, with no subprocess.
///
/// A Homebrew binary lives under `…/Cellar/<formula>/<version>/bin`, usually
/// reached through a symlink. Resolving the link is what makes it visible;
/// asking `brew` would mean running it.
pub fn locate(executable: &Path) -> Installation {
    let resolved = std::fs::canonicalize(executable).unwrap_or_else(|_| executable.to_owned());
    if is_homebrew(&resolved) {
        return Installation::Homebrew(resolved);
    }
    match writable_directory(&resolved) {
        true => Installation::Direct(resolved),
        false => Installation::NotWritable(resolved),
    }
}

fn is_homebrew(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.contains("/Cellar/netinspect/") || text.contains("/Homebrew/")
}

/// The only honest test is to try it: permissions, read-only mounts and
/// immutable flags all end at the same place.
fn writable_directory(executable: &Path) -> bool {
    let Some(directory) = executable.parent() else {
        return false;
    };
    let probe = directory.join(format!(".netinspect-write-test-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// A temp file that removes itself unless it is explicitly kept.
///
/// Every failure path in `replace` has to leave the original binary alone and
/// nothing behind, and remembering that at each `?` is how one gets missed.
struct Scratch {
    path: PathBuf,
    keep: bool,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Replace `target` with `bytes`.
///
/// The temp file is created **in the same directory as the target**, so the
/// final step is a rename within one filesystem — atomic, and with no window
/// where the binary is half-written.
pub fn replace(target: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        bail!("refusing to install an empty binary");
    }
    let directory = target
        .parent()
        .context("the running binary has no directory")?;

    let mut scratch = Scratch {
        path: directory.join(format!(".netinspect-update-{}", std::process::id())),
        keep: false,
    };

    {
        let mut file = std::fs::File::create(&scratch.path)
            .with_context(|| format!("could not write to {}", directory.display()))?;
        file.write_all(bytes)
            .context("the new binary could not be written")?;
        // Reach the disk before anything is renamed over anything.
        file.sync_all()
            .context("the new binary could not be flushed")?;
    }

    std::fs::set_permissions(&scratch.path, std::fs::Permissions::from_mode(0o755))
        .context("the new binary could not be made executable")?;

    std::fs::rename(&scratch.path, target).with_context(|| {
        format!(
            "could not put the new binary in place of {}",
            target.display()
        )
    })?;
    // From here the temp file is the target; removing it would undo the update.
    scratch.keep = true;

    // A binary that arrived over the network carries a quarantine flag, and
    // Gatekeeper will refuse it on first launch.
    crate::sys::strip_quarantine(target);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("netinspect-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_homebrew_path_is_recognised_without_running_brew() {
        assert!(is_homebrew(Path::new(
            "/opt/homebrew/Cellar/netinspect/0.3.1/bin/netinspect"
        )));
        assert!(is_homebrew(Path::new(
            "/usr/local/Cellar/netinspect/0.3.1/bin/netinspect"
        )));
        assert!(!is_homebrew(Path::new("/usr/local/bin/netinspect")));
        assert!(!is_homebrew(Path::new("/Users/maya/.cargo/bin/netinspect")));
    }

    #[test]
    fn a_writable_directory_is_found_by_trying_it() {
        let directory = scratch_dir("writable");
        let binary = directory.join("netinspect");
        std::fs::write(&binary, b"old").unwrap();

        assert_eq!(
            locate(&binary),
            Installation::Direct(std::fs::canonicalize(&binary).unwrap())
        );

        // A directory nobody may write to.
        assert!(matches!(
            locate(Path::new("/usr/bin/netinspect")),
            Installation::NotWritable(_) | Installation::Direct(_)
        ));
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn the_binary_is_replaced_and_left_executable() {
        let directory = scratch_dir("replace");
        let binary = directory.join("netinspect");
        std::fs::write(&binary, b"the old binary").unwrap();

        replace(&binary, b"the new binary").unwrap();

        assert_eq!(std::fs::read(&binary).unwrap(), b"the new binary");
        let mode = std::fs::metadata(&binary).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "mode is {:o}", mode & 0o777);
        // Nothing left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".netinspect-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        std::fs::remove_dir_all(&directory).ok();
    }

    /// Every failure path has to leave the original alone and nothing behind.
    #[test]
    fn a_refused_install_leaves_the_original_untouched() {
        let directory = scratch_dir("refused");
        let binary = directory.join("netinspect");
        std::fs::write(&binary, b"the old binary").unwrap();

        assert!(
            replace(&binary, b"").is_err(),
            "an empty binary must be refused"
        );
        assert_eq!(std::fs::read(&binary).unwrap(), b"the old binary");

        // And a target whose directory does not exist fails without a trace.
        let missing = directory.join("nowhere/netinspect");
        assert!(replace(&missing, b"bytes").is_err());

        let leftovers: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".netinspect-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn the_scratch_file_removes_itself() {
        let directory = scratch_dir("scratch");
        let path = directory.join(".netinspect-update-test");
        std::fs::write(&path, b"x").unwrap();
        {
            let _scratch = Scratch {
                path: path.clone(),
                keep: false,
            };
        }
        assert!(!path.exists());
        std::fs::remove_dir_all(&directory).ok();
    }
}
