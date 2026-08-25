//! Mechanical enforcement of the two hard constraints (spec 2.1 and 16.3).
//!
//! A reviewer will eventually miss one of these; these tests will not. They are
//! deliberately crude — a text scan over `src/` — because that is exactly the
//! kind of check that keeps working when the code around it is rewritten.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `src/`, as (repo-relative path, contents).
fn source_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.clone()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src/ must be readable") {
            let path = entry.expect("readable entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let relative = path
                    .strip_prefix(root.parent().expect("src has a parent"))
                    .expect("under the manifest")
                    .to_string_lossy()
                    .replace('\\', "/");
                let contents = std::fs::read_to_string(&path).expect("readable source");
                files.push((relative, contents));
            }
        }
    }

    assert!(!files.is_empty(), "found no sources to check");
    files
}

/// The single site where spec 2.1's subprocess exception applies.
const SSID_HELPER: &str = "src/sys/macos/ssid_helper.rs";

#[test]
fn only_the_ssid_helper_spawns_a_subprocess() {
    let offenders: Vec<String> = source_files()
        .into_iter()
        .filter(|(path, contents)| path != SSID_HELPER && contents.contains("Command::new"))
        .map(|(path, _)| path)
        .collect();

    assert!(
        offenders.is_empty(),
        "netinspect must not shell out (spec 2.1). \
         The only permitted site is {SSID_HELPER}, but Command::new appears in: {offenders:?}"
    );
}

#[test]
fn only_the_ssid_helper_allows_the_disallowed_methods_lint() {
    let offenders: Vec<String> = source_files()
        .into_iter()
        .filter(|(path, contents)| {
            path != SSID_HELPER && contents.contains("allow(clippy::disallowed_methods)")
        })
        .map(|(path, _)| path)
        .collect();

    assert!(
        offenders.is_empty(),
        "the disallowed_methods lint may only be allowed in {SSID_HELPER}, \
         but it is also allowed in: {offenders:?}"
    );
}

#[test]
fn the_ssid_helper_still_carries_its_allow() {
    // If the allow is dropped, clippy stops covering this file and the other
    // two guards start passing for the wrong reason.
    let contents = source_files()
        .into_iter()
        .find(|(path, _)| path == SSID_HELPER)
        .map(|(_, contents)| contents)
        .expect("the ssid helper must exist");

    assert!(contents.contains("allow(clippy::disallowed_methods)"));
    assert!(contents.contains("Command::new"));
}

#[test]
fn platform_conditionals_stay_inside_the_platform_layer() {
    let offenders: Vec<String> = source_files()
        .into_iter()
        .filter(|(path, contents)| {
            !path.starts_with("src/sys/") && contents.contains("cfg(target_os")
        })
        .map(|(path, _)| path)
        .collect();

    assert!(
        offenders.is_empty(),
        "the platform abstraction only holds if it is defended (spec 16.3). \
         cfg(target_os) belongs in src/sys/, but appears in: {offenders:?}"
    );
}

#[test]
fn unsafe_code_stays_inside_the_platform_layer() {
    let offenders: Vec<String> = source_files()
        .into_iter()
        .filter(|(path, contents)| !path.starts_with("src/sys/") && contents.contains("unsafe "))
        .map(|(path, _)| path)
        .collect();

    assert!(
        offenders.is_empty(),
        "unsafe belongs in src/sys/, but appears in: {offenders:?}"
    );
}

#[test]
fn the_model_depends_on_nothing_but_serde() {
    let model = source_files()
        .into_iter()
        .find(|(path, _)| path == "src/model.rs")
        .map(|(_, contents)| contents)
        .expect("the model must exist");

    for line in model.lines().filter(|l| l.trim_start().starts_with("use ")) {
        assert!(
            line.contains("serde") || line.contains("std::"),
            "model.rs is the contract between the platform layer and everything \
             above it; it must not gain a dependency. Offending import: {line}"
        );
    }
}
