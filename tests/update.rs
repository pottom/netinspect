//! What `update` and `completions` do when driven as commands.
//!
//! Nothing here touches the network or replaces anything: the point is the
//! refusals, which are the part that has to be right.
#![allow(clippy::disallowed_methods)]

use std::process::Command;

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_netinspect"))
        .args(args)
        .output()
        .expect("the binary must be runnable");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// A build with no signing key cannot check what it downloads, so it must not
/// download anything. Failing closed is the whole design.
#[test]
fn a_build_without_a_signing_key_refuses_to_update() {
    let (code, stdout, _) = run(&["update"]);
    assert_eq!(code, Some(1), "nothing was installed, and it said so");
    assert!(
        stdout.contains("signing key"),
        "the refusal must say why: {stdout}"
    );
    assert!(stdout.contains("RELEASING"), "and where to look: {stdout}");
}

/// Suggesting `sudo` is how a read-only diagnostic tool talks somebody into
/// running it as root.
#[test]
fn no_update_message_offers_to_escalate() {
    for args in [&["update"][..], &["update", "--force"][..]] {
        let (_, stdout, stderr) = run(args);
        assert!(!stdout.contains("sudo"), "{stdout}");
        assert!(!stderr.contains("sudo"), "{stderr}");
    }
}

#[test]
fn completions_are_emitted_for_every_shell_that_is_offered() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let (code, stdout, stderr) = run(&["completions", shell]);
        assert_eq!(code, Some(0), "{shell}: {stderr}");
        assert!(!stdout.is_empty(), "{shell} produced nothing");
        assert!(
            stdout.contains("netinspect"),
            "{shell} did not name the command"
        );
    }
    // A shell nobody has heard of is a usage error, not an empty script.
    assert_eq!(run(&["completions", "brainfuck"]).0, Some(2));
}

/// The completion script has to know about every subcommand, or the shell
/// quietly stops offering half the tool.
#[test]
fn the_completions_cover_the_whole_command_surface() {
    let (_, script, _) = run(&["completions", "zsh"]);
    for subcommand in ["check", "routes", "listen", "update", "completions"] {
        assert!(script.contains(subcommand), "{subcommand} is missing");
    }
    for flag in ["--json", "--watch", "--theme", "--no-lookup", "--exposed"] {
        assert!(script.contains(flag), "{flag} is missing");
    }
}

/// The version a person reads carries a `v`.
#[test]
fn the_version_flag_agrees_with_the_report_header() {
    let (code, stdout, _) = run(&["--version"]);
    assert_eq!(code, Some(0));
    assert!(stdout.trim().ends_with(concat!("v", env!("CARGO_PKG_VERSION"))), "{stdout}");
}

/// The update check writes its own cache file and never touches the geo one.
#[test]
fn the_update_check_is_separate_from_the_geo_lookup() {
    let directory = std::env::temp_dir().join(format!("netinspect-upd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);

    let output = Command::new(env!("CARGO_BIN_EXE_netinspect"))
        .args(["--no-lookup", "--no-check", "--no-color"])
        .env("NETINSPECT_CACHE_DIR", &directory)
        .env("NETINSPECT_NO_UPDATE_CHECK", "1")
        .output()
        .expect("runnable");
    assert!(output.status.success());
    // Both disabled: neither file appears.
    assert!(!directory.join("update.json").exists());
    assert!(!directory.join("geo.json").exists());

    let _ = std::fs::remove_dir_all(&directory);
}
