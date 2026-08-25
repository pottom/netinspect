//! End-to-end check on the real binary's `--json` output.
//!
//! This runs on whatever network the machine happens to have, so it asserts the
//! shape of the schema rather than any particular value. A CI machine with no
//! Wi-Fi, no VPN and no IPv6 must still pass.
//!
//! Spawning a process here is the test harness running the built binary, which
//! is not the program shelling out. The constraint in `AGENTS.md` governs
//! `src/`, and `tests/guards.rs` scans `src/` for exactly that reason.
#![allow(clippy::disallowed_methods)]

use std::process::Command;

use serde_json::Value;

fn run(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_netinspect"))
        .args(args)
        .output()
        .expect("the binary must be runnable");
    (
        output.status.success(),
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
    )
}

fn report() -> Value {
    let (ok, stdout) = run(&["--json"]);
    assert!(ok, "netinspect --json exited with a failure");
    serde_json::from_str(&stdout).expect("--json must emit valid JSON")
}

#[test]
fn json_is_a_single_line_of_valid_json() {
    let (_, stdout) = run(&["--json"]);
    assert_eq!(stdout.trim_end().lines().count(), 1);
    serde_json::from_str::<Value>(&stdout).expect("valid JSON");
}

#[test]
fn envelope_matches_schema_1() {
    let report = report();
    assert_eq!(report["schema"], 1, "schema 1 is frozen; see docs/MILESTONES.md");
    assert!(report["version"].is_string());

    let timestamp = report["timestamp"].as_str().expect("timestamp is a string");
    // RFC 3339 with an offset, e.g. 2026-08-25T14:22:07+02:00.
    assert!(timestamp.contains('T'), "{timestamp}");
    assert!(
        timestamp.ends_with('Z') || timestamp[timestamp.len() - 6..].contains(':'),
        "{timestamp}"
    );
}

#[test]
fn every_interface_has_the_documented_shape() {
    let report = report();
    let interfaces = report["interfaces"].as_array().expect("interfaces is an array");
    assert!(!interfaces.is_empty(), "a machine always has at least lo0");

    for iface in interfaces {
        assert!(iface["name"].is_string());
        assert!(iface["display_name"].is_string() || iface["display_name"].is_null());
        assert!(iface["is_default_route"].is_boolean());
        assert!(iface["mtu"].is_number() || iface["mtu"].is_null());

        for family in ["ipv4", "ipv6"] {
            for address in iface[family].as_array().expect("address list") {
                assert!(address["address"].is_string());
                // Numbers are numbers, not strings.
                assert!(address["prefix_len"].is_u64(), "{address}");
            }
        }

        let kind = iface["kind"].as_str().expect("kind is a string");
        assert!(
            ["wifi", "ethernet", "vpn", "bridge", "loopback", "other"].contains(&kind),
            "unexpected kind {kind}"
        );
        let status = iface["status"].as_str().expect("status is a string");
        assert!(
            ["connected", "up", "no_cable", "inactive", "disabled"].contains(&status),
            "unexpected status {status}"
        );
    }
}

#[test]
fn wifi_always_discloses_where_the_ssid_came_from() {
    let report = report();
    for iface in report["interfaces"].as_array().expect("interfaces") {
        let wifi = &iface["wifi"];
        if wifi.is_null() {
            continue;
        }
        // A present SSID must name its source, and an absent one must not
        // claim one.
        assert_eq!(
            wifi["ssid"].is_string(),
            wifi["ssid_source"].is_string(),
            "ssid and ssid_source disagree: {wifi}"
        );
        if let Some(source) = wifi["ssid_source"].as_str() {
            assert!(
                source == "corewlan" || source == "scdynamicstore" || source.starts_with("helper:"),
                "unexpected ssid source {source}"
            );
        }
    }
}

#[test]
fn absent_sections_are_null_not_omitted() {
    let report = report();
    // The reachability ladder and public lookup have not run in this build;
    // consumers must see null rather than a missing key.
    for key in ["reachability", "public", "update"] {
        assert!(report.get(key).is_some(), "{key} must be present");
    }
    assert!(report["dns"]["servers"].is_array());
    assert!(report["dns"]["split_dns_scopes"].is_u64());
}

#[test]
fn json_implies_no_color() {
    let (_, stdout) = run(&["--json"]);
    assert!(!stdout.contains('\x1b'));
}

#[test]
fn pretty_requires_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_netinspect"))
        .arg("--pretty")
        .output()
        .expect("runnable");
    assert!(!output.status.success(), "--pretty alone must be a usage error");
}
