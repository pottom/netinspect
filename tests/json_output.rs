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

/// The shared report deliberately passes `--no-lookup`: these tests should not
/// tell a third party about the machine running them once per assertion, and
/// the lookup path has its own test below.
fn report() -> Value {
    let (ok, stdout) = run(&["--json", "--no-lookup"]);
    assert!(ok, "netinspect --json exited with a failure");
    serde_json::from_str(&stdout).expect("--json must emit valid JSON")
}

#[test]
fn json_is_a_single_line_of_valid_json() {
    let (_, stdout) = run(&["--json", "--no-lookup"]);
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
    // The public lookup and update check have not run in this build; consumers
    // must see null rather than a missing key.
    for key in ["reachability", "public", "update"] {
        assert!(report.get(key).is_some(), "{key} must be present");
    }
    assert!(report["dns"]["servers"].is_array());
    assert!(report["dns"]["split_dns_scopes"].is_u64());
}

#[test]
fn reachability_reports_every_stage_it_did_not_attempt_as_null() {
    let report = report();
    let reachability = &report["reachability"];
    assert!(!reachability.is_null(), "the ladder runs by default");

    let state = reachability["state"].as_str().expect("a state");
    assert!(
        [
            "online",
            "captive_portal",
            "dns_failure",
            "gateway_unreachable",
            "link_down",
            "unknown"
        ]
        .contains(&state),
        "unexpected state {state}"
    );

    for stage in ["link", "gateway", "dns", "http"] {
        let value = &reachability[stage];
        if value.is_null() {
            continue; // never attempted, which is not a failure
        }
        assert!(value["ok"].is_boolean(), "{stage}: {value}");
        assert!(value["ms"].is_u64() || value["ms"].is_null(), "{stage}: {value}");
    }

    // A captive portal must always name somewhere to go.
    if state == "captive_portal" {
        assert!(reachability["captive_portal"]["login_url"].is_string());
    } else {
        assert!(reachability["captive_portal"].is_null());
    }
}

#[test]
fn no_check_leaves_the_ladder_unrun() {
    let (ok, stdout) = run(&["--json", "--no-check"]);
    assert!(ok);
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    // Not "everything failed" — not measured at all.
    assert!(report["reachability"].is_null());
}

#[test]
fn check_prints_nothing_and_reports_through_its_exit_code() {
    let output = Command::new(env!("CARGO_BIN_EXE_netinspect"))
        .arg("check")
        .output()
        .expect("runnable");
    assert!(output.stdout.is_empty(), "check must be silent on success");

    // Whatever this machine's network is doing, the code has to be one of the
    // documented ones.
    let code = output.status.code().expect("an exit code");
    assert!(
        [0, 10, 11, 12, 13].contains(&code),
        "undocumented exit code {code}"
    );
}

#[test]
fn json_implies_no_color() {
    let (_, stdout) = run(&["--json", "--no-lookup"]);
    assert!(!stdout.contains('\x1b'));
}

#[test]
fn no_lookup_means_no_public_address_at_all() {
    let report = report();
    // Not a half-filled object — the question was never asked.
    assert!(report["public"].is_null(), "{}", report["public"]);
}

/// The lookup path, tolerant of a machine with no internet: what it must not do
/// is invent a field or half-fill the object.
#[test]
fn a_public_address_is_either_absent_or_coherent() {
    let (ok, stdout) = run(&["--json"]);
    assert!(ok);
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let public = &report["public"];
    if public.is_null() {
        return; // offline, or the provider did not answer
    }

    // At least one address family, and each in the field for its family.
    let v4 = public["ipv4"].as_str();
    let v6 = public["ipv6"].as_str();
    assert!(v4.is_some() || v6.is_some(), "{public}");
    if let Some(address) = v4 {
        assert!(address.parse::<std::net::Ipv4Addr>().is_ok(), "{address}");
    }
    if let Some(address) = v6 {
        assert!(address.parse::<std::net::Ipv6Addr>().is_ok(), "{address}");
    }

    // Numbers are numbers.
    for key in ["latitude", "longitude"] {
        assert!(public[key].is_f64() || public[key].is_null(), "{key}: {public}");
    }

    // The tunnel verdict is only stated when there was something to compare
    // against; it must never be a guess dressed as a boolean.
    assert!(
        public["via_vpn"].is_boolean() || public["via_vpn"].is_null(),
        "{public}"
    );
    // And the timezone comparison only when both zones are known.
    if public["timezone"].is_null() {
        assert!(public["timezone_matches_system"].is_null(), "{public}");
    }
}

#[test]
fn check_makes_no_geo_request_even_without_no_lookup() {
    // `check` answers through an exit code; a location would be a disclosure
    // with nothing asking for it. Point the cache somewhere empty and assert
    // nothing was written there.
    let directory = std::env::temp_dir().join(format!("netinspect-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);

    let status = Command::new(env!("CARGO_BIN_EXE_netinspect"))
        .arg("check")
        .env("NETINSPECT_CACHE_DIR", &directory)
        .status()
        .expect("runnable");
    assert!([0, 10, 11, 12, 13].contains(&status.code().unwrap()));
    assert!(
        !directory.join("geo.json").exists(),
        "check wrote a geo cache, so it made a lookup"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn pretty_requires_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_netinspect"))
        .arg("--pretty")
        .output()
        .expect("runnable");
    assert!(!output.status.success(), "--pretty alone must be a usage error");
}
