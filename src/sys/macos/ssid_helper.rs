//! The SSID helper ladder — the single permitted subprocess site.
//!
//! This file exists because the supported API is closed by a permission wall a
//! CLI binary cannot pass: reading the SSID needs Location Services
//! authorization, and that prompt requires an application bundle with
//! `NSLocationUsageDescription` in its `Info.plist`. An unbundled executable
//! has no `Info.plist` to carry it.
//!
//! It is confined to this file, opt-in at runtime, and governed by the rules in
//! spec 6.4.2. **No second exception may be added to spec 2.1.**
//!
//! Measured reality on macOS 26.5.1: all three candidates are gated. The
//! `networksetup` candidate does not merely fail — it reports "You are not
//! associated with an AirPort network." on a machine that is associated, which
//! is why `parse_networksetup` maps that line to `None` and never to "no
//! Wi-Fi". Treat the ladder as a best-effort improvement over a guaranteed
//! blank, not a fix.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::model::SsidSource;
use crate::sys::HelperPolicy;

/// Everything a helper writes past this is discarded.
const MAX_OUTPUT: u64 = 64 * 1024;

const FAST_TIMEOUT: Duration = Duration::from_millis(400);
const SLOW_TIMEOUT: Duration = Duration::from_secs(3);

/// One rung of the ladder: where to look, how to ask, and how to read the
/// answer.
struct Candidate {
    path: &'static str,
    args: &'static [&'static str],
    parse: fn(&str) -> Option<String>,
    source: SsidSource,
}

/// Try each candidate in order; the first non-empty, non-redacted answer wins.
pub fn ssid(iface: &str, policy: HelperPolicy) -> Option<(String, SsidSource)> {
    if policy == HelperPolicy::Disabled || !valid_interface_name(iface) {
        return None;
    }

    const FAST: [Candidate; 2] = [
        Candidate {
            path: "/usr/sbin/networksetup",
            args: &["-getairportnetwork"],
            parse: parse_networksetup,
            source: SsidSource::HelperNetworksetup,
        },
        Candidate {
            path: "/usr/sbin/ipconfig",
            args: &["getsummary"],
            parse: parse_ipconfig,
            source: SsidSource::HelperIpconfig,
        },
    ];

    for candidate in FAST {
        let mut argv: Vec<&str> = candidate.args.to_vec();
        argv.push(iface);
        if let Some(out) = run(candidate.path, &argv, FAST_TIMEOUT) {
            if let Some(ssid) = (candidate.parse)(&out).filter(|s| is_usable(s)) {
                return Some((ssid, candidate.source));
            }
        }
    }

    if policy == HelperPolicy::Slow {
        let argv = ["-xml", "-detailLevel", "basic", "SPAirPortDataType"];
        if let Some(out) = run("/usr/sbin/system_profiler", &argv, SLOW_TIMEOUT) {
            if let Some(ssid) = parse_system_profiler(&out).filter(|s| is_usable(s)) {
                return Some((ssid, SsidSource::HelperSystemProfiler));
            }
        }
    }

    None
}

/// The only variable in any command line is the interface name, and it comes
/// from `getifaddrs` rather than the user. Validate it anyway.
fn valid_interface_name(name: &str) -> bool {
    let letters = name.chars().take_while(|c| c.is_ascii_lowercase()).count();
    let digits = name.len() - letters;
    (2..=10).contains(&letters)
        && (1..=3).contains(&digits)
        && name[letters..].chars().all(|c| c.is_ascii_digit())
}

/// A value that is present but tells us nothing is not an answer.
fn is_usable(ssid: &str) -> bool {
    let s = ssid.trim();
    !s.is_empty() && s != "<redacted>" && s != "(null)"
}

/// A candidate must be a regular file owned by root and not writable by anyone
/// else, or a writable-path hijack on a misconfigured machine would run as us.
fn trustworthy(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0
}

/// Spawn a system binary with fixed arguments and no shell, capture at most
/// `MAX_OUTPUT` of stdout, and kill it if it outlives `timeout`.
// The one place in the tree where this lint is allowed. See spec 6.4.1, and
// tests/guards.rs, which fails if this allow appears in any other file.
#[allow(clippy::disallowed_methods)]
fn run(path: &str, args: &[&str], timeout: Duration) -> Option<String> {
    if !trustworthy(Path::new(path)) {
        return None;
    }

    let mut child = std::process::Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Drain stdout on another thread: a helper that fills the pipe would
    // otherwise block forever and defeat the timeout.
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.by_ref().take(MAX_OUTPUT).read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    let finished = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) => {}
            Err(_) => break false,
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    if !finished {
        let _ = child.kill();
    }
    // Reap in every case, including the timeout path.
    let _ = child.wait();
    let buf = reader.join().ok()?;

    if !finished {
        return None;
    }
    String::from_utf8(buf).ok()
}

// ---------------------------------------------------------------------------
// Parsers — pure, `&str` in, `Option<String>` out.
//
// Do not parse with whitespace splitting: SSIDs contain spaces routinely and
// colons occasionally.
// ---------------------------------------------------------------------------

fn parse_networksetup(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.trim_end().strip_prefix("Current Wi-Fi Network: "))
        .map(str::to_owned)
}

fn parse_ipconfig(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim();
        // `BSSID : …` also ends in "SSID : "; anchor on the start of the line.
        let rest = line.strip_prefix("SSID")?.trim_start();
        let value = rest.strip_prefix(':')?;
        Some(value.trim().to_owned())
    })
}

fn parse_system_profiler(output: &str) -> Option<String> {
    let value: plist::Value = plist::from_bytes(output.as_bytes()).ok()?;
    find_current_network(&value)
}

/// Walk the property list for the dictionary describing the joined network.
/// Its single key is the SSID, and its `_name` repeats it.
fn find_current_network(value: &plist::Value) -> Option<String> {
    match value {
        plist::Value::Array(items) => items.iter().find_map(find_current_network),
        plist::Value::Dictionary(dict) => {
            if let Some(current) = dict.get("spairport_current_network_information") {
                if let Some(name) = current
                    .as_dictionary()
                    .and_then(|d| d.get("_name"))
                    .and_then(plist::Value::as_string)
                {
                    return Some(name.to_owned());
                }
            }
            dict.values().find_map(find_current_network)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networksetup_plain() {
        assert_eq!(
            parse_networksetup("Current Wi-Fi Network: Otthon_5G\n").as_deref(),
            Some("Otthon_5G")
        );
    }

    #[test]
    fn networksetup_keeps_spaces_and_colons() {
        assert_eq!(
            parse_networksetup("Current Wi-Fi Network: Cafe: Free WiFi\n").as_deref(),
            Some("Cafe: Free WiFi")
        );
    }

    #[test]
    fn networksetup_not_associated_is_unknown_not_absent() {
        // Measured on macOS 26.5.1 while the machine WAS associated. The only
        // honest reading of this line is "this tool cannot tell".
        let out = "You are not associated with an AirPort network.\n";
        assert_eq!(parse_networksetup(out), None);
    }

    #[test]
    fn ipconfig_reads_ssid_not_bssid() {
        let out = "  BSSID : 00:11:22:33:44:55\n  SSID : Otthon_5G\n";
        assert_eq!(parse_ipconfig(out).as_deref(), Some("Otthon_5G"));
    }

    #[test]
    fn ipconfig_redacted_is_rejected() {
        let out = "  BSSID : <redacted>\n  SSID : <redacted>\n";
        assert_eq!(parse_ipconfig(out).as_deref(), Some("<redacted>"));
        assert!(!is_usable("<redacted>"));
    }

    #[test]
    fn interface_names_are_validated() {
        assert!(valid_interface_name("en0"));
        assert!(valid_interface_name("utun3"));
        assert!(!valid_interface_name("en0; rm -rf /"));
        assert!(!valid_interface_name("../../bin/sh"));
        assert!(!valid_interface_name("e0"));
        assert!(!valid_interface_name("en"));
        assert!(!valid_interface_name("EN0"));
    }
}
