//! Application firewall state.
//!
//! `socketfilterfw` is a subprocess and forbidden by spec 2.1. The documented
//! alternative is `/Library/Preferences/com.apple.alf.plist`.
//!
//! **That file no longer exists on macOS 15+.** Measured on 26.5.1: the only
//! `com.apple.alf.plist` on disk is the default template shipped inside
//! `/usr/libexec/ApplicationFirewall/`, which is not live state. Its
//! `globalstate` happens to read 0 — the same value a machine with the firewall
//! genuinely off would report — which is exactly what makes trusting it
//! dangerous. We never read it.
//!
//! So on current macOS this reports `Unknown` and the renderer omits the
//! footer. Reporting "off" when you do not know is the one error that turns a
//! security check into a false reassurance.

use std::path::Path;

use crate::model::{FirewallMode, FirewallState};

/// The live preferences file, on the macOS versions that still have one.
const ALF_PLIST: &str = "/Library/Preferences/com.apple.alf.plist";

pub fn collect() -> FirewallState {
    read_state(Path::new(ALF_PLIST)).unwrap_or(FirewallState {
        state: FirewallMode::Unknown,
        block_all_incoming: false,
    })
}

fn read_state(path: &Path) -> Option<FirewallState> {
    let value: plist::Value = plist::from_file(path).ok()?;
    let global = value
        .as_dictionary()?
        .get("globalstate")
        .and_then(plist::Value::as_signed_integer)?;
    Some(interpret(global))
}

/// 0 off, 1 on for specific services, 2 block all incoming. Anything else is a
/// value this version of the tool does not know, which is not the same as off.
fn interpret(global_state: i64) -> FirewallState {
    match global_state {
        0 => FirewallState {
            state: FirewallMode::Off,
            block_all_incoming: false,
        },
        1 => FirewallState {
            state: FirewallMode::On,
            block_all_incoming: false,
        },
        2 => FirewallState {
            state: FirewallMode::BlockAll,
            block_all_incoming: true,
        },
        _ => FirewallState {
            state: FirewallMode::Unknown,
            block_all_incoming: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_states_map_through() {
        assert_eq!(interpret(0).state, FirewallMode::Off);
        assert_eq!(interpret(1).state, FirewallMode::On);
        assert_eq!(interpret(2).state, FirewallMode::BlockAll);
        assert!(interpret(2).block_all_incoming);
    }

    #[test]
    fn an_unknown_value_is_never_reported_as_off() {
        assert_eq!(interpret(7).state, FirewallMode::Unknown);
        assert_eq!(interpret(-1).state, FirewallMode::Unknown);
    }

    /// The property, which holds on any machine: no readable file means no
    /// answer. What `collect` returns depends on the macOS it runs on — the
    /// plist is gone on 26 and still there on 14, which is why the legacy path
    /// is kept rather than deleted.
    #[test]
    fn a_missing_file_yields_no_answer() {
        assert!(read_state(Path::new("/nonexistent/com.apple.alf.plist")).is_none());

        let state = collect().state;
        assert_eq!(
            state == FirewallMode::Unknown,
            !Path::new(ALF_PLIST).exists(),
            "collect() said {state:?} while {ALF_PLIST} exists = {}",
            Path::new(ALF_PLIST).exists()
        );
    }

    #[test]
    fn the_os_template_is_never_a_source() {
        // If this file is ever read as live state, a machine with the firewall
        // ON would be reported as OFF. Assert we do not name it.
        assert!(!super::ALF_PLIST.contains("/usr/libexec"));
    }
}
