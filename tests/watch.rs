//! The watch loop's contract with the terminal.
//!
//! Everything here is about what happens around the report rather than in it:
//! that the frame is redrawn in place, that the cursor comes back, and that a
//! third party is not asked where this machine is once every two seconds.
//!
//! Spawning and signalling a process is the harness driving the built binary,
//! not the program shelling out. `tests/guards.rs` scans `src/` for that
//! reason.
#![allow(clippy::disallowed_methods)]

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Run watch mode for roughly `seconds`, then interrupt it the way a person
/// would, and return everything it wrote and how it exited.
fn watch_then_interrupt(args: &[&str], seconds: u64) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_netinspect"))
        .args(args)
        .env("COLUMNS", "100")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the binary must be runnable");

    let mut stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });

    std::thread::sleep(Duration::from_secs(seconds));
    // Safety: sending SIGINT to a child this test started.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }

    let status = child.wait().expect("the child must be reapable");
    let text = reader.join().expect("the reader thread");
    (status.code(), text)
}

const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";
/// Home, then clear to the end of the screen.
const REDRAW: &str = "\x1b[H\x1b[J";

#[test]
fn the_frame_is_redrawn_in_place_and_the_cursor_comes_back() {
    let (code, text) = watch_then_interrupt(&["--watch", "1", "--no-lookup", "--no-color"], 3);

    assert_eq!(code, Some(0), "an interrupted watch is not a failure");
    assert!(
        text.starts_with(HIDE_CURSOR),
        "the cursor was left blinking"
    );
    assert!(
        text.trim_end().ends_with(SHOW_CURSOR),
        "the terminal was not given back: {:?}",
        &text[text.len().saturating_sub(24)..]
    );

    // Redrawn, not scrolled.
    let frames = text.matches(REDRAW).count();
    assert!(frames >= 2, "only {frames} frame(s) in three seconds");

    // The last frame stays on screen, which is what a monitoring command is
    // usually wanted for: the report is still there after the restore.
    let tail = text.rsplit(REDRAW).next().expect("a last frame");
    assert!(tail.contains("netinspect"), "the last frame was wiped");
}

#[test]
fn interrupting_is_answered_promptly() {
    // A ten-second cadence must not mean a ten-second wait to get out of it.
    let started = std::time::Instant::now();
    let (code, _) = watch_then_interrupt(&["--watch", "10", "--no-lookup", "--no-color"], 1);
    assert_eq!(code, Some(0));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "took {:?} to answer an interrupt",
        started.elapsed()
    );
}

/// The address is not re-fetched every tick — only when the route out changes.
/// Asking a provider every two seconds where this machine is would be both
/// rude and pointless.
#[test]
fn the_public_address_is_looked_up_once_and_then_aged() {
    let (_, text) = watch_then_interrupt(&["--watch", "1", "--no-color"], 4);

    let headings: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("PUBLIC ADDRESS"))
        .collect();
    if headings.is_empty() {
        return; // offline, or the lookup is disabled machine-wide
    }

    // At most one heading says nothing about age: the frame it was measured
    // in. Every later one carries how old it is.
    let fresh = headings.iter().filter(|line| !line.contains("ago")).count();
    assert!(
        fresh <= 1,
        "the address was looked up {fresh} times: {headings:?}"
    );
    assert!(
        headings.iter().any(|line| line.contains("ago")),
        "no frame said how old the address was: {headings:?}"
    );
}
