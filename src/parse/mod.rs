//! Binary buffer walkers.
//!
//! These live outside `sys/` even though the formats are macOS-specific today,
//! because they are pure functions over `&[u8]`: a syscall produces the buffer
//! somewhere else, and everything that can go wrong with the parsing can be
//! reached from a test with no kernel and no privileges.
//!
//! See `src/parse/AGENTS.md`.

pub mod pcb;
pub mod rt_msg;
