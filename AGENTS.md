# netinspect

Read-only network diagnostics for macOS, shipped as one binary. It prints the
current network configuration, says whether the internet is actually reachable
and which of the four ways it is not, resolves the public address, and updates
itself.

This file is the DOX rail: project-wide instructions, durable rules, and the
top-level Child DOX Index. Read it, and every AGENTS.md between here and the
file you are about to touch, before editing.

## Core Contract

- `src/model.rs` is the contract between the platform layer and everything
  above it. It depends on nothing but `serde`.
- `docs/DESIGN.md` is the contract for everything the user sees. It is
  normative for `src/render/` and replaces the colour table in §7.3 of the
  implementation spec. Its one idea — **hue encodes reach, and nothing else
  gets a hue** — is why the renderer has a single address-classification
  function and no per-row colour decisions.
- The tool is strictly read-only against the system. No writes, no route
  manipulation, no sudo. It never changes the state of the machine it inspects.
- Absent data is `None` in the model and `null` in JSON, never an empty string
  and never a guess. A field one platform cannot fill is an `Option`, and the
  renderer omits the row.

## Hard Constraints

These two override every other preference in this repository.

**No subprocess execution, with exactly one bounded exception.** Every fact
comes from a syscall, a framework binding, or a file read — never from
`ifconfig`, `netstat`, `route`, `scutil`, `networksetup`, `lsof`, `dig`,
`sysctl(8)`, or anything else. `sysctl(3)` is a libc function and is fine;
running the `sysctl` command is not.

The single exception is `src/sys/macos/ssid_helper.rs` (see its AGENTS.md).
**No second exception may be added without deleting this sentence.**

**Portable by construction.** macOS is the only supported target for 1.0, but
platform code produces the `Snapshot` model and nothing else. `src/sys/` is the
only subtree containing `cfg(target_os = …)` or `unsafe`. Everything above the
`Platform` trait compiles unchanged on a target with no backend at all —
`src/sys/unsupported.rs` exists to keep that true rather than merely claimed.

Both constraints are defended mechanically, not by review:

- `clippy.toml` disallows `std::process::Command::new`; CI runs clippy with
  `-D warnings`.
- `tests/guards.rs` fails if `Command::new`, the `disallowed_methods` allow,
  `unsafe`, or `cfg(target_os` appears outside its permitted file or subtree,
  and if `model.rs` gains an import beyond `serde` and `std`.

The constraint governs `src/`. `tests/json_output.rs` spawns the built binary,
which is the harness running the program, not the program shelling out; the
guards scan `src/` for exactly that reason.

## Work Guidance

- Milestones are tracked in `docs/MILESTONES.md`. Each one leaves a shippable
  binary; update the checklist as part of the work, not afterwards.
- Before finishing any change: `cargo clippy --all-targets -- -D warnings`,
  `cargo test`, then a DOX pass over the paths you touched.
- Prefer a pure function with a test over a comment explaining an untested one.
  The binary buffer walkers, the exposure classifier and the source-A/source-B
  join exist as pure functions specifically so they can be tested without a
  kernel.
- Two module-level `#![allow(dead_code)]` markers are in place, in `model.rs`
  and `render/theme.rs`, because both describe the whole report while its
  producers are still being written. Remove them once every field and role has
  a caller.
- Where a design document states a measurable claim, assert it in a test rather
  than trusting it. Two of `DESIGN.md`'s contrast claims turned out not to hold
  for the palettes it specifies; the tests record the measured values as
  ceilings so the shortfall is visible and cannot quietly get worse.

## Verification

```
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- --no-color
cargo run -- --json | jq .
```

## User Preferences

- macOS-specific and Linux-specific code must stay separated from the core, from
  the start rather than as a later refactor. This is why the `Platform` trait
  landed in the first milestone, before any collector was written.

## Child DOX Index

- `docs/AGENTS.md` — the design contract and the imported visual reference.
  Owns `docs/**`.
- `src/sys/AGENTS.md` — the platform layer: the `Platform` trait contract, and
  the only subtree permitted `cfg`/`unsafe`. Owns `src/sys/**`.
  - `src/sys/macos/AGENTS.md` — the macOS backend, the subprocess exception,
    and what current macOS no longer exposes.
- `src/render/AGENTS.md` — layout, colour, glyphs and output formats.

Root-owned: `src/lib.rs`, `src/main.rs`, `src/cli.rs`, `src/model.rs`,
`tests/`, and the build and release configuration.
