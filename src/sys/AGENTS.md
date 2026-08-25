# Platform layer

## Purpose

Turn whatever this operating system exposes into the `Snapshot` model, and
expose nothing else. Everything above this boundary is written against
`&dyn Platform` and compiles unchanged on any target.

## Ownership

`src/sys/mod.rs` (the trait and backend selection), `src/sys/unsupported.rs`,
and every backend subdirectory.

## Local Contracts

- **This is the only subtree that may contain `cfg(target_os = …)` or
  `unsafe`.** `tests/guards.rs` fails the build otherwise.
- Every trait method returns `Result`, and callers must tolerate `Ok(None)` and
  empty vectors. The Wi-Fi permission wall and the missing Linux firewall
  equivalent are not exceptional cases to be papered over — they are the normal
  shape of this problem.
- No method takes or returns a platform handle, file descriptor, or raw buffer.
  `SocketTable` is a parsed, owned structure. If a caller ever needs `sysctl`
  output, the abstraction has leaked.
- Attribution completeness belongs to the model, not the backend:
  `SocketTable` carries the `unattributed` count because macOS and Linux have
  the same partial-privilege problem expressed differently. Model it once.
- Presentation decisions do not belong here. RSSI-to-signal-bars lives in
  `render`, because the platform reports dBm and only the renderer decides how
  that looks.
- `unsupported.rs` is not dead weight: it keeps the portable core compiling on a
  target with no backend, which is how the portability claim is checked rather
  than believed.

## Work Guidance

Adding a backend means adding a sibling directory and one arm in the `platform`
selector. It must not require a change above the trait. If it does, the trait is
wrong — fix the trait, not the caller.

## Verification

```
cargo test --test guards
cargo clippy --all-targets -- -D warnings
```

## Child DOX Index

- `src/sys/macos/AGENTS.md` — the macOS backend.

A `src/sys/linux/` backend is not built for 1.0. The mapping is recorded in the
project specification (section 16.2); the DNS row is the expensive one.
