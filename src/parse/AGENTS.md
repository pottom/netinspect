# Binary walkers

## Purpose

Turn the opaque buffers the kernel hands back into structures the rest of the
program can read.

## Ownership

`src/parse/**`, and the fixtures under `tests/fixtures/`.

## Local Contracts

- **Pure functions over `&[u8]`.** No syscalls, no allocation of a buffer they
  did not receive, no clock. `rt_msg` deliberately reports `rmx_expire`
  verbatim — it is an absolute time, and turning it into "seconds remaining"
  needs a clock the parser does not have and should not acquire.
- **Malformed input returns an error. Never a panic, never a read past the
  end.** These parsers are the only thing between a truncated read and a crash.
  Every field access is bounds-checked, and every length claimed by the buffer
  is checked against what remains before it is trusted.
- A record with an unrecognised version is *skipped*, not rejected: a future
  kernel adding a message type must not take the whole table down with it. A
  record that claims a known version but is shorter than its own header is an
  error.
- A bit that is clear in an address bitmask consumes nothing. Getting this
  wrong reads every later field out of the middle of an earlier one, and the
  result parses cleanly while being entirely wrong — which is why
  `an_absent_slot_consumes_nothing` exists.
- These live outside `sys/` even though the formats are macOS-specific today,
  because being pure is what makes them testable and fuzzable without a kernel.

## Fixtures

`tests/fixtures/*.bin` are real buffers from a real kernel, **rewritten into
the documentation address ranges**. Every length, family, flag, alignment byte
and truncated netmask is exactly as the kernel emitted it; only the addresses
are changed. A raw dump describes the machine it came from — its LAN, and every
prefix a corporate tunnel pushes — and none of that belongs in a repository.

Re-capture with `cargo test --lib -- --ignored capture_fixtures`. The capture
asserts that sanitising did not change the record count, so a fixture that
still parses is a fixture whose structure survived.

A hand-built fixture can only encode what its author already believed the
format to be. Keep both: the unit tests build records by hand to reach shapes a
capture may not contain, and the fixture tests check that belief against a real
kernel.

## Verification

```
cargo test rt_msg
cargo test --test fixtures      # real buffers, every truncation, 4000 corruptions
cargo +nightly fuzz run rt_msg  # optional, needs cargo-fuzz
```
