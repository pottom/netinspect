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

### `pcb`, specifically

The `_n` structures are **not in the public SDK** — they sit behind `PRIVATE` —
so they are transcribed from xnu, and a transcription error is silent by
nature. Three things were wrong on the first attempt and none of them failed
loudly:

- **Blocks are padded to an eight-byte boundary.** Nothing in the structures
  says so. A walk that advances by the length alone reads the padding as the
  next block's header and stops dead, four blocks in.
- **`inp_vflag` is at offset 44, not 48**, and every field after it moves with
  it. The wrong offsets parse cleanly and report every `[::]` listener as
  `0.0.0.0`, so the table fills with apparent duplicates.
- **`so_uid` is at 64**, in a block that is 104 bytes rather than the 72 an
  older transcription gives.

All three were found by checking the running kernel — which flag byte differs
between the two port-22 listeners, where `7f000001` actually sits in a loopback
socket, which offset yields this machine's own uid — and the output was then
compared against `lsof` row for row. That comparison is the real test of a
transcription; the unit tests only prove the parser agrees with it.

A dual-stack socket carries **both** family flags: it is an `AF_INET6` socket
that also accepts v4-mapped connections. IPv6 wins, which is what `lsof` does
too.

## Fixtures

`tests/fixtures/*.bin` are real buffers from a real kernel, **rewritten into
the documentation address ranges**, and for the socket tables with every
non-root uid replaced by one anonymous value. Every length, family, flag, alignment byte
and truncated netmask is exactly as the kernel emitted it; only the addresses
are changed. A raw dump describes the machine it came from — its LAN, and every
prefix a corporate tunnel pushes — and none of that belongs in a repository.

Re-capture with `cargo test --lib -- --ignored capture_fixtures` and
`capture_socket_fixtures`. The capture
asserts that sanitising did not change the record count, so a fixture that
still parses is a fixture whose structure survived.

A hand-built fixture can only encode what its author already believed the
format to be. Keep both: the unit tests build records by hand to reach shapes a
capture may not contain, and the fixture tests check that belief against a real
kernel.

## Verification

```
cargo test parse
cargo test --test fixtures      # real buffers, every truncation, 4000 corruptions
cargo +nightly fuzz run rt_msg  # optional, needs cargo-fuzz
cargo +nightly fuzz run pcb

# The check that matters for a transcription: agree with a tool that already
# reads this kernel correctly.
cargo run -- listen --tcp --ascii --no-color
lsof -nP -iTCP -sTCP:LISTEN
```
