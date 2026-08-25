# Updating

## Purpose

Replace this binary with a newer one, and refuse to in every case where that
cannot be done safely.

## Ownership

`src/update/**`, `.github/workflows/release.yml`, `packaging/`,
`docs/RELEASING.md`.

## Local Contracts

**The order in `run` is a security property, not a style choice.** Resolve the
release, refuse a downgrade, download everything, check the digest, check the
signature, and only then put anything next to the running binary. Every failure
returns before the target is touched.

- **The signing key is compiled in and never fetched.** A key downloaded
  alongside the thing it verifies is not a check. `PUBLIC_KEY` is empty in a
  fresh checkout and `update` **fails closed** — it refuses rather than skipping
  verification, because an update path that cannot check what it downloads is
  worse than no update path.
- The checksum catches a download that broke; the signature catches one that
  was swapped. Both run, in that order, and only the second is a security
  property.
- The temp file is created **in the target's own directory**, so the last step
  is a rename within one filesystem: atomic, with no window where the binary is
  half-written. `Scratch` removes it on every path that does not reach the
  rename, so no `?` has to remember to.
- **Never offer to escalate.** A path this user cannot write is reported as
  such and nothing else. Suggesting `sudo` is how a read-only diagnostic tool
  talks somebody into running it as root; a test asserts no outcome message
  contains the word.
- A Homebrew install is detected from its path and left alone. Fighting a
  package manager over its own files is how a machine ends up in a state nobody
  can explain.
- A pre-release is never offered by the background check. Someone who wants one
  will ask for it by name.

## The background check

Once a day at most, **after the report is on screen**, and silent when it
fails. The footer is rendered from whatever the cache already knows, so drawing
it never depends on reaching a server. A first run prints no footer at all —
pausing to ask a server about itself would be a bad first impression, and the
answer is only ever used by the next run.

`NETINSPECT_NO_UPDATE_CHECK=1` disables it. `--no-lookup` does **not**: they are
different disclosures to different parties, and the README says so.

## Work Guidance

Everything that decides whether a binary is trustworthy — the digest, the
signature, the archive, the version comparison — is a pure function over bytes
or strings, and is tested without a network, a filesystem or a release. The
install itself is tested against a temp directory, including the paths where it
must leave the original untouched.

Version comparison is by number, never by string: `0.10.0` is newer than
`0.9.0`, and that is the mistake every tool makes once.

## Verification

```
cargo test update
cargo run -- update            # refuses without a key, which is correct
cargo run -- completions zsh
```

See `docs/RELEASING.md` for the keys and secrets a real release needs.
