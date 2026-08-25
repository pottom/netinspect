# The public address

## Purpose

Resolve what the internet sees of this machine, say where that is, and answer
one question about it that nothing else can: is the tunnel actually carrying
the traffic.

## Ownership

`src/public/**`.

## Local Contracts

**This is the only part of netinspect that tells a third party anything.** Every
rule below follows from that.

- One provider, named in `DEFAULT_ENDPOINT` so that changing who is told about
  this machine is a visible edit rather than a buried string.
- On a rate limit the fallback is the *same* provider's plain-address endpoint.
  Falling back to a different one would tell a second party about this machine
  to work around the first one being busy.
- Disabled by `--no-lookup` or `NETINSPECT_NO_LOOKUP=1`, and `check` never
  looks up at all — it answers through an exit code and has no use for a
  location. `tests/json_output.rs` asserts that by checking no cache was
  written.
- The lookup is **cancelled** when the ladder does not end online: there is no
  reason to keep telling a provider about a machine whose report will not use
  the reply.
- A fresh cached answer means a run discloses nothing. That is the cache's
  first job; its second is below.
- `geo.json` is written with mode `0600`, created with the mode already set
  rather than relaxed afterwards, and re-set on an existing file. It records
  where this machine is.

### Saying nothing is a result

`via_vpn` is `None` far more often than it is anything else, and that is
correct. Answering it needs a record of what this machine looks like with **no
tunnel up** — the baseline — and until one exists there is nothing to compare
against. Guessing would either raise a false alarm or, worse, quietly reassure
someone whose traffic is leaking.

`cache::baseline_after` only records an observation taken with no tunnel active.
A tunnelled observation must never become the baseline the leak check compares
against, or the check would compare the tunnel to itself and always pass.

The same applies to the timezone comparison: it is stated only when both zones
are known, never inferred from one.

## Work Guidance

Parsers are pure functions over the provider's body, tested against a captured
response including the shapes that lose fields. A provider that stops returning
`city` must not take the address down with it.

The fingerprint is what a cached answer was valid *for* — the route out, not
the clock. A tunnel coming up changes it; an idle tunnel does not; the order
tunnels are listed in must not.

## Verification

```
cargo test public
cargo test --test json_output
NETINSPECT_CACHE_DIR=$(mktemp -d) netinspect -v      # cache miss, then hit
```
