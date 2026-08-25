# Reachability probes

## Purpose

Answer one question — is the internet actually reachable, and if not, which of
the four ways is it broken — and answer it without ever claiming more than was
measured.

## Ownership

`src/probe/**`.

## Local Contracts

- **Not attempted is not failed.** A stage after a failure is `None` in the
  model and a `rule`-coloured `·` on screen, never `✗`. `DESIGN.md` calls this
  the single most common way a CLI lies about what it knows, and
  `tests/render.rs` asserts it as well as the ladder tests here.
- **The ladder bounds its own stages.** Each call is wrapped in a timeout by
  `bounded()` rather than trusting the implementation to honour the duration it
  was handed — a collaborator that stalls is exactly the case the overall bound
  exists for. The whole ladder finishes inside `GATEWAY_TIMEOUT + timeout`
  (2.5 s by default), not four times the per-probe timeout, and the DNS stage
  takes at most half the remaining budget so the HTTP stage is always reached.
- **A refused connection is an answer.** The gateway stage asks whether the
  router is *there*, and an RST proves it as well as an accepted connection
  does. Only silence means unreachable. ICMP would need a raw socket and
  therefore privileges this tool refuses to ask for.
- **A filtered port 80 is not offline.** DNS answered, so the internet is
  reachable; something is filtering the web. The stage reports `ok: false`
  while the state stays `Online`, and the renderer says which.
- **Portable.** Three small traits — `Connector`, `Resolver`, `HttpClient` —
  keep the stages off the platform layer entirely. `net.rs` is the only module
  that opens a socket; `mock.rs` is the only one used by the tests.
- Redirects are disabled: a redirect *is* the answer.
- The resolvers queried are the ones the system is configured with, from the
  `Snapshot`, not whatever this process would have used by default.
- Only two hosts are ever contacted, both over plain HTTP to Apple's captive
  portal endpoint that macOS already queries anyway. Adding a third party to
  the conversation is a privacy decision, not an implementation detail.

## Work Guidance

Every shape the ladder distinguishes has a constructor in `mock.rs`. A new
outcome means a new constructor and a test, not a new branch observed against
whatever network the developer happened to be on.

`link.rs` deliberately does not use `reach::classify`. That function answers
"who can reach this address", by which measure a link-local address is on the
LAN; this stage asks whether an address can carry traffic to a gateway, and a
self-assigned 169.254 address cannot.

## Verification

```
cargo test probe
cargo test --test render        # the not-attempted rendering
netinspect check -v; echo $?    # 0 online, 10/11/12/13 otherwise
```
