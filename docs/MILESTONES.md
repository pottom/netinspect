# Milestones

Each milestone leaves a shippable binary: it builds, `cargo clippy
--all-targets -- -D warnings` is clean, tests pass, and the binary runs.

## M1 — Skeleton and the platform boundary ✅

- [x] `Cargo.toml`, `clippy.toml`, `rustfmt.toml`, git repository
- [x] DOX documentation: root `AGENTS.md` plus `src/sys/`, `src/sys/macos/`,
      `src/render/`
- [x] `model.rs`: the full `Snapshot` type tree, schema 1
- [x] `sys/mod.rs`: the `Platform` trait, backend selection, `unsupported`
      backend so the core compiles on a target with no platform code
- [x] macOS: `getifaddrs` enumeration, kind and status classification, MAC,
      MTU via `ioctl`, KAME scope stripping, ordering
- [x] macOS: services from `Setup:/Network/Service/…` — display name, device
      mapping, address source
- [x] macOS: DNS, proxies, split-DNS scope count
- [x] macOS: Wi-Fi via CoreWLAN, SSID via `CachedScanRecord`, the helper ladder
- [x] macOS: VPN protocol classification, firewall state
- [x] Human report: header, interface blocks, DNS section, footer; ASCII
      fallback; narrow layout
- [x] The guard tests that defend spec 2.1 and 16.3

## M2 — JSON, locked to schema 1 ✅

- [x] `--json` / `--pretty`
- [x] Split into a library and a binary target so the renderer is reachable
      from an integration test
- [x] `insta` snapshot tests for the human report: full report, narrow
      terminal, ASCII mode, `--all`, SSID unavailable, scraped-SSID disclosure,
      the update footer, and no matching interface
- [x] Integration test: the real binary's `--json` parses and matches schema 1,
      tolerating whatever the machine's network looks like
- [x] Schema 1 frozen. Bumping `schema` is a breaking change and requires a
      major version bump

Cases for reachability, captive portal and the VPN leak warning arrive with the
milestones that render them (M3 and M4).

## Design system — imported and implemented ✅

Landed out of band, from the Claude Design project
`9df2afac-67e1-4eae-af1a-df3df5607f7c`. `docs/DESIGN.md` is now normative for
`src/render/`.

- [x] Eleven roles replacing the original ten; hue encodes reach and nothing
      else
- [x] `render/reach.rs` — one address classifier, used by every renderer
- [x] Four palettes with committed 256-colour tables, plus an 8/16-colour mode
      that keeps the reach triple as blue / cyan / yellow
- [x] `--theme`, `NETINSPECT_THEME`, OSC 11 detection via `termbg`, `COLORFGBG`
- [x] The interface rail, right-aligned annotations at column 62, uppercase
      section titles instead of rules
- [x] Structural compensation when colour is gone: bracketed status words, a
      `$` prefix on runnable lines, separators where hue was separating
- [x] Contrast and hue-separation asserted in tests, including the two claims
      in `DESIGN.md` §3 that the shipped palettes do not meet

## M3 — Reachability ladder and `check` ✅

- [x] Four staged probes with short-circuiting, each bounded by the ladder
      rather than by its collaborator; the whole ladder finishes inside
      `GATEWAY_TIMEOUT + timeout` (2.5 s by default), measured at ~80 ms
- [x] Captive portal classification: 204, Apple's page, a redirect, an
      intercepted 200, a filtered port 80, and the "every name, one address"
      resolver signal
- [x] `check` subcommand with exit codes 0/10/11/12/13, silent on success
- [x] Trait-object `Connector`, `Resolver` and `HttpClient`, with a mock
      covering every outcome the ladder distinguishes
- [x] The reachability section rendered per `DESIGN.md`: timings aligned under
      their stage, an untried stage drawn as `·` and never as `✗`, and a
      one-word verdict with a plain-language explanation

## Adaptive width ✅

Landed out of band, after the report was seen on a wide terminal.

- [x] Content edge follows the terminal between 62 and 96 columns
- [x] The radio row stops stacking once it fits — the second line is a
      consequence of the width, not a fixture
- [x] `DNS` and `REACHABILITY` pair side by side when both fit, packed against
      each other rather than splitting the terminal in half
- [x] Asserted at every width from 38 to 200: nothing overruns the edge it
      settled on, and the paired timings stay under their stage names

## M4 — Public address, cache, timezone, VPN correlation ✅

- [x] `ipinfo.io` lookup, cancelled if the ladder does not end online, with a
      fallback to the same provider's plain-address endpoint on a rate limit
- [x] `geo.json` cache: 15-minute TTL, fingerprint invalidation on a changed
      route out, mode 0600 set at creation and re-set on rewrite
- [x] Timezone comparison, stated only when both zones are known
- [x] VPN correlation against a baseline recorded with no tunnel up — and
      `None` whenever there is no baseline to compare against, which is most
      of the time and is the honest answer
- [x] `--no-lookup`, `NETINSPECT_NO_LOOKUP`, `NETINSPECT_GEO_ENDPOINT`, and
      `check` never looking up at all

## M5 — `routes` ✅

- [x] `parse/rt_msg.rs`: a pure `&[u8]` walker over the `NET_RT_DUMP` buffer,
      with every malformed shape returning an error rather than panicking
- [x] `sysctl(3)` FFI, the documented flag order, prefix length read from a
      netmask the kernel truncates to as few bytes as it needed
- [x] Rendering with column widths measured from the data; the gateway column
      truncates first and a destination never does
- [x] Three committed fixtures — real buffers with the addresses rewritten into
      the documentation ranges — plus every truncation of each, 4000 corrupted
      variants, and a `cargo-fuzz` target
- [x] `--all`, `--iface`, `-4`/`-6`, and `--json` on the shared envelope

Only one machine was available to capture from, so the fixtures are one tunnel
state rather than the three the specification asks for. The unit tests build
the shapes a capture could not supply.

## M6 — `listen` and the firewall footer ✅

- [x] `parse/pcb.rs`: a pure walker over `pcblist_n`, landed before the
      `libproc` enrichment so the socket list is complete whoever runs it
- [x] `libproc` attribution joined on the kernel's own socket handle, with the
      join tested for the unprivileged case where it returns nothing at all
- [x] Exposure classification, most exposed first, and the `unattributed` count
- [x] Rendering per the design reference, including the deliberately hedged
      firewall footer and the `sudo` line that fixes the missing names
- [x] `--tcp`/`--udp`, `--exposed`, `--port`, `--resolve`, `--all`, `--json`
- [x] Two committed fixtures with addresses and uids rewritten, every
      truncation, 4000 corrupted variants, and a `cargo-fuzz` target
- [x] Output compared against `lsof` row for row: a strict superset, with
      eleven root-owned listeners `lsof` cannot see unprivileged

## M7 — `--watch` ✅

- [x] Redraw in place with home and clear-to-end; local collection and the
      reachability ladder re-run every tick
- [x] The public address is looked up only when the route out changes, and the
      heading says how old the one on screen is
- [x] The cursor is hidden while watching and restored on the way out, whatever
      the way out was; an interrupt is answered inside 50 ms rather than at the
      end of the interval
- [x] An interrupted watch exits 0 — it did what was asked

The specification mentions the alternate screen; this uses home and
clear-to-end instead, which is the escape sequence it also names. The last
frame then stays on the terminal after Ctrl-C, which is what a monitoring
command is usually wanted for.

## M8 — Self-update and the release pipeline

- [ ] Update check: cached, non-blocking, refreshed at most daily
- [ ] `self-update` in the exact order of spec 10.2, leaving the original binary
      untouched on every failure path
- [ ] Homebrew receipt detection; never offers to escalate with sudo
- [ ] `completions` subcommand
- [ ] Release workflow: two targets, `lipo`, sign, notarize, staple, tar,
      minisign, `SHA256SUMS`, Homebrew tap
