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

## M4 — Public address, cache, timezone, VPN correlation

- [ ] `ipinfo.io` lookup with a plain-IP fallback on 429
- [ ] `geo.json` cache: 15-minute TTL, gateway/VPN fingerprint invalidation,
      mode 0600
- [ ] Timezone comparison against the system clock
- [ ] VPN correlation, including the leak warning

## M5 — `routes`

- [ ] `parse/rt_msg.rs`: a pure `&[u8]` walker over the `NET_RT_DUMP` buffer
- [ ] `sysctl(3)` FFI, flag decoding, prefix length from the netmask sockaddr
- [ ] Rendering with column widths computed from the data
- [ ] Committed fixtures (VPN up, VPN down, IPv6 disabled) and a fuzz target

## M6 — `listen` and the firewall footer

- [ ] `parse/pcb.rs`: a pure walker over `pcblist_n`, landing before the
      `libproc` enrichment so the socket list is always complete if anonymous
- [ ] `libproc` attribution, with the join tested for the unprivileged case
      where it returns nothing at all
- [ ] Exposure classification and the `unattributed` count
- [ ] Fuzz target

## M7 — `--watch`

- [ ] Redraw in place; re-run local collection and the ladder each tick
- [ ] Re-run the public lookup only on a fingerprint change; show cache age
- [ ] Restore the cursor on SIGINT

## M8 — Self-update and the release pipeline

- [ ] Update check: cached, non-blocking, refreshed at most daily
- [ ] `self-update` in the exact order of spec 10.2, leaving the original binary
      untouched on every failure path
- [ ] Homebrew receipt detection; never offers to escalate with sudo
- [ ] `completions` subcommand
- [ ] Release workflow: two targets, `lipo`, sign, notarize, staple, tar,
      minisign, `SHA256SUMS`, Homebrew tap
