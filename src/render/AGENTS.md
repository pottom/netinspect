# Rendering

## Purpose

Turn a `Snapshot` into bytes: the human report, and the JSON envelope.

## Ownership

`src/render/**`.

## Local Contracts

**`docs/DESIGN.md` is normative for everything in this directory.** It replaces
the colour table in §7.3 of the implementation spec. Read it before changing
anything here, and work through its §8 checklist before adding a row.

- **Hue encodes reach — how far away a thing can be touched from — and nothing
  else gets a hue.** `reach.rs` is the one function that decides it, used by
  every renderer, with no local exceptions. Everything that is not an address,
  a probe outcome, or a runnable command is a neutral, and hierarchy inside the
  neutrals comes from weight and lightness.
- Green means a probe answered and red means it did not. Never "good value" or
  "big number" — which is why the signal bars are `bright`, not `ok`.
- `public` is not a warning. Amber on a public IP is neutral; amber on
  `firewall: off` is alarming. Severity comes from the word, not the hue. Do
  not add a fourth colour.
- A stage that was never attempted is `rule`-coloured and gets `·`, not `✗`.
  Only attempted-and-failed is red. This is the most common way a CLI lies
  about what it knows.
- Absent optional data: omit the row. Never print `unknown` — except firewall
  state, where silence reads as "fine".
- **Pure.** A `Snapshot` in, a `String` out. Nothing here reads the system —
  not even the clock: the header's local time arrives through `Options` so the
  renderer stays testable.
- Fragments carry a `Role`, not a colour. `Line` tracks its own visible width so
  padding is correct whether or not escape sequences were emitted.
- Presentation decisions belong here, not in the platform layer — including
  RSSI-to-bars and the Wi-Fi generation name. `--json` keeps the raw
  `802.11xx`.
- Colour is an accelerant, never the carrier. Every distinction must survive
  `--no-color`, and it survives as **structure**: status words in brackets, a
  `$` prefix on runnable lines, a separator where a hue was doing the
  separating. If the only difference was hue, add the word.

### Palettes

Four, selected by `--theme`, then `NETINSPECT_THEME`, then the terminal's OSC 11
answer, then `COLORFGBG`, then dark. The 256-colour tables are committed
constants: never round at runtime, or a rounding change silently reshades every
report.

Two of `DESIGN.md` §3's contrast claims do not hold for the palettes it
specifies, and the tests record the measured reality instead of rounding it
away — see `KNOWN_SHORTFALLS` in `theme.rs` and the implementation note in
`DESIGN.md` §3. Each recorded value is a ceiling, so a palette edit may only
improve it. Hue separation is asserted in OKLab, because WCAG luminance
contrast is the wrong instrument for colours deliberately matched in lightness.

## Work Guidance

Wording that hedges is deliberate. The macOS application firewall filters by
application rather than by port, so the `listen` footer says exposed ports "may
still be filtered per app" and must not be tightened into a guarantee.

## Verification

```
cargo test render
cargo test --test render     # insta golden reports
cargo insta review           # after an intentional layout change
```

Snapshots under `tests/snapshots/` are reviewed, not accepted blindly: a diff
there is the report changing under someone's eyes. `tests/render.rs` also
asserts the invariants the eye will not catch — that no line overruns 62
columns at any width, that addresses are coloured by reach alone, and that the
signal bars never come out green.
