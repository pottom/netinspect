# netinspect — output design rules

Normative for everything in `render/`. Pairs with the implementation spec §7.
Where this file and §7.3 disagree, this file wins: it replaces the original
colour table.

The visual reference lives in `design/NetInspect CLI.dc.html`, turn 4.

---

## 1. The one idea

**Hue encodes reach — how far away a thing can be touched from.** Nothing else
gets a hue. A reader who learns three colours can read every subcommand.

| Channel | Carries | Vocabulary |
|---|---|---|
| `reach` | where an address lives | `local` · `lan` · `public` |
| `state` | did a probe work | `ok` · `fail` · not attempted |
| `action` | can I copy this and run it | `action` |

Everything else — names, MACs, MTUs, flags, durations, counts, process names —
is neutral. Hierarchy inside the neutrals comes from **weight and lightness,
never from hue**.

Consequences, stated so they are not re-litigated per row:

- An IP address is never coloured by importance, only by reach. The gateway is
  not more important than the DHCP server; they are both on this network, so
  they are both `lan`.
- Green never means "good value" and red never means "big number". They mean a
  probe answered or did not.
- If a row needs emphasis and has no reach, no state and no action, it gets
  `bright`, not a colour.

---

## 2. Roles

Eleven roles. Anything not on this list is a bug.

| Role | Meaning | Applied to |
|---|---|---|
| `bright` | the answer to the question the user asked | SSID, ISP name, `default`, port numbers, counts, section-leading words |
| `body` | ordinary values | protocol names, hostnames, cities, process names |
| `dim` | the label column | `ipv4`, `gateway`, section titles |
| `faint` | reference material and units | MAC, MTU, flags, `ms`, prefix `/24`, the `:` before a port, pids, `—` |
| `rule` | structure that must not be read | rails, connectors, the "not attempted" `·` |
| `ok` | a probe answered | `✓`, `connected`, `up`, `online` |
| `fail` | a probe failed, or a guarantee is broken | `✗`, `dns failure`, `not routed through VPN` |
| `local` | reachable only from this machine | `127.0.0.0/8`, `::1`, loopback sockets |
| `lan` | reachable from this network | RFC1918, CGNAT, link-local, `fe80::`, multicast, VPN inner addresses |
| `public` | reachable from, or belonging to, the open internet | public IPs, `0.0.0.0`, `[::]`, DNS resolvers, VPN endpoints, `firewall: off`, `captive portal` |
| `action` | copyable and runnable | login URLs, `netinspect self-update`, `sudo netinspect listen` |

### 2.1 Classifying an address

One function, used by every renderer. No local exceptions.

```
loopback                                   -> local
RFC1918 · CGNAT 100.64/10 · link-local
  169.254/16 · fe80::/10 · fc00::/7
  multicast · link#N                       -> lan
everything else                            -> public
```

`0.0.0.0` and `::` are `public`: a wildcard bind is an internet-facing bind
whenever an interface has a routable address, and a security readout must
assume the worse of the two readings.

### 2.2 `public` is not a warning

Amber on a public IP is neutral information; amber on `firewall: off` is a
warning. The colour is the same because the *fact* is the same — the open
internet is involved. Severity comes from the word next to it, not the hue.
Do not add a fourth "warning" colour.

---

## 3. Palettes

Terminals do not tell us their background. Ship four palettes, pick with
`termbg` where the terminal answers the OSC 11 query, fall back to
`COLORFGBG`, then to dark. `--theme dark|light|dark-warm|light-warm` overrides.

Each palette below is verified against its background: `body` ≥ 7:1,
`dim` ≥ 4.5:1, `faint` ≥ 3:1, every hue ≥ 4.5:1, and adjacent hues ≥ 1.4:1
against each other. Do not adjust one row without re-checking those.

> **Implementation note.** Two of those claims do not hold for the palettes as
> specified, and `src/render/theme.rs` records the measured reality rather than
> rounding it away:
>
> - `faint` reaches only 2.30–2.59:1 against its own background in all four
>   palettes, and `dim` reaches 3.60:1 (light-warm) and 4.29:1 (light). The
>   shortfalls are listed in `KNOWN_SHORTFALLS`; the test treats each measured
>   value as a ceiling, so a palette edit may only improve them.
> - "adjacent hues ≥ 1.4:1" is measured with the wrong instrument. The reach
>   triple is deliberately equal in lightness so the three read as peers, which
>   puts every pair near 1.1:1 in WCAG luminance terms while being obviously
>   different colours. Hue separation is asserted in OKLab instead, where the
>   triple sits at 0.13–0.24 and the closest pair of any two hues is 0.087.

### dark (default, tuned on `#0E0E11`, valid `#000000`–`#22222A`)

| Role | Hex |
|---|---|
| bright | `#F2F0E9` |
| body | `#B9B7AF` |
| dim | `#7F7D76` |
| faint | `#575550` |
| rule | `#2A2B30` |
| ok | `#8CC96F` |
| fail | `#F2705F` |
| local | `#7FB0E8` |
| lan | `#45BBA0` |
| public | `#EBAB45` |
| action | `#BCA2F5` |

### dark-warm (tuned on `#1C1917`; also covers Solarized dark `#002B36`)

| Role | Hex |
|---|---|
| bright | `#F5EFE6` |
| body | `#C0B7AB` |
| dim | `#8A8177` |
| faint | `#615A52` |
| rule | `#332E2A` |
| ok | `#93C96B` |
| fail | `#F0736A` |
| local | `#83AEEA` |
| lan | `#48BDA2` |
| public | `#EEAC41` |
| action | `#C0A4F7` |

On Solarized dark specifically, `lan` and `ok` converge; shift `lan` to
`#31BFA8` and `ok` to `#8EBF3F` when the detected background is bluer than
hue 180 at chroma > 0.02.

### light (tuned on `#FAF8F3`, valid `#F0F0F0`–`#FFFFFF`)

| Role | Hex |
|---|---|
| bright | `#17161A` |
| body | `#44423B` |
| dim | `#78766E` |
| faint | `#A3A097` |
| rule | `#E0DCD1` |
| ok | `#3F7A22` |
| fail | `#C0392B` |
| local | `#1F5FA8` |
| lan | `#0F7365` |
| public | `#8A5A0A` |
| action | `#6146C4` |

On pure white push every hue one step darker: `ok #357017`, `fail #B52F22`,
`local #14539C`, `lan #0A6659`, `public #7D4F04`, `action #5539BD`.

### light-warm (Solarized light `#FDF6E3`)

| Role | Hex |
|---|---|
| bright | `#1C1E21` |
| body | `#4B5457` |
| dim | `#7A8385` |
| faint | `#A0A69F` |
| rule | `#E6DDC6` |
| ok | `#4A7A12` |
| fail | `#BC3B2E` |
| local | `#19589E` |
| lan | `#0D6F61` |
| public | `#8A5502` |
| action | `#5B3FC0` |

### Degraded colour

- **truecolor** (`COLORTERM=truecolor|24bit`): the hexes above.
- **256 colour**: nearest xterm index, computed at build time and committed as
  a table — never rounded at runtime.
- **8/16 colour**: `local` → blue, `lan` → cyan, `public` → yellow, `ok` →
  green, `fail` → red, `action` → magenta, `bright` → bold default,
  `dim`/`faint` → default and dim. The reach triple survives; that is the
  point of choosing blue/cyan/yellow rather than three custom hues.
- **no colour** (`--no-color`, `NO_COLOR`, not a TTY): see §6.

---

## 4. Layout

Inherits §7.2 of the spec, with these refinements:

- Content width 62 columns, left margin 2.
- Label column starts at 4, padded to 12. Values start at 16.
- Annotations right-align to column 62. If the value would collide, the
  annotation drops to its own line at column 16 — never wraps mid-value.
- Interface status right-aligns to column 62.
- Sections are separated by **one blank line and an uppercase title in `dim`**,
  not a horizontal rule. Rules appear at most twice in a report: the header
  underline and the footer, and only when the terminal is at least 66 columns.
- No blank line between a section title and its first row.
- One blank line between interfaces, none between rows within one.

> **Implementation note — column numbers.** The numbers above are zero-based
> offsets: the rail sits at offset 2, labels start at offset 4, values at
> offset 16. `src/render/layout.rs` states the same positions as one-based
> columns (3, 5, 17).
>
> **Implementation note — the content follows the terminal.** 62 columns is the
> *minimum*, not the width. A fixed 62 left a wide terminal mostly empty while
> forcing rows to stack that had room to sit on one line, so the content edge
> is `clamp(terminal - 2, 62, 96)`. Everything that right-aligns follows it.
>
> The extra columns are spent on structure, not padding:
>
> - The radio's continuation line is a consequence of the width, not a fixture.
>   At 78 columns and up the standard, rate and SSID source join the row they
>   describe; below that they drop to their own line as before.
> - `DNS` and `REACHABILITY` sit side by side once both fit. Neither block
>   right-aligns anything, so each is exactly as wide as its content and they
>   are packed against each other — splitting the terminal in half would leave
>   a gap on one side and wrap the other.
>
> 96 is where it stops: past that an annotation right-aligned against the edge
> is too far from the label it belongs to for the eye to pair them, and the
> extra room buys nothing.

### 4.1 The interface rail

Active interfaces carry a left rail: `▌` in the interface's own reach colour
on the header line, `│` in `rule` on continuation lines, `╵` in `rule` on the
last line of the block. Inactive interfaces get `╵` alone and render entirely
in `faint`.

The rail is the only decorative glyph in the tool, and it is decorative only
in shape — its colour is load-bearing.

### 4.2 Ordering

Never sort by name. Sort by what the user came to find out:

1. the interface owning the default route
2. other active interfaces
3. VPNs
4. inactive, collapsed to one line each

`listen` groups **most exposed first**: `public`, then `lan`, then `local`.
The dangerous group must never be below the fold.

---

## 5. Per-subcommand rules

### default report

- Signal bars are `▇` in `bright` and `▁` in `rule` — a measurement, not a
  status. Never green.
- The port in an `address:port` pair is `bright`; the colon is `faint`; the
  host is coloured by reach. Splitting at the colon is what makes ports
  scannable.
- A value obtained from the SSID helper ladder is annotated `via networksetup`
  in `faint`, on the continuation line. Never silently present a scraped value
  as a native one.
- Absent optional data: omit the row. Never print `unknown`. The one exception
  is firewall state, which prints `unknown` because silence there reads as
  "fine" (spec §6.8).

### reachability

- The ladder renders on one line, timings on the line below, aligned under
  each stage name.
- A stage that was never attempted is `rule`-coloured and gets `·`, not `✗`.
  Only an attempted-and-failed stage is red. This is the single most common
  way a CLI lies about what it knows.
- The verdict line is one word in `ok`/`fail`/`public`, then a `faint`
  explanation in plain language. No jargon in the explanation: "the network
  answers, the internet does not" beats "HTTP 302 intercept".

### routes

- `default` is the only destination in `bright`; every other destination is
  coloured by reach.
- Column widths are measured from the data, clamped to terminal width. The
  gateway column truncates first, with `…`. **Never truncate a destination.**
- Flags are always `faint`. They are reference material, not the point.

> **Implementation note — `routes`.** Three details where the prose and the
> visual reference disagree, resolved in favour of the prose:
>
> - The letter order is the one §6.6 of the specification lists
>   (`U G H S C c L W I i m g R D M`), not `netstat`'s and not the artboard's,
>   which contradicts itself between rows. A fixed order matters more than
>   matching either.
> - The default view hides what §6.6 says to hide — cloned host entries,
>   multicast, and every interface's link-local prefix — even though the
>   artboard shows a multicast and a `fe80::/64` row. On the machine this was
>   built on that is the difference between 218 rows and 101.
> - `routes` heads each family with `ipv4 ────…` rather than the report's
>   uppercase section title. It is the subcommand's own layout, and the
>   artboard is the only description of it.

### listen

- Group headers carry the group's reach colour on the rail and the count in
  `faint`, right-aligned.
- Unattributed sockets render `—` in `faint` in both process and pid. Never
  omit the socket.
- The footer's `sudo netinspect listen` is `action` — it is the fix, so it must
  be copyable-looking.

---

## 6. `--no-color`, `--ascii`, narrow

Colour is an accelerant, never the carrier. Every distinction above must
survive its removal, and the way it survives is **structure**, not adjectives:

- Reach becomes the group header (`reachable from the network` / `bound to one
  interface` / `this machine only`) — already present in colour mode, so
  nothing changes but the emphasis.
- State becomes `ok` / `xx` / blank, and status words go in brackets:
  `[connected]`, `[online]`.
- Action lines get a `$ ` prefix so they read as commands.

Below 66 columns: stacked layout, label on its own line, value indented 4, no
right-alignment, no rules. Below 40: the same, and drop the rail.

`--ascii` glyph table is spec §7.7 and unchanged, plus: `▌` → `|`, `╵` → `.`,
`◐` → `!`.

---

> **Implementation note — watch mode.** The report is redrawn with home and
> clear-to-end rather than on the alternate screen, so the last frame survives
> the exit. The `PUBLIC ADDRESS` heading carries the age of the address on
> screen — it is not re-fetched every tick, only when the route out changes.

## 7. Copywriting

- Lowercase labels, always. Uppercase only for section titles and acronyms
  that are genuinely uppercase (DNS, VPN, TLS, ASN).
- No punctuation at the end of a row.
- Numbers get a space before the unit: `38 ms`, `1200 Mb/s`, `±20 km`.
- Say what happened, then what to do. Never say what you cannot verify — the
  firewall footer is deliberately hedged (spec §7.9) and must stay that way.
- Time is relative for anything under a day (`renews in 4h 12m`,
  `handshake 41s ago`), absolute in `--json` (RFC 3339).

---

## 8. Checklist for a new row

1. Is it an address? Colour by reach, nothing else.
2. Is it a probe outcome? `ok`/`fail`, and only if actually attempted.
3. Can the user copy and run it? `action`.
4. Otherwise: pick a neutral by how much the reader needs it, and stop.
5. Does it survive `--no-color`? If the only difference was hue, add the word.
6. Does it survive 48 columns? If not, define its stacked form now.
