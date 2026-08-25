# netinspect

Read-only network diagnostics for macOS, in one binary.

```
$ netinspect
  netinspect 0.1.0                               21:05:58 CEST
  ────────────────────────────────────────────────────────────

  ▌ Wi-Fi en0                                        connected
  │ network     Nyuszilak                        ▇▇▇▇▇ −30 dBm
  │             Wi-Fi 5 · 866 Mb/s · via scan cache
  │ ipv4        192.168.1.110/24                          dhcp
  │ ipv6        fe80::1841:c0c3:c03b:e16d
  │ gateway     192.168.1.1
  ╵ hardware    1a:18:dc:a0:08:9f                     mtu 1500

  ▌ VPN utun4                                               up
  ╵ ipv4        10.4.3.90/32

  ╵ Ethernet Adapter (en5) en5                        no cable

  DNS
    servers     10.4.60.100   10.4.60.50
    search      groupit.local
    proxy       none
    split-dns   2 scoped resolvers
```

`--json` emits the same data in a stable, versioned schema.

## Reading the colour

One idea carries the whole tool: **hue encodes reach — how far away a thing can
be touched from.** Nothing else gets a hue.

| | |
|---|---|
| blue | only this machine can reach it — `127.0.0.1`, `::1` |
| teal | this network can reach it — `192.168.…`, `10.…`, `fe80::` |
| amber | the open internet is involved — public addresses, `0.0.0.0` |

Green and red mean a probe answered or did not. They never mean "good value" or
"big number", which is why the signal bars are white. Violet marks the one thing
on a line you can copy and run. Everything else — names, MACs, MTUs, flags — is
a neutral, and its emphasis comes from weight, not colour.

Amber is not a warning. Amber on a public address is neutral information; amber
on `firewall: off` is alarming. The colour is the same because the fact is the
same; the severity is in the word next to it.

The full rules are in [`docs/DESIGN.md`](docs/DESIGN.md).

## Terminals

Four palettes, each tuned and contrast-checked against its own background:
`dark`, `dark-warm`, `light` and `light-warm`. netinspect asks the terminal what
colour it is painted (OSC 11), falls back to `COLORFGBG`, then to dark.
`--theme` or `NETINSPECT_THEME` overrides.

On a 256-colour terminal the palette maps to committed index tables rather than
being rounded at runtime. On an 8-colour terminal the reach triple survives as
blue / cyan / yellow — that is why those three hues were chosen over three
bespoke ones. With `--no-color` it survives as structure: status words go in
brackets, runnable lines take a `$` prefix, and separators appear where colour
was doing the separating.

Below 66 columns the layout stacks; below 40 it drops the rail.

## What it does not do

It never changes a setting. No `networksetup` writes, no route manipulation, no
sudo. It reads the machine and prints what it finds.

It also does not shell out. Every fact comes from a syscall, a framework
binding, or a file read — with exactly one exception, below.

## Honest limits on current macOS

**The SSID is gated.** From macOS 14, reading it requires Location Services
authorization, and a CLI binary cannot obtain it: the prompt needs an
application bundle with `NSLocationUsageDescription` in its `Info.plist`, and an
unbundled executable has none. RSSI, PHY mode and transmit rate are unaffected.

netinspect tries three things in order and tells you which one answered:

1. CoreWLAN — the supported API. Returns `nil` on macOS 14+.
2. The `CachedScanRecord` blob in the dynamic store. Native and undocumented;
   on macOS 26 it still carries the SSID. Shown as `·via scan cache`.
3. Three system commands (`networksetup`, `ipconfig`, and with `--slow-helpers`,
   `system_profiler`). This is the one subprocess exception in the program. On
   macOS 14 and later all three are subject to the same gating and usually
   return nothing — on macOS 26, `networksetup` reports "not associated" even
   when you are. Disable the ladder entirely with `--no-helpers` or
   `NETINSPECT_NO_HELPERS=1`.

A scraped value is always labelled. You should never have to guess whether a
number came from a supported API or from parsing a command's output.

**The DHCP lease expiry is not readable.** macOS 15+ removed the dynamic store
key and the lease files are root-only, so the report says `dhcp` without a
countdown.

**The application firewall state is not readable.**
`/Library/Preferences/com.apple.alf.plist` no longer exists, and the only copy
on disk is an OS default template that would report "off" regardless of the
truth. netinspect reports the state as unknown and omits the footer rather than
telling you a port is protected when it does not know. Note also that the macOS
application firewall filters by application, not by port, and does not apply to
traffic already accepted by a listening system service.

## Privacy

The public-address lookup sends this machine's IP to ipinfo.io
([privacy policy](https://ipinfo.io/privacy)). Disable it with `--no-lookup` or
`NETINSPECT_NO_LOOKUP=1`.

`--no-lookup` does **not** disable the update check; that is
`NETINSPECT_NO_UPDATE_CHECK=1`.

Nothing else leaves the machine. No telemetry, no crash reporting. The geo cache
is written with mode `0600`.

`listen --json` includes process names, pids and usernames. That output is
reasonable to paste into a bug report, and is a mild disclosure of what runs on
the machine.

## Building

```
cargo build --release
```

macOS 13+ on arm64 or x86_64. See `AGENTS.md` for the rules the codebase holds
itself to, and `docs/MILESTONES.md` for what is built so far.
