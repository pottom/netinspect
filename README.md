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

## Where the traffic goes

```
$ netinspect routes
  ipv4 ──────────────────────────────────────────────────────────

     destination         gateway            iface      flags
     default             192.168.1.1        en0        UGScg
     10.4.0.0/22         10.4.0.51          utun4      UGSc
     192.168.1.0/24      link#12            en0        UCS

  101 routes   8 default gateways · split tunnel active
```

Read from the kernel with `sysctl(3)`, not by parsing `netstat` — its columns
move between releases and it truncates long IPv6 addresses. Column widths are
measured from the data; when the table will not fit, the gateway column gives
way first and a destination never does.

By default it hides what the kernel keeps for itself: entries it cloned for
hosts this machine has spoken to, multicast, and the link-local prefix every
interface carries. `--all` shows them — on the machine this was built on, the
difference is 101 rows against 218.

The footer names two conditions worth noticing: more than one default gateway,
and a tunnel that carries some routes but not the default one.

## Is it actually online

```
$ netinspect check && echo yes
```

`check` prints nothing and answers through its exit code: `0` online, `10` link
down, `11` gateway unreachable, `12` dns failure, `13` captive portal. It exists
for shell prompts and scripts.

The four stages run in order and stop at the first failure, so the blame lands
on the thing that actually broke. A stage that was never attempted is drawn as a
dim dot, not a red cross — it is a different fact, and reporting it as a failure
would be a lie. The whole ladder is bounded at 2.5 seconds regardless of how
slow the network is.

Only two hosts are ever contacted, both over plain HTTP: Apple's captive portal
endpoint that macOS already queries by itself, and one unrelated name. If both
resolve to the same address, something is intercepting every query — which the
report says before the HTTP stage confirms it.

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
`NETINSPECT_NO_LOOKUP=1`, or point it elsewhere with `NETINSPECT_GEO_ENDPOINT`.

It is one provider and one request. The answer is cached for fifteen minutes, so
a repeated run discloses nothing; the request is cancelled outright if the
reachability ladder does not end online; and `check` never makes it at all. On a
rate limit the fallback is the same provider's plain-address endpoint rather
than a second company.

netinspect will tell you whether a VPN is actually carrying your traffic, but
only when it can prove it: that needs a record of what this machine looks like
with no tunnel up, which the cache keeps. Until it has one, the row says
nothing. A guess here would either raise a false alarm or quietly reassure
someone whose traffic is leaking.

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
