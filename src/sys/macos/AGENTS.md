# macOS backend

## Purpose

Produce the `Snapshot` model from macOS APIs: `getifaddrs`, `SCDynamicStore`,
CoreWLAN, `ioctl(2)`, `sysctl(3)`, and property list files.

## Ownership

`src/sys/macos/**`. Parent rules in `src/sys/AGENTS.md` and the repository root
apply and may not be weakened here.

## Local Contracts

- **`ssid_helper.rs` is the only file in the repository permitted to spawn a
  subprocess**, and the only one carrying
  `#[allow(clippy::disallowed_methods)]`. Three tests in `tests/guards.rs`
  enforce this. Its rules, all of which are load-bearing:
  absolute paths only and never through a shell; `stat` each candidate and skip
  it unless it is a regular file owned by uid 0 and not group- or
  world-writable; validate the interface name even though it comes from
  `getifaddrs`; 400 ms timeout (3 s for `system_profiler`) with the child killed
  and reaped on expiry; output capped at 64 KiB; stdout piped, stdin and stderr
  null; disabled entirely by `--no-helpers` or `NETINSPECT_NO_HELPERS=1`; and
  the source of every scraped value disclosed to the user.
- **Never enable `ipconfig setverbose`.** It is the known way to un-redact that
  candidate's output, it needs root, and it mutates a global system setting that
  would then have to be restored. A read-only diagnostic must not change the
  machine it inspects, and a crash between the two calls would leave it altered.
  A redacted value is a failed candidate; move on.
- Parsers are pure `&str → Option<String>` functions with fixture tests,
  including the redacted forms and SSIDs containing spaces and colons. Do not
  parse with whitespace splitting.
- All `SCDynamicStore` reads go through `cf.rs`, which converts CoreFoundation
  values into owned Rust ones. This is what stops a `CFTypeRef` escaping through
  the trait.
- Do not read `/etc/resolv.conf`: on macOS it is a compatibility shim and does
  not reflect per-interface resolvers.

## What current macOS no longer exposes

Measured on macOS 26.5.1. Each of these contradicts documentation that is still
widely repeated, so they are recorded here rather than rediscovered.

| Source | Reality | What we do |
|---|---|---|
| `/Library/Preferences/com.apple.alf.plist` | Does not exist. The only copy on disk is the OS default template under `/usr/libexec/ApplicationFirewall/`, whose `globalstate` reads 0 — indistinguishable from a machine with the firewall genuinely off. | Report `Unknown` and omit the footer. **The template is never a source.** |
| `State:/Network/Interface/<if>/DHCP` | No such key. Lease files under `/var/db/dhcpclient/leases/` are root-only. | Address source comes from `Setup:/Network/Service/<id>/IPv4` → `ConfigMethod`; the expiry is simply `None`. |
| `State:/Network/Interface/<if>/AirPort` → `SSID_STR` | Blanked by the privacy gating. `BSSID` reads `02:00:…`. `CHANNEL` is real. | Fall through to `CachedScanRecord`. |
| `State:/Network/Interface/<if>/AirPort` → `CachedScanRecord` | An `NSKeyedArchiver` blob that still carries the real SSID. Undocumented. | `scan_record.rs` extracts it. Native, so it precedes the subprocess ladder. Every failure path returns `None` quietly. |
| `networksetup -getairportnetwork` | Reports "You are not associated with an AirPort network." **on a machine that is associated.** | The parser maps that line to `None` — never to "no Wi-Fi". |
| `ipconfig getsummary`, `system_profiler` | Both return `<redacted>`. | Treated as failed candidates. |
| `net.inet6.tcp6.pcblist_n` | Returns zero bytes. | One MIB per protocol covers both families; the split comes from `inp_vflag`. |

The ladder is a best-effort improvement over a guaranteed blank, not a fix.
Apple has closed each of these paths in turn and is likely to close the
remainder; everything here is written to degrade quietly when that happens.

## Work Guidance

`getifaddrs` is shared with Linux verbatim — keep it that way. Everything
layered on top of it (display name, carrier state, address source) is
`SCDynamicStore` and is macOS-only.

## Verification

```
cargo test sys::macos
cargo test --test guards
```
