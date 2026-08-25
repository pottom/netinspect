//! The routing table, via `sysctl(3)`.
//!
//! `sysctl(3)` is a libc function; running the `sysctl` command would be a
//! subprocess and is forbidden. `netstat -rn` is not an option either — its
//! column layout differs between releases and it truncates long IPv6
//! addresses.
//!
//! This module does the syscall and the conversion into the model. The buffer
//! walk itself lives in `parse::rt_msg`, where it can be tested and fuzzed
//! without a kernel.

use anyhow::{bail, Context, Result};

use crate::model::{Family, GatewayKind, Route};
use crate::parse::rt_msg::{self, RouteMessage, SocketAddress};

const CTL_NET: libc::c_int = 4;
const PF_ROUTE: libc::c_int = 17;
const NET_RT_DUMP: libc::c_int = 1;

/// Flag letters, in the order `DESIGN.md` and the specification list them.
/// A fixed order matters more than matching any particular `netstat`.
const FLAGS: [(u32, char, &str); 15] = [
    (0x1, 'U', "up"),
    (0x2, 'G', "gateway"),
    (0x4, 'H', "host"),
    (0x800, 'S', "static"),
    (0x100, 'C', "cloning"),
    (0x10000, 'c', "protocol-cloning"),
    (0x400, 'L', "link"),
    (0x20000, 'W', "was-cloned"),
    (0x1000000, 'I', "interface-scoped"),
    (0x4000000, 'i', "iface-scope-valid"),
    (0x800000, 'm', "multicast"),
    (0x40000000, 'g', "global"),
    (0x8, 'R', "reject"),
    (0x10, 'D', "dynamic"),
    (0x20, 'M', "modified"),
];

const RTF_HOST: u32 = 0x4;

/// Ask the kernel for the whole table, then walk it.
pub fn collect(family: Option<Family>) -> Result<Vec<Route>> {
    let buffer = dump(family)?;
    let messages = rt_msg::walk(&buffer).context("the routing table could not be parsed")?;
    let now = jiff::Timestamp::now().as_second();
    Ok(messages.iter().filter_map(|m| convert(m, now)).collect())
}

/// `rmx_expire` is an absolute time. A lifetime that has already run out is
/// not a lifetime, and neither is one so far away that the field clearly means
/// something else on this route.
fn seconds_remaining(expires_at: Option<i32>, now: i64) -> Option<u32> {
    let remaining = i64::from(expires_at?) - now;
    (remaining > 0).then_some(remaining as u32)
}

/// Two calls: one to size the buffer, one to fill it. The table can grow
/// between them, so the second is allowed a little headroom and its own
/// returned length is what gets parsed.
pub(crate) fn dump(family: Option<Family>) -> Result<Vec<u8>> {
    let address_family = match family {
        Some(Family::Inet) => libc::AF_INET,
        Some(Family::Inet6) => libc::AF_INET6,
        None => 0, // both
    };
    let mut mib = [CTL_NET, PF_ROUTE, 0, address_family, NET_RT_DUMP, 0];

    let mut needed: libc::size_t = 0;
    // Safety: a six-element MIB, a null buffer to request only the size, and a
    // length the kernel writes through.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        bail!(
            "sysctl could not size the routing table: {}",
            std::io::Error::last_os_error()
        );
    }
    if needed == 0 {
        return Ok(Vec::new());
    }

    // Headroom for entries added between the two calls.
    let mut buffer = vec![0u8; needed + needed / 8 + 1024];
    let mut length = buffer.len();
    // Safety: `buffer` is `length` bytes and stays alive across the call; the
    // kernel writes at most `length` and reports what it wrote.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        bail!(
            "sysctl could not read the routing table: {}",
            std::io::Error::last_os_error()
        );
    }
    // Trust the returned length, never the requested one.
    buffer.truncate(length.min(buffer.len()));
    Ok(buffer)
}

fn convert(message: &RouteMessage, now: i64) -> Option<Route> {
    let destination = message.destination.as_ref()?;
    let ipv6 = matches!(destination, SocketAddress::V6 { .. });
    let family = if ipv6 { Family::Inet6 } else { Family::Inet };

    let prefix = match &message.netmask {
        Some(mask) => rt_msg::prefix_len(mask, ipv6),
        // No mask on a host route means all of it.
        None if message.flags & RTF_HOST != 0 => {
            if ipv6 {
                128
            } else {
                32
            }
        }
        None => 0,
    };

    let address = render_address(destination, message.interface_index)?;
    let is_default = prefix == 0 && (address == "0.0.0.0" || address == "::");
    let destination = if is_default {
        "default".to_owned()
    } else if (ipv6 && prefix == 128) || (!ipv6 && prefix == 32) {
        address
    } else {
        format!("{address}/{prefix}")
    };

    let (gateway, gateway_kind) = match &message.gateway {
        Some(SocketAddress::Link { index, name, mac }) => match mac {
            // An ARP or NDP cache entry: the next hop is a hardware address.
            Some(mac) => (Some(format_mac(mac)), GatewayKind::Mac),
            None => (
                Some(match name {
                    Some(name) => name.clone(),
                    None => format!("link#{index}"),
                }),
                GatewayKind::Link,
            ),
        },
        Some(other) => match render_address(other, message.interface_index) {
            Some(address) => (Some(address), GatewayKind::Address),
            None => (None, GatewayKind::None),
        },
        None => (None, GatewayKind::None),
    };

    Some(Route {
        family,
        destination,
        is_default,
        gateway,
        gateway_kind,
        interface: interface_name(message),
        flags: flag_letters(message.flags),
        flags_decoded: decode_flags(message.flags),
        expires_in_seconds: seconds_remaining(message.expires_at, now),
    })
}

fn render_address(address: &SocketAddress, interface_index: u16) -> Option<String> {
    match address {
        SocketAddress::V4(address) => Some(address.to_string()),
        SocketAddress::V6 { address, scope_id } => {
            // A link-local next hop is meaningless without its interface.
            let scope = if address.segments()[0] & 0xffc0 == 0xfe80 {
                let index = if *scope_id != 0 {
                    *scope_id as u16
                } else {
                    interface_index
                };
                name_for_index(index).map(|name| format!("%{name}"))
            } else {
                None
            };
            Some(format!("{address}{}", scope.unwrap_or_default()))
        }
        // A mask-shaped sockaddr in the destination slot is the default route
        // with everything zeroed.
        SocketAddress::Mask(bytes) if bytes.iter().skip(4).all(|b| *b == 0) => {
            Some("0.0.0.0".to_owned())
        }
        _ => None,
    }
}

fn interface_name(message: &RouteMessage) -> Option<String> {
    if let Some(SocketAddress::Link {
        name: Some(name), ..
    }) = &message.interface
    {
        return Some(name.clone());
    }
    name_for_index(message.interface_index)
}

/// `if_indextoname(3)`, for the routes whose message carries only an index.
fn name_for_index(index: u16) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
    // Safety: the buffer is IF_NAMESIZE bytes, which is what the call
    // documents it writes at most; a null return means no such interface.
    let name = unsafe { libc::if_indextoname(index as libc::c_uint, buffer.as_mut_ptr()) };
    if name.is_null() {
        return None;
    }
    // Safety: on success the buffer holds a NUL-terminated name.
    unsafe { std::ffi::CStr::from_ptr(name) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn flag_letters(flags: u32) -> String {
    FLAGS
        .iter()
        .filter(|(bit, _, _)| flags & bit != 0)
        .map(|(_, letter, _)| *letter)
        .collect()
}

fn decode_flags(flags: u32) -> Vec<String> {
    FLAGS
        .iter()
        .filter(|(bit, _, _)| flags & bit != 0)
        .map(|(_, _, name)| (*name).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_letters_follow_the_documented_order() {
        // up | gateway | static | protocol-cloning | global
        assert_eq!(
            flag_letters(0x1 | 0x2 | 0x800 | 0x10000 | 0x40000000),
            "UGScg"
        );
        // up | static | protocol-cloning
        assert_eq!(flag_letters(0x1 | 0x800 | 0x10000), "USc");
        // up | host | link
        assert_eq!(flag_letters(0x1 | 0x4 | 0x400), "UHL");
        assert_eq!(flag_letters(0), "");
    }

    #[test]
    fn every_letter_has_a_name() {
        let flags = FLAGS.iter().fold(0u32, |all, (bit, _, _)| all | bit);
        assert_eq!(flag_letters(flags).chars().count(), FLAGS.len());
        assert_eq!(decode_flags(flags).len(), FLAGS.len());
    }

    #[test]
    fn an_absolute_expiry_becomes_a_remaining_lifetime() {
        assert_eq!(seconds_remaining(Some(1_000_090), 1_000_000), Some(90));
        // Already gone: the kernel left a stale stamp behind, and reporting
        // "expires in 1787128161s" would be nonsense on the page.
        assert_eq!(seconds_remaining(Some(900_000), 1_000_000), None);
        assert_eq!(seconds_remaining(Some(1_000_000), 1_000_000), None);
        assert_eq!(seconds_remaining(None, 1_000_000), None);
    }

    #[test]
    fn a_mac_gateway_is_an_arp_entry() {
        assert_eq!(
            format_mac(&[0xa4, 0x83, 0xe7, 0x2d, 0x11, 0x9c]),
            "a4:83:e7:2d:11:9c"
        );
    }
}

/// Capture fixtures for `parse::rt_msg`.
///
/// Ignored by default: it writes files, and it needs a real kernel. Run it
/// deliberately with `cargo test --ignored capture_fixtures`.
///
/// A raw dump describes the machine it came from — its LAN, and every prefix a
/// corporate tunnel pushes. The addresses are rewritten into the documentation
/// ranges before anything is committed. Every length, family, flag, alignment
/// byte and truncated netmask survives untouched, which is the whole reason to
/// keep a real buffer rather than a hand-built one.
#[cfg(test)]
mod capture {
    use super::*;
    use crate::parse::rt_msg::{HEADER_LEN, RTM_VERSION};

    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 30;

    /// Deterministic, so a re-capture of an unchanged table produces an
    /// unchanged fixture.
    fn scramble(seed: &[u8]) -> u16 {
        seed.iter().fold(0x811cu16, |hash, byte| {
            (hash ^ u16::from(*byte)).wrapping_mul(0x0193)
        })
    }

    fn sanitise_address(sockaddr: &mut [u8]) {
        let length = sockaddr.len();
        match sockaddr.get(1).copied().unwrap_or(0) {
            AF_INET if length >= 8 => {
                let octets = &sockaddr[4..8];
                // Leave the addresses that carry no information about anyone:
                // the wildcard, loopback, link-local and multicast.
                if octets[0] == 0 || octets[0] == 127 || octets[0] == 169 || octets[0] >= 224 {
                    return;
                }
                let n = scramble(octets);
                sockaddr[4] = 198;
                sockaddr[5] = 51;
                sockaddr[6] = 100;
                sockaddr[7] = (n & 0xff) as u8;
            }
            AF_INET6 if length >= 24 => {
                let segment = u16::from_be_bytes([sockaddr[8], sockaddr[9]]);
                // Keep ::, ::1 and the link-local prefix.
                if segment & 0xffc0 == 0xfe80 || sockaddr[8..24].iter().all(|b| *b <= 1) {
                    return;
                }
                let n = scramble(&sockaddr[8..24]);
                let mut replacement = [0u8; 16];
                replacement[0..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
                replacement[14..16].copy_from_slice(&n.to_be_bytes());
                sockaddr[8..24].copy_from_slice(&replacement);
            }
            _ => {}
        }
    }

    /// Walk the buffer exactly as the parser does and rewrite in place.
    fn sanitise(buffer: &mut [u8]) {
        let mut offset = 0;
        while offset + 4 <= buffer.len() {
            let claimed = u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]) as usize;
            if claimed == 0 || offset + claimed > buffer.len() {
                break;
            }
            if buffer[offset + 2] == RTM_VERSION && claimed >= HEADER_LEN {
                let record = &mut buffer[offset..offset + claimed];
                let present = u32::from_ne_bytes([record[12], record[13], record[14], record[15]]);
                let mut at = HEADER_LEN;
                for bit in [0x1u32, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80] {
                    if present & bit == 0 {
                        continue;
                    }
                    let Some(&length) = record.get(at) else { break };
                    let consumed = if length == 0 {
                        4
                    } else {
                        1 + ((length as usize - 1) | 3)
                    };
                    if at + consumed > record.len() {
                        break;
                    }
                    // The netmask slot is not identifying and truncating it
                    // would destroy the very shape the fixture exists for.
                    if bit != 0x4 && length > 0 {
                        sanitise_address(&mut record[at..at + length as usize]);
                    }
                    at += consumed;
                }
            }
            offset += claimed;
        }
    }

    #[test]
    #[ignore = "writes fixture files and needs a real routing table"]
    fn capture_fixtures() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        std::fs::create_dir_all(&directory).unwrap();

        for (name, family) in [
            ("routes-both", None),
            ("routes-inet", Some(Family::Inet)),
            ("routes-inet6", Some(Family::Inet6)),
        ] {
            let mut buffer = dump(family).unwrap();
            let before = crate::parse::rt_msg::walk(&buffer).unwrap().len();
            sanitise(&mut buffer);
            let after = crate::parse::rt_msg::walk(&buffer).unwrap().len();
            assert_eq!(before, after, "{name}: sanitising changed the record count");

            std::fs::write(directory.join(format!("{name}.bin")), &buffer).unwrap();
            println!("{name}.bin: {} bytes, {after} records", buffer.len());
        }
    }
}
