//! The `NET_RT_DUMP` buffer walk.
//!
//! A pure function over `&[u8]`, deliberately separated from the syscall that
//! produces the buffer: that is what makes it testable against committed
//! fixtures with no kernel involved, and fuzzable.
//!
//! **Malformed input must return an error — never panic, never read out of
//! bounds.** The buffer comes from the kernel today, but this parser is the
//! only thing standing between a truncated read and a crash.
//!
//! The format: a sequence of `rt_msghdr` records, each followed by a packed
//! set of `sockaddr`s selected by the `rtm_addrs` bitmask, in the fixed order
//! `DST, GATEWAY, NETMASK, GENMASK, IFP, IFA, AUTHOR, BRD`. Each is padded up
//! to a four-byte boundary.

use std::net::{Ipv4Addr, Ipv6Addr};

/// `sizeof(struct rt_msghdr)` on macOS: 36 bytes of header plus a 56-byte
/// `rt_metrics`.
pub const HEADER_LEN: usize = 92;
/// Anything else is from a kernel this parser does not claim to understand.
pub const RTM_VERSION: u8 = 5;
/// Offset of `rtm_rmx.rmx_expire` inside the record.
const EXPIRE_OFFSET: usize = 36 + 12;

const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;
const AF_INET6: u8 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("a record claims {claimed} bytes but only {available} remain")]
    Truncated { claimed: usize, available: usize },
    #[error("a record claims zero length, which would never advance")]
    ZeroLength,
    #[error("a record is {0} bytes, shorter than the message header")]
    ShortHeader(usize),
    #[error("a socket address claims {claimed} bytes but only {available} remain")]
    TruncatedAddress { claimed: usize, available: usize },
}

/// One address out of a routing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddress {
    V4(Ipv4Addr),
    V6 {
        address: Ipv6Addr,
        scope_id: u32,
    },
    /// An `AF_LINK` address: an interface, and sometimes its name and hardware
    /// address.
    Link {
        index: u16,
        name: Option<String>,
        mac: Option<[u8; 6]>,
    },
    /// A netmask arrives as a truncated `sockaddr` carrying only as many
    /// address bytes as it needed, and usually with a family of zero. It can
    /// only be read once the destination's family is known.
    Mask(Vec<u8>),
    /// A family this parser does not model. Kept so a walk never silently
    /// drops a slot and misaligns everything after it.
    Other(u8),
    /// Present in the bitmask but zero-length.
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteMessage {
    pub flags: u32,
    pub interface_index: u16,
    pub destination: Option<SocketAddress>,
    pub gateway: Option<SocketAddress>,
    pub netmask: Option<SocketAddress>,
    pub interface: Option<SocketAddress>,
    /// `rmx_expire`, verbatim. It is an **absolute** time, not a duration —
    /// turning it into "seconds remaining" needs a clock, which this parser
    /// deliberately does not have.
    pub expires_at: Option<i32>,
}

/// Walk a whole `NET_RT_DUMP` buffer.
///
/// Records with an unrecognised version are skipped rather than rejected: a
/// future kernel adding a message type must not take the whole table down.
pub fn walk(buffer: &[u8]) -> Result<Vec<RouteMessage>, ParseError> {
    let mut routes = Vec::new();
    let mut offset = 0;

    while offset < buffer.len() {
        let remaining = buffer.len() - offset;
        // Enough to read the length and version out of.
        if remaining < 4 {
            return Err(ParseError::Truncated {
                claimed: 4,
                available: remaining,
            });
        }
        let record = &buffer[offset..];
        let claimed = u16::from_ne_bytes([record[0], record[1]]) as usize;
        if claimed == 0 {
            return Err(ParseError::ZeroLength);
        }
        if claimed > remaining {
            return Err(ParseError::Truncated {
                claimed,
                available: remaining,
            });
        }

        if record[2] == RTM_VERSION {
            if claimed < HEADER_LEN {
                return Err(ParseError::ShortHeader(claimed));
            }
            routes.push(parse(&record[..claimed])?);
        }
        offset += claimed;
    }

    Ok(routes)
}

fn parse(record: &[u8]) -> Result<RouteMessage, ParseError> {
    let word = |at: usize| u32::from_ne_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]]);

    let mut message = RouteMessage {
        interface_index: u16::from_ne_bytes([record[4], record[5]]),
        flags: word(8),
        ..Default::default()
    };
    let present = word(12);
    let expire = word(EXPIRE_OFFSET) as i32;
    message.expires_at = (expire != 0).then_some(expire);

    let mut offset = HEADER_LEN;
    // The order is fixed; a bit that is clear means the slot is absent, not
    // empty, so nothing is consumed for it.
    for (bit, slot) in [
        (0x1, 0),  // DST
        (0x2, 1),  // GATEWAY
        (0x4, 2),  // NETMASK
        (0x8, 3),  // GENMASK
        (0x10, 4), // IFP
        (0x20, 5), // IFA
        (0x40, 6), // AUTHOR
        (0x80, 7), // BRD
    ] {
        if present & bit == 0 {
            continue;
        }
        let (address, consumed) = read_address(&record[offset..])?;
        offset += consumed;
        match slot {
            0 => message.destination = Some(address),
            1 => message.gateway = Some(address),
            2 => message.netmask = Some(address),
            4 => message.interface = Some(address),
            _ => {}
        }
    }

    Ok(message)
}

/// Read one `sockaddr` and report how many bytes it occupies, which is its
/// length rounded up to a four-byte boundary. A zero length occupies four.
fn read_address(bytes: &[u8]) -> Result<(SocketAddress, usize), ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::TruncatedAddress {
            claimed: 1,
            available: 0,
        });
    }
    let length = bytes[0] as usize;
    let consumed = if length == 0 {
        4
    } else {
        1 + ((length - 1) | 3)
    };
    if consumed > bytes.len() {
        return Err(ParseError::TruncatedAddress {
            claimed: consumed,
            available: bytes.len(),
        });
    }
    if length == 0 {
        return Ok((SocketAddress::Empty, consumed));
    }

    let sockaddr = &bytes[..length];
    let family = sockaddr.get(1).copied().unwrap_or(0);
    let address = match family {
        AF_INET if length >= 8 => SocketAddress::V4(Ipv4Addr::new(
            sockaddr[4],
            sockaddr[5],
            sockaddr[6],
            sockaddr[7],
        )),
        AF_INET6 if length >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&sockaddr[8..24]);
            let scope_id = if length >= 28 {
                u32::from_ne_bytes([sockaddr[24], sockaddr[25], sockaddr[26], sockaddr[27]])
            } else {
                0
            };
            SocketAddress::V6 {
                address: strip_embedded_scope(Ipv6Addr::from(octets)),
                scope_id,
            }
        }
        AF_LINK if length >= 8 => read_link(sockaddr),
        // Either a netmask, or a family with fewer bytes than its struct
        // needs. Both are read by whoever knows what family to expect.
        _ => SocketAddress::Mask(sockaddr.to_vec()),
    };

    Ok((address, consumed))
}

/// `struct sockaddr_dl`: index, then a name and a hardware address whose
/// lengths are carried in the header.
fn read_link(sockaddr: &[u8]) -> SocketAddress {
    let index = u16::from_ne_bytes([sockaddr[2], sockaddr[3]]);
    let name_len = sockaddr[5] as usize;
    let mac_len = sockaddr[6] as usize;
    let data = &sockaddr[8..];

    let name = data
        .get(..name_len)
        .filter(|bytes| !bytes.is_empty())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_owned);
    let mac = (mac_len == 6)
        .then(|| data.get(name_len..name_len + 6))
        .flatten()
        .map(|bytes| {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(bytes);
            mac
        });

    SocketAddress::Link { index, name, mac }
}

/// macOS embeds the interface index in bytes 2–3 of a link-local address, the
/// KAME convention. The interface is named by its own column, so strip it.
fn strip_embedded_scope(address: Ipv6Addr) -> Ipv6Addr {
    if address.segments()[0] & 0xffc0 != 0xfe80 {
        return address;
    }
    let mut segments = address.segments();
    segments[1] = 0;
    Ipv6Addr::from(segments)
}

/// How many leading bits a netmask sets.
///
/// The kernel sends only as many bytes as it needed, so a `/8` mask arrives
/// with one address byte and the rest are implicitly zero. `family` says where
/// the address bytes start, and comes from the destination — the mask itself
/// usually reports a family of zero.
pub fn prefix_len(mask: &SocketAddress, ipv6: bool) -> u8 {
    let bytes = match mask {
        SocketAddress::Mask(bytes) => bytes.as_slice(),
        // A fully formed address in the mask slot: count it directly.
        SocketAddress::V4(address) => return address.to_bits().count_ones() as u8,
        SocketAddress::V6 { address, .. } => {
            return address.segments().iter().map(|s| s.count_ones() as u8).sum()
        }
        _ => return 0,
    };

    let start = if ipv6 { 8 } else { 4 };
    bytes
        .get(start..)
        .map(|address| address.iter().map(|byte| byte.count_ones() as u8).sum())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
