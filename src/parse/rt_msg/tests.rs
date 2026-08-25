//! Tests for the routing-message walk.
//!
//! Records are built by hand here so every shape the kernel can produce — a
//! truncated netmask, a link address with no name, an absent slot — is
//! reachable without one. Real captured buffers are exercised in
//! `tests/fixtures.rs`.

use super::*;

/// A record header with the metrics zeroed.
fn header(flags: u32, present: u32, index: u16, expire: i32) -> Vec<u8> {
    let mut record = vec![0u8; HEADER_LEN];
    record[2] = RTM_VERSION;
    record[3] = 4; // RTM_GET
    record[4..6].copy_from_slice(&index.to_ne_bytes());
    record[8..12].copy_from_slice(&flags.to_ne_bytes());
    record[12..16].copy_from_slice(&present.to_ne_bytes());
    record[EXPIRE_OFFSET..EXPIRE_OFFSET + 4].copy_from_slice(&expire.to_ne_bytes());
    record
}

fn finish(mut record: Vec<u8>, addresses: &[Vec<u8>]) -> Vec<u8> {
    for address in addresses {
        record.extend_from_slice(address);
        // Pad up to the four-byte boundary, as the kernel does.
        while record.len() % 4 != 0 {
            record.push(0);
        }
    }
    let length = record.len() as u16;
    record[0..2].copy_from_slice(&length.to_ne_bytes());
    record
}

fn sockaddr_in(address: [u8; 4]) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    bytes[0] = 16;
    bytes[1] = AF_INET;
    bytes[4..8].copy_from_slice(&address);
    bytes
}

fn sockaddr_in6(address: [u8; 16], scope_id: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 28];
    bytes[0] = 28;
    bytes[1] = AF_INET6;
    bytes[8..24].copy_from_slice(&address);
    bytes[24..28].copy_from_slice(&scope_id.to_ne_bytes());
    bytes
}

fn sockaddr_dl(index: u16, name: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; 8 + name.len()];
    bytes[0] = bytes.len() as u8;
    bytes[1] = AF_LINK;
    bytes[2..4].copy_from_slice(&index.to_ne_bytes());
    bytes[5] = name.len() as u8;
    bytes[8..].copy_from_slice(name.as_bytes());
    bytes
}

/// A netmask as the kernel actually sends it: only the bytes it needed.
fn truncated_mask(address_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 4 + address_bytes.len()];
    bytes[0] = bytes.len() as u8;
    bytes[4..].copy_from_slice(address_bytes);
    bytes
}

const RTF_UP: u32 = 0x1;
const RTF_GATEWAY: u32 = 0x2;

#[test]
fn a_default_route_walks_out_whole() {
    let record = finish(
        header(RTF_UP | RTF_GATEWAY, 0x1 | 0x2 | 0x4, 12, 0),
        &[
            sockaddr_in([0, 0, 0, 0]),
            sockaddr_in([192, 168, 1, 1]),
            // A default route's mask is zero-length.
            vec![0u8; 4],
        ],
    );

    let routes = walk(&record).unwrap();
    assert_eq!(routes.len(), 1);
    let route = &routes[0];
    assert_eq!(route.flags, RTF_UP | RTF_GATEWAY);
    assert_eq!(route.interface_index, 12);
    assert_eq!(
        route.destination,
        Some(SocketAddress::V4("0.0.0.0".parse().unwrap()))
    );
    assert_eq!(
        route.gateway,
        Some(SocketAddress::V4("192.168.1.1".parse().unwrap()))
    );
    assert_eq!(prefix_len(route.netmask.as_ref().unwrap(), false), 0);
}

#[test]
fn a_truncated_netmask_still_yields_its_prefix() {
    // The kernel sends /24 as one address byte short of a full sockaddr, and
    // /8 as three short. Reading them as fixed-size structs is the classic way
    // to get this wrong.
    for (bytes, expected) in [
        (vec![255u8, 255, 255], 24u8),
        (vec![255u8], 8),
        (vec![255u8, 255, 255, 128], 25),
        (vec![255u8, 240], 12),
    ] {
        let record = finish(
            header(RTF_UP, 0x1 | 0x4, 1, 0),
            &[sockaddr_in([10, 0, 0, 0]), truncated_mask(&bytes)],
        );
        let routes = walk(&record).unwrap();
        assert_eq!(
            prefix_len(routes[0].netmask.as_ref().unwrap(), false),
            expected,
            "{bytes:?}"
        );
    }
}

#[test]
fn an_absent_slot_consumes_nothing() {
    // DST and IFP present, GATEWAY and NETMASK absent. If a clear bit consumed
    // bytes anyway, the interface would be read out of the middle of the
    // destination.
    let record = finish(
        header(RTF_UP, 0x1 | 0x10, 18, 0),
        &[sockaddr_in([10, 7, 0, 0]), sockaddr_dl(18, "utun3")],
    );
    let routes = walk(&record).unwrap();
    assert!(routes[0].gateway.is_none());
    assert!(routes[0].netmask.is_none());
    assert_eq!(
        routes[0].interface,
        Some(SocketAddress::Link {
            index: 18,
            name: Some("utun3".to_owned()),
            mac: None,
        })
    );
}

#[test]
fn an_ipv6_route_loses_its_embedded_scope() {
    // getifaddrs and the routing socket both hand back fe80:12:: for what the
    // user knows as fe80::, with the interface index buried in the address.
    let mut address = [0u8; 16];
    address[0] = 0xfe;
    address[1] = 0x80;
    address[3] = 12;
    address[15] = 1;

    let record = finish(
        header(RTF_UP, 0x1, 12, 0),
        &[sockaddr_in6(address, 12)],
    );
    let routes = walk(&record).unwrap();
    assert_eq!(
        routes[0].destination,
        Some(SocketAddress::V6 {
            address: "fe80::1".parse().unwrap(),
            scope_id: 12,
        })
    );
}

#[test]
fn several_records_walk_in_sequence() {
    let mut buffer = finish(header(RTF_UP, 0x1, 1, 0), &[sockaddr_in([127, 0, 0, 0])]);
    buffer.extend(finish(
        header(RTF_UP, 0x1, 2, 90),
        &[sockaddr_in([10, 0, 0, 0])],
    ));
    let routes = walk(&buffer).unwrap();
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].interface_index, 1);
    assert_eq!(routes[1].interface_index, 2);
    // Verbatim: it is an absolute time and this parser has no clock.
    assert_eq!(routes[1].expires_at, Some(90));
    assert_eq!(routes[0].expires_at, None);
}

#[test]
fn a_record_from_an_unknown_version_is_skipped_not_rejected() {
    // A future kernel adding a message type must not take the whole table
    // down with it.
    let mut buffer = finish(header(RTF_UP, 0x1, 1, 0), &[sockaddr_in([127, 0, 0, 0])]);
    let mut alien = finish(header(RTF_UP, 0x1, 9, 0), &[sockaddr_in([10, 0, 0, 0])]);
    alien[2] = 99;
    buffer.extend(alien);
    buffer.extend(finish(header(RTF_UP, 0x1, 3, 0), &[sockaddr_in([10, 1, 0, 0])]));

    let routes = walk(&buffer).unwrap();
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[1].interface_index, 3);
}

// -------------------------------------------------------------------------
// Malformed input. Every one of these must return an error — never a panic,
// never a read past the end of the buffer.
// -------------------------------------------------------------------------

#[test]
fn an_empty_buffer_is_an_empty_table() {
    assert_eq!(walk(&[]).unwrap(), Vec::new());
}

#[test]
fn a_zero_length_record_is_rejected_rather_than_looping_forever() {
    let buffer = vec![0u8; 32];
    assert_eq!(walk(&buffer), Err(ParseError::ZeroLength));
}

#[test]
fn a_record_longer_than_the_buffer_is_rejected() {
    let mut record = finish(header(RTF_UP, 0x1, 1, 0), &[sockaddr_in([10, 0, 0, 0])]);
    let real = record.len();
    record[0..2].copy_from_slice(&((real + 64) as u16).to_ne_bytes());
    assert!(matches!(walk(&record), Err(ParseError::Truncated { .. })));
}

#[test]
fn a_record_shorter_than_its_header_is_rejected() {
    let mut record = vec![0u8; 40];
    record[0..2].copy_from_slice(&40u16.to_ne_bytes());
    record[2] = RTM_VERSION;
    assert_eq!(walk(&record), Err(ParseError::ShortHeader(40)));
}

#[test]
fn an_address_running_past_the_record_is_rejected() {
    // The bitmask promises a destination, but the record ends at the header.
    let mut record = header(RTF_UP, 0x1, 1, 0);
    record[0..2].copy_from_slice(&(HEADER_LEN as u16).to_ne_bytes());
    assert!(matches!(
        walk(&record),
        Err(ParseError::TruncatedAddress { .. })
    ));
}

#[test]
fn an_address_claiming_more_than_the_record_holds_is_rejected() {
    let mut oversized = sockaddr_in([10, 0, 0, 0]);
    oversized[0] = 250;
    let record = finish(header(RTF_UP, 0x1, 1, 0), &[oversized]);
    assert!(matches!(
        walk(&record),
        Err(ParseError::TruncatedAddress { .. })
    ));
}

#[test]
fn a_trailing_fragment_is_rejected() {
    let mut buffer = finish(header(RTF_UP, 0x1, 1, 0), &[sockaddr_in([10, 0, 0, 0])]);
    buffer.extend_from_slice(&[1, 2, 3]);
    assert!(matches!(walk(&buffer), Err(ParseError::Truncated { .. })));
}

#[test]
fn arbitrary_bytes_never_panic() {
    // The property that matters most: whatever comes back, the parser either
    // describes it or refuses it.
    let mut seed = 0x12345678u32;
    for length in 0..600usize {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (seed >> 16) as u8
            })
            .collect();
        let _ = walk(&bytes);
    }
}
