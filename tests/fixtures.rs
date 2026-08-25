//! The routing-table walker against real captured buffers.
//!
//! The buffers in `tests/fixtures/` came out of a real kernel and were then
//! rewritten into the documentation address ranges — every length, family,
//! flag, alignment byte and truncated netmask is exactly as the kernel emitted
//! it. That is the point: a hand-built fixture can only encode what the author
//! already believed the format to be.

use std::path::PathBuf;

use netinspect::parse::pcb;
use netinspect::parse::rt_msg::{walk, ParseError, SocketAddress};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const ALL: [(&str, usize); 3] = [
    // Captured with a corporate tunnel up, which is what makes it interesting:
    // two hundred pushed host routes and a second default gateway.
    ("routes-both.bin", 229),
    ("routes-inet.bin", 144),
    // What a machine looks like when only one family is asked for.
    ("routes-inet6.bin", 85),
];

#[test]
fn every_fixture_walks_completely() {
    for (name, expected) in ALL {
        let routes = walk(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(routes.len(), expected, "{name}");
    }
}

#[test]
fn every_record_carries_a_destination() {
    for (name, _) in ALL {
        for route in walk(&fixture(name)).unwrap() {
            assert!(
                route.destination.is_some(),
                "{name}: a route with no destination"
            );
        }
    }
}

#[test]
fn the_families_are_the_ones_that_were_asked_for() {
    let v4 = walk(&fixture("routes-inet.bin")).unwrap();
    assert!(v4.iter().all(|route| !matches!(
        route.destination,
        Some(SocketAddress::V6 { .. })
    )));

    let v6 = walk(&fixture("routes-inet6.bin")).unwrap();
    assert!(v6.iter().all(|route| !matches!(
        route.destination,
        Some(SocketAddress::V4(_))
    )));

    // And the combined dump is the sum of the two.
    assert_eq!(
        walk(&fixture("routes-both.bin")).unwrap().len(),
        v4.len() + v6.len()
    );
}

#[test]
fn a_real_table_has_a_default_route_and_link_gateways() {
    let routes = walk(&fixture("routes-both.bin")).unwrap();

    let defaults = routes
        .iter()
        .filter(|route| {
            matches!(&route.destination, Some(SocketAddress::V4(a)) if a.is_unspecified())
                || matches!(&route.destination, Some(SocketAddress::V6 { address, .. }) if address.is_unspecified())
        })
        .count();
    assert!(defaults > 0, "no default route in a real table");

    // AF_LINK gateways are the shape most likely to be misparsed, because the
    // name and hardware address lengths live in the header.
    assert!(routes
        .iter()
        .any(|route| matches!(route.gateway, Some(SocketAddress::Link { .. }))));
}

/// Truncating a real buffer anywhere must produce an error or a shorter table,
/// never a panic and never a read past the end.
#[test]
fn every_truncation_of_a_real_buffer_is_survivable() {
    for (name, _) in ALL {
        let buffer = fixture(name);
        for length in 0..buffer.len() {
            match walk(&buffer[..length]) {
                Ok(routes) => assert!(routes.len() <= 229),
                Err(
                    ParseError::Truncated { .. }
                    | ParseError::TruncatedAddress { .. }
                    | ParseError::ShortHeader(_)
                    | ParseError::ZeroLength,
                ) => {}
            }
        }
    }
}

/// Flip bytes in a real buffer and keep walking it. Structured input with one
/// thing wrong is where a parser breaks, and it is a shape random bytes almost
/// never produce.
#[test]
fn a_corrupted_real_buffer_never_panics() {
    let original = fixture("routes-both.bin");
    let mut seed = 0x2545_f491u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };

    for _ in 0..4000 {
        let mut buffer = original.clone();
        for _ in 0..(next() % 8 + 1) {
            let at = (next() as usize) % buffer.len();
            buffer[at] ^= (next() % 256) as u8;
        }
        let _ = walk(&buffer);
    }
}


// -------------------------------------------------------------------------
// The socket table
// -------------------------------------------------------------------------

const SOCKETS: [(&str, usize, usize); 2] = [
    // (fixture, sockets, listening)
    ("sockets-tcp.bin", 115, 30),
    ("sockets-udp.bin", 60, 31),
];

#[test]
fn every_socket_fixture_walks_completely() {
    for (name, total, listening) in SOCKETS {
        let sockets = pcb::walk(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(sockets.len(), total, "{name}");
        assert_eq!(
            sockets.iter().filter(|s| s.is_listening()).count(),
            listening,
            "{name}"
        );
    }
}

/// The block stream is padded to eight bytes and the structures are
/// transcribed from a kernel that is not in the public SDK. If either is wrong
/// the walk stops early, so a real buffer consumed to its last byte is the
/// check that matters.
#[test]
fn a_real_buffer_yields_both_address_families_and_both_kinds_of_owner() {
    let sockets = pcb::walk(&fixture("sockets-tcp.bin")).unwrap();

    assert!(sockets.iter().any(|s| s.local.is_ipv4()), "no IPv4 socket");
    assert!(sockets.iter().any(|s| s.local.is_ipv6()), "no IPv6 socket");
    // Wildcard binds and loopback binds are the two ends of the exposure
    // classification, and a real machine has both.
    assert!(sockets
        .iter()
        .any(|s| s.local.to_string() == "0.0.0.0" && s.is_listening()));
    assert!(sockets.iter().any(|s| s.local.is_loopback()));
    // Owners survive the capture, root and otherwise.
    assert!(sockets.iter().any(|s| s.uid == Some(0)));
    assert!(sockets.iter().any(|s| s.uid.is_some_and(|uid| uid != 0)));
    // And TCP sockets carry a state, which is what "listening" is read from.
    assert!(sockets.iter().all(|s| s.state.is_some()));
}

#[test]
fn every_truncation_of_a_real_socket_buffer_is_survivable() {
    for (name, _, _) in SOCKETS {
        let buffer = fixture(name);
        for length in 0..buffer.len() {
            // Either it describes what it was given or it refuses; both are
            // fine, a panic is not.
            if let Ok(sockets) = pcb::walk(&buffer[..length]) {
                assert!(sockets.len() <= 115);
            }
        }
    }
}

#[test]
fn a_corrupted_real_socket_buffer_never_panics() {
    let original = fixture("sockets-tcp.bin");
    let mut seed = 0x1234_5678u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    for _ in 0..4000 {
        let mut buffer = original.clone();
        for _ in 0..(next() % 8 + 1) {
            let at = (next() as usize) % buffer.len();
            buffer[at] ^= (next() % 256) as u8;
        }
        let _ = pcb::walk(&buffer);
    }
}
