//! Tests for the socket-table walk.
//!
//! Blocks are built here to the transcribed layout, which proves the parser
//! agrees with the transcription — not that the transcription agrees with the
//! kernel. `tests/fixtures.rs` checks that against a real buffer.

use super::*;

fn header() -> Vec<u8> {
    let mut bytes = vec![0u8; XINPGEN_LEN as usize];
    bytes[0..4].copy_from_slice(&XINPGEN_LEN.to_ne_bytes());
    bytes
}

fn block(kind: u32, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
    bytes[4..8].copy_from_slice(&kind.to_ne_bytes());
    bytes
}

fn inpcb_v4(local: [u8; 4], local_port: u16, foreign: [u8; 4], foreign_port: u16) -> Vec<u8> {
    let mut bytes = block(XSO_INPCB, 104);
    // A distinct handle per socket, as the kernel would give.
    let handle = 0xffff_0000_0000_0000u64 | u64::from(local_port);
    bytes[inpcb::PCB..inpcb::PCB + 8].copy_from_slice(&handle.to_ne_bytes());
    bytes[inpcb::VFLAG] = inpcb::INP_IPV4;
    bytes[inpcb::LOCAL_PORT..inpcb::LOCAL_PORT + 2].copy_from_slice(&local_port.to_be_bytes());
    bytes[inpcb::FOREIGN_PORT..inpcb::FOREIGN_PORT + 2].copy_from_slice(&foreign_port.to_be_bytes());
    let at = inpcb::LOCAL_ADDRESS + inpcb::V4_IN_V6_OFFSET;
    bytes[at..at + 4].copy_from_slice(&local);
    let at = inpcb::FOREIGN_ADDRESS + inpcb::V4_IN_V6_OFFSET;
    bytes[at..at + 4].copy_from_slice(&foreign);
    bytes
}

fn inpcb_v6(local: [u8; 16], local_port: u16) -> Vec<u8> {
    let mut bytes = block(XSO_INPCB, 104);
    bytes[inpcb::VFLAG] = inpcb::INP_IPV6;
    bytes[inpcb::LOCAL_PORT..inpcb::LOCAL_PORT + 2].copy_from_slice(&local_port.to_be_bytes());
    bytes[inpcb::LOCAL_ADDRESS..inpcb::LOCAL_ADDRESS + 16].copy_from_slice(&local);
    bytes
}

fn xsocket(uid: u32) -> Vec<u8> {
    let mut bytes = block(XSO_SOCKET, 104);
    bytes[socket::UID..socket::UID + 4].copy_from_slice(&uid.to_ne_bytes());
    bytes
}

fn xtcpcb(state: i32) -> Vec<u8> {
    let mut bytes = block(XSO_TCPCB, 256);
    bytes[tcpcb::STATE..tcpcb::STATE + 4].copy_from_slice(&state.to_ne_bytes());
    bytes
}

fn buffer(groups: Vec<Vec<Vec<u8>>>) -> Vec<u8> {
    let mut bytes = header();
    for group in groups {
        for block in group {
            bytes.extend(block);
            // The kernel pads every block up to an eight-byte boundary.
            while bytes.len() % 8 != 0 {
                bytes.push(0);
            }
        }
    }
    // The kernel closes the stream with a second xinpgen.
    bytes.extend(header());
    bytes
}

#[test]
fn a_listening_tcp_socket_assembles_from_its_blocks() {
    let bytes = buffer(vec![vec![
        inpcb_v4([0, 0, 0, 0], 5432, [0, 0, 0, 0], 0),
        xsocket(501),
        xtcpcb(1),
    ]]);

    let sockets = walk(&bytes).unwrap();
    assert_eq!(sockets.len(), 1);
    let socket = &sockets[0];
    assert_eq!(socket.local.to_string(), "0.0.0.0");
    assert_eq!(socket.local_port, 5432);
    assert_eq!(socket.foreign, None);
    assert_eq!(socket.state, Some(TcpState::Listen));
    assert_eq!(socket.uid, Some(501));
    assert!(socket.is_listening());
    // The handle the join needs.
    assert_eq!(socket.pcb, 0xffff_0000_0000_0000u64 | 5432);
}

#[test]
fn an_established_connection_is_not_listening() {
    let bytes = buffer(vec![vec![
        inpcb_v4([192, 168, 1, 24], 52341, [93, 184, 216, 34], 443),
        xsocket(501),
        xtcpcb(4),
    ]]);
    let socket = &walk(&bytes).unwrap()[0];
    assert_eq!(socket.state, Some(TcpState::Established));
    assert_eq!(socket.foreign.unwrap().to_string(), "93.184.216.34");
    assert_eq!(socket.foreign_port, 443);
    assert!(!socket.is_listening());
}

#[test]
fn udp_has_no_state_so_the_test_is_the_absence_of_a_peer() {
    // mDNSResponder on 0.0.0.0:5353 with nobody on the other end.
    let bound = buffer(vec![vec![
        inpcb_v4([0, 0, 0, 0], 5353, [0, 0, 0, 0], 0),
        xsocket(0),
    ]]);
    let socket = &walk(&bound).unwrap()[0];
    assert_eq!(socket.state, None);
    assert!(socket.is_listening());

    // A datagram socket already talking to somebody is not a service.
    let connected = buffer(vec![vec![
        inpcb_v4([192, 168, 1, 24], 51234, [1, 1, 1, 1], 53),
        xsocket(501),
    ]]);
    assert!(!walk(&connected).unwrap()[0].is_listening());
}

#[test]
fn an_ipv6_socket_reads_its_own_address_family() {
    let mut wildcard = [0u8; 16];
    let bytes = buffer(vec![vec![inpcb_v6(wildcard, 7000), xtcpcb(1)]]);
    assert_eq!(walk(&bytes).unwrap()[0].local.to_string(), "::");

    wildcard[15] = 1;
    let bytes = buffer(vec![vec![inpcb_v6(wildcard, 631), xtcpcb(1)]]);
    assert_eq!(walk(&bytes).unwrap()[0].local.to_string(), "::1");
}

#[test]
fn a_dual_stack_socket_is_read_as_ipv6() {
    // macOS sets both flags on an AF_INET6 socket that also accepts v4-mapped
    // connections. Reading it as v4 turns every `[::]` listener into another
    // `0.0.0.0` one, and the table fills with apparent duplicates.
    let mut bytes = block(XSO_INPCB, 104);
    bytes[inpcb::VFLAG] = inpcb::INP_IPV4 | inpcb::INP_IPV6;
    bytes[inpcb::LOCAL_PORT..inpcb::LOCAL_PORT + 2].copy_from_slice(&22u16.to_be_bytes());
    let bytes = buffer(vec![vec![bytes, xtcpcb(1)]]);
    assert_eq!(walk(&bytes).unwrap()[0].local.to_string(), "::");
}

#[test]
fn several_sockets_are_split_at_each_new_pcb() {
    let bytes = buffer(vec![
        vec![inpcb_v4([0, 0, 0, 0], 22, [0, 0, 0, 0], 0), xsocket(0), xtcpcb(1)],
        vec![
            inpcb_v4([127, 0, 0, 1], 6379, [0, 0, 0, 0], 0),
            xsocket(501),
            xtcpcb(1),
        ],
    ]);
    let sockets = walk(&bytes).unwrap();
    assert_eq!(sockets.len(), 2);
    assert_eq!(sockets[0].local_port, 22);
    assert_eq!(sockets[0].uid, Some(0));
    assert_eq!(sockets[1].local.to_string(), "127.0.0.1");
    assert_eq!(sockets[1].uid, Some(501));
}

#[test]
fn a_socket_with_no_extra_blocks_still_appears() {
    // Whatever else is missing, an open port is an open port.
    let bytes = buffer(vec![vec![inpcb_v4([0, 0, 0, 0], 8080, [0, 0, 0, 0], 0)]]);
    let socket = &walk(&bytes).unwrap()[0];
    assert_eq!(socket.local_port, 8080);
    assert_eq!(socket.uid, None);
    assert_eq!(socket.state, None);
}

/// A block whose length is not a multiple of eight is followed by padding.
/// Advancing by the length alone reads that padding as the next block's header
/// and stops the walk dead — which is exactly what a real buffer does.
#[test]
fn blocks_are_padded_to_an_eight_byte_boundary() {
    let bytes = buffer(vec![
        vec![
            inpcb_v4([0, 0, 0, 0], 22, [0, 0, 0, 0], 0),
            block(0x008, 132),
            xtcpcb(1),
        ],
        vec![inpcb_v4([0, 0, 0, 0], 631, [0, 0, 0, 0], 0), xtcpcb(1)],
    ]);
    let sockets = walk(&bytes).unwrap();
    assert_eq!(sockets.len(), 2, "the walk stopped at the first padded block");
    assert_eq!(sockets[1].local_port, 631);
}

#[test]
fn blocks_this_parser_does_not_model_are_skipped_by_length() {
    // Send and receive buffers and statistics sit between the useful blocks.
    let bytes = buffer(vec![vec![
        inpcb_v4([0, 0, 0, 0], 5432, [0, 0, 0, 0], 0),
        block(0x002, 40),
        block(0x004, 40),
        block(0x008, 64),
        xsocket(501),
        xtcpcb(1),
    ]]);
    let sockets = walk(&bytes).unwrap();
    assert_eq!(sockets.len(), 1);
    assert_eq!(sockets[0].uid, Some(501));
    assert_eq!(sockets[0].state, Some(TcpState::Listen));
}

// -------------------------------------------------------------------------
// Malformed input
// -------------------------------------------------------------------------

#[test]
fn an_empty_buffer_is_an_empty_table() {
    assert_eq!(walk(&[]).unwrap(), Vec::new());
}

#[test]
fn a_header_this_build_does_not_recognise_is_refused() {
    // If the kernel's layout moved, every offset below is a guess. Producing a
    // plausible-looking socket list from it would be worse than refusing.
    let mut bytes = header();
    bytes[0..4].copy_from_slice(&40u32.to_ne_bytes());
    assert_eq!(walk(&bytes), Err(ParseError::UnexpectedHeader(40)));
}

#[test]
fn a_buffer_too_short_for_a_header_is_refused() {
    assert_eq!(walk(&[1, 2, 3, 4]), Err(ParseError::NoHeader));
}

#[test]
fn a_block_that_cannot_hold_its_own_length_is_refused() {
    let mut bytes = header();
    bytes.extend(vec![4u8, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(walk(&bytes), Err(ParseError::ImpossibleBlock(4)));
    // Zero would also never advance.
    let mut bytes = header();
    bytes.extend(vec![0u8; 8]);
    assert_eq!(walk(&bytes), Err(ParseError::ImpossibleBlock(0)));
}

#[test]
fn a_block_running_past_the_buffer_is_refused() {
    let mut bytes = header();
    let mut oversized = block(XSO_INPCB, 104);
    oversized[0..4].copy_from_slice(&4096u32.to_ne_bytes());
    bytes.extend(oversized);
    assert!(matches!(walk(&bytes), Err(ParseError::Truncated { .. })));
}

#[test]
fn a_block_too_short_for_its_fields_is_ignored_not_misread() {
    // A truncated pcb yields no socket rather than an address read out of
    // whatever happened to follow it.
    let mut bytes = header();
    bytes.extend(block(XSO_INPCB, 40));
    assert_eq!(walk(&bytes).unwrap(), Vec::new());
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut seed = 0x9e37_79b9u32;
    for length in 0..800usize {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                (seed >> 8) as u8
            })
            .collect();
        let _ = walk(&bytes);
    }
}
