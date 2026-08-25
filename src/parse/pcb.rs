//! The `pcblist_n` buffer walk.
//!
//! `net.inet.tcp.pcblist_n` and `net.inet.udp.pcblist_n` return every socket
//! on the system, including other users', readable with no privileges at all.
//! That is why this is the *primary* source: the list is complete whoever runs
//! it, and process names are added afterwards for the ones we are allowed to
//! see.
//!
//! The layout is not a table of fixed records. After an `xinpgen` header comes
//! a stream of self-describing blocks, each `(xi_len, xi_kind)`, and one socket
//! is however many consecutive blocks describe it. A new `XSO_INPCB` starts the
//! next one.
//!
//! **The structures are transcribed from xnu, because the `_n` variants are not
//! in the public SDK.** A transcription error is silent by nature, so this
//! parser checks its own assumptions against the buffer — see `Header::parse`
//! and the `xi_len` checks — and refuses rather than misreads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `sizeof(struct xinpgen)`. The buffer opens with one and ends with one.
const XINPGEN_LEN: u32 = 24;

/// Blocks are padded up to an eight-byte boundary. Nothing in the structures
/// says so — a 204-byte `xtcpcb_n` is simply followed by four bytes of nothing,
/// and a walk that advances by the length alone reads the padding as the next
/// block's header and stops.
const ALIGNMENT: usize = 8;

fn advance(length: usize) -> usize {
    length.div_ceil(ALIGNMENT) * ALIGNMENT
}

const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;
const XSO_TCPCB: u32 = 0x020;

/// Offsets into `struct xinpcb_n`.
///
/// The block is 104 bytes on macOS 26. A transcription from older xnu source
/// gives 108 and puts every field from `inp_vflag` onwards four bytes too far
/// along — which parses without complaint and reports every `[::]` listener as
/// `0.0.0.0`. These offsets were checked against the running kernel: the flag
/// byte that differs between the two port-22 listeners, and where `7f000001`
/// actually sits in a loopback socket.
mod inpcb {
    /// `xi_inpp`: the kernel's own pointer to this pcb. It is what makes the
    /// join with `libproc` exact rather than a guess by address and port —
    /// two sockets can share both.
    pub const PCB: usize = 8;
    pub const FOREIGN_PORT: usize = 16;
    pub const LOCAL_PORT: usize = 18;
    pub const VFLAG: usize = 44;
    pub const FOREIGN_ADDRESS: usize = 48;
    pub const LOCAL_ADDRESS: usize = 64;
    /// Everything above has to be present for a block to be usable.
    pub const MINIMUM: usize = LOCAL_ADDRESS + 16;

    pub const INP_IPV4: u8 = 0x1;
    pub const INP_IPV6: u8 = 0x2;
    /// `in_addr_4in6` puts the IPv4 address after three padding words.
    pub const V4_IN_V6_OFFSET: usize = 12;
}

/// Offsets into `struct xsocket_n`.
///
/// The block is 104 bytes on macOS 26, not the 72 a naive reading of the older
/// xnu source gives: fields have been added over the years. `so_uid` was found
/// by checking which offset yields this machine's own uid, and it is the only
/// field this parser reads out of the block.
mod socket {
    pub const UID: usize = 64;
    pub const MINIMUM: usize = UID + 4;
}

/// Offsets into `struct xtcpcb_n`.
mod tcpcb {
    /// After `xt_len`, `xt_kind`, `t_segq`, `t_dupacks` and `t_timer[4]`.
    pub const STATE: usize = 36;
    pub const MINIMUM: usize = STATE + 4;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("the buffer is too short to hold even its header")]
    NoHeader,
    #[error("the header claims {0} bytes; this build expects {XINPGEN_LEN}")]
    UnexpectedHeader(u32),
    #[error("a block claims {claimed} bytes but only {available} remain")]
    Truncated { claimed: usize, available: usize },
    #[error("a block claims {0} bytes, which cannot hold its own length and kind")]
    ImpossibleBlock(u32),
}

/// TCP connection states, from `netinet/tcp_fsm.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    FinWait1,
    Closing,
    LastAck,
    FinWait2,
    TimeWait,
    Unknown(i32),
}

impl TcpState {
    fn from_raw(state: i32) -> Self {
        match state {
            0 => TcpState::Closed,
            1 => TcpState::Listen,
            2 => TcpState::SynSent,
            3 => TcpState::SynReceived,
            4 => TcpState::Established,
            5 => TcpState::CloseWait,
            6 => TcpState::FinWait1,
            7 => TcpState::Closing,
            8 => TcpState::LastAck,
            9 => TcpState::FinWait2,
            10 => TcpState::TimeWait,
            other => TcpState::Unknown(other),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TcpState::Closed => "closed",
            TcpState::Listen => "listen",
            TcpState::SynSent => "syn-sent",
            TcpState::SynReceived => "syn-received",
            TcpState::Established => "established",
            TcpState::CloseWait => "close-wait",
            TcpState::FinWait1 => "fin-wait-1",
            TcpState::Closing => "closing",
            TcpState::LastAck => "last-ack",
            TcpState::FinWait2 => "fin-wait-2",
            TcpState::TimeWait => "time-wait",
            TcpState::Unknown(_) => "unknown",
        }
    }
}

/// One socket, assembled from however many blocks described it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    /// The kernel's identity for this socket, for joining against `libproc`.
    pub pcb: u64,
    pub local: IpAddr,
    pub local_port: u16,
    pub foreign: Option<IpAddr>,
    pub foreign_port: u16,
    /// `None` for UDP, which has no state machine.
    pub state: Option<TcpState>,
    /// The socket's owner, when a `XSO_SOCKET` block came with it.
    pub uid: Option<u32>,
}

impl Socket {
    /// A socket that is waiting for someone to connect to it, rather than one
    /// already talking to somebody.
    ///
    /// TCP says so itself. UDP has no state, so the test is a bound local port
    /// and no peer — which is what a service listening on a datagram socket
    /// looks like.
    pub fn is_listening(&self) -> bool {
        match self.state {
            Some(state) => state == TcpState::Listen,
            None => self.local_port != 0 && self.foreign.is_none(),
        }
    }
}

/// Walk a whole `pcblist_n` buffer.
pub fn walk(buffer: &[u8]) -> Result<Vec<Socket>, ParseError> {
    let mut offset = match header_length(buffer)? {
        Some(length) => length,
        // An empty table: the kernel returned nothing at all.
        None => return Ok(Vec::new()),
    };

    let mut sockets: Vec<Socket> = Vec::new();
    let mut pending: Option<Socket> = None;

    while offset < buffer.len() {
        let remaining = buffer.len() - offset;
        if remaining < 8 {
            return Err(ParseError::Truncated {
                claimed: 8,
                available: remaining,
            });
        }
        let block = &buffer[offset..];
        let claimed = word(block, 0);
        if claimed < 8 {
            return Err(ParseError::ImpossibleBlock(claimed));
        }
        let claimed = claimed as usize;
        if claimed > remaining {
            return Err(ParseError::Truncated {
                claimed,
                available: remaining,
            });
        }
        let block = &block[..claimed];
        let kind = word(block, 4);

        match kind {
            XSO_INPCB => {
                // A new socket begins. Whatever was being assembled is done.
                if let Some(socket) = pending.take() {
                    sockets.push(socket);
                }
                pending = read_inpcb(block);
            }
            XSO_SOCKET => {
                if let (Some(socket), Some(uid)) = (pending.as_mut(), read_uid(block)) {
                    socket.uid = Some(uid);
                }
            }
            XSO_TCPCB => {
                if let (Some(socket), Some(state)) = (pending.as_mut(), read_tcp_state(block)) {
                    socket.state = Some(state);
                }
            }
            // Buffer and statistics blocks, and the trailing xinpgen. Skipped
            // by length, which is why every block carries one.
            _ => {}
        }
        // Padding after the last block may be shorter than a header; that is
        // the end of the stream, not a truncation.
        let step = advance(claimed);
        if offset + step > buffer.len() {
            break;
        }
        offset += step;
    }

    if let Some(socket) = pending.take() {
        sockets.push(socket);
    }
    Ok(sockets)
}

/// Check the buffer really begins with the header this build expects, and
/// report how long it is. A mismatch means the kernel's layout moved, and
/// guessing past that point would produce plausible nonsense.
fn header_length(buffer: &[u8]) -> Result<Option<usize>, ParseError> {
    if buffer.is_empty() {
        return Ok(None);
    }
    if buffer.len() < XINPGEN_LEN as usize {
        return Err(ParseError::NoHeader);
    }
    let claimed = word(buffer, 0);
    if claimed != XINPGEN_LEN {
        return Err(ParseError::UnexpectedHeader(claimed));
    }
    Ok(Some(XINPGEN_LEN as usize))
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn read_inpcb(block: &[u8]) -> Option<Socket> {
    if block.len() < inpcb::MINIMUM {
        return None;
    }
    // A dual-stack socket carries both flags: it is an AF_INET6 socket that
    // also accepts v4-mapped connections. IPv6 wins, or every `[::]` listener
    // reads as `0.0.0.0` and the two show up as duplicates of each other.
    let vflag = block[inpcb::VFLAG];
    let ipv6 = vflag & inpcb::INP_IPV6 != 0;
    // A block with neither flag describes nothing this parser can read.
    if vflag & (inpcb::INP_IPV4 | inpcb::INP_IPV6) == 0 {
        return None;
    }

    let address = |at: usize| -> IpAddr {
        if ipv6 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[at..at + 16]);
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            let at = at + inpcb::V4_IN_V6_OFFSET;
            IpAddr::V4(Ipv4Addr::new(
                block[at],
                block[at + 1],
                block[at + 2],
                block[at + 3],
            ))
        }
    };

    let foreign = address(inpcb::FOREIGN_ADDRESS);
    let unconnected = match foreign {
        IpAddr::V4(a) => a.is_unspecified(),
        IpAddr::V6(a) => a.is_unspecified(),
    };

    let pcb = u64::from_ne_bytes(
        block[inpcb::PCB..inpcb::PCB + 8]
            .try_into()
            .expect("eight bytes"),
    );

    Some(Socket {
        pcb,
        local: address(inpcb::LOCAL_ADDRESS),
        // Ports are in network order on the wire and in this structure.
        local_port: u16::from_be_bytes([block[inpcb::LOCAL_PORT], block[inpcb::LOCAL_PORT + 1]]),
        foreign: (!unconnected).then_some(foreign),
        foreign_port: u16::from_be_bytes([
            block[inpcb::FOREIGN_PORT],
            block[inpcb::FOREIGN_PORT + 1],
        ]),
        state: None,
        uid: None,
    })
}

fn read_uid(block: &[u8]) -> Option<u32> {
    (block.len() >= socket::MINIMUM).then(|| word(block, socket::UID))
}

fn read_tcp_state(block: &[u8]) -> Option<TcpState> {
    (block.len() >= tcpcb::MINIMUM).then(|| TcpState::from_raw(word(block, tcpcb::STATE) as i32))
}

#[cfg(test)]
mod tests;
