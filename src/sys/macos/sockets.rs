//! Listening sockets, from two sources that neither of them is sufficient
//! alone.
//!
//! **Source A — the pcb list.** `net.inet.{tcp,udp}.pcblist_n` returns every
//! socket on the system, including other users', with no privileges at all. It
//! carries addresses, ports and state, but no process identity.
//!
//! **Source B — libproc.** Walking every pid's file descriptors gives the
//! process name behind a socket, but an unprivileged process can only inspect
//! its own user's processes, so the mapping is always partial.
//!
//! The order follows from that: **enumerate from A, so the list is complete
//! whoever runs it, and enrich with B where possible.** A socket whose owner
//! could not be determined is reported with no owner and counted. Omitting it
//! because we could not name it would make this actively misleading as a
//! security check — an unattributed open port is still an open port.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{bail, Result};
use libproc::libproc::file_info::{self, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid;
use libproc::processes::{pids_by_type, ProcFilter};

use crate::model::{
    Exposure, Family, Protocol, ProcessInfo, SocketEntry, SocketFilter, SocketSummary, SocketTable,
};
use crate::parse::pcb::{self, Socket};

/// A socket as source A knows it: complete, and anonymous.
#[derive(Debug, Clone)]
pub struct Raw {
    pub protocol: Protocol,
    pub socket: Socket,
}

pub fn collect(filter: SocketFilter) -> Result<SocketTable> {
    let mut raw = Vec::new();
    if filter.tcp {
        raw.extend(read("net.inet.tcp.pcblist_n", Protocol::Tcp)?);
    }
    if filter.udp {
        raw.extend(read("net.inet.udp.pcblist_n", Protocol::Udp)?);
    }
    if !filter.include_established {
        raw.retain(|entry| entry.socket.is_listening());
    }

    Ok(join(raw, &owners()))
}

fn read(name: &str, protocol: Protocol) -> Result<Vec<Raw>> {
    let buffer = dump(name)?;
    let sockets = pcb::walk(&buffer)
        .map_err(|error| anyhow::anyhow!("{name} could not be parsed: {error}"))?;
    Ok(sockets
        .into_iter()
        .map(|socket| Raw { protocol, socket })
        .collect())
}

/// Two calls: one to size the buffer, one to fill it, with headroom for
/// sockets opened in between.
fn dump(name: &str) -> Result<Vec<u8>> {
    let name = std::ffi::CString::new(name)?;

    let mut needed: libc::size_t = 0;
    // Safety: a NUL-terminated MIB name, a null buffer to ask only for the
    // size, and a length the kernel writes through.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        bail!(
            "sysctl could not size {}: {}",
            name.to_string_lossy(),
            std::io::Error::last_os_error()
        );
    }
    if needed == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; needed + needed / 8 + 4096];
    let mut length = buffer.len();
    // Safety: `buffer` is `length` bytes and outlives the call; the kernel
    // writes at most `length` and reports what it wrote.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        bail!(
            "sysctl could not read {}: {}",
            name.to_string_lossy(),
            std::io::Error::last_os_error()
        );
    }
    buffer.truncate(length.min(buffer.len()));
    Ok(buffer)
}

/// Source B, keyed by the kernel's own handle for each socket.
///
/// Every failure here is silent and partial by design: a process that exited
/// between the listing and the lookup, or one this user may not inspect, simply
/// contributes nothing. It must never take the socket list down with it.
fn owners() -> HashMap<u64, ProcessInfo> {
    let mut owners = HashMap::new();
    let Ok(pids) = pids_by_type(ProcFilter::All) else {
        return owners;
    };

    for pid in pids {
        let pid = pid as i32;
        let Ok(descriptors) = proc_pid::listpidinfo::<ListFDs>(pid, MAX_DESCRIPTORS) else {
            continue;
        };
        let name = proc_pid::name(pid).unwrap_or_default();

        for descriptor in descriptors {
            if !matches!(ProcFDType::from(descriptor.proc_fdtype), ProcFDType::Socket) {
                continue;
            }
            let Ok(info) = file_info::pidfdinfo::<SocketFDInfo>(pid, descriptor.proc_fd) else {
                continue;
            };
            // Only IP sockets; the pcb list has nothing else in it.
            if !matches!(
                SocketInfoKind::from(info.psi.soi_kind),
                SocketInfoKind::In | SocketInfoKind::Tcp
            ) {
                continue;
            }
            owners.entry(info.psi.soi_pcb).or_insert_with(|| ProcessInfo {
                name: name.clone(),
                pid,
                uid: 0,
                user: None,
            });
        }
    }
    owners
}

/// Enough for any process; `listpidinfo` truncates rather than failing.
const MAX_DESCRIPTORS: usize = 4096;

/// Put the two sources together.
///
/// Pure, and deliberately so: the case that matters is `owners` being empty,
/// which is what an unprivileged run against other users' processes looks
/// like. Every socket must still come out.
pub fn join(raw: Vec<Raw>, owners: &HashMap<u64, ProcessInfo>) -> SocketTable {
    let mut sockets: Vec<SocketEntry> = raw
        .into_iter()
        .map(|entry| {
            let exposure = exposure(&entry.socket.local);
            // The uid comes from source A, so it is known even when the
            // process behind the socket is not.
            let process = owners.get(&entry.socket.pcb).map(|owner| ProcessInfo {
                name: owner.name.clone(),
                pid: owner.pid,
                uid: entry.socket.uid.unwrap_or(owner.uid),
                user: user_name(entry.socket.uid.unwrap_or(owner.uid)),
            });
            SocketEntry {
                protocol: entry.protocol,
                family: match entry.socket.local {
                    IpAddr::V4(_) => Family::Inet,
                    IpAddr::V6(_) => Family::Inet6,
                },
                address: entry.socket.local.to_string(),
                port: entry.socket.local_port,
                state: entry
                    .socket
                    .state
                    .map(|state| state.label().to_owned())
                    .unwrap_or_else(|| "bound".to_owned()),
                exposure,
                process,
            }
        })
        .collect();

    // Most exposed first: the dangerous group must never be below the fold.
    sockets.sort_by(|a, b| {
        rank(a.exposure)
            .cmp(&rank(b.exposure))
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.address.cmp(&b.address))
    });

    let count = |exposure: Exposure| sockets.iter().filter(|s| s.exposure == exposure).count();
    let summary = SocketSummary {
        total: sockets.len(),
        wildcard: count(Exposure::Wildcard),
        loopback: count(Exposure::Loopback),
        interface: count(Exposure::Interface),
        unattributed: sockets.iter().filter(|s| s.process.is_none()).count(),
    };

    SocketTable { sockets, summary }
}

fn rank(exposure: Exposure) -> u8 {
    match exposure {
        Exposure::Wildcard => 0,
        Exposure::Interface => 1,
        Exposure::Loopback => 2,
    }
}

/// Where a bound address can be reached from.
///
/// A wildcard bind is read as the more exposed of its two possible meanings: it
/// is internet-facing whenever any interface has a routable address, and a
/// security readout must assume the worse reading.
pub fn exposure(address: &IpAddr) -> Exposure {
    match address {
        IpAddr::V4(v4) if v4.is_unspecified() => Exposure::Wildcard,
        IpAddr::V6(v6) if v6.is_unspecified() => Exposure::Wildcard,
        IpAddr::V4(v4) if v4.is_loopback() => Exposure::Loopback,
        IpAddr::V6(v6) if v6.is_loopback() => Exposure::Loopback,
        _ => Exposure::Interface,
    }
}

/// `getpwuid(3)`, for the annotation on sockets owned by somebody else.
fn user_name(uid: u32) -> Option<String> {
    // Safety: the returned pointer is owned by the C library and valid until
    // the next call; the name is copied out before anything else runs.
    let entry = unsafe { libc::getpwuid(uid) };
    if entry.is_null() {
        return None;
    }
    let name = unsafe { (*entry).pw_name };
    if name.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(name) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::pcb::TcpState;

    fn socket(pcb: u64, address: &str, port: u16, uid: Option<u32>) -> Raw {
        Raw {
            protocol: Protocol::Tcp,
            socket: Socket {
                pcb,
                local: address.parse().unwrap(),
                local_port: port,
                foreign: None,
                foreign_port: 0,
                state: Some(TcpState::Listen),
                uid,
            },
        }
    }

    #[test]
    fn a_wildcard_bind_is_the_most_exposed_reading() {
        assert_eq!(exposure(&"0.0.0.0".parse().unwrap()), Exposure::Wildcard);
        assert_eq!(exposure(&"::".parse().unwrap()), Exposure::Wildcard);
        assert_eq!(exposure(&"127.0.0.1".parse().unwrap()), Exposure::Loopback);
        assert_eq!(exposure(&"::1".parse().unwrap()), Exposure::Loopback);
        assert_eq!(exposure(&"192.168.1.24".parse().unwrap()), Exposure::Interface);
        assert_eq!(exposure(&"fe80::1".parse().unwrap()), Exposure::Interface);
    }

    /// The case this whole design exists for: no process could be identified,
    /// and every socket still has to appear.
    #[test]
    fn an_unprivileged_run_still_lists_every_socket() {
        let raw = vec![
            socket(1, "0.0.0.0", 5432, Some(501)),
            socket(2, "127.0.0.1", 6379, Some(501)),
            socket(3, "192.168.1.24", 8384, Some(0)),
        ];
        let table = join(raw, &HashMap::new());

        assert_eq!(table.sockets.len(), 3, "no socket may be dropped");
        assert!(table.sockets.iter().all(|s| s.process.is_none()));
        assert_eq!(table.summary.unattributed, 3);
        assert_eq!(table.summary.total, 3);
        assert_eq!(table.summary.wildcard, 1);
        assert_eq!(table.summary.loopback, 1);
        assert_eq!(table.summary.interface, 1);
    }

    #[test]
    fn a_partial_mapping_names_what_it_can_and_admits_the_rest() {
        let raw = vec![
            socket(1, "0.0.0.0", 5432, Some(501)),
            socket(2, "0.0.0.0", 22, Some(0)),
        ];
        let mut owners = HashMap::new();
        owners.insert(
            1,
            ProcessInfo {
                name: "postgres".to_owned(),
                pid: 1284,
                uid: 0,
                user: None,
            },
        );

        let table = join(raw, &owners);
        assert_eq!(table.summary.unattributed, 1);
        let named = table
            .sockets
            .iter()
            .find(|s| s.port == 5432)
            .expect("the postgres socket");
        assert_eq!(named.process.as_ref().unwrap().name, "postgres");
        // The uid comes from source A, so it is right even though the owners
        // map carried a placeholder.
        assert_eq!(named.process.as_ref().unwrap().uid, 501);
        assert!(table.sockets.iter().find(|s| s.port == 22).unwrap().process.is_none());
    }

    #[test]
    fn the_dangerous_group_is_never_below_the_fold() {
        let raw = vec![
            socket(1, "127.0.0.1", 6379, None),
            socket(2, "192.168.1.24", 8384, None),
            socket(3, "0.0.0.0", 5432, None),
            socket(4, "0.0.0.0", 22, None),
        ];
        let table = join(raw, &HashMap::new());
        let order: Vec<_> = table.sockets.iter().map(|s| s.exposure).collect();
        assert_eq!(
            order,
            vec![
                Exposure::Wildcard,
                Exposure::Wildcard,
                Exposure::Interface,
                Exposure::Loopback
            ]
        );
        // And within a group, by port.
        assert_eq!(table.sockets[0].port, 22);
        assert_eq!(table.sockets[1].port, 5432);
    }

    #[test]
    fn a_socket_with_no_state_is_bound_rather_than_blank() {
        let mut raw = socket(1, "0.0.0.0", 5353, Some(0));
        raw.protocol = Protocol::Udp;
        raw.socket.state = None;
        let table = join(vec![raw], &HashMap::new());
        assert_eq!(table.sockets[0].state, "bound");
    }
}

/// Capture fixtures for `parse::pcb`.
///
/// Ignored by default: it writes files and needs a real kernel. Run it with
/// `cargo test --lib -- --ignored capture_socket_fixtures`.
///
/// A raw dump is a machine's own service inventory. Addresses and uids are
/// rewritten; every length, kind, alignment byte and block order survives,
/// which is the reason to keep a real buffer at all.
#[cfg(test)]
mod capture {
    use super::*;

    const XSO_INPCB: u32 = 0x010;
    const XSO_SOCKET: u32 = 0x001;
    const XINPGEN_LEN: usize = 24;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    fn scramble(seed: &[u8]) -> u16 {
        seed.iter().fold(0x811cu16, |hash, byte| {
            (hash ^ u16::from(*byte)).wrapping_mul(0x0193)
        })
    }

    fn sanitise(buffer: &mut [u8]) {
        let mut offset = XINPGEN_LEN;
        while offset + 8 <= buffer.len() {
            let claimed = word(buffer, offset) as usize;
            if claimed < 8 || offset + claimed > buffer.len() {
                break;
            }
            let kind = word(buffer, offset + 4);
            let block = &mut buffer[offset..offset + claimed];

            match kind {
                XSO_INPCB if claimed >= 80 => {
                    let ipv6 = block[44] & 0x2 != 0;
                    for at in [48usize, 64] {
                        let slot = &mut block[at..at + 16];
                        // Leave the wildcard and loopback alone: they identify
                        // nobody and they are what the exposure test turns on.
                        if slot.iter().all(|b| *b == 0) || (!ipv6 && slot[12] == 127) {
                            continue;
                        }
                        if ipv6 && slot[0] == 0 && slot[15] <= 1 {
                            continue;
                        }
                        let n = scramble(slot);
                        if ipv6 {
                            let mut replacement = [0u8; 16];
                            replacement[0..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
                            replacement[14..16].copy_from_slice(&n.to_be_bytes());
                            slot.copy_from_slice(&replacement);
                        } else {
                            slot[12..16].copy_from_slice(&[198, 51, 100, (n & 0xff) as u8]);
                        }
                    }
                }
                XSO_SOCKET if claimed >= 68 => {
                    // One anonymous non-root owner is enough to exercise the
                    // "somebody else's socket" annotation.
                    let uid = word(block, 64);
                    if uid != 0 {
                        block[64..68].copy_from_slice(&501u32.to_ne_bytes());
                    }
                }
                _ => {}
            }
            offset += claimed.div_ceil(8) * 8;
        }
    }

    #[test]
    #[ignore = "writes fixture files and needs a real socket table"]
    fn capture_socket_fixtures() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        std::fs::create_dir_all(&directory).unwrap();

        for (name, mib) in [
            ("sockets-tcp", "net.inet.tcp.pcblist_n"),
            ("sockets-udp", "net.inet.udp.pcblist_n"),
        ] {
            let mut buffer = dump(mib).unwrap();
            let before = crate::parse::pcb::walk(&buffer).unwrap().len();
            sanitise(&mut buffer);
            let after = crate::parse::pcb::walk(&buffer).unwrap();
            assert_eq!(before, after.len(), "{name}: sanitising changed the count");

            std::fs::write(directory.join(format!("{name}.bin")), &buffer).unwrap();
            println!(
                "{name}.bin: {} bytes, {} sockets, {} listening",
                buffer.len(),
                after.len(),
                after.iter().filter(|s| s.is_listening()).count()
            );
        }
    }
}
