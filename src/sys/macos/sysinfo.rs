//! Small ioctl-based reads that `getifaddrs` does not cover.
//!
//! `ioctl(2)` is a syscall, not a subprocess. See spec 2.1.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `SIOCGIFMTU` on macOS: `_IOWR('i', 51, struct ifreq)`.
const SIOCGIFMTU: libc::c_ulong = 0xc020_6933;

const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfReqMtu {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_mtu: libc::c_int,
    _pad: [u8; 12],
}

/// Read the MTU of an interface. `None` when the name does not fit, the
/// scratch socket cannot be opened, or the kernel refuses the request.
pub fn mtu(iface: &str) -> Option<u32> {
    let mut req = IfReqMtu {
        ifr_name: [0; IFNAMSIZ],
        ifr_mtu: 0,
        _pad: [0; 12],
    };
    let bytes = iface.as_bytes();
    if bytes.len() >= IFNAMSIZ {
        return None;
    }
    for (slot, byte) in req.ifr_name.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }

    // Safety: a datagram socket is only used as a handle for the ioctl; we own
    // the descriptor and close it via OwnedFd.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Safety: `req` is a correctly shaped `struct ifreq` with a NUL-terminated
    // name, and the kernel writes only into `ifr_mtu`.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), SIOCGIFMTU, &mut req) };
    if rc < 0 {
        return None;
    }
    u32::try_from(req.ifr_mtu).ok()
}
