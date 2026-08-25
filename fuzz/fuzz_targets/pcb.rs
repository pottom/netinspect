//! The socket-table walker, against arbitrary bytes.
//!
//! The property: whatever comes in, the parser either describes it or refuses
//! it — never a panic, never a read past the end.
//!
//!     cargo +nightly fuzz run pcb
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sockets) = netinspect::parse::pcb::walk(data) {
        for socket in sockets {
            // Whatever came out must be readable without further checks.
            let _ = socket.is_listening();
            let _ = socket.local.to_string();
        }
    }
});
