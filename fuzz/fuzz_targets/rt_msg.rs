//! The routing-message walker, against arbitrary bytes.
//!
//! The property: whatever comes in, the parser either describes it or refuses
//! it. It must never panic and never read past the end of the buffer.
//!
//!     cargo +nightly fuzz run rt_msg
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(routes) = netinspect::parse::rt_msg::walk(data) {
        // Whatever it produced must be readable without further checks.
        for route in routes {
            if let Some(mask) = &route.netmask {
                let prefix = netinspect::parse::rt_msg::prefix_len(mask, false);
                assert!(prefix <= 128);
            }
        }
    }
});
