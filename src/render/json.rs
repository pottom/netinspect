//! Machine-readable output (spec 8).
//!
//! Stable and versioned: all numbers are numbers, absent data is `null` and
//! never an empty string, and bumping `schema` is a breaking change.

use anyhow::Result;
use serde::Serialize;

/// One object on one line, or indented when `pretty`.
pub fn emit<T: Serialize>(value: &T, pretty: bool) -> Result<String> {
    let text = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsConfig, Snapshot, SCHEMA};

    fn empty_snapshot() -> Snapshot {
        Snapshot {
            schema: SCHEMA,
            version: "0.1.0".to_owned(),
            timestamp: "2026-08-25T14:22:07+02:00".to_owned(),
            interfaces: Vec::new(),
            dns: DnsConfig {
                servers: Vec::new(),
                search_domains: Vec::new(),
                proxy: None,
                split_dns_scopes: 0,
            },
            reachability: None,
            public: None,
            update: None,
        }
    }

    #[test]
    fn compact_output_is_one_line() {
        let text = emit(&empty_snapshot(), false).unwrap();
        assert!(!text.contains('\n'));
    }

    #[test]
    fn absent_data_is_null_never_an_empty_string() {
        let text = emit(&empty_snapshot(), false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(parsed["reachability"].is_null());
        assert!(parsed["public"].is_null());
        assert!(parsed["dns"]["proxy"].is_null());
        // Numbers are numbers.
        assert_eq!(parsed["schema"], 1);
        assert_eq!(parsed["dns"]["split_dns_scopes"], 0);
    }
}
