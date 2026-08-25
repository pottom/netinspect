//! Stage 2 — the gateway.
//!
//! An ICMP echo would need a raw socket and therefore privileges this tool
//! refuses to ask for, so reachability is established with a TCP connect
//! instead. The distinction that matters is between *an answer* and *silence*:
//! a refused connection is an answer — the router sent an RST, so it is there.
//! Only a timeout means unreachable.
//!
//! This module holds no logic of its own; the rule above lives in the
//! `Connector` implementations and is asserted in `src/probe/mod.rs`.
