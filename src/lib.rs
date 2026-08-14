//! Conntrack NAT event export: the parts the daemon is assembled from.
//!
//! The daemon in `main.rs` handles process supervision and the event loop; these
//! modules provide the parsing, encoding, socket, and signal-handling pieces it
//! assembles.
//!
//! They live in a library target rather than in the binary so that things
//! outside the daemon can link to them. The benchmarks in `benches/` are the
//! reason: a `benches/` target is a separate crate, and a binary-only package
//! has nothing for it to import.

pub mod event;
pub mod export;
pub mod netlink;
pub mod signals;
