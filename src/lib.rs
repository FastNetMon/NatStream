//! Conntrack NAT event export: the parts the daemon is assembled from.
//!
//! The daemon in `main.rs` is a thin wrapper over these modules — it opens the
//! sockets, runs the event loop and supervises itself, and everything it does
//! in between is here.
//!
//! They live in a library target rather than in the binary so that things
//! outside the daemon can link to them. The benchmarks in `benches/` are the
//! reason: a `benches/` target is a separate crate, and a binary-only package
//! has nothing for it to import.

pub mod event;
pub mod export;
pub mod netlink;
pub mod signals;
