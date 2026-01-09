//! High-level relay logic for TCP and UDP.
//!
//! This module provides unified relay functionality for proxying traffic
//! between client sockets and the proxy (via tunnel or direct connections).

mod tcp;
mod udp;

pub use tcp::*;
pub use udp::*;
