mod authority;
mod marked_runtime;
mod resolver;
mod server;

pub use authority::*;
pub use marked_runtime::*;
pub use resolver::*;
pub use server::*;

use std::net::{Ipv4Addr, Ipv6Addr};

/// Fake IPv4 network range (198.18.0.0/15 - TEST-NET)
pub const FAKE_IPV4_NET: ipnet::Ipv4Net =
    ipnet::Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15);

/// Fake IPv6 network range (2001:db8::/32 - Documentation)
pub const FAKE_IPV6_NET: ipnet::Ipv6Net =
    ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32);
