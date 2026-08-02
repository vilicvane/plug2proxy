mod resolver;
mod server;
mod zone_handler;

pub use resolver::{local_resolver, resolve_locally};
pub use server::{DnsConfig, DnsStrategy, run_dns_server};
pub use zone_handler::RoutingZoneHandler;

#[cfg(test)]
pub(crate) use server::build_dns_server;
