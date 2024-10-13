mod fake_authority;
#[allow(clippy::module_inception)]
mod fake_ip_dns;
mod fake_ip_resolver;

pub use fake_authority::*;
pub use fake_ip_dns::*;
pub use fake_ip_resolver::*;
