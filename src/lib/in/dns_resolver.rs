use std::net::{IpAddr, SocketAddr};

use itertools::Itertools;

pub fn create_dns_resolver<T: AsRef<str>>(servers: &[T]) -> hickory_resolver::TokioAsyncResolver {
    let mut config = hickory_resolver::config::ResolverConfig::new();

    for server in servers {
        let server = server
            .as_ref()
            .parse::<IpAddr>()
            .expect("invalid DNS server address.");

        let socket_address = SocketAddr::new(server, 53);

        config.add_name_server(hickory_resolver::config::NameServerConfig {
            socket_addr: socket_address,
            protocol: hickory_resolver::config::Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        });
    }

    hickory_resolver::TokioAsyncResolver::new(
        config,
        hickory_resolver::config::ResolverOpts::default(),
        hickory_resolver::name_server::TokioConnectionProvider::default(),
    )
}

pub async fn convert_to_socket_addresses<T: AsRef<str>>(
    source: T,
    dns_resolver: &hickory_resolver::TokioAsyncResolver,
    port_default: Option<u16>,
) -> anyhow::Result<Vec<SocketAddr>> {
    let source = source.as_ref();

    if let Result::<SocketAddr, _>::Ok(address) = source.parse() {
        return Ok(vec![address]);
    }

    let (hostname, port) = if let Some((hostname, port)) = source.split_once(":") {
        let port = port.parse::<u16>()?;

        (hostname, port)
    } else {
        let port = port_default.ok_or_else(|| anyhow::anyhow!("missing port number."))?;

        (source, port)
    };

    let addresses = dns_resolver
        .lookup_ip(hostname)
        .await?
        .iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect_vec();

    Ok(addresses)
}
