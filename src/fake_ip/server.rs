use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use hickory_resolver::{
    Resolver,
    config::{NameServerConfigGroup, ResolverConfig},
    name_server::GenericConnector,
};
use hickory_server::authority::AuthorityObject;
use std::net::IpAddr;

use super::{FakeAuthority, MarkedRuntimeProvider};

pub struct FakeIpDnsOptions<'a> {
    pub listen_address: SocketAddr,
    pub db_path: &'a PathBuf,
    /// Upstream DNS servers.
    pub servers: &'a [IpAddr],
    /// Traffic mark (SO_MARK) for upstream DNS queries.
    pub mark: Option<u32>,
}

pub async fn run_fake_ip_dns(
    FakeIpDnsOptions {
        listen_address,
        db_path,
        servers,
        mark,
    }: FakeIpDnsOptions<'_>,
) -> anyhow::Result<()> {
    tracing::info!("starting fake-ip DNS server...");

    // Create resolver with marked sockets for upstream DNS queries
    let name_servers = NameServerConfigGroup::from_ips_clear(servers, 53, true);
    let resolver_config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    let runtime_provider = MarkedRuntimeProvider::new(mark);
    let resolver = Arc::new(
        Resolver::builder_with_config(resolver_config, GenericConnector::new(runtime_provider))
            .build(),
    );

    let mut catalog = hickory_server::authority::Catalog::new();

    let authority = FakeAuthority::new(resolver, db_path);

    let authority: Arc<dyn AuthorityObject> = Arc::new(authority);

    catalog.upsert(authority.origin().clone(), vec![authority]);

    let socket = socket2::Socket::new(
        socket2::Domain::for_address(listen_address),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // Be permissive on restart; harmless on Linux and helps avoid rare bind races.
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    socket.bind(&listen_address.into())?;

    let socket = tokio::net::UdpSocket::from_std(socket.into())?;

    let mut server = hickory_server::server::ServerFuture::new(catalog);

    server.register_socket(socket);

    tracing::info!("✅ Fake-IP DNS listening on {}", listen_address);

    server.block_until_done().await?;

    Ok(())
}
