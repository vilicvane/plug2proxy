use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use hickory_server::authority::AuthorityObject;

use super::FakeAuthority;

pub struct FakeIpDnsOptions<'a> {
    pub listen_address: SocketAddr,
    pub db_path: &'a PathBuf,
}

pub async fn run_fake_ip_dns(
    resolver: Arc<hickory_resolver::TokioResolver>,
    FakeIpDnsOptions {
        listen_address,
        db_path,
    }: FakeIpDnsOptions<'_>,
) -> anyhow::Result<()> {
    tracing::info!("starting fake-ip DNS server...");

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
