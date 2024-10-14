use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use hickory_server::authority::Authority as _;

use super::FakeAuthority;

pub struct Options<'a> {
    pub listen_address: SocketAddr,
    pub db_path: &'a PathBuf,
}

pub async fn up(
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
    Options {
        listen_address,
        db_path,
    }: Options<'_>,
) -> anyhow::Result<()> {
    log::info!("starting IN fake-ip dns...");

    let mut catalog = hickory_server::authority::Catalog::new();

    let authority = FakeAuthority::new(resolver, db_path);

    let authority = Box::new(Arc::new(authority));

    catalog.upsert(authority.origin().clone(), authority);

    let socket = socket2::Socket::new(
        socket2::Domain::for_address(listen_address),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    socket.bind(&listen_address.into())?;

    let socket = tokio::net::UdpSocket::from_std(socket.into())?;

    let mut server = hickory_server::server::ServerFuture::new(catalog);

    server.register_socket(socket);

    log::info!("fake-ip dns listening on {listen_address}...");

    server.block_until_done().await?;

    Ok(())
}
