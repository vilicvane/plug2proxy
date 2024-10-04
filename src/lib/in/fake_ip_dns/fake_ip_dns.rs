use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use hickory_server::authority::Authority as _;

use super::FakeAuthority;

pub struct Options<'a> {
    pub listen_address: SocketAddr,
    pub db_path: &'a PathBuf,
}

pub async fn up(
    Options {
        listen_address,
        db_path,
    }: Options<'_>,
) -> anyhow::Result<()> {
    log::info!("starting IN fake-ip dns...");

    let mut catalog = hickory_server::authority::Catalog::new();

    let authority = FakeAuthority::new(db_path);

    let authority = Box::new(Arc::new(authority));

    catalog.upsert(authority.origin().clone(), authority);

    let udp_socket = tokio::net::UdpSocket::bind(listen_address).await?;

    let mut server = hickory_server::server::ServerFuture::new(catalog);

    server.register_socket(udp_socket);

    log::info!("fake-ip dns listening on {listen_address}...");

    server.block_until_done().await?;

    Ok(())
}
