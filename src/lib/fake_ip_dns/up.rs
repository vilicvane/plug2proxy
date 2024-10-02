use std::{net::SocketAddr, sync::Arc};

use hickory_server::authority::Authority as _;

use super::FakeAuthority;

pub async fn up() -> anyhow::Result<()> {
    let mut catalog = hickory_server::authority::Catalog::new();

    let authority = FakeAuthority::new(".debug/test.db");

    let authority = Box::new(Arc::new(authority));

    catalog.upsert(authority.origin().clone(), authority);

    let udp_socket =
        tokio::net::UdpSocket::bind("0.0.0.0:5353".parse::<SocketAddr>().unwrap()).await?;

    let mut server = hickory_server::server::ServerFuture::new(catalog);

    server.register_socket(udp_socket);

    server.block_until_done().await?;

    Ok(())
}
