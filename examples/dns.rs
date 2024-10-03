use std::{backtrace, net::SocketAddr, path::PathBuf, str::FromStr as _, sync::Arc};

use hickory_server::authority::AuthorityObject;
use plug2proxy::r#in::fake_ip_dns::FakeAuthority;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    color_backtrace::install();

    let mut catalog = hickory_server::authority::Catalog::new();

    let authority = FakeAuthority::new(&PathBuf::from(".debug/test.db"));

    let authority = Box::new(Arc::new(authority));

    catalog.upsert(authority.origin().clone(), authority);

    let udp_socket =
        tokio::net::UdpSocket::bind("0.0.0.0:5353".parse::<SocketAddr>().unwrap()).await?;

    let mut server = hickory_server::server::ServerFuture::new(catalog);

    server.register_socket(udp_socket);

    server.block_until_done().await?;

    Ok(())
}
