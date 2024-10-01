use std::{env, net::SocketAddr, str::FromStr as _, sync::Arc};

use plug2proxy::fake_ip_dns::FakeAuthority;
use redis::{AsyncCommands as _, PubSubCommands as _};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut catalog = hickory_server::authority::Catalog::new();

    let origin = hickory_server::proto::rr::Name::from_str(".")?;

    // let authority = hickory_server::store::in_memory::InMemoryAuthority::empty(
    //     origin.clone(),
    //     hickory_server::authority::ZoneType::Primary,
    //     false,
    // );

    let resolver = {
        let config = hickory_resolver::config::ResolverConfig::default();

        hickory_resolver::TokioAsyncResolver::new(
            config,
            hickory_resolver::config::ResolverOpts::default(),
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
    };

    let authority = FakeAuthority::new(resolver);

    let authority = Box::new(Arc::new(authority));

    // authority
    //     .upsert(
    //         hickory_server::proto::rr::Record::from_rdata(
    //             hickory_server::proto::rr::Name::from_str("example.com.").unwrap(),
    //             300,
    //             hickory_server::proto::rr::RData::A(hickory_server::proto::rr::rdata::A::new(
    //                 192, 168, 1, 31,
    //             )),
    //         ),
    //         0,
    //     )
    //     .await;

    // authority
    //     .upsert(
    //         hickory_server::proto::rr::Record::from_rdata(
    //             hickory_server::proto::rr::Name::from_str("localhost").unwrap(),
    //             300,
    //             hickory_server::proto::rr::RData::A(hickory_server::proto::rr::rdata::A::new(
    //                 127, 0, 0, 123,
    //             )),
    //         ),
    //         0,
    //     )
    //     .await;

    catalog.upsert(origin.into(), authority);

    let udp_socket =
        tokio::net::UdpSocket::bind("0.0.0.0:5353".parse::<SocketAddr>().unwrap()).await?;

    let mut server = hickory_server::server::ServerFuture::new(catalog);

    server.register_socket(udp_socket);

    server.block_until_done().await?;

    Ok(())
}
