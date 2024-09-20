use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use fake_authority::FakeAuthority;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};

mod fake_authority;
mod tproxy_socket;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let sqlite = rusqlite::Connection::open_with_flags(
        "test.db",
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;

    sqlite.execute(
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name STRING NOT NULL,
            real_ip STRING NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_name ON records (name);
        "#,
        [],
    )?;

    // let x = hickory_client::client::ClientFuture::

    test_dns().await?;

    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn test_dns() -> anyhow::Result<()> {
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

async fn test_socket() -> anyhow::Result<()> {
    let tcp_server_address = "0.0.0.0:12233".parse::<SocketAddr>()?;

    let tcp_server = socket2::Socket::new(
        socket2::Domain::for_address(tcp_server_address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    tcp_server.set_ip_transparent(true)?;

    tcp_server.bind(&socket2::SockAddr::from(tcp_server_address))?;
    tcp_server.listen(1024)?;

    let (socket, source_address) = tcp_server.accept()?;

    let original_destination = socket.original_dst();

    let mut socket = tokio::net::TcpStream::from_std(std::net::TcpStream::from(socket))?;

    println!("Accepted connection from: {:?}", source_address.as_socket());
    println!("{:?}", original_destination?.as_socket());

    socket.write("hello world\n".as_bytes()).await?;

    loop {
        let mut buffer = [0; 8];

        let length = socket.read(&mut buffer).await?;

        if length == 0 {
            break;
        }

        println!("Received: {:?}", &buffer[..length]);
    }

    Ok(())
}
