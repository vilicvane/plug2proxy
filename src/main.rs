mod fake_authority;
mod notes;
mod tproxy_socket;

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use fake_authority::FakeAuthority;
use stun::message::Getter as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let (peer_1, peer_1_address) = create_peer_socket().await?;
    let (peer_2, peer_2_address) = create_peer_socket().await?;

    peer_1.send_to("hello".as_bytes(), peer_1_address).await?;
    peer_1.send_to("hello".as_bytes(), peer_2_address).await?;
    peer_2.send_to("hello".as_bytes(), peer_2_address).await?;
    peer_2.send_to("hello".as_bytes(), peer_1_address).await?;

    tokio::spawn(async move {
        let mut buffer = [0u8; 1024];

        loop {
            let (length, address) = peer_1.recv_from(&mut buffer).await?;

            println!(
                "received {} bytes from {}: {:?}",
                length,
                address,
                &buffer[..length]
            );
        }

        #[allow(unreachable_code)]
        anyhow::Ok(())
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    peer_2.send_to("world".as_bytes(), peer_1_address).await?;

    // stun_client.close().await?;

    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn create_peer_socket() -> anyhow::Result<(Arc<tokio::net::UdpSocket>, SocketAddr)> {
    let stun_server_address = "stun.l.google.com:19302";

    let socket = Arc::new(tokio::net::UdpSocket::bind("0:0").await?);

    println!("peer local address: {:?}", socket.local_addr()?);

    socket.connect(stun_server_address).await?;

    let mut stun_client = stun::client::ClientBuilder::new()
        .with_conn(socket.clone())
        .build()?;

    let mut message = stun::message::Message::new();

    message.build(&[
        Box::new(stun::agent::TransactionId::new()),
        Box::new(stun::message::BINDING_REQUEST),
    ])?;

    let (response_sender, mut response_receiver) = tokio::sync::mpsc::unbounded_channel();

    stun_client
        .send(&message, Some(Arc::new(response_sender)))
        .await?;

    let address = {
        let body = response_receiver.recv().await.unwrap().event_body?;

        let mut xor_addr = stun::xoraddr::XorMappedAddress::default();

        xor_addr.get_from(&body)?;

        SocketAddr::new(xor_addr.ip, xor_addr.port)
    };

    println!("peer address: {:?}", address);

    Ok((socket, address))
}

async fn test_sqlite() -> anyhow::Result<()> {
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
