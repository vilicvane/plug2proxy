use std::{
    cell::RefCell,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::Parser;
use futures::TryFutureExt;
use plug2proxy::{punch, quinn::make_endpoint, webrtc_util::ConnWrapper};
use stun::message::Getter as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use webrtc_util::Conn as _;

#[derive(clap::Parser, Debug)]
struct Cli {
    #[clap(long)]
    server: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    color_backtrace::install();

    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let cli = Cli::parse();

    let (socket, public_address) = create_peer_socket().await?;

    let stdin = std::io::stdin();

    println!("peer address:");

    let peer_address = stdin
        .lines()
        .next()
        .unwrap()
        .unwrap()
        .parse::<SocketAddr>()?;

    tokio::spawn({
        let being_server = cli.server;

        async move {
            let socket = Arc::try_unwrap(socket).unwrap();

            punch::punch(&socket, peer_address).await?;

            let endpoint = make_endpoint(socket, being_server)?;

            if being_server {
                if let Some(incoming) = endpoint.accept().await {
                    let connection = incoming.accept()?.await?;

                    let (_, mut stream) = connection.accept_bi().await?;

                    let buffer = &mut [0u8; 1024];

                    while let Some(length) = stream.read(buffer).await? {
                        println!("{:?}", &buffer[..length]);
                    }

                    tokio::signal::ctrl_c().await?;
                }
            } else {
                let connection = endpoint.connect(peer_address, "localhost")?.await?;

                let (mut stream, _) = connection.open_bi().await?;

                loop {
                    stream.write_all(b"hello").await?;

                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                tokio::signal::ctrl_c().await?;
            }

            anyhow::Ok(())
        }
        .inspect_err(|error| panic!("{:?}", error))
    })
    .await??;

    Ok(())
}

async fn create_peer_socket() -> anyhow::Result<(Arc<tokio::net::UdpSocket>, SocketAddr)> {
    let stun_server_address = "stun.l.google.com:19302".to_socket_addrs()?.next().unwrap();

    let socket = Arc::new(tokio::net::UdpSocket::bind("0:0").await?);

    println!("peer local address: {:?}", socket.local_addr()?);

    let stun_client_conn = ConnWrapper::new(socket.clone());

    stun_client_conn.connect(stun_server_address).await?;

    let mut stun_client = stun::client::ClientBuilder::new()
        .with_conn(Arc::new(stun_client_conn))
        .build()?;

    let address = {
        let (response_sender, mut response_receiver) = tokio::sync::mpsc::unbounded_channel();

        let mut message = stun::message::Message::new();

        message.build(&[
            Box::new(stun::agent::TransactionId::new()),
            Box::new(stun::message::BINDING_REQUEST),
        ])?;

        stun_client
            .send(&message, Some(Arc::new(response_sender)))
            .await?;

        let body = response_receiver.recv().await.unwrap().event_body?;

        let mut xor_addr = stun::xoraddr::XorMappedAddress::default();

        xor_addr.get_from(&body)?;

        SocketAddr::new(xor_addr.ip, xor_addr.port)
    };

    println!("peer address: {:?}", address);

    stun_client.close().await?;

    // stun_client does a spawn internally, and loop till close, so yield now
    // and give it a chance to drop the socket reference.
    tokio::task::yield_now().await;

    Ok((socket, address))
}
