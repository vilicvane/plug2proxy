use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use stun::message::Getter as _;

const STUN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

pub async fn create_socket_and_probe_external_address(
    stun_server_addresses: &[SocketAddr],
) -> anyhow::Result<(tokio::net::UdpSocket, SocketAddr)> {
    let (socket, address) = create_and_probe(stun_server_addresses, true).await?;

    Ok((socket.unwrap(), address))
}

pub async fn probe_external_ip(stun_server_addresses: &[SocketAddr]) -> anyhow::Result<IpAddr> {
    let (_, address) = create_and_probe(stun_server_addresses, false).await?;

    Ok(address.ip())
}

async fn create_and_probe(
    stun_server_addresses: &[SocketAddr],
    keep_socket: bool,
) -> anyhow::Result<(Option<tokio::net::UdpSocket>, SocketAddr)> {
    let socket = Arc::new(tokio::net::UdpSocket::bind("0:0").await?);

    let address = {
        let mut stun_client = stun::client::ClientBuilder::new()
            .with_conn(socket.clone())
            .with_rto(STUN_RESPONSE_TIMEOUT)
            .build()?;

        let mut message = stun::message::Message::new();

        message.build(&[
            Box::new(stun::agent::TransactionId::new()),
            Box::new(stun::message::BINDING_REQUEST),
        ])?;

        let mut address = None;

        for stun_server_address in stun_server_addresses {
            let result = async {
                socket.connect(*stun_server_address).await?;

                let (response_sender, mut response_receiver) =
                    tokio::sync::mpsc::unbounded_channel();

                let response_sender = Arc::new(response_sender);

                stun_client
                    .send(&message, Some(response_sender.clone()))
                    .await?;

                let body = response_receiver
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("no response."))?
                    .event_body?;

                let mut xor_addr = stun::xoraddr::XorMappedAddress::default();

                xor_addr.get_from(&body)?;

                anyhow::Ok(SocketAddr::new(xor_addr.ip, xor_addr.port))
            }
            .await;

            match result {
                Ok(probed_address) => {
                    address = Some(probed_address);
                    break;
                }
                Err(error) => {
                    log::error!("STUN request to {stun_server_address} failed: {}", error);
                }
            }
        }

        stun_client.close().await?;

        address.ok_or_else(|| anyhow::anyhow!("failed to get public address from stun server."))?
    };

    if keep_socket {
        let mut socket = socket;

        let socket = loop {
            match Arc::try_unwrap(socket) {
                Ok(socket) => break socket,
                Err(socket_arc) => {
                    socket = socket_arc;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
        };

        socket.connect("0:0").await?;

        Ok((Some(socket), address))
    } else {
        Ok((None, address))
    }
}
