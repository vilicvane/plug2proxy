use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::TryFutureExt;
use stun::message::Getter as _;
use webrtc_util::Conn;

use crate::{
    match_server::{
        AnyInMatchServer, InMatchServer as _, MatchIn, MatchInId, MatchOut, MatchOutId,
        OutMatchServer, OutMatchServerTrait as _,
    },
    route::config::OutRuleConfig,
    tunnel::{
        byte_stream_tunnel::{ByteStreamInTunnel, ByteStreamOutTunnel},
        tunnel_provider::{InTunnelProvider, OutTunnelProvider},
        InTunnel, OutTunnel,
    },
};

use super::{
    match_pair::{PunchQuicInData, PunchQuicOutData},
    punch::punch,
    quinn::{create_client_endpoint, create_server_endpoint},
    PunchQuicInTunnelConnection, PunchQuicOutTunnelConnection,
};

pub struct PunchQuicInTunnelConfig {
    pub stun_server_addresses: Vec<SocketAddr>,
    pub traffic_mark: u32,
}

pub struct PunchQuicInTunnelProvider {
    id: MatchInId,
    match_server: Arc<AnyInMatchServer>,
    config: PunchQuicInTunnelConfig,
}

impl PunchQuicInTunnelProvider {
    pub fn new(match_server: Arc<AnyInMatchServer>, config: PunchQuicInTunnelConfig) -> Self {
        Self {
            id: MatchInId::new(),
            match_server,
            config,
        }
    }
}

#[async_trait::async_trait]
impl InTunnelProvider for PunchQuicInTunnelProvider {
    async fn accept(&self) -> anyhow::Result<(Box<dyn InTunnel>, Vec<OutRuleConfig>)> {
        let socket = tokio::net::UdpSocket::bind("0:0").await?;

        nix::sys::socket::setsockopt(
            &socket,
            nix::sys::socket::sockopt::Mark,
            &self.config.traffic_mark,
        )?;

        let (socket, in_address) =
            configure_peer_socket(socket, &self.config.stun_server_addresses).await?;

        let MatchOut {
            id,
            tunnel_id,
            tunnel_labels,
            tunnel_priority,
            routing_rules,
            data: PunchQuicOutData { address },
        } = self
            .match_server
            .match_out(
                self.id,
                PunchQuicInData {
                    address: in_address,
                },
            )
            .await?;

        log::info!("matched OUT {address} as tunnel {tunnel_id}.");

        punch(&socket, address).await?;

        let endpoint = create_client_endpoint(socket.into_std()?)?;

        let connection = endpoint.connect(address, "localhost")?.await?;

        let tunnel = ByteStreamInTunnel::new(
            tunnel_id,
            id,
            tunnel_labels,
            tunnel_priority,
            PunchQuicInTunnelConnection::new(connection),
        );

        log::info!("tunnel {tunnel} established.");

        return Ok((Box::new(tunnel), routing_rules));
    }
}

pub struct PunchQuicOutTunnelConfig {
    pub priority: i64,
    pub stun_server_addresses: Vec<SocketAddr>,
    pub routing_rules: Vec<OutRuleConfig>,
}

pub struct PunchQuicOutTunnelProvider {
    id: MatchOutId,
    match_server: Arc<OutMatchServer>,
    config: PunchQuicOutTunnelConfig,
}

impl PunchQuicOutTunnelProvider {
    pub fn new(match_server: OutMatchServer, config: PunchQuicOutTunnelConfig) -> Self {
        Self {
            id: MatchOutId::new(),
            match_server: Arc::new(match_server),
            config,
        }
    }
}

#[async_trait::async_trait]
impl OutTunnelProvider for PunchQuicOutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>> {
        let socket = tokio::net::UdpSocket::bind("0:0").await?;

        let (socket, out_address) =
            configure_peer_socket(socket, &self.config.stun_server_addresses).await?;

        let MatchIn {
            id,
            tunnel_id,
            data: PunchQuicInData { address },
        } = self
            .match_server
            .match_in(
                self.id,
                PunchQuicOutData {
                    address: out_address,
                },
                self.config.priority,
                &self.config.routing_rules,
            )
            .await?;

        log::info!("matched IN {address} as tunnel {tunnel_id}.");

        punch(&socket, address).await?;

        let endpoint = create_server_endpoint(socket.into_std()?)?;

        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("incoming not available"))?;

        let connection = incoming.accept()?.await?;

        log::info!("tunnel {tunnel_id} established.");

        let connection = Arc::new(connection);

        self.match_server.register_in(id).await?;

        tokio::spawn({
            let connection = Arc::clone(&connection);
            let match_server = Arc::clone(&self.match_server);

            async move {
                let _ = connection.closed().await;

                match_server.unregister_in(&id).await?;

                anyhow::Ok(())
            }
            .inspect_err(|error| log::error!("{}", error))
        });

        return Ok(Box::new(ByteStreamOutTunnel::new(
            tunnel_id,
            PunchQuicOutTunnelConnection::new(connection),
        )));
    }
}

const STUN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

async fn configure_peer_socket(
    socket: tokio::net::UdpSocket,
    stun_server_addresses: &[SocketAddr],
) -> anyhow::Result<(tokio::net::UdpSocket, SocketAddr)> {
    let socket = Arc::new(socket);

    let address = {
        let stun_client_conn = Arc::new(ConnWrapper::new(socket.clone()));

        let mut stun_client = stun::client::ClientBuilder::new()
            .with_conn(stun_client_conn.clone())
            .build()?;

        let (response_sender, mut response_receiver) = tokio::sync::mpsc::unbounded_channel();

        let mut message = stun::message::Message::new();

        message.build(&[
            Box::new(stun::agent::TransactionId::new()),
            Box::new(stun::message::BINDING_REQUEST),
        ])?;

        let response_sender = Arc::new(response_sender);

        let mut address = None;

        for stun_server_address in stun_server_addresses {
            stun_client_conn.connect(*stun_server_address).await?;

            stun_client
                .send(&message, Some(response_sender.clone()))
                .await?;

            let body = tokio::select! {
                Some(response) = response_receiver.recv() => response.event_body?,
                _ = tokio::time::sleep(STUN_RESPONSE_TIMEOUT) => continue,
                else => continue,
            };

            let mut xor_addr = stun::xoraddr::XorMappedAddress::default();

            xor_addr.get_from(&body)?;

            address = Some(SocketAddr::new(xor_addr.ip, xor_addr.port));

            break;
        }

        stun_client.close().await?;

        address.ok_or_else(|| anyhow::anyhow!("failed to get public address from stun server."))?
    };

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

    Ok((socket, address))
}

pub struct ConnWrapper {
    socket: Arc<tokio::net::UdpSocket>,
    remote_address: Mutex<Option<SocketAddr>>,
}

impl ConnWrapper {
    pub fn new(socket: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            socket,
            remote_address: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl Conn for ConnWrapper {
    async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
        self.remote_address.lock().unwrap().replace(addr);

        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        Ok(self.socket.recv(buf).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        Ok(self.socket.recv_from(buf).await?)
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        let remote_addr = self
            .remote_address
            .lock()
            .unwrap()
            .expect("connect to an address before send.");

        Ok(self.socket.send_to(buf, remote_addr).await?)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        Ok(self.socket.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        *self.remote_address.lock().unwrap()
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        Ok(self.socket.close().await?)
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
