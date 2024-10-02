use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
};

use futures::TryFutureExt;
use stun::message::Getter as _;
use webrtc_util::Conn;

use crate::{
    tunnel::{InTunnel, OutTunnel},
    tunnel_provider::{InTunnelProvider, OutTunnelProvider},
};

use super::{
    match_server::{InMatchServer, OutMatchServer},
    punch::punch,
    quinn::{create_client_endpoint, create_server_endpoint},
    PunchQuicInTunnel, PunchQuicOutTunnel,
};

pub struct PunchQuicInTunnelConfig {
    pub stun_server_addr: String,
}

pub struct PunchQuicInTunnelProvider {
    id: uuid::Uuid,
    match_server: Box<dyn InMatchServer + Sync>,
    config: PunchQuicInTunnelConfig,
}

impl PunchQuicInTunnelProvider {
    pub fn new(
        match_server: Box<dyn InMatchServer + Sync>,
        config: PunchQuicInTunnelConfig,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            match_server,
            config,
        }
    }
}

#[async_trait::async_trait]
impl InTunnelProvider for PunchQuicInTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn InTunnel>> {
        let (socket, address) = create_peer_socket(&self.config.stun_server_addr).await?;

        let peer_address = self.match_server.match_out(self.id, address).await?;

        punch(&socket, peer_address).await?;

        let endpoint = create_client_endpoint(socket.into_std()?)?;

        let conn = endpoint.connect(peer_address, "localhost")?.await?;

        return Ok(Box::new(PunchQuicInTunnel::new(conn)));
    }
}

pub struct PunchQuicOutTunnelConfig {
    pub stun_server_addr: String,
}

pub struct PunchQuicOutTunnelProvider {
    id: uuid::Uuid,
    match_server: Arc<Box<dyn OutMatchServer + Sync>>,
    config: PunchQuicOutTunnelConfig,
}

impl PunchQuicOutTunnelProvider {
    pub fn new(
        match_server: Box<dyn OutMatchServer + Sync>,
        config: PunchQuicOutTunnelConfig,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            match_server: Arc::new(match_server),
            config,
        }
    }
}

#[async_trait::async_trait]
impl OutTunnelProvider for PunchQuicOutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>> {
        let (socket, address) = create_peer_socket(&self.config.stun_server_addr).await?;

        let (in_id, in_address) = self.match_server.match_in(self.id, address).await?;

        punch(&socket, in_address).await?;

        let endpoint = create_server_endpoint(socket.into_std()?)?;

        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("incoming not available"))?;

        let conn = incoming.accept()?.await?;

        let conn = Arc::new(conn);

        self.match_server.register_in(in_id).await?;

        tokio::spawn({
            let conn = Arc::clone(&conn);
            let match_server = Arc::clone(&self.match_server);

            async move {
                let _ = conn.closed().await;

                match_server.unregister_in(&in_id).await?;

                anyhow::Ok(())
            }
            .inspect_err(|error| log::error!("{}", error))
        });

        return Ok(Box::new(PunchQuicOutTunnel::new(conn)));
    }
}

async fn create_peer_socket(
    stun_server_addr: &str,
) -> anyhow::Result<(tokio::net::UdpSocket, SocketAddr)> {
    async fn inner(
        stun_server_addr: &str,
    ) -> anyhow::Result<(Arc<tokio::net::UdpSocket>, SocketAddr)> {
        let stun_server_addr = stun_server_addr.to_socket_addrs()?.next().unwrap();

        let socket = Arc::new(tokio::net::UdpSocket::bind("0:0").await?);

        let stun_client_conn = ConnWrapper::new(socket.clone());

        stun_client_conn.connect(stun_server_addr).await?;

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

        stun_client.close().await?;

        Ok((socket, address))
    }

    let (socket, address) = inner(stun_server_addr).await?;

    // `stun_client` does a spawn internally, and loops till close, so yield now
    // and give it a chance to drop the socket reference.
    //
    // But I don't know why I have to put this after `inner()` call.
    tokio::task::yield_now().await;

    let socket = Arc::try_unwrap(socket).unwrap();

    Ok((socket, address))
}

pub struct ConnWrapper {
    socket: Arc<tokio::net::UdpSocket>,
    remote_addr: Mutex<Option<SocketAddr>>,
}

impl ConnWrapper {
    pub fn new(socket: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            socket,
            remote_addr: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl Conn for ConnWrapper {
    async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
        self.remote_addr.lock().unwrap().replace(addr);

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
            .remote_addr
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
        *self.remote_addr.lock().unwrap()
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        Ok(self.socket.close().await?)
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
