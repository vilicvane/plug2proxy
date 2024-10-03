use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

#[async_trait::async_trait]
pub trait InTunnel: Send + Sync {
    fn get_id(&self) -> TunnelId;

    async fn connect(
        &self,
        typ: TransportType,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )>;

    fn is_closed(&self) -> bool;
}

#[async_trait::async_trait]
pub trait OutTunnel: Send + Sync {
    fn get_id(&self) -> TunnelId;

    async fn accept(
        &self,
    ) -> anyhow::Result<(
        TransportType,
        SocketAddr,
        (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ),
    )>;

    fn is_closed(&self) -> bool;
}

#[derive(Debug, derive_more::Display)]
pub enum TransportType {
    #[display("UDP")]
    Udp,
    #[display("TCP")]
    Tcp,
}

#[derive(
    Clone,
    Debug,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    derive_more::Display,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TunnelId(pub uuid::Uuid);

impl TunnelId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}
