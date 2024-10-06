use std::{fmt::Display, net::SocketAddr};

#[async_trait::async_trait]
pub trait InTunnel: Display + Send + Sync {
    fn id(&self) -> TunnelId;

    fn labels(&self) -> &[String];

    fn priority(&self) -> i64;

    async fn connect(
        &self,
        r#type: TransportType,
        destination_hostname: String,
        destination_address: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )>;

    async fn closed(&self);

    fn is_closed(&self) -> bool;
}

#[async_trait::async_trait]
pub trait OutTunnel: Send + Sync {
    fn id(&self) -> TunnelId;

    async fn accept(
        &self,
    ) -> anyhow::Result<(
        TransportType,
        (String, u16),
        (
            Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
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
