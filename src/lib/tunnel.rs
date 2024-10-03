use std::net::SocketAddr;

#[async_trait::async_trait]
pub trait InTunnel: Send + Sync {
    fn id(&self) -> TunnelId;

    fn labels(&self) -> &[String];

    fn priority(&self) -> i64;

    fn get_remote(&self, address: SocketAddr, name: Option<String>) -> (String, u16);

    async fn connect(
        &self,
        r#type: TransportType,
        remote_hostname: String,
        remote_port: u16,
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
