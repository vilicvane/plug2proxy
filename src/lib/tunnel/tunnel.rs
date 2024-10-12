use std::{fmt, net::SocketAddr};

use crate::match_server::MatchOutId;

#[async_trait::async_trait]
pub trait InTunnelLike: fmt::Display + Send + Sync {
    async fn connect(
        &self,
        destination_address: SocketAddr,
        destination_name: Option<String>,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )>;
}

#[async_trait::async_trait]
pub trait InTunnel: InTunnelLike {
    fn id(&self) -> TunnelId;

    fn out_id(&self) -> MatchOutId;

    fn labels(&self) -> &[String];

    fn priority(&self) -> i64;

    async fn closed(&self);

    fn is_closed(&self) -> bool;
}

#[async_trait::async_trait]
pub trait OutTunnel: fmt::Display + Send {
    fn id(&self) -> TunnelId;

    async fn accept(
        &self,
    ) -> anyhow::Result<(
        (SocketAddr, Option<String>),
        (
            Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        ),
    )>;

    fn is_closed(&self) -> bool;
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
