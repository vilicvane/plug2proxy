use std::net::SocketAddr;

use crate::tunnel::TunnelId;

#[async_trait::async_trait]
pub trait InMatchServer {
    async fn match_out(
        &self,
        in_id: uuid::Uuid,
        in_address: SocketAddr,
    ) -> anyhow::Result<MatchOut>;
}

pub struct MatchOut {
    pub id: uuid::Uuid,
    pub tunnel_id: TunnelId,
    pub tunnel_labels: Vec<String>,
    pub address: SocketAddr,
}

#[async_trait::async_trait]
pub trait OutMatchServer: Send {
    async fn match_in(
        &self,
        out_id: uuid::Uuid,
        out_address: SocketAddr,
    ) -> anyhow::Result<MatchIn>;

    async fn register_in(&self, in_id: uuid::Uuid) -> anyhow::Result<()>;

    async fn unregister_in(&self, in_id: &uuid::Uuid) -> anyhow::Result<()>;
}

pub struct MatchIn {
    pub id: uuid::Uuid,
    pub tunnel_id: TunnelId,
    pub address: SocketAddr,
}
