use std::net::SocketAddr;

#[async_trait::async_trait]
pub trait InMatchServer {
    async fn match_out(
        &self,
        in_id: uuid::Uuid,
        in_address: SocketAddr,
    ) -> anyhow::Result<SocketAddr>;
}

#[async_trait::async_trait]
pub trait OutMatchServer: Send {
    async fn match_in(
        &self,
        out_id: uuid::Uuid,
        out_address: SocketAddr,
    ) -> anyhow::Result<(uuid::Uuid, SocketAddr)>;

    async fn register_in(&self, in_id: uuid::Uuid) -> anyhow::Result<()>;

    async fn unregister_in(&self, in_id: &uuid::Uuid) -> anyhow::Result<()>;
}
