use std::net::SocketAddr;

#[async_trait::async_trait]
pub trait MatchServer {
    async fn match_server(&self, id: uuid::Uuid, address: SocketAddr)
        -> anyhow::Result<SocketAddr>;

    async fn match_client(&self, id: uuid::Uuid, address: SocketAddr)
        -> anyhow::Result<SocketAddr>;
}
