use std::net::SocketAddr;

#[async_trait::async_trait]
pub trait ClientSideMatchServer {
    async fn match_server(
        &self,
        client_id: uuid::Uuid,
        client_address: SocketAddr,
    ) -> anyhow::Result<SocketAddr>;
}

#[async_trait::async_trait]
pub trait ServerSideMatchServer: Send {
    async fn match_client(
        &self,
        server_id: uuid::Uuid,
        server_address: SocketAddr,
    ) -> anyhow::Result<(uuid::Uuid, SocketAddr)>;

    async fn register_client(&self, client_id: uuid::Uuid) -> anyhow::Result<()>;

    async fn unregister_client(&self, client_id: &uuid::Uuid) -> anyhow::Result<()>;
}
