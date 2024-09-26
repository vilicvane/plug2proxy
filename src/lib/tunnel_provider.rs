use crate::tunnel::{ClientTunnel, ServerTunnel};

#[async_trait::async_trait]
pub trait ServerTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn ServerTunnel>>;
}

#[async_trait::async_trait]
pub trait ClientTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn ClientTunnel>>;
}
