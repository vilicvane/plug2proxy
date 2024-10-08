use crate::{
    route::config::OutRuleConfig,
    tunnel::{InTunnel, OutTunnel},
};

#[async_trait::async_trait]
pub trait OutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>>;
}

#[async_trait::async_trait]
pub trait InTunnelProvider {
    async fn accept(&self) -> anyhow::Result<(Box<dyn InTunnel>, Vec<OutRuleConfig>)>;
}
