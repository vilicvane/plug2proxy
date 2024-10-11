use crate::route::config::OutRuleConfig;

use super::{InTunnel, OutTunnel};

#[async_trait::async_trait]
pub trait InTunnelProvider {
    fn connections(&self) -> usize {
        1
    }

    async fn accept(&self) -> anyhow::Result<(Box<dyn InTunnel>, (Vec<OutRuleConfig>, i64))>;
}

#[async_trait::async_trait]
pub trait OutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>>;
}
