use crate::{match_server::MatchOutId, route::config::OutRuleConfig};

use super::{InTunnel, OutTunnel};

#[async_trait::async_trait]
pub trait InTunnelProvider: Sync {
    fn name(&self) -> &'static str;

    async fn accept_out(&self) -> anyhow::Result<(MatchOutId, usize)>;

    async fn accept(
        &self,
        out_id: MatchOutId,
    ) -> anyhow::Result<Option<(Box<dyn InTunnel>, (Vec<OutRuleConfig>, i64))>>;
}

#[async_trait::async_trait]
pub trait OutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>>;
}
