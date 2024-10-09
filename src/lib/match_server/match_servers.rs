use crate::route::config::OutRuleConfig;

use super::{
    redis_match_server::{RedisInMatchServer, RedisOutMatchServer},
    InMatchServer, MatchIn, MatchInId, MatchOut, MatchOutId, MatchPair, OutMatchServerTrait,
};

#[derive(derive_more::From)]
pub enum AnyInMatchServer {
    Redis(RedisInMatchServer),
}

#[async_trait::async_trait]
impl InMatchServer for AnyInMatchServer {
    async fn match_out<TInData, TOutData>(
        &self,
        in_id: MatchInId,
        in_data: TInData,
    ) -> anyhow::Result<MatchOut<TOutData>>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>,
    {
        match self {
            Self::Redis(redis) => redis.match_out(in_id, in_data).await,
        }
    }
}

#[derive(derive_more::From)]
pub enum OutMatchServer {
    Redis(RedisOutMatchServer),
}

#[async_trait::async_trait]
impl OutMatchServerTrait for OutMatchServer {
    async fn match_in<TInData, TOutData>(
        &self,
        out_id: MatchOutId,
        out_data: TOutData,
        out_priority: Option<i64>,
        out_routing_rules: &[OutRuleConfig],
        out_routing_priority: i64,
    ) -> anyhow::Result<MatchIn<TInData>>
    where
        TInData: serde::de::DeserializeOwned + Send,
        TOutData: serde::Serialize + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>,
    {
        match self {
            Self::Redis(redis) => {
                redis
                    .match_in(
                        out_id,
                        out_data,
                        out_priority,
                        out_routing_rules,
                        out_routing_priority,
                    )
                    .await
            }
        }
    }

    async fn register_in(&self, in_id: MatchInId) -> anyhow::Result<()> {
        match self {
            Self::Redis(redis) => redis.register_in(in_id).await,
        }
    }

    async fn unregister_in(&self, in_id: &MatchInId) -> anyhow::Result<()> {
        match self {
            Self::Redis(redis) => redis.unregister_in(in_id).await,
        }
    }
}
