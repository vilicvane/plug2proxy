use crate::route::config::OutRuleConfig;

use super::{
    redis_match_server::{RedisInMatchServer, RedisOutMatchServer},
    InMatchServer, MatchIn, MatchOut, MatchOutId, MatchPair, OutMatchServerTrait,
};

#[derive(derive_more::From)]
pub enum AnyInMatchServer {
    Redis(RedisInMatchServer),
}

#[async_trait::async_trait]
impl InMatchServer for AnyInMatchServer {
    async fn accept_out<TInData, TOutData>(&self) -> anyhow::Result<MatchOutId>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>,
    {
        match self {
            Self::Redis(redis) => redis.accept_out::<TInData, TOutData>().await,
        }
    }

    async fn match_out<TInData, TOutData>(
        &self,
        out_id: MatchOutId,
        in_data: TInData,
    ) -> anyhow::Result<Option<MatchOut<TOutData>>>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>,
    {
        match self {
            Self::Redis(redis) => redis.match_out(out_id, in_data).await,
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
                        out_data,
                        out_priority,
                        out_routing_rules,
                        out_routing_priority,
                    )
                    .await
            }
        }
    }
}
