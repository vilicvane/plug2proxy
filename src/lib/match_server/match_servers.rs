use crate::routing::config::OutRuleConfig;

use super::{
    redis_match_server::{RedisInMatchServer, RedisOutMatchServer},
    InMatchServerTrait as _, MatchCodec, MatchIn, MatchInId, MatchOut, MatchOutId,
    OutMatchServerTrait as _,
};

#[derive(derive_more::From)]
pub enum InMatchServer {
    Redis(RedisInMatchServer),
}

impl InMatchServer {
    pub async fn match_out<TInData, TOutData>(
        &self,
        in_id: MatchInId,
        in_data: TInData,
    ) -> anyhow::Result<MatchOut<TOutData>>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchCodec<TInData, TOutData>,
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

impl OutMatchServer {
    pub async fn match_in<TInData, TOutData>(
        &self,
        out_id: MatchOutId,
        out_data: TOutData,
        out_priority: i64,
        out_routing_rules: &[OutRuleConfig],
    ) -> anyhow::Result<MatchIn<TInData>>
    where
        TInData: serde::de::DeserializeOwned + Send,
        TOutData: serde::Serialize + Send,
        (TInData, TOutData): MatchCodec<TInData, TOutData>,
    {
        match self {
            Self::Redis(redis) => {
                redis
                    .match_in(out_id, out_data, out_priority, out_routing_rules)
                    .await
            }
        }
    }

    pub async fn register_in(&self, in_id: MatchInId) -> anyhow::Result<()> {
        match self {
            Self::Redis(redis) => redis.register_in(in_id).await,
        }
    }

    pub async fn unregister_in(&self, in_id: &MatchInId) -> anyhow::Result<()> {
        match self {
            Self::Redis(redis) => redis.unregister_in(in_id).await,
        }
    }
}
