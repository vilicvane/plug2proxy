use crate::{route::config::OutRuleConfig, tunnel::TunnelId};

#[async_trait::async_trait]
pub trait InMatchServerTrait {
    async fn match_out<TInData, TOutData>(
        &self,
        in_id: MatchInId,
        in_data: TInData,
    ) -> anyhow::Result<MatchOut<TOutData>>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>;
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MatchOut<TData> {
    pub id: MatchOutId,
    pub tunnel_id: TunnelId,
    pub tunnel_labels: Vec<String>,
    pub tunnel_priority: i64,
    pub routing_rules: Vec<OutRuleConfig>,
    pub data: TData,
}

#[async_trait::async_trait]
pub trait OutMatchServerTrait: Send {
    async fn match_in<TInData, TOutData>(
        &self,
        out_id: MatchOutId,
        out_data: TOutData,
        out_priority: i64,
        out_routing_rules: &[OutRuleConfig],
    ) -> anyhow::Result<MatchIn<TInData>>
    where
        TInData: serde::de::DeserializeOwned + Send,
        TOutData: serde::Serialize + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>;

    async fn register_in(&self, in_id: MatchInId) -> anyhow::Result<()>;

    async fn unregister_in(&self, in_id: &MatchInId) -> anyhow::Result<()>;
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MatchIn<TData> {
    pub id: MatchInId,
    pub tunnel_id: TunnelId,
    pub data: TData,
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    derive_more::From,
    derive_more::FromStr,
    derive_more::Display,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct MatchInId(uuid::Uuid);

impl MatchInId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

#[derive(
    Clone,
    Copy,
    Default,
    derive_more::From,
    derive_more::FromStr,
    derive_more::Display,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct MatchOutId(uuid::Uuid);

impl MatchOutId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

pub trait MatchPair<TInData, TOutData> {
    fn get_redis_match_channel_name(in_id: MatchInId, in_data: &TInData) -> String;
    fn get_redis_match_lock_key(in_id: MatchInId, in_data: &TInData) -> String;
    fn get_redis_in_announcement_channel_name() -> String;
}
