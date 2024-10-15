use std::str::FromStr;

use crate::{route::config::OutRuleConfig, tunnel::TunnelId};

#[async_trait::async_trait]
pub trait InMatchServer {
    async fn accept_out<TInData, TOutData>(&self) -> anyhow::Result<MatchOutId>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>;

    async fn match_out<TInData, TOutData>(
        &self,
        out_id: MatchOutId,
        in_id: MatchInId,
        in_data: TInData,
    ) -> anyhow::Result<Option<MatchOut<TOutData>>>
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
    pub tunnel_priority: Option<i64>,
    pub routing_priority: i64,
    pub routing_rules: Vec<OutRuleConfig>,
    pub data: TData,
}

#[async_trait::async_trait]
pub trait OutMatchServerTrait: Send {
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
        (TInData, TOutData): MatchPair<TInData, TOutData>;
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
    PartialEq,
    Eq,
    Hash,
    Default,
    derive_more::From,
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

impl FromStr for MatchOutId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(uuid::Uuid::parse_str(s)?))
    }
}

pub trait MatchPair<TInData, TOutData> {
    fn get_match_name() -> &'static str;
    fn get_redis_out_pattern() -> &'static str;
    fn get_out_id_from_redis_out_key(out_key: &str) -> anyhow::Result<MatchOutId>;
    fn get_redis_out_key(out_id: &MatchOutId) -> String;
    fn get_redis_in_announcement_channel_name(out_id: &MatchOutId) -> String;
}
