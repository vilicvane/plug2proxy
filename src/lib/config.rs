use crate::punch_quic::{
    match_server::{InMatchServer, OutMatchServer},
    redis_match_server::{RedisInMatchServer, RedisOutMatchServer},
};

pub fn stun_server_default() -> String {
    "stun.l.google.com:19302".to_string()
}

#[derive(Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum MatchServerConfig {
    #[serde(rename = "redis")]
    Redis(RedisMatchServerConfig),
}

impl MatchServerConfig {
    pub fn new_in_match_server(&self) -> anyhow::Result<Box<dyn InMatchServer + Sync>> {
        let server = match self {
            Self::Redis(config) => RedisInMatchServer::new(new_redis_client(config)?),
        };

        Ok(Box::new(server))
    }

    pub async fn new_out_match_server(&self) -> anyhow::Result<Box<dyn OutMatchServer + Sync>> {
        let server = match self {
            Self::Redis(config) => RedisOutMatchServer::new(new_redis_client(config)?).await?,
        };

        Ok(Box::new(server))
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct RedisMatchServerConfig {
    pub url: String,
}

fn new_redis_client(
    RedisMatchServerConfig { url }: &RedisMatchServerConfig,
) -> anyhow::Result<redis::Client> {
    Ok(redis::Client::open(format!("{}?protocol=resp3", url))?)
}
