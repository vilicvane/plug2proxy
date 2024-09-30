use crate::punch_quic::{
    matcher::{ClientSideMatcher, ServerSideMatcher},
    redis_matcher::{RedisClientSideMatcher, RedisServerSideMatcher},
};

pub fn stun_server_default() -> String {
    "stun.l.google.com:19302".to_string()
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
pub enum MatcherConfig {
    #[serde(rename = "redis")]
    Redis(RedisMatcherConfig),
}

impl MatcherConfig {
    pub fn new_client_side_matcher(&self) -> anyhow::Result<Box<dyn ClientSideMatcher + Sync>> {
        let matcher = match self {
            Self::Redis(config) => RedisClientSideMatcher::new(get_redis_client(config)?),
        };

        Ok(Box::new(matcher))
    }

    pub fn new_server_side_matcher(&self) -> anyhow::Result<Box<dyn ServerSideMatcher + Sync>> {
        let matcher = match self {
            Self::Redis(config) => RedisServerSideMatcher::new(get_redis_client(config)?),
        };

        Ok(Box::new(matcher))
    }
}

#[derive(serde::Deserialize)]
pub struct RedisMatcherConfig {
    pub url: String,
}

fn get_redis_client(
    RedisMatcherConfig { url }: &RedisMatcherConfig,
) -> anyhow::Result<redis::Client> {
    Ok(redis::Client::open(format!("{}?protocol=resp3", url))?)
}
