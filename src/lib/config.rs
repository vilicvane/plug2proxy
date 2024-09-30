use crate::punch_quic::{match_server::MatchServer, redis_match_server::RedisMatchServer};

pub fn stun_server_default() -> String {
    "stun.l.google.com:19302".to_string()
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
pub enum MatchServerConfig {
    #[serde(rename = "redis")]
    Redis(RedisMatchServerConfig),
}

impl MatchServerConfig {
    pub fn new_match_server(&self) -> anyhow::Result<Box<dyn MatchServer + Sync>> {
        let match_server = match self {
            Self::Redis(config) => RedisMatchServer::new(redis::Client::open(format!(
                "{}?protocol=resp3",
                config.url
            ))?),
        };

        Ok(Box::new(match_server))
    }
}

#[derive(serde::Deserialize)]
pub struct RedisMatchServerConfig {
    pub url: String,
}
