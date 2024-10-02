use crate::punch_quic::{
    match_server::{ClientSideMatchServer, ServerSideMatchServer},
    redis_match_server::{RedisClientSideMatchServer, RedisServerSideMatchServer},
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
    pub fn new_client_side_match_server(
        &self,
    ) -> anyhow::Result<Box<dyn ClientSideMatchServer + Sync>> {
        let server = match self {
            Self::Redis(config) => RedisClientSideMatchServer::new(get_redis_client(config)?),
        };

        Ok(Box::new(server))
    }

    pub async fn new_server_side_match_server(
        &self,
    ) -> anyhow::Result<Box<dyn ServerSideMatchServer + Sync>> {
        let server = match self {
            Self::Redis(config) => {
                RedisServerSideMatchServer::new(get_redis_client(config)?).await?
            }
        };

        Ok(Box::new(server))
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct RedisMatchServerConfig {
    pub url: String,
}

fn get_redis_client(
    RedisMatchServerConfig { url }: &RedisMatchServerConfig,
) -> anyhow::Result<redis::Client> {
    Ok(redis::Client::open(format!("{}?protocol=resp3", url))?)
}
