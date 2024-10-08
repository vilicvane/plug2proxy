use crate::match_server::{
    redis_match_server::{RedisInMatchServer, RedisOutMatchServer},
    InMatchServer, OutMatchServer,
};

#[derive(Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum MatchServerConfig {
    #[serde(rename = "redis")]
    Redis(RedisMatchServerConfig),
}

impl MatchServerConfig {
    pub fn new_in_match_server(&self) -> anyhow::Result<InMatchServer> {
        Ok(match self {
            Self::Redis(config) => RedisInMatchServer::new(new_redis_client(config)?).into(),
        })
    }

    pub async fn new_out_match_server(
        &self,
        labels: Vec<String>,
    ) -> anyhow::Result<OutMatchServer> {
        Ok(match self {
            Self::Redis(config) => RedisOutMatchServer::new(new_redis_client(config)?, labels)
                .await?
                .into(),
        })
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

#[derive(Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum MatchServerUrlOrConfig {
    Url(String),
    Config(MatchServerConfig),
}

impl MatchServerUrlOrConfig {
    pub fn into_config(self) -> MatchServerConfig {
        match self {
            Self::Url(url) => {
                let parsed_url = url::Url::parse(&url).expect("invalid match server url.");

                let scheme = parsed_url.scheme();

                match scheme {
                    "redis" | "rediss" => MatchServerConfig::Redis(RedisMatchServerConfig { url }),
                    _ => panic!("unsupported match server url."),
                }
            }
            Self::Config(config) => config,
        }
    }
}
