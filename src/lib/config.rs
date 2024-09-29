pub fn stun_server_default() -> String {
    "stun.l.google.com:19302".to_string()
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
pub enum ExchangeServerConfig {
    #[serde(rename = "redis")]
    Redis(RedisExchangeServerConfig),
}

#[derive(serde::Deserialize)]
pub struct RedisExchangeServerConfig {
    pub url: String,
    pub auth: Option<RedisExchangeServerConfigAuth>,
}

#[derive(serde::Deserialize)]
pub enum RedisExchangeServerConfigAuth {
    UsernamePassword(String, String),
    Password(String),
}
