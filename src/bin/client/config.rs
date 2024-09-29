use plug2proxy::config::{stun_server_default, ExchangeServerConfig};

#[derive(serde::Deserialize)]
pub struct Config {
    #[serde(default = "stun_server_default")]
    pub stun_server: String,
    pub exchange_server: ExchangeServerConfig,
}
