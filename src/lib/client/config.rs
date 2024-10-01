use crate::config::{stun_server_default, MatcherConfig};

#[derive(Clone, serde::Deserialize)]
pub struct Config {
    #[serde(default = "stun_server_default")]
    pub stun_server: String,
    pub matcher: MatcherConfig,
}
