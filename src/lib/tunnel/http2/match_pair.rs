use std::net::SocketAddr;

use crate::match_server::MatchPair;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Http2InData {}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Http2OutData {
    pub address: SocketAddr,
    pub cert: String,
    pub key: String,
}

impl MatchPair<Http2InData, Http2OutData> for (Http2InData, Http2OutData) {
    fn get_match_name() -> &'static str {
        "http2"
    }

    fn get_redis_in_announcement_channel_name() -> String {
        "http2:in_announcement".to_owned()
    }
}
