use std::net::SocketAddr;

use crate::match_server::MatchPair;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct YamuxInData {
    pub address: SocketAddr,
    pub cert: String,
    pub token: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct YamuxOutData {}

impl MatchPair<YamuxInData, YamuxOutData> for (YamuxInData, YamuxOutData) {
    fn get_match_name() -> &'static str {
        "yamux"
    }

    fn get_redis_in_announcement_channel_name() -> String {
        "yamux:in_announcement".to_owned()
    }
}
