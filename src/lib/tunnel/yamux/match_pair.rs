use std::net::SocketAddr;

use crate::match_server::{MatchInId, MatchPair};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct YamuxInData {
    pub index: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct YamuxOutData {
    pub address: SocketAddr,
    pub cert: String,
    pub token: String,
}

impl MatchPair<YamuxInData, YamuxOutData> for (YamuxInData, YamuxOutData) {
    fn get_match_name() -> &'static str {
        "yamux"
    }

    fn get_redis_match_channel_name(in_id: MatchInId, in_data: &YamuxInData) -> String {
        format!("yamux:{}/{}", in_id, in_data.index)
    }

    fn get_redis_match_lock_key(in_id: MatchInId, in_data: &YamuxInData) -> String {
        format!("yamux:match:{}/{}", in_id, in_data.index)
    }

    fn get_redis_in_announcement_channel_name() -> String {
        "yamux:in_announcement".to_owned()
    }
}
