use std::net::SocketAddr;

use crate::match_server::{MatchInId, MatchPair};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Http2InData {
    pub address: SocketAddr,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Http2OutData {
    pub address: SocketAddr,
}

impl MatchPair<Http2InData, Http2OutData> for (Http2InData, Http2OutData) {
    fn get_redis_match_channel_name(in_id: MatchInId, in_data: &Http2InData) -> String {
        format!("http2:{}/{}", in_id, in_data.address)
    }

    fn get_redis_match_lock_key(in_id: MatchInId, in_data: &Http2InData) -> String {
        format!("http2:match:{}/{}", in_id, in_data.address)
    }

    fn get_redis_in_announcement_channel_name() -> String {
        "http2:in_announcement".to_owned()
    }
}
