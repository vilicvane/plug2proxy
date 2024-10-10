use std::net::SocketAddr;

use crate::match_server::MatchPair;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PunchQuicInData {
    pub address: SocketAddr,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PunchQuicOutData {
    pub address: SocketAddr,
}

impl MatchPair<PunchQuicInData, PunchQuicOutData> for (PunchQuicInData, PunchQuicOutData) {
    fn get_match_name() -> &'static str {
        "punch_quic"
    }

    fn get_redis_in_announcement_channel_name() -> String {
        "punch_quic:in_announcement".to_owned()
    }
}
