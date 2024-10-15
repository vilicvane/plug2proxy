use std::{net::SocketAddr, str::FromStr as _};

use itertools::Itertools as _;

use crate::match_server::{MatchOutId, MatchPair};

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

    fn get_redis_out_pattern() -> &'static str {
        "punch_quic:out:*"
    }

    fn get_redis_out_key(out_id: &MatchOutId) -> String {
        format!("punch_quic:out:{}", out_id)
    }

    fn get_out_id_from_redis_out_key(out_key: &str) -> anyhow::Result<MatchOutId> {
        out_key
            .split(":")
            .collect_vec()
            .last()
            .map(|out_id| MatchOutId::from_str(out_id))
            .unwrap()
    }

    fn get_redis_in_announcement_channel_name(out_id: &MatchOutId) -> String {
        format!("punch_quic:in:out:{}", out_id)
    }
}
