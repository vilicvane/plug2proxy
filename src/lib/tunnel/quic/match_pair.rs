use std::{net::SocketAddr, str::FromStr as _};

use itertools::Itertools as _;

use crate::match_server::{MatchOutId, MatchPair};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct QuicInData {}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct QuicOutData {
    pub address: SocketAddr,
    pub cert: String,
    pub key: String,
}

impl MatchPair<QuicInData, QuicOutData> for (QuicInData, QuicOutData) {
    fn get_match_name() -> &'static str {
        "quic"
    }

    fn get_redis_out_pattern() -> &'static str {
        "quic:out:*"
    }

    fn get_redis_out_key(out_id: &MatchOutId) -> String {
        format!("quic:out:{}", out_id)
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
        format!("quic:in:out:{}", out_id)
    }
}
