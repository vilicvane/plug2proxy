use std::{net::SocketAddr, str::FromStr};

use itertools::Itertools as _;

use crate::match_server::{MatchOutId, MatchPair};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Http2InData {}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Http2OutData {
    pub address: SocketAddr,
    pub cert: String,
    pub key: String,
}

pub type Http2MatchPair = (Http2InData, Http2OutData);

impl MatchPair<Http2InData, Http2OutData> for Http2MatchPair {
    fn get_match_name() -> &'static str {
        "http2"
    }

    fn get_redis_out_pattern() -> &'static str {
        "http2:out:*"
    }

    fn get_redis_out_key(out_id: &MatchOutId) -> String {
        format!("http2:out:{}", out_id)
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
        format!("http2:in:out:{}", out_id)
    }
}
