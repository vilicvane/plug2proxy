use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use plug2proxy::routing::config::{InFallbackRuleConfig, InRuleConfig};

pub const DATA_DIR_DEFAULT: &str = ".plug2proxy";

pub fn dns_server_addresses_default() -> Vec<String> {
    vec!["119.29.29.29".to_string(), "119.28.28.28".to_string()]
}

pub fn fake_ip_dns_address_default() -> SocketAddr {
    "127.0.0.124:53".parse().unwrap()
}

pub fn fake_ipv4_net_default() -> ipnet::Ipv4Net {
    "198.18.0.0/15".parse().unwrap()
}

pub fn fake_ipv6_net_default() -> ipnet::Ipv6Net {
    "2001:db8::/32".parse().unwrap()
}

pub fn transparent_proxy_address_default() -> SocketAddr {
    "127.0.0.1:12345".parse().unwrap()
}

pub fn transparent_proxy_traffic_mark_default() -> u32 {
    0xff
}

pub fn stun_server_addresses_default() -> Vec<String> {
    vec![
        "stun.l.google.com:19302".to_string(),
        "stun.miwifi.com:3478".to_string(),
    ]
}

pub fn fake_ip_dns_db_path_default(data_dir: Option<&str>) -> PathBuf {
    Path::new(data_dir.unwrap_or(DATA_DIR_DEFAULT)).join("fake_ip_dns.db")
}

pub fn geolite2_cache_path_default(data_dir: Option<&str>) -> PathBuf {
    Path::new(data_dir.unwrap_or(DATA_DIR_DEFAULT)).join("geolite2.mmdb")
}

pub fn geolite2_url_default() -> String {
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb".to_string()
}

pub fn geolite2_update_interval_default() -> Duration {
    Duration::from_secs(24 * 60 * 60)
}

pub fn in_routing_rules_default() -> Vec<InRuleConfig> {
    vec![InRuleConfig::Fallback(InFallbackRuleConfig {
        out: "ANY".to_owned().into(),
    })]
}
