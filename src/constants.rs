use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use plug2proxy::routing::config::InRuleConfig;

pub const DATA_DIR: &str = ".plug2proxy";

pub fn transparent_proxy_port_default() -> u16 {
    12345
}

pub fn fake_ip_dns_port_default() -> u16 {
    5353
}

pub fn fake_ipv4_net_default() -> ipnet::Ipv4Net {
    ipnet::Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 15).unwrap()
}

pub fn fake_ipv6_net_default() -> ipnet::Ipv6Net {
    ipnet::Ipv6Net::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32).unwrap()
}

pub fn stun_server_address_default() -> String {
    "stun.l.google.com:19302".to_string()
}

pub fn fake_ip_dns_db_path_default() -> PathBuf {
    Path::new(DATA_DIR).join("fake_ip_dns.db")
}

pub fn geolite2_cache_path_default() -> PathBuf {
    Path::new(DATA_DIR).join("geolite2.mmdb")
}

pub fn geolite2_url_default() -> String {
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb".to_string()
}

pub fn geolite2_update_interval_default() -> Duration {
    Duration::from_secs(24 * 60 * 60)
}

pub fn in_routing_rules_default() -> Vec<InRuleConfig> {
    vec![]
}
