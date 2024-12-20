mod config;
mod constants;

use std::sync::Arc;

use clap::Parser as _;
use config::{InConfig, OutConfig};
use constants::{
    dns_server_addresses_default, fake_ip_dns_db_path_default, fake_ipv4_net_default,
    fake_ipv6_net_default, geolite2_cache_path_default, geolite2_update_interval_default,
    stun_server_addresses_default, tunneling_http2_priority_default,
    tunneling_quic_priority_default, DATA_DIR_DEFAULT,
};
use plug2proxy::{
    out,
    r#in::{self, dns_resolver::create_dns_resolver},
    utils::{log::init_log, OneOrMany},
};
use tokio::fs;

#[derive(clap::Parser)]
struct Cli {
    config: String,
    #[clap(long)]
    data_dir: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(tag = "mode")]
enum Config {
    #[serde(rename = "in")]
    In(InConfig),
    #[serde(rename = "out")]
    Out(OutConfig),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_log();

    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let cli = Cli::parse();

    let config: Config = {
        let json = tokio::fs::read(&cli.config).await?;
        let json = json_comments::StripComments::new(json.as_slice());

        serde_json::from_reader(json)?
    };

    match config {
        Config::In(InConfig {
            dns_resolver,
            fake_ip_dns,
            transparent_proxy,
            tunneling,
            routing,
        }) => {
            fs::create_dir_all(DATA_DIR_DEFAULT).await?;

            let dns_resolver = Arc::new(create_dns_resolver(
                &dns_resolver
                    .server
                    .map_or_else(dns_server_addresses_default, |server| server.into_vec()),
            ));

            let fake_ip_dns_db_path = fake_ip_dns_db_path_default(cli.data_dir.as_deref());

            // ensure db file exists.
            drop(rusqlite::Connection::open(&fake_ip_dns_db_path));

            let geolite2_cache_path = geolite2_cache_path_default(cli.data_dir.as_deref());

            tokio::try_join!(
                r#in::fake_ip_dns::up(
                    dns_resolver.clone(),
                    r#in::fake_ip_dns::Options {
                        listen_address: fake_ip_dns.listen,
                        db_path: &fake_ip_dns_db_path
                    }
                ),
                r#in::transparent_proxy::up(
                    dns_resolver,
                    r#in::transparent_proxy::Options {
                        listen_address: transparent_proxy.listen,
                        traffic_mark: transparent_proxy.traffic_mark,
                        fake_ip_dns_db_path: &fake_ip_dns_db_path,
                        fake_ipv4_net: fake_ipv4_net_default(),
                        fake_ipv6_net: fake_ipv6_net_default(),
                        stun_server_addresses: tunneling
                            .stun_server
                            .map_or_else(stun_server_addresses_default, |address| address
                                .into_vec()),
                        match_server_config: tunneling.match_server.into_config(),
                        tunneling_http2_enabled: tunneling.http2.enabled,
                        tunneling_http2_connections: tunneling.http2.connections,
                        tunneling_http2_priority: tunneling.http2.priority,
                        tunneling_http2_priority_default: tunneling_http2_priority_default(),
                        tunneling_quic_enabled: tunneling.quic.enabled,
                        tunneling_quic_priority: tunneling.quic.priority,
                        tunneling_quic_priority_default: tunneling_quic_priority_default(),
                        routing_rules: routing.rules,
                        geolite2_cache_path: &geolite2_cache_path,
                        geolite2_url: routing.geolite2.url,
                        geolite2_update_interval: routing.geolite2.update_interval.map_or_else(
                            geolite2_update_interval_default,
                            |duration| {
                                humantime::parse_duration(&duration)
                                    .expect("invalid GeoLite2 database update interval.")
                            },
                        ),
                    }
                ),
            )?;
        }
        Config::Out(OutConfig {
            tunneling,
            routing,
            outputs,
        }) => {
            out::up(out::Options {
                labels: tunneling.label.map_or_else(Vec::new, OneOrMany::into_vec),
                tcp_priority: tunneling.http2.priority,
                udp_priority: tunneling.quic.priority,
                stun_server_addresses: tunneling
                    .stun_server
                    .map_or_else(stun_server_addresses_default, |address| address.into_vec()),
                match_server_config: tunneling.match_server.into_config(),
                routing_rules: routing.rules,
                routing_priority: routing.priority,
                output_configs: outputs,
            })
            .await?
        }
    }

    Ok(())
}
