mod config;
mod constants;

use clap::Parser as _;
use config::{InConfig, OutConfig};
use constants::{
    fake_ip_dns_db_path_default, fake_ipv4_net_default, fake_ipv6_net_default,
    geolite2_cache_path_default, geolite2_update_interval_default, DATA_DIR,
};
use plug2proxy::{
    out, r#in,
    utils::{log::init_log, OneOrMany},
};
use tokio::fs;

#[derive(clap::Parser)]
struct Cli {
    #[clap(long, short)]
    config: String,
}

#[derive(serde::Deserialize)]
#[serde(tag = "role")]
enum Config {
    #[serde(rename = "in")]
    In(InConfig),
    #[serde(rename = "out")]
    Out(OutConfig),
}

#[tokio::main(flavor = "current_thread")]
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
            transparent_proxy,
            fake_ip_dns,
            tunneling,
            routing,
        }) => {
            fs::create_dir_all(DATA_DIR).await?;

            let fake_ip_dns_db_path = fake_ip_dns_db_path_default();

            // ensure db file exists.
            drop(rusqlite::Connection::open(&fake_ip_dns_db_path));

            let geolite2_cache_path = geolite2_cache_path_default();

            tokio::try_join!(
                r#in::transparent_proxy::up(r#in::transparent_proxy::Options {
                    listen_address: transparent_proxy.listen,
                    fake_ip_dns_db_path: &fake_ip_dns_db_path,
                    fake_ipv4_net: fake_ipv4_net_default(),
                    fake_ipv6_net: fake_ipv6_net_default(),
                    stun_server_address: tunneling.stun_server,
                    match_server_config: tunneling.match_server.into_config(),
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
                }),
                r#in::fake_ip_dns::up(r#in::fake_ip_dns::Options {
                    listen_address: fake_ip_dns.listen,
                    db_path: &fake_ip_dns_db_path
                })
            )?;
        }
        Config::Out(OutConfig { tunneling, routing }) => {
            out::up(out::Options {
                labels: tunneling.label.map_or_else(Vec::new, OneOrMany::into_vec),
                priority: tunneling.priority,
                stun_server_address: tunneling.stun_server,
                match_server_config: tunneling.match_server.into_config(),
                routing_rules: routing.rules,
            })
            .await?
        }
    }

    Ok(())
}
