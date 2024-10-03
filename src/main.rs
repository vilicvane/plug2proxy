mod config;
mod constants;

use clap::Parser as _;
use config::{InConfig, OutConfig};
use constants::{
    fake_ip_dns_db_path_default, fake_ipv4_net_default, fake_ipv6_net_default, DATA_DIR,
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
        }) => {
            fs::create_dir_all(DATA_DIR).await?;

            let fake_ip_dns_db_path = fake_ip_dns_db_path_default();

            // ensure db file exists.
            drop(rusqlite::Connection::open(&fake_ip_dns_db_path));

            tokio::try_join!(
                r#in::transparent_proxy::up(r#in::transparent_proxy::Options {
                    listen_address: transparent_proxy.listen,
                    fake_ip_dns_db_path: fake_ip_dns_db_path.clone(),
                    fake_ipv4_net: fake_ipv4_net_default(),
                    fake_ipv6_net: fake_ipv6_net_default(),
                    stun_server_address: tunneling.stun_server,
                    match_server_config: tunneling.match_server.into_config()
                }),
                r#in::fake_ip_dns::up(r#in::fake_ip_dns::Options {
                    listen_address: fake_ip_dns.listen,
                    db_path: fake_ip_dns_db_path
                })
            )?;
        }
        Config::Out(OutConfig { tunneling }) => {
            out::up(out::Options {
                labels: tunneling.label.map_or_else(Vec::new, OneOrMany::into_vec),
                stun_server_address: tunneling.stun_server,
                match_server_config: tunneling.match_server.into_config(),
            })
            .await?
        }
    }

    Ok(())
}
