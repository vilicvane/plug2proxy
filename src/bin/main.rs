use clap::Parser as _;
use plug2proxy::{client, server, utils::log::init_log};

#[derive(clap::Parser)]
struct Cli {
    #[clap(long, short)]
    config: String,
}

#[derive(serde::Deserialize)]
#[serde(tag = "role")]
enum Config {
    #[serde(rename = "server")]
    Server(server::Config),
    #[serde(rename = "client")]
    Client(client::Config),
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
        Config::Server(config) => server::up(config).await?,
        Config::Client(config) => client::up(config).await?,
    }

    Ok(())
}
