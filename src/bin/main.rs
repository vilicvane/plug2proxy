pub mod client;
pub mod server;

use clap::Parser as _;

#[derive(clap::Parser)]
struct Cli {
    #[clap(long, short)]
    config: String,
}

#[derive(serde::Deserialize)]
#[serde(tag = "role")]
enum Config {
    #[serde(rename = "server")]
    Server(server::config::Config),
    #[serde(rename = "client")]
    Client(client::config::Config),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config: Config = {
        let json = tokio::fs::read(&cli.config).await?;
        let json = json_comments::StripComments::new(json.as_slice());

        serde_json::from_reader(json)?
    };

    match config {
        Config::Server(config) => server::up::up(config).await?,
        Config::Client(config) => client::up::up(config).await?,
    }

    Ok(())
}
