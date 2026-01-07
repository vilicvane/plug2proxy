use clap::Parser;
use plug2proxy::config::{Config, HubConfig, InConfig, OutConfig};
use plug2proxy::node::{Hub, InNode, OutNode, RouteRule};
use plug2proxy::socks5::Socks5Server;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "plug2proxy")]
#[command(about = "QUIC-over-TCP proxy with SOCKS5 support", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config = Config::from_file(&args.config)?;

    match config {
        Config::Hub(hub_config) => run_hub(hub_config).await,
        Config::Out(out_config) => run_out(out_config).await,
        Config::In(in_config) => run_in(in_config).await,
    }
}

async fn run_hub(config: HubConfig) -> anyhow::Result<()> {
    tracing::info!("Starting HUB node: {}", config.id);
    tracing::info!("Listening on: {}", config.listen);

    let hub_quic_config = plug2proxy::node::HubConfig {
        cert_path: config.cert_path.clone(),
        key_path: config.key_path.clone(),
    };

    let hub = Arc::new(Hub::new(hub_quic_config));

    // Set routing rules
    if !config.routes.is_empty() {
        tracing::info!("Loading {} routing rules", config.routes.len());
        let rules: Vec<RouteRule> = config
            .routes
            .iter()
            .map(|r| RouteRule {
                pattern: r.pattern.clone(),
                tag: r.tag.clone(),
            })
            .collect();
        hub.set_route_rules(rules).await;
    }

    hub.serve(config.listen).await?;

    tracing::info!("HUB node stopped");
    Ok(())
}

async fn run_out(config: OutConfig) -> anyhow::Result<()> {
    tracing::info!("Starting OUT node: {}", config.id);
    tracing::info!("Tags: {:?}", config.tags);
    tracing::info!("Connecting to HUB: {}", config.hub_addr);

    let connection_count = config.connection_count.unwrap_or(1);

    // Auto-reconnect loop
    loop {
        let mut out = OutNode::new(config.id.clone(), config.tags.clone());

        match out.connect_hub(config.hub_addr, connection_count).await {
            Ok(()) => {
                tracing::info!("✅ OUT node connected and registered with HUB");

                // Run until disconnection
                if let Err(e) = out.run().await {
                    tracing::error!("OUT node error: {}", e);
                }

                tracing::warn!("OUT node disconnected, reconnecting in 5 seconds...");
            }
            Err(e) => {
                tracing::error!("Failed to connect to HUB: {}", e);
                tracing::info!("Retrying in 5 seconds...");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn run_in(config: InConfig) -> anyhow::Result<()> {
    tracing::info!("Starting IN node: {}", config.id);
    tracing::info!("Connecting to HUB: {}", config.hub_addr);

    let connection_count = config.connection_count.unwrap_or(1);

    // Auto-reconnect loop
    loop {
        let mut in_node = InNode::new(config.id.clone());

        match in_node.connect_hub(config.hub_addr, connection_count).await {
            Ok(()) => {
                let in_node = Arc::new(in_node);
                tracing::info!("✅ IN node connected and registered with HUB");

                // Start SOCKS5 server if configured
                if let Some(ref socks5_config) = config.socks5 {
                    tracing::info!("Starting SOCKS5 server on: {}", socks5_config.listen);

                    let socks5 = Socks5Server::new(Arc::clone(&in_node), socks5_config.listen);

                    // Spawn message loop to receive updates from HUB
                    let in_node_clone = Arc::clone(&in_node);
                    tokio::spawn(async move {
                        if let Err(e) = in_node_clone.run().await {
                            tracing::error!("IN node message loop error: {}", e);
                        }
                    });

                    // Run SOCKS5 server (blocks until HUB disconnects)
                    if let Err(e) = socks5.run().await {
                        tracing::error!("SOCKS5 server error: {}", e);
                    }

                    tracing::warn!("IN node disconnected, reconnecting in 5 seconds...");
                } else {
                    tracing::warn!(
                        "No SOCKS5 config provided, IN node will only handle tunnel connections"
                    );
                    if let Err(e) = in_node.run().await {
                        tracing::error!("IN node error: {}", e);
                    }

                    tracing::warn!("IN node disconnected, reconnecting in 5 seconds...");
                }
            }
            Err(e) => {
                tracing::error!("Failed to connect to HUB: {}", e);
                tracing::info!("Retrying in 5 seconds...");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
