use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;

use plug2proxy::cert::{generate_ca, generate_node_cert, load_ca_from_pem};
use plug2proxy::config::{Config, HubConfig, InConfig, OutConfig};
use plug2proxy::node::{Hub, InNode, OutNode};
use plug2proxy::socks5::Socks5Server;

/// Conventional paths for certificates
const CA_PEM_PATH: &str = "ca.pem";
const HUB_PEM_PATH: &str = "hub.pem";
const NODE_PEM_PATH: &str = "node.pem";

#[derive(Parser, Debug)]
#[command(name = "plug2proxy")]
#[command(about = "QUIC-over-TCP proxy with SOCKS5 support", long_about = None)]
struct Args {
    /// Path to configuration file (default: config.yaml)
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Generate node certificate under <name>/ directory (for IN/OUT nodes)
    /// The node will use <name>/node.pem for authentication
    #[arg(long)]
    node_cert: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config = Config::from_file(&args.config)?;

    match config {
        Config::Hub(hub_config) => run_hub(hub_config).await,
        Config::Out(out_config) => run_out(out_config, args.node_cert).await,
        Config::In(in_config) => run_in(in_config, args.node_cert).await,
    }
}

/// Ensure CA and Hub certificates exist, generating if needed.
fn ensure_hub_certs() -> anyhow::Result<()> {
    let ca_path = Path::new(CA_PEM_PATH);
    let hub_path = Path::new(HUB_PEM_PATH);

    // Generate CA if it doesn't exist
    if !ca_path.exists() {
        tracing::info!("Generating CA certificate: {}", CA_PEM_PATH);
        let ca = generate_ca("plug2proxy-ca")?;
        ca.write_to_file(ca_path)?;
        tracing::info!("✅ CA certificate generated: {}", CA_PEM_PATH);
    }

    // Generate Hub cert if it doesn't exist
    if !hub_path.exists() {
        tracing::info!("Generating Hub certificate: {}", HUB_PEM_PATH);
        let (ca_cert_pem, ca_key_pem) = load_ca_from_pem(ca_path)?;
        let hub_cert = generate_node_cert("hub", &ca_cert_pem, &ca_key_pem, true)?;
        hub_cert.write_to_file(hub_path)?;
        tracing::info!("✅ Hub certificate generated: {}", HUB_PEM_PATH);
    }

    Ok(())
}

/// Generate node certificate and save to <name>/node.pem for distribution.
/// The generated file includes: node cert + node key + CA cert (for server verification).
fn generate_node_cert_for_distribution(node_name: &str) -> anyhow::Result<()> {
    let node_dir = PathBuf::from(node_name);
    let node_pem_path = node_dir.join("node.pem");
    let ca_path = Path::new(CA_PEM_PATH);

    // Check if CA exists (required for generating node cert)
    if !ca_path.exists() {
        anyhow::bail!(
            "CA certificate not found: {}\n\
            Run Hub first to generate CA, or copy ca.pem from Hub.",
            CA_PEM_PATH
        );
    }

    // Generate node cert if it doesn't exist
    if !node_pem_path.exists() {
        tracing::info!("Generating node certificate: {}", node_pem_path.display());

        // Create directory
        std::fs::create_dir_all(&node_dir)?;

        let (ca_cert_pem, ca_key_pem) = load_ca_from_pem(ca_path)?;
        let node_cert = generate_node_cert(node_name, &ca_cert_pem, &ca_key_pem, false)?;
        // Include CA cert in node.pem for server verification
        node_cert.write_to_file_with_ca(&node_pem_path, &ca_cert_pem)?;

        tracing::info!("✅ Node certificate generated: {}", node_pem_path.display());
        tracing::info!("   Copy this file to the node as 'node.pem'");
    }

    Ok(())
}

async fn run_hub(config: HubConfig) -> anyhow::Result<()> {
    tracing::info!("Starting HUB node");
    tracing::info!("Listening on: {}", config.listen);

    // Ensure certs exist (generate if needed)
    ensure_hub_certs()?;

    let hub_quic_config = plug2proxy::node::HubConfig {
        pem_path: HUB_PEM_PATH.to_string(),
        ca_pem_path: Some(CA_PEM_PATH.to_string()),
        tags: config.tags.clone(),
    };

    let hub = Arc::new(Hub::new(hub_quic_config));

    // Set routing rules
    if !config.routing.rules.is_empty() {
        tracing::info!("Loading {} routing rules", config.routing.rules.len());
        hub.set_route_rules(config.routing.rules.clone()).await;
    }

    hub.serve(config.listen).await?;

    tracing::info!("HUB node stopped");
    Ok(())
}

async fn run_out(config: OutConfig, node_cert: Option<String>) -> anyhow::Result<()> {
    tracing::info!("Starting OUT node with tags: {:?}", config.tags);
    tracing::info!("Connecting to HUB: {}", config.hub_addr);

    let connection_count = config.connection_count.unwrap_or(1);

    // If --node-cert is provided, generate cert for distribution
    if let Some(ref name) = node_cert {
        generate_node_cert_for_distribution(name)?;
    }

    // Use node.pem from cwd for connection (contains cert + key + CA cert)
    let node_pem_path = Path::new(NODE_PEM_PATH);
    let client_config = if node_pem_path.exists() {
        plug2proxy::node::ClientConfig {
            pem_path: Some(NODE_PEM_PATH.to_string()),
            // CA cert is included in node.pem, use same file for verification
            ca_pem_path: Some(NODE_PEM_PATH.to_string()),
        }
    } else {
        // No cert auth
        plug2proxy::node::ClientConfig {
            pem_path: None,
            ca_pem_path: None,
        }
    };

    // Auto-reconnect loop
    loop {
        let mut out = OutNode::new(
            config.tags.clone(),
            config.routing.rules.clone(),
            config.routing.priority,
            config.routing.outputs.clone(),
            client_config.clone(),
        );

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

async fn run_in(config: InConfig, node_cert: Option<String>) -> anyhow::Result<()> {
    tracing::info!("Starting IN node");
    tracing::info!("Connecting to HUB: {}", config.hub_addr);

    let connection_count = config.connection_count.unwrap_or(1);

    // If --node-cert is provided, generate cert for distribution
    if let Some(ref name) = node_cert {
        generate_node_cert_for_distribution(name)?;
    }

    // Use node.pem from cwd for connection (contains cert + key + CA cert)
    let node_pem_path = Path::new(NODE_PEM_PATH);
    let client_config = if node_pem_path.exists() {
        plug2proxy::node::ClientConfig {
            pem_path: Some(NODE_PEM_PATH.to_string()),
            // CA cert is included in node.pem, use same file for verification
            ca_pem_path: Some(NODE_PEM_PATH.to_string()),
        }
    } else {
        // No cert auth
        plug2proxy::node::ClientConfig {
            pem_path: None,
            ca_pem_path: None,
        }
    };

    // Auto-reconnect loop
    loop {
        let mut in_node = InNode::new(client_config.clone());

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
