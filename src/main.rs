use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use plug2proxy::cert::{generate_ca, generate_node_cert, load_ca_from_files};
use plug2proxy::config::{Config, HubConfig, InConfig, OutConfig};
use plug2proxy::node::{Hub, InNode, OutNode, RouteRule};
use plug2proxy::socks5::Socks5Server;

#[derive(Parser, Debug)]
#[command(name = "plug2proxy")]
#[command(about = "QUIC-over-TCP proxy with SOCKS5 support", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a node (HUB, IN, or OUT) based on config file
    Run {
        /// Path to configuration file
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Certificate management commands
    #[command(subcommand)]
    Cert(CertCommand),
}

#[derive(Subcommand, Debug)]
enum CertCommand {
    /// Generate a new CA certificate
    Ca {
        /// Common name for the CA certificate
        #[arg(short, long, default_value = "plug2proxy-ca")]
        name: String,

        /// Output directory for certificate files
        #[arg(short, long, default_value = "certs")]
        out: PathBuf,
    },

    /// Generate a node certificate (server or client)
    Node {
        /// Node name (used as common name in certificate)
        #[arg(short, long)]
        name: String,

        /// Path to CA certificate file
        #[arg(long, default_value = "certs/ca.crt")]
        ca_cert: PathBuf,

        /// Path to CA private key file
        #[arg(long, default_value = "certs/ca.key")]
        ca_key: PathBuf,

        /// Generate a server certificate (for HUB) instead of client certificate
        #[arg(long)]
        server: bool,

        /// Output directory for certificate files
        #[arg(short, long, default_value = "certs")]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Run { config } => {
            tracing_subscriber::fmt::init();
            let config = Config::from_file(&config)?;

            match config {
                Config::Hub(hub_config) => run_hub(hub_config).await,
                Config::Out(out_config) => run_out(out_config).await,
                Config::In(in_config) => run_in(in_config).await,
            }
        }
        Command::Cert(cert_cmd) => run_cert_command(cert_cmd),
    }
}

fn run_cert_command(cmd: CertCommand) -> anyhow::Result<()> {
    match cmd {
        CertCommand::Ca { name, out } => {
            // Create output directory if it doesn't exist
            std::fs::create_dir_all(&out)?;

            let cert = generate_ca(&name)?;

            let cert_path = out.join("ca.crt");
            let key_path = out.join("ca.key");

            cert.write_to_files(&cert_path, &key_path)?;

            println!("✅ CA certificate generated:");
            println!("   Certificate: {}", cert_path.display());
            println!("   Private key: {}", key_path.display());
            println!();
            println!("⚠️  Keep the CA private key secure! It's used to sign node certificates.");

            Ok(())
        }
        CertCommand::Node {
            name,
            ca_cert,
            ca_key,
            server,
            out,
        } => {
            // Load CA certificate and key
            let (ca_cert_pem, ca_key_pem) = load_ca_from_files(&ca_cert, &ca_key)?;

            // Create output directory if it doesn't exist
            std::fs::create_dir_all(&out)?;

            let cert = generate_node_cert(&name, &ca_cert_pem, &ca_key_pem, server)?;

            let cert_path = out.join(format!("{}.crt", name));
            let key_path = out.join(format!("{}.key", name));

            cert.write_to_files(&cert_path, &key_path)?;

            let cert_type = if server { "Server" } else { "Client" };
            println!("✅ {} certificate generated for '{}':", cert_type, name);
            println!("   Certificate: {}", cert_path.display());
            println!("   Private key: {}", key_path.display());

            if server {
                println!();
                println!("📝 Add to HUB config:");
                println!("   cert_path: \"{}\"", cert_path.display());
                println!("   key_path: \"{}\"", key_path.display());
                println!("   ca_cert_path: \"{}\"", ca_cert.display());
            } else {
                println!();
                println!("📝 Add to IN/OUT config:");
                println!("   cert_path: \"{}\"", cert_path.display());
                println!("   key_path: \"{}\"", key_path.display());
                println!("   ca_cert_path: \"{}\"", ca_cert.display());
            }

            Ok(())
        }
    }
}

async fn run_hub(config: HubConfig) -> anyhow::Result<()> {
    tracing::info!("Starting HUB node: {}", config.id);
    tracing::info!("Listening on: {}", config.listen);

    let hub_quic_config = plug2proxy::node::HubConfig {
        cert_path: config.cert_path.clone(),
        key_path: config.key_path.clone(),
        ca_cert_path: config.ca_cert_path.clone(),
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

    let client_config = plug2proxy::node::ClientConfig {
        cert_path: config.cert_path.clone(),
        key_path: config.key_path.clone(),
        ca_cert_path: config.ca_cert_path.clone(),
    };

    // Auto-reconnect loop
    loop {
        let mut out = OutNode::new(config.id.clone(), config.tags.clone(), client_config.clone());

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

    let client_config = plug2proxy::node::ClientConfig {
        cert_path: config.cert_path.clone(),
        key_path: config.key_path.clone(),
        ca_cert_path: config.ca_cert_path.clone(),
    };

    // Auto-reconnect loop
    loop {
        let mut in_node = InNode::new(config.id.clone(), client_config.clone());

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
