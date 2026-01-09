use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use lits::duration;

use plug2proxy::cert::{generate_ca, generate_node_cert, load_ca_from_pem};
use plug2proxy::config::{Config, HubConfig, InConfig, OutConfig};
use plug2proxy::node::{Hub, InNode, OutNode};
use plug2proxy::socks5::Socks5Server;
use plug2proxy::tproxy::TProxyServer;

/// Conventional paths for certificates
const CA_PEM_PATH: &str = "ca.pem";
const HUB_PEM_PATH: &str = "hub.pem";
const NODE_PEM_PATH: &str = "node.pem";

#[derive(Parser, Debug)]
#[command(name = "plug2proxy")]
#[command(about = "QUIC-over-TCP proxy with SOCKS5 support", long_about = None)]
struct Args {
    /// Generate node certificate under <name>/ directory (for IN/OUT nodes)
    /// The node will use <name>/node.pem for authentication
    #[arg(long)]
    node_cert: Option<String>,
}

/// Conventional config file name.
const CONFIG_PATH: &str = "config.yaml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // If --node-cert is provided, just generate the certificate and exit
    if let Some(node_name) = args.node_cert {
        return generate_node_cert_for_distribution(&node_name);
    }

    let config = Config::from_file(CONFIG_PATH)?;

    if let Some(hub_config) = config.hub {
        run_hub(hub_config).await
    } else if let Some(out_config) = config.out {
        run_out(out_config).await
    } else if let Some(in_config) = config.in_config {
        run_in(in_config).await
    } else {
        anyhow::bail!("Config must specify one of: hub, out, or in")
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
        labels: config.label.clone().into_vec(),
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

async fn run_out(config: OutConfig) -> anyhow::Result<()> {
    let labels = config.label.clone().into_vec();
    let hub_addr = config.hub.address();
    tracing::info!("Starting OUT node with labels: {:?}", labels);
    tracing::info!("Connecting to HUB: {}", hub_addr);

    let connections = config.connections.unwrap_or(1);

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

    // Configure direct server for IN→OUT connections (if listen is set)
    let direct_server_config = config.listen.map(|_| plug2proxy::node::DirectServerConfig {
        pem_path: NODE_PEM_PATH.to_string(),
        ca_pem_path: Some(NODE_PEM_PATH.to_string()),
    });

    if let Some(addr) = config.listen {
        tracing::info!("Direct IN→OUT listener will be on: {}", addr);
    }

    // Auto-reconnect loop
    loop {
        let mut out = OutNode::new(labels.clone(), config.exits.clone(), client_config.clone());

        // Configure direct listener if enabled
        if let (Some(server_config), Some(listen_addr)) =
            (direct_server_config.clone(), config.listen)
        {
            out = out.with_direct_server(server_config, listen_addr);
        }

        match out.connect_hub(hub_addr, connections).await {
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

        tokio::time::sleep(duration!("5 seconds")).await;
    }
}

async fn run_in(config: InConfig) -> anyhow::Result<()> {
    let hub_addr = config.hub.address();
    tracing::info!("Starting IN node");
    tracing::info!("Connecting to HUB: {}", hub_addr);

    let connections = config.connections.unwrap_or(1);
    let direct_filter = config.direct.clone().into_vec();

    if !direct_filter.is_empty() {
        tracing::info!("Direct OUT filter: {:?}", direct_filter);
    }

    // Convention-based paths
    const GEOIP_DB_PATH: &str = "geolite2.mmdb";
    const FAKE_IP_DB_PATH: &str = "fakeip.db";

    // Load GeoLite2 database if exists (convention: geolite2.mmdb)
    let geolite2 = match plug2proxy::route::GeoLite2::open(GEOIP_DB_PATH) {
        Ok(db) => {
            tracing::info!("Loaded GeoIP database: {}", GEOIP_DB_PATH);
            Some(db)
        }
        Err(e) => {
            tracing::debug!("GeoIP database not available: {} ({})", GEOIP_DB_PATH, e);
            None
        }
    };

    // Start fake-ip DNS server and create resolver if configured
    let fake_ip_resolver = if let Some(ref fake_ip_config) = config.fake_ip {
        let listen_addr = fake_ip_config.listen();
        tracing::info!("Starting fake-ip DNS server on: {}", listen_addr);

        // Create resolver for upstream DNS queries
        let dns_resolver = Arc::new(hickory_resolver::TokioResolver::builder_tokio()?.build());
        let db_path = std::path::PathBuf::from(FAKE_IP_DB_PATH);

        tokio::spawn(async move {
            let options = plug2proxy::fake_ip::FakeIpDnsOptions {
                listen_address: listen_addr,
                db_path: &db_path,
            };
            if let Err(e) = plug2proxy::fake_ip::run_fake_ip_dns(dns_resolver, options).await {
                tracing::error!("Fake-IP DNS server error: {}", e);
            }
        });

        // Create fake IP resolver for SOCKS5 to translate fake IPs to hostnames
        Some(Arc::new(plug2proxy::fake_ip::FakeIpResolver::new(
            FAKE_IP_DB_PATH,
            plug2proxy::fake_ip::FAKE_IPV4_NET,
            plug2proxy::fake_ip::FAKE_IPV6_NET,
        )))
    } else {
        None
    };

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

    // Track spawned tasks to abort on reconnect
    let mut spawned_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Auto-reconnect loop
    loop {
        // Abort any previous tasks before starting new connection
        for handle in spawned_tasks.drain(..) {
            handle.abort();
        }

        let mut in_node = InNode::new(
            client_config.clone(),
            direct_filter.clone(),
            geolite2.clone(),
            config.mark,
        );

        match in_node.connect_hub(hub_addr, connections).await {
            Ok(()) => {
                let in_node = Arc::new(in_node);
                tracing::info!("✅ IN node connected and registered with HUB");

                // Channel to detect when message loop exits (HUB disconnect)
                let (disconnect_tx, disconnect_rx) = tokio::sync::oneshot::channel::<()>();

                // Spawn message loop to receive updates from HUB
                let in_node_clone = Arc::clone(&in_node);
                spawned_tasks.push(tokio::spawn(async move {
                    if let Err(e) = in_node_clone.run().await {
                        tracing::error!("IN node message loop error: {}", e);
                    }
                    // Signal disconnect
                    let _ = disconnect_tx.send(());
                }));

                // Spawn GeoIP updater task (uses convention path geolite2.mmdb)
                let in_node_clone = Arc::clone(&in_node);
                spawned_tasks.push(tokio::spawn(async move {
                    run_geoip_updater(in_node_clone, GEOIP_DB_PATH.to_string()).await;
                }));

                // Start TPROXY server if configured (Linux only)
                #[cfg(target_os = "linux")]
                if let Some(ref tproxy_config) = config.tproxy {
                    tracing::info!("Starting TPROXY server on: {}", tproxy_config.listen());

                    let mut tproxy =
                        TProxyServer::new(Arc::clone(&in_node), tproxy_config.listen());
                    if let Some(ref resolver) = fake_ip_resolver {
                        tproxy = tproxy.with_fake_ip_resolver(Arc::clone(resolver));
                    }

                    spawned_tasks.push(tokio::spawn(async move {
                        if let Err(e) = tproxy.run().await {
                            tracing::error!("TPROXY server error: {}", e);
                        }
                    }));
                }

                // Start SOCKS5 server if configured
                if let Some(ref socks5_config) = config.socks5 {
                    tracing::info!("Starting SOCKS5 server on: {}", socks5_config.listen());

                    let mut socks5 =
                        Socks5Server::new(Arc::clone(&in_node), socks5_config.listen());
                    if let Some(ref resolver) = fake_ip_resolver {
                        socks5 = socks5.with_fake_ip_resolver(Arc::clone(resolver));
                    }

                    // Run SOCKS5 server (blocks until error/disconnect)
                    if let Err(e) = socks5.run().await {
                        tracing::error!("SOCKS5 server error: {}", e);
                    }
                } else if config.tproxy.is_some() {
                    // TPROXY only mode - wait for HUB disconnect
                    let _ = disconnect_rx.await;
                } else {
                    tracing::warn!(
                        "No SOCKS5 or TPROXY config provided, IN node will only handle tunnel connections"
                    );
                    // Wait for HUB disconnect
                    let _ = disconnect_rx.await;
                }

                tracing::warn!("IN node disconnected, reconnecting in 5 seconds...");
            }
            Err(e) => {
                tracing::error!("Failed to connect to HUB: {}", e);
                tracing::info!("Retrying in 5 seconds...");
            }
        }

        tokio::time::sleep(duration!("5 seconds")).await;
    }
}

/// Run GeoIP database updater periodically.
async fn run_geoip_updater(in_node: Arc<InNode>, db_path: String) {
    use lits::duration;
    use plug2proxy::geoip_updater::GeoIpUpdater;

    const UPDATE_INTERVAL: std::time::Duration = duration!("24 hours");
    const INITIAL_DELAY: std::time::Duration = duration!("10 seconds");
    const RETRY_DELAY: std::time::Duration = duration!("10 seconds");

    tokio::time::sleep(INITIAL_DELAY).await;

    let updater = GeoIpUpdater::new(&db_path);

    loop {
        match updater.update(Some(Arc::clone(&in_node))).await {
            Ok(()) => {
                tracing::info!("GeoIP database update completed successfully");
                // Wait for next update cycle
                tokio::time::sleep(UPDATE_INTERVAL).await;
            }
            Err(e) => {
                tracing::warn!("GeoIP database update failed: {}", e);
                // Wait for next update cycle
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
}
