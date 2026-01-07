/// Example demonstrating SOCKS5 proxy with IN, HUB, and OUT nodes.
///
/// This sets up:
/// 1. A HUB node to coordinate routing
/// 2. An OUT node to exit traffic
/// 3. An IN node with SOCKS5 server
///
/// You can then configure your browser/app to use SOCKS5 proxy at 127.0.0.1:1080
use std::net::SocketAddr;
use std::sync::Arc;

use plug2proxy::node::{Hub, HubConfig, InNode, OutNode};
use plug2proxy::socks5::Socks5Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Configuration
    let hub_addr: SocketAddr = "127.0.0.1:8765".parse()?;
    let socks5_addr: SocketAddr = "127.0.0.1:1080".parse()?;

    println!("Starting plug2proxy with SOCKS5 interface...");
    println!("HUB:     {}", hub_addr);
    println!("SOCKS5:  {}", socks5_addr);
    println!();

    // Start HUB
    let hub = Arc::new(Hub::new(HubConfig {
        cert_path: "certs/cert.pem".to_string(),
        key_path: "certs/key.pem".to_string(),
    }));

    let hub_clone = Arc::clone(&hub);
    tokio::spawn(async move {
        if let Err(e) = hub_clone.serve(hub_addr).await {
            eprintln!("HUB error: {}", e);
        }
    });

    // Give HUB time to start
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    println!("✓ HUB started");

    // Start OUT node
    let mut out_node = OutNode::new("out1".to_string(), vec!["default".to_string()]);
    out_node.connect_hub(hub_addr, 1).await?;
    println!("✓ OUT node connected");

    tokio::spawn(async move {
        if let Err(e) = out_node.run().await {
            eprintln!("OUT node error: {}", e);
        }
    });

    // Start IN node
    let mut in_node = InNode::new("in1".to_string());
    in_node.connect_hub(hub_addr, 1).await?;
    println!("✓ IN node connected");

    // Spawn IN message loop
    let in_node_clone = Arc::new(in_node);
    let in_node_for_loop = Arc::clone(&in_node_clone);
    tokio::spawn(async move {
        if let Err(e) = in_node_for_loop.run().await {
            eprintln!("IN node error: {}", e);
        }
    });

    // Start SOCKS5 server
    let socks5_server = Socks5Server::new(Arc::clone(&in_node_clone), socks5_addr);
    println!("✓ SOCKS5 server starting on {}", socks5_addr);
    println!();
    println!("Proxy is ready! Configure your application to use:");
    println!("  SOCKS5 proxy: {}", socks5_addr);
    println!();
    println!("Press Ctrl+C to stop.");

    socks5_server.run().await?;

    Ok(())
}
