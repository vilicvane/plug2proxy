use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::*;

#[tokio::test]
async fn test_in_out_connect_to_hub() {
    let _ = tracing_subscriber::fmt::try_init();

    // Start HUB
    let hub = Arc::new(Hub::new(HubConfig {
        cert_path: "certs/cert.pem".to_string(),
        key_path: "certs/key.pem".to_string(),
    }));

    let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(hub_addr).await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    drop(listener);

    let hub_clone = Arc::clone(&hub);
    let hub_handle = tokio::spawn(async move {
        hub_clone.serve(hub_addr).await.unwrap();
    });

    // Give HUB time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect OUT first (so IN receives it in the initial update)
    let mut out = OutNode::new("out-1".to_string(), vec!["direct".to_string()]);
    out.connect(hub_addr).await.unwrap();
    tracing::info!("OUT connected");

    // Give HUB time to process OUT registration
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect IN
    let mut in_node = InNode::new("in-1".to_string());
    in_node.connect(hub_addr).await.unwrap();
    tracing::info!("IN connected");

    // Verify IN received OUT info
    let outs = in_node.get_outs().await;
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0].id, "out-1");
    assert_eq!(outs[0].tags, vec!["direct"]);

    hub_handle.abort();
}
