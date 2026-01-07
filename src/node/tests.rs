use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
    out.connect_hub(hub_addr).await.unwrap();
    tracing::info!("OUT connected");

    // Give HUB time to process OUT registration
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect IN
    let mut in_node = InNode::new("in-1".to_string());
    in_node.connect_hub(hub_addr).await.unwrap();
    tracing::info!("IN connected");

    // Verify IN received OUT info
    let outs = in_node.get_outs().await;
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0].id, "out-1");
    assert_eq!(outs[0].tags, vec!["direct"]);

    hub_handle.abort();
}

#[tokio::test]
async fn test_full_proxy_flow() {
    let _ = tracing_subscriber::fmt::try_init();

    // Start a simple echo server as the target
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    let echo_handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
    });

    // Start HUB
    let hub = Arc::new(Hub::new(HubConfig {
        cert_path: "certs/cert.pem".to_string(),
        key_path: "certs/key.pem".to_string(),
    }));

    let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(hub_addr).await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    drop(listener);

    let hub_clone = Arc::clone(&hub);
    let hub_handle = tokio::spawn(async move {
        hub_clone.serve(hub_addr).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect IN
    let mut in_node = InNode::new("in-1".to_string());
    in_node.connect_hub(hub_addr).await.unwrap();
    tracing::info!("IN connected to HUB");

    // Create proxied connection to echo server through HUB
    let stream = in_node.connect(&echo_addr.to_string()).await.unwrap();
    tracing::info!("proxied connection established");

    // Wait for relay to be set up on HUB side
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send data through the tunnel
    let test_data = b"Hello, proxy!";
    let n = stream.send(test_data).await.unwrap();
    tracing::info!("sent test data ({} bytes) on stream {}", n, stream.id());

    // Receive echoed data (with retry since QUIC stream recv is non-blocking)
    let mut buf = [0u8; 1024];
    let mut total_received = 0;
    for _ in 0..100 {
        let (n, fin) = stream.recv(&mut buf[total_received..]).await.unwrap();
        total_received += n;
        if total_received >= test_data.len() || fin {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tracing::info!("received {} bytes", total_received);

    assert_eq!(&buf[..total_received], test_data);
    tracing::info!("proxy flow test passed!");

    hub_handle.abort();
    echo_handle.abort();
}
