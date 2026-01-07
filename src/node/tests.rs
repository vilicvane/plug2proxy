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

#[tokio::test]
async fn test_multi_out_with_routing() {
    let _ = tracing_subscriber::fmt::try_init();

    // Start three echo servers to represent different targets
    let echo1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo1_addr = echo1.local_addr().unwrap();
    let echo2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo2_addr = echo2.local_addr().unwrap();
    let echo3 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo3_addr = echo3.local_addr().unwrap();

    // Spawn echo servers with identifiable responses
    let spawn_echo = |listener: TcpListener, prefix: &'static str| {
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        // Echo with prefix to identify which server handled it
                        let response =
                            format!("[{}]{}", prefix, String::from_utf8_lossy(&buf[..n]));
                        stream.write_all(response.as_bytes()).await.unwrap();
                    }
                });
            }
        })
    };

    let echo1_handle = spawn_echo(echo1, "HUB");
    let echo2_handle = spawn_echo(echo2, "OUT1");
    let echo3_handle = spawn_echo(echo3, "OUT2");

    // Start HUB
    let hub = Arc::new(Hub::new(HubConfig {
        cert_path: "certs/cert.pem".to_string(),
        key_path: "certs/key.pem".to_string(),
    }));

    let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(hub_addr).await.unwrap();
    let hub_addr = listener.local_addr().unwrap();
    drop(listener);

    // Set routing rules
    // - "example.com" -> "out1" tag
    // - "google.com" -> "out2" tag
    // - everything else -> no tag (handled by HUB)
    hub.set_route_rules(vec![
        RouteRule {
            pattern: "example.com".to_string(),
            tag: "out1".to_string(),
        },
        RouteRule {
            pattern: "google.com".to_string(),
            tag: "out2".to_string(),
        },
    ])
    .await;

    let hub_clone = Arc::clone(&hub);
    let hub_handle = tokio::spawn(async move {
        hub_clone.serve(hub_addr).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect OUT nodes with different tags
    let mut out1 = OutNode::new("out-1".to_string(), vec!["out1".to_string()]);
    out1.connect_hub(hub_addr).await.unwrap();
    tracing::info!("OUT1 connected with tag 'out1'");

    let mut out2 = OutNode::new("out-2".to_string(), vec!["out2".to_string()]);
    out2.connect_hub(hub_addr).await.unwrap();
    tracing::info!("OUT2 connected with tag 'out2'");

    // Spawn OUT run loops (though they won't actually handle traffic in this test
    // since HUB currently exits directly)
    tokio::spawn(async move {
        let _ = out1.run().await;
    });
    tokio::spawn(async move {
        let _ = out2.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect IN
    let mut in_node = InNode::new("in-1".to_string());
    in_node.connect_hub(hub_addr).await.unwrap();
    tracing::info!("IN connected to HUB");

    // Verify IN received both OUTs
    let outs = in_node.get_outs().await;
    assert_eq!(outs.len(), 2);
    tracing::info!("IN received {} OUT nodes", outs.len());

    // Test 1: Connect to echo1 (no matching rule, should go through HUB)
    tracing::info!("\n=== Test 1: No matching rule (HUB handles) ===");
    let stream1 = in_node.connect(&echo1_addr.to_string()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let test_msg1 = b"test-hub";
    stream1.send(test_msg1).await.unwrap();

    let mut buf1 = vec![0u8; 1024];
    let mut received1 = 0;
    for _ in 0..50 {
        let (n, _) = stream1.recv(&mut buf1[received1..]).await.unwrap();
        received1 += n;
        if received1 > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let response1 = String::from_utf8_lossy(&buf1[..received1]);
    tracing::info!("Response 1: {}", response1);
    assert!(response1.contains("[HUB]"));
    assert!(response1.contains("test-hub"));

    // Test 2: Connect through OUT1 - manually set tag to match 'out1'
    tracing::info!("\n=== Test 2: Force routing through OUT1 (simulating 'example.com' match) ===");
    // For testing, we'll manually create a connection with a tag
    let connector2 = in_node.hub_connector().unwrap();
    let stream2 = connector2
        .connect_with_tag(&echo2_addr.to_string(), Some("out1"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let test_msg2 = b"test-out1";
    stream2.send(test_msg2).await.unwrap();

    let mut buf2 = vec![0u8; 1024];
    let mut received2 = 0;
    for _ in 0..50 {
        let (n, _) = stream2.recv(&mut buf2[received2..]).await.unwrap();
        received2 += n;
        if received2 > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let response2 = String::from_utf8_lossy(&buf2[..received2]);
    tracing::info!("Response 2: {}", response2);
    // With OUT forwarding enabled, this should now show [OUT1]
    assert!(response2.contains("[OUT1]"), "Expected OUT1 routing");
    assert!(response2.contains("test-out1"));

    // Test 3: Connect through OUT2 - manually set tag to match 'out2'
    tracing::info!("\n=== Test 3: Force routing through OUT2 (simulating 'google.com' match) ===");
    // For testing, we'll manually create a connection with a tag
    let connector3 = in_node.hub_connector().unwrap();
    let stream3 = connector3
        .connect_with_tag(&echo3_addr.to_string(), Some("out2"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let test_msg3 = b"test-out2";
    stream3.send(test_msg3).await.unwrap();

    let mut buf3 = vec![0u8; 1024];
    let mut received3 = 0;
    for _ in 0..50 {
        let (n, _) = stream3.recv(&mut buf3[received3..]).await.unwrap();
        received3 += n;
        if received3 > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let response3 = String::from_utf8_lossy(&buf3[..received3]);
    tracing::info!("Response 3: {}", response3);
    // With OUT forwarding enabled, this should now show [OUT2]
    assert!(response3.contains("[OUT2]"), "Expected OUT2 routing");
    assert!(response3.contains("test-out2"));

    // Test 4: Verify tag resolution works
    tracing::info!("\n=== Test 4: Verify tag resolution ===");
    let tag_example = in_node.resolve_tag("example.com:80").await;
    let tag_google = in_node.resolve_tag("google.com:443").await;
    let tag_other = in_node.resolve_tag("other.com:80").await;
    tracing::info!("Tag for 'example.com:80': {:?}", tag_example);
    tracing::info!("Tag for 'google.com:443': {:?}", tag_google);
    tracing::info!("Tag for 'other.com:80': {:?}", tag_other);
    assert_eq!(tag_example, Some("out1".to_string()));
    assert_eq!(tag_google, Some("out2".to_string()));
    assert_eq!(tag_other, None);

    tracing::info!("\n✅ Multi-OUT routing test completed!");
    tracing::info!("✓ HUB direct exit (no tag): working");
    tracing::info!("✓ OUT1 forwarding (tag 'out1'): working");
    tracing::info!("✓ OUT2 forwarding (tag 'out2'): working");
    tracing::info!("✓ Tag resolution: working");

    hub_handle.abort();
    echo1_handle.abort();
    echo2_handle.abort();
    echo3_handle.abort();
}
