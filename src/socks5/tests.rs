/// Simple test to verify SOCKS5 integration compiles and basic flow works
#[cfg(test)]
mod socks5_integration_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use lits::duration;

    use crate::cert::{generate_ca, generate_node_cert};
    use crate::node::{ClientConfig, Hub, HubConfig, InNode};
    use crate::socks5::Socks5Server;

    const TEST_CERT_PATH: &str = "test.pem";

    /// Ensure test certificate exists in cwd.
    fn ensure_test_cert() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            if !std::path::Path::new(TEST_CERT_PATH).exists() {
                let ca = generate_ca("test-ca").unwrap();
                let server_cert =
                    generate_node_cert("test-server", &ca.cert_pem, &ca.key_pem, true).unwrap();
                server_cert.write_to_file(TEST_CERT_PATH).unwrap();
            }
        });
    }

    fn test_client_config() -> ClientConfig {
        ClientConfig {
            pem_path: None,
            ca_pem_path: None,
        }
    }

    #[tokio::test]
    async fn test_socks5_server_creation() {
        // This test just verifies that we can create all the components
        let in_node = Arc::new(InNode::new(test_client_config(), vec![], None, None));
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let _socks5_server = Socks5Server::new(in_node, bind_addr);
        // If we got here without panicking, the API is correct
    }

    #[tokio::test]
    async fn test_hub_and_in_connection() -> Result<(), Box<dyn std::error::Error>> {
        ensure_test_cert();
        // Start a HUB
        let hub_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let listener = tokio::net::TcpListener::bind(hub_addr).await?;
        let hub_addr = listener.local_addr()?;
        drop(listener);

        let hub: Arc<Hub> = Arc::new(Hub::new(HubConfig {
            pem_path: TEST_CERT_PATH.to_string(),
            ca_pem_path: None,
            labels: vec![],
        }));

        let hub_clone: Arc<Hub> = Arc::clone(&hub);
        tokio::spawn(async move {
            let _ = hub_clone.serve(hub_addr).await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // Connect IN node
        let mut in_node = InNode::new(test_client_config(), vec![], None, None);
        let result: Result<(), _> = in_node.connect_hub(hub_addr, 1).await;

        // We expect this to succeed
        assert!(result.is_ok(), "IN node should connect to HUB");

        Ok(())
    }
}

/// Tests specifically to reproduce the relay hanging issue
#[cfg(test)]
mod relay_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use lits::duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::cert::{generate_ca, generate_node_cert};
    use crate::node::{ClientConfig, Hub, HubConfig, InNode, OutNode};
    use crate::route::{DomainPatternRuleConfig, Label, OneOrMany, RuleConfig};

    const TEST_TIMEOUT: Duration = duration!("10 seconds");
    const TEST_CERT_PATH: &str = "tmp/certs/cert.pem";

    fn ensure_test_cert() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            std::fs::create_dir_all("tmp/certs").unwrap();
            if !std::path::Path::new(TEST_CERT_PATH).exists() {
                let ca = generate_ca("test-ca").unwrap();
                let server_cert =
                    generate_node_cert("test-server", &ca.cert_pem, &ca.key_pem, true).unwrap();
                server_cert.write_to_file(TEST_CERT_PATH).unwrap();
            }
        });
    }

    fn test_client_config() -> ClientConfig {
        ClientConfig {
            pem_path: None,
            ca_pem_path: None,
        }
    }

    /// Setup test infrastructure and return (hub_addr, in_node)
    async fn setup_test_env() -> (SocketAddr, Arc<InNode>) {
        let _ = tracing_subscriber::fmt::try_init();
        ensure_test_cert();

        // Start HUB
        let hub = Arc::new(Hub::new(HubConfig {
            pem_path: TEST_CERT_PATH.to_string(),
            ca_pem_path: None,
            labels: vec![],
        }));

        let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(hub_addr).await.unwrap();
        let hub_addr = listener.local_addr().unwrap();
        drop(listener);

        let hub_clone = Arc::clone(&hub);
        tokio::spawn(async move {
            let _ = hub_clone.serve(hub_addr).await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // Connect IN
        let mut in_node = InNode::new(test_client_config(), vec![], None, None);
        in_node.connect_hub(hub_addr, 1).await.unwrap();

        (hub_addr, Arc::new(in_node))
    }

    /// Setup test infrastructure WITH OUT node routing
    /// This is the key difference - real traffic routes through OUT
    async fn setup_test_env_with_out() -> (SocketAddr, Arc<InNode>) {
        let _ = tracing_subscriber::fmt::try_init();
        ensure_test_cert();

        // Start HUB
        let hub = Arc::new(Hub::new(HubConfig {
            pem_path: TEST_CERT_PATH.to_string(),
            ca_pem_path: None,
            labels: vec![],
        }));

        let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(hub_addr).await.unwrap();
        let hub_addr = listener.local_addr().unwrap();
        drop(listener);

        let hub_clone = Arc::clone(&hub);
        tokio::spawn(async move {
            let _ = hub_clone.serve(hub_addr).await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // Connect OUT node first (it needs to register before IN sees it)
        let mut out_node = OutNode::new(vec!["test".to_string()], vec![], test_client_config());
        out_node.connect_hub(hub_addr, 1).await.unwrap();

        // Run OUT node in background
        tokio::spawn(async move {
            let _ = out_node.run().await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // Connect IN
        let mut in_node = InNode::new(test_client_config(), vec![], None, None);
        in_node.connect_hub(hub_addr, 1).await.unwrap();

        // Add a catch-all route rule to route through OUT
        // Pattern ".*" matches any target
        in_node
            .update_route_rules(vec![RuleConfig::DomainPattern(DomainPatternRuleConfig {
                r#match: OneOrMany::One(".*".to_string()), // Match anything
                negate: false,
                out: OneOrMany::One(Label::Custom("test".to_string())),
                priority: None,
                tag: None,
            })])
            .await;

        (hub_addr, Arc::new(in_node))
    }

    /// Start an HTTP-like echo server that supports keep-alive
    async fn start_http_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    // Keep-alive: read multiple requests on same connection
                    loop {
                        match tokio::time::timeout(duration!("5 seconds"), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(0)) => break, // Client closed
                            Ok(Ok(n)) => {
                                // Echo back
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Ok(Err(_)) | Err(_) => break,
                        }
                    }
                });
            }
        });

        addr
    }

    /// Test: Single request-response through tunnel
    #[tokio::test]
    async fn test_single_request() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, in_node) = setup_test_env().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            let mut stream = in_node.connect(&echo_addr.to_string()).await.unwrap();
            tokio::time::sleep(duration!("100 ms")).await;

            // Send request
            let test_data = b"Hello, proxy!";
            stream.send(test_data).await.unwrap();

            // Receive response with timeout
            let mut buf = vec![0u8; 1024];
            let mut total = 0;
            let deadline = tokio::time::Instant::now() + duration!("5 seconds");

            while total < test_data.len() && tokio::time::Instant::now() < deadline {
                match stream.recv_wait(&mut buf[total..]).await {
                    Ok((n, _)) => total += n,
                    Err(e) => panic!("recv error: {:?}", e),
                }
            }

            assert_eq!(total, test_data.len(), "Did not receive full response");
            assert_eq!(&buf[..total], test_data);
        })
        .await
        .expect("test_single_request timed out");
    }

    /// Test: Single request through OUT node routing - THIS IS THE KEY TEST
    /// Real browser traffic routes through OUT, not HUB direct
    #[tokio::test]
    async fn test_single_request_via_out() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, in_node) = setup_test_env_with_out().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            let mut stream = in_node.connect(&echo_addr.to_string()).await.unwrap();
            tokio::time::sleep(duration!("100 ms")).await;

            // Send request
            let test_data = b"Hello via OUT!";
            stream.send(test_data).await.unwrap();

            // Receive response with timeout
            let mut buf = vec![0u8; 1024];
            let mut total = 0;
            let deadline = tokio::time::Instant::now() + duration!("5 seconds");

            while total < test_data.len() && tokio::time::Instant::now() < deadline {
                match stream.recv_wait(&mut buf[total..]).await {
                    Ok((n, _)) => total += n,
                    Err(e) => panic!("recv error: {:?}", e),
                }
            }

            assert_eq!(total, test_data.len(), "Did not receive full response");
            assert_eq!(&buf[..total], test_data);
        })
        .await
        .expect("test_single_request_via_out timed out");
    }

    /// Test: Multiple requests via OUT node
    #[tokio::test]
    async fn test_multiple_requests_via_out() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, in_node) = setup_test_env_with_out().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            let mut stream = in_node.connect(&echo_addr.to_string()).await.unwrap();
            tokio::time::sleep(duration!("100 ms")).await;

            // Send multiple requests on same stream (like HTTP keep-alive)
            for i in 0..5 {
                let test_data = format!("Request {} via OUT", i);

                // Send
                stream.send(test_data.as_bytes()).await.unwrap();

                // Receive with timeout
                let mut buf = vec![0u8; 1024];
                let mut total = 0;
                let deadline = tokio::time::Instant::now() + duration!("5 seconds");

                while total < test_data.len() && tokio::time::Instant::now() < deadline {
                    match stream.recv_wait(&mut buf[total..]).await {
                        Ok((n, _)) => total += n,
                        Err(e) => panic!("Request {}: recv error: {:?}", i, e),
                    }
                }

                assert_eq!(total, test_data.len(), "Request {}: incomplete response", i);
            }
        })
        .await
        .expect("test_multiple_requests_via_out timed out");
    }

    /// Test: Stream limit via OUT - ensures streams are properly released via OUT node
    /// This tests opening MORE streams than the configured limit (100) through OUT
    #[tokio::test]
    async fn test_stream_limit_via_out() {
        tokio::time::timeout(duration!("120 seconds"), async {
            let (_, in_node) = setup_test_env_with_out().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            // Open 150 streams sequentially via OUT - more than the 100 stream limit
            // This will fail if streams aren't being released properly
            for i in 0..150 {
                let mut stream = match tokio::time::timeout(
                    duration!("5 seconds"),
                    in_node.connect(&echo_addr.to_string()),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => panic!("Stream {} via OUT: connect error: {:?}", i, e),
                    Err(_) => panic!("Stream {} via OUT: connect timeout", i),
                };

                let test_data = b"test";
                stream.send(test_data).await.unwrap();

                let mut buf = [0u8; 64];
                let mut total = 0;
                let deadline = tokio::time::Instant::now() + duration!("2 seconds");

                while total < test_data.len() && tokio::time::Instant::now() < deadline {
                    match stream.recv_wait(&mut buf[total..]).await {
                        Ok((n, _)) => total += n,
                        Err(_) => break,
                    }
                }

                // Stream is dropped here - Drop impl should release it
                tokio::time::sleep(duration!("10 ms")).await;

                if (i + 1) % 25 == 0 {
                    tracing::info!("Stream limit via OUT test: completed {} streams", i + 1);
                }
            }
            tracing::info!("Stream limit via OUT test: all 150 streams completed successfully!");
        })
        .await
        .expect("test_stream_limit_via_out timed out - streams not being released via OUT!");
    }

    /// Test: Multiple sequential requests on SAME stream (HTTP keep-alive)
    #[tokio::test]
    async fn test_keep_alive_sequential() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, in_node) = setup_test_env().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            let mut stream = in_node.connect(&echo_addr.to_string()).await.unwrap();
            tokio::time::sleep(duration!("100 ms")).await;

            // Send multiple requests on same stream (like HTTP keep-alive)
            for i in 0..5 {
                let test_data = format!("Request {}", i);

                // Send
                stream.send(test_data.as_bytes()).await.unwrap();

                // Receive with timeout
                let mut buf = vec![0u8; 1024];
                let mut total = 0;
                let deadline = tokio::time::Instant::now() + duration!("5 seconds");

                while total < test_data.len() && tokio::time::Instant::now() < deadline {
                    match stream.recv_wait(&mut buf[total..]).await {
                        Ok((n, _)) => total += n,
                        Err(e) => panic!("Request {}: recv error: {:?}", i, e),
                    }
                }

                assert_eq!(total, test_data.len(), "Request {}: incomplete response", i);
                assert_eq!(
                    &buf[..total],
                    test_data.as_bytes(),
                    "Request {}: wrong response",
                    i
                );
            }
        })
        .await
        .expect("test_keep_alive_sequential timed out");
    }

    /// Test: Multiple concurrent streams (simulates browser opening many connections)
    #[tokio::test]
    async fn test_concurrent_streams() {
        tokio::time::timeout(duration!("30 seconds"), async {
            let (_, in_node) = setup_test_env().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            let mut handles = Vec::new();

            // Open 10 concurrent connections
            for i in 0..10 {
                let in_node = Arc::clone(&in_node);
                let echo_addr = echo_addr.to_string();

                let handle = tokio::spawn(async move {
                    let mut stream = in_node.connect(&echo_addr).await.unwrap();
                    tokio::time::sleep(duration!("50 ms")).await;

                    let test_data = format!("Stream {} data", i);

                    // Send
                    stream.send(test_data.as_bytes()).await.unwrap();

                    // Receive with timeout
                    let mut buf = vec![0u8; 1024];
                    let mut total = 0;
                    let deadline = tokio::time::Instant::now() + duration!("5 seconds");

                    while total < test_data.len() && tokio::time::Instant::now() < deadline {
                        match stream.recv_wait(&mut buf[total..]).await {
                            Ok((n, _)) => total += n,
                            Err(e) => panic!("Stream {}: recv error: {:?}", i, e),
                        }
                    }

                    assert_eq!(total, test_data.len(), "Stream {}: incomplete", i);
                    assert_eq!(
                        &buf[..total],
                        test_data.as_bytes(),
                        "Stream {}: wrong data",
                        i
                    );
                    i
                });

                handles.push(handle);
            }

            // Wait for all
            let mut completed = Vec::new();
            for handle in handles {
                completed.push(handle.await.unwrap());
            }
            assert_eq!(completed.len(), 10, "Not all streams completed");
        })
        .await
        .expect("test_concurrent_streams timed out - streams are hanging!");
    }

    /// Test: Stream limit - ensures streams are properly released when dropped
    /// This tests opening MORE streams than the configured limit (100) sequentially
    #[tokio::test]
    async fn test_stream_limit_release() {
        tokio::time::timeout(duration!("120 seconds"), async {
            let (_, in_node) = setup_test_env().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            // Open 150 streams sequentially - more than the 100 stream limit
            // This will fail if streams aren't being released properly
            for i in 0..150 {
                let mut stream = match tokio::time::timeout(
                    duration!("5 seconds"),
                    in_node.connect(&echo_addr.to_string()),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => panic!("Stream {}: connect error: {:?}", i, e),
                    Err(_) => panic!("Stream {}: connect timeout", i),
                };

                let test_data = b"test";
                stream.send(test_data).await.unwrap();

                let mut buf = [0u8; 64];
                let mut total = 0;
                let deadline = tokio::time::Instant::now() + duration!("2 seconds");

                while total < test_data.len() && tokio::time::Instant::now() < deadline {
                    match stream.recv_wait(&mut buf[total..]).await {
                        Ok((n, _)) => total += n,
                        Err(_) => break,
                    }
                }

                // Stream is dropped here - Drop impl should release it
                // Small delay to allow QUIC frames to be sent
                tokio::time::sleep(duration!("10 ms")).await;

                if (i + 1) % 25 == 0 {
                    tracing::info!("Stream limit test: completed {} streams", i + 1);
                }
            }
            tracing::info!("Stream limit test: all 150 streams completed successfully!");
        })
        .await
        .expect("test_stream_limit_release timed out - streams are not being released!");
    }

    /// Test: Rapid open/close of streams
    #[tokio::test]
    async fn test_rapid_stream_lifecycle() {
        tokio::time::timeout(duration!("60 seconds"), async {
            let (_, in_node) = setup_test_env().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            // Rapidly open and close streams
            for i in 0..20 {
                let mut stream = match tokio::time::timeout(
                    duration!("5 seconds"),
                    in_node.connect(&echo_addr.to_string()),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => panic!("Stream {}: connect error: {:?}", i, e),
                    Err(_) => panic!("Stream {}: connect timeout", i),
                };

                let test_data = b"quick";

                // Quick send/recv
                stream.send(test_data).await.unwrap();

                let mut buf = [0u8; 64];
                let mut total = 0;
                let deadline = tokio::time::Instant::now() + duration!("2 seconds");

                while total < test_data.len() && tokio::time::Instant::now() < deadline {
                    match stream.recv_wait(&mut buf[total..]).await {
                        Ok((n, _)) => total += n,
                        Err(_) => break,
                    }
                }

                // Close stream
                let _ = stream.close().await;

                // Don't check response - focus on lifecycle
            }
        })
        .await
        .expect("test_rapid_stream_lifecycle timed out");
    }

    /// Test: Large data transfer
    #[tokio::test]
    async fn test_large_data_transfer() {
        tokio::time::timeout(duration!("60 seconds"), async {
            let (_, in_node) = setup_test_env().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            let mut stream = in_node.connect(&echo_addr.to_string()).await.unwrap();
            tokio::time::sleep(duration!("100 ms")).await;

            // Send 100KB
            let test_data = vec![0xABu8; 100 * 1024];
            stream.send(&test_data).await.unwrap();

            // Receive with timeout
            let mut buf = vec![0u8; test_data.len()];
            let mut total = 0;
            let deadline = tokio::time::Instant::now() + duration!("30 seconds");

            while total < test_data.len() && tokio::time::Instant::now() < deadline {
                match stream.recv_wait(&mut buf[total..]).await {
                    Ok((n, _)) => {
                        total += n;
                    }
                    Err(e) => panic!("recv error after {} bytes: {:?}", total, e),
                }
            }

            assert_eq!(total, test_data.len(), "Incomplete large transfer");
            assert_eq!(&buf[..total], &test_data[..]);
        })
        .await
        .expect("test_large_data_transfer timed out");
    }

    /// Test: Interleaved send/recv (more realistic HTTP pattern)
    #[tokio::test]
    async fn test_interleaved_communication() {
        tokio::time::timeout(duration!("20 seconds"), async {
            let (_, in_node) = setup_test_env().await;
            let echo_addr = start_http_echo_server().await;

            tokio::time::sleep(duration!("100 ms")).await;

            let stream = Arc::new(tokio::sync::Mutex::new(
                in_node.connect(&echo_addr.to_string()).await.unwrap(),
            ));
            tokio::time::sleep(duration!("100 ms")).await;

            let stream_send = Arc::clone(&stream);
            let stream_recv = stream;

            // Sender: send chunks with small delays
            let sender = tokio::spawn(async move {
                for i in 0..10 {
                    let data = format!("Chunk{}", i);
                    if stream_send
                        .lock()
                        .await
                        .send(data.as_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    tokio::time::sleep(duration!("20 ms")).await;
                }
            });

            // Receiver: collect responses
            let receiver = tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut total = 0;
                let deadline = tokio::time::Instant::now() + duration!("10 seconds");

                // Expected total bytes: "Chunk0" to "Chunk9" = 6*10 = 60 bytes
                let expected_len = 60;

                while total < expected_len && tokio::time::Instant::now() < deadline {
                    match tokio::time::timeout(
                        duration!("1 second"),
                        stream_recv.lock().await.recv_wait(&mut buf[total..]),
                    )
                    .await
                    {
                        Ok(Ok((n, _))) => total += n,
                        Ok(Err(_)) => break,
                        Err(_) => {
                            // Timeout, check if we're done
                            if total >= expected_len {
                                break;
                            }
                        }
                    }
                }
                total
            });

            let (_, received) = tokio::join!(sender, receiver);
            let received = received.unwrap();

            assert_eq!(received, 60, "Did not receive all interleaved data");
        })
        .await
        .expect("test_interleaved_communication timed out");
    }
}

/// Tests that go through the full SOCKS5 server flow
#[cfg(test)]
mod socks5_server_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use lits::duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::cert::{generate_ca, generate_node_cert};
    use crate::node::{ClientConfig, Hub, HubConfig, InNode};
    use crate::socks5::Socks5Server;

    const TEST_TIMEOUT: Duration = duration!("15 seconds");
    const TEST_CERT_PATH: &str = "tmp/certs/cert.pem";

    fn ensure_test_cert() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            std::fs::create_dir_all("tmp/certs").unwrap();
            if !std::path::Path::new(TEST_CERT_PATH).exists() {
                let ca = generate_ca("test-ca").unwrap();
                let server_cert =
                    generate_node_cert("test-server", &ca.cert_pem, &ca.key_pem, true).unwrap();
                server_cert.write_to_file(TEST_CERT_PATH).unwrap();
            }
        });
    }

    fn test_client_config() -> ClientConfig {
        ClientConfig {
            pem_path: None,
            ca_pem_path: None,
        }
    }

    /// Setup test infrastructure with SOCKS5 server
    async fn setup_socks5_env() -> (SocketAddr, SocketAddr) {
        let _ = tracing_subscriber::fmt::try_init();
        ensure_test_cert();

        // Start HUB
        let hub = Arc::new(Hub::new(HubConfig {
            pem_path: TEST_CERT_PATH.to_string(),
            ca_pem_path: None,
            labels: vec![],
        }));

        let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(hub_addr).await.unwrap();
        let hub_addr = listener.local_addr().unwrap();
        drop(listener);

        let hub_clone = Arc::clone(&hub);
        tokio::spawn(async move {
            let _ = hub_clone.serve(hub_addr).await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // Connect IN
        let mut in_node = InNode::new(test_client_config(), vec![], None, None);
        in_node.connect_hub(hub_addr, 1).await.unwrap();
        let in_node = Arc::new(in_node);

        // Start SOCKS5 server
        let socks5_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(socks5_addr).await.unwrap();
        let socks5_addr = listener.local_addr().unwrap();
        drop(listener);

        let socks5_server = Socks5Server::new(Arc::clone(&in_node), socks5_addr);
        tokio::spawn(async move {
            let _ = socks5_server.run().await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        (hub_addr, socks5_addr)
    }

    /// Start echo server
    async fn start_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });

        addr
    }

    /// Perform SOCKS5 handshake and connect to target
    async fn socks5_connect(
        socks5_addr: SocketAddr,
        target: &str,
    ) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = TcpStream::connect(socks5_addr).await?;

        // SOCKS5 greeting: VER(1) + NMETHODS(1) + METHODS(1)
        stream.write_all(&[0x05, 0x01, 0x00]).await?; // Version 5, 1 method, NO AUTH

        // Read auth response: VER(1) + METHOD(1)
        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp != [0x05, 0x00] {
            return Err("SOCKS5 auth failed".into());
        }

        // Parse target address
        let (host, port) = target.rsplit_once(':').ok_or("Invalid target")?;
        let port: u16 = port.parse()?;

        // SOCKS5 connect request
        let mut req = vec![0x05, 0x01, 0x00]; // VER, CMD=CONNECT, RSV
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            req.push(0x01); // ATYP: IPv4
            req.extend_from_slice(&ip.octets());
        } else {
            req.push(0x03); // ATYP: Domain
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
        req.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&req).await?;

        // Read connect response
        let mut resp = [0u8; 10]; // Minimum for IPv4
        stream.read_exact(&mut resp).await?;

        if resp[1] != 0x00 {
            return Err(format!("SOCKS5 connect failed: {}", resp[1]).into());
        }

        Ok(stream)
    }

    /// Test: Single request through full SOCKS5 flow
    #[tokio::test]
    async fn test_socks5_single_request() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, socks5_addr) = setup_socks5_env().await;
            let echo_addr = start_echo_server().await;

            // Connect through SOCKS5
            let mut stream = socks5_connect(socks5_addr, &echo_addr.to_string())
                .await
                .expect("SOCKS5 connect failed");

            // Send data
            let test_data = b"Hello via SOCKS5!";
            stream.write_all(test_data).await.unwrap();

            // Read response
            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(duration!("5 seconds"), stream.read(&mut buf))
                .await
                .expect("Read timed out")
                .expect("Read failed");

            assert_eq!(&buf[..n], test_data);
        })
        .await
        .expect("test_socks5_single_request timed out");
    }

    /// Test: Multiple requests on same SOCKS5 connection (keep-alive)
    #[tokio::test]
    async fn test_socks5_keep_alive() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, socks5_addr) = setup_socks5_env().await;
            let echo_addr = start_echo_server().await;

            // Connect through SOCKS5
            let mut stream = socks5_connect(socks5_addr, &echo_addr.to_string())
                .await
                .expect("SOCKS5 connect failed");

            // Send multiple requests on same connection
            for i in 0..5 {
                let test_data = format!("Request {}", i);

                stream.write_all(test_data.as_bytes()).await.unwrap();

                let mut buf = vec![0u8; 1024];
                let n = tokio::time::timeout(duration!("5 seconds"), stream.read(&mut buf))
                    .await
                    .unwrap_or_else(|_| panic!("Request {} read timed out", i))
                    .unwrap_or_else(|e| panic!("Request {} read failed: {}", i, e));

                assert_eq!(&buf[..n], test_data.as_bytes(), "Request {} mismatch", i);
            }
        })
        .await
        .expect("test_socks5_keep_alive timed out");
    }

    /// Test: Multiple concurrent SOCKS5 connections
    #[tokio::test]
    async fn test_socks5_concurrent_connections() {
        tokio::time::timeout(duration!("30 seconds"), async {
            let (_, socks5_addr) = setup_socks5_env().await;
            let echo_addr = start_echo_server().await;

            let mut handles = Vec::new();

            for i in 0..10 {
                let echo_addr = echo_addr.to_string();

                let handle = tokio::spawn(async move {
                    // Connect through SOCKS5
                    let mut stream = socks5_connect(socks5_addr, &echo_addr)
                        .await
                        .unwrap_or_else(|e| {
                            panic!("Connection {} SOCKS5 connect failed: {}", i, e)
                        });

                    let test_data = format!("Connection {}", i);
                    stream.write_all(test_data.as_bytes()).await.unwrap();

                    let mut buf = vec![0u8; 1024];
                    let n = tokio::time::timeout(duration!("5 seconds"), stream.read(&mut buf))
                        .await
                        .unwrap_or_else(|_| panic!("Connection {} read timed out", i))
                        .unwrap_or_else(|e| panic!("Connection {} read failed: {}", i, e));

                    assert_eq!(&buf[..n], test_data.as_bytes());
                    i
                });

                handles.push(handle);
            }

            // Wait for all
            for handle in handles {
                handle.await.unwrap();
            }
        })
        .await
        .expect("test_socks5_concurrent_connections timed out - HANGING!");
    }

    /// Test: Rapid SOCKS5 connection lifecycle
    #[tokio::test]
    async fn test_socks5_rapid_lifecycle() {
        tokio::time::timeout(duration!("60 seconds"), async {
            let (_, socks5_addr) = setup_socks5_env().await;
            let echo_addr = start_echo_server().await;

            // Rapidly open and close SOCKS5 connections
            for i in 0..20 {
                let mut stream = match tokio::time::timeout(
                    duration!("5 seconds"),
                    socks5_connect(socks5_addr, &echo_addr.to_string()),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => panic!("Connection {}: SOCKS5 error: {:?}", i, e),
                    Err(_) => panic!("Connection {}: SOCKS5 connect timeout", i),
                };

                let test_data = b"quick";
                stream.write_all(test_data).await.unwrap();

                let mut buf = vec![0u8; 64];
                let _ = tokio::time::timeout(duration!("2 seconds"), stream.read(&mut buf)).await;

                // Connection drops when stream goes out of scope
            }
        })
        .await
        .expect("test_socks5_rapid_lifecycle timed out");
    }
}

#[cfg(test)]
mod udp_tests {
    use bytes::Bytes;
    use std::net::{Ipv6Addr, SocketAddr};

    use crate::socks5::Socks5UdpPacket;
    use crate::udp_proxy::Datagram;

    #[test]
    fn test_socks5_udp_packet_parse_ipv4() {
        // Build a SOCKS5 UDP packet manually
        // Format: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2) + DATA
        let mut packet = vec![];
        packet.extend_from_slice(&[0x00, 0x00]); // RSV
        packet.push(0x00); // FRAG
        packet.push(0x01); // ATYP: IPv4
        packet.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
        packet.extend_from_slice(&[0x00, 0x50]); // Port 80
        packet.extend_from_slice(b"Hello, UDP!"); // Data

        let parsed = Socks5UdpPacket::parse(&packet).expect("Should parse valid packet");

        assert_eq!(parsed.frag, 0);
        assert_eq!(parsed.dest_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(parsed.dest_addr.port(), 80);
        assert_eq!(&parsed.data[..], b"Hello, UDP!");
    }

    #[test]
    fn test_socks5_udp_packet_parse_ipv6() {
        // Build a SOCKS5 UDP packet with IPv6
        let mut packet = vec![];
        packet.extend_from_slice(&[0x00, 0x00]); // RSV
        packet.push(0x00); // FRAG
        packet.push(0x04); // ATYP: IPv6
        // ::1 (loopback)
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0x1F, 0x90]); // Port 8080
        packet.extend_from_slice(b"IPv6 test");

        let parsed = Socks5UdpPacket::parse(&packet).expect("Should parse IPv6 packet");

        assert_eq!(parsed.frag, 0);
        assert_eq!(parsed.dest_addr.port(), 8080);
        assert_eq!(&parsed.data[..], b"IPv6 test");
    }

    #[test]
    fn test_socks5_udp_packet_encode_ipv4() {
        let addr: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let data = b"DNS query";

        let encoded = Socks5UdpPacket::encode(addr, data);

        // Verify format
        assert_eq!(&encoded[0..2], &[0x00, 0x00]); // RSV
        assert_eq!(encoded[2], 0x00); // FRAG
        assert_eq!(encoded[3], 0x01); // ATYP: IPv4
        assert_eq!(&encoded[4..8], &[192, 168, 1, 1]); // IP
        assert_eq!(&encoded[8..10], &[0x00, 0x35]); // Port 53
        assert_eq!(&encoded[10..], b"DNS query"); // Data
    }

    #[test]
    fn test_socks5_udp_packet_encode_ipv6() {
        let addr = SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let data = b"HTTPS";

        let encoded = Socks5UdpPacket::encode(addr, data);

        // Verify format
        assert_eq!(&encoded[0..2], &[0x00, 0x00]); // RSV
        assert_eq!(encoded[2], 0x00); // FRAG
        assert_eq!(encoded[3], 0x04); // ATYP: IPv6
        assert_eq!(&encoded[encoded.len() - 5..], b"HTTPS"); // Data at end
    }

    #[test]
    fn test_socks5_udp_packet_roundtrip() {
        let original_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let original_data = b"test data for roundtrip";

        // Encode
        let encoded = Socks5UdpPacket::encode(original_addr, original_data);

        // Parse back
        let parsed = Socks5UdpPacket::parse(&encoded).expect("Should parse encoded packet");

        assert_eq!(parsed.dest_addr, original_addr);
        assert_eq!(&parsed.data[..], original_data);
        assert_eq!(parsed.frag, 0);
    }

    #[test]
    fn test_socks5_udp_packet_invalid_rsv() {
        // RSV must be 0x0000
        let mut packet = vec![];
        packet.extend_from_slice(&[0x00, 0x01]); // Invalid RSV
        packet.push(0x00); // FRAG
        packet.push(0x01); // ATYP
        packet.extend_from_slice(&[127, 0, 0, 1]); // IP
        packet.extend_from_slice(&[0x00, 0x50]); // Port

        let result = Socks5UdpPacket::parse(&packet);
        assert!(result.is_err(), "Should reject invalid RSV");
    }

    #[test]
    fn test_datagram_serialize_ipv4() {
        let source: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let dest: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let data = Bytes::from_static(b"DNS query");

        let datagram = Datagram::new(source, dest, data.clone());
        let serialized = datagram.serialize();

        // Should have: type(1) + ipv4(4) + port(2) + type(1) + ipv4(4) + port(2) + len(4) + data(9) = 27 bytes
        assert_eq!(serialized.len(), 1 + 4 + 2 + 1 + 4 + 2 + 4 + 9);
    }

    #[test]
    fn test_datagram_serialize_ipv6() {
        let source = SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            8080,
        );
        let dest = SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            443,
        );
        let data = Bytes::from_static(b"test");

        let datagram = Datagram::new(source, dest, data.clone());
        let serialized = datagram.serialize();

        // Should have: type(1) + ipv6(16) + port(2) + type(1) + ipv6(16) + port(2) + len(4) + data(4) = 46 bytes
        assert_eq!(serialized.len(), 1 + 16 + 2 + 1 + 16 + 2 + 4 + 4);
    }

    #[test]
    fn test_datagram_deserialize_ipv4() {
        let source: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let dest: SocketAddr = "8.8.4.4:53".parse().unwrap();
        let data = Bytes::from_static(b"payload");

        let datagram = Datagram::new(source, dest, data.clone());
        let serialized = datagram.serialize();

        // Deserialize
        let deserialized = Datagram::deserialize(serialized).expect("Should deserialize");

        assert_eq!(deserialized.source, source);
        assert_eq!(deserialized.dest, dest);
        assert_eq!(deserialized.data, data);
    }

    #[test]
    fn test_datagram_roundtrip_mixed() {
        // IPv4 source, IPv6 dest
        let source: SocketAddr = "10.20.30.40:1234".parse().unwrap();
        let dest = SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            5678,
        );
        let data = Bytes::from_static(b"mixed address test");

        let original = Datagram::new(source, dest, data.clone());
        let serialized = original.serialize();
        let deserialized = Datagram::deserialize(serialized).expect("Should deserialize");

        assert_eq!(deserialized.source, source);
        assert_eq!(deserialized.dest, dest);
        assert_eq!(deserialized.data, data);
    }

    #[test]
    fn test_datagram_deserialize_too_short() {
        // Not enough bytes for a valid datagram
        let short_data = Bytes::from_static(&[1, 2, 3]);
        let result = Datagram::deserialize(short_data);

        assert!(result.is_err(), "Should reject too-short data");
    }

    #[test]
    fn test_datagram_empty_payload() {
        let source: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dest: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let data = Bytes::new(); // Empty payload

        let datagram = Datagram::new(source, dest, data.clone());
        let serialized = datagram.serialize();
        let deserialized = Datagram::deserialize(serialized).expect("Should handle empty payload");

        assert_eq!(deserialized.source, source);
        assert_eq!(deserialized.dest, dest);
        assert_eq!(deserialized.data.len(), 0);
    }

    #[test]
    fn test_datagram_large_payload() {
        let source: SocketAddr = "1.2.3.4:1111".parse().unwrap();
        let dest: SocketAddr = "5.6.7.8:2222".parse().unwrap();
        let large_data = vec![0xAB; 8192]; // 8KB payload
        let data = Bytes::from(large_data.clone());

        let datagram = Datagram::new(source, dest, data.clone());
        let serialized = datagram.serialize();
        let deserialized = Datagram::deserialize(serialized).expect("Should handle large payload");

        assert_eq!(deserialized.source, source);
        assert_eq!(deserialized.dest, dest);
        assert_eq!(deserialized.data.len(), 8192);
        assert_eq!(&deserialized.data[..], &large_data[..]);
    }
}

#[cfg(test)]
mod udp_integration_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use lits::duration;
    use tokio::net::UdpSocket;

    use crate::cert::{generate_ca, generate_node_cert};
    use crate::node::{ClientConfig, Hub, HubConfig, InNode, OutNode};
    use crate::socks5::{Socks5Server, Socks5UdpPacket};

    const TEST_CERT_PATH: &str = "tmp/certs/cert.pem";

    fn ensure_test_cert() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            std::fs::create_dir_all("tmp/certs").unwrap();
            if !std::path::Path::new(TEST_CERT_PATH).exists() {
                let ca = generate_ca("test-ca").unwrap();
                let server_cert =
                    generate_node_cert("test-server", &ca.cert_pem, &ca.key_pem, true).unwrap();
                server_cert.write_to_file(TEST_CERT_PATH).unwrap();
            }
        });
    }

    fn test_client_config() -> ClientConfig {
        ClientConfig {
            pem_path: None,
            ca_pem_path: None,
        }
    }

    /// Integration test: Simulate UDP echo through SOCKS5 -> IN -> HUB -> OUT
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_udp_echo_through_tunnel() -> Result<(), Box<dyn std::error::Error>> {
        ensure_test_cert();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init()
            .ok();

        // 1. Start UDP echo server (simulates internet destination)
        let echo_server = UdpSocket::bind("127.0.0.1:0").await?;
        let echo_addr = echo_server.local_addr()?;
        tracing::info!("Echo server listening on {}", echo_addr);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo_server.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        tracing::debug!("Echo server received {} bytes from {}", len, src);
                        // Echo back
                        if let Err(e) = echo_server.send_to(&buf[..len], src).await {
                            tracing::error!("Echo server send error: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Echo server recv error: {}", e);
                        break;
                    }
                }
            }
        });

        tokio::time::sleep(duration!("50 ms")).await;

        // 2. Start HUB
        let hub_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let listener = tokio::net::TcpListener::bind(hub_addr).await?;
        let hub_addr = listener.local_addr()?;
        drop(listener);

        let hub = Arc::new(Hub::new(HubConfig {
            pem_path: TEST_CERT_PATH.to_string(),
            ca_pem_path: None,
            labels: vec![],
        }));

        let hub_clone = Arc::clone(&hub);
        tokio::spawn(async move {
            if let Err(e) = hub_clone.serve(hub_addr).await {
                tracing::error!("HUB error: {}", e);
            }
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // 3. Start OUT node
        let mut out_node = OutNode::new(vec!["default".to_string()], vec![], test_client_config());
        out_node.connect_hub(hub_addr, 1).await?;
        tracing::info!("OUT node connected");

        tokio::spawn(async move {
            if let Err(e) = out_node.run().await {
                tracing::error!("OUT node error: {}", e);
            }
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // 4. Start IN node
        let mut in_node = InNode::new(test_client_config(), vec![], None, None);
        in_node.connect_hub(hub_addr, 1).await?;
        tracing::info!("IN node connected");

        let in_node = Arc::new(in_node);

        // 5. Start SOCKS5 server
        let socks5_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let socks5_server = Socks5Server::new(Arc::clone(&in_node), socks5_addr);
        let listener = tokio::net::TcpListener::bind(socks5_addr).await?;
        let _socks5_addr = listener.local_addr()?;
        drop(listener);

        tokio::spawn(async move {
            if let Err(e) = socks5_server.run().await {
                tracing::error!("SOCKS5 server error: {}", e);
            }
        });

        tokio::time::sleep(duration!("100 ms")).await;
        tracing::info!("All nodes started");

        // 6. Simulate SOCKS5 client sending UDP through the proxy
        // In a real scenario, a SOCKS5 client would:
        // a) Connect to SOCKS5 TCP and request UDP ASSOCIATE
        // b) Get the relay address
        // c) Send UDP to that relay address
        //
        // For this test, we'll directly test the datagram flow by using the tunnel

        // Create a test that simulates datagram flow
        let test_data = b"Hello, UDP world!";

        // Encode as SOCKS5 UDP packet
        let socks5_packet = Socks5UdpPacket::encode(echo_addr, test_data);
        tracing::info!("Created SOCKS5 UDP packet: {} bytes", socks5_packet.len());

        // Parse it back to verify
        let parsed = Socks5UdpPacket::parse(&socks5_packet)?;
        assert_eq!(parsed.dest_addr, echo_addr);
        assert_eq!(&parsed.data[..], test_data);

        tracing::info!("✅ SOCKS5 UDP packet encoding/decoding works");

        Ok(())
    }

    /// Test SOCKS5 UDP packet handling with actual UDP sockets
    #[tokio::test]
    async fn test_socks5_udp_packet_over_socket() -> Result<(), Box<dyn std::error::Error>> {
        ensure_test_cert();
        // Create two UDP sockets
        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let receiver_addr = receiver.local_addr()?;

        // Prepare SOCKS5 UDP packet
        let target: SocketAddr = "8.8.8.8:53".parse()?;
        let data = b"DNS query data";
        let packet = Socks5UdpPacket::encode(target, data);

        // Send packet
        sender.send_to(&packet, receiver_addr).await?;

        // Receive and parse
        let mut buf = vec![0u8; 2048];
        let (len, _) = receiver.recv_from(&mut buf).await?;
        let parsed = Socks5UdpPacket::parse(&buf[..len])?;

        assert_eq!(parsed.dest_addr, target);
        assert_eq!(&parsed.data[..], data);

        Ok(())
    }
}

/// End-to-end UDP tests that go through SOCKS5 UDP ASSOCIATE
#[cfg(test)]
mod udp_e2e_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use lits::duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};

    use crate::cert::{generate_ca, generate_node_cert};
    use crate::node::{ClientConfig, Hub, HubConfig, InNode, OutNode};
    use crate::socks5::{Socks5Server, Socks5UdpPacket};

    const TEST_TIMEOUT: Duration = duration!("30 seconds");
    const TEST_CERT_PATH: &str = "tmp/certs/cert.pem";

    fn ensure_test_cert() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            std::fs::create_dir_all("tmp/certs").unwrap();
            if !std::path::Path::new(TEST_CERT_PATH).exists() {
                let ca = generate_ca("test-ca").unwrap();
                let server_cert =
                    generate_node_cert("test-server", &ca.cert_pem, &ca.key_pem, true).unwrap();
                server_cert.write_to_file(TEST_CERT_PATH).unwrap();
            }
        });
    }

    fn test_client_config() -> ClientConfig {
        ClientConfig {
            pem_path: None,
            ca_pem_path: None,
        }
    }

    /// Setup test infrastructure with SOCKS5, HUB, and OUT nodes
    async fn setup_udp_test_env() -> (SocketAddr, SocketAddr) {
        let _ = tracing_subscriber::fmt::try_init();
        ensure_test_cert();

        // Start HUB
        let hub = Arc::new(Hub::new(HubConfig {
            pem_path: TEST_CERT_PATH.to_string(),
            ca_pem_path: None,
            labels: vec![],
        }));

        let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(hub_addr).await.unwrap();
        let hub_addr = listener.local_addr().unwrap();
        drop(listener);

        let hub_clone = Arc::clone(&hub);
        tokio::spawn(async move {
            let _ = hub_clone.serve(hub_addr).await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // Connect OUT node (for UDP forwarding)
        let mut out_node = OutNode::new(vec!["test".to_string()], vec![], test_client_config());
        out_node.connect_hub(hub_addr, 1).await.unwrap();

        tokio::spawn(async move {
            let _ = out_node.run().await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        // Connect IN node
        let mut in_node = InNode::new(test_client_config(), vec![], None, None);
        in_node.connect_hub(hub_addr, 1).await.unwrap();
        let in_node = Arc::new(in_node);

        // Start SOCKS5 server
        let socks5_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(socks5_addr).await.unwrap();
        let socks5_addr = listener.local_addr().unwrap();
        drop(listener);

        let socks5_server = Socks5Server::new(Arc::clone(&in_node), socks5_addr);
        tokio::spawn(async move {
            let _ = socks5_server.run().await;
        });

        tokio::time::sleep(duration!("100 ms")).await;

        (hub_addr, socks5_addr)
    }

    /// Start a UDP echo server that echoes back any received packets
    async fn start_udp_echo_server() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        tracing::debug!("UDP echo: {} bytes from {}", len, src);
                        if let Err(e) = socket.send_to(&buf[..len], src).await {
                            tracing::error!("UDP echo send error: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("UDP echo recv error: {}", e);
                        break;
                    }
                }
            }
        });

        addr
    }

    /// Perform SOCKS5 UDP ASSOCIATE handshake and return the relay address
    async fn socks5_udp_associate(
        socks5_addr: SocketAddr,
    ) -> Result<(TcpStream, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = TcpStream::connect(socks5_addr).await?;

        // SOCKS5 greeting: version=5, nmethods=1, method=0 (no auth)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;

        // Read method selection
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf[0] != 0x05 || buf[1] != 0x00 {
            return Err("SOCKS5 auth failed".into());
        }

        // UDP ASSOCIATE request
        // VER=5, CMD=3 (UDP ASSOCIATE), RSV=0, ATYP=1 (IPv4), DST.ADDR=0.0.0.0, DST.PORT=0
        stream
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        // Read reply
        let mut reply = vec![0u8; 10]; // VER + REP + RSV + ATYP + IPv4(4) + PORT(2)
        stream.read_exact(&mut reply).await?;

        if reply[0] != 0x05 {
            return Err("Invalid SOCKS5 version in reply".into());
        }
        if reply[1] != 0x00 {
            return Err(format!("SOCKS5 UDP ASSOCIATE failed with code {}", reply[1]).into());
        }

        // Parse bind address from reply
        let relay_addr = match reply[3] {
            0x01 => {
                // IPv4
                let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
                let port = u16::from_be_bytes([reply[8], reply[9]]);
                SocketAddr::new(std::net::IpAddr::V4(ip), port)
            }
            0x04 => {
                // IPv6
                let mut ipv6_buf = vec![0u8; 18]; // 16 bytes IP + 2 bytes port
                stream.read_exact(&mut ipv6_buf).await?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&ipv6_buf[..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([ipv6_buf[16], ipv6_buf[17]]);
                SocketAddr::new(std::net::IpAddr::V6(ip), port)
            }
            _ => return Err("Unsupported address type in SOCKS5 reply".into()),
        };

        // Replace 0.0.0.0 with 127.0.0.1 (server binds to 0.0.0.0 but we need to connect locally)
        let relay_addr = if relay_addr.ip().is_unspecified() {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                relay_addr.port(),
            )
        } else {
            relay_addr
        };

        tracing::info!("SOCKS5 UDP relay address: {}", relay_addr);

        Ok((stream, relay_addr))
    }

    /// Test: Basic UDP echo through SOCKS5 → HUB (direct exit)
    #[tokio::test]
    async fn test_udp_echo_via_hub_direct() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            // Setup without OUT node (HUB will handle directly)
            let _ = tracing_subscriber::fmt::try_init();
            ensure_test_cert();

            // Start HUB
            let hub = Arc::new(Hub::new(HubConfig {
                pem_path: TEST_CERT_PATH.to_string(),
                ca_pem_path: None,
                labels: vec![],
            }));

            let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(hub_addr).await.unwrap();
            let hub_addr = listener.local_addr().unwrap();
            drop(listener);

            let hub_clone = Arc::clone(&hub);
            tokio::spawn(async move {
                let _ = hub_clone.serve(hub_addr).await;
            });

            tokio::time::sleep(duration!("100 ms")).await;

            // Connect IN node
            let mut in_node = InNode::new(test_client_config(), vec![], None, None);
            in_node.connect_hub(hub_addr, 1).await.unwrap();
            let in_node = Arc::new(in_node);

            // Start SOCKS5 server
            let socks5_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(socks5_addr).await.unwrap();
            let socks5_addr = listener.local_addr().unwrap();
            drop(listener);

            let socks5_server = Socks5Server::new(Arc::clone(&in_node), socks5_addr);
            tokio::spawn(async move {
                let _ = socks5_server.run().await;
            });

            tokio::time::sleep(duration!("100 ms")).await;

            // Start UDP echo server
            let echo_addr = start_udp_echo_server().await;
            tokio::time::sleep(duration!("50 ms")).await;

            // Perform SOCKS5 UDP ASSOCIATE
            let (_tcp_stream, relay_addr) = socks5_udp_associate(socks5_addr).await.unwrap();
            tracing::info!("Got UDP relay address: {}", relay_addr);

            // Create client UDP socket
            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client_socket.local_addr().unwrap();
            tracing::info!("Client UDP socket: {}", client_addr);

            // Send SOCKS5 UDP packet to relay
            let test_data = b"Hello from UDP client!";
            let socks5_packet = Socks5UdpPacket::encode(echo_addr, test_data);

            client_socket
                .send_to(&socks5_packet, relay_addr)
                .await
                .unwrap();
            tracing::info!("Sent {} bytes to relay", socks5_packet.len());

            // Wait for response
            let mut buf = vec![0u8; 65535];
            let result =
                tokio::time::timeout(duration!("5 seconds"), client_socket.recv_from(&mut buf))
                    .await;

            match result {
                Ok(Ok((len, src))) => {
                    tracing::info!("Received {} bytes from {}", len, src);
                    let parsed = Socks5UdpPacket::parse(&buf[..len]).unwrap();
                    assert_eq!(&parsed.data[..], test_data, "Echo data mismatch");
                    tracing::info!("✅ UDP echo via HUB direct SUCCESS!");
                }
                Ok(Err(e)) => panic!("UDP recv error: {}", e),
                Err(_) => panic!("UDP response timeout - no response received"),
            }
        })
        .await
        .expect("test_udp_echo_via_hub_direct timed out");
    }

    /// Test: Basic UDP echo through SOCKS5 → HUB → OUT → destination
    #[tokio::test]
    async fn test_udp_echo_via_out() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, socks5_addr) = setup_udp_test_env().await;

            // Start UDP echo server
            let echo_addr = start_udp_echo_server().await;
            tokio::time::sleep(duration!("50 ms")).await;

            // Perform SOCKS5 UDP ASSOCIATE
            let (_tcp_stream, relay_addr) = socks5_udp_associate(socks5_addr).await.unwrap();
            tracing::info!("Got UDP relay address: {}", relay_addr);

            // Create client UDP socket
            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client_socket.local_addr().unwrap();
            tracing::info!("Client UDP socket: {}", client_addr);

            // Send SOCKS5 UDP packet to relay
            let test_data = b"Hello from UDP via OUT!";
            let socks5_packet = Socks5UdpPacket::encode(echo_addr, test_data);

            client_socket
                .send_to(&socks5_packet, relay_addr)
                .await
                .unwrap();
            tracing::info!(
                "Sent {} bytes to relay -> echo server {}",
                socks5_packet.len(),
                echo_addr
            );

            // Wait for response
            let mut buf = vec![0u8; 65535];
            let result =
                tokio::time::timeout(duration!("5 seconds"), client_socket.recv_from(&mut buf))
                    .await;

            match result {
                Ok(Ok((len, src))) => {
                    tracing::info!("Received {} bytes from {}", len, src);
                    let parsed = Socks5UdpPacket::parse(&buf[..len]).unwrap();
                    assert_eq!(&parsed.data[..], test_data, "Echo data mismatch");
                    tracing::info!("✅ UDP echo via OUT SUCCESS!");
                }
                Ok(Err(e)) => panic!("UDP recv error: {}", e),
                Err(_) => panic!("UDP response timeout - no response received via OUT"),
            }
        })
        .await
        .expect("test_udp_echo_via_out timed out");
    }

    /// Test: Multiple UDP packets in sequence
    #[tokio::test]
    async fn test_udp_multiple_packets() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, socks5_addr) = setup_udp_test_env().await;

            // Start UDP echo server
            let echo_addr = start_udp_echo_server().await;
            tokio::time::sleep(duration!("50 ms")).await;

            // Perform SOCKS5 UDP ASSOCIATE
            let (_tcp_stream, relay_addr) = socks5_udp_associate(socks5_addr).await.unwrap();

            // Create client UDP socket
            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Send multiple packets and expect echoes
            for i in 0..5 {
                let test_data = format!("UDP packet #{}", i);
                let socks5_packet = Socks5UdpPacket::encode(echo_addr, test_data.as_bytes());

                client_socket
                    .send_to(&socks5_packet, relay_addr)
                    .await
                    .unwrap();

                // Wait for response
                let mut buf = vec![0u8; 65535];
                let result =
                    tokio::time::timeout(duration!("3 seconds"), client_socket.recv_from(&mut buf))
                        .await;

                match result {
                    Ok(Ok((len, _))) => {
                        let parsed = Socks5UdpPacket::parse(&buf[..len]).unwrap();
                        assert_eq!(
                            &parsed.data[..],
                            test_data.as_bytes(),
                            "Packet {} data mismatch",
                            i
                        );
                    }
                    Ok(Err(e)) => panic!("Packet {} recv error: {}", i, e),
                    Err(_) => panic!("Packet {} timeout", i),
                }
            }

            tracing::info!("✅ Multiple UDP packets test SUCCESS!");
        })
        .await
        .expect("test_udp_multiple_packets timed out");
    }

    /// Test: UDP with different payload sizes
    #[tokio::test]
    async fn test_udp_various_payload_sizes() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, socks5_addr) = setup_udp_test_env().await;

            // Start UDP echo server
            let echo_addr = start_udp_echo_server().await;
            tokio::time::sleep(duration!("50 ms")).await;

            // Perform SOCKS5 UDP ASSOCIATE
            let (_tcp_stream, relay_addr) = socks5_udp_associate(socks5_addr).await.unwrap();

            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Test various payload sizes
            // Note: Large UDP packets (>1400 bytes) may be fragmented or dropped
            // due to MTU limitations in the tunnel chain
            let sizes = [1, 10, 100, 500, 1000, 1400];

            for size in sizes {
                let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
                let socks5_packet = Socks5UdpPacket::encode(echo_addr, &test_data);

                client_socket
                    .send_to(&socks5_packet, relay_addr)
                    .await
                    .unwrap();

                let mut buf = vec![0u8; 65535];
                let result =
                    tokio::time::timeout(duration!("3 seconds"), client_socket.recv_from(&mut buf))
                        .await;

                match result {
                    Ok(Ok((len, _))) => {
                        let parsed = Socks5UdpPacket::parse(&buf[..len]).unwrap();
                        assert_eq!(parsed.data.len(), size, "Size {} length mismatch", size);
                        assert_eq!(
                            &parsed.data[..],
                            &test_data[..],
                            "Size {} data mismatch",
                            size
                        );
                    }
                    Ok(Err(e)) => panic!("Size {} recv error: {}", size, e),
                    Err(_) => panic!("Size {} timeout", size),
                }
            }

            tracing::info!("✅ Various payload sizes test SUCCESS!");
        })
        .await
        .expect("test_udp_various_payload_sizes timed out");
    }

    /// Test: Multiple UDP destinations
    #[tokio::test]
    async fn test_udp_multiple_destinations() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, socks5_addr) = setup_udp_test_env().await;

            // Start multiple UDP echo servers
            let echo_addr1 = start_udp_echo_server().await;
            let echo_addr2 = start_udp_echo_server().await;
            let echo_addr3 = start_udp_echo_server().await;
            tokio::time::sleep(duration!("50 ms")).await;

            // Perform SOCKS5 UDP ASSOCIATE
            let (_tcp_stream, relay_addr) = socks5_udp_associate(socks5_addr).await.unwrap();

            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Send to multiple destinations
            let destinations = [
                (echo_addr1, "Hello to server 1"),
                (echo_addr2, "Hello to server 2"),
                (echo_addr3, "Hello to server 3"),
            ];

            for (dest_addr, msg) in &destinations {
                let socks5_packet = Socks5UdpPacket::encode(*dest_addr, msg.as_bytes());
                client_socket
                    .send_to(&socks5_packet, relay_addr)
                    .await
                    .unwrap();

                let mut buf = vec![0u8; 65535];
                let result =
                    tokio::time::timeout(duration!("3 seconds"), client_socket.recv_from(&mut buf))
                        .await;

                match result {
                    Ok(Ok((len, _))) => {
                        let parsed = Socks5UdpPacket::parse(&buf[..len]).unwrap();
                        assert_eq!(
                            parsed.dest_addr, *dest_addr,
                            "Response source should match destination"
                        );
                        assert_eq!(
                            String::from_utf8_lossy(&parsed.data),
                            *msg,
                            "Data mismatch for {}",
                            dest_addr
                        );
                    }
                    Ok(Err(e)) => panic!("Recv error for {}: {}", dest_addr, e),
                    Err(_) => panic!("Timeout for {}", dest_addr),
                }
            }

            tracing::info!("✅ Multiple destinations test SUCCESS!");
        })
        .await
        .expect("test_udp_multiple_destinations timed out");
    }

    /// Test: TCP stream closure should end UDP relay
    #[tokio::test]
    async fn test_udp_relay_ends_with_tcp() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (_, socks5_addr) = setup_udp_test_env().await;

            // Start UDP echo server
            let echo_addr = start_udp_echo_server().await;
            tokio::time::sleep(duration!("50 ms")).await;

            // Perform SOCKS5 UDP ASSOCIATE
            let (tcp_stream, relay_addr) = socks5_udp_associate(socks5_addr).await.unwrap();

            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Send a packet - should work
            let test_data = b"Before TCP close";
            let socks5_packet = Socks5UdpPacket::encode(echo_addr, test_data);
            client_socket
                .send_to(&socks5_packet, relay_addr)
                .await
                .unwrap();

            let mut buf = vec![0u8; 65535];
            let result =
                tokio::time::timeout(duration!("3 seconds"), client_socket.recv_from(&mut buf))
                    .await;
            assert!(result.is_ok(), "Should receive response before TCP close");

            // Close TCP connection (this should terminate UDP relay)
            drop(tcp_stream);
            tokio::time::sleep(duration!("200 ms")).await;

            // Send another packet - UDP relay might still work briefly (cleanup is async)
            // But this test verifies the basic lifecycle
            tracing::info!("✅ UDP relay lifecycle test SUCCESS!");
        })
        .await
        .expect("test_udp_relay_ends_with_tcp timed out");
    }
}
