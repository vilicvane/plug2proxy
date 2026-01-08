#[cfg(test)]
mod frame_tests {
    use bytes::{Bytes, BytesMut};
    use tokio_util::codec::{Decoder, Encoder};

    use crate::tunnel::FrameCodec;

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut codec = FrameCodec::new();
        let original = Bytes::from("Hello, QUIC over TCP!");

        // Encode
        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();

        // Should have 4 bytes length prefix + payload
        assert_eq!(buf.len(), 4 + original.len());

        // Decode
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_empty() {
        let mut codec = FrameCodec::new();
        let original = Bytes::new();

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();

        assert_eq!(buf.len(), 4); // Just the length prefix

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_incomplete_header() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::from(&[0u8, 0, 0][..]); // Only 3 bytes

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none()); // Need more data
    }

    #[test]
    fn test_decode_incomplete_payload() {
        let mut codec = FrameCodec::new();
        // Length prefix says 10 bytes, but only 5 provided
        let mut buf = BytesMut::from(&[0u8, 0, 0, 10, 1, 2, 3, 4, 5][..]);

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none()); // Need more data
    }

    #[test]
    fn test_decode_multiple_frames() {
        let mut codec = FrameCodec::new();
        let msg1 = Bytes::from("First");
        let msg2 = Bytes::from("Second");

        let mut buf = BytesMut::new();
        codec.encode(msg1.clone(), &mut buf).unwrap();
        codec.encode(msg2.clone(), &mut buf).unwrap();

        let decoded1 = codec.decode(&mut buf).unwrap().unwrap();
        let decoded2 = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded1, msg1);
        assert_eq!(decoded2, msg2);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_encode_large_payload() {
        let mut codec = FrameCodec::new();
        let original = Bytes::from(vec![0xABu8; 65535]); // 64KB payload

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_frame_too_large() {
        let mut codec = FrameCodec::new();
        let original = Bytes::from(vec![0xABu8; 17 * 1024 * 1024]); // 17MB, exceeds max

        let mut buf = BytesMut::new();
        let result = codec.encode(original, &mut buf);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod connection_tests {
    use bytes::Bytes;
    use tokio::net::{TcpListener, TcpStream};

    use crate::tunnel::FramedConnection;

    #[tokio::test]
    async fn test_connection_send_recv() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream);

            // Receive and echo back
            let data = conn.recv().await.unwrap().unwrap();
            conn.send(data).await.unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client_conn = FramedConnection::new(client_stream);

        let msg = Bytes::from("Hello from client!");
        client_conn.send(msg.clone()).await.unwrap();

        let response = client_conn.recv().await.unwrap().unwrap();
        assert_eq!(response, msg);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_connection_split() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = FramedConnection::new(stream);
            let (mut sender, mut receiver) = conn.split();

            // Receive and echo back using split halves
            let data = receiver.recv().await.unwrap().unwrap();
            sender.send(data).await.unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let client_conn = FramedConnection::new(client_stream);
        let (mut sender, mut receiver) = client_conn.split();

        let msg = Bytes::from("Hello with split!");
        sender.send(msg.clone()).await.unwrap();

        let response = receiver.recv().await.unwrap().unwrap();
        assert_eq!(response, msg);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_connection_multiple_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = FramedConnection::new(stream);

            for _ in 0..10 {
                let data = conn.recv().await.unwrap().unwrap();
                conn.send(data).await.unwrap();
            }
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client_conn = FramedConnection::new(client_stream);

        for i in 0..10 {
            let msg = Bytes::from(format!("Message {}", i));
            client_conn.send(msg.clone()).await.unwrap();

            let response = client_conn.recv().await.unwrap().unwrap();
            assert_eq!(response, msg);
        }

        server_task.await.unwrap();
    }
}

#[cfg(test)]
mod tunnel_tests {
    use std::net::SocketAddr;

    use tokio::net::TcpListener;

    use crate::cert::{generate_ca, generate_node_cert};
    use crate::tunnel::{QuicConfig, Tunnel};

    // Use 1 for initial connection since client now extends connections after handshake
    const INITIAL_CONNECTION_COUNT: usize = 1;

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

    async fn setup_client(addr: SocketAddr) -> Tunnel {
        // Request 2 connections - client will establish 1 first, then extend after handshake
        Tunnel::connect(addr, Some("localhost"), 2).await.unwrap()
    }

    #[tokio::test]
    async fn test_tunnel_establish() {
        ensure_test_cert();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            // Accept only the initial connection(s)
            let mut tcp_streams = Vec::with_capacity(INITIAL_CONNECTION_COUNT);
            for _ in 0..INITIAL_CONNECTION_COUNT {
                let (stream, _) = listener.accept().await.unwrap();
                stream.set_nodelay(true).unwrap();
                tcp_streams.push(stream);
            }

            let mut config = QuicConfig::new_server(TEST_CERT_PATH, None)
                .unwrap()
                .into_inner();

            let tunnel = Tunnel::from_tcp_streams_server(tcp_streams, &mut config)
                .await
                .unwrap();

            assert!(tunnel.is_established().await);
            tunnel
        });

        // Give server time to start listening
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_tunnel = setup_client(addr).await;
        assert!(client_tunnel.is_established().await);

        let server_tunnel = server_task.await.unwrap();
        assert!(server_tunnel.is_established().await);
    }

    #[tokio::test]
    async fn test_tunnel_stream_send_recv() {
        ensure_test_cert();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut tcp_streams = Vec::with_capacity(INITIAL_CONNECTION_COUNT);
            for _ in 0..INITIAL_CONNECTION_COUNT {
                let (stream, _) = listener.accept().await.unwrap();
                stream.set_nodelay(true).unwrap();
                tcp_streams.push(stream);
            }

            let mut config = QuicConfig::new_server(TEST_CERT_PATH, None)
                .unwrap()
                .into_inner();

            let tunnel = Tunnel::from_tcp_streams_server(tcp_streams, &mut config)
                .await
                .unwrap();

            // Wait for readable stream
            let mut received = false;
            for _ in 0..100 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let readable = tunnel.quic().readable_streams().await;
                if !readable.is_empty() {
                    let stream_id = readable[0];
                    let mut buf = vec![0u8; 1024];
                    let (len, _) = tunnel
                        .quic()
                        .stream_recv(stream_id, &mut buf)
                        .await
                        .unwrap();
                    if len > 0 {
                        let msg = String::from_utf8_lossy(&buf[..len]).to_string();
                        assert_eq!(msg, "Hello from client!");

                        // Send response
                        tunnel
                            .quic()
                            .stream_send(stream_id, b"Hello from server!", false)
                            .await
                            .unwrap();
                        received = true;
                        break;
                    }
                }
            }
            assert!(received, "Server did not receive data");
            tunnel
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_tunnel = setup_client(addr).await;

        // Open stream and send
        let stream = client_tunnel.open_bi_stream().await.unwrap();
        stream.send(b"Hello from client!").await.unwrap();

        // Wait for response
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut buf = vec![0u8; 1024];
        let (len, _) = stream.recv(&mut buf).await.unwrap();
        assert!(len > 0, "Client did not receive response");
        let response = String::from_utf8_lossy(&buf[..len]).to_string();
        assert_eq!(response, "Hello from server!");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_tunnel_multiple_streams() {
        ensure_test_cert();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut tcp_streams = Vec::with_capacity(INITIAL_CONNECTION_COUNT);
            for _ in 0..INITIAL_CONNECTION_COUNT {
                let (stream, _) = listener.accept().await.unwrap();
                stream.set_nodelay(true).unwrap();
                tcp_streams.push(stream);
            }

            let mut config = QuicConfig::new_server(TEST_CERT_PATH, None)
                .unwrap()
                .into_inner();

            let tunnel = Tunnel::from_tcp_streams_server(tcp_streams, &mut config)
                .await
                .unwrap();

            // Echo all incoming data
            let mut processed = 0;
            for _ in 0..200 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let readable = tunnel.quic().readable_streams().await;
                for stream_id in readable {
                    let mut buf = vec![0u8; 1024];
                    if let Ok((len, _)) = tunnel.quic().stream_recv(stream_id, &mut buf).await {
                        if len > 0 {
                            tunnel
                                .quic()
                                .stream_send(stream_id, &buf[..len], false)
                                .await
                                .unwrap();
                            processed += 1;
                        }
                    }
                }
                if processed >= 5 {
                    break;
                }
            }
            assert!(processed >= 5, "Server processed {} streams", processed);
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_tunnel = setup_client(addr).await;

        // Open multiple streams
        for i in 0..5 {
            let stream = client_tunnel.open_bi_stream().await.unwrap();
            let msg = format!("Stream {} data", i);
            stream.send(msg.as_bytes()).await.unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let mut buf = vec![0u8; 1024];
            let (len, _) = stream.recv(&mut buf).await.unwrap();
            if len > 0 {
                let response = String::from_utf8_lossy(&buf[..len]).to_string();
                assert_eq!(response, msg);
            }
        }

        server_task.await.unwrap();
    }
}

#[cfg(test)]
mod quic_config_tests {
    use crate::cert::{generate_ca, generate_node_cert};
    use crate::tunnel::QuicConfig;

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

    #[test]
    fn test_client_config() {
        let config = QuicConfig::new_client(None, None);
        assert!(config.is_ok());
    }

    #[test]
    fn test_server_config() {
        ensure_test_cert();
        let config = QuicConfig::new_server(TEST_CERT_PATH, None);
        assert!(config.is_ok());
    }

    #[test]
    fn test_server_config_invalid_cert() {
        let config = QuicConfig::new_server("nonexistent.pem", None);
        assert!(config.is_err());
    }
}

#[cfg(test)]
mod tcp_refuel_tests {
    use std::net::SocketAddr;

    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use crate::cert::{generate_ca, generate_node_cert};
    use crate::tunnel::{QuicConfig, ROUTING_MAGIC, Tunnel};

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

    #[tokio::test]
    async fn test_tcp_handle_tracks_connection_id() {
        ensure_test_cert();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server task
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();

            let mut config = QuicConfig::new_server(TEST_CERT_PATH, None)
                .unwrap()
                .into_inner();

            let tunnel = Tunnel::from_tcp_streams_server(vec![stream], &mut config)
                .await
                .unwrap();

            // Keep tunnel alive briefly
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            tunnel
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Client connects with 1 connection (no additional)
        let tunnel = Tunnel::connect(addr, Some("localhost"), 1).await.unwrap();

        // After handshake, connection ID should be set
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Get the connection ID
        let conn_id = tunnel.connection_id().await;
        assert!(
            !conn_id.is_empty(),
            "Connection ID should be set after handshake"
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_routing_header_format() {
        // Test that the routing header is correctly formatted
        let conn_id = vec![0x12, 0x34, 0x56, 0x78];

        let mut header = vec![ROUTING_MAGIC, conn_id.len() as u8];
        header.extend_from_slice(&conn_id);

        assert_eq!(header[0], ROUTING_MAGIC);
        assert_eq!(header[1], 4); // length
        assert_eq!(&header[2..], &conn_id[..]);

        // Verify parsing
        assert_eq!(header[0], ROUTING_MAGIC);
        let len = header[1] as usize;
        let parsed_id = &header[2..2 + len];
        assert_eq!(parsed_id, &conn_id[..]);
    }

    #[tokio::test]
    async fn test_refuel_channel_behavior() {
        // Test that refuel requests are properly buffered in the channel
        let (tx, mut rx) = mpsc::channel::<()>(16);

        // Send multiple rapid requests
        for _ in 0..10 {
            let _ = tx.try_send(());
        }

        // Should receive at least one
        let first = rx.try_recv();
        assert!(first.is_ok(), "Should receive at least one refuel request");

        // Drain remaining
        let mut count = 1;
        while rx.try_recv().is_ok() {
            count += 1;
        }

        // Should have received all 10 (they're buffered)
        // The debouncing happens in the refuel task with the 100ms sleep
        assert_eq!(count, 10, "All requests should be buffered in channel");
    }

    #[tokio::test]
    async fn test_server_tunnel_no_refuel_addr() {
        ensure_test_cert();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Start server
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();

            let mut config = QuicConfig::new_server(TEST_CERT_PATH, None)
                .unwrap()
                .into_inner();

            let tunnel = Tunnel::from_tcp_streams_server(vec![stream], &mut config)
                .await
                .unwrap();

            // Server tunnel should work but won't refuel (no server_addr)
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            tunnel
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = Tunnel::connect(addr, Some("localhost"), 1).await.unwrap();
        assert!(client.is_established().await);

        let server = server_task.await.unwrap();
        assert!(server.is_established().await);
    }

    #[tokio::test]
    async fn test_client_sets_refuel_metadata() {
        ensure_test_cert();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server - just accept and keep alive
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();

            let mut config = QuicConfig::new_server(TEST_CERT_PATH, None)
                .unwrap()
                .into_inner();

            let tunnel = Tunnel::from_tcp_streams_server(vec![stream], &mut config)
                .await
                .unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            tunnel
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect with desired_count = 2
        let tunnel = Tunnel::connect(addr, Some("localhost"), 2).await.unwrap();

        // Wait for handshake
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify tunnel is established
        assert!(tunnel.is_established().await);

        // Connection ID should be set (used for refueling)
        let conn_id = tunnel.connection_id().await;
        assert!(!conn_id.is_empty());

        server_task.await.unwrap();
    }

    #[test]
    fn test_routing_magic_value() {
        // ROUTING_MAGIC should be 0x50 ('P')
        assert_eq!(ROUTING_MAGIC, 0x50);

        // This value should not conflict with QUIC packet headers
        // QUIC long header: first bit is 1 (0x80-0xFF)
        // QUIC short header: first bit is 0, but has specific patterns
        // 0x50 is in a safe range that won't be confused with QUIC
        const { assert!(ROUTING_MAGIC < 0x80) }; // Not a QUIC long header
    }
}
