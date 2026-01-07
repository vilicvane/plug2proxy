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

    use crate::tunnel::{QuicConfig, Tunnel};

    const CONNECTION_COUNT: usize = 2;

    async fn setup_client(addr: SocketAddr) -> Tunnel {
        Tunnel::connect(addr, Some("localhost"), CONNECTION_COUNT)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_tunnel_establish() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut tcp_streams = Vec::with_capacity(CONNECTION_COUNT);
            for _ in 0..CONNECTION_COUNT {
                let (stream, _) = listener.accept().await.unwrap();
                stream.set_nodelay(true).unwrap();
                tcp_streams.push(stream);
            }

            let mut config = QuicConfig::new_server("certs/cert.pem", "certs/key.pem")
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
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut tcp_streams = Vec::with_capacity(CONNECTION_COUNT);
            for _ in 0..CONNECTION_COUNT {
                let (stream, _) = listener.accept().await.unwrap();
                stream.set_nodelay(true).unwrap();
                tcp_streams.push(stream);
            }

            let mut config = QuicConfig::new_server("certs/cert.pem", "certs/key.pem")
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
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut tcp_streams = Vec::with_capacity(CONNECTION_COUNT);
            for _ in 0..CONNECTION_COUNT {
                let (stream, _) = listener.accept().await.unwrap();
                stream.set_nodelay(true).unwrap();
                tcp_streams.push(stream);
            }

            let mut config = QuicConfig::new_server("certs/cert.pem", "certs/key.pem")
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
    use crate::tunnel::QuicConfig;

    #[test]
    fn test_client_config() {
        let config = QuicConfig::new_client();
        assert!(config.is_ok());
    }

    #[test]
    fn test_server_config() {
        let config = QuicConfig::new_server("certs/cert.pem", "certs/key.pem");
        assert!(config.is_ok());
    }

    #[test]
    fn test_server_config_invalid_cert() {
        let config = QuicConfig::new_server("nonexistent.pem", "nonexistent.pem");
        assert!(config.is_err());
    }
}
