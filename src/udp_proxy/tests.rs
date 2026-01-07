use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::*;

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[tokio::test]
async fn test_datagram_creation() {
    let src = localhost(1234);
    let dest = localhost(53);
    let data = b"test query";

    let datagram = Datagram::new(src, dest, &data[..]);

    assert_eq!(datagram.source, src);
    assert_eq!(datagram.dest, dest);
    assert_eq!(datagram.data, Bytes::from_static(data));
}

#[tokio::test]
async fn test_channel_send_recv() {
    let (tx, mut rx) = channel(16);

    let datagram = Datagram::new(localhost(1234), localhost(53), "hello");

    tx.send(datagram.clone()).await.unwrap();

    let received = rx.recv().await.unwrap();
    assert_eq!(received.source, datagram.source);
    assert_eq!(received.dest, datagram.dest);
    assert_eq!(received.data, datagram.data);
}

#[tokio::test]
async fn test_channel_pair() {
    let (mut inbound, mut outbound) = channel_pair(16);

    // Inbound sends request
    let request = Datagram::new(localhost(1234), localhost(53), "query");
    inbound.tx.send(request.clone()).await.unwrap();

    // Outbound receives request
    let received = outbound.rx.recv().await.unwrap();
    assert_eq!(received.source, request.source);
    assert_eq!(received.data, request.data);

    // Outbound sends response
    let response = Datagram::new(localhost(53), localhost(1234), "response");
    outbound.tx.send(response.clone()).await.unwrap();

    // Inbound receives response
    let received = inbound.rx.recv().await.unwrap();
    assert_eq!(received.source, response.source);
    assert_eq!(received.data, response.data);
}

#[tokio::test]
async fn test_nat_mapping_create_and_lookup() {
    let mappings = NatMappingTable::new((50000, 50010));

    let client = localhost(12345);
    let server = localhost(53);

    // Create mapping
    let port = mappings.get_or_create(client, server).await.unwrap();
    assert!((50000..=50010).contains(&port));

    // Lookup by port
    let mapping = mappings.lookup_by_port(port).await.unwrap();
    assert_eq!(mapping.internal_addr, client);
    assert_eq!(mapping.original_dest, server);

    // Lookup by internal address
    let found_port = mappings.lookup_by_internal(&client).await.unwrap();
    assert_eq!(found_port, port);
}

#[tokio::test]
async fn test_nat_mapping_reuse() {
    let mappings = NatMappingTable::new((50000, 50010));

    let client = localhost(12345);
    let server = localhost(53);

    // Create mapping
    let port1 = mappings.get_or_create(client, server).await.unwrap();

    // Same client should get same port
    let port2 = mappings.get_or_create(client, server).await.unwrap();
    assert_eq!(port1, port2);
}

#[tokio::test]
async fn test_nat_mapping_different_clients() {
    let mappings = NatMappingTable::new((50000, 50010));

    let client1 = localhost(12345);
    let client2 = localhost(12346);
    let server = localhost(53);

    let port1 = mappings.get_or_create(client1, server).await.unwrap();
    let port2 = mappings.get_or_create(client2, server).await.unwrap();

    // Different clients should get different ports
    assert_ne!(port1, port2);
}

#[tokio::test]
async fn test_nat_mapping_expiry() {
    let mappings = NatMappingTable::new((50000, 50010)).with_ttl(Duration::from_millis(50));

    let client = localhost(12345);
    let server = localhost(53);

    let port = mappings.get_or_create(client, server).await.unwrap();

    // Mapping should exist
    assert!(mappings.lookup_by_port(port).await.is_some());

    // Wait for expiry
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Mapping should be expired
    assert!(mappings.lookup_by_port(port).await.is_none());
}

#[tokio::test]
async fn test_nat_mapping_cleanup() {
    let mappings = NatMappingTable::new((50000, 50010)).with_ttl(Duration::from_millis(50));

    let client = localhost(12345);
    let server = localhost(53);

    mappings.get_or_create(client, server).await.unwrap();

    assert_eq!(mappings.len().await, 1);

    // Wait and cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;
    mappings.cleanup_expired().await;

    assert_eq!(mappings.len().await, 0);
}

#[tokio::test]
async fn test_nat_mapping_touch_refresh() {
    let mappings = NatMappingTable::new((50000, 50010)).with_ttl(Duration::from_millis(100));

    let client = localhost(12345);
    let server = localhost(53);

    let port = mappings.get_or_create(client, server).await.unwrap();

    // Wait half the TTL
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Touch to refresh
    mappings.touch(port).await;

    // Wait another 60ms (would be expired without touch)
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Should still be valid because we touched it
    assert!(mappings.lookup_by_port(port).await.is_some());
}

#[tokio::test]
async fn test_nat_mapping_port_exhaustion() {
    let mappings = NatMappingTable::new((50000, 50002));

    let server = localhost(53);

    // Allocate all 3 ports
    let port1 = mappings
        .get_or_create(localhost(10001), server)
        .await
        .unwrap();
    let port2 = mappings
        .get_or_create(localhost(10002), server)
        .await
        .unwrap();
    let port3 = mappings
        .get_or_create(localhost(10003), server)
        .await
        .unwrap();

    // All ports should be different and in range
    let ports = vec![port1, port2, port3];
    assert_eq!(
        ports.iter().collect::<std::collections::HashSet<_>>().len(),
        3
    );
    for port in &ports {
        assert!(*port >= 50000 && *port <= 50002);
    }

    // Next allocation should fail
    let result = mappings.get_or_create(localhost(10004), server).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_channel_closed() {
    let (tx, rx) = channel(16);
    drop(rx);

    let datagram = Datagram::new(localhost(1234), localhost(53), "hello");
    let result = tx.send(datagram).await;

    assert!(matches!(result, Err(ChannelError::Closed)));
}

#[tokio::test]
async fn test_channel_try_send_full() {
    let (tx, _rx) = channel(1);

    let datagram = Datagram::new(localhost(1234), localhost(53), "hello");

    // First send should succeed
    tx.try_send(datagram.clone()).unwrap();

    // Second should fail with Full
    let result = tx.try_send(datagram);
    assert!(matches!(result, Err(ChannelError::Full)));
}

#[tokio::test]
async fn test_inbound_outbound_direct_integration() {
    // This test simulates a full direct flow:
    // client -> inbound -> channel -> outbound -> (mock server) -> outbound -> channel -> inbound -> client

    // Create channel pair
    let (inbound_channel, outbound_channel) = channel_pair(16);

    // Create NAT mapping table
    let mappings = NatMappingTable::new((50000, 50100));

    // Bind sockets
    let inbound_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let inbound_addr = inbound_socket.local_addr().unwrap();

    let outbound_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Create client socket
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_socket.local_addr().unwrap();

    // Create mock UDP server (destination)
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    // Split channels
    let (inbound_tx, inbound_rx) = inbound_channel.split();
    let (outbound_tx, outbound_rx) = outbound_channel.split();

    // Create handlers
    let inbound = Inbound::new(inbound_socket, inbound_tx, inbound_rx);
    let outbound = Outbound::new(outbound_socket, outbound_rx, outbound_tx, mappings);

    let (inbound_receiver, mut inbound_sender) = inbound.split();
    let (mut outbound_forwarder, outbound_responder) = outbound.split();

    // Spawn mock UDP server
    let server_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (len, src) = server_socket.recv_from(&mut buf).await.unwrap();
        // Echo back with "response:" prefix
        let response = format!("response:{}", std::str::from_utf8(&buf[..len]).unwrap());
        server_socket.send_to(response.as_bytes(), src).await.unwrap();
    });

    // Spawn inbound receiver
    let inbound_recv_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (len, src) = inbound_receiver.recv(&mut buf).await.unwrap();
        let datagram = Datagram::new(src, server_addr, Bytes::copy_from_slice(&buf[..len]));
        inbound_receiver.forward(datagram).await.unwrap();
    });

    // Spawn inbound sender
    let inbound_socket_for_send = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let inbound_send_handle = tokio::spawn(async move {
        let datagram = inbound_sender.recv().await.unwrap();
        inbound_socket_for_send
            .send_to(&datagram.data, datagram.dest)
            .await
            .unwrap();
        datagram
    });

    // Spawn outbound forwarder
    let outbound_fwd_handle = tokio::spawn(async move {
        let datagram = outbound_forwarder.recv().await.unwrap();
        outbound_forwarder
            .get_or_create_mapping(datagram.source, datagram.dest)
            .await
            .unwrap();
        outbound_forwarder
            .send_to(&datagram.data, datagram.dest)
            .await
            .unwrap();
        datagram.source
    });

    // Spawn outbound responder
    let outbound_resp_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (len, src) = outbound_responder.recv(&mut buf).await.unwrap();

        // Find the client to send response to
        // In this test, we know there's only one client
        let response = Datagram::new(src, client_addr, Bytes::copy_from_slice(&buf[..len]));
        outbound_responder.send(response).await.unwrap();
    });

    // Send query from client
    client_socket
        .send_to(b"test query", inbound_addr)
        .await
        .unwrap();

    // Wait for all components
    tokio::time::timeout(Duration::from_secs(5), async {
        server_handle.await.unwrap();
        inbound_recv_handle.await.unwrap();
        let _ = outbound_fwd_handle.await.unwrap();
        outbound_resp_handle.await.unwrap();
        let response = inbound_send_handle.await.unwrap();
        assert_eq!(response.data, Bytes::from_static(b"response:test query"));
    })
    .await
    .expect("test timed out");
}

/// Demonstrates how `Datagram` can be serialized for transport over a tunnel.
/// This is the key to supporting inbound/outbound on different machines.
fn serialize_datagram(datagram: &Datagram) -> Bytes {
    let mut buf = BytesMut::new();

    // Serialize source address
    match datagram.source {
        SocketAddr::V4(addr) => {
            buf.put_u8(4);
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
        SocketAddr::V6(addr) => {
            buf.put_u8(6);
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
    }

    // Serialize dest address
    match datagram.dest {
        SocketAddr::V4(addr) => {
            buf.put_u8(4);
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
        SocketAddr::V6(addr) => {
            buf.put_u8(6);
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
    }

    // Serialize payload length and data
    buf.put_u32(datagram.data.len() as u32);
    buf.put_slice(&datagram.data);

    buf.freeze()
}

fn deserialize_datagram(mut data: Bytes) -> Datagram {
    // Deserialize source address
    let source = if data.get_u8() == 4 {
        let mut octets = [0u8; 4];
        data.copy_to_slice(&mut octets);
        let port = data.get_u16();
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
    } else {
        let mut octets = [0u8; 16];
        data.copy_to_slice(&mut octets);
        let port = data.get_u16();
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
    };

    // Deserialize dest address
    let dest = if data.get_u8() == 4 {
        let mut octets = [0u8; 4];
        data.copy_to_slice(&mut octets);
        let port = data.get_u16();
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
    } else {
        let mut octets = [0u8; 16];
        data.copy_to_slice(&mut octets);
        let port = data.get_u16();
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
    };

    // Deserialize payload
    let len = data.get_u32() as usize;
    let payload = data.split_to(len);

    Datagram::new(source, dest, payload)
}

/// This test demonstrates the remote deployment scenario where:
/// - Inbound runs on Machine A (e.g., client-facing proxy)
/// - Outbound runs on Machine B (e.g., server with internet access)
/// - They communicate via a simulated tunnel (TCP stream in this test)
///
/// The flow is:
/// 1. Client sends datagram to inbound (Machine A)
/// 2. Inbound serializes Datagram and sends over "tunnel" to Machine B
/// 3. Outbound (Machine B) deserializes, creates NAT mapping, forwards to destination
/// 4. Response comes back, outbound serializes and sends over tunnel
/// 5. Inbound deserializes and sends response to client
#[tokio::test]
async fn test_remote_inbound_outbound_via_simulated_tunnel() {
    // Create TCP listener to simulate tunnel endpoint on "Machine B" (outbound side)
    let tunnel_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = tunnel_listener.local_addr().unwrap();

    // Create NAT mapping table (lives on outbound/Machine B)
    let mappings = NatMappingTable::new((50000, 50100));

    // Create inbound socket (Machine A - receives client datagrams)
    let inbound_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let inbound_addr = inbound_socket.local_addr().unwrap();

    // Create outbound socket (Machine B - sends to destinations)
    let outbound_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Create client socket
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_socket.local_addr().unwrap();

    // Create mock UDP server (destination)
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    // === MACHINE B (Outbound side) ===
    // Accept tunnel connection and handle forwarding
    let machine_b_handle = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut tunnel_stream, _) = tunnel_listener.accept().await.unwrap();

        // Read datagram from tunnel (step 3: forwarder receives)
        let mut len_buf = [0u8; 4];
        tunnel_stream.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut data = vec![0u8; len];
        tunnel_stream.read_exact(&mut data).await.unwrap();

        // Deserialize datagram
        let datagram = deserialize_datagram(Bytes::from(data));
        tracing::info!(
            src = %datagram.source,
            dest = %datagram.dest,
            "Machine B: received datagram from tunnel"
        );

        // Step 3: Create NAT mapping
        let _port = mappings
            .get_or_create(datagram.source, datagram.dest)
            .await
            .unwrap();
        tracing::info!(
            internal = %datagram.source,
            "Machine B: created NAT mapping"
        );

        // Step 3: Forward to actual destination
        outbound_socket
            .send_to(&datagram.data, datagram.dest)
            .await
            .unwrap();
        tracing::info!(dest = %datagram.dest, "Machine B: forwarded to destination");

        // Receive response from destination
        let mut resp_buf = vec![0u8; 1024];
        let (resp_len, server_src) = outbound_socket.recv_from(&mut resp_buf).await.unwrap();
        tracing::info!(src = %server_src, len = resp_len, "Machine B: received response");

        // Create response datagram (dest is the original client)
        let response = Datagram::new(
            server_src,
            datagram.source, // Route back to original client
            Bytes::copy_from_slice(&resp_buf[..resp_len]),
        );

        // Serialize and send back through tunnel
        let serialized = serialize_datagram(&response);
        tunnel_stream
            .write_all(&(serialized.len() as u32).to_be_bytes())
            .await
            .unwrap();
        tunnel_stream.write_all(&serialized).await.unwrap();
        tracing::info!("Machine B: sent response back through tunnel");
    });

    // === Mock UDP Server (destination) ===
    let server_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (len, src) = server_socket.recv_from(&mut buf).await.unwrap();
        let response = format!("response:{}", std::str::from_utf8(&buf[..len]).unwrap());
        server_socket.send_to(response.as_bytes(), src).await.unwrap();
    });

    // === MACHINE A (Inbound side) ===
    let machine_a_handle = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Connect to Machine B via tunnel
        let mut tunnel_stream = tokio::net::TcpStream::connect(tunnel_addr).await.unwrap();

        // Step 1: Receive datagram from client
        let mut buf = vec![0u8; 1024];
        let (len, src) = inbound_socket.recv_from(&mut buf).await.unwrap();
        tracing::info!(src = %src, len, "Machine A: received datagram from client");

        // Create datagram with routing info
        let datagram = Datagram::new(src, server_addr, Bytes::copy_from_slice(&buf[..len]));

        // Step 2: Serialize and send to forwarder (Machine B) via tunnel
        let serialized = serialize_datagram(&datagram);
        tunnel_stream
            .write_all(&(serialized.len() as u32).to_be_bytes())
            .await
            .unwrap();
        tunnel_stream.write_all(&serialized).await.unwrap();
        tracing::info!("Machine A: sent datagram to Machine B via tunnel");

        // Receive response from tunnel
        let mut len_buf = [0u8; 4];
        tunnel_stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        let mut resp_data = vec![0u8; resp_len];
        tunnel_stream.read_exact(&mut resp_data).await.unwrap();

        let response = deserialize_datagram(Bytes::from(resp_data));
        tracing::info!(
            dest = %response.dest,
            "Machine A: received response from tunnel"
        );

        // Send response back to client
        inbound_socket
            .send_to(&response.data, response.dest)
            .await
            .unwrap();
        tracing::info!(dest = %response.dest, "Machine A: sent response to client");

        response
    });

    // === CLIENT ===
    // Send query and receive response
    client_socket
        .send_to(b"test query", inbound_addr)
        .await
        .unwrap();

    let mut response_buf = vec![0u8; 1024];
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        server_handle.await.unwrap();
        machine_b_handle.await.unwrap();
        let response = machine_a_handle.await.unwrap();

        // Also verify client receives the response
        let (len, _) = client_socket.recv_from(&mut response_buf).await.unwrap();
        (response, len)
    })
    .await
    .expect("test timed out");

    let (response, client_recv_len) = result;

    // Verify the response datagram
    assert_eq!(response.dest, client_addr);
    assert_eq!(response.data, Bytes::from_static(b"response:test query"));

    // Verify client received the response
    assert_eq!(&response_buf[..client_recv_len], b"response:test query");
}
