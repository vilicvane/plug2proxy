use std::net::SocketAddr;
use std::sync::Arc;

use plug2proxy::tunnel::{QuicConfig, Tunnel};
use tokio::net::TcpListener;
use tokio::sync::Notify;

const CONNECTION_COUNT: usize = 4;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = "127.0.0.1:8765".parse()?;
    let client_done = Arc::new(Notify::new());
    let client_done_clone = Arc::clone(&client_done);

    // Spawn server
    let server_handle = tokio::spawn(async move {
        if let Err(e) = run_server(addr, client_done_clone).await {
            eprintln!("Server error: {}", e);
        }
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Run client
    run_client(addr).await?;

    // Signal server we're done
    client_done.notify_one();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    server_handle.abort();

    println!("\n✅ QUIC-over-TCP tunnel test completed successfully!");
    Ok(())
}

async fn run_server(addr: SocketAddr, done: Arc<Notify>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("Server: listening on {}", addr);

    // Accept TCP connections
    let mut tcp_streams = Vec::with_capacity(CONNECTION_COUNT);
    for _ in 0..CONNECTION_COUNT {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        println!("Server: accepted TCP connection from {}", peer);
        tcp_streams.push(stream);
    }

    // Create server QUIC config
    let mut config = QuicConfig::new_server("certs/cert.pem", "certs/key.pem")?.into_inner();

    // Create tunnel from TCP streams
    let tunnel = Tunnel::from_tcp_streams_server(tcp_streams, &mut config).await?;
    println!("Server: QUIC tunnel established!");

    // Wait for incoming streams and echo data back
    let mut stream_count = 0;
    loop {
        tokio::select! {
            _ = done.notified() => {
                println!("Server: shutting down (processed {} streams)", stream_count);
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                // Check for readable streams
                let quic = tunnel.quic();
                let readable = quic.readable_streams().await;

                for stream_id in readable {
                    stream_count += 1;

                    // Read data from stream
                    let mut buf = vec![0u8; 1024];
                    match quic.stream_recv(stream_id, &mut buf).await {
                        Ok((len, _fin)) => {
                            if len > 0 {
                                let msg = String::from_utf8_lossy(&buf[..len]);
                                println!("Server: received on stream {}: \"{}\"", stream_id, msg);

                                // Echo back with prefix
                                let response = format!("Echo: {}", msg);
                                if let Err(e) = quic.stream_send(stream_id, response.as_bytes(), false).await {
                                    println!("Server: failed to send response: {}", e);
                                } else {
                                    println!("Server: sent response on stream {}", stream_id);
                                }
                            }
                        }
                        Err(e) => {
                            println!("Server: error reading stream {}: {}", stream_id, e);
                        }
                    }
                }

                if tunnel.is_closed().await {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn run_client(addr: SocketAddr) -> anyhow::Result<()> {
    println!("Client: connecting to {}", addr);

    // Create client tunnel
    let tunnel = Tunnel::connect(addr, Some("localhost"), CONNECTION_COUNT).await?;
    println!("Client: QUIC tunnel established!");

    // Open streams and send data
    for i in 0..3 {
        // Open a new bidirectional stream
        let stream = tunnel.open_bi_stream().await?;
        println!("Client: opened stream {}", stream.id());

        // Send a message
        let msg = format!("Hello from stream {}!", i);
        stream.send(msg.as_bytes()).await?;
        println!("Client: sent on stream {}: \"{}\"", stream.id(), msg);

        // Give server time to process and respond
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Try to receive response
        let mut buf = vec![0u8; 1024];
        let (len, _fin) = stream.recv(&mut buf).await?;
        if len > 0 {
            let response = String::from_utf8_lossy(&buf[..len]);
            println!("Client: received on stream {}: \"{}\"", stream.id(), response);
        } else {
            println!("Client: no response yet on stream {}", stream.id());
        }
    }

    // Close the tunnel
    tunnel.close().await?;
    println!("Client: tunnel closed");

    Ok(())
}
