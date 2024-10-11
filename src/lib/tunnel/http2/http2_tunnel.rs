use std::{
    fmt,
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    match_server::MatchOutId,
    tunnel::{
        common::get_tunnel_string,
        http2::compat::{H2RecvStreamAsyncRead, H2SendStreamAsyncWrite},
        InTunnel, InTunnelLike, OutTunnel, TunnelId,
    },
};

type Http2ServerConnection =
    h2::server::Connection<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, bytes::Bytes>;

type Http2ClientConnection =
    h2::client::Connection<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, bytes::Bytes>;

pub struct Http2InTunnel {
    id: TunnelId,
    out_id: MatchOutId,
    labels: Vec<String>,
    priority: i64,
    request_sender: Arc<Mutex<h2::client::SendRequest<bytes::Bytes>>>,
    closed_notify: Arc<tokio::sync::Notify>,
    closed: AtomicBool,
}

impl Http2InTunnel {
    pub fn new(
        id: TunnelId,
        out_id: MatchOutId,
        labels: Vec<String>,
        priority: i64,
        request_sender: h2::client::SendRequest<bytes::Bytes>,
        h2_connection: Http2ClientConnection,
    ) -> Self {
        let closed_notify = Arc::new(tokio::sync::Notify::new());

        tokio::spawn({
            let closed_notify = closed_notify.clone();

            async move {
                if let Err(error) = h2_connection.await {
                    log::error!("http2 connection error: {}", error);
                }

                closed_notify.notify_waiters();
            }
        });

        Http2InTunnel {
            id,
            out_id,
            labels,
            priority,
            request_sender: Arc::new(Mutex::new(request_sender)),
            closed_notify,
            closed: AtomicBool::new(false),
        }
    }
}

impl fmt::Display for Http2InTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            get_tunnel_string("http2", self.id(), self.labels())
        )
    }
}

#[async_trait::async_trait]
impl InTunnelLike for Http2InTunnel {
    async fn connect(
        &self,
        destination_address: SocketAddr,
        destination_name: Option<String>,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let http_request = {
            let mut http_request = http::Request::builder();

            http_request = http_request
                .method(http::Method::POST)
                .header("X-Address", destination_address.to_string());

            if let Some(destination_name) = destination_name {
                http_request = http_request.header("X-Name", destination_name);
            }

            http_request.body(()).unwrap()
        };

        let (response, write_stream) = self
            .request_sender
            .lock()
            .unwrap()
            .send_request(http_request, false)?;

        let read_stream = H2RecvStreamAsyncRead::new(response);
        let write_stream = H2SendStreamAsyncWrite::new(write_stream);

        Ok((Box::new(read_stream), Box::new(write_stream)))
    }
}

#[async_trait::async_trait]
impl InTunnel for Http2InTunnel {
    fn id(&self) -> TunnelId {
        self.id
    }

    fn out_id(&self) -> MatchOutId {
        self.out_id
    }

    fn labels(&self) -> &[String] {
        &self.labels
    }

    fn priority(&self) -> i64 {
        self.priority
    }

    async fn closed(&self) {
        self.closed_notify.notified().await;
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub struct Http2OutTunnel {
    id: TunnelId,
    connection: Arc<tokio::sync::Mutex<Http2ServerConnection>>,
    closed: AtomicBool,
    closed_sender: tokio::sync::mpsc::UnboundedSender<()>,
}

impl Http2OutTunnel {
    pub fn new(
        id: TunnelId,
        connection: Http2ServerConnection,
        closed_sender: tokio::sync::mpsc::UnboundedSender<()>,
    ) -> Self {
        Http2OutTunnel {
            id,
            connection: Arc::new(tokio::sync::Mutex::new(connection)),
            closed: AtomicBool::new(false),
            closed_sender,
        }
    }
}

impl fmt::Display for Http2OutTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", get_tunnel_string("http2", self.id(), &[]))
    }
}

#[async_trait::async_trait]
impl OutTunnel for Http2OutTunnel {
    fn id(&self) -> TunnelId {
        self.id
    }

    async fn accept(
        &self,
    ) -> anyhow::Result<(
        (SocketAddr, Option<String>),
        (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ),
    )> {
        let mut connection = self.connection.lock().await;

        let result = match connection.accept().await {
            Some(Ok((request, mut response_sender))) => {
                let (destination_address, destination_name) = {
                    let headers = request.headers();

                    (
                        headers
                            .get("X-Address")
                            .and_then(|value| value.to_str().ok())
                            .and_then(|value| value.parse::<SocketAddr>().ok())
                            .ok_or_else(|| anyhow::anyhow!("missing X-Address header."))?,
                        headers
                            .get("X-Name")
                            .and_then(|value| value.to_str().ok())
                            .map(|value| value.to_string()),
                    )
                };

                let response = http::Response::builder().body(()).unwrap();

                let send_stream = response_sender.send_response(response, false)?;

                let read_stream = H2RecvStreamAsyncRead::new(request.into_body());
                let write_stream = H2SendStreamAsyncWrite::new(send_stream);

                Ok((
                    (destination_address, destination_name),
                    (
                        Box::new(read_stream) as Box<dyn AsyncRead + Send + Unpin>,
                        Box::new(write_stream) as Box<dyn AsyncWrite + Send + Unpin>,
                    ),
                ))
            }
            Some(Err(error)) => Err(error.into()),
            None => Err(anyhow::anyhow!("http2 connection closed.")),
        };

        if result.is_err() {
            self.closed
                .store(true, std::sync::atomic::Ordering::Relaxed);

            let _ = self.closed_sender.send(());
        }

        result
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }
}
