use std::{
    fmt,
    net::SocketAddr,
    os::fd::{AsFd, BorrowedFd},
    sync::{
        atomic::{self, AtomicBool},
        Arc, Mutex,
    },
    task::Poll,
    time::Duration,
};

use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    match_server::MatchOutId,
    route::rule::Label,
    tunnel::{
        common::get_tunnel_string,
        http2::compat::{H2RecvStreamAsyncRead, H2SendStreamAsyncWrite},
        InTunnel, InTunnelLike, OutTunnel, TunnelId,
    },
};

const WINDOW_SIZE_CHECK_INTERVAL: Duration = Duration::from_millis(200);

type Http2ServerConnection =
    h2::server::Connection<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, bytes::Bytes>;

type Http2ClientConnection =
    h2::client::Connection<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, bytes::Bytes>;

pub struct Http2InTunnel {
    id: TunnelId,
    out_id: MatchOutId,
    labels: Vec<Label>,
    priority: i64,
    request_sender: Arc<Mutex<h2::client::SendRequest<bytes::Bytes>>>,
    closed_notify: Arc<tokio::sync::Notify>,
    closed: Arc<AtomicBool>,
}

impl Http2InTunnel {
    pub fn new(
        id: TunnelId,
        out_id: MatchOutId,
        labels: Vec<Label>,
        priority: i64,
        request_sender: h2::client::SendRequest<bytes::Bytes>,
        mut connection: Http2ClientConnection,
        fd: i32,
    ) -> Self {
        let closed_notify = Arc::new(tokio::sync::Notify::new());
        let closed = Arc::new(AtomicBool::new(false));

        tokio::spawn({
            let closed_notify = closed_notify.clone();
            let closed = closed.clone();

            async move {
                let mut window_size_setter = WindowSizeSetter::new(fd);

                let mut interval = tokio::time::interval(WINDOW_SIZE_CHECK_INTERVAL);

                futures::future::poll_fn(|context| {
                    match connection.poll_unpin(context) {
                        std::task::Poll::Ready(_) => return Poll::Ready(()),
                        std::task::Poll::Pending => {}
                    }

                    match interval.poll_tick(context) {
                        Poll::Ready(_) => {
                            window_size_setter
                                .set_window_size(H2ConnectionMutRef::Client(&mut connection));
                        }
                        Poll::Pending => {}
                    }

                    Poll::Pending
                })
                .await;

                closed.store(true, atomic::Ordering::Relaxed);
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
            closed,
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
        tag: Option<String>,
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

            if let Some(tag) = tag {
                http_request = http_request.header("X-Tag", tag);
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

    fn labels(&self) -> &[Label] {
        &self.labels
    }

    fn priority(&self) -> i64 {
        self.priority
    }

    async fn closed(&self) {
        self.closed_notify.notified().await;
    }

    fn is_closed(&self) -> bool {
        self.closed.load(atomic::Ordering::Relaxed)
    }
}

pub struct Http2OutTunnel {
    id: TunnelId,
    connection: Arc<tokio::sync::Mutex<Http2ServerConnection>>,
    closed: AtomicBool,
    fd: i32,
}

impl Http2OutTunnel {
    pub fn new(id: TunnelId, connection: Http2ServerConnection, fd: i32) -> Self {
        Http2OutTunnel {
            id,
            connection: Arc::new(tokio::sync::Mutex::new(connection)),
            closed: AtomicBool::new(false),
            fd,
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
        (SocketAddr, Option<String>, Option<String>),
        (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ),
    )> {
        let mut connection = self.connection.lock().await;
        let mut window_size_setter = WindowSizeSetter::new(self.fd);

        let mut interval = tokio::time::interval(WINDOW_SIZE_CHECK_INTERVAL);

        let result = futures::future::poll_fn(|context| {
            match connection.poll_accept(context) {
                Poll::Ready(Some(Ok((request, mut response_sender)))) => {
                    let destination_tuple = {
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
                            headers
                                .get("X-Tag")
                                .and_then(|value| value.to_str().ok())
                                .map(|value| value.to_string()),
                        )
                    };

                    let response = http::Response::builder().body(()).unwrap();

                    let send_stream = response_sender.send_response(response, false)?;

                    let read_stream = H2RecvStreamAsyncRead::new(request.into_body());
                    let write_stream = H2SendStreamAsyncWrite::new(send_stream);

                    return Poll::Ready(Ok((
                        destination_tuple,
                        (
                            Box::new(read_stream) as Box<dyn AsyncRead + Send + Unpin>,
                            Box::new(write_stream) as Box<dyn AsyncWrite + Send + Unpin>,
                        ),
                    )));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error.into())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow::anyhow!("http2 connection closed.")))
                }
                Poll::Pending => {}
            }

            match interval.poll_tick(context) {
                Poll::Ready(_) => {
                    window_size_setter.set_window_size(H2ConnectionMutRef::Server(&mut connection));
                }
                Poll::Pending => {}
            }

            Poll::Pending
        })
        .await;

        if result.is_err() {
            self.closed.store(true, atomic::Ordering::Relaxed);
        }

        result
    }

    fn is_closed(&self) -> bool {
        self.closed.load(atomic::Ordering::Relaxed)
    }
}

struct AnyAsFd {
    raw_fd: i32,
}

impl AsFd for AnyAsFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.raw_fd) }
    }
}

const MIN_WINDOW_SIZE: u32 = 4 * 1024 * 1024; // 4MB

struct WindowSizeSetter {
    fd: AnyAsFd,
    recorded_receive_buffer_size: u32,
}

impl WindowSizeSetter {
    fn new(fd: i32) -> Self {
        WindowSizeSetter {
            fd: AnyAsFd { raw_fd: fd },
            recorded_receive_buffer_size: 0,
        }
    }

    fn set_window_size(&mut self, connection: H2ConnectionMutRef) {
        let receive_buffer_size =
            nix::sys::socket::getsockopt(&self.fd, nix::sys::socket::sockopt::RcvBuf).unwrap()
                as u32;

        if self.recorded_receive_buffer_size == receive_buffer_size {
            return;
        }

        self.recorded_receive_buffer_size = receive_buffer_size;

        let stream_window_size = receive_buffer_size;
        let connection_window_size = receive_buffer_size.max(MIN_WINDOW_SIZE) * 4;

        match connection {
            H2ConnectionMutRef::Server(connection) => {
                connection.set_initial_window_size(stream_window_size).ok();
                connection.set_target_window_size(connection_window_size);
            }
            H2ConnectionMutRef::Client(connection) => {
                connection.set_initial_window_size(stream_window_size).ok();
                connection.set_target_window_size(connection_window_size);
            }
        }
    }
}

enum H2ConnectionMutRef<'a> {
    Server(&'a mut Http2ServerConnection),
    Client(&'a mut Http2ClientConnection),
}
