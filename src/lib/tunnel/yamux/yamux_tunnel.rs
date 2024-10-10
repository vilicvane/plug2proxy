use std::sync::{atomic::AtomicBool, Arc, Mutex};

use futures::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt as _};

use crate::tunnel::byte_stream_tunnel::{
    ByteStreamInTunnelConnection, ByteStreamOutTunnelConnection,
};

type YamuxClientConnection = yamux::Connection<
    tokio_util::compat::Compat<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
>;

type YamuxServerConnection = yamux::Connection<
    tokio_util::compat::Compat<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
>;

pub struct YamuxInTunnelConnection {
    connection: Arc<Mutex<YamuxServerConnection>>,
    waker: Arc<Mutex<Option<futures::task::Waker>>>,
    open_mutex: tokio::sync::Mutex<()>,
    closed_notify: tokio::sync::Notify,
    closed: AtomicBool,
    permit: Arc<Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>,
}

impl YamuxInTunnelConnection {
    pub fn new(connection: YamuxServerConnection) -> Self {
        let connection = Arc::new(Mutex::new(connection));

        let waker = Arc::new(Mutex::new(None));

        tokio::spawn({
            let connection = connection.clone();
            let waker = waker.clone();

            async {
                futures::future::poll_fn(move |context| {
                    waker.lock().unwrap().replace(context.waker().clone());

                    connection.lock().unwrap().poll_next_inbound(context)
                })
                .await;
            }
        });

        YamuxInTunnelConnection {
            connection,
            waker,
            open_mutex: tokio::sync::Mutex::new(()),
            closed_notify: tokio::sync::Notify::new(),
            closed: AtomicBool::new(false),
            permit: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl ByteStreamInTunnelConnection for YamuxInTunnelConnection {
    async fn open(
        &self,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let _guard = self.open_mutex.lock().await;

        match futures::future::poll_fn(|context| {
            let mut connection = self.connection.lock().unwrap();

            let poll = connection.poll_new_outbound(context);

            if poll.is_ready() {
                if let Some(waker) = self.waker.lock().unwrap().take() {
                    waker.wake();
                }
            }

            poll
        })
        .await
        {
            Ok(stream) => {
                let (read_stream, write_stream) = stream.split();

                Ok((
                    Box::new(read_stream.compat()),
                    Box::new(write_stream.compat_write()),
                ))
            }
            Err(yamux::ConnectionError::Closed) => {
                self.closed
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                self.closed_notify.notify_waiters();

                anyhow::bail!("yamux connection closed.");
            }
            Err(error) => anyhow::bail!(error),
        }
    }

    async fn closed(&self) {
        self.closed_notify.notified().await;
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn handle_permit(&self, permit: tokio::sync::OwnedSemaphorePermit) {
        self.permit.lock().unwrap().replace(permit);
    }
}

pub struct YamuxOutTunnelConnection {
    connection: Arc<Mutex<YamuxClientConnection>>,
    closed: AtomicBool,
    closed_sender: tokio::sync::mpsc::UnboundedSender<()>,
}

impl YamuxOutTunnelConnection {
    pub fn new(
        connection: YamuxClientConnection,
        closed_sender: tokio::sync::mpsc::UnboundedSender<()>,
    ) -> Self {
        YamuxOutTunnelConnection {
            connection: Arc::new(Mutex::new(connection)),
            closed: AtomicBool::new(false),
            closed_sender,
        }
    }
}

#[async_trait::async_trait]
impl ByteStreamOutTunnelConnection for YamuxOutTunnelConnection {
    async fn accept(
        &self,
    ) -> anyhow::Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )> {
        match futures::future::poll_fn(|context| {
            self.connection.lock().unwrap().poll_next_inbound(context)
        })
        .await
        {
            Some(stream) => {
                let stream = stream?;

                let (read_stream, write_stream) = stream.split();

                Ok((
                    Box::new(read_stream.compat()),
                    Box::new(write_stream.compat_write()),
                ))
            }
            None => {
                self.closed
                    .store(true, std::sync::atomic::Ordering::Relaxed);

                self.closed_sender.send(())?;

                anyhow::bail!("yamux connection closed.");
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }
}
