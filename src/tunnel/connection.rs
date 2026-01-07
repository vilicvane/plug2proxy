use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use super::{FrameCodec, FrameError};

/// A framed TCP connection that sends and receives length-prefixed datagrams.
pub struct FramedConnection {
    framed: Framed<TcpStream, FrameCodec>,
}

impl FramedConnection {
    /// Wrap a TCP stream with the frame codec.
    pub fn new(stream: TcpStream) -> Self {
        Self {
            framed: Framed::new(stream, FrameCodec::new()),
        }
    }

    /// Send a datagram over this connection.
    pub async fn send(&mut self, data: Bytes) -> Result<(), ConnectionError> {
        self.framed.send(data).await?;
        Ok(())
    }

    /// Receive the next datagram from this connection.
    /// Returns `None` if the connection is closed.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, ConnectionError> {
        match self.framed.next().await {
            Some(Ok(data)) => Ok(Some(data)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Split this connection into separate send and receive halves.
    pub fn split(self) -> (ConnectionSender, ConnectionReceiver) {
        let (sink, stream) = self.framed.split();
        (ConnectionSender { sink }, ConnectionReceiver { stream })
    }

    /// Get a reference to the underlying TCP stream.
    pub fn get_ref(&self) -> &TcpStream {
        self.framed.get_ref()
    }

    /// Consume and return the underlying TCP stream.
    pub fn into_inner(self) -> TcpStream {
        self.framed.into_inner()
    }
}

/// The sending half of a split connection.
pub struct ConnectionSender {
    sink: futures::stream::SplitSink<Framed<TcpStream, FrameCodec>, Bytes>,
}

impl ConnectionSender {
    /// Send a datagram.
    pub async fn send(&mut self, data: Bytes) -> Result<(), ConnectionError> {
        self.sink.send(data).await?;
        Ok(())
    }

    /// Flush the underlying buffer.
    pub async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.sink.flush().await?;
        Ok(())
    }
}

/// The receiving half of a split connection.
pub struct ConnectionReceiver {
    stream: futures::stream::SplitStream<Framed<TcpStream, FrameCodec>>,
}

impl ConnectionReceiver {
    /// Receive the next datagram.
    /// Returns `None` if the connection is closed.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, ConnectionError> {
        match self.stream.next().await {
            Some(Ok(data)) => Ok(Some(data)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
