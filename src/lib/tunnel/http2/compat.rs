use std::{
    cmp::min,
    pin::Pin,
    task::{ready, Context, Poll},
};

use bytes::Buf;
use futures::FutureExt;

#[derive(derive_more::From)]
pub enum ResponseFutureOrRecvStream {
    ResponseFuture(h2::client::ResponseFuture),
    RecvStream(h2::RecvStream),
}

pub struct H2RecvStreamAsyncRead {
    inner: ResponseFutureOrRecvStream,
    pending: bytes::BytesMut,
}

impl H2RecvStreamAsyncRead {
    pub fn new(inner: impl Into<ResponseFutureOrRecvStream>) -> Self {
        Self {
            inner: inner.into(),
            pending: bytes::BytesMut::new(),
        }
    }
}

impl tokio::io::AsyncRead for H2RecvStreamAsyncRead {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();

        let pending = &mut this.pending;

        if !pending.is_empty() {
            let length = min(pending.len(), buffer.remaining());

            buffer.put_slice(&pending[..length]);

            pending.advance(length);

            context.waker().wake_by_ref();

            return Poll::Ready(Ok(()));
        }

        loop {
            break match &mut this.inner {
                ResponseFutureOrRecvStream::ResponseFuture(response_future) => {
                    let response = ready!(response_future.poll_unpin(context))
                        .map_err(h2_error_to_io_error)?;

                    let body = response.into_body();

                    this.inner = ResponseFutureOrRecvStream::RecvStream(body);

                    continue;
                }
                ResponseFutureOrRecvStream::RecvStream(recv_stream) => {
                    if let Some(data) = ready!(recv_stream.poll_data(context)) {
                        let data = data.map_err(h2_error_to_io_error)?;

                        if data.len() < buffer.remaining() {
                            buffer.put_slice(&data);
                        } else {
                            let length = buffer.remaining();

                            buffer.put_slice(&data[..length]);

                            pending.extend_from_slice(&data[length..]);
                        }

                        recv_stream
                            .flow_control()
                            .release_capacity(data.len())
                            .map_err(h2_error_to_io_error)?;

                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Ok(()))
                    }
                }
            };
        }
    }
}

pub struct H2SendStreamAsyncWrite {
    send_stream: h2::SendStream<bytes::Bytes>,
}

impl H2SendStreamAsyncWrite {
    pub fn new(send_stream: h2::SendStream<bytes::Bytes>) -> Self {
        Self { send_stream }
    }
}

impl tokio::io::AsyncWrite for H2SendStreamAsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context,
        buffer: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        while this.send_stream.capacity() == 0 {
            this.send_stream.reserve_capacity(buffer.len());

            match ready!(this.send_stream.poll_capacity(context)) {
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    return Poll::Ready(Err(h2_error_to_io_error(error)));
                }
                None => {
                    // stream closed.
                    return Poll::Ready(Ok(0));
                }
            }
        }

        let length = min(this.send_stream.capacity(), buffer.len());

        match this
            .send_stream
            .send_data(buffer[..length].to_vec().into(), false)
        {
            Ok(_) => Poll::Ready(Ok(length)),
            Err(error) => Poll::Ready(Err(h2_error_to_io_error(error))),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _context: &mut Context,
    ) -> Poll<Result<(), tokio::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context,
    ) -> Poll<Result<(), tokio::io::Error>> {
        let this = self.get_mut();

        match this.send_stream.send_data(bytes::Bytes::new(), true) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(h2_error_to_io_error(error))),
        }
    }
}

fn h2_error_to_io_error(error: h2::Error) -> std::io::Error {
    if error.is_io() {
        error.into_io().unwrap()
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, error.to_string())
    }
}
