use tokio::io::{AsyncRead, AsyncWrite};

pub trait BidiStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> BidiStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}
