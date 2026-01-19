use lowkit::SelfWrapExt;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt};

pub async fn postcard_read_stream<T>(
  stream: &mut (impl AsyncRead + Unpin + Send),
) -> Result<T, PostcardStreamError>
where
  T: DeserializeOwned,
{
  let mut buffer = Vec::new();

  loop {
    let byte = stream.read_u8().await?;

    buffer.push(byte);

    match postcard::from_bytes::<T>(&buffer) {
      Ok(data) => return Ok(data),
      Err(error) => match error {
        postcard::Error::DeserializeUnexpectedEnd => continue,
        error => Err(error)?,
      },
    }
  }
}

pub async fn postcard_read_stream_to_end<T>(
  stream: &mut (impl AsyncRead + Unpin + Send),
) -> Result<T, PostcardStreamError>
where
  T: DeserializeOwned,
{
  let mut data = Vec::new();

  stream.read_to_end(&mut data).await?;

  postcard::from_bytes::<T>(&data)?.wrap_ok()
}

#[derive(thiserror::Error, Debug)]
pub enum PostcardStreamError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Postcard deserialization error")]
  Deserialization(#[from] postcard::Error),
}
