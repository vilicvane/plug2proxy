use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt};

pub async fn read_postcard_from_stream<T>(
  stream: &mut (dyn AsyncRead + Unpin + Send),
) -> Result<T, ReadPostcardFromStreamError>
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

#[derive(thiserror::Error, Debug)]
pub enum ReadPostcardFromStreamError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Postcard deserialization error")]
  Deserialization(#[from] postcard::Error),
}
