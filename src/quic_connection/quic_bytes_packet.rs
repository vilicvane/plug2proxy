use std::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct QuicBytesPacket(Vec<u8>);

impl From<Vec<u8>> for QuicBytesPacket {
  fn from(value: Vec<u8>) -> Self {
    Self(value)
  }
}

impl Deref for QuicBytesPacket {
  type Target = Vec<u8>;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl DerefMut for QuicBytesPacket {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.0
  }
}
