use std::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct QuicBytesPacket {
  bytes: Vec<u8>,
  pub(crate) delivery: Option<quiche::ReliablePacket>,
  pub(crate) recv_order: Option<quiche::ReliableRecv>,
}

impl From<Vec<u8>> for QuicBytesPacket {
  fn from(value: Vec<u8>) -> Self {
    Self {
      bytes: value,
      delivery: None,
      recv_order: None,
    }
  }
}

impl Deref for QuicBytesPacket {
  type Target = Vec<u8>;

  fn deref(&self) -> &Self::Target {
    &self.bytes
  }
}

impl DerefMut for QuicBytesPacket {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.bytes
  }
}
