use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum frame size: 16MB
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// A length-prefixed frame codec for sending datagrams over TCP.
///
/// Frame format:
/// - 4 bytes: length (big-endian u32)
/// - N bytes: payload
#[derive(Debug, Clone, Default)]
pub struct FrameCodec;

impl FrameCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for FrameCodec {
    type Item = Bytes;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 4 bytes for the length prefix
        if src.len() < 4 {
            return Ok(None);
        }

        // Peek at the length without consuming
        let length = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;

        if length > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge {
                size: length,
                max: MAX_FRAME_SIZE,
            });
        }

        let total_length = 4 + length;

        if src.len() < total_length {
            // Reserve space for the full frame to avoid repeated allocations
            src.reserve(total_length - src.len());
            return Ok(None);
        }

        // Skip the length prefix
        src.advance(4);

        // Extract the payload
        let payload = src.split_to(length).freeze();

        Ok(Some(payload))
    }
}

impl Encoder<Bytes> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let length = item.len();

        if length > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge {
                size: length,
                max: MAX_FRAME_SIZE,
            });
        }

        dst.reserve(4 + length);
        dst.put_u32(length as u32);
        dst.put(item);

        Ok(())
    }
}

/// Also support encoding &[u8] directly for convenience
impl Encoder<&[u8]> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        let length = item.len();

        if length > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge {
                size: length,
                max: MAX_FRAME_SIZE,
            });
        }

        dst.reserve(4 + length);
        dst.put_u32(length as u32);
        dst.put_slice(item);

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too large: {size} bytes (max: {max})")]
    FrameTooLarge { size: usize, max: usize },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
