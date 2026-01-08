//! Output module for OUT node - defines how traffic exits.
//!
//! Second-level routing: the `tag` from routing rules selects which output to use.

mod config;
mod local;
mod socks5;

pub use config::{
    LocalOutputConfig, OutputConfig, OutputMap, Socks5AuthConfig, Socks5OutputConfig,
};
pub use local::{LocalIpOrInterface, LocalOutput};
pub use socks5::Socks5Output;

use tokio::net::TcpStream;

/// Trait for different output strategies.
#[async_trait::async_trait]
pub trait Output: Send + Sync {
    /// Connect to the target through this output.
    async fn connect(&self, target: &str) -> Result<TcpStream, OutputError>;
}

/// Direct output - connects directly to the target.
#[derive(Default)]
pub struct DirectOutput;

#[async_trait::async_trait]
impl Output for DirectOutput {
    async fn connect(&self, target: &str) -> Result<TcpStream, OutputError> {
        let stream = TcpStream::connect(target).await?;
        Ok(stream)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("socks5 error: {0}")]
    Socks5(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
}
