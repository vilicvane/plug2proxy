//! Exit module for OUT node - defines how traffic exits.
//!
//! Second-level routing: the `tag` from routing rules selects which exit to use.

mod config;
mod local;
mod socks5;

pub use config::{ExitConfig, ExitMap, LocalExitConfig, Socks5AuthConfig, Socks5ExitConfig};
pub use local::{LocalExit, LocalIpOrInterface};
pub use socks5::Socks5Exit;

use tokio::net::TcpStream;

/// Trait for different exit strategies.
#[async_trait::async_trait]
pub trait Exit: Send + Sync {
    /// Connect to the target through this exit.
    async fn connect(&self, target: &str) -> Result<TcpStream, ExitError>;
}

/// Direct exit - connects directly to the target.
#[derive(Default)]
pub struct DirectExit;

#[async_trait::async_trait]
impl Exit for DirectExit {
    async fn connect(&self, target: &str) -> Result<TcpStream, ExitError> {
        let stream = TcpStream::connect(target).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExitError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("socks5 error: {0}")]
    Socks5(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
}
