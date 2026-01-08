//! SOCKS5 output - routes traffic through a SOCKS5 proxy.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{Output, OutputError};

/// SOCKS5 output that routes through another SOCKS5 proxy.
pub struct Socks5Output {
    /// SOCKS5 proxy address.
    proxy_addr: SocketAddr,
    /// Optional authentication.
    auth: Option<(String, String)>,
}

impl Socks5Output {
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            auth: None,
        }
    }

    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.auth = Some((username, password));
        self
    }
}

#[async_trait::async_trait]
impl Output for Socks5Output {
    async fn connect(&self, target: &str) -> Result<TcpStream, OutputError> {
        // Connect to SOCKS5 proxy
        let mut stream = TcpStream::connect(self.proxy_addr).await?;

        // Parse target
        let (host, port) = parse_target(target)?;

        // SOCKS5 handshake
        if self.auth.is_some() {
            // Offer both no-auth and username/password auth
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            // Only offer no-auth
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        // Read auth method selection
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != 0x05 {
            return Err(OutputError::Socks5("invalid SOCKS version".to_string()));
        }

        match buf[1] {
            0x00 => {
                // No authentication required
            }
            0x02 => {
                // Username/password authentication
                let (username, password) = self
                    .auth
                    .as_ref()
                    .ok_or_else(|| OutputError::Socks5("auth required but not provided".to_string()))?;

                // Send auth request
                let mut auth_req = vec![0x01]; // Version
                auth_req.push(username.len() as u8);
                auth_req.extend_from_slice(username.as_bytes());
                auth_req.push(password.len() as u8);
                auth_req.extend_from_slice(password.as_bytes());
                stream.write_all(&auth_req).await?;

                // Read auth response
                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;

                if auth_resp[1] != 0x00 {
                    return Err(OutputError::Socks5("authentication failed".to_string()));
                }
            }
            0xFF => {
                return Err(OutputError::Socks5("no acceptable auth method".to_string()));
            }
            _ => {
                return Err(OutputError::Socks5(format!(
                    "unsupported auth method: {}",
                    buf[1]
                )));
            }
        }

        // Send connect request
        let mut connect_req = vec![
            0x05, // SOCKS5
            0x01, // CONNECT
            0x00, // Reserved
        ];

        // Add address
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            connect_req.push(0x01); // IPv4
            connect_req.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            connect_req.push(0x04); // IPv6
            connect_req.extend_from_slice(&ip.octets());
        } else {
            connect_req.push(0x03); // Domain
            connect_req.push(host.len() as u8);
            connect_req.extend_from_slice(host.as_bytes());
        }

        // Add port
        connect_req.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&connect_req).await?;

        // Read connect response
        let mut resp_header = [0u8; 4];
        stream.read_exact(&mut resp_header).await?;

        if resp_header[0] != 0x05 {
            return Err(OutputError::Socks5("invalid SOCKS version in response".to_string()));
        }

        if resp_header[1] != 0x00 {
            let error_msg = match resp_header[1] {
                0x01 => "general SOCKS server failure",
                0x02 => "connection not allowed by ruleset",
                0x03 => "network unreachable",
                0x04 => "host unreachable",
                0x05 => "connection refused",
                0x06 => "TTL expired",
                0x07 => "command not supported",
                0x08 => "address type not supported",
                _ => "unknown error",
            };
            return Err(OutputError::Socks5(error_msg.to_string()));
        }

        // Read bound address (skip it)
        match resp_header[3] {
            0x01 => {
                // IPv4
                let mut addr = [0u8; 6]; // 4 bytes IP + 2 bytes port
                stream.read_exact(&mut addr).await?;
            }
            0x04 => {
                // IPv6
                let mut addr = [0u8; 18]; // 16 bytes IP + 2 bytes port
                stream.read_exact(&mut addr).await?;
            }
            0x03 => {
                // Domain
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize + 2]; // domain + 2 bytes port
                stream.read_exact(&mut domain).await?;
            }
            _ => {
                return Err(OutputError::Socks5(format!(
                    "invalid address type: {}",
                    resp_header[3]
                )));
            }
        }

        Ok(stream)
    }
}

/// Parse target string into host and port.
fn parse_target(target: &str) -> Result<(&str, u16), OutputError> {
    // Handle IPv6 addresses in brackets
    if target.starts_with('[') {
        if let Some(bracket_end) = target.find(']') {
            let host = &target[1..bracket_end];
            let rest = &target[bracket_end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                let port = port_str
                    .parse()
                    .map_err(|_| OutputError::InvalidTarget(format!("invalid port: {}", port_str)))?;
                return Ok((host, port));
            }
        }
        return Err(OutputError::InvalidTarget(format!(
            "invalid IPv6 address format: {}",
            target
        )));
    }

    // Standard host:port
    if let Some(colon_pos) = target.rfind(':') {
        let host = &target[..colon_pos];
        let port_str = &target[colon_pos + 1..];
        let port = port_str
            .parse()
            .map_err(|_| OutputError::InvalidTarget(format!("invalid port: {}", port_str)))?;
        Ok((host, port))
    } else {
        Err(OutputError::InvalidTarget(format!(
            "missing port in target: {}",
            target
        )))
    }
}
