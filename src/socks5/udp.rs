use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// SOCKS5 UDP packet header format:
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// A parsed SOCKS5 UDP packet.
#[derive(Debug, Clone)]
pub struct Socks5UdpPacket {
    /// Fragment number (usually 0 for non-fragmented packets)
    pub frag: u8,
    /// Destination address
    pub dest_addr: SocketAddr,
    /// Payload data
    pub data: Bytes,
}

impl Socks5UdpPacket {
    /// Parse a SOCKS5 UDP packet from bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, Socks5UdpError> {
        if buf.len() < 10 {
            // Minimum: 2 (RSV) + 1 (FRAG) + 1 (ATYP) + 4 (IPv4) + 2 (PORT)
            return Err(Socks5UdpError::PacketTooShort);
        }

        let mut cursor = Cursor::new(buf);

        // RSV - must be 0x0000
        let rsv = cursor.get_u16();
        if rsv != 0 {
            return Err(Socks5UdpError::InvalidReserved);
        }

        // FRAG
        let frag = cursor.get_u8();

        // ATYP
        let atyp = cursor.get_u8();

        // DST.ADDR
        let dest_addr = match atyp {
            ATYP_IPV4 => {
                if cursor.remaining() < 6 {
                    // 4 bytes IP + 2 bytes port
                    return Err(Socks5UdpError::PacketTooShort);
                }
                let ip = Ipv4Addr::new(
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                );
                let port = cursor.get_u16();
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            ATYP_IPV6 => {
                if cursor.remaining() < 18 {
                    // 16 bytes IP + 2 bytes port
                    return Err(Socks5UdpError::PacketTooShort);
                }
                let mut octets = [0u8; 16];
                cursor.copy_to_slice(&mut octets);
                let ip = Ipv6Addr::from(octets);
                let port = cursor.get_u16();
                SocketAddr::new(IpAddr::V6(ip), port)
            }
            ATYP_DOMAIN => {
                if cursor.remaining() < 1 {
                    return Err(Socks5UdpError::PacketTooShort);
                }
                let len = cursor.get_u8() as usize;
                if cursor.remaining() < len + 2 {
                    return Err(Socks5UdpError::PacketTooShort);
                }
                let mut domain_bytes = vec![0u8; len];
                cursor.copy_to_slice(&mut domain_bytes);
                let domain =
                    String::from_utf8(domain_bytes).map_err(|_| Socks5UdpError::InvalidDomain)?;
                let port = cursor.get_u16();

                // For domain names, we need to resolve them
                // For now, return an error - domain support requires DNS resolution
                return Err(Socks5UdpError::DomainNotSupported(domain, port));
            }
            _ => return Err(Socks5UdpError::InvalidAddressType),
        };

        // Remaining bytes are the data
        let data = Bytes::copy_from_slice(&buf[cursor.position() as usize..]);

        Ok(Self {
            frag,
            dest_addr,
            data,
        })
    }

    /// Encode a SOCKS5 UDP packet into bytes.
    ///
    /// This creates a packet with:
    /// - RSV = 0x0000
    /// - FRAG = 0 (no fragmentation)
    /// - ATYP, DST.ADDR, DST.PORT from source_addr
    /// - DATA from data
    pub fn encode(source_addr: SocketAddr, data: &[u8]) -> Bytes {
        let mut buf = BytesMut::new();

        // RSV
        buf.put_u16(0);

        // FRAG
        buf.put_u8(0);

        // ATYP + DST.ADDR
        match source_addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&ip.octets());
            }
        }

        // DST.PORT
        buf.put_u16(source_addr.port());

        // DATA
        buf.put_slice(data);

        buf.freeze()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Socks5UdpError {
    #[error("packet too short")]
    PacketTooShort,
    #[error("invalid reserved field")]
    InvalidReserved,
    #[error("invalid address type")]
    InvalidAddressType,
    #[error("invalid domain name")]
    InvalidDomain,
    #[error("domain names not supported (yet): {0}:{1}")]
    DomainNotSupported(String, u16),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_packet() {
        // RSV(0x0000) + FRAG(0x00) + ATYP(0x01) + IP(192.168.1.1) + PORT(8080) + DATA(hello)
        let data = vec![
            0x00, 0x00, // RSV
            0x00, // FRAG
            0x01, // ATYP (IPv4)
            192, 168, 1, 1, // IP
            0x1f, 0x90, // PORT (8080)
            b'h', b'e', b'l', b'l', b'o', // DATA
        ];

        let packet = Socks5UdpPacket::parse(&data).unwrap();
        assert_eq!(packet.frag, 0);
        assert_eq!(
            packet.dest_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080)
        );
        assert_eq!(packet.data.as_ref(), b"hello");
    }

    #[test]
    fn test_encode_ipv4_packet() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let data = b"hello";

        let encoded = Socks5UdpPacket::encode(addr, data);

        let expected = vec![
            0x00, 0x00, // RSV
            0x00, // FRAG
            0x01, // ATYP (IPv4)
            192, 168, 1, 1, // IP
            0x1f, 0x90, // PORT (8080)
            b'h', b'e', b'l', b'l', b'o', // DATA
        ];

        assert_eq!(encoded.as_ref(), &expected[..]);
    }

    #[test]
    fn test_parse_encode_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53);
        let data = b"DNS query";

        let encoded = Socks5UdpPacket::encode(addr, data);
        let parsed = Socks5UdpPacket::parse(&encoded).unwrap();

        assert_eq!(parsed.dest_addr, addr);
        assert_eq!(parsed.data.as_ref(), data);
    }
}
