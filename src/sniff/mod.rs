use std::{
  io,
  net::{IpAddr, SocketAddr},
  pin::Pin,
  task::{Context, Poll},
  time::Duration,
};

use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
  time::{Instant, timeout_at},
};

const MAX_TLS_RECORD_PAYLOAD: usize = 18_432;
const MAX_TLS_CLIENT_HELLO: usize = 64 * 1024;
const MAX_HTTP_HEADER: usize = 64 * 1024;
const MAX_QUIC_DATAGRAMS: usize = 16;
const MAX_QUIC_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SniffedProtocol {
  Tls,
  Http,
  Quic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SniffedDomain {
  pub protocol: SniffedProtocol,
  pub domain: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SniffOutcome {
  NeedMoreData,
  Domain(SniffedDomain),
  NoDomain,
}

impl SniffOutcome {
  fn domain(protocol: SniffedProtocol, authority: &[u8]) -> Self {
    normalize_domain(authority)
      .map(|domain| SniffedDomain { protocol, domain })
      .map(Self::Domain)
      .unwrap_or(Self::NoDomain)
  }
}

#[derive(Clone, Copy, Debug)]
pub struct TcpSniffOptions {
  pub max_bytes: usize,
  pub timeout: Duration,
}

impl Default for TcpSniffOptions {
  fn default() -> Self {
    Self {
      max_bytes: MAX_TLS_CLIENT_HELLO.max(MAX_HTTP_HEADER),
      timeout: Duration::from_secs(1),
    }
  }
}

pub struct SniffedTcpStream<S> {
  pub domain: Option<SniffedDomain>,
  pub stream: ReplayStream<S>,
}

pub struct ReplayStream<S> {
  prefix: Vec<u8>,
  prefix_offset: usize,
  inner: S,
}

impl<S> ReplayStream<S> {
  fn new(prefix: Vec<u8>, inner: S) -> Self {
    Self {
      prefix,
      prefix_offset: 0,
      inner,
    }
  }

  pub fn into_inner(self) -> S {
    self.inner
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
    read_buffer: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    if self.prefix_offset < self.prefix.len() && read_buffer.remaining() > 0 {
      let available = &self.prefix[self.prefix_offset..];
      let length = available.len().min(read_buffer.remaining());
      read_buffer.put_slice(&available[..length]);
      self.prefix_offset += length;
      return Poll::Ready(Ok(()));
    }

    Pin::new(&mut self.inner).poll_read(context, read_buffer)
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
    buffer: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(context, buffer)
  }

  fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(context)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(context)
  }
}

pub async fn sniff_tcp_stream<S>(
  mut stream: S,
  options: TcpSniffOptions,
) -> io::Result<SniffedTcpStream<S>>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let max_bytes = options.max_bytes.max(1);
  let deadline = Instant::now() + options.timeout;
  let mut prefix = Vec::with_capacity(4096.min(max_bytes));
  let domain = loop {
    match sniff_tcp_prefix(&prefix) {
      SniffOutcome::Domain(domain) => break Some(domain),
      SniffOutcome::NoDomain => break None,
      SniffOutcome::NeedMoreData if prefix.len() >= max_bytes => break None,
      SniffOutcome::NeedMoreData => {}
    }

    let remaining = max_bytes - prefix.len();
    let mut buffer = vec![0; remaining.min(4096)];
    let read = match timeout_at(deadline, stream.read(&mut buffer)).await {
      Ok(result) => result?,
      Err(_) => break None,
    };

    if read == 0 {
      break None;
    }

    prefix.extend_from_slice(&buffer[..read]);
  };

  Ok(SniffedTcpStream {
    domain,
    stream: ReplayStream::new(prefix, stream),
  })
}

pub fn sniff_tcp_prefix(buffer: &[u8]) -> SniffOutcome {
  if buffer.is_empty() {
    return SniffOutcome::NeedMoreData;
  }

  if buffer[0] == 22 {
    return sniff_tls_client_hello(buffer);
  }

  sniff_http_request(buffer)
}

fn sniff_tls_client_hello(buffer: &[u8]) -> SniffOutcome {
  let mut record_offset = 0;
  let mut handshake = Vec::new();

  loop {
    if buffer.len().saturating_sub(record_offset) < 5 {
      return SniffOutcome::NeedMoreData;
    }

    if buffer[record_offset] != 22 {
      return SniffOutcome::NoDomain;
    }

    let legacy_version = u16::from_be_bytes([buffer[record_offset + 1], buffer[record_offset + 2]]);
    if !(0x0301..=0x0304).contains(&legacy_version) {
      return SniffOutcome::NoDomain;
    }

    let record_length =
      u16::from_be_bytes([buffer[record_offset + 3], buffer[record_offset + 4]]) as usize;
    if record_length == 0 || record_length > MAX_TLS_RECORD_PAYLOAD {
      return SniffOutcome::NoDomain;
    }

    let record_end = match record_offset
      .checked_add(5)
      .and_then(|offset| offset.checked_add(record_length))
    {
      Some(end) => end,
      None => return SniffOutcome::NoDomain,
    };
    if buffer.len() < record_end {
      return SniffOutcome::NeedMoreData;
    }

    handshake.extend_from_slice(&buffer[record_offset + 5..record_end]);
    if handshake.len() > MAX_TLS_CLIENT_HELLO {
      return SniffOutcome::NoDomain;
    }

    if handshake.len() >= 4 {
      if handshake[0] != 1 {
        return SniffOutcome::NoDomain;
      }

      let hello_length =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
      if hello_length > MAX_TLS_CLIENT_HELLO {
        return SniffOutcome::NoDomain;
      }

      if handshake.len() >= hello_length + 4 {
        return parse_tls_client_hello(&handshake[4..hello_length + 4]);
      }
    }

    record_offset = record_end;
    if record_offset == buffer.len() {
      return SniffOutcome::NeedMoreData;
    }
  }
}

fn parse_tls_client_hello(hello: &[u8]) -> SniffOutcome {
  let mut cursor = SliceCursor::new(hello);

  if cursor.take(2).is_none() || cursor.take(32).is_none() {
    return SniffOutcome::NoDomain;
  }

  if cursor.take_u8_length_prefixed().is_none()
    || cursor.take_u16_length_prefixed().is_none()
    || cursor.take_u8_length_prefixed().is_none()
  {
    return SniffOutcome::NoDomain;
  }

  let Some(extensions) = cursor.take_u16_length_prefixed() else {
    return SniffOutcome::NoDomain;
  };
  let mut extensions = SliceCursor::new(extensions);

  while !extensions.is_empty() {
    let Some(extension_type) = extensions.take_u16() else {
      return SniffOutcome::NoDomain;
    };
    let Some(extension_payload) = extensions.take_u16_length_prefixed() else {
      return SniffOutcome::NoDomain;
    };

    if extension_type != 0 {
      continue;
    }

    let mut names = SliceCursor::new(extension_payload);
    let Some(names) = names.take_u16_length_prefixed() else {
      return SniffOutcome::NoDomain;
    };
    let mut names = SliceCursor::new(names);

    while !names.is_empty() {
      let Some(name_type) = names.take_u8() else {
        return SniffOutcome::NoDomain;
      };
      let Some(name) = names.take_u16_length_prefixed() else {
        return SniffOutcome::NoDomain;
      };

      if name_type == 0 {
        return SniffOutcome::domain(SniffedProtocol::Tls, name);
      }
    }

    return SniffOutcome::NoDomain;
  }

  SniffOutcome::NoDomain
}

fn sniff_http_request(buffer: &[u8]) -> SniffOutcome {
  let Some(first_space) = buffer.iter().position(|byte| *byte == b' ') else {
    return if buffer.len() <= 32
      && buffer
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || *byte == b'-')
    {
      SniffOutcome::NeedMoreData
    } else {
      SniffOutcome::NoDomain
    };
  };

  if first_space == 0
    || first_space > 32
    || !buffer[..first_space]
      .iter()
      .all(|byte| byte.is_ascii_uppercase() || *byte == b'-')
  {
    return SniffOutcome::NoDomain;
  }

  let Some(header_end) = find_bytes(buffer, b"\r\n\r\n") else {
    return if buffer.len() < MAX_HTTP_HEADER {
      SniffOutcome::NeedMoreData
    } else {
      SniffOutcome::NoDomain
    };
  };
  let header = &buffer[..header_end + 4];
  let Some(request_line_end) = find_bytes(header, b"\r\n") else {
    return SniffOutcome::NoDomain;
  };
  let request_line = &header[..request_line_end];
  let mut request_parts = request_line.split(|byte| *byte == b' ');
  let Some(method) = request_parts.next() else {
    return SniffOutcome::NoDomain;
  };
  let Some(target) = request_parts.next() else {
    return SniffOutcome::NoDomain;
  };
  let Some(version) = request_parts.next() else {
    return SniffOutcome::NoDomain;
  };
  if request_parts.next().is_some() || !version.starts_with(b"HTTP/") {
    return SniffOutcome::NoDomain;
  }

  let headers_start = request_line_end + 2;
  if headers_start <= header_end {
    for line in header[headers_start..header_end].split(|byte| *byte == b'\n') {
      let line = line.strip_suffix(b"\r").unwrap_or(line);
      let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        continue;
      };
      if line[..colon].eq_ignore_ascii_case(b"host") {
        return SniffOutcome::domain(SniffedProtocol::Http, trim_ascii(&line[colon + 1..]));
      }
    }
  }

  if method == b"CONNECT" {
    return SniffOutcome::domain(SniffedProtocol::Http, target);
  }

  if let Some(authority) = absolute_uri_authority(target) {
    return SniffOutcome::domain(SniffedProtocol::Http, authority);
  }

  SniffOutcome::NoDomain
}

fn absolute_uri_authority(target: &[u8]) -> Option<&[u8]> {
  let remainder = if target.len() >= 7 && target[..7].eq_ignore_ascii_case(b"http://") {
    &target[7..]
  } else if target.len() >= 8 && target[..8].eq_ignore_ascii_case(b"https://") {
    &target[8..]
  } else {
    return None;
  };

  let end = remainder
    .iter()
    .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
    .unwrap_or(remainder.len());
  Some(&remainder[..end])
}

fn normalize_domain(authority: &[u8]) -> Option<String> {
  let authority = trim_ascii(authority);
  let authority = if authority.starts_with(b"[") {
    let closing = authority.iter().position(|byte| *byte == b']')?;
    if authority[closing + 1..].is_empty()
      || (authority[closing + 1] == b':' && authority[closing + 2..].iter().all(u8::is_ascii_digit))
    {
      &authority[1..closing]
    } else {
      return None;
    }
  } else if authority.iter().filter(|byte| **byte == b':').count() == 1 {
    let colon = authority.iter().position(|byte| *byte == b':')?;
    if !authority[colon + 1..].is_empty() && authority[colon + 1..].iter().all(u8::is_ascii_digit) {
      &authority[..colon]
    } else {
      authority
    }
  } else {
    authority
  };

  let authority = authority.strip_suffix(b".").unwrap_or(authority);
  if authority.is_empty() || authority.len() > 253 || !authority.is_ascii() {
    return None;
  }

  let domain = std::str::from_utf8(authority).ok()?.to_ascii_lowercase();
  if domain.parse::<IpAddr>().is_ok()
    || domain.split('.').any(|label| {
      label.is_empty()
        || label.len() > 63
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
  {
    return None;
  }

  Some(domain)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
  while value.first().is_some_and(u8::is_ascii_whitespace) {
    value = &value[1..];
  }
  while value.last().is_some_and(u8::is_ascii_whitespace) {
    value = &value[..value.len() - 1];
  }
  value
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  haystack
    .windows(needle.len())
    .position(|window| window == needle)
}

struct SliceCursor<'a> {
  remaining: &'a [u8],
}

impl<'a> SliceCursor<'a> {
  fn new(remaining: &'a [u8]) -> Self {
    Self { remaining }
  }

  fn is_empty(&self) -> bool {
    self.remaining.is_empty()
  }

  fn take(&mut self, length: usize) -> Option<&'a [u8]> {
    let (value, remaining) = self.remaining.split_at_checked(length)?;
    self.remaining = remaining;
    Some(value)
  }

  fn take_u8(&mut self) -> Option<u8> {
    Some(self.take(1)?[0])
  }

  fn take_u16(&mut self) -> Option<u16> {
    let bytes = self.take(2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
  }

  fn take_u8_length_prefixed(&mut self) -> Option<&'a [u8]> {
    let length = self.take_u8()? as usize;
    self.take(length)
  }

  fn take_u16_length_prefixed(&mut self) -> Option<&'a [u8]> {
    let length = self.take_u16()? as usize;
    self.take(length)
  }
}

pub struct QuicSniffer {
  connection: Option<quiche::Connection>,
  datagrams: usize,
  bytes: usize,
  finished: bool,
}

impl Default for QuicSniffer {
  fn default() -> Self {
    Self::new()
  }
}

impl QuicSniffer {
  pub fn new() -> Self {
    Self {
      connection: None,
      datagrams: 0,
      bytes: 0,
      finished: false,
    }
  }

  pub fn looks_like_initial(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|first| first & 0xc0 == 0xc0)
  }

  pub fn is_finished(&self) -> bool {
    self.finished
  }

  pub fn sniff_datagram(
    &mut self,
    datagram: &[u8],
    source: SocketAddr,
    destination: SocketAddr,
  ) -> SniffOutcome {
    if self.finished
      || self.datagrams >= MAX_QUIC_DATAGRAMS
      || self.bytes.saturating_add(datagram.len()) > MAX_QUIC_BYTES
    {
      self.finished = true;
      return SniffOutcome::NoDomain;
    }

    self.datagrams += 1;
    self.bytes += datagram.len();

    let mut packet = datagram.to_vec();
    if self.connection.is_none() {
      let Ok(header) = quiche::Header::from_slice(&mut packet, quiche::MAX_CONN_ID_LEN) else {
        self.finished = true;
        return SniffOutcome::NoDomain;
      };
      if header.ty != quiche::Type::Initial || !quiche::version_is_supported(header.version) {
        self.finished = true;
        return SniffOutcome::NoDomain;
      }

      let Ok(mut config) = quiche::Config::new(header.version) else {
        self.finished = true;
        return SniffOutcome::NoDomain;
      };
      if config
        .set_application_protos(&[b"h3", b"h3-29", b"h3-32", b"hq-interop", b"doq"])
        .is_err()
      {
        self.finished = true;
        return SniffOutcome::NoDomain;
      }

      let Ok(connection) = quiche::accept(&header.dcid, None, destination, source, &mut config)
      else {
        self.finished = true;
        return SniffOutcome::NoDomain;
      };
      self.connection = Some(connection);
    }

    let connection = self.connection.as_mut().unwrap();
    let _ = connection.recv(
      &mut packet,
      quiche::RecvInfo {
        from: source,
        to: destination,
      },
    );

    if let Some(domain) = connection.server_name() {
      self.finished = true;
      return SniffOutcome::domain(SniffedProtocol::Quic, domain.as_bytes());
    }

    if connection.is_closed() {
      self.finished = true;
      SniffOutcome::NoDomain
    } else {
      SniffOutcome::NeedMoreData
    }
  }
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  use super::*;

  fn tls_client_hello(domain: &str) -> Vec<u8> {
    let name = domain.as_bytes();
    let mut server_name = Vec::new();
    server_name.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    server_name.push(0);
    server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
    server_name.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0_u16.to_be_bytes());
    extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&server_name);

    let mut hello = Vec::new();
    hello.extend_from_slice(&0x0303_u16.to_be_bytes());
    hello.extend_from_slice(&[7; 32]);
    hello.push(0);
    hello.extend_from_slice(&2_u16.to_be_bytes());
    hello.extend_from_slice(&0x1301_u16.to_be_bytes());
    hello.push(1);
    hello.push(0);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    handshake.extend_from_slice(&[
      ((hello.len() >> 16) & 0xff) as u8,
      ((hello.len() >> 8) & 0xff) as u8,
      (hello.len() & 0xff) as u8,
    ]);
    handshake.extend_from_slice(&hello);

    tls_record(&handshake)
  }

  fn tls_record(payload: &[u8]) -> Vec<u8> {
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
  }

  #[test]
  fn sniffs_tls_sni() {
    assert_eq!(
      sniff_tcp_prefix(&tls_client_hello("C2C.CDN.WEIXIN.QQ.COM.")),
      SniffOutcome::Domain(SniffedDomain {
        protocol: SniffedProtocol::Tls,
        domain: "c2c.cdn.weixin.qq.com".to_owned(),
      })
    );
  }

  #[test]
  fn reassembles_client_hello_across_tls_records() {
    let packet = tls_client_hello("example.com");
    let handshake = &packet[5..];
    let split = 17;
    let mut records = tls_record(&handshake[..split]);
    records.extend_from_slice(&tls_record(&handshake[split..]));

    assert_eq!(
      sniff_tcp_prefix(&records),
      SniffOutcome::Domain(SniffedDomain {
        protocol: SniffedProtocol::Tls,
        domain: "example.com".to_owned(),
      })
    );
  }

  #[test]
  fn every_tls_prefix_is_safe_and_requests_more_data() {
    let packet = tls_client_hello("example.com");
    for length in 0..packet.len() {
      assert_eq!(
        sniff_tcp_prefix(&packet[..length]),
        SniffOutcome::NeedMoreData,
        "prefix length {length}"
      );
    }
  }

  #[test]
  fn malformed_tls_lengths_fail_open() {
    let mut packet = tls_client_hello("example.com");
    packet[3..5].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(sniff_tcp_prefix(&packet), SniffOutcome::NoDomain);

    let mut packet = tls_client_hello("example.com");
    packet[6..9].copy_from_slice(&[0xff, 0xff, 0xff]);
    assert_eq!(sniff_tcp_prefix(&packet), SniffOutcome::NoDomain);
  }

  #[test]
  fn sniffs_http_host_connect_and_absolute_form() {
    for (request, domain) in [
      (
        b"GET /image HTTP/1.1\r\nhOsT: C2C.CDN.WEIXIN.QQ.COM:443\r\n\r\n".as_slice(),
        "c2c.cdn.weixin.qq.com",
      ),
      (
        b"CONNECT passkeys.example.com:443 HTTP/1.1\r\n\r\n".as_slice(),
        "passkeys.example.com",
      ),
      (
        b"GET https://absolute.example/path HTTP/1.1\r\nUser-Agent: test\r\n\r\n".as_slice(),
        "absolute.example",
      ),
    ] {
      assert_eq!(
        sniff_tcp_prefix(request),
        SniffOutcome::Domain(SniffedDomain {
          protocol: SniffedProtocol::Http,
          domain: domain.to_owned(),
        })
      );
    }
  }

  #[test]
  fn http_partial_and_non_protocol_data_are_distinguished() {
    assert_eq!(
      sniff_tcp_prefix(b"POST / HTTP/1.1\r\nHost: example.com\r\n"),
      SniffOutcome::NeedMoreData
    );
    assert_eq!(
      sniff_tcp_prefix(b"\x01\x02\x03\x04"),
      SniffOutcome::NoDomain
    );
    assert_eq!(
      sniff_tcp_prefix(b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n"),
      SniffOutcome::NoDomain
    );
  }

  #[test]
  fn every_http_prefix_is_safe() {
    let request = b"GET /image HTTP/1.1\r\nHost: c2c.cdn.weixin.qq.com:443\r\n\r\n";
    for length in 0..request.len() {
      assert_eq!(
        sniff_tcp_prefix(&request[..length]),
        SniffOutcome::NeedMoreData,
        "prefix length {length}"
      );
    }
  }

  #[tokio::test]
  async fn async_sniffer_replays_every_byte_and_delegates_writes() -> anyhow::Result<()> {
    let payload = tls_client_hello("example.com");
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    let sent_payload = payload.clone();
    let sender = tokio::spawn(async move {
      for chunk in sent_payload.chunks(7) {
        client.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
      }
      let mut response = [0; 4];
      client.read_exact(&mut response).await.unwrap();
      response
    });

    let sniffed = sniff_tcp_stream(
      server,
      TcpSniffOptions {
        max_bytes: 64 * 1024,
        timeout: Duration::from_secs(1),
      },
    )
    .await?;
    assert_eq!(
      sniffed.domain,
      Some(SniffedDomain {
        protocol: SniffedProtocol::Tls,
        domain: "example.com".to_owned(),
      })
    );

    let mut replay = sniffed.stream;
    let mut received = vec![0; payload.len()];
    replay.read_exact(&mut received).await?;
    assert_eq!(received, payload);
    replay.write_all(b"pong").await?;
    assert_eq!(sender.await?, *b"pong");
    Ok(())
  }

  #[tokio::test]
  async fn async_sniffer_timeout_replays_partial_data() -> anyhow::Result<()> {
    let (mut client, server) = tokio::io::duplex(1024);
    let partial = b"GET / HTTP/1.1\r\nHost: examp";
    client.write_all(partial).await?;

    let sniffed = sniff_tcp_stream(
      server,
      TcpSniffOptions {
        max_bytes: 1024,
        timeout: Duration::from_millis(10),
      },
    )
    .await?;
    assert_eq!(sniffed.domain, None);

    let mut replay = sniffed.stream;
    let mut received = vec![0; partial.len()];
    replay.read_exact(&mut received).await?;
    assert_eq!(received, partial);
    Ok(())
  }

  #[test]
  fn sniffs_quic_v1_client_hello() -> anyhow::Result<()> {
    let source: SocketAddr = "127.0.0.1:12345".parse()?;
    let destination: SocketAddr = "127.0.0.1:443".parse()?;
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_application_protos(&[b"h3"])?;
    let source_connection_id = quiche::ConnectionId::from_ref(&[0x42; 16]);
    let mut client = quiche::connect(
      Some("passkeys.example.com"),
      &source_connection_id,
      source,
      destination,
      &mut config,
    )?;
    let mut packet = vec![0; 1350];
    let (length, _) = client.send(&mut packet)?;

    let mut sniffer = QuicSniffer::new();
    assert_eq!(
      sniffer.sniff_datagram(&packet[..length], source, destination),
      SniffOutcome::Domain(SniffedDomain {
        protocol: SniffedProtocol::Quic,
        domain: "passkeys.example.com".to_owned(),
      })
    );
    Ok(())
  }

  #[test]
  fn invalid_quic_datagrams_fail_open_without_panicking() {
    let source = "127.0.0.1:12345".parse().unwrap();
    let destination = "127.0.0.1:443".parse().unwrap();
    for length in 0..64 {
      let mut sniffer = QuicSniffer::new();
      assert_eq!(
        sniffer.sniff_datagram(&vec![0xff; length], source, destination),
        SniffOutcome::NoDomain
      );
    }
  }
}
