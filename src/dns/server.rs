use std::{net::SocketAddr, sync::Arc, time::Duration};

use hickory_server::{
  Server,
  net::runtime::Time,
  proto::{
    op::{Header, HeaderCounts, MessageType, Metadata, ResponseCode},
    rr::RecordType,
  },
  server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
  zone_handler::{Catalog, MessageResponseBuilder, ZoneHandler},
};
use lowkit::SerdeSocketAddress;
use serde::Deserialize;

use crate::{
  dns::RoutingZoneHandler, r#in::InLike, utils::serde::deserialize_listen_socket_address,
};

const TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_RESPONSE_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
  #[serde(deserialize_with = "deserialize_listen_socket_address")]
  pub listen: SerdeSocketAddress,
}

/// 运行 DNS 服务：按路由配置把域名解析代理到对应出口解析。
pub async fn run_dns_server(
  config: DnsConfig,
  node: Arc<dyn InLike + Send + Sync>,
) -> anyhow::Result<()> {
  // 尽早加载本机解析配置，配置错误在启动时直接 panic。
  super::local_resolver();

  let listen: SocketAddr = config.listen.into();

  let udp_socket = tokio::net::UdpSocket::bind(listen).await?;
  let tcp_listener = tokio::net::TcpListener::bind(listen).await?;

  let mut server = build_dns_server(node);
  server.register_socket(udp_socket);
  server.register_listener(tcp_listener, TCP_REQUEST_TIMEOUT, TCP_RESPONSE_BUFFER_SIZE);

  log::info!("DNS server listening on {listen} (UDP/TCP).");

  server.block_until_done().await?;

  Ok(())
}

pub(crate) fn build_dns_server(
  node: Arc<dyn InLike + Send + Sync>,
) -> Server<RoutingRequestHandler> {
  let handler = Arc::new(RoutingZoneHandler::new(node));

  let mut catalog = Catalog::new();
  catalog.upsert(handler.origin().clone(), vec![handler]);

  Server::new(RoutingRequestHandler { catalog })
}

/// Catalog 的 External zone 错误映射只会产生 ServFail，这里拦下不支持的
/// 查询类型，精确返回 NOTIMP。
pub(crate) struct RoutingRequestHandler {
  catalog: Catalog,
}

#[async_trait::async_trait]
impl RequestHandler for RoutingRequestHandler {
  async fn handle_request<R: ResponseHandler, T: Time>(
    &self,
    request: &Request,
    mut response_handle: R,
  ) -> ResponseInfo {
    let unsupported = request
      .request_info()
      .map(|info| {
        matches!(
          info.query.query_type(),
          RecordType::AXFR | RecordType::IXFR | RecordType::ANY
        )
      })
      .unwrap_or(false);

    if unsupported {
      let response = MessageResponseBuilder::new(&request.queries, request.edns.as_ref())
        .error_msg(&request.metadata, ResponseCode::NotImp);

      return match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(error) => {
          log::error!("failed to send NOTIMP response: {error}");

          let mut metadata = Metadata::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
          );
          metadata.response_code = ResponseCode::ServFail;

          ResponseInfo::from(Header {
            metadata,
            counts: HeaderCounts::default(),
          })
        }
      };
    }

    self
      .catalog
      .handle_request::<R, T>(request, response_handle)
      .await
  }
}

#[cfg(test)]
mod config_tests {
  use super::*;

  #[test]
  fn rejects_zero_listen_port() {
    let error = serde_json::from_str::<DnsConfig>(r#"{"listen":"127.0.0.1:0"}"#).unwrap_err();

    assert!(error.to_string().contains("listen port must be non-zero"));
  }
}
