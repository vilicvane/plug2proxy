use std::net::SocketAddr;

#[async_trait::async_trait]
pub trait MatchServer {
    async fn match_server(
        &self,
        id: &MatchPeerId,
        address: SocketAddr,
    ) -> anyhow::Result<SocketAddr>;

    async fn match_client(
        &self,
        id: &MatchPeerId,
        address: SocketAddr,
    ) -> anyhow::Result<SocketAddr>;
}

#[derive(
    Clone, Debug, derive_more::From, derive_more::Into, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct MatchPeerId(pub String);
