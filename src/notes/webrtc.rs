use std::sync::Arc;

use webrtc::{
    api::APIBuilder,
    ice_transport::ice_server::RTCIceServer,
    peer_connection::{
        configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
    },
    stats::PeerConnectionStats,
};

pub async fn test() -> anyhow::Result<()> {
    let api = APIBuilder::new().build();

    let config = RTCConfiguration {
        ice_servers: vec![RTCIceServer {
            urls: vec!["stun:stun.miwifi.com".to_owned()],
            ..Default::default()
        }],
        ..Default::default()
    };

    let peer_connection = api.new_peer_connection(config).await?;

    peer_connection.on_peer_connection_state_change(Box::new(|state| {
        println!("Peer connection state changed: {:?}", state);

        Box::pin(async {})
    }));

    let offer = peer_connection.create_offer(None).await?;

    println!("Offer: {:?}", offer);

    peer_connection.set_local_description(offer).await?;

    tokio::signal::ctrl_c().await?;

    Ok(())
}
