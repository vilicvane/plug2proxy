use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    routing::router::Router,
    tunnel::{InTunnel, TunnelId},
    tunnel_provider::InTunnelProvider,
};

use super::direct_in_tunnel::DirectInTunnel;

type TunnelMap = HashMap<TunnelId, Arc<Box<dyn InTunnel>>>;
type LabelToTunnelsMap = HashMap<String, Vec<Arc<Box<dyn InTunnel>>>>;

pub struct TunnelManager {
    pub accept_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    direct_tunnel: Arc<Box<dyn InTunnel>>,
    label_to_tunnels_map: Arc<tokio::sync::Mutex<LabelToTunnelsMap>>,
}

impl TunnelManager {
    pub fn new(tunnel_provider: Box<dyn InTunnelProvider + Send>, router: Arc<Router>) -> Self {
        let label_to_tunnels_map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        let accept_handle = tokio::spawn({
            let label_to_tunnels_map = Arc::clone(&label_to_tunnels_map);

            async move {
                let tunnel_map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

                loop {
                    if let Ok((tunnel, out_routing_rules)) = tunnel_provider.accept().await {
                        let tunnel_id = tunnel.id();
                        let tunnel = Arc::new(tunnel);

                        {
                            let mut tunnel_map = tunnel_map.lock().await;

                            tunnel_map.insert(tunnel_id, Arc::clone(&tunnel));

                            let mut label_to_tunnels_map = label_to_tunnels_map.lock().await;

                            Self::update_label_to_tunnels_map(
                                &tunnel_map,
                                &mut label_to_tunnels_map,
                            );

                            router
                                .register_tunnel(tunnel_id, out_routing_rules, tunnel.priority())
                                .await;
                        }

                        tokio::spawn({
                            let tunnel_map = tunnel_map.clone();
                            let label_to_tunnels_map = label_to_tunnels_map.clone();

                            let router = router.clone();

                            async move {
                                tunnel.closed().await;

                                let mut tunnel_map = tunnel_map.lock().await;

                                tunnel_map.remove(&tunnel_id);

                                let mut label_to_tunnels_map = label_to_tunnels_map.lock().await;

                                Self::update_label_to_tunnels_map(
                                    &tunnel_map,
                                    &mut label_to_tunnels_map,
                                );

                                router.unregister_tunnel(tunnel_id).await;
                            }
                        });
                    }
                }
            }
        });

        Self {
            accept_handle: Mutex::new(Some(accept_handle)),
            direct_tunnel: Arc::new(Box::new(DirectInTunnel::new())),
            label_to_tunnels_map,
        }
    }

    pub async fn select_tunnel(&self, labels: &[String]) -> Option<Arc<Box<dyn InTunnel>>> {
        let label_to_tunnels_map = self.label_to_tunnels_map.lock().await;

        let mut proxy_label_exists = false;

        for label in labels {
            match label.as_str() {
                "DIRECT" => return Some(self.direct_tunnel.clone()),
                "PROXY" => {
                    proxy_label_exists = true;
                }
                _ => {
                    if let Some(tunnels) = label_to_tunnels_map.get(label) {
                        if let Some(tunnel) = tunnels.first() {
                            return Some(Arc::clone(tunnel));
                        }
                    }
                }
            }
        }

        if proxy_label_exists {
            return label_to_tunnels_map
                .get("PROXY")
                .and_then(|tunnels| tunnels.first().cloned());
        }

        None
    }

    fn update_label_to_tunnels_map(
        tunnel_map: &TunnelMap,
        label_to_tunnels_map: &mut LabelToTunnelsMap,
    ) {
        label_to_tunnels_map.clear();

        for (_, tunnel) in tunnel_map.iter() {
            let single_proxy_label_array = ["PROXY".to_owned()];

            let labels = tunnel.labels().iter().chain(&single_proxy_label_array);

            for label in labels {
                label_to_tunnels_map
                    .entry(label.clone())
                    .or_default()
                    .push(Arc::clone(tunnel));
            }
        }

        for (_, tunnels) in label_to_tunnels_map.iter_mut() {
            tunnels.sort_by_key(|tunnel| tunnel.priority().checked_neg().unwrap_or(i64::MAX));
        }
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        if let Some(accept_handle) = self.accept_handle.lock().unwrap().take() {
            accept_handle.abort();
        }
    }
}
