use std::{
    collections::HashMap,
    sync::{atomic::AtomicUsize, Arc, Mutex},
};

use itertools::Itertools;

use crate::{
    routing::router::Router,
    tunnel::{InTunnel, TunnelId},
    tunnel_provider::InTunnelProvider,
};

use super::direct_in_tunnel::DirectInTunnel;

type TunnelMap = HashMap<TunnelId, Arc<Box<dyn InTunnel>>>;
type LabelToTunnelsMap = HashMap<String, Vec<Arc<Box<dyn InTunnel>>>>;

pub struct TunnelManager {
    pub accept_handles: Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>,
    direct_tunnel: Arc<Box<dyn InTunnel>>,
    label_to_tunnels_map: Arc<tokio::sync::Mutex<LabelToTunnelsMap>>,
    select_index: AtomicUsize,
}

impl TunnelManager {
    pub fn new(
        tunnel_providers: Vec<Box<dyn InTunnelProvider + Send>>,
        router: Arc<Router>,
        traffic_mark: u32,
    ) -> Self {
        let tunnel_map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let label_to_tunnels_map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        let accept_handles = tunnel_providers
            .into_iter()
            .map(|tunnel_provider| {
                tokio::spawn({
                    let router = Arc::clone(&router);

                    let tunnel_map = Arc::clone(&tunnel_map);
                    let label_to_tunnels_map = Arc::clone(&label_to_tunnels_map);

                    async move {
                        loop {
                            if let Ok((tunnel, out_routing_rules)) = tunnel_provider.accept().await
                            {
                                let tunnel_id = tunnel.id();
                                let tunnel = Arc::new(tunnel);

                                {
                                    let mut tunnel_map = tunnel_map.lock().await;

                                    tunnel_map.insert(tunnel_id, Arc::clone(&tunnel));

                                    let mut label_to_tunnels_map =
                                        label_to_tunnels_map.lock().await;

                                    Self::update_label_to_tunnels_map(
                                        &tunnel_map,
                                        &mut label_to_tunnels_map,
                                    );

                                    router
                                        .register_tunnel(
                                            tunnel_id,
                                            out_routing_rules,
                                            tunnel.priority(),
                                        )
                                        .await;
                                }

                                tokio::spawn({
                                    let tunnel_map = tunnel_map.clone();
                                    let label_to_tunnels_map = label_to_tunnels_map.clone();

                                    let router = router.clone();

                                    async move {
                                        tunnel.closed().await;

                                        log::info!("tunnel {tunnel_id} closed.");

                                        let mut tunnel_map = tunnel_map.lock().await;

                                        tunnel_map.remove(&tunnel_id);

                                        let mut label_to_tunnels_map =
                                            label_to_tunnels_map.lock().await;

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
                })
            })
            .collect_vec();

        Self {
            accept_handles: Mutex::new(Some(accept_handles)),
            direct_tunnel: Arc::new(Box::new(DirectInTunnel::new(traffic_mark))),
            label_to_tunnels_map,
            select_index: AtomicUsize::new(0),
        }
    }

    pub async fn select_tunnel(
        &self,
        labels_groups: &[Vec<String>],
    ) -> Option<Arc<Box<dyn InTunnel>>> {
        let index = self
            .select_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let label_to_tunnels_map = self.label_to_tunnels_map.lock().await;

        let mut label_proxy_exists = false;
        let mut label_any_exists = false;

        for labels in labels_groups {
            for label in labels {
                match label.as_str() {
                    "DIRECT" => {
                        return Some(self.direct_tunnel.clone());
                    }
                    "PROXY" => {
                        label_proxy_exists = true;
                    }
                    "ANY" => {
                        label_any_exists = true;
                    }
                    _ => {
                        if let Some(tunnels) = label_to_tunnels_map.get(label) {
                            let tunnel = select_from_tunnels(tunnels, index);

                            if tunnel.is_some() {
                                return tunnel;
                            }
                        }
                    }
                }
            }

            let proxy_tunnel = label_to_tunnels_map
                .get("PROXY")
                .and_then(|tunnels| select_from_tunnels(tunnels, index));

            if label_proxy_exists {
                return proxy_tunnel;
            }

            if label_any_exists {
                return proxy_tunnel.or_else(|| Some(self.direct_tunnel.clone()));
            }
        }

        None
    }

    fn update_label_to_tunnels_map(
        tunnel_map: &TunnelMap,
        label_to_tunnels_map: &mut LabelToTunnelsMap,
    ) {
        label_to_tunnels_map.clear();

        for (_, tunnel) in tunnel_map.iter() {
            let extra_labels = ["PROXY".to_owned(), tunnel.out_id().to_string()];

            let labels = tunnel.labels().iter().chain(&extra_labels);

            for label in labels {
                label_to_tunnels_map
                    .entry(label.clone())
                    .or_default()
                    .push(Arc::clone(tunnel));
            }
        }

        for (_, tunnels) in label_to_tunnels_map.iter_mut() {
            tunnels.sort_by_key(|tunnel| tunnel.priority());
        }
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        if let Some(accept_handles) = self.accept_handles.lock().unwrap().take() {
            for accept_handle in accept_handles {
                accept_handle.abort();
            }
        }
    }
}

fn select_from_tunnels(
    tunnels: &[Arc<Box<dyn InTunnel>>],
    index: usize,
) -> Option<Arc<Box<dyn InTunnel>>> {
    if tunnels.is_empty() {
        return None;
    }

    let top_priority = tunnels.first().unwrap().priority();

    let tunnels_with_top_priority = tunnels
        .iter()
        .take_while(|tunnel| tunnel.priority() == top_priority)
        .collect_vec();

    Some(Arc::clone(
        tunnels_with_top_priority[index % tunnels_with_top_priority.len()],
    ))
}
