use std::{
    collections::HashMap,
    sync::{
        atomic::{self, AtomicUsize},
        Arc, Mutex,
    },
    time::Duration,
};

use itertools::Itertools;

use crate::{
    match_server::MatchOutId,
    route::router::Router,
    tunnel::{
        direct_tunnel::DirectInTunnel, AnyInTunnelLikeArc, InTunnel, InTunnelLike,
        InTunnelProvider, TunnelId,
    },
};

type TunnelMap = HashMap<TunnelId, Arc<Box<dyn InTunnel>>>;
type LabelToTunnelsMap = HashMap<String, Vec<Arc<Box<dyn InTunnel>>>>;

pub struct TunnelManager {
    pub accept_handles: Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>,
    direct_tunnel: Arc<Box<dyn InTunnelLike>>,
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
                let router = router.clone();
                let tunnel_map = tunnel_map.clone();
                let label_to_tunnels_map = label_to_tunnels_map.clone();

                tokio::spawn(Self::handle_tunnel_provider(
                    tunnel_provider,
                    router,
                    tunnel_map,
                    label_to_tunnels_map,
                ))

                // tokio::task::spawn_blocking(move || {
                //     tokio::runtime::Builder::new_current_thread()
                //         .enable_all()
                //         .build()
                //         .unwrap()
                //         .block_on(Self::handle_tunnel_provider(
                //             tunnel_provider,
                //             router,
                //             tunnel_map,
                //             label_to_tunnels_map,
                //         ));
                // })
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
        labels_groups: &[Vec<(String, Option<String>)>],
    ) -> Option<(AnyInTunnelLikeArc, Option<String>)> {
        let index = self.select_index.fetch_add(1, atomic::Ordering::Relaxed);

        let label_to_tunnels_map = self.label_to_tunnels_map.lock().await;

        for labels in labels_groups {
            let mut label_proxy_presence = None;
            let mut label_any_presence = None;

            for (label, tag) in labels {
                match label.as_str() {
                    "DIRECT" => {
                        return Some((self.direct_tunnel.clone().into(), tag.clone()));
                    }
                    "PROXY" => {
                        if label_proxy_presence.is_none() {
                            label_proxy_presence = Some(tag.clone());
                        }
                    }
                    "ANY" => {
                        if label_any_presence.is_none() {
                            label_any_presence = Some(tag.clone());
                        }
                    }
                    _ => {
                        if let Some(tunnels) = label_to_tunnels_map.get(label) {
                            let tunnel = select_from_tunnels(tunnels, index);

                            if tunnel.is_some() {
                                return tunnel.map(|tunnel| (tunnel, tag.clone()));
                            }
                        }
                    }
                }
            }

            let proxy_tunnel = label_to_tunnels_map
                .get("PROXY")
                .and_then(|tunnels| select_from_tunnels(tunnels, index));

            if let Some(tag) = label_proxy_presence {
                return proxy_tunnel.map(|tunnel| (tunnel, tag));
            }

            if let Some(tag) = label_any_presence {
                return proxy_tunnel
                    .or_else(|| Some(self.direct_tunnel.clone().into()))
                    .map(|tunnel| (tunnel, tag));
            }
        }

        None
    }

    async fn handle_tunnel_provider(
        tunnel_provider: Box<dyn InTunnelProvider + Send>,
        router: Arc<Router>,
        tunnel_map: Arc<tokio::sync::Mutex<TunnelMap>>,
        label_to_tunnels_map: Arc<tokio::sync::Mutex<LabelToTunnelsMap>>,
    ) {
        let tunnel_provider = Arc::new(tunnel_provider);

        loop {
            match tunnel_provider.accept_out().await {
                Ok((out_id, connections)) => {
                    tokio::spawn(Self::handle_out(
                        out_id,
                        connections,
                        tunnel_provider.clone(),
                        router.clone(),
                        tunnel_map.clone(),
                        label_to_tunnels_map.clone(),
                    ));
                }
                Err(error) => {
                    log::warn!("error accepting OUT: {error}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn handle_out(
        out_id: MatchOutId,
        connections: usize,
        tunnel_provider: Arc<Box<dyn InTunnelProvider + Send>>,
        router: Arc<Router>,
        tunnel_map: Arc<tokio::sync::Mutex<TunnelMap>>,
        label_to_tunnels_map: Arc<tokio::sync::Mutex<LabelToTunnelsMap>>,
    ) {
        let tunnel_name = tunnel_provider.name();

        let semaphore = Arc::new(tokio::sync::Semaphore::new(connections));

        let mut handles = Vec::<tokio::task::JoinHandle<()>>::new();

        loop {
            let permit = semaphore.clone().acquire_owned().await;

            handles.retain(|handle| !handle.is_finished());

            log::info!("accepting {tunnel_name} tunnel...");

            match tunnel_provider.accept(out_id).await {
                Ok(Some((tunnel, (out_routing_rules, out_routing_priority)))) => {
                    let tunnel_id = tunnel.id();
                    let tunnel = Arc::new(tunnel);

                    {
                        let mut tunnel_map = tunnel_map.lock().await;

                        tunnel_map.insert(tunnel_id, tunnel.clone());

                        let mut label_to_tunnels_map = label_to_tunnels_map.lock().await;

                        Self::update_label_to_tunnels_map(&tunnel_map, &mut label_to_tunnels_map);

                        router.register_tunnel(tunnel_id, out_routing_rules, out_routing_priority);
                    }

                    let handle = tokio::spawn({
                        let tunnel_map = tunnel_map.clone();
                        let label_to_tunnels_map = label_to_tunnels_map.clone();

                        let router = router.clone();

                        async move {
                            tunnel.closed().await;

                            log::info!("tunnel {tunnel} closed.");

                            let mut tunnel_map = tunnel_map.lock().await;

                            tunnel_map.remove(&tunnel_id);

                            let mut label_to_tunnels_map = label_to_tunnels_map.lock().await;

                            Self::update_label_to_tunnels_map(
                                &tunnel_map,
                                &mut label_to_tunnels_map,
                            );

                            router.unregister_tunnel(tunnel_id);

                            drop(permit);
                        }
                    });

                    handles.push(handle);
                }
                Ok(None) => {
                    // OUT no longer active, abort all unfinished handles to avoid active tunnel to
                    // this OUT lives (which could potentially result in connections exceeding the
                    // desired number).

                    for handle in handles {
                        handle.abort();
                    }

                    break;
                }
                Err(error) => {
                    log::warn!("error accepting tunnel: {error}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
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
) -> Option<AnyInTunnelLikeArc> {
    if tunnels.is_empty() {
        return None;
    }

    let top_priority = tunnels.first().unwrap().priority();

    let tunnels_with_top_priority = tunnels
        .iter()
        .take_while(|tunnel| tunnel.priority() == top_priority)
        .collect_vec();

    Some(Arc::clone(tunnels_with_top_priority[index % tunnels_with_top_priority.len()]).into())
}
