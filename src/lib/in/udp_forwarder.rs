use std::{
    collections::HashMap,
    mem,
    net::SocketAddr,
    os::fd::{AsFd as _, AsRawFd as _},
    sync::Arc,
    time::Duration,
};

use futures::FutureExt;

use crate::utils::net::{
    get_any_address, get_any_port_address, socket::read_udp_data_with_source_and_destination,
};

pub struct UdpForwarder {
    proxy_socket: tokio::io::unix::AsyncFd<socket2::Socket>,
    association_map: Arc<
        tokio::sync::Mutex<
            HashMap<
                // source address
                SocketAddr,
                Association,
            >,
        >,
    >,
    traffic_mark: u32,
}

pub const UDP_BUFFER_SIZE: usize = 65536;

const RESPONSE_SOCKET_EXPIRATION: Duration = Duration::from_secs(60);

impl UdpForwarder {
    pub fn new(listen_address: SocketAddr, traffic_mark: u32) -> anyhow::Result<Self> {
        let proxy_socket = socket2::Socket::new(
            socket2::Domain::for_address(listen_address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        proxy_socket.set_ip_transparent(true)?;
        proxy_socket.set_nonblocking(true)?;

        {
            let fd = proxy_socket.as_fd().as_raw_fd();

            let enable: libc::c_int = 1;

            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_RECVORIGDSTADDR,
                    &enable as *const _ as *const _,
                    mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        proxy_socket.bind(&listen_address.into())?;

        Ok(Self {
            proxy_socket: tokio::io::unix::AsyncFd::new(proxy_socket)?,
            association_map: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            traffic_mark,
        })
    }

    pub async fn receive(
        &self,
        buffer: &mut [u8],
    ) -> anyhow::Result<(usize, SocketAddr, SocketAddr)> {
        Ok(read_udp_data_with_source_and_destination(&self.proxy_socket, buffer).await?)
    }

    pub async fn send(
        &self,
        source_address: SocketAddr,
        original_destination_address: SocketAddr,
        real_destination_address: SocketAddr,
        buffer: &[u8],
    ) -> anyhow::Result<()> {
        let mut association_map = self.association_map.lock().await;

        let association = association_map.entry(source_address).or_insert_with(|| {
            let (timeout_sender, timeout_receiver) = tokio::sync::oneshot::channel();

            tokio::spawn({
                let association_map = self.association_map.clone();

                async move {
                    timeout_receiver.await.ok();
                    association_map.lock().await.remove(&source_address);
                }
            });

            Association::new(
                source_address,
                original_destination_address,
                real_destination_address,
                self.traffic_mark,
                timeout_sender,
            )
        });

        association
            .send(
                buffer,
                &original_destination_address,
                &real_destination_address,
            )
            .await?;

        Ok(())
    }

    /// Shortcut before routing, to:
    /// - avoid unnecessary routing.
    /// - avoid routing rule missed because of port not match on full-cone scenario.
    pub async fn get_associated_destination(
        &self,
        source_address: &SocketAddr,
        original_destination_address: &SocketAddr,
    ) -> Option<SocketAddr> {
        let association_map = self.association_map.lock().await;

        if let Some(association) = association_map.get(source_address) {
            let original_to_real_destination_map =
                association.original_to_real_destination_map.read().await;

            original_to_real_destination_map
                .get(original_destination_address)
                .cloned()
        } else {
            None
        }
    }
}

struct Association {
    delegate_socket: Arc<tokio::net::UdpSocket>,
    original_to_response_socket_map:
        Arc<tokio::sync::RwLock<HashMap<SocketAddr, Arc<tokio::net::UdpSocket>>>>,
    real_to_response_socket_map:
        Arc<tokio::sync::RwLock<HashMap<SocketAddr, Arc<tokio::net::UdpSocket>>>>,
    original_to_real_destination_map: Arc<tokio::sync::RwLock<HashMap<SocketAddr, SocketAddr>>>,
    send_signal_sender: tokio::sync::mpsc::UnboundedSender<()>,
    traffic_mark: u32,
    handle: tokio::task::JoinHandle<()>,
}

impl Association {
    fn new(
        source_address: SocketAddr,
        original_destination_address: SocketAddr,
        real_destination_address: SocketAddr,
        traffic_mark: u32,
        timeout_sender: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        let delegate_socket = socket2::Socket::new(
            socket2::Domain::for_address(source_address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();

        delegate_socket.set_mark(traffic_mark).unwrap();
        delegate_socket.set_nonblocking(true).unwrap();

        delegate_socket
            .bind(&get_any_address(&source_address.ip()).into())
            .unwrap();

        let delegate_socket =
            Arc::new(tokio::net::UdpSocket::from_std(delegate_socket.into()).unwrap());

        let mut original_to_response_socket_map = HashMap::new();
        let mut real_to_response_socket_map = HashMap::new();
        let mut original_to_real_destination_map = HashMap::new();

        Self::assign_response_socket(
            &mut original_to_response_socket_map,
            &mut real_to_response_socket_map,
            &mut original_to_real_destination_map,
            Some(&original_destination_address),
            &real_destination_address,
            traffic_mark,
        );

        let original_to_response_socket_map =
            Arc::new(tokio::sync::RwLock::new(original_to_response_socket_map));
        let real_to_response_socket_map =
            Arc::new(tokio::sync::RwLock::new(real_to_response_socket_map));
        let original_to_real_destination_map =
            Arc::new(tokio::sync::RwLock::new(original_to_real_destination_map));

        let (activity_signal_sender, mut activity_signal_receiver) =
            tokio::sync::mpsc::unbounded_channel();

        let read_task = {
            let delegate_socket = delegate_socket.clone();

            let original_to_response_socket_map = original_to_response_socket_map.clone();
            let real_to_response_socket_map = real_to_response_socket_map.clone();
            let original_to_real_destination_map = original_to_real_destination_map.clone();

            let receive_signal_sender = activity_signal_sender.clone();

            let mut buffer = Vec::with_capacity(UDP_BUFFER_SIZE);

            async move {
                loop {
                    let (length, remote_address) =
                        delegate_socket.recv_buf_from(&mut buffer).await?;

                    let _ = receive_signal_sender.send(());

                    let mut original_to_response_socket_map =
                        original_to_response_socket_map.write().await;
                    let mut real_to_response_socket_map = real_to_response_socket_map.write().await;
                    let mut original_to_real_destination_map =
                        original_to_real_destination_map.write().await;

                    let response_socket = Self::assign_response_socket(
                        &mut original_to_response_socket_map,
                        &mut real_to_response_socket_map,
                        &mut original_to_real_destination_map,
                        None,
                        &remote_address,
                        traffic_mark,
                    );

                    response_socket
                        .send_to(&buffer[..length], source_address)
                        .await?;
                }

                #[allow(unreachable_code)]
                anyhow::Ok(())
            }
        };

        let timeout_task = async move {
            loop {
                tokio::select! {
                    _ = activity_signal_receiver.recv() => continue,
                    _ = tokio::time::sleep(RESPONSE_SOCKET_EXPIRATION) => {
                        let _ = timeout_sender.send(());

                        println!("timeout for source {source_address}");

                        break;
                    },
                }
            }

            anyhow::Ok(())
        };

        let handle = tokio::spawn(async {
            tokio::select! {
                _ = read_task.fuse() => {},
                _ = timeout_task.fuse() => {},
            }
        });

        Association {
            delegate_socket,
            original_to_response_socket_map,
            real_to_response_socket_map,
            original_to_real_destination_map,
            send_signal_sender: activity_signal_sender,
            traffic_mark,
            handle,
        }
    }

    async fn send(
        &self,
        buffer: &[u8],
        original_destination_address: &SocketAddr,
        real_destination_address: &SocketAddr,
    ) -> anyhow::Result<()> {
        self.send_signal_sender.send(())?;

        let mut original_to_response_socket_map =
            self.original_to_response_socket_map.write().await;
        let mut real_to_response_socket_map = self.real_to_response_socket_map.write().await;
        let mut original_to_real_destination_map =
            self.original_to_real_destination_map.write().await;

        Self::assign_response_socket(
            &mut original_to_response_socket_map,
            &mut real_to_response_socket_map,
            &mut original_to_real_destination_map,
            Some(original_destination_address),
            real_destination_address,
            self.traffic_mark,
        );

        println!(
            "delegate send {} bytes to {real_destination_address}",
            buffer.len()
        );

        self.delegate_socket
            .send_to(buffer, real_destination_address)
            .await?;

        Ok(())
    }

    fn assign_response_socket(
        original_to_response_socket_map: &mut HashMap<SocketAddr, Arc<tokio::net::UdpSocket>>,
        real_to_response_socket_map: &mut HashMap<SocketAddr, Arc<tokio::net::UdpSocket>>,
        original_to_real_destination_map: &mut HashMap<SocketAddr, SocketAddr>,
        original_destination_address: Option<&SocketAddr>,
        real_destination_address: &SocketAddr,
        traffic_mark: u32,
    ) -> Arc<tokio::net::UdpSocket> {
        let binding_address = if let Some(original_destination_address) =
            original_destination_address
        {
            if let Some(socket) = original_to_response_socket_map.get(original_destination_address)
            {
                return socket.clone();
            }

            *original_destination_address
        } else {
            if let Some(socket) = real_to_response_socket_map.get(real_destination_address) {
                return socket.clone();
            }

            get_any_port_address(&original_to_response_socket_map.keys().next().unwrap().ip())
        };

        let socket = socket2::Socket::new(
            socket2::Domain::for_address(binding_address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();

        socket.set_ip_transparent(true).unwrap();
        socket.set_reuse_port(true).unwrap();
        socket.set_mark(traffic_mark).unwrap();
        socket.set_nonblocking(true).unwrap();

        println!("Binding response socket to {}", binding_address);

        socket.bind(&binding_address.into()).unwrap();

        let socket = tokio::net::UdpSocket::from_std(socket.into()).unwrap();

        let original_destination_address = socket.local_addr().unwrap();

        let socket = Arc::new(socket);

        original_to_response_socket_map.insert(original_destination_address, socket.clone());
        real_to_response_socket_map.insert(*real_destination_address, socket.clone());
        original_to_real_destination_map
            .insert(original_destination_address, *real_destination_address);

        println!(
            "Assigned response socket original {original_destination_address} real {real_destination_address}"
        );

        socket
    }
}

impl Drop for UdpForwarder {
    fn drop(&mut self) {
        let association_map = self.association_map.clone();

        tokio::spawn(async move {
            let association_map = association_map.lock().await;

            for association in association_map.values() {
                association.handle.abort();
            }
        });
    }
}
