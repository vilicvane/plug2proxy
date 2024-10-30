use std::{mem, net::SocketAddr, os::fd::AsRawFd, ptr};

/// Requires socket to have `IP_RECVORIGDSTADDR` or `IPV6_RECVORIGDSTADDR` enabled.
pub async fn receive_udp_data_with_source_and_destination<TSocket: AsRawFd>(
    fd: &tokio::io::unix::AsyncFd<TSocket>,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
    loop {
        let mut read_guard = fd.readable().await?;

        let result = receive_udp_data_with_source_and_destination_(fd, buffer);

        if let Err(ref error) = result {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                read_guard.clear_ready();
                continue;
            }
        }

        return result;
    }
}

fn receive_udp_data_with_source_and_destination_<TSocket: AsRawFd>(
    socket: &TSocket,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut message_header = mem::zeroed::<libc::msghdr>();

        let mut source_address_storage = mem::zeroed::<libc::sockaddr_storage>();

        message_header.msg_name = &mut source_address_storage as *mut _ as *mut _;
        message_header.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut _,
            iov_len: buffer.len() as libc::size_t,
        };

        message_header.msg_iov = &mut iov;
        message_header.msg_iovlen = 1;

        let mut control_buffer = [0u8; 64];

        message_header.msg_control = control_buffer.as_mut_ptr() as *mut _;

        cfg_if::cfg_if! {
            if #[cfg(any(target_env = "musl", all(target_env = "uclibc", target_arch = "arm")))] {
                message_header.msg_controllen = control_buffer.len() as libc::socklen_t;
            } else {
                message_header.msg_controllen = control_buffer.len() as libc::size_t;
            }
        }

        let fd = socket.as_raw_fd();

        let length = libc::recvmsg(fd, &mut message_header, 0);

        if length < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let (_, source_address) = socket2::SockAddr::try_init(|address_storage, length| {
            ptr::copy_nonoverlapping(
                message_header.msg_name,
                address_storage as *mut _,
                message_header.msg_namelen as usize,
            );

            *length = message_header.msg_namelen;

            Ok(())
        })
        .unwrap();

        Ok((
            length as usize,
            source_address.as_socket().map_or_else(
                || {
                    let err = std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "failed to convert SockAddr to SocketAddr.",
                    );
                    Err(err)
                },
                Ok,
            )?,
            get_destination(&message_header)?,
        ))
    }
}

fn get_destination(message_header: &libc::msghdr) -> std::io::Result<SocketAddr> {
    unsafe {
        let (_, address) = socket2::SockAddr::try_init(|address_storage, length| {
            let mut control_message_header_pointer = libc::CMSG_FIRSTHDR(message_header);

            while !control_message_header_pointer.is_null() {
                let control_message_header = &*control_message_header_pointer;

                match (
                    control_message_header.cmsg_level,
                    control_message_header.cmsg_type,
                ) {
                    (libc::SOL_IP, libc::IP_RECVORIGDSTADDR) => {
                        ptr::copy(
                            libc::CMSG_DATA(control_message_header_pointer),
                            address_storage as *mut _,
                            mem::size_of::<libc::sockaddr_in>(),
                        );

                        *length = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

                        return Ok(());
                    }
                    (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) => {
                        ptr::copy(
                            libc::CMSG_DATA(control_message_header_pointer),
                            address_storage as *mut _,
                            mem::size_of::<libc::sockaddr_in6>(),
                        );

                        *length = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

                        return Ok(());
                    }
                    _ => {}
                }

                control_message_header_pointer =
                    libc::CMSG_NXTHDR(message_header, control_message_header_pointer);
            }

            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing destination address in msghdr",
            ))
        })?;

        Ok(address.as_socket().unwrap())
    }
}
