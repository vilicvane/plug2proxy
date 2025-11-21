use std::{
    net::{IpAddr, SocketAddr},
    os::fd::{AsFd, AsRawFd},
};

pub enum IpFamily {
    V4,
    V6,
}

pub fn get_socket_original_destination<TSocket: AsFd>(
    socket: &TSocket,
    family: IpFamily,
) -> anyhow::Result<SocketAddr> {
    match family {
        IpFamily::V4 => {
            let address =
                nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::OriginalDst)?;
            let ip = IpAddr::V4(address.sin_addr.s_addr.to_be().into());
            Ok(SocketAddr::new(ip, address.sin_port.to_be()))
        }
        IpFamily::V6 => {
            let address =
                nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::Ip6tOriginalDst)?;
            let ip = IpAddr::V6(address.sin6_addr.s6_addr.into());
            Ok(SocketAddr::new(ip, address.sin6_port.to_be()))
        }
    }
}

pub fn set_keepalive_options<TSocket: AsFd>(
    socket: &TSocket,
    idle: u32,
    interval: u32,
    count: u32,
) -> anyhow::Result<()> {
    let fd = socket.as_fd().as_raw_fd();

    let idle_result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            &idle as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if idle_result != 0 {
        anyhow::bail!("failed to set TCP_KEEPIDLE: {}", nix::errno::Errno::last());
    }

    let interval_result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            &interval as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if interval_result != 0 {
        anyhow::bail!("failed to set TCP_KEEPINTVL: {}", nix::errno::Errno::last());
    }

    let count_result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &count as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if count_result != 0 {
        anyhow::bail!("failed to set TCP_KEEPCNT: {}", nix::errno::Errno::last());
    }

    Ok(())
}
