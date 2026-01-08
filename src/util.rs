/// Set SO_MARK socket option (Linux-specific, for TPROXY).
///
/// This sets the traffic mark on a socket, which is used by Linux's TPROXY
/// to route packets based on their mark value.
///
/// # Arguments
/// * `socket` - The socket to mark
/// * `mark` - The mark value to set
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if setting the socket option fails
///
/// # Platform Support
/// * Linux: Fully supported
/// * Other platforms: No-op (returns `Ok(())`)
#[cfg(target_os = "linux")]
pub fn set_socket_mark<S: std::os::unix::io::AsRawFd>(
    socket: &S,
    mark: u32,
) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_socket_mark<S>(_: &S, _: u32) -> std::io::Result<()> {
    // SO_MARK is Linux-specific, no-op on other platforms
    Ok(())
}
