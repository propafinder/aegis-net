//! Socket-local UDP bounds; never changes the host's global UDP settings.
use std::io;
pub fn prepare(socket: &tokio::net::UdpSocket) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // Darwin defaults SO_SNDBUF to 9216, causing EMSGSIZE for a legal
        // large datagram even though the relay/frame path permits 65 KiB.
        let socket = socket2::SockRef::from(socket);
        let minimum = 128 * 1024;
        if socket.send_buffer_size()? < minimum {
            socket.set_send_buffer_size(minimum)?;
        }
        if socket.recv_buffer_size()? < minimum {
            socket.set_recv_buffer_size(minimum)?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = socket;
    Ok(())
}
