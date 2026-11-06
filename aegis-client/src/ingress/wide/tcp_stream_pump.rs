//! Lossless nonblocking transfer between smoltcp and a relay byte stream.

use smoltcp::socket::tcp;
use std::io::{self, Read, Write};

#[derive(Default)]
pub(crate) struct TcpStreamPump {
    relay_read_closed: bool,
    relay_write_closed: bool,
}

#[derive(Default)]
pub(crate) struct PumpProgress {
    pub to_client: usize,
    pub to_relay: usize,
    pub shutdown_relay_write: bool,
}

impl TcpStreamPump {
    pub fn removable(socket: &tcp::Socket<'_>) -> bool {
        matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) && !socket.can_recv()
    }

    pub fn pump(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        relay: &mut (impl Read + Write),
    ) -> io::Result<PumpProgress> {
        let mut progress = PumpProgress::default();
        if socket.can_recv() {
            // Leave every unaccepted byte in smoltcp's receive queue. A
            // nonblocking write_all can write a prefix and then return EAGAIN.
            progress.to_relay = socket
                .recv(|bytes| match relay.write(bytes) {
                    Ok(0) => (0, Err(io::ErrorKind::WriteZero.into())),
                    Ok(n) => (n, Ok(n)),
                    Err(e) if retry_later(&e) => (0, Ok(0)),
                    Err(e) => (0, Err(e)),
                })
                .map_err(|e| io::Error::other(format!("smoltcp receive: {e}")))??;
        }

        if !self.relay_write_closed
            && !socket.can_recv()
            && matches!(
                socket.state(),
                tcp::State::CloseWait
                    | tcp::State::LastAck
                    | tcp::State::Closing
                    | tcp::State::TimeWait
                    | tcp::State::Closed
            )
        {
            // Forward the application's FIN only after all preceding bytes
            // reached the relay. Its response direction remains open.
            self.relay_write_closed = true;
            progress.shutdown_relay_write = true;
        }

        if !self.relay_read_closed && socket.can_send() {
            // Read directly into actual available transmit capacity. Reading
            // first and then calling send_slice loses a suffix on partial send,
            // or the whole chunk when the TCP window is full.
            let (written, eof) = socket
                .send(|bytes| {
                    let capacity = bytes.len().min(8192);
                    match relay.read(&mut bytes[..capacity]) {
                        Ok(n) => (n, Ok((n, n == 0))),
                        Err(e) if retry_later(&e) => (0, Ok((0, false))),
                        Err(e) => (0, Err(e)),
                    }
                })
                .map_err(|e| io::Error::other(format!("smoltcp send: {e}")))??;
            progress.to_client = written;
            if eof {
                self.relay_read_closed = true;
                // smoltcp queues FIN after buffered data. Keep the socket in
                // the poll loop until the close handshake has progressed.
                socket.close();
            }
        }
        Ok(progress)
    }
}

fn retry_later(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::time::Instant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv6Address};

    struct Pair {
        iface: Interface,
        device: Loopback,
        sockets: SocketSet<'static>,
        client: SocketHandle,
        server: SocketHandle,
        ticks: i64,
    }

    impl Pair {
        fn new(capacity: usize) -> Self {
            let address = IpAddress::Ipv6(Ipv6Address::LOCALHOST);
            let mut device = Loopback::new(Medium::Ip);
            let mut config = Config::new(HardwareAddress::Ip);
            config.random_seed = 17;
            let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
            iface.update_ip_addrs(|addresses| {
                addresses.push(IpCidr::new(address, 128)).unwrap();
            });
            let mut sockets = SocketSet::new(vec![]);
            let mut make_socket = || {
                sockets.add(tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; capacity]),
                    tcp::SocketBuffer::new(vec![0; capacity]),
                ))
            };
            let client = make_socket();
            let server = make_socket();
            sockets.get_mut::<tcp::Socket>(server).listen(443).unwrap();
            sockets
                .get_mut::<tcp::Socket>(client)
                .connect(iface.context(), (address, 443), 40001)
                .unwrap();
            let mut pair = Self {
                iface,
                device,
                sockets,
                client,
                server,
                ticks: 0,
            };
            for _ in 0..10 {
                pair.poll();
            }
            assert_eq!(pair.server().state(), tcp::State::Established);
            pair
        }

        fn poll(&mut self) {
            self.ticks += 1;
            self.iface.poll(
                Instant::from_millis(self.ticks),
                &mut self.device,
                &mut self.sockets,
            );
        }

        fn server(&mut self) -> &mut tcp::Socket<'static> {
            self.sockets.get_mut(self.server)
        }
    }

    struct Relay {
        received: Vec<u8>,
        response: io::Cursor<Vec<u8>>,
        read_calls: usize,
        write_calls: usize,
        write_closed: bool,
        wait_for_fin: bool,
        write_zero: bool,
    }

    impl Relay {
        fn new(response: Vec<u8>) -> Self {
            Self {
                received: vec![],
                response: io::Cursor::new(response),
                read_calls: 0,
                write_calls: 0,
                write_closed: false,
                wait_for_fin: false,
                write_zero: false,
            }
        }
    }

    impl Read for Relay {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.read_calls += 1;
            if self.wait_for_fin && !self.write_closed {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.response.read(output)
        }
    }

    impl Write for Relay {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            assert!(
                !self.write_closed,
                "bytes written after relay write shutdown"
            );
            self.write_calls += 1;
            if self.write_zero {
                return Ok(0);
            }
            if self.write_calls.is_multiple_of(3) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if self.write_calls.is_multiple_of(7) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = input.len().min(257);
            self.received.extend_from_slice(&input[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn relay_read_respects_partial_and_full_transmit_capacity() {
        let mut pair = Pair::new(1024);
        pair.server().send_slice(&vec![0x55; 1017]).unwrap();
        let mut relay = Relay::new(vec![0x77; 2048]);
        let mut pump = TcpStreamPump::default();
        assert_eq!(pump.pump(pair.server(), &mut relay).unwrap().to_client, 7);
        assert_eq!(relay.response.position(), 7);
        assert_eq!(pair.server().send_queue(), 1024);
        for _ in 0..8 {
            assert_eq!(pump.pump(pair.server(), &mut relay).unwrap().to_client, 0);
        }
        assert_eq!(
            relay.read_calls, 1,
            "full queue must not consume relay bytes"
        );
        assert_eq!(relay.response.position(), 7);
    }

    #[test]
    fn large_duplex_stream_survives_backpressure_and_both_half_closes() {
        let mut pair = Pair::new(4096);
        let upload: Vec<u8> = (0..131_113).map(|n| (n % 251) as u8).collect();
        let response: Vec<u8> = (0..262_189).map(|n| (n % 239) as u8).collect();
        let mut relay = Relay::new(response.clone());
        relay.wait_for_fin = true;
        let mut pump = TcpStreamPump::default();
        let mut sent = 0;
        let mut received = vec![];
        let mut client_fin = false;
        let mut shutdowns = 0;
        let mut response_started = None;
        for tick in 0..100_000 {
            pair.poll();
            let client = pair.sockets.get_mut::<tcp::Socket>(pair.client);
            if sent < upload.len() && client.can_send() {
                sent += client.send_slice(&upload[sent..]).unwrap();
            }
            if sent == upload.len() && !client_fin {
                client.close();
                client_fin = true;
            }
            let progress = pump.pump(pair.server(), &mut relay).unwrap();
            if progress.shutdown_relay_write {
                assert!(
                    relay.received == upload,
                    "FIN must follow every request byte"
                );
                relay.write_closed = true;
                shutdowns += 1;
            }
            if progress.to_client > 0 {
                response_started.get_or_insert(tick);
            }
            // Hold a zero receive window, then drain slowly in tiny pieces.
            if response_started.is_some_and(|start| tick > start + 100) && tick % 7 == 0 {
                let client = pair.sockets.get_mut::<tcp::Socket>(pair.client);
                if client.can_recv() {
                    let mut bytes = [0; 113];
                    let n = client.recv_slice(&mut bytes).unwrap();
                    received.extend_from_slice(&bytes[..n]);
                }
                if !client.may_recv() {
                    break;
                }
            }
        }
        assert!(relay.received == upload, "request bytes must remain exact");
        assert_eq!(
            received.len(),
            response.len(),
            "response must drain before FIN"
        );
        assert!(received == response, "response bytes must remain exact");
        assert_eq!(shutdowns, 1);
        assert!(!pair.sockets.get_mut::<tcp::Socket>(pair.client).may_recv());
    }

    #[test]
    fn zero_write_does_not_consume_request_bytes() {
        let mut pair = Pair::new(1024);
        pair.sockets
            .get_mut::<tcp::Socket>(pair.client)
            .send_slice(b"keep")
            .unwrap();
        for _ in 0..10 {
            pair.poll();
            if pair.server().can_recv() {
                break;
            }
        }
        let queued = pair.server().recv_queue();
        assert_eq!(queued, 4);
        let mut relay = Relay::new(vec![]);
        relay.write_zero = true;
        let error = TcpStreamPump::default()
            .pump(pair.server(), &mut relay)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(pair.server().recv_queue(), queued);
    }

    #[test]
    fn early_response_eof_does_not_discard_buffered_request_at_close() {
        let mut pair = Pair::new(4096);
        let request: Vec<u8> = (0..32_779).map(|n| (n % 251) as u8).collect();
        let mut relay = Relay::new(vec![]);
        let mut pump = TcpStreamPump::default();
        let mut sent = 0;
        let mut client_fin = false;
        let mut shutdowns = 0;
        let mut closed_with_queued_request = false;
        let mut removed = false;
        for _ in 0..10_000 {
            pair.poll();
            let client = pair.sockets.get_mut::<tcp::Socket>(pair.client);
            if sent < request.len() && client.can_send() {
                sent += client.send_slice(&request[sent..]).unwrap();
            }
            if sent == request.len() && !client_fin {
                client.close();
                client_fin = true;
            }
            let socket = pair.server();
            if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
                && socket.can_recv()
            {
                closed_with_queued_request = true;
            }
            // Use the same removal predicate as the production engine.
            if TcpStreamPump::removable(socket) {
                removed = true;
                break;
            }
            let progress = pump.pump(socket, &mut relay).unwrap();
            if progress.shutdown_relay_write {
                assert!(relay.received == request);
                relay.write_closed = true;
                shutdowns += 1;
            }
        }
        assert!(
            closed_with_queued_request,
            "test must reach the close/drain race"
        );
        assert!(removed);
        assert!(
            relay.received == request,
            "close must preserve buffered request bytes"
        );
        assert_eq!(shutdowns, 1);
    }
}
