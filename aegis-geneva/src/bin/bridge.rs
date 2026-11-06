//! Explicit Linux packet bridge. Never changes routes, namespaces, addresses,
//! iptables or sysctls; dropping this process leaves its two ports disconnected.
#[cfg(target_os = "linux")]
mod linux {
    use aegis_geneva::{
        live::{program::Program, wire::MAX_FRAME},
        packet::model::Direction,
    };
    use rand::SeedableRng;
    use std::{
        ffi::CString,
        fs,
        io::{self, Write},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::{Duration, Instant},
    };
    fn isolated_ports(a: &str, b: &str) -> Result<(), Box<dyn std::error::Error>> {
        let ports = fs::read_dir("/sys/class/net")?
            .map(|e| e.map(|v| v.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        if ports.iter().any(|n| n != "lo" && n != a && n != b) {
            return Err("namespace contains an unselected interface".into());
        }
        if fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() != "0"
            || fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")?.trim() != "0"
        {
            return Err("namespace has kernel routing enabled".into());
        }
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs owns this linked list until freeifaddrs; no pointers escape.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut row = head;
        let mut addressed = false;
        while !row.is_null() {
            let value = unsafe { &*row };
            let name = unsafe { std::ffi::CStr::from_ptr(value.ifa_name) }.to_string_lossy();
            if (name == a || name == b) && !value.ifa_addr.is_null() {
                let family = unsafe { (*value.ifa_addr).sa_family } as i32;
                if family == libc::AF_INET || family == libc::AF_INET6 {
                    addressed = true;
                }
            }
            row = value.ifa_next;
        }
        unsafe { libc::freeifaddrs(head) };
        if addressed {
            return Err("bridge ports must have no kernel IP addresses".into());
        }
        Ok(())
    }
    fn socket(name: &str) -> Result<OwnedFd, Box<dyn std::error::Error>> {
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err("invalid interface".into());
        }
        let base = format!("/sys/class/net/{name}");
        if fs::symlink_metadata(format!("{base}/master")).is_ok() {
            return Err("interface already has a master".into());
        }
        if fs::read_to_string(format!("{base}/type"))?.trim() != "1"
            || fs::read_to_string(format!("{base}/mtu"))?
                .trim()
                .parse::<usize>()?
                > 65535
        {
            return Err("unsupported interface".into());
        }
        let name = CString::new(name)?;
        // SAFETY: a valid NUL-terminated interface name; the returned index is checked.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: no pointer arguments. Ownership immediately transfers to OwnedFd.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let enabled: libc::c_int = 1;
        // PACKET_IGNORE_OUTGOING (23): refusing an unsupported kernel avoids forwarding loops.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                23,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = index as i32;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(fd)
    }
    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() == 2 && args[1] == "--version" {
            println!(
                "aegis-geneva-bridge {} source {} live-linux",
                env!("CARGO_PKG_VERSION"),
                option_env!("AEGIS_BUILD_GIT_SHA").unwrap_or("unknown")
            );
            return Ok(());
        }
        if args.len() != 6 {
            return Err("usage: aegis-geneva-bridge OUTBOUND_PORT INBOUND_PORT STRATEGY_FILE SECONDS PACKET_LIMIT".into());
        }
        let seconds: u64 = args[4].parse()?;
        let budget: u64 = args[5].parse()?;
        if !(1..=900).contains(&seconds) || !(1..=100000).contains(&budget) || args[1] == args[2] {
            return Err("invalid finite bridge limits/ports".into());
        }
        if fs::read_link("/proc/self/ns/net")? == fs::read_link("/proc/1/ns/net")? {
            return Err("requires an explicitly isolated network namespace".into());
        }
        let mut strategy = Program::parse(&aegis_geneva::live::input::load(
            std::path::Path::new(&args[3]),
        )?)?;
        isolated_ports(&args[1], &args[2])?;
        let sockets = [socket(&args[1])?, socket(&args[2])?];
        let mut poll = [
            libc::pollfd {
                fd: sockets[0].as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sockets[1].as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        println!("bounded bridge ready");
        io::stdout().flush()?;
        let mut buffer = vec![0u8; MAX_FRAME + 1];
        let mut rng = rand::rngs::StdRng::from_entropy();
        let start = Instant::now();
        let deadline = Duration::from_secs(seconds);
        let mut received = 0u64;
        let mut sent = 0u64;
        while start.elapsed() < deadline {
            let ms = (deadline - start.elapsed().min(deadline))
                .as_millis()
                .min(100) as i32;
            let ready = unsafe { libc::poll(poll.as_mut_ptr(), 2, ms) };
            if ready < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
            for i in 0..2 {
                if poll[i].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err("packet socket failed".into());
                }
                if poll[i].revents & libc::POLLIN == 0 {
                    continue;
                }
                let n = unsafe {
                    libc::recv(
                        sockets[i].as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        libc::MSG_TRUNC,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                if n as usize > MAX_FRAME {
                    return Err("frame limit exceeded".into());
                }
                if received >= budget {
                    return Err("receive budget exhausted before forwarding".into());
                }
                received += 1;
                let images = strategy.execute(
                    &buffer[..n as usize],
                    if i == 0 {
                        Direction::Outbound
                    } else {
                        Direction::Inbound
                    },
                    &mut rng,
                )?;
                if sent + images.len() as u64 > 1000000 {
                    return Err("transmit budget exhausted before batch".into());
                }
                for image in images {
                    let n = unsafe {
                        libc::send(
                            sockets[1 - i].as_raw_fd(),
                            image.as_ptr().cast(),
                            image.len(),
                            0,
                        )
                    };
                    if n < 0 || n as usize != image.len() {
                        return Err("frame transmit failed; link remains fail-closed".into());
                    }
                    sent += 1;
                }
            }
        }
        // Kernel capture loss is a failure, not a successful unmeasured bridge.
        for socket in &sockets {
            let mut stats = [0u32; 2];
            let mut size = std::mem::size_of_val(&stats) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_STATISTICS,
                    stats.as_mut_ptr().cast(),
                    &mut size,
                )
            } != 0
                || size as usize != std::mem::size_of_val(&stats)
                || stats[1] != 0
            {
                return Err("capture statistics unavailable or loss detected".into());
            }
        }
        println!(
            "bounded bridge completed: received={received} emitted={sent} elapsed_ms={}",
            start.elapsed().as_millis()
        );
        Ok(())
    }
}
fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::run() {
        eprintln!("geneva bridge failed: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("geneva bridge requires Linux");
        std::process::exit(1);
    }
}
