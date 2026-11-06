const DNS_QR_RESPONSE: u8 = 0x80;
const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_NXDOMAIN: u8 = 3;
const DNS_RCODE_NOTIMPL: u8 = 4;
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;
const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;
const SYNTHETIC_POOL_START: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const SYNTHETIC_POOL_END: u32 = u32::from_be_bytes([198, 20, 0, 0]);

fn checked_pool(pool_cidr: &str) -> Result<(u32, u32), String> {
    let (start, prefix) = parse_cidr_v4(pool_cidr)?;
    if !(15..=30).contains(&prefix) {
        return Err("fake-ip pool prefix must be between 15 and 30".into());
    }
    let size = 1u32
        .checked_shl(u32::from(32 - prefix))
        .ok_or_else(|| "fake-ip pool size overflow".to_string())?;
    let start = u32::from(start);
    if start & (size - 1) != 0 {
        return Err("fake-ip pool must use its canonical network address".into());
    }
    let end = start
        .checked_add(size)
        .ok_or_else(|| "fake-ip pool end overflow".to_string())?;
    if start < SYNTHETIC_POOL_START || end > SYNTHETIC_POOL_END {
        return Err("fake-ip pool must be a subnet of 198.18.0.0/15".into());
    }
    Ok((start, size))
}

/// Configuration-only bootstrap guard: never resolve control names through the
/// application fake resolver. Existing numeric dial / TLS authority separation
/// is preserved, and no native DNS fallback is introduced.
#[cfg(any(target_os = "linux", test))]
pub fn validate_dns_preview_config(
    settings: &WideIngressSettings,
    relay: &RelaySettings,
) -> io::Result<()> {
    if !settings.enabled || settings.dns_preview_listen.is_none() {
        return Ok(());
    }
    checked_pool(&settings.dns_preview_fake_ip_pool)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let check = |server: &str, field: &str| -> io::Result<()> {
        let address: SocketAddr = server.parse().map_err(|_| io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("dns_preview_bootstrap: {field} requires a pinned numeric dial address; retain TLS server_name separately"),
        ))?;
        let v4 = match address.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped(),
        };
        let invalid_v4 = v4.is_some_and(|ip| {
            is_synthetic_ip(ip) || ip.is_broadcast() || ip.is_unspecified() || ip.is_multicast()
        });
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || invalid_v4
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("dns_preview_bootstrap: {field} is not a usable control address"),
            ));
        }
        Ok(())
    };
    check(
        &settings.dns_relay_upstream.to_string(),
        "wide.dns_relay_upstream",
    )?;
    let udp = relay
        .udp_transport_priority
        .as_deref()
        .unwrap_or(&relay.transport_priority);
    let tcp = relay.transport_priority.iter().any(|family| {
        matches!(
            family,
            TunnelTransportFamily::LegacyTls
                | TunnelTransportFamily::HttpsWs
                | TunnelTransportFamily::GrpcStream
        )
    }) || udp.contains(&TunnelTransportFamily::GrpcDatagram);
    let tcp_masque = relay
        .transport_priority
        .contains(&TunnelTransportFamily::MasqueDerived)
        || udp.contains(&TunnelTransportFamily::MasqueDerived);
    if relay.endpoints.is_empty() {
        if tcp {
            check(&relay.server, "relay.server")?;
        }
        if tcp_masque {
            check(
                relay.masque_server.as_deref().unwrap_or(&relay.server),
                "relay.masque_server",
            )?;
        }
    } else {
        for endpoint in &relay.endpoints {
            if tcp {
                check(&endpoint.server, "relay.endpoints.server")?;
            }
            if tcp_masque {
                check(
                    endpoint
                        .masque_server
                        .as_deref()
                        .or(relay.masque_server.as_deref())
                        .unwrap_or(&endpoint.server),
                    "relay.endpoints.masque_server",
                )?;
            }
        }
    }
    // TCP and fixed/multi-target UDP now share endpoint selection and the
    // same top-level MASQUE inheritance. Never resolve control names through
    // the application preview, even when they appear only in the UDP plan.
    Ok(())
}

fn is_synthetic_ip(ip: Ipv4Addr) -> bool {
    (SYNTHETIC_POOL_START..SYNTHETIC_POOL_END).contains(&u32::from(ip))
}

/// The map's clock. Read through tokio so paused-time tests reach it; outside a
/// runtime (the engine thread) and in every non-test build it is the
/// monotonic system clock.
type FakeIpInstant = tokio::time::Instant;
/// The rcode of an A answer the map cannot give (`build_response_with_sink`).
const RCODE_SERVFAIL: u8 = 2;

/// One synthetic address bound to its one name.
///
/// B-06 build 37 endurance (2026-10-28): the engine forgot an answered
/// address exactly 60 s after its last DNS answer, while macOS's resolver
/// served that answer for longer (a cached 60 s answer was used 67.6 s after
/// it was received), so every connect in between was answered with a SYN-ACK
/// and then reset: 34 of 121 HTTP probes. A binding is therefore never taken
/// back on a timer. Its address goes to another name only when the pool has
/// no address that was never given out, it is the least recently used
/// binding, no flow or queued reply holds it, and it has been unused for the
/// map's `recycle_idle` (`FakeIpMap::assign`). Use is every DNS answer that
/// carries the address, every lookup or lease of it by a flow, and the end
/// of its last lease.
#[derive(Debug)]
pub struct FakeIpMapping {
    pub hostname: String,
    last_used: FakeIpInstant,
    /// Its place in the use order (`FakeIpMapInner::lru`).
    seq: u64,
    /// This binding of the address (an address rebound to another name is
    /// another binding), so a late lease end never marks the next one used.
    binding: u64,
    /// The marker the flows and queued replies holding this binding share,
    /// by its id. Only that marker's own end clears it, under the map lock
    /// and together with marking the binding used, so the binding stays held
    /// from its first lease until its last lease's end has marked it used.
    lease: Option<(u64, std::sync::Weak<LeaseCore>)>,
}

/// What every lease of one binding shares. When the last of them ends (the
/// flow and its queued replies are gone) the binding's idle time starts.
#[derive(Debug)]
struct LeaseCore {
    inner: std::sync::Weak<Mutex<FakeIpMapInner>>,
    ip: u32,
    binding: u64,
    /// This marker among the binding's markers (`FakeIpMapping::lease`).
    id: u64,
}

impl Drop for LeaseCore {
    fn drop(&mut self) {
        // Never dropped while the map lock is held: the map only clones or
        // creates cores under it, and hands them out.
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let Ok(mut inner) = inner.lock() else {
            return;
        };
        let Some(mapping) = inner.by_ip.get_mut(&self.ip) else {
            return;
        };
        if mapping.binding != self.binding {
            return;
        }
        // The binding stayed held from the last holder's drop until this
        // end took the lock. A newer marker, made by a lease while this end
        // waited for the lock, keeps holding it.
        if mapping.lease.as_ref().is_some_and(|(id, _)| *id == self.id) {
            mapping.lease = None;
        }
        inner.touch(self.ip, FakeIpInstant::now());
    }
}

/// Keeps this mapping bound while a flow or its queued replies still exist.
/// The allocator remains the sole map owner; leases own only a lifetime
/// marker, whose end marks the mapping used.
#[derive(Debug, Clone)]
pub struct FakeIpLease {
    _core: Arc<LeaseCore>,
}

pub struct FakeIpMap {
    pool_start: u32,
    pool_size: u32,
    recycle_idle: Duration,
    inner: Arc<Mutex<FakeIpMapInner>>,
}

struct FakeIpMapInner {
    /// The next offset never given out, and how many such offsets remain.
    cursor: u32,
    fresh: u32,
    by_ip: HashMap<u32, FakeIpMapping>,
    by_host: HashMap<String, Ipv4Addr>,
    /// Use order, least recently used first: `seq` to address.
    lru: std::collections::BTreeMap<u64, u32>,
    next_seq: u64,
    next_binding: u64,
    next_lease: u64,
}

impl FakeIpMapInner {
    /// `ip`'s binding was used at `now`. Every caller reads `now` under the
    /// map lock, so the use order is also the order of `last_used`.
    fn touch(&mut self, ip: u32, now: FakeIpInstant) {
        let seq = self.next_seq;
        let Some(mapping) = self.by_ip.get_mut(&ip) else {
            return;
        };
        self.next_seq += 1;
        self.lru.remove(&mapping.seq);
        mapping.seq = seq;
        mapping.last_used = now;
        self.lru.insert(seq, ip);
    }
}

impl FakeIpMap {
    /// A map over `pool_cidr` whose bindings may go to another name only
    /// after `recycle_idle` unused (see `FakeIpMapping`). It must be far
    /// longer than any resolver or application may keep an answer: the TTL
    /// answered with, and macOS's resolver grace beyond it.
    pub fn new(pool_cidr: &str, recycle_idle: Duration) -> Result<Self, String> {
        let (start, size) = checked_pool(pool_cidr)?;
        Ok(Self {
            pool_start: start,
            pool_size: size,
            recycle_idle,
            inner: Arc::new(Mutex::new(FakeIpMapInner {
                cursor: 2,       // reserve network + 1
                fresh: size - 3, // network, reserved +1 and broadcast
                by_ip: HashMap::new(),
                by_host: HashMap::new(),
                lru: std::collections::BTreeMap::new(),
                next_seq: 0,
                next_binding: 0,
                next_lease: 0,
            })),
        })
    }

    /// Give out never-used addresses from `offset` on (wrapping). A map that
    /// follows another one (a new process) then does not hand the earlier
    /// map's first answers, which applications may still cache, to other
    /// names first. Only before the first assignment.
    #[allow(dead_code)]
    pub fn starting_at(self, offset: u32) -> Self {
        {
            let mut inner = self.inner.lock().expect("dns_preview map lock");
            if inner.fresh == self.pool_size - 3 {
                inner.cursor = 2 + offset % (self.pool_size - 3);
            }
        }
        self
    }

    pub fn ip_in_pool(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        v >= self.pool_start && v < self.pool_start + self.pool_size
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn lookup_hostname(&self, ip: Ipv4Addr) -> Option<String> {
        let key = u32::from(ip);
        let mut inner = self.inner.lock().expect("dns_preview map lock");
        let now = FakeIpInstant::now();
        let hostname = inner.by_ip.get(&key)?.hostname.clone();
        inner.touch(key, now);
        Some(hostname)
    }

    fn lease_hostname(&self, ip: Ipv4Addr) -> Option<(String, FakeIpLease)> {
        let key = u32::from(ip);
        let mut guard = self.inner.lock().expect("dns_preview map lock");
        let now = FakeIpInstant::now();
        let inner = &mut *guard;
        let mapping = inner.by_ip.get_mut(&key)?;
        // Pin under the same allocator lock: the address cannot be rebound
        // between resolving its name and holding its meaning.
        let live = mapping.lease.as_ref().and_then(|(_, core)| core.upgrade());
        let core = match live {
            Some(core) => core,
            None => {
                let id = inner.next_lease;
                inner.next_lease += 1;
                let core = Arc::new(LeaseCore {
                    inner: Arc::downgrade(&self.inner),
                    ip: key,
                    binding: mapping.binding,
                    id,
                });
                mapping.lease = Some((id, Arc::downgrade(&core)));
                core
            }
        };
        let hostname = mapping.hostname.clone();
        inner.touch(key, now);
        Some((hostname, FakeIpLease { _core: core }))
    }

    /// Get-or-assign: a bound name keeps its address, however long ago it
    /// was answered, and the answer marks it used. Returns (fake_ip, was_new);
    /// None when every address is bound and none may be recycled yet.
    pub fn assign(&self, hostname: &str) -> Option<(Ipv4Addr, bool)> {
        let mut guard = self.inner.lock().expect("dns_preview map lock");
        let now = FakeIpInstant::now();
        let inner = &mut *guard;
        if let Some(existing) = inner.by_host.get(hostname).copied() {
            inner.touch(u32::from(existing), now);
            return Some((existing, false));
        }
        let ip = match self.take_fresh(inner) {
            Some(ip) => ip,
            None => {
                let ip = self.recyclable(inner, now)?;
                let old = inner.by_ip.remove(&ip).expect("use order names a binding");
                inner.lru.remove(&old.seq);
                inner.by_host.remove(&old.hostname);
                ip
            }
        };
        let (seq, binding) = (inner.next_seq, inner.next_binding);
        inner.next_seq += 1;
        inner.next_binding += 1;
        inner.by_ip.insert(
            ip,
            FakeIpMapping {
                hostname: hostname.to_string(),
                last_used: now,
                seq,
                binding,
                lease: None,
            },
        );
        inner.lru.insert(seq, ip);
        let address = Ipv4Addr::from(ip);
        inner.by_host.insert(hostname.to_string(), address);
        Some((address, true))
    }

    /// The next address never given out.
    fn take_fresh(&self, inner: &mut FakeIpMapInner) -> Option<u32> {
        if inner.fresh == 0 {
            return None;
        }
        let offset = inner.cursor;
        inner.cursor = if offset + 1 >= self.pool_size - 1 {
            2
        } else {
            offset + 1
        };
        inner.fresh -= 1;
        let ip = self.pool_start + offset;
        debug_assert!(!inner.by_ip.contains_key(&ip));
        Some(ip)
    }

    /// The least recently used binding that nothing holds, once it has been
    /// unused for `recycle_idle`. A held binding is skipped, also after its
    /// last holder's drop until that end has taken the lock and marked it
    /// used; the first unheld one decides, since every later one was used
    /// more recently.
    fn recyclable(&self, inner: &FakeIpMapInner, now: FakeIpInstant) -> Option<u32> {
        for ip in inner.lru.values() {
            let mapping = &inner.by_ip[ip];
            if mapping.lease.is_some() {
                continue;
            }
            return (now.saturating_duration_since(mapping.last_used) >= self.recycle_idle)
                .then_some(*ip);
        }
        None
    }

    /// Reserved for future operator-side admin probes / health reporting.
    /// Kept on the public API surface so callers don't reach into the
    /// internal mutex.
    #[allow(dead_code)]
    pub fn snapshot_size(&self) -> usize {
        self.inner.lock().expect("dns_preview map lock").by_ip.len()
    }
}

/// Resolve the logical relay target without changing the original socket tuple.
/// The reserved synthetic range must never escape as a numeric relay target,
/// including in the standalone UDP helper which has no DNS owner/map.
#[cfg(any(target_os = "linux", test))]
pub fn resolve_target_host(destination: SocketAddr, map: Option<&FakeIpMap>) -> io::Result<String> {
    let synthetic_ip = match destination.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    }
    .filter(|ip| is_synthetic_ip(*ip));
    if let Some(ip) = synthetic_ip {
        return map
            .filter(|map| map.ip_in_pool(ip))
            .and_then(|map| map.lookup_hostname(ip))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "wide_fake_ip_mapping_missing: synthetic target is unknown or expired",
                )
            });
    }
    Ok(destination.ip().to_string())
}

/// Resolve and pin a synthetic UDP target in one allocator transaction. A
/// numeric non-synthetic destination does not need a mapping lease.
pub fn lease_target_host(
    destination: SocketAddr,
    map: Option<&FakeIpMap>,
) -> io::Result<(String, Option<FakeIpLease>)> {
    let synthetic_ip = match destination.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    }
    .filter(|ip| is_synthetic_ip(*ip));
    if let Some(ip) = synthetic_ip {
        return map
            .filter(|map| map.ip_in_pool(ip))
            .and_then(|map| map.lease_hostname(ip))
            .map(|(host, lease)| (host, Some(lease)))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "synthetic destination has no live owned mapping",
                )
            });
    }
    Ok((destination.ip().to_string(), None))
}

fn parse_cidr_v4(s: &str) -> Result<(Ipv4Addr, u8), String> {
    let (ip_s, prefix_s) = s
        .split_once('/')
        .ok_or_else(|| format!("not a CIDR: {s}"))?;
    let ip: Ipv4Addr = ip_s.parse().map_err(|e| format!("ip parse: {e}"))?;
    let prefix: u8 = prefix_s.parse().map_err(|e| format!("prefix parse: {e}"))?;
    if prefix > 32 {
        return Err(format!("prefix {prefix} > 32"));
    }
    Ok((ip, prefix))
}

pub fn question_type(req: &[u8]) -> Option<u16> {
    if req.len() < 12 || u16::from_be_bytes([req[4], req[5]]) != 1 {
        return None;
    }
    let (_, qname_end) = parse_qname(&req[12..])?;
    let qtype_offset = 12 + qname_end;
    (req.len() >= qtype_offset + 4)
        .then(|| u16::from_be_bytes([req[qtype_offset], req[qtype_offset + 1]]))
}

pub fn dns_error_response(req: &[u8], rcode: u8) -> Vec<u8> {
    if req.len() < 12 {
        return Vec::new();
    }
    let question_end = parse_qname(&req[12..])
        .map(|(_, len)| 12 + len + 4)
        .filter(|end| *end <= req.len())
        .unwrap_or(12);
    let mut out = req[..question_end].to_vec();
    out[2] = DNS_QR_RESPONSE | (req[2] & 0x01);
    out[3] = rcode & 0x0f;
    out[6..12].fill(0);
    out
}

/// Build a DNS response. Synthesizes A records with fake IPs; returns NODATA
/// (NOERROR with no answers) for AAAA; NOTIMP for other types; NXDOMAIN
/// for parse failures we can still echo back.
pub fn build_response_with_sink(
    req: &[u8],
    map: &Arc<FakeIpMap>,
    ttl_secs: u32,
    sink: &dyn aegis_client::packet_engine::services::EventSink,
) -> Vec<u8> {
    if req.len() < 12 {
        return Vec::new();
    }
    let id_hi = req[0];
    let id_lo = req[1];
    // Parse QDCOUNT — handle only 1-question queries
    let qdcount = u16::from_be_bytes([req[4], req[5]]);
    if qdcount != 1 {
        return reply_header(id_hi, id_lo, DNS_RCODE_NOTIMPL, 0);
    }
    let (qname, qname_end) = match parse_qname(&req[12..]) {
        Some(x) => x,
        None => return reply_header(id_hi, id_lo, DNS_RCODE_NXDOMAIN, 0),
    };
    let qend = 12 + qname_end;
    if req.len() < qend + 4 {
        return reply_header(id_hi, id_lo, DNS_RCODE_NXDOMAIN, 0);
    }
    let qtype = u16::from_be_bytes([req[qend], req[qend + 1]]);
    let qclass = u16::from_be_bytes([req[qend + 2], req[qend + 3]]);
    if qclass != QCLASS_IN {
        return reply_header(id_hi, id_lo, DNS_RCODE_NOTIMPL, 0);
    }
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&[id_hi, id_lo]);
    // flags: QR=1, AA=1, RCODE=NOERROR
    out.extend_from_slice(&[DNS_QR_RESPONSE | 0x04, DNS_RCODE_NOERROR]);
    // QDCOUNT=1
    out.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT placeholder
    let ancount_off = out.len();
    out.extend_from_slice(&[0x00, 0x00]);
    // NSCOUNT, ARCOUNT = 0
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // copy question section verbatim
    out.extend_from_slice(&req[12..qend + 4]);

    let mut ancount: u16 = 0;
    match qtype {
        QTYPE_A => {
            let hostname = qname.trim_end_matches('.').to_string();
            if hostname.is_empty() || hostname.len() > MAX_NAME_LEN {
                // empty → return NODATA
            } else {
                // Every address is bound and none may be recycled yet: fail
                // the answer rather than take an address a flow, a cache or
                // an application may still use for its own name.
                let Some((ip, was_new)) = map.assign(&hostname) else {
                    return dns_error_response(req, RCODE_SERVFAIL);
                };
                // emit event
                let event = if was_new {
                    aegis_client::packet_engine::services::EngineEvent::DnsFakeIpAssigned
                } else {
                    aegis_client::packet_engine::services::EngineEvent::DnsFakeIpMappingHit
                };
                sink.emit(
                    "info",
                    event,
                    "dns preview fake-ip mapping",
                    json!({
                        "hostname": hostname,
                        "fake_ip": ip.to_string(),
                        "was_new": was_new,
                    }),
                );
                // Answer: name pointer (0xc00c), type A, class IN, TTL, RDLENGTH=4, RDATA
                out.extend_from_slice(&[0xc0, 0x0c]);
                out.extend_from_slice(&QTYPE_A.to_be_bytes());
                out.extend_from_slice(&QCLASS_IN.to_be_bytes());
                out.extend_from_slice(&ttl_secs.to_be_bytes());
                out.extend_from_slice(&[0x00, 0x04]);
                out.extend_from_slice(&ip.octets());
                ancount = 1;
            }
        }
        QTYPE_AAAA => {
            // intentionally return NODATA (no AAAA records) so clients fall
            // back to A; this keeps the fake-IP path simple (IPv4 only).
        }
        _ => {
            // unknown type: NODATA (RCODE=NOERROR, no answers)
        }
    }
    out[ancount_off..ancount_off + 2].copy_from_slice(&ancount.to_be_bytes());
    out
}

fn reply_header(id_hi: u8, id_lo: u8, rcode: u8, ancount: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&[id_hi, id_lo]);
    out.extend_from_slice(&[DNS_QR_RESPONSE | 0x04, rcode]);
    out.extend_from_slice(&[0x00, 0x00]); // QDCOUNT
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS, AR
    out
}

/// Parse a DNS QNAME. Returns (name_as_string, bytes_consumed).
fn parse_qname(input: &[u8]) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut i = 0;
    while i < input.len() {
        let len = input[i] as usize;
        if len == 0 {
            return Some((name, i + 1));
        }
        if len > MAX_LABEL_LEN {
            return None;
        }
        if i + 1 + len > input.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        // labels are case-insensitive ASCII per RFC 1035
        for b in &input[i + 1..i + 1 + len] {
            name.push(b.to_ascii_lowercase() as char);
        }
        if name.len() > MAX_NAME_LEN {
            return None;
        }
        i += 1 + len;
    }
    None
}
