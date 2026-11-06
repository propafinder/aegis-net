//! B-06 S20b leak guard: the per-packet verdict of the NEFilterPacketProvider
//! that runs in the same system extension process as the packet tunnel.
//!
//! The S20 capture window showed kernel residue of sockets opened before the
//! tunnel (TCP keepalives, ICMPv6 errors and echo replies, peer
//! retransmissions) leaving the physical interface while the tunnel was
//! Connected. No tunnel API closes other processes' sockets, so while a
//! tunnel epoch may have its settings applied the filter drops every packet
//! on a physical (Guarded) interface except the provider's own relay
//! traffic and the link control a working network needs (ARP, EAPOL, DHCP,
//! IPv6 ND and MLD).
//!
//! v40 (CP-D3 M1): the guard arms the profile's whole carrier pool, every
//! exact relay pin (a direct relay and CDN edge pins, at most
//! [`MAX_RELAY_PINS`], each an IP and port) and nothing else, so a session
//! rebuilt on another carrier of the pool needs no re-arm and no tuple
//! outside the signed pool is ever allowed. A single-pin profile arms
//! exactly as before.
//!
//! v31 (S23b): the S20b allowance of the enrollment authority's TCP tuple
//! is gone. While the gate guards, the provider dials no tuple other than
//! the relay's ([`Gate::dial_refused`]): a renewal that falls due then is
//! deferred to the next provider start, which runs before any arm, while
//! the gate is Open (R0) and needs no allowance. An authority that is the
//! relay's own tuple is relay traffic. `Reason::Authority` and its
//! `allow_authority` counter stay on the `filter-status` wire for v26 to
//! v30 hosts and always read 0.
//!
//! Shared state is one process-global [`Gate`] of atomics only, written by
//! the tunnel provider on its main runloop and read by the packet handler on
//! any number of threads: a seqlock over the arm token and the relay
//! endpoint. The token is issued by the gate itself at every arm
//! and never repeats in the process, so only the arm that set the gate can
//! open it: provider instances restart their epoch generations at 1, and a
//! late join of an old instance must not open a newer instance's gate. A torn read after three attempts is read as
//! Guarding with no allowed endpoint (fail closed). The process starts Open.
//!
//! [`verdict`] is pure, bounded and allocation free: one framing decision,
//! one IP header walk of at most eight IPv6 extension headers, and the rules
//! below. Nothing here logs, allocates or locks; the per-reason counters are
//! relaxed atomics on their own cache lines.
//!
//! Rules, the first match deciding:
//! - R0 Open gate: Allow (not counted).
//! - R1 tunnel (`utun<n>`, `ipsec<n>`) or loopback (`lo<n>`) interface: Allow.
//! - R2 any other interface is Guarded and framed as Ethernet (one 802.1Q
//!   tag skipped) when the frame is consistent, else as raw IP whose length
//!   is exact, else Drop(malformed). ARP and EAPOL with a plausible header:
//!   Allow(link_control), unless the same bytes are also an exact raw IP
//!   packet (a raw packet's source address can look like the ARP or EAPOL
//!   ethertype and header): then they are judged as that IP packet. Other
//!   non-IP frames: Drop(non_ip).
//! - R3/R4 IPv4 and IPv6: TCP to or from a relay pin (v40: any pin of the
//!   armed set, exact address and port), UDP to a
//!   relay pin only when the profile's carrier allows UDP, DHCPv4/DHCPv6 client
//!   traffic, IPv6 ND with hop limit 255 and MLD with hop limit 1 from a
//!   link-local or unspecified source, inbound ICMP errors quoting a relay
//!   flow, and non-first fragments of a relay address pair. Everything else
//!   drops by its reason (v31: TCP to the enrollment authority's own port
//!   too).
//! - R5 direction Any: Allow when either orientation allows.
//!
//! v27 (S20f) observability, address-free by construction and never part of
//! a verdict: every drop is also counted by the interface class it was
//! presented on ([`DropClass`]: the pinned relay interface, other `en<n>`,
//! `awdl`/`llw`, `bridge`/`ap`/`anpi`, other) and its direction, and written
//! to a ring of the last [`RING_SLOTS`] drops ([`DropRing`]: milliseconds
//! since the arm, class, an interface code that is a known BSD name such as
//! `en7` or a 31-bit hash, direction, IP family, protocol, TCP flag class and
//! reason; never an address, port or payload byte). A ring write is wait
//! free: a `fetch_add` slot index and a per-slot seqlock claimed by one
//! compare-exchange; a writer that meets a busy or newer slot skips (counted)
//! instead of waiting, and a torn slot read is detected and counted. The
//! gate keeps arm accounting (arms, disarms, armed milliseconds and Open
//! intervals while an epoch's settings may be applied), so a transient
//! disarm leaves a trace in `filter-status`.
//!
//! v29 (S20h) observability, still address-free and never part of a
//! verdict. An outbound drop is also counted by its class and kind
//! ([`OutKind`]: the TCP flag class, or `non_tcp`), counted again when it
//! is a TCP segment from a source port of [`MARK_SPORT_FIRST`]'s range (the
//! positive control's pre-existing sockets bind there), and written to a
//! second ring that holds outbound drops only, so an inbound flood never
//! evicts them. The second ring follows the first ring's wait-free write
//! and torn-read rules.
//! Tunnel and loopback packets, which R1 allows in both modes, read only
//! the gate's guarding bit (to count them while guarding) instead of the
//! whole seqlocked snapshot. Their verdict is still Allow, and a torn
//! snapshot is no longer counted for them.
use std::{
    hint::spin_loop,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{
            fence, AtomicBool, AtomicI32, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering,
        },
        OnceLock,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

/// `NEFilterPacketProviderVerdict` as this filter uses it. Delay is never
/// returned: nothing here keeps a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Drop,
}

impl Verdict {
    /// The SDK raw value: Allow 0, Drop 1.
    pub const fn raw(self) -> isize {
        match self {
            Verdict::Allow => 0,
            Verdict::Drop => 1,
        }
    }
}

/// `NETrafficDirection`: Any 0, Inbound 1, Outbound 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Any,
    Inbound,
    Outbound,
}

impl Direction {
    /// An unknown raw value is judged as Any: allowed only when either
    /// orientation would be.
    pub const fn from_raw(raw: isize) -> Self {
        match raw {
            1 => Direction::Inbound,
            2 => Direction::Outbound,
            _ => Direction::Any,
        }
    }

    /// v27: the stable token of a drop's direction (`in`, `out`, `any`).
    pub const fn name(self) -> &'static str {
        match self {
            Direction::Inbound => "in",
            Direction::Outbound => "out",
            Direction::Any => "any",
        }
    }

    /// v27: the slot of a direction in [`DIRECTIONS`] and the drop arrays.
    pub const fn slot(self) -> usize {
        match self {
            Direction::Inbound => 0,
            Direction::Outbound => 1,
            Direction::Any => 2,
        }
    }
}

/// v27: every direction, in drop-array slot order.
pub const DIRECTIONS: [Direction; 3] = [Direction::Inbound, Direction::Outbound, Direction::Any];

/// What the interface name says about the path a packet takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfaceClass {
    /// `utun<n>` or `ipsec<n>`: a tunnel interface (this tunnel's packets).
    Tunnel,
    /// `lo<n>`.
    Loopback,
    /// Everything else, a missing name included: it may reach a wire.
    Guarded,
}

/// `prefix` followed by one to four decimal digits and nothing else.
fn numbered(name: &[u8], prefix: &[u8]) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|rest| (1..=4).contains(&rest.len()) && rest.iter().all(u8::is_ascii_digit))
}

/// The interface class of one `nw_interface_get_name` result. A missing or
/// unexpected name is Guarded (fail closed).
pub fn classify_interface(name: Option<&[u8]>) -> IfaceClass {
    match name {
        Some(name) if numbered(name, b"utun") || numbered(name, b"ipsec") => IfaceClass::Tunnel,
        Some(name) if numbered(name, b"lo") => IfaceClass::Loopback,
        _ => IfaceClass::Guarded,
    }
}

/// Why a packet got its verdict. Every reason but `Open` is counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    TunnelIface,
    LoopbackIface,
    LinkControl,
    Relay,
    /// v31: retired, never a verdict. The S20b enrollment-authority
    /// allowance is gone; the slot and its `allow_authority` counter stay
    /// so the `filter-status` wire still matches v26 to v30 (always 0).
    Authority,
    RelayFragment,
    RelayIcmpError,
    Dhcp4,
    Dhcp6,
    Nd,
    Mld,
    NonIp,
    Malformed,
    Fragment,
    TcpOut,
    TcpIn,
    Udp,
    Mdns,
    Icmp4Out,
    Icmp4In,
    Icmp6Echo,
    Icmp6Error,
    Icmp6Other,
    Igmp,
    OtherProto,
    /// Not a verdict: a snapshot that stayed torn and was read as Guarding
    /// with no endpoint.
    TornSnapshot,
    /// The gate is Open: allowed, never counted.
    Open,
}

/// Every counted reason, in counter order; `Reason::Open` is not counted.
pub const COUNTED: [Reason; 26] = [
    Reason::TunnelIface,
    Reason::LoopbackIface,
    Reason::LinkControl,
    Reason::Relay,
    Reason::Authority,
    Reason::RelayFragment,
    Reason::RelayIcmpError,
    Reason::Dhcp4,
    Reason::Dhcp6,
    Reason::Nd,
    Reason::Mld,
    Reason::NonIp,
    Reason::Malformed,
    Reason::Fragment,
    Reason::TcpOut,
    Reason::TcpIn,
    Reason::Udp,
    Reason::Mdns,
    Reason::Icmp4Out,
    Reason::Icmp4In,
    Reason::Icmp6Echo,
    Reason::Icmp6Error,
    Reason::Icmp6Other,
    Reason::Igmp,
    Reason::OtherProto,
    Reason::TornSnapshot,
];

impl Reason {
    /// The stable token for logs and the XPC `filter-status` reply.
    pub const fn name(self) -> &'static str {
        match self {
            Reason::TunnelIface => "allow_tunnel_iface",
            Reason::LoopbackIface => "allow_loopback_iface",
            Reason::LinkControl => "allow_link_control",
            Reason::Relay => "allow_relay",
            Reason::Authority => "allow_authority",
            Reason::RelayFragment => "allow_relay_fragment",
            Reason::RelayIcmpError => "allow_relay_icmp_error",
            Reason::Dhcp4 => "allow_dhcp4",
            Reason::Dhcp6 => "allow_dhcp6",
            Reason::Nd => "allow_nd",
            Reason::Mld => "allow_mld",
            Reason::NonIp => "drop_non_ip",
            Reason::Malformed => "drop_malformed",
            Reason::Fragment => "drop_fragment",
            Reason::TcpOut => "drop_tcp_out",
            Reason::TcpIn => "drop_tcp_in",
            Reason::Udp => "drop_udp",
            Reason::Mdns => "drop_mdns",
            Reason::Icmp4Out => "drop_icmp4_out",
            Reason::Icmp4In => "drop_icmp4_in",
            Reason::Icmp6Echo => "drop_icmp6_echo",
            Reason::Icmp6Error => "drop_icmp6_error",
            Reason::Icmp6Other => "drop_icmp6_other",
            Reason::Igmp => "drop_igmp",
            Reason::OtherProto => "drop_other_proto",
            Reason::TornSnapshot => "torn_snapshot",
            Reason::Open => "open",
        }
    }

    /// The counter slot, `None` for the uncounted `Open`.
    pub const fn index(self) -> Option<usize> {
        match self {
            Reason::Open => None,
            other => Some(other as usize),
        }
    }
}

/// Whether the gate guards Guarded interfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Open,
    Guarding,
}

/// One TCP (or UDP, for the relay when allowed) endpoint the provider uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub ip: IpAddr,
    pub port: u16,
}

impl From<SocketAddr> for Peer {
    fn from(address: SocketAddr) -> Self {
        Peer {
            ip: canonical(address.ip()),
            port: address.port(),
        }
    }
}

/// An IPv4-mapped IPv6 address compares as the IPv4 address it maps.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// v40: the most relay pins one arm allows: aegis-core's carrier pool bound
/// (`brain::carrier_failover::MAX_CARRIERS`, the v4 profile's 16).
pub const MAX_RELAY_PINS: usize = 16;

const NO_PEER: Peer = Peer {
    ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    port: 0,
};

/// v40 (CP-D3 M1): the exact relay pins one arm allows, in the order given
/// (the profile's pool order), each at most once. Copy and allocation free,
/// so a packet verdict reads it without locking; slots past `len` are
/// always `NO_PEER`, so equal sets compare equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerSet {
    len: u8,
    peers: [Peer; MAX_RELAY_PINS],
}

impl PeerSet {
    pub const EMPTY: PeerSet = PeerSet {
        len: 0,
        peers: [NO_PEER; MAX_RELAY_PINS],
    };

    /// The set of `peers` (a repeated pin kept once); None when more than
    /// [`MAX_RELAY_PINS`] distinct pins are named, never a truncated set.
    pub fn new(peers: &[Peer]) -> Option<PeerSet> {
        let mut set = PeerSet::EMPTY;
        for peer in peers {
            let peer = Peer::from(SocketAddr::new(peer.ip, peer.port));
            if set.contains(peer) {
                continue;
            }
            if usize::from(set.len) == MAX_RELAY_PINS {
                return None;
            }
            set.peers[usize::from(set.len)] = peer;
            set.len += 1;
        }
        Some(set)
    }

    /// The set of one pin, or the empty set.
    pub fn one(peer: Option<Peer>) -> PeerSet {
        match peer {
            Some(peer) => PeerSet::new(&[peer]).unwrap_or(PeerSet::EMPTY),
            None => PeerSet::EMPTY,
        }
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[Peer] {
        &self.peers[..self.len()]
    }

    /// The first pin (the profile's primary), if any.
    pub fn first(&self) -> Option<Peer> {
        self.as_slice().first().copied()
    }

    /// Whether `peer` is one of the pins: address and port exactly.
    pub fn contains(&self, peer: Peer) -> bool {
        self.as_slice().contains(&peer)
    }

    /// Whether `ip` is the address of one of the pins (any port): only for a
    /// later fragment or an ICMP error quoting a pinned flow, which carry no
    /// port of their own to compare.
    pub fn has_ip(&self, ip: IpAddr) -> bool {
        self.as_slice().iter().any(|peer| peer.ip == ip)
    }
}

/// A consistent view of the gate. v31: no enrollment-authority endpoint;
/// the relay is the only peer a guarding gate allows. v40: the relay pool's
/// exact pins (`relays`), one for a single-pin profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub mode: Mode,
    /// The arm token while Guarding (0 when Open or torn).
    pub token: u64,
    pub relays: PeerSet,
    pub udp_relay: bool,
    /// D6's separately owned exact media tuples; never derived from TCP pins.
    pub udp_media: PeerSet,
}

impl Snapshot {
    pub const OPEN: Snapshot = Snapshot {
        mode: Mode::Open,
        token: 0,
        relays: PeerSet::EMPTY,
        udp_relay: false,
        udp_media: PeerSet::EMPTY,
    };
    /// What a torn read becomes: Guarding, nothing allowed but link control.
    pub const FAIL_CLOSED: Snapshot = Snapshot {
        mode: Mode::Guarding,
        token: 0,
        relays: PeerSet::EMPTY,
        udp_relay: false,
        udp_media: PeerSet::EMPTY,
    };

    /// v31: whether a provider dial of TCP to `target` must not be made
    /// under this view: while guarding, anything but a relay pin's own tuple
    /// (v40: any pin of the armed pool; a torn view guards with no pin, so
    /// it refuses every dial).
    pub fn dial_refused(&self, target: SocketAddr) -> bool {
        self.mode == Mode::Guarding && !self.relays.contains(Peer::from(target))
    }
}

/// One endpoint cell: family 0 (none), 4 or 6, the address words and port.
struct PeerCell {
    family: AtomicU8,
    words: [AtomicU32; 4],
    port: AtomicU16,
}

impl PeerCell {
    const fn new() -> Self {
        PeerCell {
            family: AtomicU8::new(0),
            words: [const { AtomicU32::new(0) }; 4],
            port: AtomicU16::new(0),
        }
    }

    fn store(&self, peer: Option<Peer>) {
        let (family, octets, port) = match peer {
            None => (0, [0u8; 16], 0),
            Some(Peer {
                ip: IpAddr::V4(v4),
                port,
            }) => {
                let mut octets = [0u8; 16];
                octets[..4].copy_from_slice(&v4.octets());
                (4, octets, port)
            }
            Some(Peer {
                ip: IpAddr::V6(v6),
                port,
            }) => (6, v6.octets(), port),
        };
        self.family.store(family, Ordering::Relaxed);
        for (word, chunk) in self.words.iter().zip(octets.chunks_exact(4)) {
            word.store(
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                Ordering::Relaxed,
            );
        }
        self.port.store(port, Ordering::Relaxed);
    }

    fn load(&self) -> Option<Peer> {
        let family = self.family.load(Ordering::Relaxed);
        let mut octets = [0u8; 16];
        for (word, chunk) in self.words.iter().zip(octets.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_be_bytes());
        }
        let port = self.port.load(Ordering::Relaxed);
        let ip = match family {
            4 => IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
            6 => IpAddr::V6(Ipv6Addr::from(octets)),
            _ => return None,
        };
        Some(Peer { ip, port })
    }
}

/// The proof of one [`Gate::arm`]: process-unique, it alone can open that
/// arm. Never constructed outside this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmToken(u64);

impl ArmToken {
    /// The token's number, for logs and comparison with a snapshot.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Read attempts before a snapshot is taken as torn.
pub const SNAPSHOT_ATTEMPTS: usize = 3;

/// The seqlocked gate. Writers exclude each other through the odd sequence
/// value; readers never block a writer.
pub struct Gate {
    seq: AtomicU32,
    guarding: AtomicBool,
    /// The token of the arm that set the gate.
    token: AtomicU64,
    /// The last token issued; tokens start at 1 and never repeat. v27: also
    /// the arm sequence number of `filter-status`.
    issued: AtomicU64,
    /// v40: the armed pins, `relay_count` of them (at most
    /// [`MAX_RELAY_PINS`]), in the arm's order.
    relays: [PeerCell; MAX_RELAY_PINS],
    relay_count: AtomicU8,
    /// Pins installed by the arm itself cannot be withdrawn by a descriptor
    /// stream's drop; only slots after this count are transient D5 pins.
    base_count: AtomicU8,
    udp_relay: AtomicBool,
    udp_media: [PeerCell; MAX_RELAY_PINS],
    udp_media_count: AtomicU8,
    /// v27: [`clock_ms`] at the arm of `token` (written in the arm's write
    /// section, read under the seqlock with it).
    armed_at_ms: AtomicU64,
    /// v27: [`clock_ms`] when the gate last went from Open to Guarding; a
    /// re-arm while guarding keeps it.
    guarding_since_ms: AtomicU64,
    /// v27: the milliseconds of every guarding span that ended.
    armed_total_ms: AtomicU64,
    /// v27: disarms that opened the gate.
    disarms: AtomicU64,
    /// v27: epochs whose settings may be applied ([`Gate::note_applied`]
    /// less [`Gate::note_withdrawn`]); control path only.
    applied: AtomicU64,
    /// v27: Open intervals that began while an epoch's settings may be
    /// applied: an open by disarm while `applied` > 0, or an epoch noted
    /// applied while the gate was Open.
    open_while_applied: AtomicU64,
    /// v27: the [`iface_code`] of the epoch's pinned relay interface (0:
    /// none), the `primary` drop class. One atomic, never torn.
    primary: AtomicU32,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    pub const fn new() -> Self {
        Gate {
            seq: AtomicU32::new(0),
            guarding: AtomicBool::new(false),
            token: AtomicU64::new(0),
            issued: AtomicU64::new(0),
            relays: [const { PeerCell::new() }; MAX_RELAY_PINS],
            relay_count: AtomicU8::new(0),
            base_count: AtomicU8::new(0),
            udp_relay: AtomicBool::new(false),
            udp_media: [const { PeerCell::new() }; MAX_RELAY_PINS],
            udp_media_count: AtomicU8::new(0),
            armed_at_ms: AtomicU64::new(0),
            guarding_since_ms: AtomicU64::new(0),
            armed_total_ms: AtomicU64::new(0),
            disarms: AtomicU64::new(0),
            applied: AtomicU64::new(0),
            open_while_applied: AtomicU64::new(0),
            primary: AtomicU32::new(0),
        }
    }

    /// One write section: the sequence turns odd (claimed against every
    /// other writer), the fields are stored, then it turns even again.
    fn write(&self, body: impl FnOnce(&Self)) {
        let mut seq = self.seq.load(Ordering::Relaxed);
        loop {
            if seq & 1 == 0 {
                match self.seq.compare_exchange_weak(
                    seq,
                    seq.wrapping_add(1),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(now) => seq = now,
                }
            } else {
                spin_loop();
                seq = self.seq.load(Ordering::Relaxed);
            }
        }
        fence(Ordering::Release);
        body(self);
        self.seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    /// Guard, allowing exactly this relay endpoint, and return the token
    /// that alone can open this arm. A re-arm replaces the endpoint and
    /// supersedes every earlier token. v31: there is no second (authority)
    /// endpoint any more.
    pub fn arm(&self, relay: Option<Peer>, udp_relay: bool) -> ArmToken {
        self.arm_at(relay, udp_relay, control_clock_ms())
    }

    /// [`Gate::arm`] at `now` on the [`clock_ms`] clock.
    pub(crate) fn arm_at(&self, relay: Option<Peer>, udp_relay: bool, now: u64) -> ArmToken {
        self.arm_pins_at(&PeerSet::one(relay), udp_relay, now)
    }

    /// v40 (CP-D3 M1): guard, allowing exactly the pins of `relays` (the
    /// profile's carrier pool) and nothing else, and return the arm's token.
    /// An empty set allows only link control (fail closed).
    pub fn arm_pins(&self, relays: &PeerSet, udp_relay: bool) -> ArmToken {
        self.arm_pins_at(relays, udp_relay, control_clock_ms())
    }

    pub(crate) fn arm_pins_with_base(
        &self,
        relays: &PeerSet,
        base_count: usize,
        udp_relay: bool,
    ) -> Option<ArmToken> {
        (base_count <= relays.len()).then(|| {
            self.arm_pins_with_base_at(relays, base_count as u8, udp_relay, control_clock_ms())
        })
    }

    /// Extend only the current TCP-only arm by one exact authenticated
    /// descriptor socket. The caller must hold the arm token and verify the
    /// descriptor against its signed generation before invoking this. This
    /// never opens the gate, changes the token, or enables UDP for the pin.
    /// A stale epoch, torn state, empty/invalid peer or full set refuses.
    pub(crate) fn amend_tcp_pin(&self, token: ArmToken, socket: SocketAddr) -> bool {
        let peer = Peer::from(socket);
        if peer.port == 0 || peer.ip.is_unspecified() || peer.ip.is_multicast() {
            return false;
        }
        let mut accepted = false;
        self.write(|gate| {
            if !gate.guarding.load(Ordering::Relaxed)
                || gate.token.load(Ordering::Relaxed) != token.0
                || gate.udp_relay.load(Ordering::Relaxed)
            {
                return;
            }
            let count = usize::from(gate.relay_count.load(Ordering::Relaxed));
            if count > MAX_RELAY_PINS {
                return;
            }
            if (0..count).any(|index| gate.relays[index].load() == Some(peer)) {
                accepted = true;
                return;
            }
            if count == MAX_RELAY_PINS {
                return;
            }
            gate.relays[count].store(Some(peer));
            gate.relay_count.store((count + 1) as u8, Ordering::Relaxed);
            accepted = true;
        });
        accepted
    }

    /// Withdraw a transient descriptor pin after its final stream owner
    /// drops. A signed base pin cannot be removed, and another arm's token
    /// cannot be touched. Readers observe the whole compacted set or a
    /// fail-closed torn view through the same seqlock as arm/amend.
    pub(crate) fn withdraw_tcp_pin(&self, token: ArmToken, socket: SocketAddr) -> bool {
        let peer = Peer::from(socket);
        let mut withdrawn = false;
        self.write(|gate| {
            if !gate.guarding.load(Ordering::Relaxed)
                || gate.token.load(Ordering::Relaxed) != token.0
            {
                return;
            }
            let base = usize::from(gate.base_count.load(Ordering::Relaxed));
            let count = usize::from(gate.relay_count.load(Ordering::Relaxed));
            let Some(index) = (base..count).find(|&index| gate.relays[index].load() == Some(peer))
            else {
                return;
            };
            for next in index + 1..count {
                gate.relays[next - 1].store(gate.relays[next].load());
            }
            gate.relays[count - 1].store(None);
            gate.relay_count.store((count - 1) as u8, Ordering::Relaxed);
            withdrawn = true;
        });
        withdrawn
    }

    /// A verified SFU candidate's exact UDP tuple, separate from the TCP
    /// carrier pool. A descriptor never sets the arm-wide `udp_relay` bit.
    pub(crate) fn amend_udp_media(&self, token: ArmToken, socket: SocketAddr) -> bool {
        let peer = Peer::from(socket);
        if peer.port == 0 || peer.ip.is_unspecified() || peer.ip.is_multicast() {
            return false;
        }
        let mut accepted = false;
        self.write(|gate| {
            if !gate.guarding.load(Ordering::Relaxed)
                || gate.token.load(Ordering::Relaxed) != token.0
                || gate.udp_relay.load(Ordering::Relaxed)
            {
                return;
            }
            let count = usize::from(gate.udp_media_count.load(Ordering::Relaxed));
            if count > MAX_RELAY_PINS {
                return;
            }
            if (0..count).any(|index| gate.udp_media[index].load() == Some(peer)) {
                accepted = true;
                return;
            }
            if count == MAX_RELAY_PINS {
                return;
            }
            gate.udp_media[count].store(Some(peer));
            gate.udp_media_count
                .store((count + 1) as u8, Ordering::Relaxed);
            accepted = true;
        });
        accepted
    }

    pub(crate) fn withdraw_udp_media(&self, token: ArmToken, socket: SocketAddr) -> bool {
        let peer = Peer::from(socket);
        let mut withdrawn = false;
        self.write(|gate| {
            if !gate.guarding.load(Ordering::Relaxed)
                || gate.token.load(Ordering::Relaxed) != token.0
            {
                return;
            }
            let count = usize::from(gate.udp_media_count.load(Ordering::Relaxed));
            let Some(index) = (0..count).find(|&index| gate.udp_media[index].load() == Some(peer))
            else {
                return;
            };
            for next in index + 1..count {
                gate.udp_media[next - 1].store(gate.udp_media[next].load());
            }
            gate.udp_media[count - 1].store(None);
            gate.udp_media_count
                .store((count - 1) as u8, Ordering::Relaxed);
            withdrawn = true;
        });
        withdrawn
    }

    /// [`Gate::arm_pins`] at `now` on the [`clock_ms`] clock.
    pub(crate) fn arm_pins_at(&self, relays: &PeerSet, udp_relay: bool, now: u64) -> ArmToken {
        self.arm_pins_with_base_at(relays, relays.len, udp_relay, now)
    }

    fn arm_pins_with_base_at(
        &self,
        relays: &PeerSet,
        base_count: u8,
        udp_relay: bool,
        now: u64,
    ) -> ArmToken {
        let mut token = ArmToken(0);
        self.write(|gate| {
            // Issued inside the write section: writers are serialized, so the
            // stored token is always the newest one issued.
            token = ArmToken(gate.issued.load(Ordering::Relaxed).wrapping_add(1));
            gate.issued.store(token.0, Ordering::Relaxed);
            gate.token.store(token.0, Ordering::Relaxed);
            for (index, cell) in gate.relays.iter().enumerate() {
                cell.store(relays.as_slice().get(index).copied());
            }
            gate.relay_count.store(relays.len, Ordering::Relaxed);
            gate.base_count.store(base_count, Ordering::Relaxed);
            gate.udp_relay.store(udp_relay, Ordering::Relaxed);
            for cell in &gate.udp_media {
                cell.store(None);
            }
            gate.udp_media_count.store(0, Ordering::Relaxed);
            // v27: a guarding span starts only when the gate was Open; a
            // re-arm continues it.
            if !gate.guarding.load(Ordering::Relaxed) {
                gate.guarding_since_ms.store(now, Ordering::Relaxed);
            }
            gate.armed_at_ms.store(now, Ordering::Relaxed);
            gate.guarding.store(true, Ordering::Relaxed);
        });
        token
    }

    /// Open the gate, but only when it still guards the arm of `token`: a
    /// superseded arm (an older epoch, or another provider instance whose
    /// generations also started at 1) can never open a newer one. True when
    /// this opened it.
    pub fn disarm(&self, token: ArmToken) -> bool {
        self.disarm_at(token, control_clock_ms())
    }

    /// [`Gate::disarm`] at `now` on the [`clock_ms`] clock.
    pub(crate) fn disarm_at(&self, token: ArmToken, now: u64) -> bool {
        let mut opened = false;
        self.write(|gate| {
            if gate.guarding.load(Ordering::Relaxed)
                && gate.token.load(Ordering::Relaxed) == token.0
            {
                // The endpoints stay until the next arm replaces them: an
                // Open snapshot never reads them.
                gate.guarding.store(false, Ordering::Relaxed);
                opened = true;
                // v27: the span's length, the disarm, and an Open interval
                // while an epoch may still have its settings applied.
                let since = gate.guarding_since_ms.load(Ordering::Relaxed);
                gate.armed_total_ms
                    .fetch_add(now.saturating_sub(since), Ordering::Relaxed);
                gate.disarms.fetch_add(1, Ordering::Relaxed);
                if gate.applied.load(Ordering::Relaxed) > 0 {
                    gate.open_while_applied.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        opened
    }

    /// v27: an epoch's settings may take effect from now on (called right
    /// after its arm, on the provider's main runloop). Noted while the gate
    /// is Open, it counts an Open interval while applied. No write section:
    /// a packet reader never retries for it.
    pub fn note_applied(&self) {
        self.applied.fetch_add(1, Ordering::AcqRel);
        if !self.guarding.load(Ordering::Acquire) {
            self.open_while_applied.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// v27: an epoch noted applied has joined and stopped (called right
    /// before its disarm). Saturates at zero.
    pub fn note_withdrawn(&self) {
        let _ = self
            .applied
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_sub(1))
            });
    }

    /// v27: the pinned relay interface of the arming epoch (the `primary`
    /// drop class); `None` clears it. Control path only.
    pub fn set_primary(&self, name: Option<&[u8]>) {
        self.primary.store(iface_code(name), Ordering::Relaxed);
    }

    /// v27: the [`iface_code`] of the pinned relay interface, 0 for none.
    pub fn primary(&self) -> u32 {
        self.primary.load(Ordering::Relaxed)
    }

    /// v29: the guarding bit alone, one relaxed load. Only the counting of
    /// packets R1 allows in both modes reads it; every verdict that depends
    /// on the gate reads a whole snapshot.
    pub fn guarding_now(&self) -> bool {
        self.guarding.load(Ordering::Relaxed)
    }

    /// v31 (S23b): whether the provider must not dial TCP to `target` now:
    /// the gate guards (any arm, of any epoch or provider instance) and
    /// `target` is not an armed relay pin's tuple (v40: any pin of the
    /// pool). A torn read refuses. The renewal step and its monitor ask this
    /// before any dial or seal.
    pub fn dial_refused(&self, target: SocketAddr) -> bool {
        self.snapshot().0.dial_refused(target)
    }

    /// One consistent snapshot, and whether it was torn (then
    /// `Snapshot::FAIL_CLOSED`). An Open gate is read with two loads and a
    /// re-check of the sequence.
    pub fn snapshot(&self) -> (Snapshot, bool) {
        let (snapshot, torn, _) = self.read();
        (snapshot, torn)
    }

    /// [`Gate::snapshot`] and, while guarding, the [`clock_ms`] of the arm
    /// of its token (0 when Open or torn).
    pub(crate) fn read(&self) -> (Snapshot, bool, u64) {
        for _ in 0..SNAPSHOT_ATTEMPTS {
            let before = self.seq.load(Ordering::Acquire);
            if before & 1 == 1 {
                spin_loop();
                continue;
            }
            let guarding = self.guarding.load(Ordering::Relaxed);
            let (snapshot, armed_at) = if guarding {
                (
                    Snapshot {
                        mode: Mode::Guarding,
                        token: self.token.load(Ordering::Relaxed),
                        relays: self.load_relays(),
                        udp_relay: self.udp_relay.load(Ordering::Relaxed),
                        udp_media: self.load_udp_media(),
                    },
                    self.armed_at_ms.load(Ordering::Relaxed),
                )
            } else {
                (Snapshot::OPEN, 0)
            };
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == before {
                return (snapshot, false, armed_at);
            }
        }
        (Snapshot::FAIL_CLOSED, true, 0)
    }

    /// v40: the armed pins, read inside a snapshot's seqlock: the count
    /// (bounded) and that many cells. A cell that reads as no pin ends the
    /// set there, so a set never holds a placeholder.
    fn load_relays(&self) -> PeerSet {
        let count = usize::from(self.relay_count.load(Ordering::Relaxed)).min(MAX_RELAY_PINS);
        let mut set = PeerSet::EMPTY;
        for cell in &self.relays[..count] {
            let Some(peer) = cell.load() else {
                break;
            };
            set.peers[usize::from(set.len)] = peer;
            set.len += 1;
        }
        set
    }

    fn load_udp_media(&self) -> PeerSet {
        let count = usize::from(self.udp_media_count.load(Ordering::Relaxed)).min(MAX_RELAY_PINS);
        let mut set = PeerSet::EMPTY;
        for cell in &self.udp_media[..count] {
            let Some(peer) = cell.load() else { break };
            set.peers[usize::from(set.len)] = peer;
            set.len += 1;
        }
        set
    }

    /// v27: the arm accounting at this moment.
    pub fn arm_stats(&self) -> ArmStats {
        self.arm_stats_at(control_clock_ms())
    }

    /// [`Gate::arm_stats`] at `now` on the [`clock_ms`] clock. The span
    /// fields are read under the seqlock; after three torn attempts the
    /// last read is reported (diagnostics only, never a verdict).
    pub(crate) fn arm_stats_at(&self, now: u64) -> ArmStats {
        let mut read = ArmStats::default();
        for _ in 0..SNAPSHOT_ATTEMPTS {
            let before = self.seq.load(Ordering::Acquire);
            if before & 1 == 1 {
                spin_loop();
                continue;
            }
            let guarding = self.guarding.load(Ordering::Relaxed);
            let since = self.guarding_since_ms.load(Ordering::Relaxed);
            let armed_at = self.armed_at_ms.load(Ordering::Relaxed);
            let total = self.armed_total_ms.load(Ordering::Relaxed);
            read = ArmStats {
                arm_seq: self.issued.load(Ordering::Relaxed),
                disarms: self.disarms.load(Ordering::Relaxed),
                armed_ms_total: total.saturating_add(if guarding {
                    now.saturating_sub(since)
                } else {
                    0
                }),
                armed_for_ms: guarding.then(|| now.saturating_sub(armed_at)),
                open_while_applied: self.open_while_applied.load(Ordering::Relaxed),
                applied_epochs: self.applied.load(Ordering::Relaxed),
                primary: self.primary.load(Ordering::Relaxed),
            };
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == before {
                break;
            }
        }
        read
    }

    /// Test seam: a writer holding the sequence odd, as one paused mid-write.
    #[cfg(test)]
    pub(crate) fn hold_write_for_test(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::AcqRel)
    }
    #[cfg(test)]
    pub(crate) fn release_write_for_test(&self) {
        self.seq.fetch_add(1, Ordering::AcqRel);
    }
}

/// The process-global gate. Both providers of the system extension run in
/// this one process (Apple DTS, forum threads 695969 and 791216).
pub static LEAK_GUARD: Gate = Gate::new();

/// One counter on its own cache line.
#[repr(align(64))]
struct Padded(AtomicU64);

/// Per-reason verdict counters, and (v27) the drops by interface class and
/// direction and the ring of the last drops, and (v29) the outbound drops by
/// class and kind, the marked ones among them and a ring of outbound drops.
pub struct Counters {
    reasons: [Padded; COUNTED.len()],
    /// `[class][direction]`, in [`DROP_CLASSES`] and [`DIRECTIONS`] order.
    drops: [[Padded; DIRECTIONS.len()]; DROP_CLASSES.len()],
    ring: DropRing,
    /// v29: outbound drops by `[class][kind]`, in [`DROP_CLASSES`] and
    /// [`OUT_KINDS`] order.
    out_kinds: [[Padded; OUT_KINDS.len()]; DROP_CLASSES.len()],
    /// v29: those of `out_kinds` that carried the marker ([`marked_sport`]).
    out_marked: [[Padded; OUT_KINDS.len()]; DROP_CLASSES.len()],
    /// v29: the last outbound drops only; inbound and Any drops never
    /// reach it.
    out_ring: DropRing,
}

/// v27: drops by `[class][direction]`.
pub type DropCounts = [[u64; DIRECTIONS.len()]; DROP_CLASSES.len()];

/// v29: outbound drops by `[class][kind]`.
pub type OutCounts = [[u64; OUT_KINDS.len()]; DROP_CLASSES.len()];

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

/// One `[class][kind]` table of padded counters.
fn out_table_snapshot(table: &[[Padded; OUT_KINDS.len()]; DROP_CLASSES.len()]) -> OutCounts {
    let mut values = [[0; OUT_KINDS.len()]; DROP_CLASSES.len()];
    for (row, slots) in values.iter_mut().zip(table.iter()) {
        for (value, slot) in row.iter_mut().zip(slots.iter()) {
            *value = slot.0.load(Ordering::Relaxed);
        }
    }
    values
}

impl Counters {
    pub const fn new() -> Self {
        Counters {
            reasons: [const { Padded(AtomicU64::new(0)) }; COUNTED.len()],
            drops: [const { [const { Padded(AtomicU64::new(0)) }; DIRECTIONS.len()] };
                DROP_CLASSES.len()],
            ring: DropRing::new(),
            out_kinds: [const { [const { Padded(AtomicU64::new(0)) }; OUT_KINDS.len()] };
                DROP_CLASSES.len()],
            out_marked: [const { [const { Padded(AtomicU64::new(0)) }; OUT_KINDS.len()] };
                DROP_CLASSES.len()],
            out_ring: DropRing::new(),
        }
    }

    /// v29: one outbound drop of `kind` on an interface of `class`, and
    /// once more in the marked table when it carried the marker.
    pub fn count_out(&self, class: DropClass, kind: OutKind, marked: bool) {
        let bump = |table: &[[Padded; OUT_KINDS.len()]; DROP_CLASSES.len()]| {
            if let Some(slot) = table.get(class.slot()).and_then(|row| row.get(kind.slot())) {
                slot.0.fetch_add(1, Ordering::Relaxed);
            }
        };
        bump(&self.out_kinds);
        if marked {
            bump(&self.out_marked);
        }
    }

    /// v29: the outbound drops by `[class][kind]`, and the marked ones.
    /// The marked table is read first, so (writes counting both tables
    /// first in `out_kinds`) a quiescent read never shows more marked
    /// than all drops of a cell.
    pub fn out_snapshot(&self) -> (OutCounts, OutCounts) {
        let marked = out_table_snapshot(&self.out_marked);
        (out_table_snapshot(&self.out_kinds), marked)
    }

    /// v29: the ring of the last outbound drops.
    pub fn out_ring(&self) -> &DropRing {
        &self.out_ring
    }

    pub fn count(&self, reason: Reason) {
        if let Some(slot) = reason.index().and_then(|index| self.reasons.get(index)) {
            slot.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> [u64; COUNTED.len()] {
        let mut values = [0; COUNTED.len()];
        for (value, slot) in values.iter_mut().zip(self.reasons.iter()) {
            *value = slot.0.load(Ordering::Relaxed);
        }
        values
    }

    /// v27: one drop on an interface of `class` in `direction`.
    pub fn count_drop(&self, class: DropClass, direction: Direction) {
        if let Some(slot) = self
            .drops
            .get(class.slot())
            .and_then(|row| row.get(direction.slot()))
        {
            slot.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// v27: the drops by `[class][direction]`.
    pub fn drop_snapshot(&self) -> DropCounts {
        let mut values = [[0; DIRECTIONS.len()]; DROP_CLASSES.len()];
        for (row, slots) in values.iter_mut().zip(self.drops.iter()) {
            for (value, slot) in row.iter_mut().zip(slots.iter()) {
                *value = slot.0.load(Ordering::Relaxed);
            }
        }
        values
    }

    /// v27: the ring of the last drops.
    pub fn ring(&self) -> &DropRing {
        &self.ring
    }

    /// v27, the drop path only: the class and direction counter and one
    /// ring record. Bounded, allocation and lock free.
    #[allow(clippy::too_many_arguments)]
    fn record_drop(
        &self,
        primary: u32,
        token: u64,
        armed_at: u64,
        interface: Option<&[u8]>,
        direction: Direction,
        bytes: &[u8],
        reason: Reason,
        now: u64,
    ) {
        let iface = iface_code(interface);
        let class = drop_class(iface, primary);
        self.count_drop(class, direction);
        let summary = summarize(bytes);
        let record = DropRecord {
            arm_seq: u32::try_from(token).unwrap_or(u32::MAX),
            ms: u32::try_from(now.saturating_sub(armed_at)).unwrap_or(u32::MAX),
            iface,
            class,
            direction,
            family: summary.family,
            protocol: summary.protocol,
            tcp: summary.tcp,
            reason,
        };
        self.ring.record(&record);
        // v29: outbound drops only, by kind, marked or not, and into the
        // outbound ring, which no inbound flood can overwrite.
        if direction == Direction::Outbound {
            let marked = summary.family != 0 && marked_sport(summary.sport);
            self.count_out(class, OutKind::of(summary.protocol, summary.tcp), marked);
            self.out_ring.record_marked(&record, marked);
        }
    }
}

pub static COUNTERS: Counters = Counters::new();

/// Whether the filter provider of this process is started, its pid, and
/// how many times it stopped.
///
/// v26: the stop count is the provider-side enforcement point of the
/// leak guard's administrator gate. The gate on `--disable-filter` and
/// `--remove-filter` lives only in the host, and any signed host (an older
/// build without the prompt, too) can change the filter configuration, so
/// a tunnel epoch records the count when it arms the guard and fails closed
/// when the filter stopped since (`apple::filter_stopped_since_arm`).
pub struct Attachment {
    attached: AtomicBool,
    pid: AtomicI32,
    stops: AtomicU64,
}

impl Default for Attachment {
    fn default() -> Self {
        Self::new()
    }
}

impl Attachment {
    pub const fn new() -> Self {
        Attachment {
            attached: AtomicBool::new(false),
            pid: AtomicI32::new(0),
            stops: AtomicU64::new(0),
        }
    }
    pub fn attach(&self, pid: i32) {
        self.pid.store(pid, Ordering::Relaxed);
        self.attached.store(true, Ordering::Release);
    }
    /// `stopFilter`: detached, and one more stop counted (never wraps in
    /// practice; a wrapped count still differs from the recorded one).
    pub fn detach(&self) {
        self.attached.store(false, Ordering::Release);
        self.stops.fetch_add(1, Ordering::AcqRel);
    }
    /// Stops of the filter in this process; 0 before any stop.
    pub fn stops(&self) -> u64 {
        self.stops.load(Ordering::Acquire)
    }
    pub fn attached(&self) -> bool {
        self.attached.load(Ordering::Acquire)
    }
    /// The pid `startFilter` recorded; 0 before any start.
    pub fn pid(&self) -> i32 {
        self.pid.load(Ordering::Relaxed)
    }
}

pub static ATTACHMENT: Attachment = Attachment::new();

/// The whole per-packet path: snapshot, interface class, verdict, count.
/// v27: a drop is also counted by interface class and direction and
/// written to the drop ring; the verdict never depends on either.
pub fn filter_packet(
    gate: &Gate,
    counters: &Counters,
    interface: Option<&[u8]>,
    direction: isize,
    bytes: &[u8],
) -> Verdict {
    filter_packet_with(gate, counters, interface, direction, bytes, clock_ms)
}

/// [`filter_packet`] with the clock of the drop ring injected; it is read
/// only for a drop.
///
/// v29: a tunnel or loopback packet is allowed in both modes (R0, R1), so
/// it reads only the guarding bit, to count it as before while guarding,
/// and never the seqlocked snapshot (no retry, no torn count). Every other
/// packet takes the snapshot path unchanged.
pub(crate) fn filter_packet_with(
    gate: &Gate,
    counters: &Counters,
    interface: Option<&[u8]>,
    direction: isize,
    bytes: &[u8],
    now: impl FnOnce() -> u64,
) -> Verdict {
    let iface = classify_interface(interface);
    let allowed_iface = match iface {
        IfaceClass::Tunnel => Some(Reason::TunnelIface),
        IfaceClass::Loopback => Some(Reason::LoopbackIface),
        IfaceClass::Guarded => None,
    };
    if let Some(reason) = allowed_iface {
        if gate.guarding_now() {
            counters.count(reason);
        }
        return Verdict::Allow;
    }
    let (snapshot, torn, armed_at) = gate.read();
    if torn {
        counters.count(Reason::TornSnapshot);
    }
    if snapshot.mode == Mode::Open {
        return Verdict::Allow;
    }
    let direction = Direction::from_raw(direction);
    let (verdict, reason) = verdict(&snapshot, iface, direction, bytes);
    counters.count(reason);
    if verdict == Verdict::Drop {
        counters.record_drop(
            gate.primary(),
            snapshot.token,
            armed_at,
            interface,
            direction,
            bytes,
            reason,
            now(),
        );
    }
    verdict
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_EAPOL: u16 = 0x888E;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERNET_HEADER: usize = 14;
const VLAN_TAG: usize = 4;
const PROTO_ICMP: u8 = 1;
const PROTO_IGMP: u8 = 2;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;
const IPV6_HEADER: usize = 40;
/// IPv6 extension headers walked before the upper-layer protocol.
pub const MAX_EXTENSION_HEADERS: usize = 8;
const MDNS_PORT: u16 = 5353;

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

/// How a frame on a Guarded interface decodes.
#[derive(Debug, PartialEq, Eq)]
enum Frame<'a> {
    Ip(&'a [u8]),
    LinkControl,
    NonIp,
    Malformed,
}

/// The IP packet's own length against what is available: `exact` for raw
/// IP framing (no trailer), at most the available bytes after an Ethernet
/// header (a minimum-size frame carries padding).
fn ip_consistent(packet: &[u8], exact: bool) -> bool {
    let length = match packet.first().map(|b| b >> 4) {
        Some(4) => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            match be16(packet, 2) {
                Some(total) if ihl >= 20 && usize::from(total) >= ihl => usize::from(total),
                _ => return false,
            }
        }
        Some(6) => match be16(packet, 4) {
            Some(payload) => IPV6_HEADER + usize::from(payload),
            None => return false,
        },
        _ => return false,
    };
    if exact {
        length == packet.len()
    } else {
        length <= packet.len()
    }
}

/// ARP for IPv4 over Ethernet: htype 1, ptype 0x0800, hlen 6, plen 4.
fn arp_plausible(payload: &[u8]) -> bool {
    payload.get(..6) == Some(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04][..])
}

/// EAPOL: protocol version 1 to 3 and a packet type up to 8.
fn eapol_plausible(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(1..=3)) && matches!(payload.get(1), Some(0..=8))
}

fn frame(bytes: &[u8]) -> Frame<'_> {
    if let Some(ethertype) = be16(bytes, 12) {
        let (ethertype, offset) = if ethertype == ETHERTYPE_VLAN {
            match be16(bytes, 16) {
                Some(inner) => (inner, ETHERNET_HEADER + VLAN_TAG),
                None => (0, bytes.len()),
            }
        } else {
            (ethertype, ETHERNET_HEADER)
        };
        let payload = bytes.get(offset..).unwrap_or(&[]);
        match ethertype {
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 if ip_consistent(payload, false) => {
                let version = if ethertype == ETHERTYPE_IPV4 { 4 } else { 6 };
                if payload[0] >> 4 == version {
                    return Frame::Ip(payload);
                }
            }
            ETHERTYPE_ARP if arp_plausible(payload) => return Frame::LinkControl,
            ETHERTYPE_EAPOL if eapol_plausible(payload) => return Frame::LinkControl,
            _ => {}
        }
        // Not a consistent Ethernet frame: a raw IP packet must be exact.
        if ip_consistent(bytes, true) {
            return Frame::Ip(bytes);
        }
        return match ethertype {
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 | ETHERTYPE_ARP | ETHERTYPE_EAPOL => Frame::Malformed,
            _ if bytes.len() >= ETHERNET_HEADER => Frame::NonIp,
            _ => Frame::Malformed,
        };
    }
    if ip_consistent(bytes, true) {
        Frame::Ip(bytes)
    } else {
        Frame::Malformed
    }
}

/// The parsed IP layer of one packet.
struct Ip<'a> {
    src: IpAddr,
    dst: IpAddr,
    v6: bool,
    hop_limit: u8,
    protocol: u8,
    /// Upper-layer bytes, bounded by the IP length (empty for a later
    /// fragment).
    l4: &'a [u8],
    later_fragment: bool,
}

fn parse_ip(packet: &[u8]) -> Option<Ip<'_>> {
    match packet.first()? >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => None,
    }
}

fn parse_v4(packet: &[u8]) -> Option<Ip<'_>> {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(be16(packet, 2)?);
    if ihl < 20 || total < ihl || total > packet.len() {
        return None;
    }
    let fragment = be16(packet, 6)? & 0x1fff;
    let address = |at: usize| -> Option<IpAddr> {
        let o = packet.get(at..at + 4)?;
        Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
    };
    Some(Ip {
        src: address(12)?,
        dst: address(16)?,
        v6: false,
        hop_limit: packet[8],
        protocol: packet[9],
        l4: if fragment == 0 {
            &packet[ihl..total]
        } else {
            &[]
        },
        later_fragment: fragment != 0,
    })
}

fn parse_v6(packet: &[u8]) -> Option<Ip<'_>> {
    let end = IPV6_HEADER + usize::from(be16(packet, 4)?);
    if end > packet.len() {
        return None;
    }
    let address = |at: usize| -> Option<IpAddr> {
        let o: [u8; 16] = packet.get(at..at + 16)?.try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(o)))
    };
    let mut next = packet[6];
    let mut offset = IPV6_HEADER;
    let mut walked = 0;
    let mut later_fragment = false;
    loop {
        match next {
            0 | 43 | 60 => {
                let length = (usize::from(*packet.get(offset + 1)?) + 1) * 8;
                if walked == MAX_EXTENSION_HEADERS || offset + length > end {
                    return None;
                }
                next = packet[offset];
                offset += length;
                walked += 1;
            }
            44 => {
                if walked == MAX_EXTENSION_HEADERS || offset + 8 > end {
                    return None;
                }
                let fragment = be16(packet, offset + 2)? >> 3;
                next = packet[offset];
                offset += 8;
                walked += 1;
                if fragment != 0 {
                    later_fragment = true;
                    break;
                }
            }
            _ => break,
        }
    }
    Some(Ip {
        src: address(8)?,
        dst: address(24)?,
        v6: true,
        hop_limit: packet[7],
        protocol: next,
        l4: if later_fragment {
            &[]
        } else {
            &packet[offset..end]
        },
        later_fragment,
    })
}

/// The remote address of `ip` in this orientation.
fn remote(ip: &Ip<'_>, outbound: bool) -> IpAddr {
    if outbound {
        ip.dst
    } else {
        ip.src
    }
}

/// v40: whether `address:port` is one of the armed pins, exactly.
fn is_peer(pins: &PeerSet, address: IpAddr, port: u16) -> bool {
    pins.contains(Peer { ip: address, port })
}

/// Whether a flow of `protocol` to `address:port` is one this gate allows,
/// and as which.
fn endpoint(s: &Snapshot, protocol: u8, address: IpAddr, port: u16) -> Option<Reason> {
    match protocol {
        PROTO_TCP if is_peer(&s.relays, address, port) => Some(Reason::Relay),
        PROTO_UDP
            if (s.udp_relay && is_peer(&s.relays, address, port))
                || is_peer(&s.udp_media, address, port) =>
        {
            Some(Reason::Relay)
        }
        _ => None,
    }
}

/// A later fragment carries no ports: the address pair and protocol decide.
fn fragment_allowed(s: &Snapshot, ip: &Ip<'_>, outbound: bool) -> bool {
    let address = remote(ip, outbound);
    let relay = s.relays.has_ip(address);
    match ip.protocol {
        PROTO_TCP => relay,
        // D6 media candidates have no port-free fragment allowance: a later
        // fragment cannot prove which exact candidate tuple sent it.
        PROTO_UDP => relay && s.udp_relay,
        _ => false,
    }
}

/// An inbound ICMP error whose quoted packet is ours to the relay.
/// `quoted` starts at the quoted IP header.
fn quotes_allowed_flow(s: &Snapshot, quoted: &[u8], v6: bool) -> bool {
    let (protocol, destination, l4) = if v6 {
        if quoted.first().map(|b| b >> 4) != Some(6) {
            return false;
        }
        let Some(dst) = quoted
            .get(24..40)
            .and_then(|o| <[u8; 16]>::try_from(o).ok())
        else {
            return false;
        };
        (
            quoted[6],
            IpAddr::V6(Ipv6Addr::from(dst)),
            quoted.get(IPV6_HEADER..).unwrap_or(&[]),
        )
    } else {
        if quoted.first().map(|b| b >> 4) != Some(4) {
            return false;
        }
        let ihl = usize::from(quoted[0] & 0x0f) * 4;
        let Some(o) = quoted.get(16..20) else {
            return false;
        };
        if ihl < 20 {
            return false;
        }
        (
            *quoted.get(9).unwrap_or(&0),
            IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])),
            quoted.get(ihl..).unwrap_or(&[]),
        )
    };
    let Some(port) = be16(l4, 2) else {
        return false;
    };
    endpoint(s, protocol, destination, port).is_some()
}

fn unspecified_or_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V6(v6) => v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

/// One orientation of the IP rules (R3/R4).
fn oriented(s: &Snapshot, ip: &Ip<'_>, outbound: bool) -> (Verdict, Reason) {
    use Verdict::{Allow, Drop};
    if ip.later_fragment {
        return if fragment_allowed(s, ip, outbound) {
            (Allow, Reason::RelayFragment)
        } else {
            (Drop, Reason::Fragment)
        };
    }
    let ports = || Some((be16(ip.l4, 0)?, be16(ip.l4, 2)?));
    match ip.protocol {
        PROTO_TCP => {
            let Some((sport, dport)) = ports() else {
                return (Drop, Reason::Malformed);
            };
            let (address, port) = if outbound {
                (ip.dst, dport)
            } else {
                (ip.src, sport)
            };
            match endpoint(s, PROTO_TCP, address, port) {
                Some(reason) => (Allow, reason),
                None if outbound => (Drop, Reason::TcpOut),
                None => (Drop, Reason::TcpIn),
            }
        }
        PROTO_UDP => {
            let Some((sport, dport)) = ports() else {
                return (Drop, Reason::Malformed);
            };
            let (address, port) = if outbound {
                (ip.dst, dport)
            } else {
                (ip.src, sport)
            };
            if let Some(reason) = endpoint(s, PROTO_UDP, address, port) {
                return (Allow, reason);
            }
            let (client, server, reason) = if ip.v6 {
                (546, 547, Reason::Dhcp6)
            } else {
                (68, 67, Reason::Dhcp4)
            };
            let dhcp = if outbound {
                sport == client && dport == server
            } else {
                sport == server && dport == client
            };
            if dhcp {
                (Allow, reason)
            } else if sport == MDNS_PORT || dport == MDNS_PORT {
                (Drop, Reason::Mdns)
            } else {
                (Drop, Reason::Udp)
            }
        }
        PROTO_ICMP if !ip.v6 => {
            let Some(&kind) = ip.l4.first() else {
                return (Drop, Reason::Malformed);
            };
            if !outbound
                && matches!(kind, 3 | 11)
                && quotes_allowed_flow(s, ip.l4.get(8..).unwrap_or(&[]), false)
            {
                (Allow, Reason::RelayIcmpError)
            } else if outbound {
                (Drop, Reason::Icmp4Out)
            } else {
                (Drop, Reason::Icmp4In)
            }
        }
        PROTO_ICMPV6 if ip.v6 => {
            let Some(&kind) = ip.l4.first() else {
                return (Drop, Reason::Malformed);
            };
            match kind {
                133..=137 if ip.hop_limit == 255 => (Allow, Reason::Nd),
                130 | 131 | 132 | 143 if ip.hop_limit == 1 && unspecified_or_link_local(ip.src) => {
                    (Allow, Reason::Mld)
                }
                1..=4
                    if !outbound && quotes_allowed_flow(s, ip.l4.get(8..).unwrap_or(&[]), true) =>
                {
                    (Allow, Reason::RelayIcmpError)
                }
                128 | 129 => (Drop, Reason::Icmp6Echo),
                1..=4 => (Drop, Reason::Icmp6Error),
                _ => (Drop, Reason::Icmp6Other),
            }
        }
        PROTO_IGMP if !ip.v6 => (Drop, Reason::Igmp),
        _ => (Drop, Reason::OtherProto),
    }
}

/// The verdict for one packet presented on an interface of class `iface`.
pub fn verdict(
    snapshot: &Snapshot,
    iface: IfaceClass,
    direction: Direction,
    bytes: &[u8],
) -> (Verdict, Reason) {
    if snapshot.mode == Mode::Open {
        return (Verdict::Allow, Reason::Open);
    }
    match iface {
        IfaceClass::Tunnel => return (Verdict::Allow, Reason::TunnelIface),
        IfaceClass::Loopback => return (Verdict::Allow, Reason::LoopbackIface),
        IfaceClass::Guarded => {}
    }
    let framed = frame(bytes);
    // Ambiguous link control: bytes that read as plausible ARP or EAPOL and
    // also as an exact raw IP packet (a raw source address such as
    // 136.142.1.5 reads as the EAPOL ethertype and header) are judged as
    // that IP packet, so link control never shadows a raw IP flow.
    if framed == Frame::LinkControl && ip_consistent(bytes, true) {
        return judge_frame(snapshot, direction, Frame::Ip(bytes));
    }
    judge_frame(snapshot, direction, framed)
}

/// The verdict for one decoded frame on a Guarded interface.
fn judge_frame(snapshot: &Snapshot, direction: Direction, framed: Frame<'_>) -> (Verdict, Reason) {
    let packet = match framed {
        Frame::Ip(packet) => packet,
        Frame::LinkControl => return (Verdict::Allow, Reason::LinkControl),
        Frame::NonIp => return (Verdict::Drop, Reason::NonIp),
        Frame::Malformed => return (Verdict::Drop, Reason::Malformed),
    };
    let Some(ip) = parse_ip(packet) else {
        return (Verdict::Drop, Reason::Malformed);
    };
    match direction {
        Direction::Outbound => oriented(snapshot, &ip, true),
        Direction::Inbound => oriented(snapshot, &ip, false),
        Direction::Any => {
            let out = oriented(snapshot, &ip, true);
            if out.0 == Verdict::Allow {
                return out;
            }
            let inbound = oriented(snapshot, &ip, false);
            if inbound.0 == Verdict::Allow {
                inbound
            } else {
                out
            }
        }
    }
}

/// `name:value` for every non-zero counter, in counter order: stable log
/// fields (`[a-z0-9_:]`) without any address.
pub fn counter_fields(values: &[u64; COUNTED.len()]) -> Vec<String> {
    COUNTED
        .iter()
        .zip(values.iter())
        .filter(|(_, value)| **value != 0)
        .map(|(reason, value)| format!("{}:{value}", reason.name()))
        .collect()
}

/// The address family token of an armed endpoint, for logs: `v4`, `v6` or
/// `none`. Never the address.
pub fn family_token(peer: Option<Peer>) -> &'static str {
    match peer.map(|peer| peer.ip) {
        Some(IpAddr::V4(_)) => "v4",
        Some(IpAddr::V6(_)) => "v6",
        None => "none",
    }
}

/// v40: the address family token of an armed pin set, for logs: the one
/// family of every pin (`v4`, `v6`), `mixed`, or `none`. Never an address.
pub fn pins_family_token(pins: &PeerSet) -> &'static str {
    let first = family_token(pins.first());
    if pins
        .as_slice()
        .iter()
        .all(|peer| family_token(Some(*peer)) == first)
    {
        first
    } else {
        "mixed"
    }
}

// ---------------------------------------------------------------------------
// v27 (S20f) observability: never part of a verdict, never an address.

/// The clock of the observability fields: milliseconds of `Instant` (on
/// macOS `CLOCK_UPTIME_RAW`, which stops while the Mac sleeps) since a base
/// the first control-path read sets.
static CLOCK_BASE: OnceLock<Instant> = OnceLock::new();

fn elapsed_ms(base: &Instant) -> u64 {
    u64::try_from(Instant::now().saturating_duration_since(*base).as_millis()).unwrap_or(u64::MAX)
}

/// The packet path's read of the observability clock: it never sets the
/// base (no wait on a `Once`), so before the first arm it reads 0.
pub fn clock_ms() -> u64 {
    CLOCK_BASE.get().map_or(0, elapsed_ms)
}

/// The control path's read; the first one sets the base.
fn control_clock_ms() -> u64 {
    elapsed_ms(CLOCK_BASE.get_or_init(Instant::now))
}

/// v27: wall-clock seconds with microseconds (`1800000000.250000`), the
/// `wall:` field of the provider's `leak_guard_span` lines, which the
/// window compares with capture timestamps. Never an address.
pub fn wall_token(at: SystemTime) -> String {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}.{:06}", since.as_secs(), since.subsec_micros())
}

/// v27: the bounded class of the interface a dropped packet was presented
/// on, from its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropClass {
    /// The epoch's pinned relay interface ([`Gate::set_primary`]), the
    /// physical primary (normally an `en<n>`).
    Primary,
    /// Any other `en<n>`.
    EnOther,
    /// `awdl<n>`, `llw<n>`.
    AwdlLlw,
    /// `bridge<n>`, `ap<n>`, `anpi<n>`.
    BridgeApAnpi,
    /// Any other name, and a missing one.
    Other,
}

/// v27: every drop class, in drop-array slot order.
pub const DROP_CLASSES: [DropClass; 5] = [
    DropClass::Primary,
    DropClass::EnOther,
    DropClass::AwdlLlw,
    DropClass::BridgeApAnpi,
    DropClass::Other,
];

impl DropClass {
    /// The stable token for `filter-status` and the host line.
    pub const fn name(self) -> &'static str {
        match self {
            DropClass::Primary => "primary",
            DropClass::EnOther => "en_other",
            DropClass::AwdlLlw => "awdl_llw",
            DropClass::BridgeApAnpi => "bridge_ap_anpi",
            DropClass::Other => "other",
        }
    }

    /// The slot in [`DROP_CLASSES`] and the drop arrays.
    pub const fn slot(self) -> usize {
        self as usize
    }
}

/// v27: the interface name prefixes an [`iface_code`] keeps as a name, with
/// their unit: macOS's own driver names, which no user chooses. Any other
/// name is kept only as a hash.
pub const IFACE_PREFIXES: [&str; 15] = [
    "en", "awdl", "llw", "bridge", "ap", "anpi", "utun", "ipsec", "lo", "gif", "stf", "pktap",
    "vmenet", "vmnet", "vnic",
];
const IFACE_NAMED: u32 = 1 << 31;
/// Bytes of a name an [`iface_code`] hash reads, at most.
const IFACE_SCAN: usize = 32;

/// The unit of `prefix` followed by one to four decimal digits without a
/// leading zero.
fn unit_of(name: &[u8], prefix: &[u8]) -> Option<u16> {
    let rest = name.strip_prefix(prefix)?;
    if !(1..=4).contains(&rest.len())
        || !rest.iter().all(u8::is_ascii_digit)
        || (rest.len() > 1 && rest.first() == Some(&b'0'))
    {
        return None;
    }
    Some(
        rest.iter()
            .fold(0u16, |unit, digit| unit * 10 + u16::from(digit - b'0')),
    )
}

/// v27: an address-free code of one interface name. A known prefix and
/// unit (`en7`) is `1 << 31 | prefix id << 16 | unit`; any other name is a
/// 31-bit FNV-1a hash of at most its first 32 bytes and its length (never
/// 0); no name is 0. Bounded: at most 15 prefix checks and 32 bytes.
pub fn iface_code(name: Option<&[u8]>) -> u32 {
    let Some(name) = name else {
        return 0;
    };
    for (id, prefix) in (1u32..).zip(IFACE_PREFIXES.iter()) {
        if let Some(unit) = unit_of(name, prefix.as_bytes()) {
            return IFACE_NAMED | (id << 16) | u32::from(unit);
        }
    }
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in name.iter().take(IFACE_SCAN) {
        hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
    }
    let length = u32::try_from(name.len().min(255)).unwrap_or(255);
    hash = (hash ^ length).wrapping_mul(0x0100_0193);
    (hash & !IFACE_NAMED).max(1)
}

/// The known prefix of a named code.
fn iface_prefix(code: u32) -> Option<&'static str> {
    if code & IFACE_NAMED == 0 {
        return None;
    }
    let id = usize::try_from((code >> 16) & 0xff).ok()?;
    IFACE_PREFIXES.get(id.checked_sub(1)?).copied()
}

/// v27: the `filter-status` token of an [`iface_code`]: the name (`en7`),
/// `h:<8 hex>` for a hashed name, `none` for no name.
pub fn iface_token(code: u32) -> String {
    match iface_prefix(code) {
        _ if code == 0 => "none".into(),
        Some(prefix) => format!("{prefix}{}", code & 0xffff),
        None => format!("h:{code:08x}"),
    }
}

/// v27: whether `text` is a token [`iface_token`] can produce.
pub fn iface_token_valid(text: &str) -> bool {
    if text == "none" {
        return true;
    }
    if let Some(hex) = text.strip_prefix("h:") {
        return hex.len() == 8
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && u32::from_str_radix(hex, 16).is_ok_and(|code| code != 0 && code & IFACE_NAMED == 0);
    }
    IFACE_PREFIXES
        .iter()
        .any(|prefix| unit_of(text.as_bytes(), prefix.as_bytes()).is_some())
}

/// v27: the drop class of an interface code; `primary` is the gate's.
pub fn drop_class(code: u32, primary: u32) -> DropClass {
    if code != 0 && code == primary {
        return DropClass::Primary;
    }
    match iface_prefix(code) {
        Some("en") => DropClass::EnOther,
        Some("awdl" | "llw") => DropClass::AwdlLlw,
        Some("bridge" | "ap" | "anpi") => DropClass::BridgeApAnpi,
        _ => DropClass::Other,
    }
}

/// v27: the TCP flag class of a dropped segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpClass {
    /// Not TCP, or a later fragment.
    None,
    Syn,
    SynAck,
    /// ACK set, no payload, no SYN, FIN or RST (a keepalive among them).
    AckOnly,
    /// Payload bytes (by the IP and TCP header lengths).
    Data,
    Fin,
    Rst,
    /// A TCP header too short to read, or no ACK, SYN, FIN, RST or data.
    Other,
}

/// v27: every TCP class, in ring-field order.
pub const TCP_CLASSES: [TcpClass; 8] = [
    TcpClass::None,
    TcpClass::Syn,
    TcpClass::SynAck,
    TcpClass::AckOnly,
    TcpClass::Data,
    TcpClass::Fin,
    TcpClass::Rst,
    TcpClass::Other,
];

impl TcpClass {
    pub const fn name(self) -> &'static str {
        match self {
            TcpClass::None => "none",
            TcpClass::Syn => "syn",
            TcpClass::SynAck => "syn_ack",
            TcpClass::AckOnly => "ack_only",
            TcpClass::Data => "data",
            TcpClass::Fin => "fin",
            TcpClass::Rst => "rst",
            TcpClass::Other => "other",
        }
    }
}

/// The TCP class of `l4`, bounded by the IP length (no Ethernet padding).
fn tcp_class(l4: &[u8]) -> TcpClass {
    const FIN: u8 = 0x01;
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    let (Some(&offset), Some(&flags)) = (l4.get(12), l4.get(13)) else {
        return TcpClass::Other;
    };
    let header = usize::from(offset >> 4) * 4;
    if flags & RST != 0 {
        TcpClass::Rst
    } else if flags & SYN != 0 {
        if flags & ACK != 0 {
            TcpClass::SynAck
        } else {
            TcpClass::Syn
        }
    } else if flags & FIN != 0 {
        TcpClass::Fin
    } else if header >= 20 && l4.len() > header {
        TcpClass::Data
    } else if flags & ACK != 0 {
        TcpClass::AckOnly
    } else {
        TcpClass::Other
    }
}

/// The header fields a drop record and the outbound counters keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Summary {
    /// 0 (not IP or unreadable), 4 or 6.
    family: u8,
    /// The IP protocol (0 when not IP).
    protocol: u8,
    tcp: TcpClass,
    /// v29: the TCP source port; 0 when not TCP, a later fragment, or a
    /// header shorter than 20 bytes. Only [`marked_sport`] reads it.
    sport: u16,
}

/// The IP family, protocol, TCP class and (v29) TCP source port of a
/// dropped frame, framed as the verdict framed it. Header fields only.
fn summarize(bytes: &[u8]) -> Summary {
    const NONE: Summary = Summary {
        family: 0,
        protocol: 0,
        tcp: TcpClass::None,
        sport: 0,
    };
    let packet = match frame(bytes) {
        Frame::Ip(packet) => packet,
        Frame::LinkControl if ip_consistent(bytes, true) => bytes,
        _ => return NONE,
    };
    let Some(ip) = parse_ip(packet) else {
        return NONE;
    };
    let (tcp, sport) = if ip.protocol == PROTO_TCP && !ip.later_fragment {
        let sport = if ip.l4.len() >= 20 {
            be16(ip.l4, 0).unwrap_or(0)
        } else {
            0
        };
        (tcp_class(ip.l4), sport)
    } else {
        (TcpClass::None, 0)
    };
    Summary {
        family: if ip.v6 { 6 } else { 4 },
        protocol: ip.protocol,
        tcp,
        sport,
    }
}

/// v29 (S20h): the first TCP source port of the marker range, the ports
/// the positive control's pre-existing sockets bind to
/// (`harness/net_probe.py presock`, `PRESOCK_MARK_SPORT_FIRST`; a test
/// reads that line and those of `leak_review.py` and `controls.sh`). An
/// outbound TCP drop from a port of the range is counted as marked. Never
/// part of a verdict.
///
/// The marker is the source port, not the TTL: XNU sends a socket's
/// keepalives through `tcp_respond`, which builds them from the
/// connection's template (its addresses and ports) but sets an IPv4
/// packet's TTL to the system default (`ip_defttl`), never the socket's
/// `IP_TTL`. A keepalive that did not carry its connection's ports would
/// not belong to the connection, so every segment and keepalive of a
/// marked socket carries the marker.
pub const MARK_SPORT_FIRST: u16 = 47_000;
/// v29: how many source ports the marker range holds (four sockets on
/// each of up to four interfaces, and room for ports held by others).
/// Below the ephemeral range (49152) and the positive control's fresh
/// probes (`PC_SPORT_BASE`, 47100).
pub const MARK_SPORT_COUNT: u16 = 32;

/// v29: whether `sport` lies in the marker range. Two comparisons and a
/// subtraction that cannot underflow; 0 (no TCP source port) never does.
pub const fn marked_sport(sport: u16) -> bool {
    sport >= MARK_SPORT_FIRST && sport - MARK_SPORT_FIRST < MARK_SPORT_COUNT
}

/// v29: the kind of an outbound drop: the TCP flag class of a TCP segment,
/// or `non_tcp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutKind {
    Syn,
    SynAck,
    /// ACK set, no payload, no SYN, FIN or RST: a keepalive among them.
    AckOnly,
    Data,
    Fin,
    Rst,
    /// A TCP header too short to read, a later fragment of a TCP packet,
    /// or no ACK, SYN, FIN, RST or data.
    Other,
    /// Not TCP (UDP, ICMP, any other protocol, or not IP at all).
    NonTcp,
}

/// v29: every outbound kind, in counter order.
pub const OUT_KINDS: [OutKind; 8] = [
    OutKind::Syn,
    OutKind::SynAck,
    OutKind::AckOnly,
    OutKind::Data,
    OutKind::Fin,
    OutKind::Rst,
    OutKind::Other,
    OutKind::NonTcp,
];

impl OutKind {
    /// The stable token for `filter-status` and the host line.
    pub const fn name(self) -> &'static str {
        match self {
            OutKind::Syn => "syn",
            OutKind::SynAck => "syn_ack",
            OutKind::AckOnly => "ack_only",
            OutKind::Data => "data",
            OutKind::Fin => "fin",
            OutKind::Rst => "rst",
            OutKind::Other => "other",
            OutKind::NonTcp => "non_tcp",
        }
    }

    /// The slot in [`OUT_KINDS`] and the outbound tables.
    pub const fn slot(self) -> usize {
        self as usize
    }

    /// The kind of a dropped frame's IP protocol and TCP class.
    pub const fn of(protocol: u8, tcp: TcpClass) -> Self {
        match tcp {
            TcpClass::Syn => OutKind::Syn,
            TcpClass::SynAck => OutKind::SynAck,
            TcpClass::AckOnly => OutKind::AckOnly,
            TcpClass::Data => OutKind::Data,
            TcpClass::Fin => OutKind::Fin,
            TcpClass::Rst => OutKind::Rst,
            TcpClass::Other => OutKind::Other,
            TcpClass::None if protocol == PROTO_TCP => OutKind::Other,
            TcpClass::None => OutKind::NonTcp,
        }
    }
}

/// v27: one dropped packet as the ring keeps it. No address, port or
/// payload byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DropRecord {
    /// The arm token's low 32 bits (saturating).
    pub arm_seq: u32,
    /// Milliseconds since that arm on the [`clock_ms`] clock (saturating).
    pub ms: u32,
    /// The [`iface_code`] of the interface name.
    pub iface: u32,
    pub class: DropClass,
    pub direction: Direction,
    /// 0 (not IP or unreadable), 4 or 6.
    pub family: u8,
    /// The IP protocol (0 when not IP).
    pub protocol: u8,
    pub tcp: TcpClass,
    pub reason: Reason,
}

/// Set in every packed `b` word, so an empty slot never decodes.
const RECORD_VALID: u64 = 1 << 31;
/// v29: set in a packed `b` word of a drop that carried the marker
/// ([`marked_sport`]); [`DropRecord::unpack`] ignores it.
const RECORD_MARKED: u64 = 1 << 15;

impl DropRecord {
    fn pack(&self) -> (u64, u64) {
        let family = match self.family {
            4 => 1,
            6 => 2,
            _ => 0,
        };
        let tcp = TCP_CLASSES
            .iter()
            .position(|class| *class == self.tcp)
            .unwrap_or(TCP_CLASSES.len() - 1) as u64;
        let reason = self.reason.index().unwrap_or(0) as u64;
        let a = (u64::from(self.arm_seq) << 32) | u64::from(self.ms);
        let b = (u64::from(self.iface) << 32)
            | RECORD_VALID
            | (self.class.slot() as u64)
            | ((self.direction.slot() as u64) << 3)
            | (family << 5)
            | (tcp << 7)
            | (reason << 10)
            | (u64::from(self.protocol) << 16);
        (a, b)
    }

    /// The record of a packed slot; `None` for any field out of range.
    fn unpack(a: u64, b: u64) -> Option<Self> {
        if b & RECORD_VALID == 0 {
            return None;
        }
        let field = |shift: u32, bits: u32| usize::try_from((b >> shift) & ((1 << bits) - 1)).ok();
        Some(DropRecord {
            arm_seq: u32::try_from(a >> 32).ok()?,
            ms: u32::try_from(a & 0xffff_ffff).ok()?,
            iface: u32::try_from(b >> 32).ok()?,
            class: *DROP_CLASSES.get(field(0, 3)?)?,
            direction: *DIRECTIONS.get(field(3, 2)?)?,
            family: *[0u8, 4, 6].get(field(5, 2)?)?,
            tcp: *TCP_CLASSES.get(field(7, 3)?)?,
            reason: *COUNTED.get(field(10, 5)?)?,
            protocol: u8::try_from(field(16, 8)?).ok()?,
        })
    }
}

/// v27: drops the ring keeps, the newest ones.
pub const RING_SLOTS: usize = 64;

/// One ring slot: a seqlock (`2 * index + 1` while written, `2 * index + 2`
/// once written, 0 empty) over two packed words, on its own cache line.
#[repr(align(64))]
struct RingSlot {
    seq: AtomicU64,
    a: AtomicU64,
    b: AtomicU64,
}

/// v27: the ring of the last [`RING_SLOTS`] drops. Writing is wait free:
/// one `fetch_add` for the index, one compare-exchange to claim the slot,
/// two stores and a release. A writer that finds its slot being written,
/// or already holding a newer record, skips its record (counted in
/// `skipped`) instead of waiting. A reader detects a torn slot by the
/// slot's sequence and counts it in `torn`, never reporting it.
pub struct DropRing {
    next: AtomicU64,
    skipped: AtomicU64,
    slots: [RingSlot; RING_SLOTS],
}

impl Default for DropRing {
    fn default() -> Self {
        Self::new()
    }
}

/// v27: one read of the ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingSnapshot {
    /// Records attempted so far (the next record's index).
    pub next: u64,
    /// Records skipped because their slot was busy or newer.
    pub skipped: u64,
    /// Slots that stayed torn for three read attempts or did not decode.
    pub torn: u64,
    /// `(index, record)` of the last [`RING_SLOTS`] indices, oldest first.
    pub entries: Vec<(u64, DropRecord)>,
}

/// v29: one read of a ring with each record's marked bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkedRingSnapshot {
    pub next: u64,
    pub skipped: u64,
    pub torn: u64,
    /// `(index, record, marked)` of the last [`RING_SLOTS`] indices,
    /// oldest first.
    pub entries: Vec<(u64, DropRecord, bool)>,
}

impl DropRing {
    pub const fn new() -> Self {
        DropRing {
            next: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            slots: [const {
                RingSlot {
                    seq: AtomicU64::new(0),
                    a: AtomicU64::new(0),
                    b: AtomicU64::new(0),
                }
            }; RING_SLOTS],
        }
    }

    /// Write one record: bounded, allocation free and wait free.
    pub fn record(&self, record: &DropRecord) {
        self.record_marked(record, false);
    }

    /// v29: [`DropRing::record`], with whether the drop carried the
    /// marker ([`marked_sport`]) kept in the slot (read by
    /// [`DropRing::snapshot_marked`]).
    pub fn record_marked(&self, record: &DropRecord, marked: bool) {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        self.write_words(index, record, marked);
    }

    /// The write of record `index` (taken from `next`): claim its slot with
    /// one compare-exchange, or skip. (v29: the test seam's entry; the
    /// packet path writes through [`DropRing::record_marked`].)
    #[cfg(test)]
    fn write_index(&self, index: u64, record: &DropRecord) {
        self.write_words(index, record, false);
    }

    /// [`DropRing::write_index`] with the marked bit.
    fn write_words(&self, index: u64, record: &DropRecord, marked: bool) {
        let Some(slot) = self.slots.get((index % RING_SLOTS as u64) as usize) else {
            return;
        };
        let writing = index.wrapping_mul(2).wrapping_add(1);
        let current = slot.seq.load(Ordering::Relaxed);
        if current & 1 == 1
            || current >= writing
            || slot
                .seq
                .compare_exchange(current, writing, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            self.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        fence(Ordering::Release);
        let (a, b) = record.pack();
        slot.a.store(a, Ordering::Relaxed);
        slot.b.store(
            if marked { b | RECORD_MARKED } else { b },
            Ordering::Relaxed,
        );
        slot.seq.store(writing.wrapping_add(1), Ordering::Release);
    }

    /// Every consistent record of the last [`RING_SLOTS`] indices.
    pub fn snapshot(&self) -> RingSnapshot {
        let (next, torn, entries) = self.read_slots();
        RingSnapshot {
            next,
            skipped: self.skipped.load(Ordering::Relaxed),
            torn,
            entries: entries
                .into_iter()
                .map(|(index, record, _)| (index, record))
                .collect(),
        }
    }

    /// v29: [`DropRing::snapshot`] with each record's marked bit.
    pub fn snapshot_marked(&self) -> MarkedRingSnapshot {
        let (next, torn, entries) = self.read_slots();
        MarkedRingSnapshot {
            next,
            skipped: self.skipped.load(Ordering::Relaxed),
            torn,
            entries,
        }
    }

    /// `next`, the torn count and every consistent `(index, record,
    /// marked)` of the last [`RING_SLOTS`] indices, oldest first.
    #[allow(clippy::type_complexity)]
    fn read_slots(&self) -> (u64, u64, Vec<(u64, DropRecord, bool)>) {
        let next = self.next.load(Ordering::Acquire);
        let mut torn = 0;
        let mut entries = Vec::with_capacity(RING_SLOTS);
        for slot in &self.slots {
            let mut read = None;
            let mut settled = false;
            for _ in 0..SNAPSHOT_ATTEMPTS {
                let before = slot.seq.load(Ordering::Acquire);
                if before == 0 {
                    settled = true;
                    break;
                }
                if before & 1 == 1 {
                    spin_loop();
                    continue;
                }
                let a = slot.a.load(Ordering::Relaxed);
                let b = slot.b.load(Ordering::Relaxed);
                fence(Ordering::Acquire);
                if slot.seq.load(Ordering::Relaxed) == before {
                    read = Some((before / 2 - 1, a, b));
                    settled = true;
                    break;
                }
            }
            match read.map(|(index, a, b)| (index, DropRecord::unpack(a, b), b)) {
                Some((index, Some(record), b)) => {
                    entries.push((index, record, b & RECORD_MARKED != 0))
                }
                Some((_, None, _)) => torn += 1,
                None if !settled => torn += 1,
                None => {}
            }
        }
        entries.sort_by_key(|(index, _, _)| *index);
        let floor = next.saturating_sub(RING_SLOTS as u64);
        entries.retain(|(index, _, _)| *index >= floor);
        (next, torn, entries)
    }

    /// Test seam: slot `slot` held odd, as by a writer paused mid-write.
    #[cfg(test)]
    pub(crate) fn hold_slot_for_test(&self, slot: usize) {
        self.slots[slot].seq.fetch_add(1, Ordering::AcqRel);
    }
    #[cfg(test)]
    pub(crate) fn release_slot_for_test(&self, slot: usize) {
        self.slots[slot].seq.fetch_add(1, Ordering::AcqRel);
    }
    /// Test seam: a slot whose words do not decode.
    #[cfg(test)]
    pub(crate) fn corrupt_slot_for_test(&self, slot: usize) {
        self.slots[slot].b.store(0, Ordering::Relaxed);
    }
    /// Test seam: a writer of an earlier index, delayed until now.
    #[cfg(test)]
    pub(crate) fn write_stale_for_test(&self, index: u64, record: &DropRecord) {
        self.write_index(index, record);
    }
}

/// v27: the gate's arm accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArmStats {
    /// Arms in this process (the last token issued).
    pub arm_seq: u64,
    /// Disarms that opened the gate.
    pub disarms: u64,
    /// Milliseconds guarded: every ended span plus the current one.
    pub armed_ms_total: u64,
    /// Milliseconds since the current token's arm; `None` while Open.
    pub armed_for_ms: Option<u64>,
    /// Open intervals that began while an epoch's settings may be applied.
    pub open_while_applied: u64,
    /// Epochs noted applied and not yet withdrawn.
    pub applied_epochs: u64,
    /// The [`iface_code`] of the pinned relay interface, 0 for none.
    pub primary: u32,
}

#[cfg(test)]
#[path = "leak_guard_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "leak_guard_observe_tests.rs"]
mod observe_tests;

#[cfg(test)]
#[path = "leak_guard_outbound_tests.rs"]
mod outbound_tests;
