//! Existing Aegis AST semantics on real frames, without implicit repair of
//! explicit checksum/data-offset tampering or silently truncated expansion.
use crate::{
    actions::{payload, tamper},
    packet::{
        field::{Field, Proto},
        model::{Direction, IpHeader, Packet, TcpHeader, IP_FLAG_MORE_FRAGMENTS},
    },
    syntax::{
        action::{Action, FragmentOrder},
        strategy::Strategy,
    },
};
use rand::Rng;

pub const MAX_FRAME: usize = 65549;
pub const MAX_OUTPUTS: usize = 64;
pub const MAX_BATCH_BYTES: usize = 262144;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("unsupported or malformed Ethernet/IPv4 frame")]
    Frame,
    #[error("action cannot be represented exactly on this wire packet")]
    Unrepresentable,
    #[error("atomic frame expansion budget exceeded")]
    Budget,
}

#[derive(Clone)]
struct Image {
    ethernet: Vec<u8>,
    ip: Vec<u8>,
    tcp: Option<Vec<u8>>,
    tcp_options: Option<super::options::Rows>,
    packet: Packet,
    offset: usize,
    ip_override: bool,
    tcp_override: bool,
    fragmented: bool,
    ip_dirty: bool,
    tcp_dirty: bool,
    overrides: std::collections::BTreeSet<Field>,
    plan: Option<PlanCursor>,
}

#[derive(Clone)]
struct PlanCursor {
    specs: std::rc::Rc<Vec<super::program::FragmentSpec>>,
    cursor: std::rc::Rc<std::cell::Cell<usize>>,
    payloads: std::rc::Rc<Vec<Proto>>,
    payload_cursor: std::rc::Rc<std::cell::Cell<usize>>,
    tampers: std::rc::Rc<Vec<Option<super::program::LiveTamper>>>,
    tamper_cursor: std::rc::Rc<std::cell::Cell<usize>>,
}
impl PlanCursor {
    fn new(plan: super::program::RulePlan) -> Self {
        Self {
            specs: std::rc::Rc::new(plan.fragments),
            tampers: std::rc::Rc::new(plan.tampers),
            tamper_cursor: std::rc::Rc::new(std::cell::Cell::new(0)),
            payloads: std::rc::Rc::new(plan.payloads),
            payload_cursor: std::rc::Rc::new(std::cell::Cell::new(0)),
            cursor: std::rc::Rc::new(std::cell::Cell::new(0)),
        }
    }
    fn next(&self) -> Result<super::program::FragmentSpec, WireError> {
        let index = self.cursor.get();
        let spec = self
            .specs
            .get(index)
            .ok_or(WireError::Unrepresentable)?
            .clone();
        self.cursor.set(index + 1);
        Ok(spec)
    }
    fn next_payload(&self) -> Result<Proto, WireError> {
        let index = self.payload_cursor.get();
        let proto = *self.payloads.get(index).ok_or(WireError::Unrepresentable)?;
        self.payload_cursor.set(index + 1);
        Ok(proto)
    }
    fn next_tamper(&self) -> Result<Option<super::program::LiveTamper>, WireError> {
        let index = self.tamper_cursor.get();
        let spec = self
            .tampers
            .get(index)
            .ok_or(WireError::Unrepresentable)?
            .clone();
        self.tamper_cursor.set(index + 1);
        Ok(spec)
    }
    fn complete(&self) -> bool {
        self.cursor.get() == self.specs.len()
            && self.payload_cursor.get() == self.payloads.len()
            && self.tamper_cursor.get() == self.tampers.len()
    }
}

fn u16_at(b: &[u8], n: usize) -> u16 {
    u16::from_be_bytes([b[n], b[n + 1]])
}
fn u32_at(b: &[u8], n: usize) -> u32 {
    u32::from_be_bytes(b[n..n + 4].try_into().unwrap())
}
fn put16(b: &mut [u8], n: usize, v: u16) {
    b[n..n + 2].copy_from_slice(&v.to_be_bytes());
}
fn put32(b: &mut [u8], n: usize, v: u32) {
    b[n..n + 4].copy_from_slice(&v.to_be_bytes());
}
fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in b.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
impl Image {
    fn decode(b: &[u8], direction: Direction) -> Result<Self, WireError> {
        if b.len() < 34 || b.len() > MAX_FRAME || u16_at(b, 12) != 0x0800 || b[14] >> 4 != 4 {
            return Err(WireError::Frame);
        }
        let ihl = usize::from(b[14] & 15) * 4;
        let total = usize::from(u16_at(b, 16));
        if ihl < 20 || total < ihl || b.len() < 14 + total {
            return Err(WireError::Frame);
        }
        let bits = u16_at(b, 20);
        let offset = usize::from(bits & 0x1fff) * 8;
        let fragmented = offset != 0 || bits & IP_FLAG_MORE_FRAGMENTS != 0;
        let body = &b[14 + ihl..14 + total];
        let mut tcp = None;
        let mut model_tcp = None;
        let mut data = body.to_vec();
        if b[23] == 6 && offset == 0 {
            if body.len() >= 20 {
                let thl = usize::from(body[12] >> 4) * 4;
                if thl < 20 || thl > body.len() {
                    if !fragmented {
                        return Err(WireError::Frame);
                    }
                } else {
                    tcp = Some(body[..thl].to_vec());
                    model_tcp = Some(TcpHeader {
                        flags: u16::from(body[13]) | (u16::from(body[12] & 1) << 8),
                        seq: u32_at(body, 4),
                        ack: u32_at(body, 8),
                        window: u16_at(body, 14),
                        checksum: u16_at(body, 16),
                        data_offset: body[12] >> 4,
                    });
                    data = body[thl..].to_vec();
                }
            } else if !fragmented {
                return Err(WireError::Frame);
            }
        }
        if b[23] == 17 && offset == 0 && body.len() < 8 && !fragmented {
            return Err(WireError::Frame);
        }
        let mut wire_fields = std::collections::BTreeMap::new();
        for (field, value) in [
            (Field::IpVersion, u32::from(b[14] >> 4)),
            (Field::IpIhl, u32::from(b[14] & 15)),
            (Field::IpTos, u32::from(b[15])),
            (Field::IpLength, total as u32),
            (Field::IpFragment, (offset / 8) as u32),
            (Field::IpProtocol, u32::from(b[23])),
            (Field::IpSource, u32_at(b, 26)),
            (Field::IpDestination, u32_at(b, 30)),
        ] {
            wire_fields.insert(field, value);
        }
        if tcp.is_some() {
            for (field, value) in [
                (Field::TcpSource, u32::from(u16_at(body, 0))),
                (Field::TcpDestination, u32::from(u16_at(body, 2))),
                (Field::TcpReserved, u32::from((body[12] >> 1) & 7)),
                (Field::TcpUrgent, u32::from(u16_at(body, 18))),
            ] {
                wire_fields.insert(field, value);
            }
        }
        if b[23] == 17 && offset == 0 && body.len() >= 8 {
            for (field, value) in [
                (Field::UdpSource, u32::from(u16_at(body, 0))),
                (Field::UdpDestination, u32::from(u16_at(body, 2))),
                (Field::UdpLength, u32::from(u16_at(body, 4))),
                (Field::UdpChecksum, u32::from(u16_at(body, 6))),
            ] {
                wire_fields.insert(field, value);
            }
        }
        Ok(Self {
            ethernet: b[..14].to_vec(),
            ip: b[14..14 + ihl].to_vec(),
            tcp,
            tcp_options: None,
            packet: Packet {
                wire_fields,
                ip: IpHeader {
                    ttl: b[22],
                    flags: bits & 0xe000,
                    id: u16_at(b, 18),
                    checksum: u16_at(b, 24),
                    frag_offset: offset as u16,
                },
                tcp: model_tcp,
                payload: data,
                direction,
            },
            offset,
            ip_override: false,
            tcp_override: false,
            fragmented,
            ip_dirty: false,
            tcp_dirty: false,
            overrides: Default::default(),
            plan: None,
        })
    }
    fn dns_data(&self) -> Result<Option<(&[u8], usize)>, WireError> {
        let tcp = self.packet.tcp.is_some();
        let fields = &self.packet.wire_fields;
        let ports = if tcp {
            (
                fields.get(&Field::TcpSource),
                fields.get(&Field::TcpDestination),
            )
        } else {
            (
                fields.get(&Field::UdpSource),
                fields.get(&Field::UdpDestination),
            )
        };
        if ![ports.0, ports.1].into_iter().flatten().any(|p| *p == 53) {
            return Ok(None);
        }
        if self.fragmented {
            return Err(WireError::Unrepresentable);
        }
        let prefix = if tcp { 2 } else { 8 };
        let dns = self.packet.payload.get(prefix..).ok_or(WireError::Frame)?;
        if dns.len() < 12 {
            return Err(WireError::Frame);
        }
        if tcp && usize::from(u16_at(&self.packet.payload, 0)) != dns.len() {
            return Err(WireError::Unrepresentable);
        }
        Ok(Some((dns, prefix)))
    }
    fn dns_trigger_data(&self) -> Result<Option<(&[u8], usize)>, WireError> {
        if self.packet.tcp.is_some() && !self.fragmented {
            // A TCP segment need not contain one complete DNS message, even on
            // port 53. Lifecycle packets, split/coalesced messages, and other
            // bytes are nonmatches; this packet runner does not reassemble TCP.
            // Keep strict extraction for actions and fragmented inputs.
            let payload = &self.packet.payload;
            let Some(prefix) = payload.get(..2) else {
                return Ok(None);
            };
            let declared = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
            if declared < 12 || declared != payload.len() - 2 {
                return Ok(None);
            }
        }
        self.dns_data()
    }
    fn has_layer(&self, proto: Proto) -> bool {
        match proto {
            Proto::Ip => true,
            Proto::Tcp => self.packet.tcp.is_some(),
            Proto::Udp => self.packet.wire_fields.contains_key(&Field::UdpSource),
        }
    }
    fn load(&self, proto: Proto) -> Option<&[u8]> {
        if !self.has_layer(proto) {
            return None;
        }
        if self.packet.wire_fields.contains_key(&Field::UdpSource) {
            self.packet.payload.get(8..)
        } else {
            Some(&self.packet.payload)
        }
    }
    fn matches_text(&self, spec: &super::program::TextTrigger) -> Result<bool, WireError> {
        use super::program::TextTrigger;
        Ok(match spec {
            TextTrigger::Dns {
                field,
                value,
                wildcard,
            } => {
                if let Some((dns, _)) = self.dns_trigger_data()? {
                    let actual = super::dns::get(dns, *field)?;
                    actual.is_some_and(|actual| {
                        if *wildcard {
                            actual.contains(value)
                        } else {
                            actual == *value
                        }
                    })
                } else {
                    false
                }
            }
            TextTrigger::Option {
                name,
                value,
                wildcard,
            } => {
                if let Some(tcp) = &self.tcp {
                    let actual = super::options::get(tcp, *name)?;
                    if *wildcard {
                        actual.contains(value)
                    } else {
                        actual == *value
                    }
                } else {
                    false
                }
            }
            TextTrigger::Flags {
                proto,
                value,
                wildcard,
            } => {
                let bits = match proto {
                    Proto::Ip => Some(self.packet.ip.flags),
                    Proto::Tcp => self.packet.tcp.as_ref().map(|t| t.flags),
                    Proto::Udp => None,
                };
                bits.is_some_and(|bits| {
                    let actual = super::values::flags_text(*proto, bits);
                    if *wildcard {
                        actual.contains(value)
                    } else {
                        actual == *value
                    }
                })
            }
            TextTrigger::Address { field, value } => self
                .packet
                .get(*field)
                .is_some_and(|v| std::net::Ipv4Addr::from(v).to_string().contains(value)),
            TextTrigger::Load {
                proto,
                value,
                wildcard,
            } => self.load(*proto).is_some_and(|bytes| {
                let actual = super::values::quote_utf8_ignore(bytes);
                if *wildcard {
                    actual.contains(value)
                } else {
                    actual == *value
                }
            }),
        })
    }
    fn transport(&self) -> Result<Vec<u8>, WireError> {
        let mut body = self.tcp.clone().unwrap_or_default();
        if let Some(t) = &self.packet.tcp {
            if t.flags & !0x01ff != 0 || t.data_offset > 15 {
                return Err(WireError::Unrepresentable);
            }
            put32(&mut body, 4, t.seq);
            put32(&mut body, 8, t.ack);
            body[12] = (t.data_offset << 4) | (body[12] & 0x0e) | ((t.flags >> 8) as u8 & 1);
            body[13] = t.flags as u8;
            put16(&mut body, 14, t.window);
            put16(&mut body, 16, t.checksum);
        }
        body.extend_from_slice(&self.packet.payload);
        let w = &self.packet.wire_fields;
        if self.packet.tcp.is_some() {
            put16(&mut body, 0, w[&Field::TcpSource] as u16);
            put16(&mut body, 2, w[&Field::TcpDestination] as u16);
            body[12] = (body[12] & !0x0e) | ((w[&Field::TcpReserved] as u8) << 1);
            put16(&mut body, 18, w[&Field::TcpUrgent] as u16);
        }
        if w.contains_key(&Field::UdpSource) {
            if body.len() < 8 {
                return Err(WireError::Unrepresentable);
            }
            put16(&mut body, 0, w[&Field::UdpSource] as u16);
            put16(&mut body, 2, w[&Field::UdpDestination] as u16);
            let len = if self.overrides.contains(&Field::UdpLength) || self.fragmented {
                w[&Field::UdpLength] as u16
            } else {
                body.len() as u16
            };
            put16(&mut body, 4, len);
            put16(&mut body, 6, w[&Field::UdpChecksum] as u16);
        }
        if self.packet.tcp.is_some() && !self.tcp_override && !self.fragmented && self.tcp_dirty {
            put16(&mut body, 16, 0);
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&w[&Field::IpSource].to_be_bytes());
            pseudo.extend_from_slice(&w[&Field::IpDestination].to_be_bytes());
            pseudo.extend_from_slice(&[0, w[&Field::IpProtocol] as u8]);
            if body.len() > 65535 {
                return Err(WireError::Unrepresentable);
            }
            pseudo.extend_from_slice(&(body.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(&body);
            let sum = checksum(&pseudo);
            put16(&mut body, 16, sum);
        }
        if w.contains_key(&Field::UdpSource)
            && self.tcp_dirty
            && !self.fragmented
            && !self.overrides.contains(&Field::UdpChecksum)
        {
            if body.len() > 65535 {
                return Err(WireError::Unrepresentable);
            }
            put16(&mut body, 6, 0);
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&w[&Field::IpSource].to_be_bytes());
            pseudo.extend_from_slice(&w[&Field::IpDestination].to_be_bytes());
            pseudo.extend_from_slice(&[0, w[&Field::IpProtocol] as u8]);
            pseudo.extend_from_slice(&(body.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(&body);
            let sum = checksum(&pseudo);
            put16(&mut body, 6, if sum == 0 { 65535 } else { sum });
        }
        Ok(body)
    }
    fn render(&self) -> Result<Vec<u8>, WireError> {
        if !self.offset.is_multiple_of(8)
            || self.offset / 8 > 8191
            || self.packet.ip.flags & !0xe000 != 0
        {
            return Err(WireError::Unrepresentable);
        }
        let body = self.transport()?;
        let total = self.ip.len() + body.len();
        if total > 65535
            || self.packet.ip.flags & IP_FLAG_MORE_FRAGMENTS != 0 && body.len() % 8 != 0
        {
            return Err(WireError::Unrepresentable);
        }
        let mut ip = self.ip.clone();
        let w = &self.packet.wire_fields;
        ip[0] = ((w[&Field::IpVersion] as u8) << 4) | (w[&Field::IpIhl] as u8);
        ip[1] = w[&Field::IpTos] as u8;
        ip[9] = w[&Field::IpProtocol] as u8;
        put32(&mut ip, 12, w[&Field::IpSource]);
        put32(&mut ip, 16, w[&Field::IpDestination]);
        put16(
            &mut ip,
            2,
            if self.overrides.contains(&Field::IpLength) {
                w[&Field::IpLength] as u16
            } else {
                total as u16
            },
        );
        put16(&mut ip, 4, self.packet.ip.id);
        put16(&mut ip, 6, self.packet.ip.flags | (self.offset / 8) as u16);
        ip[8] = self.packet.ip.ttl;
        put16(
            &mut ip,
            10,
            if self.ip_override || !self.ip_dirty {
                self.packet.ip.checksum
            } else {
                0
            },
        );
        if !self.ip_override && self.ip_dirty {
            let sum = checksum(&ip);
            put16(&mut ip, 10, sum);
        }
        let mut frame = self.ethernet.clone();
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&body);
        Ok(frame)
    }
}
fn emit<R: Rng + ?Sized>(
    action: &Action,
    mut image: Image,
    rng: &mut R,
    out: &mut Vec<Vec<u8>>,
    bytes: &mut usize,
    depth: usize,
) -> Result<(), WireError> {
    if depth >= crate::syntax::action::MAX_DEPTH {
        return Err(WireError::Budget);
    }
    match action {
        Action::Pass => {
            let frame = image.render()?;
            *bytes = bytes.checked_add(frame.len()).ok_or(WireError::Budget)?;
            if out.len() >= MAX_OUTPUTS || *bytes > MAX_BATCH_BYTES {
                return Err(WireError::Budget);
            }
            out.push(frame);
        }
        Action::Drop => {}
        Action::Duplicate { left, right } => {
            emit(left, image.clone(), rng, out, bytes, depth + 1)?;
            emit(right, image, rng, out, bytes, depth + 1)?;
        }
        Action::Tamper { field, mode, next } => {
            if let Some(spec) = image
                .plan
                .as_ref()
                .map(PlanCursor::next_tamper)
                .transpose()?
                .flatten()
            {
                match &spec {
                    super::program::LiveTamper::TcpOption(spec) => {
                        if let Some(tcp) = image.tcp.as_mut() {
                            if image.fragmented {
                                return Err(WireError::Unrepresentable);
                            }
                            super::options::apply(tcp, spec, &mut image.tcp_options, rng)?;
                            let data_offset = (tcp.len() / 4) as u8;
                            image
                                .packet
                                .tcp
                                .as_mut()
                                .ok_or(WireError::Unrepresentable)?
                                .data_offset = data_offset;
                            image.overrides.remove(&Field::DataOffset);
                            image.overrides.remove(&Field::IpLength);
                            image.overrides.remove(&Field::TcpChecksum);
                            image.overrides.remove(&Field::IpChecksum);
                            image.ip_override = false;
                            image.tcp_override = false;
                            image.ip_dirty = true;
                            image.tcp_dirty = true;
                        }
                    }
                    super::program::LiveTamper::Dns(spec) => {
                        if let Some((dns_bytes, prefix)) = image.dns_data()? {
                            if matches!(spec.mode, super::dns::Mode::Compress)
                                && (image.packet.tcp.is_some() || u16_at(dns_bytes, 4) == 0)
                            {
                                emit(next, image, rng, out, bytes, depth + 1)?;
                                return Ok(());
                            }
                            let changed = super::dns::apply(
                                dns_bytes,
                                spec,
                                image.packet.tcp.is_some(),
                                rng,
                            )?;
                            image.packet.payload.truncate(prefix);
                            image.packet.payload.extend_from_slice(&changed);
                            if image.packet.tcp.is_some() {
                                let len = changed.len();
                                if len > 65535 {
                                    return Err(WireError::Budget);
                                }
                                put16(&mut image.packet.payload, 0, len as u16);
                            }
                            image.ip_override = false;
                            image.tcp_override = false;
                            image.ip_dirty = true;
                            image.tcp_dirty = true;
                            for field in [
                                Field::IpLength,
                                Field::IpChecksum,
                                Field::TcpChecksum,
                                Field::UdpLength,
                                Field::UdpChecksum,
                            ] {
                                image.overrides.remove(&field);
                            }
                        }
                    }
                }
                emit(next, image, rng, out, bytes, depth + 1)?;
                return Ok(());
            }
            let before = image.packet.clone();
            let applicable = image.packet.get(*field).is_some();
            if image.plan.is_some() && applicable {
                image.ip_override = false;
                image.tcp_override = false;
                image.ip_dirty = true;
                image.tcp_dirty = true;
                image.overrides.remove(&Field::IpChecksum);
                image.overrides.remove(&Field::TcpChecksum);
            }
            let mode =
                if image.plan.is_some() && *mode == crate::syntax::action::TamperMode::Corrupt {
                    match field {
                        Field::IpFlags => crate::syntax::action::TamperMode::Replace(u32::from(
                            rng.gen::<u16>() & 0xe000,
                        )),
                        Field::TcpFlags => crate::syntax::action::TamperMode::Replace(u32::from(
                            rng.gen::<u16>() & 511,
                        )),
                        Field::DataOffset => crate::syntax::action::TamperMode::Replace(u32::from(
                            rng.gen::<u8>() & 15,
                        )),
                        _ => mode.clone(),
                    }
                } else {
                    mode.clone()
                };
            let present = tamper::apply(&mut image.packet, *field, &mode, rng);
            image.ip_dirty |= image.packet != before;
            image.tcp_dirty |=
                image.packet.tcp != before.tcp || image.packet.wire_fields != before.wire_fields;
            if present {
                image.overrides.insert(*field);
            }
            if present && *field == Field::IpFragment {
                image.offset = image.packet.wire_fields[field] as usize * 8;
            }
            if present && *field == Field::IpChecksum {
                image.ip_override = true;
            }
            if present && *field == Field::TcpChecksum {
                image.tcp_override = true;
            }
            emit(next, image, rng, out, bytes, depth + 1)?;
        }
        Action::TamperPayload { mode, next } => {
            let proto = image
                .plan
                .as_ref()
                .map(PlanCursor::next_payload)
                .transpose()?
                .unwrap_or(Proto::Tcp);
            if !image.has_layer(proto) {
                if image.plan.is_none() {
                    return Err(WireError::Unrepresentable);
                }
                emit(next, image, rng, out, bytes, depth + 1)?;
                return Ok(());
            }
            let header = if image.packet.wire_fields.contains_key(&Field::UdpSource) {
                8
            } else {
                0
            };
            let before = image.packet.payload.clone();
            let mut packet = image.packet.clone();
            packet.payload = image
                .load(proto)
                .ok_or(WireError::Unrepresentable)?
                .to_vec();
            let selected =
                if image.plan.is_some() && *mode == crate::actions::payload::PayloadMode::Corrupt {
                    let value = match rng.gen_range(0..4) {
                        0 => Vec::new(),
                        1 => super::values::unquote("__DNS_REQUEST__")
                            .map_err(|_| WireError::Unrepresentable)?,
                        2 => super::values::unquote("__HTTP_REQUEST__")
                            .map_err(|_| WireError::Unrepresentable)?,
                        _ => {
                            const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
                            (0..10)
                                .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())])
                                .collect()
                        }
                    };
                    crate::actions::payload::PayloadMode::Replace(value)
                } else {
                    mode.clone()
                };
            payload::apply(&mut packet, &selected, rng);
            if proto == Proto::Ip && image.plan.is_some() {
                // Layer.set_load replaces IP.payload with Raw, including any old
                // TCP/UDP layer. Subsequent actions cannot access that old layer.
                image.tcp = None;
                image.tcp_options = None;
                image.packet.tcp = None;
                image
                    .packet
                    .wire_fields
                    .retain(|field, _| field.proto() == Proto::Ip);
                image.packet.payload = packet.payload;
            } else {
                image.packet.payload.truncate(header);
                image.packet.payload.extend_from_slice(&packet.payload);
            }
            if image.plan.is_some() {
                image.ip_override = false;
                image.tcp_override = false;
                image.overrides.remove(&Field::IpLength);
                image.overrides.remove(&Field::IpChecksum);
                image.overrides.remove(&Field::TcpChecksum);
                image.ip_dirty = true;
                image.tcp_dirty = true;
            } else {
                image.ip_dirty |= image.packet.payload != before;
                image.tcp_dirty |= image.packet.payload != before;
            }
            emit(next, image, rng, out, bytes, depth + 1)?;
        }
        Action::Fragment {
            proto,
            offset,
            order,
            left,
            right,
        } => {
            let spec = image.plan.as_ref().map(PlanCursor::next).transpose()?;
            let mut split = usize::from(*offset).min(image.packet.payload.len());
            if let Some(spec) = &spec {
                if *proto == Proto::Tcp {
                    let len = image.packet.payload.len();
                    split = if spec.size == -1 || spec.size as usize >= len {
                        len / 2
                    } else {
                        spec.size as usize
                    };
                }
            }
            let mut a = image.clone();
            let mut b = image.clone();
            a.ip_dirty = true;
            b.ip_dirty = true;
            match proto {
                Proto::Udp => {
                    return Err(WireError::Unrepresentable);
                }
                Proto::Tcp => {
                    if image.packet.tcp.is_none() || image.packet.payload.is_empty() {
                        if spec.is_none() {
                            return Err(WireError::Unrepresentable);
                        }
                        a.ip_dirty = image.ip_dirty;
                        b.ip_dirty = image.ip_dirty;
                        emit(left, a, rng, out, bytes, depth + 1)?;
                        emit(right, b, rng, out, bytes, depth + 1)?;
                        return Ok(());
                    }
                    if image.fragmented {
                        return Err(WireError::Unrepresentable);
                    }
                    if spec.is_some() {
                        for part in [&mut a, &mut b] {
                            part.ip_override = false;
                            part.tcp_override = false;
                            part.overrides.remove(&Field::IpLength);
                            part.overrides.remove(&Field::TcpChecksum);
                            part.overrides.remove(&Field::IpChecksum);
                            part.packet.tcp.as_mut().unwrap().data_offset =
                                (part.tcp.as_ref().unwrap().len() / 4) as u8;
                        }
                    }
                    a.tcp_dirty = true;
                    b.tcp_dirty = true;
                    a.packet.payload.truncate(
                        split
                            + spec.as_ref().map_or(0, |s| {
                                usize::from(s.overlap).min(image.packet.payload.len() - split)
                            }),
                    );
                    b.packet.payload = image.packet.payload[split..].to_vec();
                    let t = b.packet.tcp.as_mut().unwrap();
                    t.seq = t.seq.wrapping_add(split as u32);
                }
                Proto::Ip => {
                    if spec.is_some() && image.load(Proto::Ip).is_some_and(|data| data.is_empty()) {
                        a.ip_dirty = image.ip_dirty;
                        b.ip_dirty = image.ip_dirty;
                        emit(left, a, rng, out, bytes, depth + 1)?;
                        emit(right, b, rng, out, bytes, depth + 1)?;
                        return Ok(());
                    }
                    // Freeze the transport checksum over the complete pre-fragment datagram.
                    let body = image.transport()?;
                    let prefix = image.tcp.as_ref().map_or(0, Vec::len);
                    let cut = if let Some(spec) = &spec {
                        if body.is_empty() {
                            a.ip_dirty = image.ip_dirty;
                            b.ip_dirty = image.ip_dirty;
                            emit(left, a, rng, out, bytes, depth + 1)?;
                            emit(right, b, rng, out, bytes, depth + 1)?;
                            return Ok(());
                        }
                        let requested = spec.size as i64 * 8;
                        let cut = if spec.size == -1
                            || requested > body.len() as i64
                            || body.len() <= 8
                        {
                            (body.len() / 2 / 8) * 8
                        } else {
                            requested as usize
                        };
                        if cut == 0 || cut >= body.len() {
                            a.ip_dirty = image.ip_dirty;
                            b.ip_dirty = image.ip_dirty;
                            emit(left, a, rng, out, bytes, depth + 1)?;
                            emit(right, b, rng, out, bytes, depth + 1)?;
                            return Ok(());
                        }
                        cut
                    } else {
                        prefix + split
                    };
                    if !cut.is_multiple_of(8) || image.offset + cut > 65528 {
                        return Err(WireError::Unrepresentable);
                    }
                    if let Some(t) = a.packet.tcp.as_mut() {
                        t.checksum = u16_at(&body, 16);
                    }
                    if spec.is_some() {
                        a.ip_override = false;
                        b.ip_override = false;
                        a.overrides.remove(&Field::IpLength);
                        b.overrides.remove(&Field::IpLength);
                    }
                    if cut < prefix {
                        a.tcp = None;
                        a.packet.tcp = None;
                        a.packet
                            .wire_fields
                            .retain(|field, _| field.proto() == Proto::Ip);
                        a.packet.payload = body[..cut].to_vec();
                    } else {
                        a.packet.payload.truncate(cut - prefix);
                    }
                    a.packet.ip.flags |= IP_FLAG_MORE_FRAGMENTS;
                    a.fragmented = true;
                    a.tcp_override = true;
                    if a.packet.wire_fields.contains_key(&Field::UdpChecksum) {
                        a.packet
                            .wire_fields
                            .insert(Field::UdpChecksum, u32::from(u16_at(&body, 6)));
                    }
                    b.tcp = None;
                    b.packet.tcp = None;
                    b.packet
                        .wire_fields
                        .retain(|field, _| field.proto() == Proto::Ip);
                    b.packet.payload = body[cut..].to_vec();
                    b.offset = image.offset + cut;
                    b.packet.ip.frag_offset = b.offset as u16;
                    b.packet
                        .wire_fields
                        .insert(Field::IpFragment, (b.offset / 8) as u32);
                    b.fragmented = true;
                    if spec.is_some() && body.len() > cut.saturating_mul(2) {
                        // Upstream coalesces third-and-later Scapy fragments into
                        // the second packet and explicitly writes its flags to DF.
                        b.packet.ip.flags = 0x4000;
                    }
                }
            }
            if *order == FragmentOrder::Reversed {
                std::mem::swap(&mut a, &mut b);
            }
            emit(left, a, rng, out, bytes, depth + 1)?;
            emit(right, b, rng, out, bytes, depth + 1)?;
        }
    }
    Ok(())
}
/// Execute atomically: callers receive either the entire ordered batch or an
/// error and MUST send no frames. ARP alone is passed byte-for-byte; VLAN,
/// IPv6 and malformed/unknown link protocols fail closed.
pub fn execute<R: Rng + ?Sized>(
    strategy: &Strategy,
    frame: &[u8],
    direction: Direction,
    rng: &mut R,
) -> Result<Vec<Vec<u8>>, WireError> {
    if frame.len() >= 42 && frame.len() <= MAX_FRAME && u16_at(frame, 12) == 0x0806 {
        if u16_at(frame, 14) != 1
            || u16_at(frame, 16) != 0x0800
            || frame[18] != 6
            || frame[19] != 4
            || ![1, 2].contains(&u16_at(frame, 20))
        {
            return Err(WireError::Frame);
        }
        return Ok(vec![frame.to_vec()]);
    }
    let image = Image::decode(frame, direction)?;
    let Some(rule) = strategy.first_match(&image.packet) else {
        return Ok(vec![frame.to_vec()]);
    };
    // An explicit pass is also byte-preserving, including deliberately bad incoming checksums.
    if rule.action == Action::Pass {
        return Ok(vec![frame.to_vec()]);
    }
    let mut output = Vec::new();
    emit(&rule.action, image, rng, &mut output, &mut 0, 0)?;
    Ok(output)
}

pub(super) fn execute_forest<R: Rng + ?Sized>(
    strategy: &Strategy,
    gas: &mut [Option<i32>],
    bombs: &[bool],
    fragments: &[super::program::RulePlan],
    frame: &[u8],
    direction: Direction,
    rng: &mut R,
) -> Result<Vec<Vec<u8>>, WireError> {
    // The stateless entrypoint owns the exact ARP validation contract.
    if frame.len() >= 14 && u16_at(frame, 12) == 0x0806 {
        return execute(&Strategy::identity(), frame, direction, rng);
    }
    let image = Image::decode(frame, direction)?;
    let rules = strategy.rules_for(direction);
    if gas.len() != rules.len() || bombs.len() != rules.len() || fragments.len() != rules.len() {
        return Err(WireError::Unrepresentable);
    }
    let mut next = gas.to_vec();
    let mut output = Vec::new();
    let mut bytes = 0;
    let mut fired = false;
    for (((rule, counter), bomb), specs) in
        rules.iter().zip(next.iter_mut()).zip(bombs).zip(fragments)
    {
        let matches = match &specs.trigger {
            Some(spec) => image.matches_text(spec)?,
            None => rule.trigger.matches(&image.packet),
        };
        if !matches {
            continue;
        }
        let run = match counter {
            None => true,
            Some(n) if *n < 0 => {
                *n += 1;
                false
            }
            Some(0) => *bomb,
            Some(n) => {
                *n -= 1;
                true
            }
        };
        if !run {
            continue;
        }
        fired = true;
        if rule.action == Action::Pass {
            bytes += frame.len();
            if output.len() >= MAX_OUTPUTS || bytes > MAX_BATCH_BYTES {
                return Err(WireError::Budget);
            }
            output.push(frame.to_vec());
        } else {
            let mut original = image.clone();
            let plan = PlanCursor::new(specs.clone());
            original.plan = Some(plan.clone());
            emit(&rule.action, original, rng, &mut output, &mut bytes, 0)?;
            if !plan.complete() {
                return Err(WireError::Unrepresentable);
            }
        }
    }
    if !fired {
        output.push(frame.to_vec());
    }
    gas.clone_from_slice(&next);
    Ok(output)
}

#[cfg(test)]
#[path = "wire_dns_trigger_tests.rs"]
mod dns_trigger_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::program::Program;
    use rand::{rngs::StdRng, SeedableRng};
    fn rng() -> StdRng {
        StdRng::seed_from_u64(45)
    }
    fn frame() -> Vec<u8> {
        let mut b = vec![0u8; 14 + 24 + 24 + 16];
        b[..12].copy_from_slice(&[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]);
        put16(&mut b, 12, 0x0800);
        b[14] = 0x46;
        let total = (b.len() - 14) as u16;
        put16(&mut b, 16, total);
        put16(&mut b, 18, 42);
        b[22] = 64;
        b[23] = 6;
        b[26..34].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        b[34..38].copy_from_slice(&[1, 1, 0, 0]);
        let t = 38;
        put16(&mut b, t, 1234);
        put16(&mut b, t + 2, 443);
        put32(&mut b, t + 4, u32::MAX - 2);
        put32(&mut b, t + 8, 10);
        b[t + 12] = 0x60;
        b[t + 13] = 0x18;
        put16(&mut b, t + 14, 4096);
        b[t + 20..t + 24].copy_from_slice(&[1, 1, 0, 0]);
        b[t + 24..].copy_from_slice(b"abcdefghijklmnop");
        let mut pseudo = b[26..34].to_vec();
        pseudo.extend_from_slice(&[0, 6, 0, 40]);
        pseudo.extend_from_slice(&b[t..]);
        let tcp = checksum(&pseudo);
        put16(&mut b, t + 16, tcp);
        let ip = checksum(&b[14..38]);
        put16(&mut b, 24, ip);
        b
    }
    fn run(text: &str, b: &[u8]) -> Result<Vec<Vec<u8>>, WireError> {
        execute(
            &Strategy::parse(text).unwrap(),
            b,
            Direction::Outbound,
            &mut rng(),
        )
    }
    #[test]
    fn duplicates_preserve_headers_options_and_bad_checksums() {
        let mut b = frame();
        put16(&mut b, 24, 12);
        put16(&mut b, 54, 34);
        assert_eq!(
            run("[IP:ttl:64]-duplicate(,)-|", &b).unwrap(),
            vec![b.clone(), b]
        );
    }
    #[test]
    fn tcp_segments_are_real_ordered_frames_with_wrapped_sequence_and_valid_checksums() {
        let b = frame();
        let out = run("[TCP:flags:PA]-fragment{TCP:3:reversed}(,)-|", &b).unwrap();
        assert_eq!(&out[0][62..], b"defghijklmnop");
        assert_eq!(u32_at(&out[0], 42), 0);
        assert_eq!(&out[1][62..], b"abc");
        for f in out {
            assert_eq!(&f[26..34], &b[26..34]);
            assert_eq!(&f[58..62], &b[58..62]);
            assert_eq!(checksum(&f[14..38]), 0);
            let mut pseudo = f[26..34].to_vec();
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&((f.len() - 38) as u16).to_be_bytes());
            pseudo.extend_from_slice(&f[38..]);
            assert_eq!(checksum(&pseudo), 0);
        }
    }
    #[test]
    fn ip_fragments_cover_transport_bytes_and_absolute_offsets() {
        let b = frame();
        let out = run("[IP:ttl:64]-fragment{IP:8:in-order}(,)-|", &b).unwrap();
        assert_eq!(u16_at(&out[0], 20) & 0x2000, 0x2000);
        assert_eq!(u16_at(&out[1], 20) & 0x1fff, 4);
        let mut payload = out[0][38..].to_vec();
        payload.extend_from_slice(&out[1][38..]);
        assert_eq!(payload, b[38..]);
        assert_eq!(u16_at(&out[0], 18), u16_at(&out[1], 18));
    }
    #[test]
    fn unaligned_ip_fragment_is_atomic_refusal() {
        assert_eq!(
            run(
                "[IP:ttl:64]-duplicate(,fragment{IP:3:in-order}(,))-|",
                &frame()
            ),
            Err(WireError::Unrepresentable)
        );
    }
    #[test]
    fn inbound_branching_executes_both_children() {
        let p = Strategy::parse("\\/ [IP:ttl:64]-duplicate(tamper{IP:ttl:replace:4}(),drop)-|")
            .unwrap();
        let out = execute(&p, &frame(), Direction::Inbound, &mut rng()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][22], 4);
    }
    #[test]
    fn explicit_checksum_equal_to_original_is_not_repaired_after_payload_change() {
        let b = frame();
        let sum = u16_at(&b, 54);
        let out = run(
            &format!(
                "[IP:ttl:64]-tamper{{TCP:chksum:replace:{sum}}}(tamper{{TCP:load:truncate:1}}())-|"
            ),
            &b,
        )
        .unwrap();
        assert_eq!(u16_at(&out[0], 54), sum);
        assert_eq!(&out[0][62..], b"a");
    }
    #[test]
    fn numeric_fields_and_add_rewrite_real_wire_bits() {
        let b = frame();
        let out = run(
            "[TCP:sport:1234]-tamper{TCP:sport:add:-234}(tamper{IP:tos:replace:16}())-|",
            &b,
        )
        .unwrap();
        assert_eq!(u16_at(&out[0], 38), 1000);
        assert_eq!(out[0][15], 16);
        assert_eq!(checksum(&out[0][14..38]), 0);
    }
    #[test]
    fn udp_trigger_and_tamper_uses_real_datagram_fields() {
        let mut b = frame();
        b[23] = 17;
        b.truncate(38 + 8 + 8);
        let len = (b.len() - 14) as u16;
        put16(&mut b, 16, len);
        put16(&mut b, 38, 1234);
        put16(&mut b, 40, 53);
        put16(&mut b, 42, 16);
        put16(&mut b, 44, 0);
        b[46..].copy_from_slice(b"abcdefgh");
        let ip = checksum(&b[14..38]);
        put16(&mut b, 24, ip);
        let out = run("[UDP:dport:53]-tamper{UDP:sport:add:1}()-|", &b).unwrap();
        assert_eq!(u16_at(&out[0], 38), 1235);
        let mut pseudo = out[0][26..34].to_vec();
        pseudo.extend_from_slice(&[0, 17, 0, 16]);
        pseudo.extend_from_slice(&out[0][38..]);
        assert_eq!(checksum(&pseudo), 0);
    }
    #[test]
    fn all_forest_matches_use_independent_original_copies() {
        let mut p = Program::parse(
            "[IP:ttl:64]-tamper{IP:ttl:replace:3}()-| [IP:ttl:64]-tamper{IP:ttl:replace:5}()-|",
        )
        .unwrap();
        let out = p
            .execute(&frame(), Direction::Outbound, &mut rng())
            .unwrap();
        assert_eq!(out.iter().map(|b| b[22]).collect::<Vec<_>>(), vec![3, 5]);
    }
    #[test]
    fn gas_positive_zero_negative_and_direction_counters_are_stateful() {
        let b = frame();
        let mut p = Program::parse("[IP:ttl:64]-drop-| \\/ [IP:ttl:64:2]-drop-|").unwrap();
        assert!(p
            .execute(&b, Direction::Outbound, &mut rng())
            .unwrap()
            .is_empty());
        for _ in 0..2 {
            assert!(p
                .execute(&b, Direction::Inbound, &mut rng())
                .unwrap()
                .is_empty());
        }
        assert_eq!(
            p.execute(&b, Direction::Inbound, &mut rng()).unwrap(),
            vec![b.clone()]
        );
        let mut bomb = Program::parse("[IP:ttl:64:-2]-drop-|").unwrap();
        for _ in 0..2 {
            assert_eq!(
                bomb.execute(&b, Direction::Outbound, &mut rng()).unwrap(),
                vec![b.clone()]
            );
        }
        for _ in 0..3 {
            assert!(bomb
                .execute(&b, Direction::Outbound, &mut rng())
                .unwrap()
                .is_empty());
        }
        let mut zero = Program::parse("[IP:ttl:64:0]-drop-|").unwrap();
        assert_eq!(
            zero.execute(&b, Direction::Outbound, &mut rng()).unwrap(),
            vec![b]
        );
    }
    #[test]
    fn forest_expansion_limit_returns_no_partial_batch() {
        let text = "[IP:ttl:64]-duplicate(,)-| ".repeat(33);
        let mut p = Program::parse(&text).unwrap();
        assert_eq!(
            p.execute(&frame(), Direction::Outbound, &mut rng()),
            Err(WireError::Budget)
        );
    }
    #[test]
    fn extended_declared_length_is_an_intentional_wire_override() {
        let out = run("[IP:ttl:64]-tamper{IP:len:replace:1}()-|", &frame()).unwrap();
        assert_eq!(u16_at(&out[0], 16), 1);
        assert_eq!(out[0].len(), 78);
    }
    #[test]
    fn header_only_ip_fragment_duplicates_before_checksum_repair() {
        let mut b = frame();
        b.truncate(62);
        put16(&mut b, 16, 48);
        let mut p = Program::parse("[TCP:flags:PA]-fragment{IP:1:True}(,)-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()).unwrap(),
            vec![b.clone(), b]
        );
    }
    #[test]
    fn dns_compress_tcp_is_untouched_and_record_sections_remain_before_raw_queries() {
        let udp = dns_frame();
        let dns = &udp[46..];
        let mut tcp = frame();
        tcp.truncate(62);
        put16(&mut tcp, 40, 53);
        tcp.extend_from_slice(&(dns.len() as u16).to_be_bytes());
        tcp.extend_from_slice(dns);
        let len = tcp.len() - 14;
        put16(&mut tcp, 16, len as u16);
        let mut p = Program::parse("[DNS:id:4660]-tamper{DNS:qd:compress}()-|").unwrap();
        assert_eq!(
            p.execute(&tcp, Direction::Outbound, &mut rng()).unwrap(),
            vec![tcp]
        );
        let mut message = dns.to_vec();
        put16(&mut message, 6, 1);
        message.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 12, 0, 1]);
        let spec = super::super::dns::Spec::parse("DNS", "qd", &["compress"]).unwrap();
        let out = super::super::dns::apply(&message, &spec, false, &mut rng()).unwrap();
        assert_eq!(u16_at(&out, 4), 2);
        assert_eq!(u16_at(&out, 6), 1);
        assert_eq!(&out[12..29], b"\x03www\x07example\x03com\x00");
        assert_eq!(&out[39..43], &[192, 12, 0, 1]);
        // Faithful original oddity: records precede appended raw queries, while
        // the forward pointer still uses the original 12-byte header base.
        assert_eq!(
            &out[43..],
            b"\x03www\xc0\x16\x00\x01\x00\x01\x07example\x03com\x00\x00\x01\x00\x01"
        );
    }
    #[test]
    fn live_midpoint_overlap_and_boolean_order_use_upstream_tcp_semantics() {
        let b = frame();
        let mut p = Program::parse("[TCP:flags:PA]-fragment{TCP:-1:False:3}(,)-|").unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(&out[0][62..], b"ijklmnop");
        assert_eq!(&out[1][62..], b"abcdefghijk");
        assert_eq!(u32_at(&out[0], 42), 5);
        let mut over = Program::parse("[TCP:flags:PA]-fragment{TCP:60000:True}(,)-|").unwrap();
        let out = over.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(&out[0][62..], b"abcdefgh");
        assert_eq!(&out[1][62..], b"ijklmnop");
    }
    #[test]
    fn live_ip_cut_counts_eight_byte_transport_units_including_partial_tcp_header() {
        let b = frame();
        let mut p = Program::parse("[IP:ttl:64]-fragment{IP:-1:True}(,)-|").unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(out[0].len(), 38 + 16);
        assert_eq!(u16_at(&out[1], 20) & 8191, 2);
        let mut full = out[0][38..].to_vec();
        full.extend_from_slice(&out[1][38..]);
        assert_eq!(full, b[38..]);
        let mut one = Program::parse("[IP:ttl:64]-fragment{IP:1:True}(,)-|").unwrap();
        let out = one.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(out[0].len(), 38 + 8);
        assert_eq!(u16_at(&out[1], 20) & 8191, 1);
    }
    #[test]
    fn live_fragment_metadata_is_executed_in_nested_preorder_without_silent_alias() {
        let b = frame();
        let mut p = Program::parse(
            "[IP:ttl:64]-duplicate(fragment{TCP:3:True:2}(,),fragment{TCP:-1:False}(,))-| \\/",
        )
        .unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(
            out.iter().map(|f| f[62..].to_vec()).collect::<Vec<_>>(),
            vec![
                b"abcde".to_vec(),
                b"defghijklmnop".to_vec(),
                b"ijklmnop".to_vec(),
                b"abcdefgh".to_vec()
            ]
        );
        let mut ignored_overlap = Program::parse("[IP:ttl:64]-fragment{IP:1:True:2}(,)-|").unwrap();
        let overlap_out = ignored_overlap
            .execute(&b, Direction::Outbound, &mut rng())
            .unwrap();
        let mut plain = Program::parse("[IP:ttl:64]-fragment{IP:1:True}(,)-|").unwrap();
        assert_eq!(
            overlap_out,
            plain.execute(&b, Direction::Outbound, &mut rng()).unwrap()
        );
        assert_eq!(u16_at(&overlap_out[1], 20) & 0xe000, 0x4000);
        assert!(Program::parse("[IP:ttl:64]-fragment{TCP:-2:True}(,)-|").is_err());
    }
    #[test]
    fn absent_tcp_segmentation_duplicates_without_rewriting_original_checksums() {
        let mut b = frame();
        b[23] = 1;
        put16(&mut b, 24, 12);
        let mut p = Program::parse("[IP:ttl:64]-fragment{TCP:-1:True}(,)-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()).unwrap(),
            vec![b.clone(), b]
        );
    }
    #[test]
    fn unknown_protocol_vlan_ipv6_bad_layer_and_large_frame_refuse() {
        for b in [vec![0u8; 10], vec![0u8; MAX_FRAME + 1]] {
            assert_eq!(run("", &b), Err(WireError::Frame));
        }
        let mut b = frame();
        put16(&mut b, 12, 0x86dd);
        assert_eq!(run("", &b), Err(WireError::Frame));
        assert!(Program::parse("[DNS:qd:1]-drop-|").is_err());
        assert!(Program::parse("[IP:ttl:64:1:2]-drop-|").is_err());
        assert!(Program::parse("\u{2003}[IP:ttl:64]-drop-|").is_err());
    }
    #[test]
    fn live_text_flags_addresses_and_encoded_load_match_real_fields() {
        let b = frame();
        for trigger in [
            "TCP:flags:P*",
            "IP:src:10.0.*",
            "TCP:load:abcd*",
            "IP:load:abcdefghijklmnop",
        ] {
            let mut p = Program::parse(&format!("[{trigger}]-drop-|")).unwrap();
            assert!(p
                .execute(&b, Direction::Outbound, &mut rng())
                .unwrap()
                .is_empty());
        }
        let mut p = Program::parse("[TCP:load:xyz*]-drop-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()).unwrap(),
            vec![b.clone()]
        );
        let mut b = b;
        put16(&mut b, 20, 0x6000);
        let mut p = Program::parse("[IP:flags:MF+DF]-drop-|").unwrap();
        assert!(p
            .execute(&b, Direction::Outbound, &mut rng())
            .unwrap()
            .is_empty());
        let mut p = Program::parse("[IP:flags:DF+MF]-drop-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()).unwrap(),
            vec![b]
        );
    }
    #[test]
    fn live_payload_escapes_and_layer_semantics_are_wire_execution() {
        let b = frame();
        let mut p = Program::parse("[IP:ttl:64]-tamper{TCP:load:replace:GET%20/%3A%7B%7D%2D%7C}(tamper{TCP:flags:replace:ECN}())-|").unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(&out[0][62..], b"GET /:{}-|");
        assert_eq!(out[0][50] & 1, 1);
        assert_eq!(out[0][51], 0xc0);
        assert_eq!(checksum(&out[0][14..38]), 0);
        let mut p =
            Program::parse("[IP:ttl:64]-tamper{UDP:load:replace:refused-on-TCP}()-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()).unwrap(),
            vec![b]
        );
    }
    #[test]
    fn ip_load_replaces_transport_layer_and_chained_old_tcp_action_is_missing() {
        let b = frame();
        let mut program = Program::parse(
            "[IP:ttl:64]-tamper{IP:load:replace:Raw%3A}(tamper{TCP:flags:replace:ECN}())-|",
        )
        .unwrap();
        let output = program
            .execute(&b, Direction::Outbound, &mut rng())
            .unwrap();
        assert_eq!(&output[0][38..], b"Raw:");
        assert_eq!(output[0][23], 6); // Declared protocol is intentionally retained.
        assert_eq!(u16_at(&output[0], 16), 28);
        assert_eq!(checksum(&output[0][14..38]), 0);
    }
    #[test]
    fn live_program_checksum_override_obeys_upstream_last_write_order() {
        let b = frame();
        let mut p = Program::parse(
            "[IP:ttl:64]-tamper{TCP:chksum:replace:0}(tamper{IP:ttl:replace:63}())-|",
        )
        .unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_ne!(u16_at(&out[0], 54), 0);
        let mut p = Program::parse(
            "[IP:ttl:64]-tamper{IP:ttl:replace:63}(tamper{TCP:chksum:replace:0}())-|",
        )
        .unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(u16_at(&out[0], 54), 0);
    }
    #[test]
    fn load_quote_decode_matches_upstream_utf8_ignore_and_escaped_delimiters() {
        assert_eq!(
            super::super::values::quote_utf8_ignore(&[b'A', 0xff, b' ', b':']),
            "A%20%3A"
        );
        assert_eq!(
            super::super::values::unquote("a%3Ab%7Dc%2A").unwrap(),
            b"a:b}c*"
        );
        assert!(super::super::values::unquote("%zz").is_err());
        assert!(Program::parse("[IP:ttl:64]-tamper{TCP:load:replace:%zz}()-|").is_err());
        assert!(Program::parse(&format!(
            "[IP:ttl:64]-{}drop{}-|",
            "duplicate(".repeat(10000),
            ",)".repeat(10000)
        ))
        .is_err());
    }
    #[test]
    fn live_tcp_options_execute_all_original_option_kinds_and_checksums() {
        let original = frame();
        let mut b = original[..58].to_vec();
        b[50] = 0x50;
        b.extend_from_slice(b"data");
        put16(&mut b, 16, 48);
        for (name, value, expected) in [
            ("mss", "1460", "1460"),
            ("wscale", "7", "7"),
            ("timestamp", "1234", "1234"),
            ("altchksum", "1", "1"),
            ("uto", "23", "23"),
            (
                "md5header",
                "000102030405060708090a0b0c0d0e0f",
                "000102030405060708090a0b0c0d0e0f",
            ),
            ("altchksumopt", "abcd", "abcd"),
            ("sack", "", ""),
            ("sackok", "", ""),
            ("nop", "", ""),
            ("eol", "", ""),
        ] {
            let mut p = Program::parse(&format!(
                "[IP:ttl:64]-tamper{{TCP:options-{name}:replace:{value}}}()-|"
            ))
            .unwrap();
            let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
            let image = Image::decode(&out[0], Direction::Outbound).unwrap();
            assert_eq!(
                super::super::options::get(
                    image.tcp.as_ref().unwrap(),
                    super::super::options::Name::parse(name).unwrap()
                )
                .unwrap(),
                expected,
                "{}",
                name
            );
            assert_eq!(image.packet.payload, b"data");
            assert_eq!(checksum(&out[0][14..38]), 0);
            let mut pseudo = out[0][26..34].to_vec();
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&((out[0].len() - 38) as u16).to_be_bytes());
            pseudo.extend_from_slice(&out[0][38..]);
            assert_eq!(checksum(&pseudo), 0);
        }
    }
    #[test]
    fn live_options_trigger_and_wrapped_add_observe_real_option_bytes() {
        let b = frame();
        let mut p=Program::parse("[TCP:options-mss:]-tamper{TCP:options-mss:replace:65535}(tamper{TCP:options-mss:add:2}())-|").unwrap();
        // Scapy appends missing options after an existing EOL; preserve that ordering.
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        // Chained Add sees the logical option list even though the receiver stops at EOL.
        assert_eq!(&out[0][58..66], &[1, 1, 0, 2, 4, 0, 1, 0]);
        assert_eq!(
            super::super::options::get(&out[0][38..66], super::super::options::Name::Mss).unwrap(),
            ""
        );
        let mut b = b[..58].to_vec();
        b[50] = 0x50;
        put16(&mut b, 16, 44);
        let mut p=Program::parse("[TCP:options-mss:]-tamper{TCP:options-mss:replace:65535}(tamper{TCP:options-mss:add:2}())-|").unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        let mut p = Program::parse("[TCP:options-mss:1]-drop-|").unwrap();
        assert!(p
            .execute(&out[0], Direction::Outbound, &mut rng())
            .unwrap()
            .is_empty());
        assert!(Program::parse("[TCP:options-mss:1*]-drop-|").is_err());
        assert!(
            Program::parse("[IP:ttl:64]-tamper{TCP:options-md5header:replace:01}()-|").is_err()
        );
    }
    #[test]
    fn malformed_option_access_and_option_header_overflow_are_atomic_refusal() {
        let mut b = frame();
        b[58..62].copy_from_slice(&[2, 8, 0, 0]);
        let mut p = Program::parse("[TCP:options-mss:]-drop-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()),
            Err(WireError::Frame)
        );
        let b = frame();
        let mut p=Program::parse("[IP:ttl:64]-duplicate(,tamper{TCP:options-altchksumopt:replace:00000000000000000000000000000000000000000000000000000000000000000000000000}())-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()),
            Err(WireError::Budget)
        );
    }
    fn dns_frame() -> Vec<u8> {
        let mut b = frame()[..38].to_vec();
        b[23] = 17;
        let mut dns = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        dns.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
        b.extend_from_slice(&[0x04, 0xd2, 0, 53, 0, 0, 0, 0]);
        b.extend_from_slice(&dns);
        let total = b.len() - 14;
        put16(&mut b, 16, total as u16);
        put16(&mut b, 42, (total - 24) as u16);
        b
    }
    #[test]
    fn dns_and_question_fields_trigger_and_tamper_actual_udp_wire() {
        let b = dns_frame();
        let mut p=Program::parse("[DNSQR:qname:example*]-tamper{DNS:rcode:replace:3}(tamper{DNSQR:qtype:replace:28}())-|").unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        let dns = &out[0][46..];
        assert_eq!(u16_at(dns, 2) & 15, 3);
        assert_eq!(
            super::super::dns::get(dns, super::super::dns::Field::Qtype).unwrap(),
            Some("28".into())
        );
        let mut p =
            Program::parse("[DNS:id:4660]-tamper{DNSQR:qname:replace:changed.test.}()-|").unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(
            super::super::dns::get(&out[0][46..], super::super::dns::Field::Qname).unwrap(),
            Some("changed.test.".into())
        );
        assert_eq!(checksum(&out[0][14..38]), 0);
        let mut pseudo = out[0][26..34].to_vec();
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&((out[0].len() - 38) as u16).to_be_bytes());
        pseudo.extend_from_slice(&out[0][38..]);
        assert_eq!(checksum(&pseudo), 0);
        let mut p = Program::parse("[DNS:rd:1]-tamper{DNS:id:add:-4660}()-|").unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        assert_eq!(u16_at(&out[0], 46), 0);
    }
    #[test]
    fn original_dns_compress_emits_real_forward_pointer_and_two_questions() {
        let b = dns_frame();
        let mut p = Program::parse("[DNSQR:qtype:1]-tamper{DNS:qd:compress}()-|").unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        let dns = &out[0][46..];
        assert_eq!(u16_at(dns, 4), 2);
        assert_eq!(u16_at(dns, 16), 0xc016);
        assert_eq!(
            super::super::dns::get(dns, super::super::dns::Field::Qname).unwrap(),
            Some("www.example.com.".into())
        );
        assert_eq!(u16_at(&out[0], 42) as usize, out[0].len() - 38);
        assert_eq!(u16_at(&out[0], 16) as usize, out[0].len() - 14);
    }
    #[test]
    fn dns_name_pointer_cycle_and_unrepresentable_record_rewrite_refuse_atomically() {
        let mut b = dns_frame();
        b[58..60].copy_from_slice(&[0xc0, 12]);
        let mut p = Program::parse("[IP:ttl:64]--| [DNSQR:qname:example*]-drop-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()),
            Err(WireError::Frame)
        );
        let mut b = dns_frame();
        put16(&mut b, 52, 1);
        let mut p =
            Program::parse("[DNS:id:4660]-tamper{DNSQR:qname:replace:changed.test.}()-|").unwrap();
        assert_eq!(
            p.execute(&b, Direction::Outbound, &mut rng()),
            Err(WireError::Frame)
        );
        assert!(Program::parse("[DNS:qd:1]-drop-|").is_err());
        assert!(
            Program::parse("[IP:ttl:64]-tamper{DNS:qd:replace:arbitrary-python-object}()-|")
                .is_err()
        );
    }
    #[test]
    fn qname_rewrite_relocates_compressed_answer_names_without_corrupting_address_bytes() {
        let mut b = dns_frame();
        put16(&mut b, 52, 2);
        b.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 16]);
        b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 12, 0, 1]);
        let len = (b.len() - 14) as u16;
        put16(&mut b, 16, len);
        put16(&mut b, 42, len - 24);
        let mut p =
            Program::parse("[DNSQR:qname:example*]-tamper{DNSQR:qname:replace:changed.test.}()-|")
                .unwrap();
        let out = p.execute(&b, Direction::Outbound, &mut rng()).unwrap();
        let dns = &out[0][46..];
        assert_eq!(
            super::super::dns::get(dns, super::super::dns::Field::Qname).unwrap(),
            Some("changed.test.".into())
        );
        assert!(dns.windows(13).any(|w| w == b"\x07example\x03com\x00"));
        assert_eq!(&dns[dns.len() - 4..], &[192, 12, 0, 1]);
        assert_eq!(u16_at(dns, 6), 2);
        assert_eq!(checksum(&out[0][14..38]), 0);
    }
}
