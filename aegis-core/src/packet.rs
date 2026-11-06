//! Raw IPv4/TCP helpers: packet build, header patching, fragmentation and raw send.
//! Стратегии и capability-aware orchestration находятся в `raw_engine`.

use std::io;
use std::net::Ipv4Addr;

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4HeaderShaping {
    pub tos: u8,
    pub identification: u16,
    pub dont_fragment: bool,
}

fn default_ipv4_identification(sport: u16, dport: u16, seq: u32, ack: u32) -> u16 {
    ((sport as u32) ^ ((dport as u32) << 3) ^ seq ^ ack) as u16
}

fn apply_ipv4_header_shaping_fields(
    ip: &mut [u8; 20],
    identification: u16,
    shaping: Option<Ipv4HeaderShaping>,
) {
    let shaping = shaping.unwrap_or(Ipv4HeaderShaping {
        tos: 0,
        identification,
        dont_fragment: false,
    });
    ip[1] = shaping.tos;
    ip[4..6].copy_from_slice(&shaping.identification.to_be_bytes());
    let flags_offset = if shaping.dont_fragment {
        0x4000u16
    } else {
        0u16
    };
    ip[6..8].copy_from_slice(&flags_offset.to_be_bytes());
}

fn finalize_ipv4_header_checksum(ip: &mut [u8; 20]) {
    ip[10..12].fill(0);
    let ip_csum = ipv4_header_checksum(ip);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());
}

fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Контрольная сумма IPv4-заголовка (поле checksum при расчёте = 0).
pub fn ipv4_header_checksum(header_20: &[u8; 20]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        sum += u16::from_be_bytes([header_20[i], header_20[i + 1]]) as u32;
    }
    fold_checksum(sum)
}

/// TCP checksum (IPv4 pseudo-header + сегмент, в сегменте байты 16–17 = 0).
pub fn tcp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += 6u32;
    sum += tcp_segment.len() as u32;
    let mut i = 0usize;
    while i < tcp_segment.len() {
        let w = if i + 1 < tcp_segment.len() {
            u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32
        } else {
            (tcp_segment[i] as u32) << 8
        };
        sum += w;
        i += 2;
    }
    fold_checksum(sum)
}

/// Полный IPv4/TCP пакет c опциональным TCP options block.
///
/// `tcp_options` должен быть выровнен по 4 байтам и помещаться в TCP header limit.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp_packet_with_options(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    ttl: u8,
    tcp_options: &[u8],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    build_ipv4_tcp_packet_with_options_and_shaping(
        src_ip,
        dst_ip,
        sport,
        dport,
        seq,
        ack,
        flags,
        window,
        ttl,
        None,
        tcp_options,
        payload,
    )
}

/// Полный IPv4/TCP пакет c опциональным TCP options block и optional outer IPv4 shaping.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp_packet_with_options_and_shaping(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    ttl: u8,
    ipv4_header_shaping: Option<Ipv4HeaderShaping>,
    tcp_options: &[u8],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if !tcp_options.len().is_multiple_of(4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP options must be 4-byte aligned",
        ));
    }
    if tcp_options.len() > 40 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP options exceed 40-byte header limit",
        ));
    }
    let tcp_header_len = 20usize
        .checked_add(tcp_options.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TCP header too large"))?;
    let total_len = 20usize
        .checked_add(tcp_header_len)
        .and_then(|x| x.checked_add(payload.len()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "IPv4 packet too large"))?;
    let total_len_u16 = u16::try_from(total_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "IPv4 packet exceeds 65535"))?;
    let identification = default_ipv4_identification(sport, dport, seq, ack);

    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
    apply_ipv4_header_shaping_fields(&mut ip, identification, ipv4_header_shaping);
    ip[8] = ttl;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());
    finalize_ipv4_header_checksum(&mut ip);

    let mut tcp = vec![0u8; tcp_header_len + payload.len()];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = u8::try_from(tcp_header_len / 4)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TCP data offset"))?
        << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    tcp[20..tcp_header_len].copy_from_slice(tcp_options);
    tcp[tcp_header_len..].copy_from_slice(payload);

    let tc = tcp_checksum_ipv4(src_ip, dst_ip, &tcp);
    tcp[16..18].copy_from_slice(&tc.to_be_bytes());

    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&tcp);
    Ok(out)
}

/// Полный IPv4/TCP пакет без опций. TTL задаётся явно, payload может быть пустым.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    ttl: u8,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    build_ipv4_tcp_packet_with_shaping(
        src_ip, dst_ip, sport, dport, seq, ack, flags, window, ttl, None, payload,
    )
}

/// Полный IPv4/TCP пакет без опций и optional outer IPv4 shaping.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp_packet_with_shaping(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    ttl: u8,
    ipv4_header_shaping: Option<Ipv4HeaderShaping>,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    build_ipv4_tcp_packet_with_options_and_shaping(
        src_ip,
        dst_ip,
        sport,
        dport,
        seq,
        ack,
        flags,
        window,
        ttl,
        ipv4_header_shaping,
        &[],
        payload,
    )
}

/// Полный IPv4-пакет с TCP RST+ACK (40 байт). Без отправки в сеть.
pub fn build_ipv4_tcp_rst_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    build_ipv4_tcp_packet(
        src_ip,
        dst_ip,
        sport,
        dport,
        seq,
        ack,
        TCP_FLAG_RST | TCP_FLAG_ACK,
        4096,
        64,
        &[],
    )
    .expect("fixed-size RST packet must fit in IPv4")
}

fn expect_basic_ipv4_no_options(packet: &[u8]) -> io::Result<()> {
    if packet.len() < 40 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet too short for IPv4/TCP",
        ));
    }
    if packet[0] >> 4 != 4 || (packet[0] & 0x0f) != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only IPv4 without options is supported",
        ));
    }
    Ok(())
}

/// Патчит TTL в IPv4 заголовке и пересчитывает checksum.
pub fn patch_ipv4_ttl(packet: &mut [u8], ttl: u8) -> io::Result<()> {
    expect_basic_ipv4_no_options(packet)?;
    packet[8] = ttl;
    let mut header: [u8; 20] = packet[..20]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv4 header"))?;
    header[8] = ttl;
    finalize_ipv4_header_checksum(&mut header);
    packet[..20].copy_from_slice(&header);
    Ok(())
}

/// Патчит outer IPv4 shaping поля и пересчитывает checksum.
pub fn patch_ipv4_header_shaping(packet: &mut [u8], shaping: Ipv4HeaderShaping) -> io::Result<()> {
    expect_basic_ipv4_no_options(packet)?;
    let mut header: [u8; 20] = packet[..20]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv4 header"))?;
    apply_ipv4_header_shaping_fields(&mut header, shaping.identification, Some(shaping));
    finalize_ipv4_header_checksum(&mut header);
    packet[..20].copy_from_slice(&header);
    Ok(())
}

/// Намеренно портит TCP checksum в already-built IPv4/TCP packet.
pub fn corrupt_ipv4_tcp_checksum(packet: &mut [u8]) -> io::Result<()> {
    expect_basic_ipv4_no_options(packet)?;
    packet[36] ^= 0xff;
    packet[37] ^= 0x01;
    Ok(())
}

fn normalized_first_fragment_len(
    ip_payload_len: usize,
    first_ip_payload_len: usize,
    max_fragment_payload: usize,
) -> io::Result<usize> {
    let mut split = first_ip_payload_len
        .min(ip_payload_len.saturating_sub(1))
        .min(max_fragment_payload);
    split -= split % 8;
    if split < 24 || split >= ip_payload_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fragment split must preserve a full TCP header in first fragment",
        ));
    }
    Ok(split)
}

fn max_fragment_payload_for_mtu(mtu: usize) -> io::Result<usize> {
    let max_payload = mtu.saturating_sub(20);
    let aligned = max_payload - (max_payload % 8);
    if aligned < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path MTU is too small to preserve a full TCP header in first fragment",
        ));
    }
    Ok(aligned)
}

fn build_ipv4_fragment(
    packet: &[u8],
    start: usize,
    end: usize,
    more_fragments: bool,
    mutate_prefix: usize,
) -> io::Result<Vec<u8>> {
    let ihl = 20usize;
    let ip_payload = &packet[ihl..];
    if start >= end || end > ip_payload.len() || !start.is_multiple_of(8) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid IPv4 fragment payload range",
        ));
    }
    if more_fragments && !(end - start).is_multiple_of(8) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "non-final IPv4 fragment payload must be 8-byte aligned",
        ));
    }

    let mut header: [u8; 20] = packet[..20]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv4 header"))?;
    let total_len = u16::try_from(ihl + end - start)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "IPv4 fragment too large"))?;
    header[2..4].copy_from_slice(&total_len.to_be_bytes());
    let offset = u16::try_from(start / 8).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 fragment offset too large",
        )
    })?;
    let flags_offset = offset | if more_fragments { 0x2000 } else { 0 };
    header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    finalize_ipv4_header_checksum(&mut header);

    let mut payload = ip_payload[start..end].to_vec();
    let mutate_len = mutate_prefix.min(payload.len());
    for byte in payload.iter_mut().take(mutate_len) {
        *byte ^= 0x5a;
    }
    let mut fragment = Vec::with_capacity(ihl + payload.len());
    fragment.extend_from_slice(&header);
    fragment.extend_from_slice(&payload);
    Ok(fragment)
}

fn fragment_ipv4_packet_with_plan(
    packet: &[u8],
    first_ip_payload_len: usize,
    overlap_len: usize,
    mtu: usize,
) -> io::Result<Vec<Vec<u8>>> {
    expect_basic_ipv4_no_options(packet)?;
    let ihl = 20usize;
    let ip_payload = &packet[ihl..];
    if ip_payload.len() < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet too small to preserve full TCP header in first fragment",
        ));
    }
    let max_fragment_payload = max_fragment_payload_for_mtu(mtu)?;
    let split = normalized_first_fragment_len(
        ip_payload.len(),
        first_ip_payload_len,
        max_fragment_payload,
    )?;
    let mut overlap = overlap_len.min(split.saturating_sub(24));
    overlap -= overlap % 8;
    if overlap_len > 0 && overlap < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fragment overlap must preserve TCP header and at least 8 aligned bytes",
        ));
    }

    let mut fragments = Vec::new();
    fragments.push(build_ipv4_fragment(packet, 0, split, true, 0)?);
    let mut cursor = split - overlap;
    let mut mutate_prefix = overlap;
    while cursor < ip_payload.len() {
        let remaining = ip_payload.len() - cursor;
        let chunk_len = remaining.min(max_fragment_payload);
        let end = cursor + chunk_len;
        let more = end < ip_payload.len();
        fragments.push(build_ipv4_fragment(
            packet,
            cursor,
            end,
            more,
            mutate_prefix,
        )?);
        mutate_prefix = 0;
        cursor = end;
    }
    Ok(fragments)
}

/// Делит IPv4 packet на фрагменты с заданным первым IP payload и гарантирует,
/// что ни один фрагмент не превышает `mtu`.
pub fn fragment_ipv4_packet_to_mtu_with_first_payload(
    packet: &[u8],
    first_ip_payload_len: usize,
    mtu: usize,
) -> io::Result<Vec<Vec<u8>>> {
    fragment_ipv4_packet_with_plan(packet, first_ip_payload_len, 0, mtu)
}

/// Делит oversized IPv4 packet по `mtu`. Packet, уже помещающийся в MTU,
/// возвращается без изменений как единственный элемент.
pub fn fragment_ipv4_packet_to_mtu(packet: &[u8], mtu: usize) -> io::Result<Vec<Vec<u8>>> {
    expect_basic_ipv4_no_options(packet)?;
    if packet.len() <= mtu {
        return Ok(vec![packet.to_vec()]);
    }
    let max_payload = max_fragment_payload_for_mtu(mtu)?;
    fragment_ipv4_packet_with_plan(packet, max_payload, 0, mtu)
}

/// Делит IPv4 пакет на два фрагмента.
///
/// `first_ip_payload_len` задаётся в байтах IP payload (TCP header + data) и
/// будет автоматически выровнен вниз по 8 байтам согласно IPv4 fragment offset.
pub fn fragment_ipv4_packet(
    packet: &[u8],
    first_ip_payload_len: usize,
) -> io::Result<Vec<Vec<u8>>> {
    fragment_ipv4_packet_to_mtu_with_first_payload(packet, first_ip_payload_len, u16::MAX as usize)
}

/// Делит IPv4 пакет на фрагменты с конфликтующим overlap, каждый не больше MTU.
///
/// Первый фрагмент заканчивается на `first_ip_payload_len`, а второй начинается
/// раньше на `overlap_len` байт (с выравниванием по 8 байт для fragment offset).
/// Overlap prefix второго фрагмента намеренно мутируется, чтобы reassembly path
/// столкнулся с конфликтующими данными на одном и том же диапазоне смещений.
pub fn fragment_ipv4_packet_with_overlap_to_mtu(
    packet: &[u8],
    first_ip_payload_len: usize,
    overlap_len: usize,
    mtu: usize,
) -> io::Result<Vec<Vec<u8>>> {
    fragment_ipv4_packet_with_plan(packet, first_ip_payload_len, overlap_len, mtu)
}

/// Backward-compatible two-fragment overlap helper without an MTU cap.
pub fn fragment_ipv4_packet_with_overlap(
    packet: &[u8],
    first_ip_payload_len: usize,
    overlap_len: usize,
) -> io::Result<Vec<Vec<u8>>> {
    fragment_ipv4_packet_with_overlap_to_mtu(
        packet,
        first_ip_payload_len,
        overlap_len,
        u16::MAX as usize,
    )
}

/// Отправка полного IPv4-пакета (включая заголовок). **Linux**, `feature = "raw-socket"`, обычно **root** / `CAP_NET_RAW`.
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
pub fn linux_send_raw_ipv4_best_effort(packet: &[u8], dst: Ipv4Addr) -> io::Result<usize> {
    use std::mem;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if let Err(error) = crate::socket_mark::apply_configured_direct_socket_mark(fd) {
            libc::close(fd);
            return Err(error);
        }
        let on: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &on as *const _ as *const libc::c_void,
            mem::size_of_val(&on) as libc::socklen_t,
        ) < 0
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let mut addr: libc::sockaddr_in = mem::zeroed();
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_addr.s_addr = u32::from_be_bytes(dst.octets());
        let n = libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(fd);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

/// Отправка полного IPv4-пакета с предварительным патчем TTL.
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
pub fn linux_send_raw_ipv4_with_ttl_best_effort(
    packet: &[u8],
    dst: Ipv4Addr,
    ttl: u8,
) -> io::Result<usize> {
    let mut patched = packet.to_vec();
    patch_ipv4_ttl(&mut patched, ttl)?;
    linux_send_raw_ipv4_best_effort(&patched, dst)
}

/// Заглушка на не-Linux или без feature `raw-socket`.
#[cfg(not(all(target_os = "linux", feature = "raw-socket")))]
pub fn linux_send_raw_ipv4_best_effort(_packet: &[u8], _dst: Ipv4Addr) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "linux_send_raw_ipv4_best_effort: use Linux and --features raw-socket (CAP_NET_RAW)",
    ))
}

/// Заглушка на не-Linux или без feature `raw-socket`.
#[cfg(not(all(target_os = "linux", feature = "raw-socket")))]
pub fn linux_send_raw_ipv4_with_ttl_best_effort(
    _packet: &[u8],
    _dst: Ipv4Addr,
    _ttl: u8,
) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "linux_send_raw_ipv4_with_ttl_best_effort: use Linux and --features raw-socket (CAP_NET_RAW)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_packet_shape() {
        let p = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            b"abc",
        )
        .unwrap();
        assert_eq!(p.len(), 43);
        assert_eq!(p[8], 32);
        assert_eq!(p[33], TCP_FLAG_ACK | TCP_FLAG_PSH);
    }

    #[test]
    fn data_packet_shape_with_tcp_options() {
        let tcp_options = [1u8, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
        let p = build_ipv4_tcp_packet_with_options(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            &tcp_options,
            b"abc",
        )
        .unwrap();
        assert_eq!(p.len(), 55);
        assert_eq!(p[8], 32);
        assert_eq!(p[32] >> 4, 8);
        assert_eq!(&p[40..52], &tcp_options);
    }

    #[test]
    fn rst_packet_shape() {
        let p = build_ipv4_tcp_rst_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            443,
            1000,
            2000,
        );
        assert_eq!(p.len(), 40);
        assert_eq!(p[0], 0x45);
        assert_eq!(p[33], TCP_FLAG_RST | TCP_FLAG_ACK);
    }

    #[test]
    fn patch_ttl_recomputes_header_checksum() {
        let mut p = build_ipv4_tcp_rst_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            443,
            1000,
            2000,
        );
        let before = [p[10], p[11]];
        patch_ipv4_ttl(&mut p, 3).unwrap();
        assert_eq!(p[8], 3);
        assert_ne!([p[10], p[11]], before);
    }

    #[test]
    fn patch_ipv4_header_shaping_updates_outer_header_fields() {
        let mut p = build_ipv4_tcp_rst_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            443,
            1000,
            2000,
        );
        patch_ipv4_header_shaping(
            &mut p,
            Ipv4HeaderShaping {
                tos: 0x10,
                identification: 0x1234,
                dont_fragment: true,
            },
        )
        .unwrap();
        assert_eq!(p[1], 0x10);
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([p[6], p[7]]) & 0x4000, 0x4000);
    }

    #[test]
    fn build_with_shaping_matches_build_then_patch() {
        let shaping = Ipv4HeaderShaping {
            tos: 0x10,
            identification: 0x1234,
            dont_fragment: true,
        };
        let built = build_ipv4_tcp_packet_with_shaping(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            Some(shaping),
            b"abc",
        )
        .unwrap();
        let mut patched = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            b"abc",
        )
        .unwrap();
        patch_ipv4_header_shaping(&mut patched, shaping).unwrap();
        assert_eq!(built, patched);
    }

    #[test]
    fn fragment_packet_into_two_ipv4_fragments() {
        let p = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            &[0u8; 24],
        )
        .unwrap();
        let frags = fragment_ipv4_packet(&p, 24).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(
            u16::from_be_bytes([frags[0][6], frags[0][7]]) & 0x2000,
            0x2000
        );
        assert_eq!(u16::from_be_bytes([frags[1][6], frags[1][7]]) & 0x2000, 0);
        assert_eq!(u16::from_be_bytes([frags[1][6], frags[1][7]]) & 0x1fff, 3);
    }

    #[test]
    fn fragment_rejects_split_before_full_tcp_header() {
        let p = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            &[0u8; 8],
        )
        .unwrap();
        let err = fragment_ipv4_packet(&p, 21).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn fragment_packet_with_overlap_mutates_second_fragment_prefix() {
        let payload: Vec<u8> = (0u8..32).collect();
        let p = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            &payload,
        )
        .unwrap();
        let frags = fragment_ipv4_packet_with_overlap(&p, 32, 8).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(u16::from_be_bytes([frags[1][6], frags[1][7]]) & 0x1fff, 3);
        let original_ip_payload = &p[20..];
        let second_payload = &frags[1][20..];
        assert_ne!(&second_payload[..8], &original_ip_payload[24..32]);
        assert_eq!(&second_payload[8..], &original_ip_payload[32..]);
    }

    #[test]
    fn mtu_fragment_plan_never_emits_oversized_packets() {
        let p = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            &[0x16; 2000],
        )
        .unwrap();
        let frags = fragment_ipv4_packet_to_mtu(&p, 576).unwrap();
        assert!(frags.len() >= 4);
        for (index, frag) in frags.iter().enumerate() {
            assert!(frag.len() <= 576, "fragment {index} exceeds path MTU");
            assert_eq!(u16::from_be_bytes([frag[2], frag[3]]) as usize, frag.len());
            let header: [u8; 20] = frag[..20].try_into().unwrap();
            assert_eq!(ipv4_header_checksum(&header), 0);
            if index + 1 < frags.len() {
                assert_ne!(u16::from_be_bytes([frag[6], frag[7]]) & 0x2000, 0);
                assert!((frag.len() - 20).is_multiple_of(8));
            }
        }
        let last = frags.last().unwrap();
        assert_eq!(u16::from_be_bytes([last[6], last[7]]) & 0x2000, 0);
    }

    #[test]
    fn mtu_overlap_plan_preserves_conflict_across_multiple_fragments() {
        let p = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 20),
            12345,
            443,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            8192,
            32,
            &[0x16; 2000],
        )
        .unwrap();
        let frags = fragment_ipv4_packet_with_overlap_to_mtu(&p, 32, 8, 576).unwrap();
        assert!(frags.len() >= 4);
        assert!(frags.iter().all(|frag| frag.len() <= 576));
        assert_eq!(u16::from_be_bytes([frags[1][6], frags[1][7]]) & 0x1fff, 3);
        assert_ne!(&frags[1][20..28], &p[44..52]);
        assert_eq!(&frags[1][28..], &p[52..20 + 24 + (frags[1].len() - 20)]);
    }

    #[test]
    fn corrupt_tcp_checksum_mutates_header() {
        let mut p = build_ipv4_tcp_rst_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            443,
            1000,
            2000,
        );
        let before = [p[36], p[37]];
        corrupt_ipv4_tcp_checksum(&mut p).unwrap();
        assert_ne!([p[36], p[37]], before);
    }

    /// На не-Linux или без `raw-socket` отправка — заглушка (интеграция с ядром только на Linux+feature).
    #[test]
    fn linux_raw_send_stub_unsupported() {
        let p = build_ipv4_tcp_rst_packet(
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(198, 51, 100, 2),
            40000,
            443,
            1,
            2,
        );
        let r = linux_send_raw_ipv4_best_effort(&p, Ipv4Addr::new(198, 51, 100, 2));
        #[cfg(not(all(target_os = "linux", feature = "raw-socket")))]
        {
            assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
        #[cfg(all(target_os = "linux", feature = "raw-socket"))]
        {
            if let Err(e) = &r {
                assert_ne!(
                    e.kind(),
                    io::ErrorKind::Unsupported,
                    "на Linux+raw-socket ожидается реальная попытка send, не заглушка"
                );
            }
        }
    }
}
