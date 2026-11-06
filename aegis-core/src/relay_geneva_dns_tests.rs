use super::*;
use rand::{rngs::StdRng, SeedableRng};

fn rng() -> StdRng {
    StdRng::seed_from_u64(58)
}

fn pin() -> RelayFlowPin {
    RelayFlowPin {
        local: Ipv4Addr::new(192, 0, 2, 2),
        relay: Ipv4Addr::new(192, 0, 2, 3),
        local_port: 1234,
        relay_port: 53,
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes.chunks(2).fold(0u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))
    });
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn frame(payload: &[u8], flags: u8, direction: Direction) -> Vec<u8> {
    let mut frame = vec![0; 54 + payload.len()];
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    let (src, dst, sport, dport) = if direction == Direction::Outbound {
        (pin().local, pin().relay, pin().local_port, pin().relay_port)
    } else {
        (pin().relay, pin().local, pin().relay_port, pin().local_port)
    };
    frame[26..30].copy_from_slice(&src.octets());
    frame[30..34].copy_from_slice(&dst.octets());
    frame[34..36].copy_from_slice(&sport.to_be_bytes());
    frame[36..38].copy_from_slice(&dport.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&4096u16.to_be_bytes());
    frame[54..].copy_from_slice(payload);
    let ip_checksum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    let mut pseudo = frame[26..34].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[34..]);
    let tcp_checksum = checksum(&pseudo);
    frame[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());
    frame
}

fn dns_payload() -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    dns.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
    let mut payload = (dns.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(&dns);
    payload
}

#[test]
fn tcp53_syn_and_reply_preserve_same_session_for_later_dns() {
    let mut program =
        RelayGenevaProgram::new("[DNS:id:4660:1]-drop-| \\/ [DNS:id:4660]-drop-|", pin()).unwrap();
    for (direction, flags) in [(Direction::Outbound, 0x02), (Direction::Inbound, 0x12)] {
        let syn = frame(&[], flags, direction);
        assert_eq!(checksum(&syn[14..34]), 0);
        assert_eq!(
            program
                .execute(&syn, direction, &mut rng())
                .unwrap()
                .frames(),
            &[syn]
        );
        assert!(!program.is_closed());
    }
    let query = frame(&dns_payload(), 0x18, Direction::Outbound);
    assert!(program
        .execute(&query, Direction::Outbound, &mut rng())
        .unwrap()
        .frames()
        .is_empty());
    assert_eq!(
        program
            .execute(&query, Direction::Outbound, &mut rng())
            .unwrap()
            .frames(),
        &[query]
    );
    assert!(!program.is_closed());
}

#[test]
fn tcp53_non_dns_bytes_do_not_poison_the_relay_session() {
    let mut program = RelayGenevaProgram::new("[DNS:id:4660]-drop-|", pin()).unwrap();
    for payload in [
        &b"ordinary encrypted TCP bytes"[..],
        &[0x12][..],
        &[0, 0][..],
    ] {
        let input = frame(payload, 0x18, Direction::Outbound);
        assert_eq!(
            program
                .execute(&input, Direction::Outbound, &mut rng())
                .unwrap()
                .frames(),
            &[input]
        );
        assert!(!program.is_closed());
    }
}

#[test]
fn tcp53_trusted_dns_tamper_error_keeps_whole_batch_terminal() {
    let mut program = RelayGenevaProgram::new(
        "[IP:ttl:64]--| [TCP:dport:53]-tamper{DNS:id:replace:7}()-|",
        pin(),
    )
    .unwrap();
    let syn = frame(&[], 0x02, Direction::Outbound);
    assert_eq!(
        program
            .execute(&syn, Direction::Outbound, &mut rng())
            .unwrap_err(),
        RelayGenevaError::Program
    );
    assert!(program.is_closed());
    assert_eq!(
        program
            .execute(&syn, Direction::Outbound, &mut rng())
            .unwrap_err(),
        RelayGenevaError::Closed
    );
}

#[test]
fn tcp53_malformed_admitted_dns_still_closes_without_partial_output() {
    let mut payload = dns_payload();
    payload[14..16].copy_from_slice(&[0xc0, 12]);
    let malformed = frame(&payload, 0x18, Direction::Outbound);
    let mut program =
        RelayGenevaProgram::new("[IP:ttl:64]--| [DNSQR:qname:example*]-drop-|", pin()).unwrap();
    assert_eq!(
        program
            .execute(&malformed, Direction::Outbound, &mut rng())
            .unwrap_err(),
        RelayGenevaError::Program
    );
    assert!(program.is_closed());
}

#[test]
fn tcp53_generated_tuple_escape_keeps_whole_batch_terminal() {
    let mut program = RelayGenevaProgram::new(
        "[DNS:id:4660]-duplicate(,tamper{TCP:dport:replace:80}())-|",
        pin(),
    )
    .unwrap();
    let query = frame(&dns_payload(), 0x18, Direction::Outbound);
    assert_eq!(
        program
            .execute(&query, Direction::Outbound, &mut rng())
            .unwrap_err(),
        RelayGenevaError::Ownership
    );
    assert!(program.is_closed());
    assert_eq!(
        program
            .execute(&query, Direction::Outbound, &mut rng())
            .unwrap_err(),
        RelayGenevaError::Closed
    );
}
