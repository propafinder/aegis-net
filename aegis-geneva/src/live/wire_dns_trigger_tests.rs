use super::*;
use crate::live::program::Program;
use rand::{rngs::StdRng, SeedableRng};

fn rng() -> StdRng {
    StdRng::seed_from_u64(58)
}

fn tcp53(payload: &[u8], flags: u8, direction: Direction) -> Vec<u8> {
    let mut frame = vec![0; 54 + payload.len()];
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    put16(&mut frame, 16, (40 + payload.len()) as u16);
    frame[22] = 64;
    frame[23] = 6;
    let (src, dst, sport, dport) = if direction == Direction::Outbound {
        ([192, 0, 2, 2], [192, 0, 2, 3], 1234, 53)
    } else {
        ([192, 0, 2, 3], [192, 0, 2, 2], 53, 1234)
    };
    frame[26..30].copy_from_slice(&src);
    frame[30..34].copy_from_slice(&dst);
    put16(&mut frame, 34, sport);
    put16(&mut frame, 36, dport);
    frame[46] = 0x50;
    frame[47] = flags;
    put16(&mut frame, 48, 4096);
    frame[54..].copy_from_slice(payload);
    let ip_checksum = checksum(&frame[14..34]);
    put16(&mut frame, 24, ip_checksum);
    let mut pseudo = frame[26..34].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[34..]);
    let tcp_checksum = checksum(&pseudo);
    put16(&mut frame, 50, tcp_checksum);
    frame
}

fn dns_message() -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    dns.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
    dns
}

fn framed(dns: &[u8]) -> Vec<u8> {
    let mut payload = (dns.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(dns);
    payload
}

#[test]
fn tcp53_lifecycle_without_dns_is_a_trigger_nonmatch() {
    let mut program = Program::parse("[DNS:id:4660]-drop-| \\/ [DNS:id:4660]-drop-|").unwrap();
    for direction in [Direction::Outbound, Direction::Inbound] {
        for flags in [0x02, 0x12, 0x10, 0x11, 0x04] {
            let frame = tcp53(&[], flags, direction);
            assert_eq!(checksum(&frame[14..34]), 0);
            assert_eq!(
                program.execute(&frame, direction, &mut rng()),
                Ok(vec![frame]),
                "direction={direction:?}, flags={flags:#x}"
            );
        }
    }
}

#[test]
fn tcp53_partial_coalesced_and_non_dns_bytes_are_trigger_nonmatches() {
    let message = framed(&dns_message());
    let mut coalesced = message.clone();
    coalesced.extend_from_slice(&message);
    let mut short = message.clone();
    short.pop();
    let mut trailing = message.clone();
    trailing.push(0);
    let mut program = Program::parse("[DNS:id:4660]-drop-|").unwrap();
    for payload in [
        vec![0x12],
        vec![0, 0],
        vec![0, 2, 0x12, 0x34],
        b"ordinary encrypted TCP bytes".to_vec(),
        vec![255; 20],
        short,
        trailing,
        coalesced,
    ] {
        let frame = tcp53(&payload, 0x18, Direction::Outbound);
        assert_eq!(
            program.execute(&frame, Direction::Outbound, &mut rng()),
            Ok(vec![frame])
        );
    }
}

#[test]
fn tcp53_nonmatches_preserve_gas_for_a_complete_dns_message() {
    let mut program = Program::parse("[DNS:id:4660:1]-drop-|").unwrap();
    for payload in [&[][..], &b"not a complete DNS message"[..]] {
        let frame = tcp53(payload, 0x10, Direction::Outbound);
        assert_eq!(
            program.execute(&frame, Direction::Outbound, &mut rng()),
            Ok(vec![frame])
        );
    }
    let frame = tcp53(&framed(&dns_message()), 0x18, Direction::Outbound);
    assert_eq!(
        program.execute(&frame, Direction::Outbound, &mut rng()),
        Ok(vec![])
    );
    assert_eq!(
        program.execute(&frame, Direction::Outbound, &mut rng()),
        Ok(vec![frame])
    );
}

#[test]
fn tcp53_complete_dns_trigger_still_tampers_the_actual_wire_message() {
    let frame = tcp53(&framed(&dns_message()), 0x18, Direction::Outbound);
    let mut program =
        Program::parse("[DNSQR:qname:example*]-tamper{DNS:id:replace:7}()-|").unwrap();
    let output = program
        .execute(&frame, Direction::Outbound, &mut rng())
        .unwrap();
    assert_eq!(output.len(), 1);
    assert_eq!(u16_at(&output[0], 54) as usize, output[0].len() - 56);
    assert_eq!(u16_at(&output[0], 56), 7);
    assert_eq!(&output[0][58..], &frame[58..]);
    assert_eq!(checksum(&output[0][14..34]), 0);
}

#[test]
fn tcp53_dns_tamper_failure_still_refuses_the_whole_batch() {
    let frame = tcp53(&[], 0x02, Direction::Outbound);
    let mut program =
        Program::parse("[IP:ttl:64]--| [TCP:dport:53]-tamper{DNS:id:replace:7}()-|").unwrap();
    assert_eq!(
        program.execute(&frame, Direction::Outbound, &mut rng()),
        Err(WireError::Frame)
    );
}

#[test]
fn tcp53_malformed_frames_remain_bounded_refusals() {
    let frame = tcp53(&[], 0x02, Direction::Outbound);
    let mut program = Program::parse("[DNS:id:4660]-drop-|").unwrap();
    for length in 0..frame.len() {
        assert_eq!(
            program.execute(&frame[..length], Direction::Outbound, &mut rng()),
            Err(WireError::Frame)
        );
    }
    for (offset, value) in [(14, 0x44), (46, 0x40), (46, 0xf0)] {
        let mut malformed = frame.clone();
        malformed[offset] = value;
        assert_eq!(
            program.execute(&malformed, Direction::Outbound, &mut rng()),
            Err(WireError::Frame)
        );
    }
    assert_eq!(
        program.execute(&vec![0; MAX_FRAME + 1], Direction::Outbound, &mut rng()),
        Err(WireError::Frame)
    );
}

#[test]
fn tcp53_dns_pointer_cycles_and_excessive_chains_refuse_atomically() {
    let mut cyclic = dns_message();
    cyclic[12..14].copy_from_slice(&[0xc0, 12]);
    let mut chain = vec![0; 12];
    put16(&mut chain, 4, 1);
    for index in 0..129 {
        chain.extend_from_slice(&(0xc000u16 | (14 + index * 2) as u16).to_be_bytes());
    }
    chain.push(0);
    for (dns, expected) in [(cyclic, WireError::Frame), (chain, WireError::Budget)] {
        let frame = tcp53(&framed(&dns), 0x18, Direction::Outbound);
        let mut program = Program::parse("[IP:ttl:64]--| [DNSQR:qname:example*]-drop-|").unwrap();
        assert_eq!(
            program.execute(&frame, Direction::Outbound, &mut rng()),
            Err(expected)
        );
    }
}
