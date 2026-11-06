//! Canonical public manager intent bytes for an authenticated process channel.
//! These bytes are consistency data, never enrollment or a packet/Store grant.
use crate::policy::FullWide;
use std::net::IpAddr;

const DOMAIN: &[u8] = b"AEGIS-NE-PUBLIC-INTENT\0\x01";
const SCHEMA: &str = "aegis-ne-profile-v1";
const MAX_WIRE_BYTES: usize = 512;
const MAX_GENERATION_BYTES: usize = 128;
const MAX_RELAY_BYTES: usize = 39;
const MAX_DNS_BYTES: usize = 79;
const MAX_MTU_BYTES: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DecodedPublicIntent {
    pub(crate) generation: String,
    pub(crate) policy: FullWide,
}

fn valid_generation(generation: &str) -> bool {
    !generation.is_empty()
        && generation.len() <= MAX_GENERATION_BYTES
        && !generation.chars().any(char::is_control)
}

pub(crate) fn encode_public_intent(
    generation: &str,
    policy: &FullWide,
) -> Result<Vec<u8>, &'static str> {
    if !valid_generation(generation) {
        return Err("intent_wire_generation");
    }
    let relay = policy.relay().to_string();
    let dns = policy
        .dns()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mtu = policy.mtu().to_string();
    let fields = [
        SCHEMA,
        generation,
        relay.as_str(),
        dns.as_str(),
        mtu.as_str(),
    ];
    for (field, max) in fields.iter().zip([
        SCHEMA.len(),
        MAX_GENERATION_BYTES,
        MAX_RELAY_BYTES,
        MAX_DNS_BYTES,
        MAX_MTU_BYTES,
    ]) {
        if field.len() > max || field.is_empty() {
            return Err("intent_wire_field_bound");
        }
    }
    let mut wire = Vec::with_capacity(MAX_WIRE_BYTES);
    wire.extend_from_slice(DOMAIN);
    for field in fields {
        let bytes = field.as_bytes();
        let length = u16::try_from(bytes.len()).map_err(|_| "intent_wire_field_bound")?;
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(bytes);
    }
    if wire.len() > MAX_WIRE_BYTES {
        return Err("intent_wire_bound");
    }
    Ok(wire)
}

pub(crate) fn decode_public_intent(wire: &[u8]) -> Result<DecodedPublicIntent, &'static str> {
    if wire.len() > MAX_WIRE_BYTES || !wire.starts_with(DOMAIN) {
        return Err("intent_wire_domain_or_bound");
    }
    let mut rest = &wire[DOMAIN.len()..];
    let mut fields = Vec::with_capacity(5);
    for max in [
        SCHEMA.len(),
        MAX_GENERATION_BYTES,
        MAX_RELAY_BYTES,
        MAX_DNS_BYTES,
        MAX_MTU_BYTES,
    ] {
        let length = rest.get(..2).ok_or("intent_wire_truncated")?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        rest = &rest[2..];
        if length == 0 || length > max {
            return Err("intent_wire_field_bound");
        }
        let bytes = rest.get(..length).ok_or("intent_wire_truncated")?;
        let text = std::str::from_utf8(bytes).map_err(|_| "intent_wire_utf8")?;
        fields.push(text);
        rest = &rest[length..];
    }
    if !rest.is_empty() || fields[0] != SCHEMA || !valid_generation(fields[1]) {
        return Err("intent_wire_shape");
    }
    let relay: IpAddr = fields[2].parse().map_err(|_| "intent_wire_relay")?;
    let dns = fields[3]
        .split(',')
        .map(|part| part.parse().map_err(|_| "intent_wire_dns"))
        .collect::<Result<Vec<IpAddr>, _>>()?;
    let mtu = fields[4].parse().map_err(|_| "intent_wire_mtu")?;
    let policy = FullWide::new(relay, dns, mtu)?;
    let canonical = encode_public_intent(fields[1], &policy)?;
    if canonical != wire {
        return Err("intent_wire_noncanonical");
    }
    Ok(DecodedPublicIntent {
        generation: fields[1].to_owned(),
        policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FullWide {
        FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec![
                "2001:db8::53".parse().unwrap(),
                "198.51.100.53".parse().unwrap(),
            ],
            1280,
        )
        .unwrap()
    }
    fn field_wire(fields: &[&str; 5]) -> Vec<u8> {
        let mut wire = DOMAIN.to_vec();
        for field in fields {
            wire.extend_from_slice(&(field.len() as u16).to_be_bytes());
            wire.extend_from_slice(field.as_bytes());
        }
        wire
    }

    #[test]
    fn public_intent_exact_five_field_roundtrip_and_stable_vector() {
        let p = policy();
        let wire = encode_public_intent("gen|1", &p).unwrap();
        assert_eq!(
            wire,
            field_wire(&[
                SCHEMA,
                "gen|1",
                "192.0.2.1",
                "2001:db8::53,198.51.100.53",
                "1280"
            ])
        );
        assert_eq!(
            decode_public_intent(&wire).unwrap(),
            DecodedPublicIntent {
                generation: "gen|1".into(),
                policy: p
            }
        );
    }

    #[test]
    fn public_intent_rejects_shape_bounds_and_ambiguous_values() {
        let good = encode_public_intent("gen-1", &policy()).unwrap();
        for bad in [
            Vec::new(),
            good[..good.len() - 1].to_vec(),
            [good.as_slice(), b"x"].concat(),
            [b"BAD", good.as_slice()].concat(),
            field_wire(&[SCHEMA, "gen-1", "192.0.2.1", "2001:0db8::53", "1280"]),
            field_wire(&[SCHEMA, "gen-1", "192.0.2.1", "2001:db8::53", "01280"]),
            field_wire(&[SCHEMA, "gen-1", "192.0.2.1", "2001:db8::53", "1279"]),
            field_wire(&[SCHEMA, "gen-1", "127.0.0.1", "2001:db8::53", "1280"]),
            field_wire(&[SCHEMA, "gen\n1", "192.0.2.1", "2001:db8::53", "1280"]),
            field_wire(&[
                SCHEMA,
                &"a".repeat(129),
                "192.0.2.1",
                "2001:db8::53",
                "1280",
            ]),
        ] {
            assert!(decode_public_intent(&bad).is_err());
        }
        let mut bad_utf8 = field_wire(&[SCHEMA, "gen-1", "192.0.2.1", "2001:db8::53", "1280"]);
        bad_utf8[DOMAIN.len() + 2] = 0xff;
        assert!(decode_public_intent(&bad_utf8).is_err());
        assert!(encode_public_intent("", &policy()).is_err());
        assert!(encode_public_intent(&"a".repeat(129), &policy()).is_err());
        assert!(decode_public_intent(&vec![0; MAX_WIRE_BYTES + 1]).is_err());
    }
}
