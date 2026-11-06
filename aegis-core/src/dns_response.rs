//! Structural DNS relay response validation, without interpreting opaque RDATA.

const HEADER_LEN: usize = 12;
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;
const MAX_NAME_LEN: usize = 255;
const MAX_POINTER_HOPS: usize = 128;

/// Accept a complete response only for the request's transaction and question.
///
/// TC, RCODE, EDNS and DNSSEC flags/data are preserved by the callers. A TC
/// response may contain no answers or an incomplete RRset, but each declared
/// record must be complete. This permits UDP clients to retry over TCP without
/// treating malformed records as valid truncation. Unknown RDATA stays opaque.
pub fn is_valid_relay_response(request: &[u8], response: &[u8]) -> bool {
    let Some(request) = Message::parse(request) else {
        return false;
    };
    let Some(response) = Message::parse(response) else {
        return false;
    };
    request.flags & 0x8000 == 0
        && response.flags & 0x8000 != 0
        && request.id == response.id
        && request.flags & 0x7800 == response.flags & 0x7800
        && request.question == response.question
}

#[derive(PartialEq, Eq)]
struct Question {
    // Length prefixes retain label boundaries; only ASCII case is folded.
    name: Vec<u8>,
    kind: u16,
    class: u16,
}

struct Message {
    id: [u8; 2],
    flags: u16,
    question: Question,
}

impl Message {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if !(HEADER_LEN..=MAX_MESSAGE_LEN).contains(&bytes.len())
            || u16_at(bytes, 4)? != 1
            // The reserved Z bit is distinct from the valid AD and CD bits.
            || bytes[3] & 0x40 != 0
        {
            return None;
        }
        let mut names = Names {
            bytes,
            visited: vec![0; bytes.len()],
            epoch: 0,
        };
        let (name, mut cursor) = names.decode(HEADER_LEN)?;
        let question = Question {
            name,
            kind: u16_at(bytes, cursor)?,
            class: u16_at(bytes, cursor.checked_add(2)?)?,
        };
        cursor = cursor.checked_add(4)?;
        let records = usize::from(u16_at(bytes, 6)?)
            + usize::from(u16_at(bytes, 8)?)
            + usize::from(u16_at(bytes, 10)?);
        // Even a root owner with empty RDATA needs eleven octets. This also
        // bounds the loop before following any record's compression pointers.
        if records > bytes.len().checked_sub(cursor)? / 11 {
            return None;
        }
        for _ in 0..records {
            let (_, fixed) = names.decode(cursor)?;
            let data_len = usize::from(u16_at(bytes, fixed.checked_add(8)?)?);
            let data = fixed.checked_add(10)?;
            cursor = data.checked_add(data_len)?;
            bytes.get(data..cursor)?;
        }
        if cursor != bytes.len() {
            return None;
        }
        Some(Self {
            id: [bytes[0], bytes[1]],
            flags: u16_at(bytes, 2)?,
            question,
        })
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

struct Names<'a> {
    bytes: &'a [u8],
    // Reuse one bounded scratch array across names, without clearing it or
    // allocating an array per record. An epoch detects label/pointer cycles.
    visited: Vec<u16>,
    epoch: u16,
}

impl Names<'_> {
    fn decode(&mut self, start: usize) -> Option<(Vec<u8>, usize)> {
        self.epoch = self.epoch.checked_add(1)?;
        let mut cursor = start;
        let mut end = None;
        let mut name = Vec::new();
        let mut expanded_len = 1; // The final root label also occupies an octet.
        let mut pointer_hops = 0;
        loop {
            let mark = self.visited.get_mut(cursor)?;
            if *mark == self.epoch {
                return None;
            }
            *mark = self.epoch;
            let length = *self.bytes.get(cursor)?;
            match length & 0xc0 {
                0 => {
                    cursor = cursor.checked_add(1)?;
                    if length == 0 {
                        name.push(0);
                        return Some((name, end.unwrap_or(cursor)));
                    }
                    let length = usize::from(length);
                    expanded_len += length + 1;
                    if expanded_len > MAX_NAME_LEN {
                        return None;
                    }
                    let next = cursor.checked_add(length)?;
                    let label = self.bytes.get(cursor..next)?;
                    name.push(length as u8);
                    name.extend(label.iter().map(u8::to_ascii_lowercase));
                    cursor = next;
                }
                0xc0 => {
                    let next = cursor.checked_add(2)?;
                    let target = (usize::from(length & 0x3f) << 8)
                        | usize::from(*self.bytes.get(cursor.checked_add(1)?)?);
                    // RFC 1035 compression references a prior name occurrence,
                    // never the header, a forward offset or an absent byte.
                    if target < HEADER_LEN || target >= cursor {
                        return None;
                    }
                    pointer_hops += 1;
                    if pointer_hops > MAX_POINTER_HOPS {
                        return None;
                    }
                    end.get_or_insert(next);
                    cursor = target;
                }
                _ => return None, // Reserved label encodings 01 and 10.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(labels: &[&[u8]], kind: u16, class: u16) -> Vec<u8> {
        let mut packet = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in labels {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label);
        }
        packet.push(0);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&class.to_be_bytes());
        packet
    }

    fn query() -> Vec<u8> {
        question(&[b"example", b"com"], 28, 1)
    }

    fn reply(request: &[u8]) -> Vec<u8> {
        let mut response = request.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response
    }

    fn record(packet: &mut Vec<u8>, owner: &[u8], kind: u16, data: &[u8]) {
        packet.extend_from_slice(owner);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);
    }

    fn opt(packet: &mut Vec<u8>) {
        let start = packet.len();
        record(packet, &[0], 41, &[0, 10, 0, 2, 0xab, 0xcd]);
        packet[start + 3..start + 5].copy_from_slice(&1232u16.to_be_bytes());
        packet[start + 5..start + 9].copy_from_slice(&0x8000u32.to_be_bytes()); // DO.
    }

    #[test]
    fn dns_relay_response_matches_full_question_not_just_transaction() {
        let request = query();
        let response = reply(&request);
        assert!(is_valid_relay_response(&request, &response));
        for mut wrong in [
            reply(&question(&[b"different", b"com"], 28, 1)),
            reply(&question(&[b"example", b"com"], 1, 1)),
            reply(&question(&[b"example", b"com"], 28, 3)),
        ] {
            assert_eq!(&wrong[..2], &request[..2]);
            assert!(!is_valid_relay_response(&request, &wrong));
            wrong[2] |= 0x08;
            assert!(!is_valid_relay_response(&request, &wrong));
        }
    }

    #[test]
    fn dns_relay_response_validates_both_headers_and_exact_question_count() {
        let request = query();
        let response = reply(&request);
        assert!(!is_valid_relay_response(&request[..4], &response));
        for length in 0..HEADER_LEN {
            assert!(!is_valid_relay_response(&request, &response[..length]));
        }
        for (offset, value) in [(1, 0xce), (2, 0x01), (2, 0x89), (3, 0xc0), (5, 0), (5, 2)] {
            let mut wrong = response.clone();
            wrong[offset] = value;
            assert!(!is_valid_relay_response(&request, &wrong));
        }
        let mut not_query = request.clone();
        not_query[2] |= 0x80;
        assert!(!is_valid_relay_response(&not_query, &response));
        let mut missing_question = response[..HEADER_LEN].to_vec();
        assert!(!is_valid_relay_response(&request, &missing_question));
        missing_question.extend_from_slice(&[0, 0, 28, 0]); // Missing QCLASS byte.
        assert!(!is_valid_relay_response(&request, &missing_question));
    }

    #[test]
    fn dns_relay_response_preserves_label_boundaries_case_and_compression() {
        let request = query();
        let mut response = reply(&question(&[b"EXAMPLE", b"Com"], 28, 1));
        response[7] = 2;
        let first = response.len();
        record(
            &mut response,
            &[3, b'w', b'w', b'w', 0xc0, 0x0c],
            28,
            &[0; 16],
        );
        record(&mut response, &[0xc0, first as u8], 28, &[1; 16]);
        assert!(is_valid_relay_response(&request, &response));
        assert!(!is_valid_relay_response(
            &question(&[b"a.b"], 28, 1),
            &reply(&question(&[b"a", b"b"], 28, 1))
        ));
        let binary_name = question(&[&[0xff, b'A']], 28, 1);
        assert!(is_valid_relay_response(&binary_name, &reply(&binary_name)));
    }

    #[test]
    fn dns_relay_response_preserves_negative_edns_dnssec_and_unknown_rdata() {
        let mut edns_request = query();
        edns_request[11] = 1;
        opt(&mut edns_request);
        assert!(is_valid_relay_response(
            &edns_request,
            &reply(&edns_request)
        ));
        let request = query();
        let mut response = reply(&request);
        assert!(is_valid_relay_response(&request, &response)); // NODATA.
        response[3] = 0xb3; // NXDOMAIN with AD and CD; no reserved Z bit.
        response[9] = 1;
        let mut soa = vec![0xc0, 0x0c, 0xc0, 0x0c];
        soa.extend_from_slice(&[0; 20]);
        record(&mut response, &[0xc0, 0x0c], 6, &soa);
        response[11] = 3;
        opt(&mut response);
        let mut signature = vec![0; 18];
        signature[..4].copy_from_slice(&[0, 28, 8, 2]);
        signature.extend_from_slice(&[0xc0, 0x0c]);
        signature.extend_from_slice(&[0; 64]);
        record(&mut response, &[0xc0, 0x0c], 46, &signature); // Opaque RRSIG.
        record(&mut response, &[0xc0, 0x0c], 65000, &[0x80, 0xc0, 0x00]);
        let before = response.clone();
        assert!(is_valid_relay_response(&request, &response));
        assert_eq!(response, before); // No RDATA or flags are rewritten.
    }

    #[test]
    fn dns_relay_response_tc_allows_complete_partial_rrsets_not_cut_records() {
        let request = query();
        let mut truncated = reply(&request);
        truncated[2] |= 0x02;
        assert!(is_valid_relay_response(&request, &truncated)); // TCP retry signal.
        truncated[7] = 1;
        record(&mut truncated, &[0xc0, 0x0c], 28, &[0; 16]);
        assert!(is_valid_relay_response(&request, &truncated));
        assert_ne!(truncated[2] & 0x02, 0);
        let question_end = request.len();
        for length in question_end..truncated.len() {
            assert!(!is_valid_relay_response(&request, &truncated[..length]));
        }
        truncated[7] = 2;
        assert!(!is_valid_relay_response(&request, &truncated));
        let mut tcp_reply = truncated;
        tcp_reply[2] &= !0x02;
        record(&mut tcp_reply, &[0xc0, 0x0c], 28, &[1; 16]);
        assert!(is_valid_relay_response(&request, &tcp_reply));
    }

    #[test]
    fn dns_relay_response_refuses_every_record_section_overrun_and_trailing_data() {
        let request = query();
        for count_offset in [7, 9, 11] {
            let mut response = reply(&request);
            response[count_offset] = 1;
            record(&mut response, &[0xc0, 0x0c], 65000, &[1, 2]);
            assert!(is_valid_relay_response(&request, &response));
            let rdlength = request.len() + 10;
            response[rdlength + 1] = 3;
            assert!(!is_valid_relay_response(&request, &response));
            let mut bad_owner = reply(&request);
            bad_owner[count_offset] = 1;
            record(&mut bad_owner, &[0x40, 0], 65000, &[1, 2]);
            assert!(!is_valid_relay_response(&request, &bad_owner));
        }
        let mut trailing = reply(&request);
        trailing.push(0);
        assert!(!is_valid_relay_response(&request, &trailing));
        let mut bad_request = request.clone();
        bad_request[11] = 1;
        assert!(!is_valid_relay_response(&bad_request, &reply(&request)));
    }

    #[test]
    fn dns_relay_response_refuses_invalid_labels_and_compression_cycles() {
        let request = query();
        let mut cut_pointer = reply(&request)[..HEADER_LEN].to_vec();
        cut_pointer.push(0xc0);
        assert!(!is_valid_relay_response(&request, &cut_pointer));
        for bad_name in [
            vec![0xc0, 0x0c],          // Self pointer.
            vec![0xc0, 0xff],          // Forward/out-of-packet pointer.
            vec![0xc0, 0x00],          // Header pointer.
            vec![0x40, 0],             // Reserved label encoding.
            vec![0x80, 0],             // Reserved label encoding.
            vec![63, b'a', 0],         // Cut label.
            vec![1, b'a', 0xc0, 0x0c], // Backward pointer/label cycle.
        ] {
            let mut malformed = reply(&request)[..HEADER_LEN].to_vec();
            malformed.extend_from_slice(&bad_name);
            malformed.extend_from_slice(&[0, 28, 0, 1]);
            assert!(!is_valid_relay_response(&request, &malformed));
        }
    }

    #[test]
    fn dns_relay_response_bounds_expanded_names_pointer_hops_and_packet_size() {
        let label = [b'a'; 63];
        let max_name = question(&[&label, &label, &label, &[b'a'; 61]], 28, 1);
        assert!(is_valid_relay_response(&max_name, &reply(&max_name)));
        let overlong = question(&[&label, &label, &label, &label], 28, 1);
        assert!(!is_valid_relay_response(&overlong, &reply(&overlong)));
        let mut pointers = vec![0; HEADER_LEN + 1]; // Root name at offset 12.
        let mut target = HEADER_LEN;
        for _ in 0..=MAX_POINTER_HOPS {
            let position = pointers.len();
            pointers.push(0xc0 | ((target >> 8) as u8));
            pointers.push(target as u8);
            target = position;
        }
        let mut names = Names {
            visited: vec![0; pointers.len()],
            bytes: &pointers,
            epoch: 0,
        };
        assert!(names.decode(target - 2).is_some());
        assert!(names.decode(target).is_none());
        let oversized = vec![0; MAX_MESSAGE_LEN + 1];
        assert!(!is_valid_relay_response(&question(&[], 28, 1), &oversized));
    }
}
