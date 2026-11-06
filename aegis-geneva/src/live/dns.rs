//! Bounded DNS wire fields and Geneva two-question forward-pointer transform.
//! No resolver/network calls; malformed names and unrepresentable record edits refuse.
use super::{program::ProgramError, wire::WireError};
use rand::Rng;
#[derive(Clone, Copy, Debug)]
pub enum Field {
    Header { offset: usize, shift: u8, mask: u16 },
    Qname,
    Qtype,
    Qclass,
    Qd,
}
impl Field {
    pub fn parse(proto: &str, name: &str) -> Result<Self, ProgramError> {
        Ok(match (proto, name) {
            ("DNS", "id") => Self::Header {
                offset: 0,
                shift: 0,
                mask: 65535,
            },
            ("DNS", "qr") => Self::Header {
                offset: 2,
                shift: 15,
                mask: 1,
            },
            ("DNS", "opcode") => Self::Header {
                offset: 2,
                shift: 11,
                mask: 15,
            },
            ("DNS", "aa") => Self::Header {
                offset: 2,
                shift: 10,
                mask: 1,
            },
            ("DNS", "tc") => Self::Header {
                offset: 2,
                shift: 9,
                mask: 1,
            },
            ("DNS", "rd") => Self::Header {
                offset: 2,
                shift: 8,
                mask: 1,
            },
            ("DNS", "ra") => Self::Header {
                offset: 2,
                shift: 7,
                mask: 1,
            },
            ("DNS", "z") => Self::Header {
                offset: 2,
                shift: 6,
                mask: 1,
            },
            ("DNS", "ad") => Self::Header {
                offset: 2,
                shift: 5,
                mask: 1,
            },
            ("DNS", "cd") => Self::Header {
                offset: 2,
                shift: 4,
                mask: 1,
            },
            ("DNS", "rcode") => Self::Header {
                offset: 2,
                shift: 0,
                mask: 15,
            },
            ("DNS", "qdcount") => Self::Header {
                offset: 4,
                shift: 0,
                mask: 65535,
            },
            ("DNS", "ancount") => Self::Header {
                offset: 6,
                shift: 0,
                mask: 65535,
            },
            ("DNS", "nscount") => Self::Header {
                offset: 8,
                shift: 0,
                mask: 65535,
            },
            ("DNS", "arcount") => Self::Header {
                offset: 10,
                shift: 0,
                mask: 65535,
            },
            ("DNS", "qd") => Self::Qd,
            ("DNSQR", "qname") => Self::Qname,
            ("DNSQR", "qtype") => Self::Qtype,
            ("DNSQR", "qclass") => Self::Qclass,
            _ => return Err(ProgramError::Syntax),
        })
    }
    pub fn textual(self) -> bool {
        matches!(self, Self::Qname)
    }
}
#[derive(Clone, Debug)]
pub enum Mode {
    Replace(u32),
    Name(Vec<u8>),
    Corrupt,
    Add(i32),
    Compress,
}
#[derive(Clone, Debug)]
pub struct Spec {
    pub field: Field,
    pub mode: Mode,
}
impl Spec {
    pub fn parse(proto: &str, field: &str, parts: &[&str]) -> Result<Self, ProgramError> {
        let field = Field::parse(proto, field)?;
        let mode = match parts {
            ["compress"] if matches!(field, Field::Qd) => Mode::Compress,
            ["replace", name] if field.textual() => {
                Mode::Name(encode_name(name).map_err(|_| ProgramError::Syntax)?)
            }
            ["replace", n] if !matches!(field, Field::Qd) => {
                Mode::Replace(n.parse().map_err(|_| ProgramError::Syntax)?)
            }
            ["corrupt"] if !matches!(field, Field::Qd) => Mode::Corrupt,
            ["add", n] if !field.textual() && !matches!(field, Field::Qd) => {
                Mode::Add(n.parse().map_err(|_| ProgramError::Syntax)?)
            }
            _ => return Err(ProgramError::Syntax),
        };
        Ok(Self { field, mode })
    }
}
fn word(b: &[u8], offset: usize) -> Result<u16, WireError> {
    Ok(u16::from_be_bytes(
        b.get(offset..offset + 2)
            .ok_or(WireError::Frame)?
            .try_into()
            .unwrap(),
    ))
}
fn name(b: &[u8], start: usize) -> Result<(Vec<Vec<u8>>, usize), WireError> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut end = None;
    let mut visited = std::collections::BTreeSet::new();
    let mut length = 1;
    loop {
        if !visited.insert(cursor) {
            return Err(WireError::Frame);
        }
        if visited.len() > 128 {
            return Err(WireError::Budget);
        }
        let n = *b.get(cursor).ok_or(WireError::Frame)?;
        if n & 0xc0 == 0xc0 {
            let pointer = usize::from(word(b, cursor)? & 0x3fff);
            end.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if n & 0xc0 != 0 {
            return Err(WireError::Frame);
        }
        cursor += 1;
        if n == 0 {
            return Ok((labels, end.unwrap_or(cursor)));
        }
        let value = b
            .get(cursor..cursor + usize::from(n))
            .ok_or(WireError::Frame)?;
        length += value.len() + 1;
        if length > 255 {
            return Err(WireError::Budget);
        }
        labels.push(value.to_vec());
        cursor += value.len();
    }
}
fn encode_name(s: &str) -> Result<Vec<u8>, WireError> {
    let s = s.strip_suffix('.').unwrap_or(s);
    let mut out = Vec::new();
    if !s.is_empty() {
        for label in s.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(WireError::Unrepresentable);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() > 255 {
        return Err(WireError::Budget);
    }
    Ok(out)
}
type Question = (Vec<Vec<u8>>, usize);
fn question(b: &[u8]) -> Result<Option<Question>, WireError> {
    if word(b, 4)? == 0 {
        return Ok(None);
    }
    Ok(Some(name(b, 12)?))
}
pub fn get(b: &[u8], field: Field) -> Result<Option<String>, WireError> {
    if b.len() < 12 {
        return Err(WireError::Frame);
    }
    let value = match field {
        Field::Header {
            offset,
            shift,
            mask,
        } => ((word(b, offset)? >> shift) & mask).to_string(),
        Field::Qd => return Err(WireError::Unrepresentable),
        Field::Qname | Field::Qtype | Field::Qclass => {
            let Some((labels, end)) = question(b)? else {
                return Ok(None);
            };
            if matches!(field, Field::Qname) {
                let mut text = String::new();
                for label in labels {
                    let label =
                        std::str::from_utf8(&label).map_err(|_| WireError::Unrepresentable)?;
                    text.push_str(label);
                    text.push('.');
                }
                if text.is_empty() {
                    text.push('.');
                }
                text
            } else {
                word(b, end + if matches!(field, Field::Qclass) { 2 } else { 0 })?.to_string()
            }
        }
    };
    Ok(Some(value))
}
pub fn apply<R: Rng + ?Sized>(
    b: &[u8],
    spec: &Spec,
    tcp: bool,
    rng: &mut R,
) -> Result<Vec<u8>, WireError> {
    if b.len() < 12 {
        return Err(WireError::Frame);
    }
    let mut result = b.to_vec();
    if matches!(spec.mode, Mode::Compress) {
        if tcp {
            // Original Tamper catches DNSLayer's TCP NotImplementedError.
            return Ok(result);
        }
        if word(b, 4)? == 0 {
            return Ok(result);
        }
        let (labels, _) = name(b, 12)?;
        if labels.is_empty() {
            return Err(WireError::Unrepresentable);
        }
        let first = &labels[0];
        let offset = 12 + 1 + first.len() + 2 + 4;
        if offset > 0x3fff {
            return Err(WireError::Budget);
        }
        // The original transform serializes DNS with qd=None (including
        // remaining RR sections), then appends the two raw questions. It does
        // not relocate its hard-coded query pointer past those RR bytes.
        result = rewrite_questions(b, None)?;
        result[4..6].copy_from_slice(&2u16.to_be_bytes());
        result.push(first.len() as u8);
        result.extend_from_slice(first);
        result.extend_from_slice(&(0xc000 | offset as u16).to_be_bytes());
        result.extend_from_slice(&[0, 1, 0, 1]);
        for label in &labels[1..] {
            result.push(label.len() as u8);
            result.extend_from_slice(label);
        }
        result.push(0);
        result.extend_from_slice(&[0, 1, 0, 1]);
        return Ok(result);
    }
    if spec.field.textual() && word(b, 4)? == 0 {
        return Ok(result);
    }
    if spec.field.textual() {
        let replacement = match &spec.mode {
            Mode::Name(name) => name.clone(),
            Mode::Corrupt => encode_name("example.com.")?,
            _ => return Err(WireError::Unrepresentable),
        };
        return rewrite_first_question(b, &replacement);
    }
    let (offset, shift, mask) = match spec.field {
        Field::Header {
            offset,
            shift,
            mask,
        } => (offset, shift, mask),
        Field::Qtype | Field::Qclass => {
            let Some((_, end)) = question(b)? else {
                return Ok(result);
            };
            (
                end + if matches!(spec.field, Field::Qclass) {
                    2
                } else {
                    0
                },
                0,
                65535,
            )
        }
        _ => return Err(WireError::Unrepresentable),
    };
    let old = word(b, offset)?;
    let current = (old >> shift) & mask;
    let value = match spec.mode {
        Mode::Replace(n) => n as u16,
        Mode::Add(n) => current.wrapping_add(n as u16),
        Mode::Corrupt => rng.gen::<u16>(),
        _ => return Err(WireError::Unrepresentable),
    } & mask;
    result[offset..offset + 2]
        .copy_from_slice(&((old & !(mask << shift)) | (value << shift)).to_be_bytes());
    Ok(result)
}

fn encoded_labels(labels: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out
}
// RDATA known to contain names is decompressed before relocation. Unknown RR
// types retain opaque RDATA, per RFC3597 (compression inside unknown RDATA is
// not permitted). Address/signature/TXT bytes are never searched for C0 patterns.
fn relocated_rdata(b: &[u8], kind: u16, start: usize, end: usize) -> Result<Vec<u8>, WireError> {
    let data = b.get(start..end).ok_or(WireError::Frame)?;
    let mut cursor = start;
    let mut out = Vec::new();
    let (prefix, names, tail) = match kind {
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 23 | 39 => (0, 1, false),
        6 => (0, 2, true),
        14 | 17 => (0, 2, false),
        15 | 18 | 21 | 36 => (2, 1, false),
        26 => (2, 2, false),
        33 => (6, 1, false),
        24 | 46 => (18, 1, true),
        30 | 47 => (0, 1, true),
        64 | 65 => (2, 1, true),
        249 | 250 => (0, 1, true),
        35 => {
            if data.len() < 4 {
                return Err(WireError::Frame);
            }
            cursor += 4;
            for _ in 0..3 {
                let n = usize::from(*b.get(cursor).ok_or(WireError::Frame)?);
                cursor += n + 1;
                if cursor > end {
                    return Err(WireError::Frame);
                }
            }
            (cursor - start, 1, false)
        }
        _ => return Ok(data.to_vec()),
    };
    cursor = start + prefix;
    if cursor > end {
        return Err(WireError::Frame);
    }
    out.extend_from_slice(&b[start..cursor]);
    for _ in 0..names {
        let (labels, next) = name(b, cursor)?;
        if next > end {
            return Err(WireError::Frame);
        }
        out.extend_from_slice(&encoded_labels(&labels));
        cursor = next;
    }
    if kind == 6 && end - cursor != 20 {
        return Err(WireError::Frame);
    }
    if tail {
        out.extend_from_slice(&b[cursor..end]);
    } else if cursor != end {
        return Err(WireError::Frame);
    }
    Ok(out)
}
fn rewrite_first_question(b: &[u8], replacement: &[u8]) -> Result<Vec<u8>, WireError> {
    rewrite_questions(b, Some(replacement))
}
fn rewrite_questions(b: &[u8], replacement: Option<&[u8]>) -> Result<Vec<u8>, WireError> {
    let counts = [word(b, 4)?, word(b, 6)?, word(b, 8)?, word(b, 10)?];
    if counts.iter().map(|n| usize::from(*n)).sum::<usize>() > 256 {
        return Err(WireError::Budget);
    }
    if counts[0] == 0 && replacement.is_some() {
        return Ok(b.to_vec());
    }
    let mut cursor = 12;
    let mut out = b[..12].to_vec();
    for index in 0..counts[0] {
        let (labels, next) = name(b, cursor)?;
        let trailer = b.get(next..next + 4).ok_or(WireError::Frame)?;
        if let Some(replacement) = replacement {
            if index == 0 {
                out.extend_from_slice(replacement);
            } else {
                out.extend_from_slice(&encoded_labels(&labels));
            }
            out.extend_from_slice(trailer);
        }
        cursor = next + 4;
    }
    for count in &counts[1..] {
        for _ in 0..*count {
            let (labels, next) = name(b, cursor)?;
            let header = b.get(next..next + 10).ok_or(WireError::Frame)?;
            let kind = word(header, 0)?;
            let len = usize::from(word(header, 8)?);
            let start = next + 10;
            let end = start.checked_add(len).ok_or(WireError::Budget)?;
            let rdata = relocated_rdata(b, kind, start, end)?;
            if rdata.len() > 65535 {
                return Err(WireError::Budget);
            }
            out.extend_from_slice(&encoded_labels(&labels));
            out.extend_from_slice(&header[..8]);
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&rdata);
            cursor = end;
        }
    }
    if cursor > b.len() {
        return Err(WireError::Frame);
    }
    out.extend_from_slice(&b[cursor..]);
    if out.len() > 65535 {
        return Err(WireError::Budget);
    }
    Ok(out)
}
