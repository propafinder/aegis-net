//! Stateful live forests. Unlike the historical offline first-match runner,
//! upstream Geneva evaluates every matching tree on the original image.
use super::wire::{self, WireError};
use crate::{packet::model::Direction, syntax::strategy::Strategy};
use rand::Rng;
#[derive(Debug, thiserror::Error)]
pub enum ProgramError {
    #[error("live strategy syntax is unsupported or malformed")]
    Syntax,
    #[error("live strategy resource limit exceeded")]
    Limit,
}
#[derive(Clone, Debug)]
pub(super) struct FragmentSpec {
    pub size: i32,
    pub overlap: u16,
}
#[derive(Clone, Debug)]
pub(super) enum TextTrigger {
    Dns {
        field: super::dns::Field,
        value: String,
        wildcard: bool,
    },
    Flags {
        proto: crate::packet::field::Proto,
        value: String,
        wildcard: bool,
    },
    Address {
        field: crate::packet::field::Field,
        value: String,
    },
    Option {
        name: super::options::Name,
        value: String,
        wildcard: bool,
    },
    Load {
        proto: crate::packet::field::Proto,
        value: String,
        wildcard: bool,
    },
}
#[derive(Clone, Debug)]
pub(super) enum LiveTamper {
    TcpOption(super::options::Spec),
    Dns(super::dns::Spec),
}
#[derive(Clone, Debug, Default)]
pub(super) struct RulePlan {
    pub fragments: Vec<FragmentSpec>,
    pub payloads: Vec<crate::packet::field::Proto>,
    pub tampers: Vec<Option<LiveTamper>>,
    pub trigger: Option<TextTrigger>,
}
pub struct Program {
    strategy: Strategy,
    out_gas: Vec<Option<i32>>,
    in_gas: Vec<Option<i32>>,
    out_bombs: Vec<bool>,
    in_bombs: Vec<bool>,
    out_fragments: Vec<RulePlan>,
    in_fragments: Vec<RulePlan>,
}
impl Program {
    pub fn parse(text: &str) -> Result<Self, ProgramError> {
        if text.len() > 65536 {
            return Err(ProgramError::Limit);
        }
        if !text.is_ascii() || text.matches("\\/").count() > 1 {
            return Err(ProgramError::Syntax);
        }
        let mut depth = 0usize;
        for byte in text.bytes() {
            if byte == b'(' {
                depth += 1;
                if depth >= crate::syntax::action::MAX_DEPTH {
                    return Err(ProgramError::Limit);
                }
            } else if byte == b')' {
                depth = depth.checked_sub(1).ok_or(ProgramError::Syntax)?;
            }
        }
        if depth != 0 {
            return Err(ProgramError::Syntax);
        }
        let (outbound, inbound) = text.split_once("\\/").unwrap_or((text, ""));
        let (out_text, out_gas, out_fragments) = normalize(outbound)?;
        let (in_text, in_gas, in_fragments) = normalize(inbound)?;
        if out_gas.len() + in_gas.len() > 128 {
            return Err(ProgramError::Limit);
        }
        let strategy = Strategy::parse(&format!("{out_text} \\/ {in_text}"))
            .map_err(|_| ProgramError::Syntax)?;
        let out_bombs = out_gas.iter().map(|g| g.is_some_and(|n| n < 0)).collect();
        let in_bombs = in_gas.iter().map(|g| g.is_some_and(|n| n < 0)).collect();
        Ok(Self {
            strategy,
            out_gas,
            in_gas,
            out_bombs,
            in_bombs,
            out_fragments,
            in_fragments,
        })
    }
    pub fn execute<R: Rng + ?Sized>(
        &mut self,
        frame: &[u8],
        direction: Direction,
        rng: &mut R,
    ) -> Result<Vec<Vec<u8>>, WireError> {
        let gas = if direction == Direction::Outbound {
            &mut self.out_gas
        } else {
            &mut self.in_gas
        };
        let bombs = if direction == Direction::Outbound {
            &self.out_bombs
        } else {
            &self.in_bombs
        };
        let fragments = if direction == Direction::Outbound {
            &self.out_fragments
        } else {
            &self.in_fragments
        };
        wire::execute_forest(&self.strategy, gas, bombs, fragments, frame, direction, rng)
    }
}
type Normalized = (String, Vec<Option<i32>>, Vec<RulePlan>);
fn normalize(text: &str) -> Result<Normalized, ProgramError> {
    let mut result = String::new();
    let mut counters = Vec::new();
    let mut fragments = Vec::new();
    let mut remaining = text.trim();
    while !remaining.is_empty() {
        if !remaining.starts_with('[') {
            return Err(ProgramError::Syntax);
        }
        let end = remaining.find("]").ok_or(ProgramError::Syntax)?;
        let fields: Vec<_> = remaining[1..end].split(':').collect();
        if !(3..=4).contains(&fields.len()) {
            return Err(ProgramError::Syntax);
        }
        let gas = if fields.len() == 4 {
            Some(
                fields[3]
                    .trim()
                    .parse::<i32>()
                    .map_err(|_| ProgramError::Syntax)?,
            )
        } else {
            None
        };
        counters.push(gas);
        if counters.len() > 128 {
            return Err(ProgramError::Limit);
        }
        let (trigger, spec) = normalize_trigger(&fields[..3])?;
        result.push('[');
        result.push_str(&trigger);
        result.push(']');
        let tail = remaining[end + 1..]
            .find("-|")
            .ok_or(ProgramError::Syntax)?
            + end
            + 3;
        let (action, specs) = normalize_fragments(&remaining[end + 1..tail])?;
        let (action, payloads, tampers) = normalize_tampers(&action)?;
        fragments.push(RulePlan {
            fragments: specs,
            payloads,
            tampers,
            trigger: spec,
        });
        result.push_str(&action);
        result.push(' ');
        remaining = remaining[tail..].trim();
    }
    Ok((result, counters, fragments))
}

fn normalize_fragments(text: &str) -> Result<(String, Vec<FragmentSpec>), ProgramError> {
    let mut normalized = String::new();
    let mut specs = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("fragment{") {
        normalized.push_str(&rest[..start]);
        let body_start = start + 9;
        let body_end = rest[body_start..].find('}').ok_or(ProgramError::Syntax)? + body_start;
        let fields: Vec<_> = rest[body_start..body_end]
            .split(':')
            .map(str::trim)
            .collect();
        if !(3..=4).contains(&fields.len()) {
            return Err(ProgramError::Syntax);
        }
        let proto =
            crate::packet::field::Proto::parse(fields[0]).map_err(|_| ProgramError::Syntax)?;
        if proto == crate::packet::field::Proto::Udp {
            return Err(ProgramError::Syntax);
        }
        let size = fields[1].parse::<i32>().map_err(|_| ProgramError::Syntax)?;
        if !(-1..=65535).contains(&size) {
            return Err(ProgramError::Limit);
        }
        let order = crate::syntax::action::FragmentOrder::parse(fields[2])
            .map_err(|_| ProgramError::Syntax)?;
        let overlap = if fields.len() == 4 {
            fields[3].parse::<u16>().map_err(|_| ProgramError::Syntax)?
        } else {
            0
        };
        // Upstream parses IP overlap but only applies it to TCP segmentation.
        specs.push(FragmentSpec { size, overlap });
        normalized.push_str(&format!(
            "fragment{{{}:0:{}}}",
            proto.as_str(),
            order.as_str()
        ));
        rest = &rest[body_end + 1..];
    }
    normalized.push_str(rest);
    Ok((normalized, specs))
}

fn normalize_trigger(fields: &[&str]) -> Result<(String, Option<TextTrigger>), ProgramError> {
    use crate::packet::field::{Field, Proto};
    if matches!(fields[0].trim(), "DNS" | "DNSQR") {
        let field = super::dns::Field::parse(fields[0].trim(), fields[1].trim())?;
        if matches!(field, super::dns::Field::Qd) {
            return Err(ProgramError::Syntax);
        }
        let raw = fields[2].trim();
        let wildcard = raw.ends_with('*');
        if wildcard && !field.textual() {
            return Err(ProgramError::Syntax);
        }
        if !field.textual() {
            raw.parse::<u32>().map_err(|_| ProgramError::Syntax)?;
        }
        return Ok((
            "IP:ttl:0".into(),
            Some(TextTrigger::Dns {
                field,
                value: raw.strip_suffix('*').unwrap_or(raw).into(),
                wildcard,
            }),
        ));
    }
    let proto = Proto::parse(fields[0].trim()).map_err(|_| ProgramError::Syntax)?;
    let name = fields[1].trim();
    let value = fields[2].trim();
    let wildcard = value.ends_with('*');
    let pattern = if wildcard {
        &value[..value.len() - 1]
    } else {
        value
    };
    let dummy = "IP:ttl:0".to_string();
    if let Some(option) = name.strip_prefix("options-") {
        if proto != Proto::Tcp {
            return Err(ProgramError::Syntax);
        }
        let name = super::options::Name::parse(option)?;
        if wildcard && name.numeric() {
            return Err(ProgramError::Syntax);
        }
        return Ok((
            dummy,
            Some(TextTrigger::Option {
                name,
                value: pattern.to_string(),
                wildcard,
            }),
        ));
    }
    if name == "load" {
        return Ok((
            dummy,
            Some(TextTrigger::Load {
                proto,
                value: pattern.to_string(),
                wildcard,
            }),
        ));
    }
    let field = Field::parse(proto, name).map_err(|_| ProgramError::Syntax)?;
    if field == Field::IpFlags {
        if wildcard || value.parse::<u8>().is_err() {
            return Ok((
                dummy,
                Some(TextTrigger::Flags {
                    proto,
                    value: pattern.to_string(),
                    wildcard,
                }),
            ));
        }
        let bits = super::values::ip_flags(value)?;
        return Ok((format!("IP:flags:{bits}"), None));
    }
    if field == Field::TcpFlags
        && (wildcard || crate::packet::model::tcp_flags::parse(value).is_some())
    {
        return Ok((
            dummy,
            Some(TextTrigger::Flags {
                proto,
                value: pattern.to_string(),
                wildcard,
            }),
        ));
    }
    if matches!(field, Field::IpSource | Field::IpDestination) && wildcard {
        return Ok((
            dummy,
            Some(TextTrigger::Address {
                field,
                value: pattern.to_string(),
            }),
        ));
    }
    if wildcard {
        return Err(ProgramError::Syntax);
    }
    Ok((fields.join(":"), None))
}
type NormalizedTampers = (
    String,
    Vec<crate::packet::field::Proto>,
    Vec<Option<LiveTamper>>,
);
fn normalize_tampers(text: &str) -> Result<NormalizedTampers, ProgramError> {
    use crate::packet::field::{Field, Proto};
    let mut result = String::new();
    let mut layers = Vec::new();
    let mut tampers = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("tamper{") {
        result.push_str(&rest[..start]);
        let begin = start + 7;
        let end = rest[begin..].find('}').ok_or(ProgramError::Syntax)? + begin;
        let parts: Vec<_> = rest[begin..end].split(':').map(str::trim).collect();
        if !(3..=4).contains(&parts.len()) {
            return Err(ProgramError::Syntax);
        }
        if matches!(parts[0], "DNS" | "DNSQR") {
            tampers.push(Some(LiveTamper::Dns(super::dns::Spec::parse(
                parts[0],
                parts[1],
                &parts[2..],
            )?)));
            result.push_str("tamper{IP:ttl:replace:0}");
            rest = &rest[end + 1..];
            continue;
        }
        let proto = Proto::parse(parts[0]).map_err(|_| ProgramError::Syntax)?;
        if let Some(option) = parts[1].strip_prefix("options-") {
            if proto != Proto::Tcp {
                return Err(ProgramError::Syntax);
            }
            tampers.push(Some(LiveTamper::TcpOption(super::options::Spec::parse(
                option,
                &parts[2..],
            )?)));
            result.push_str("tamper{IP:ttl:replace:0}");
        } else if parts[1] == "load" {
            layers.push(proto);
            match parts[2] {
                "replace" if parts.len() == 4 => {
                    let bytes = super::values::unquote(parts[3])?;
                    let value = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    result.push_str(&format!("tamper{{TCP:load:replace:{value}}}"));
                }
                "corrupt" if parts.len() == 3 => result.push_str("tamper{TCP:load:corrupt}"),
                "truncate" if parts.len() == 4 => {
                    result.push_str(&format!("tamper{{TCP:load:truncate:{}}}", parts[3]))
                }
                _ => return Err(ProgramError::Syntax),
            }
        } else {
            tampers.push(None);
            let field = Field::parse(proto, parts[1]).map_err(|_| ProgramError::Syntax)?;
            if field == Field::IpFlags && parts.len() == 4 {
                let value = match parts[2] {
                    "replace" => i32::from(super::values::ip_flags(parts[3])?),
                    "add" => parts[3]
                        .parse::<i32>()
                        .ok()
                        .and_then(|n| n.checked_mul(8192))
                        .ok_or(ProgramError::Syntax)?,
                    _ => return Err(ProgramError::Syntax),
                };
                result.push_str(&format!("tamper{{IP:flags:{}:{value}}}", parts[2]));
            } else {
                result.push_str(&rest[start..=end]);
            }
        }
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    Ok((result, layers, tampers))
}
