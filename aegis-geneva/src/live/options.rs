//! Explicit bounded TCP option fields; no packet-library or arbitrary evaluation.
use super::{program::ProgramError, wire::WireError};
use rand::Rng;
#[derive(Clone, Copy, Debug)]
pub enum Name {
    Eol,
    Nop,
    Mss,
    Wscale,
    Sackok,
    Sack,
    Timestamp,
    Altchksum,
    Altchksumopt,
    Md5header,
    Uto,
}
impl Name {
    pub fn parse(s: &str) -> Result<Self, ProgramError> {
        Ok(match s {
            "eol" => Self::Eol,
            "nop" => Self::Nop,
            "mss" => Self::Mss,
            "wscale" => Self::Wscale,
            "sackok" => Self::Sackok,
            "sack" => Self::Sack,
            "timestamp" => Self::Timestamp,
            "altchksum" => Self::Altchksum,
            "altchksumopt" => Self::Altchksumopt,
            "md5header" => Self::Md5header,
            "uto" => Self::Uto,
            _ => return Err(ProgramError::Syntax),
        })
    }
    fn kind(self) -> u8 {
        match self {
            Self::Eol => 0,
            Self::Nop => 1,
            Self::Mss => 2,
            Self::Wscale => 3,
            Self::Sackok => 4,
            Self::Sack => 5,
            Self::Timestamp => 8,
            Self::Altchksum => 14,
            Self::Altchksumopt => 15,
            Self::Md5header => 19,
            Self::Uto => 28,
        }
    }
    pub fn numeric(self) -> bool {
        matches!(
            self,
            Self::Mss | Self::Wscale | Self::Timestamp | Self::Altchksum | Self::Uto
        )
    }
    fn width(self) -> usize {
        match self {
            Self::Mss | Self::Uto => 2,
            Self::Wscale => 1,
            Self::Timestamp => 8,
            Self::Altchksum => 3,
            Self::Md5header => 16,
            _ => 0,
        }
    }
    fn max(self) -> u32 {
        match self {
            Self::Mss | Self::Uto => 65535,
            Self::Wscale | Self::Altchksum => 255,
            Self::Timestamp => u32::MAX,
            _ => 0,
        }
    }
}
#[derive(Clone, Debug)]
pub enum Mode {
    Replace(Vec<u8>),
    Corrupt,
    Add(i32),
}
#[derive(Clone, Debug)]
pub struct Spec {
    pub name: Name,
    pub mode: Mode,
}
impl Spec {
    pub fn parse(name: &str, parts: &[&str]) -> Result<Self, ProgramError> {
        let name = Name::parse(name)?;
        let mode = match parts {
            ["corrupt"] => Mode::Corrupt,
            ["add", value] if name.numeric() => {
                Mode::Add(value.parse().map_err(|_| ProgramError::Syntax)?)
            }
            ["replace", value] => Mode::Replace(if name.numeric() {
                let n = if value.is_empty() {
                    0
                } else {
                    value.parse::<u32>().map_err(|_| ProgramError::Syntax)?
                };
                if n > name.max() {
                    return Err(ProgramError::Syntax);
                }
                numeric_bytes(name, n)
            } else {
                let bytes = crate::syntax::action::hex_decode(value).ok_or(ProgramError::Syntax)?;
                if matches!(name, Name::Eol | Name::Nop | Name::Sackok | Name::Sack)
                    && !bytes.is_empty()
                {
                    return Err(ProgramError::Syntax);
                }
                if matches!(name, Name::Md5header) && bytes.len() != 16 {
                    return Err(ProgramError::Syntax);
                }
                if bytes.len() > 38 {
                    return Err(ProgramError::Limit);
                }
                bytes
            }),
            _ => return Err(ProgramError::Syntax),
        };
        Ok(Self { name, mode })
    }
}
fn numeric_bytes(name: Name, n: u32) -> Vec<u8> {
    match name {
        Name::Mss | Name::Uto => (n as u16).to_be_bytes().to_vec(),
        Name::Wscale => vec![n as u8],
        Name::Timestamp => [n.to_be_bytes().as_slice(), &[0, 0, 0, 0]].concat(),
        Name::Altchksum => vec![n as u8, 0, 0],
        _ => Vec::new(),
    }
}
pub type Rows = Vec<(u8, Vec<u8>)>;
fn entries(tcp: &[u8]) -> Result<Rows, WireError> {
    if tcp.len() < 20 || tcp.len() > 60 {
        return Err(WireError::Frame);
    }
    let mut out = Vec::new();
    let mut pos = 20;
    while pos < tcp.len() {
        let kind = tcp[pos];
        if kind < 2 {
            out.push((kind, Vec::new()));
            pos += 1;
            if kind == 0 {
                break;
            }
            continue;
        }
        let len = usize::from(*tcp.get(pos + 1).ok_or(WireError::Frame)?);
        if len < 2 || pos + len > tcp.len() {
            return Err(WireError::Frame);
        }
        out.push((kind, tcp[pos + 2..pos + len].to_vec()));
        pos += len;
    }
    Ok(out)
}
fn value(name: Name, data: &[u8]) -> Result<String, WireError> {
    if data.is_empty() {
        return Ok(String::new());
    }
    if name.numeric() {
        if data.len() != name.width() {
            return Err(WireError::Frame);
        }
        let n = match name {
            Name::Mss | Name::Uto => u32::from(u16::from_be_bytes(data[..2].try_into().unwrap())),
            Name::Timestamp => u32::from_be_bytes(data[..4].try_into().unwrap()),
            _ => u32::from(data[0]),
        };
        return Ok(n.to_string());
    }
    Ok(data.iter().map(|b| format!("{b:02x}")).collect())
}
pub fn get(tcp: &[u8], name: Name) -> Result<String, WireError> {
    let rows = entries(tcp)?;
    let Some((_, data)) = rows.into_iter().find(|(kind, _)| *kind == name.kind()) else {
        return Ok(String::new());
    };
    value(name, &data)
}
pub fn apply<R: Rng + ?Sized>(
    tcp: &mut Vec<u8>,
    spec: &Spec,
    cached: &mut Option<Rows>,
    rng: &mut R,
) -> Result<(), WireError> {
    // Original Geneva retains the in-memory option list across chained actions,
    // even entries appended after EOL that a receiver will not parse.
    let mut rows = match cached {
        Some(rows) => rows.clone(),
        None => entries(tcp)?,
    };
    let data = match &spec.mode {
        Mode::Replace(bytes) => bytes.clone(),
        Mode::Corrupt => {
            if spec.name.numeric() {
                numeric_bytes(spec.name, rng.gen::<u32>() & spec.name.max())
            } else {
                (0..spec.name.width()).map(|_| rng.gen::<u8>()).collect()
            }
        }
        Mode::Add(delta) => {
            let previous = rows
                .iter()
                .find(|(kind, _)| *kind == spec.name.kind())
                .map(|(_, data)| value(spec.name, data))
                .transpose()?
                .unwrap_or_default()
                .parse::<u32>()
                .map_err(|_| WireError::Unrepresentable)?;
            numeric_bytes(
                spec.name,
                previous.wrapping_add(*delta as u32) & spec.name.max(),
            )
        }
    };
    if let Some(row) = rows.iter_mut().find(|(kind, _)| *kind == spec.name.kind()) {
        row.1 = data;
    } else {
        rows.push((spec.name.kind(), data));
    }
    let mut options = Vec::new();
    for (kind, data) in &rows {
        options.push(*kind);
        if *kind >= 2 {
            options.push((data.len() + 2) as u8);
            options.extend_from_slice(data);
        }
    }
    while !options.len().is_multiple_of(4) {
        options.push(0);
    }
    if options.len() > 40 {
        return Err(WireError::Budget);
    }
    *cached = Some(rows);
    tcp.truncate(20);
    tcp.extend_from_slice(&options);
    tcp[12] = (tcp[12] & 15) | ((tcp.len() / 4) as u8) << 4;
    Ok(())
}
