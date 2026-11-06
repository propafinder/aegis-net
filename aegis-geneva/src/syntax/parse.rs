//! Parser for the Geneva strategy DSL.
//!
//! Grammar (one rule):
//! ```text
//! rule    := trigger '-' action '-|'
//! trigger := '[' PROTO ':' field ':' value ']'
//! action  := '' | 'drop'
//!          | 'duplicate' '(' action ',' action ')'
//!          | 'fragment' '{' PROTO ':' offset ':' order '}' '(' action ',' action ')'
//!          | 'tamper' '{' PROTO ':' field ':' mode [':' value] '}' '(' action ')'
//! ```
//!
//! Hand-written rather than generated: the grammar is small, and a parser that
//! reports *where* a strategy is malformed is worth more here than one that
//! only reports *that* it is — evolved strategies are read by humans debugging
//! why a run went nowhere.

use crate::actions::payload::PayloadMode;
use crate::error::{Error, Result};
use crate::packet::field::{Field, Proto};
use crate::packet::model::tcp_flags;
use crate::syntax::action::{hex_decode, Action, FragmentOrder, TamperMode};
use crate::syntax::trigger::Trigger;

pub(crate) struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        Parser { text, pos: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.text[self.pos..]
    }

    fn skip_ws(&mut self) {
        while self.rest().starts_with(char::is_whitespace) {
            self.pos += 1;
        }
    }

    /// Consume `token` if present. Exposed to the crate so rule parsing can
    /// share the same whitespace handling.
    pub(crate) fn eat_token(&mut self, token: &str) -> bool {
        self.eat(token)
    }

    fn eat(&mut self, token: &str) -> bool {
        self.skip_ws();
        if self.rest().starts_with(token) {
            self.pos += token.len();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, token: &str) -> Result<()> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(Error::Syntax(format!(
                "expected `{token}` at offset {} in `{}`",
                self.pos, self.text
            )))
        }
    }

    /// Read up to `close`, honouring nothing else — used for `[...]` and `{...}`
    /// bodies, which never nest.
    fn take_until(&mut self, close: char) -> Result<&'a str> {
        let start = self.pos;
        match self.rest().find(close) {
            Some(idx) => {
                let body = &self.text[start..start + idx];
                self.pos = start + idx + close.len_utf8();
                Ok(body)
            }
            None => Err(Error::Syntax(format!(
                "unterminated `{close}` in `{}`",
                self.text
            ))),
        }
    }

    pub(crate) fn parse_trigger(&mut self) -> Result<Trigger> {
        self.expect("[")?;
        let body = self.take_until(']')?;
        Trigger::parse(body)
    }

    pub(crate) fn parse_action(&mut self) -> Result<Action> {
        self.skip_ws();
        if self.eat("duplicate") {
            let (left, right) = self.parse_two_children()?;
            return Ok(Action::Duplicate {
                left: Box::new(left),
                right: Box::new(right),
            });
        }
        if self.eat("fragment") {
            self.expect("{")?;
            let body = self.take_until('}')?;
            let (proto, offset, order) = parse_fragment_body(body)?;
            let (left, right) = self.parse_two_children()?;
            return Ok(Action::Fragment {
                proto,
                offset,
                order,
                left: Box::new(left),
                right: Box::new(right),
            });
        }
        if self.eat("tamper") {
            self.expect("{")?;
            let body = self.take_until('}')?;
            // `TCP:load` addresses the payload, which is bytes rather than a
            // numeric header field, so it parses into its own action.
            if let Some(mode) = parse_payload_body(body)? {
                self.expect("(")?;
                let next = self.parse_action()?;
                self.expect(")")?;
                return Ok(Action::TamperPayload {
                    mode,
                    next: Box::new(next),
                });
            }
            let (field, mode) = parse_tamper_body(body)?;
            self.expect("(")?;
            let next = self.parse_action()?;
            self.expect(")")?;
            return Ok(Action::Tamper {
                field,
                mode,
                next: Box::new(next),
            });
        }
        if self.eat("drop") {
            return Ok(Action::Drop);
        }
        // An empty action slot is `pass`: end of input, a child separator, a
        // closing paren, or the start of the rule terminator.
        let rest = self.rest();
        if rest.is_empty()
            || rest.starts_with(',')
            || rest.starts_with(')')
            || rest.starts_with("-|")
        {
            return Ok(Action::Pass);
        }
        Err(Error::Syntax(format!(
            "expected an action at offset {} in `{}`",
            self.pos, self.text
        )))
    }

    fn parse_two_children(&mut self) -> Result<(Action, Action)> {
        self.expect("(")?;
        let left = self.parse_action()?;
        self.expect(",")?;
        let right = self.parse_action()?;
        self.expect(")")?;
        Ok((left, right))
    }

    pub(crate) fn at_end(&mut self) -> bool {
        self.skip_ws();
        self.rest().is_empty()
    }
}

fn parse_fragment_body(body: &str) -> Result<(Proto, u16, FragmentOrder)> {
    let parts: Vec<&str> = body.split(':').collect();
    if parts.len() != 3 {
        return Err(Error::Syntax(format!(
            "fragment needs PROTO:offset:order, got `{body}`"
        )));
    }
    let proto = Proto::parse(parts[0].trim())?;
    if proto == Proto::Udp {
        return Err(Error::Syntax(
            "UDP fragment is not a supported primitive".into(),
        ));
    }
    let offset = parts[1]
        .trim()
        .parse::<u16>()
        .map_err(|_| Error::Syntax(format!("fragment offset `{}` is not a number", parts[1])))?;
    Ok((proto, offset, FragmentOrder::parse(parts[2])?))
}

/// Recognise `TCP:load:...`, returning `None` for any other field so the
/// numeric tamper parser gets its turn.
fn parse_payload_body(body: &str) -> Result<Option<PayloadMode>> {
    let parts: Vec<&str> = body.split(':').collect();
    if parts.len() < 3 || !parts[1].trim().eq_ignore_ascii_case("load") {
        return Ok(None);
    }
    if !parts[0].trim().eq_ignore_ascii_case("TCP") {
        return Err(Error::Syntax(
            "payload action currently requires TCP:load".into(),
        ));
    }
    let mode = match parts[2].trim() {
        "corrupt" if parts.len() == 3 => PayloadMode::Corrupt,
        "replace" if parts.len() == 4 => {
            let raw = parts
                .get(3)
                .ok_or_else(|| Error::Syntax("tamper load replace needs bytes".into()))?
                .trim();
            let bytes = hex_decode(raw)
                .ok_or_else(|| Error::BadFieldValue("TCP:load".into(), raw.to_string()))?;
            PayloadMode::Replace(bytes)
        }
        "truncate" if parts.len() == 4 => {
            let raw = parts
                .get(3)
                .ok_or_else(|| Error::Syntax("tamper load truncate needs a length".into()))?
                .trim();
            PayloadMode::Truncate(
                raw.parse::<u16>()
                    .map_err(|_| Error::BadFieldValue("TCP:load".into(), raw.to_string()))?,
            )
        }
        other => {
            return Err(Error::Syntax(format!(
                "unknown payload tamper mode `{other}`"
            )))
        }
    };
    Ok(Some(mode))
}

fn parse_tamper_body(body: &str) -> Result<(Field, TamperMode)> {
    let parts: Vec<&str> = body.split(':').collect();
    if parts.len() < 3 {
        return Err(Error::Syntax(format!(
            "tamper needs PROTO:field:mode[:value], got `{body}`"
        )));
    }
    let proto = Proto::parse(parts[0].trim())?;
    let field = Field::parse(proto, parts[1].trim())?;

    match parts[2].trim() {
        "corrupt" if parts.len() == 3 => Ok((field, TamperMode::Corrupt)),
        "add" if parts.len() == 4 => Ok((
            field,
            TamperMode::Add(
                parts[3]
                    .trim()
                    .parse::<i32>()
                    .map_err(|_| Error::BadFieldValue(field.to_string(), parts[3].to_string()))?,
            ),
        )),
        "replace" if parts.len() == 4 => {
            let raw = parts
                .get(3)
                .ok_or_else(|| Error::Syntax("tamper replace needs a value".into()))?
                .trim();
            if field == Field::TcpFlags {
                if let Some(bits) = tcp_flags::parse(raw) {
                    return Ok((field, TamperMode::Replace(u32::from(bits))));
                }
            }
            if matches!(field, Field::IpSource | Field::IpDestination) && raw.contains('.') {
                let ip = raw
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|_| Error::BadFieldValue(field.to_string(), raw.to_string()))?;
                return Ok((field, TamperMode::Replace(u32::from(ip))));
            }
            let value = if let Some(hex) = raw.strip_prefix("0x") {
                u32::from_str_radix(hex, 16)
            } else {
                raw.parse::<u32>()
            }
            .map_err(|_| Error::BadFieldValue(field.to_string(), raw.to_string()))?;
            Ok((field, TamperMode::Replace(value)))
        }
        other => Err(Error::Syntax(format!("unknown tamper mode `{other}`"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(text: &str) -> Result<Action> {
        let mut p = Parser::new(text);
        let a = p.parse_action()?;
        assert!(p.at_end(), "trailing input in `{text}`");
        Ok(a)
    }

    #[test]
    fn parses_every_primitive() {
        assert_eq!(action("").unwrap(), Action::Pass);
        assert_eq!(action("drop").unwrap(), Action::Drop);
        assert!(matches!(
            action("duplicate(,drop)").unwrap(),
            Action::Duplicate { .. }
        ));
        assert!(matches!(
            action("fragment{IP:8:reversed}(,)").unwrap(),
            Action::Fragment { .. }
        ));
        assert!(matches!(
            action("tamper{TCP:flags:corrupt}()").unwrap(),
            Action::Tamper { .. }
        ));
    }

    #[test]
    fn round_trips_through_display() {
        for text in [
            "",
            "drop",
            "duplicate(,drop)",
            "fragment{IP:8:reversed}(,)",
            "fragment{TCP:16:in-order}(drop,)",
            "tamper{TCP:flags:corrupt}()",
            "tamper{TCP:flags:replace:R}()",
            "tamper{TCP:load:corrupt}()",
            "tamper{TCP:load:replace:6f6b}()",
            "tamper{TCP:load:truncate:4}(drop)",
            "tamper{IP:ttl:replace:3}(duplicate(,drop))",
            "duplicate(tamper{IP:ttl:replace:1}(),fragment{IP:4:in-order}(,drop))",
        ] {
            let parsed = action(text).unwrap_or_else(|e| panic!("parse `{text}`: {e}"));
            assert_eq!(parsed.to_string(), text, "round-trip mismatch");
        }
    }

    #[test]
    fn tolerates_whitespace() {
        assert_eq!(
            action(" duplicate( , drop ) ").unwrap(),
            action("duplicate(,drop)").unwrap()
        );
    }

    #[test]
    fn reports_malformed_input_rather_than_guessing() {
        for bad in [
            "duplicate()",                 // missing second child
            "duplicate(,drop",             // unclosed
            "tamper{TCP:flags:replace}()", // replace without a value
            "tamper{TCP:flags:nonesuch}()",
            "tamper{TCP:load:replace}()",
            "tamper{TCP:load:replace:xyz}()",
            "tamper{TCP:load:nonesuch}()",
            "fragment{IP:8}(,)", // missing order
            "fragment{IP:x:in-order}(,)",
            "nonsense",
        ] {
            assert!(action(bad).is_err(), "accepted malformed `{bad}`");
        }
    }

    #[test]
    fn parses_triggers() {
        let mut p = Parser::new("[TCP:flags:SA]");
        let t = p.parse_trigger().unwrap();
        assert_eq!(t.to_string(), "[TCP:flags:SA]");
        assert!(Parser::new("[TCP:flags:SA").parse_trigger().is_err());
    }
}
