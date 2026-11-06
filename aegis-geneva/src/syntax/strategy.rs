//! A whole strategy: outbound rules `\/` inbound rules.
//!
//! Geneva writes a strategy as `<outbound> \/ <inbound>`, either half possibly
//! empty. Both halves are lists of `trigger-action-|` rules, applied in order;
//! the first matching rule wins, and a packet no rule matches passes through
//! untouched.

use crate::error::{Error, Result};
use crate::packet::model::{Direction, Packet};
use crate::syntax::action::Action;
use crate::syntax::parse::Parser;
use crate::syntax::trigger::Trigger;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub trigger: Trigger,
    pub action: Action,
}

impl Rule {
    pub fn parse(text: &str) -> Result<Self> {
        let mut parser = Parser::new(text);
        let trigger = parser.parse_trigger()?;
        parser_expect_dash(&mut parser, text)?;
        let action = parser.parse_action()?;
        parser_expect_tail(&mut parser, text)?;
        action.check_depth()?;
        Ok(Rule { trigger, action })
    }
}

fn parser_expect_dash(parser: &mut Parser<'_>, text: &str) -> Result<()> {
    if parser.eat_token("-") {
        Ok(())
    } else {
        Err(Error::Syntax(format!(
            "expected `-` after trigger in `{text}`"
        )))
    }
}

fn parser_expect_tail(parser: &mut Parser<'_>, text: &str) -> Result<()> {
    if parser.eat_token("-|") && parser.at_end() {
        Ok(())
    } else {
        Err(Error::Syntax(format!("rule must end with `-|`: `{text}`")))
    }
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}-|", self.trigger, self.action)
    }
}

/// The separator between the outbound and inbound halves.
pub const HALVES_SEPARATOR: &str = "\\/";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Strategy {
    pub outbound: Vec<Rule>,
    pub inbound: Vec<Rule>,
}

impl Strategy {
    /// The identity strategy: touch nothing. This is the baseline every
    /// evolved strategy has to beat.
    pub fn identity() -> Self {
        Strategy::default()
    }

    pub fn is_identity(&self) -> bool {
        self.outbound.is_empty() && self.inbound.is_empty()
    }

    pub fn parse(text: &str) -> Result<Self> {
        let (out_text, in_text) = match text.split_once(HALVES_SEPARATOR) {
            Some((a, b)) => (a, b),
            None => (text, ""),
        };
        Ok(Strategy {
            outbound: parse_rules(out_text)?,
            inbound: parse_rules(in_text)?,
        })
    }

    /// The rules that apply to a packet's direction.
    pub fn rules_for(&self, direction: Direction) -> &[Rule] {
        match direction {
            Direction::Outbound => &self.outbound,
            Direction::Inbound => &self.inbound,
        }
    }

    /// The first rule whose trigger fires on `packet`.
    pub fn first_match(&self, packet: &Packet) -> Option<&Rule> {
        self.rules_for(packet.direction)
            .iter()
            .find(|rule| rule.trigger.matches(packet))
    }

    /// Total node count across both halves — the complexity tie-breaker.
    pub fn size(&self) -> usize {
        self.outbound
            .iter()
            .chain(self.inbound.iter())
            .map(|r| r.action.size())
            .sum()
    }
}

fn parse_rules(text: &str) -> Result<Vec<Rule>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    // Rules are concatenated; each ends with `-|`.
    let mut rules = Vec::new();
    let mut rest = trimmed;
    while !rest.is_empty() {
        let end = rest
            .find("-|")
            .ok_or_else(|| Error::Syntax(format!("rule must end with `-|`: `{rest}`")))?;
        let (one, remainder) = rest.split_at(end + 2);
        rules.push(Rule::parse(one.trim())?);
        rest = remainder.trim();
    }
    Ok(rules)
}

impl std::fmt::Display for Strategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let render = |rules: &[Rule]| {
            rules
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        };
        write!(
            f,
            "{} {HALVES_SEPARATOR} {}",
            render(&self.outbound),
            render(&self.inbound)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::model::tcp_flags;

    #[test]
    fn parses_both_halves() {
        let s = Strategy::parse(
            "[TCP:flags:S]-duplicate(,drop)-| \\/ [TCP:flags:A]-tamper{IP:ttl:replace:1}()-|",
        )
        .unwrap();
        assert_eq!(s.outbound.len(), 1);
        assert_eq!(s.inbound.len(), 1);
    }

    #[test]
    fn round_trips_through_display() {
        let text = "[TCP:flags:S]-duplicate(,drop)-| \\/ [IP:ttl:64]-drop-|";
        let s = Strategy::parse(text).unwrap();
        assert_eq!(s.to_string(), text);
        assert_eq!(Strategy::parse(&s.to_string()).unwrap(), s);
    }

    #[test]
    fn accepts_an_empty_half() {
        let s = Strategy::parse("[TCP:flags:S]-drop-| \\/").unwrap();
        assert_eq!(s.outbound.len(), 1);
        assert!(s.inbound.is_empty());

        let s = Strategy::parse("\\/ [TCP:flags:S]-drop-|").unwrap();
        assert!(s.outbound.is_empty());
        assert_eq!(s.inbound.len(), 1);
    }

    #[test]
    fn identity_is_empty_and_round_trips() {
        let s = Strategy::identity();
        assert!(s.is_identity());
        assert_eq!(Strategy::parse(&s.to_string()).unwrap(), s);
    }

    #[test]
    fn several_rules_per_half_keep_their_order() {
        let s = Strategy::parse("[TCP:flags:S]-drop-| [IP:ttl:64]--| \\/").unwrap();
        assert_eq!(s.outbound.len(), 2);
        assert_eq!(s.outbound[0].action, Action::Drop);
        assert_eq!(s.outbound[1].action, Action::Pass);
    }

    #[test]
    fn first_matching_rule_wins_within_the_right_direction() {
        let s = Strategy::parse("[IP:ttl:64]-drop-| [IP:ttl:64]--| \\/ [IP:ttl:64]--|").unwrap();
        let mut packet = Packet::tcp_data(b"x");
        packet.tcp.as_mut().unwrap().flags = tcp_flags::SYN;

        let hit = s.first_match(&packet).expect("outbound rule matches");
        assert_eq!(hit.action, Action::Drop, "the first rule must win");

        packet.direction = Direction::Inbound;
        assert_eq!(
            s.first_match(&packet).unwrap().action,
            Action::Pass,
            "inbound must use the inbound half"
        );
    }

    #[test]
    fn no_match_yields_none() {
        let s = Strategy::parse("[TCP:flags:R]-drop-| \\/").unwrap();
        let packet = Packet::tcp_data(b"x");
        assert!(s.first_match(&packet).is_none());
    }

    #[test]
    fn rejects_rules_without_a_tail() {
        assert!(Rule::parse("[TCP:flags:S]-drop").is_err());
        assert!(Strategy::parse("[TCP:flags:S]-drop").is_err());
    }
}
