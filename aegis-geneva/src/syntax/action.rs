//! The action tree: what a rule does to a matched packet.
//!
//! Geneva's four primitives, each of which may pass its output to children:
//!
//! - `duplicate(left, right)` — copy the packet; each copy runs down one branch
//! - `fragment{proto:offset:order}(left, right)` — split into two packets
//! - `tamper{proto:field:mode[:value]}(child)` — rewrite one field
//! - `drop` — discard the packet
//!
//! A tree is a value: it has no side effects and no I/O, so mutation,
//! crossover, and evaluation are all pure functions over it.

use crate::actions::payload::PayloadMode;
use crate::error::{Error, Result};
use crate::packet::field::{Field, Proto};
use crate::packet::model::tcp_flags;

/// How `tamper` chooses the replacement value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TamperMode {
    /// Set the field to a fixed value.
    Replace(u32),
    /// Set the field to a random value (chosen when the action runs).
    Corrupt,
    /// Signed addition modulo the addressed wire field width.
    Add(i32),
}

/// Which fragment gets sent first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragmentOrder {
    InOrder,
    Reversed,
}

/// The maximum tree depth. Evolution otherwise happily grows trees until they
/// are neither executable nor comprehensible; a censor is not defeated by depth.
pub const MAX_DEPTH: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Pass the packet through unchanged.
    ///
    /// Written as the **empty string**, as in real Geneva (`duplicate(,)` is a
    /// duplicate whose two children both pass). Spelling it `|` would collide
    /// with the `-|` rule terminator and make the grammar ambiguous.
    Pass,
    Drop,
    Duplicate {
        left: Box<Action>,
        right: Box<Action>,
    },
    Fragment {
        proto: Proto,
        /// Byte offset to split at.
        offset: u16,
        order: FragmentOrder,
        left: Box<Action>,
        right: Box<Action>,
    },
    Tamper {
        field: Field,
        mode: TamperMode,
        next: Box<Action>,
    },
    /// Rewrite the payload itself (`tamper{TCP:load:...}`).
    ///
    /// Separate from [`Action::Tamper`] because a payload is bytes, not a
    /// numeric header field — and because it is the only primitive that can
    /// make a censor and a server read different content.
    TamperPayload {
        mode: PayloadMode,
        next: Box<Action>,
    },
}

impl Action {
    /// Tree depth, counting this node.
    pub fn depth(&self) -> usize {
        1 + match self {
            Action::Pass | Action::Drop => 0,
            Action::Duplicate { left, right } | Action::Fragment { left, right, .. } => {
                left.depth().max(right.depth())
            }
            Action::Tamper { next, .. } | Action::TamperPayload { next, .. } => next.depth(),
        }
    }

    /// Number of nodes, used as a tie-breaker so evolution prefers the simpler
    /// of two equally effective strategies.
    pub fn size(&self) -> usize {
        1 + match self {
            Action::Pass | Action::Drop => 0,
            Action::Duplicate { left, right } | Action::Fragment { left, right, .. } => {
                left.size() + right.size()
            }
            Action::Tamper { next, .. } | Action::TamperPayload { next, .. } => next.size(),
        }
    }

    pub fn check_depth(&self) -> Result<()> {
        if self.depth() > MAX_DEPTH {
            Err(Error::TooDeep(MAX_DEPTH))
        } else {
            Ok(())
        }
    }

    /// Every subtree, root first — the pool mutation and crossover pick from.
    pub fn subtrees(&self) -> Vec<&Action> {
        let mut out = vec![self];
        match self {
            Action::Pass | Action::Drop => {}
            Action::Duplicate { left, right } | Action::Fragment { left, right, .. } => {
                out.extend(left.subtrees());
                out.extend(right.subtrees());
            }
            Action::Tamper { next, .. } | Action::TamperPayload { next, .. } => {
                out.extend(next.subtrees())
            }
        }
        out
    }

    /// Replace the subtree at `index` (in [`Self::subtrees`] order) with
    /// `replacement`. Returns false if the index is out of range.
    pub fn replace_subtree(&mut self, index: usize, replacement: Action) -> bool {
        let mut counter = 0;
        self.replace_inner(index, &replacement, &mut counter)
    }

    fn replace_inner(&mut self, target: usize, replacement: &Action, counter: &mut usize) -> bool {
        if *counter == target {
            *self = replacement.clone();
            return true;
        }
        *counter += 1;
        match self {
            Action::Pass | Action::Drop => false,
            Action::Duplicate { left, right } | Action::Fragment { left, right, .. } => {
                left.replace_inner(target, replacement, counter)
                    || right.replace_inner(target, replacement, counter)
            }
            Action::Tamper { next, .. } | Action::TamperPayload { next, .. } => {
                next.replace_inner(target, replacement, counter)
            }
        }
    }
}

/// Payload bytes are carried as hex so a strategy stays one printable token.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

impl std::fmt::Display for TamperMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TamperMode::Replace(_) => write!(f, "replace"),
            TamperMode::Corrupt => write!(f, "corrupt"),
            TamperMode::Add(_) => write!(f, "add"),
        }
    }
}

impl FragmentOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            FragmentOrder::InOrder => "in-order",
            FragmentOrder::Reversed => "reversed",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text.trim() {
            "in-order" | "0" | "True" => Ok(FragmentOrder::InOrder),
            "reversed" | "1" | "False" => Ok(FragmentOrder::Reversed),
            other => Err(Error::Syntax(format!("unknown fragment order {other}"))),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Pass => Ok(()),
            Action::Drop => write!(f, "drop"),
            Action::Duplicate { left, right } => write!(f, "duplicate({left},{right})"),
            Action::Fragment {
                proto,
                offset,
                order,
                left,
                right,
            } => write!(
                f,
                "fragment{{{}:{}:{}}}({left},{right})",
                proto.as_str(),
                offset,
                order.as_str()
            ),
            Action::Tamper { field, mode, next } => {
                let value = match mode {
                    TamperMode::Corrupt => String::new(),
                    TamperMode::Add(v) => format!(":{v}"),
                    TamperMode::Replace(v) => {
                        // Fall back to the numeric form when the value carries a
                        // bit the letter form cannot express, so text always
                        // parses back to the same value.
                        let rendered = (*field == Field::TcpFlags)
                            .then(|| tcp_flags::render_exact(*v as u16))
                            .flatten()
                            .unwrap_or_else(|| v.to_string());
                        format!(":{rendered}")
                    }
                };
                write!(f, "tamper{{{field}:{mode}{value}}}({next})")
            }
            Action::TamperPayload { mode, next } => {
                let body = match mode {
                    PayloadMode::Corrupt => "corrupt".to_string(),
                    PayloadMode::Replace(bytes) => {
                        format!("replace:{}", hex_encode(bytes))
                    }
                    PayloadMode::Truncate(n) => format!("truncate:{n}"),
                };
                write!(f, "tamper{{TCP:load:{body}}}({next})")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Action {
        Action::Duplicate {
            left: Box::new(Action::Tamper {
                field: Field::TcpFlags,
                mode: TamperMode::Replace(u32::from(tcp_flags::RST)),
                next: Box::new(Action::Pass),
            }),
            right: Box::new(Action::Drop),
        }
    }

    #[test]
    fn renders_geneva_syntax() {
        assert_eq!(
            sample().to_string(),
            "duplicate(tamper{TCP:flags:replace:R}(),drop)"
        );
    }

    #[test]
    fn payload_tamper_renders_and_counts_like_any_node() {
        let a = Action::TamperPayload {
            mode: PayloadMode::Replace(b"ok".to_vec()),
            next: Box::new(Action::Pass),
        };
        assert_eq!(a.to_string(), "tamper{TCP:load:replace:6f6b}()");
        assert_eq!(a.depth(), 2);
        assert_eq!(a.size(), 2);
        assert_eq!(a.subtrees().len(), 2);

        let c = Action::TamperPayload {
            mode: PayloadMode::Corrupt,
            next: Box::new(Action::Drop),
        };
        assert_eq!(c.to_string(), "tamper{TCP:load:corrupt}(drop)");
        let t = Action::TamperPayload {
            mode: PayloadMode::Truncate(4),
            next: Box::new(Action::Pass),
        };
        assert_eq!(t.to_string(), "tamper{TCP:load:truncate:4}()");
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex_decode(&hex_encode(b"GET /x")).unwrap(), b"GET /x");
        assert_eq!(hex_decode("abc"), None, "odd length is not hex");
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn depth_and_size_count_the_whole_tree() {
        let a = sample();
        assert_eq!(a.depth(), 3); // duplicate -> tamper -> pass
        assert_eq!(a.size(), 4); // duplicate, tamper, pass, drop
        assert_eq!(Action::Pass.depth(), 1);
        assert!(a.check_depth().is_ok());
    }

    #[test]
    fn overly_deep_trees_are_rejected() {
        let mut a = Action::Pass;
        for _ in 0..MAX_DEPTH {
            a = Action::Tamper {
                field: Field::Ttl,
                mode: TamperMode::Corrupt,
                next: Box::new(a),
            };
        }
        assert_eq!(a.check_depth(), Err(Error::TooDeep(MAX_DEPTH)));
    }

    #[test]
    fn subtrees_are_enumerated_root_first() {
        let a = sample();
        let subs = a.subtrees();
        assert_eq!(subs.len(), a.size());
        assert!(matches!(subs[0], Action::Duplicate { .. }));
    }

    #[test]
    fn replacing_a_subtree_hits_the_indexed_node() {
        let mut a = sample();
        // index 3 is the `drop` branch (root, tamper, pass, drop)
        assert!(a.replace_subtree(3, Action::Pass));
        assert_eq!(a.to_string(), "duplicate(tamper{TCP:flags:replace:R}(),)");
        assert!(!a.replace_subtree(99, Action::Drop), "out of range");
    }

    #[test]
    fn replacing_the_root_replaces_everything() {
        let mut a = sample();
        assert!(a.replace_subtree(0, Action::Drop));
        assert_eq!(a, Action::Drop);
    }
}
