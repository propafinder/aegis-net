use super::native_test::Value;
use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

/// An authority that issued forms at a time: valid until `ttl` has passed,
/// destroyed by its first verification, like authd under the registered
/// non-shared rule.
struct FakeAuthority {
    now: Cell<u64>,
    ttl: u64,
    issued: RefCell<HashMap<[u8; EXTERNAL_FORM_LENGTH], u64>>,
    calls: Cell<u32>,
    next: Cell<u8>,
}
impl FakeAuthority {
    fn new(ttl: u64) -> Self {
        Self {
            now: Cell::new(100),
            ttl,
            issued: RefCell::new(HashMap::new()),
            calls: Cell::new(0),
            next: Cell::new(1),
        }
    }
    fn issue(&self) -> [u8; EXTERNAL_FORM_LENGTH] {
        let mut form = [0xA5; EXTERNAL_FORM_LENGTH];
        form[0] = self.next.get();
        self.next.set(self.next.get() + 1);
        self.issued.borrow_mut().insert(form, self.now.get());
        form
    }
}
impl FormVerifier for FakeAuthority {
    fn verify(&self, form: &[u8; EXTERNAL_FORM_LENGTH]) -> Result<(), &'static str> {
        self.calls.set(self.calls.get() + 1);
        let issued = self
            .issued
            .borrow_mut()
            .remove(form)
            .ok_or("identity_authorization_invalid")?;
        if self.now.get() >= issued + self.ttl {
            return Err("identity_authorization_expired");
        }
        Ok(())
    }
}

/// A verifier that admits every well-formed form, every time: only the
/// gate's own memory can refuse a replay to it.
#[derive(Default)]
struct Lenient {
    calls: Cell<u32>,
}
impl FormVerifier for Lenient {
    fn verify(&self, _: &[u8; EXTERNAL_FORM_LENGTH]) -> Result<(), &'static str> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

#[test]
fn identity_authorization_missing_or_malformed_is_refused_before_verification() {
    let gate = AuthorizationGate::new();
    let verifier = Lenient::default();
    assert_eq!(
        gate.admit(None, &verifier),
        Err("identity_authorization_missing")
    );
    for bytes in [
        &[][..],
        &[1; EXTERNAL_FORM_LENGTH - 1][..],
        &[1; EXTERNAL_FORM_LENGTH + 1][..],
        &[0; EXTERNAL_FORM_LENGTH][..],
    ] {
        assert_eq!(
            gate.admit(Some(bytes), &verifier),
            Err("identity_authorization_malformed"),
            "{} bytes",
            bytes.len()
        );
    }
    assert_eq!(verifier.calls.get(), 0);
    assert_eq!(gate.spent(), 0);
}

#[test]
fn identity_authorization_valid_form_is_accepted_once_and_its_replay_refused() {
    let gate = AuthorizationGate::new();
    let authority = FakeAuthority::new(30);
    let form = authority.issue();
    assert_eq!(gate.admit(Some(&form), &authority), Ok(()));
    assert_eq!(
        gate.admit(Some(&form), &authority),
        Err("identity_authorization_replayed")
    );
    // The replay never reached the authority.
    assert_eq!(authority.calls.get(), 1);
    // Even a verifier that would admit it again is never asked.
    let lenient = Lenient::default();
    let other = authority.issue();
    assert_eq!(gate.admit(Some(&other), &lenient), Ok(()));
    assert_eq!(
        gate.admit(Some(&other), &lenient),
        Err("identity_authorization_replayed")
    );
    assert_eq!(lenient.calls.get(), 1);
    // A second gate (a restarted provider) still meets the destroyed rights.
    assert_eq!(
        AuthorizationGate::new().admit(Some(&form), &authority),
        Err("identity_authorization_invalid")
    );
}

#[test]
fn identity_authorization_invalid_or_expired_form_is_refused_and_spent() {
    let gate = AuthorizationGate::new();
    let authority = FakeAuthority::new(30);
    // Never issued (forged, or another host's destroyed reference).
    let forged = [0x5A; EXTERNAL_FORM_LENGTH];
    assert_eq!(
        gate.admit(Some(&forged), &authority),
        Err("identity_authorization_invalid")
    );
    let late = authority.issue();
    authority.now.set(authority.now.get() + 30);
    assert_eq!(
        gate.admit(Some(&late), &authority),
        Err("identity_authorization_expired")
    );
    // A refused form is spent too: presenting it again is a replay.
    for form in [forged, late] {
        assert_eq!(
            gate.admit(Some(&form), &Lenient::default()),
            Err("identity_authorization_replayed")
        );
    }
    // Just inside the lifetime is admitted.
    let fresh = authority.issue();
    authority.now.set(authority.now.get() + 29);
    assert_eq!(gate.admit(Some(&fresh), &authority), Ok(()));
}

#[test]
fn identity_authorization_gate_remembers_a_bounded_number_of_digests() {
    let gate = AuthorizationGate::new();
    let verifier = Lenient::default();
    let form = |index: usize| {
        let mut form = [0xC3; EXTERNAL_FORM_LENGTH];
        form[..8].copy_from_slice(&(index as u64).to_be_bytes());
        form
    };
    for index in 0..=MAX_SPENT_FORMS {
        assert_eq!(gate.admit(Some(&form(index)), &verifier), Ok(()));
    }
    assert_eq!(gate.spent(), MAX_SPENT_FORMS);
    // The newest is remembered; only the oldest was evicted.
    assert_eq!(
        gate.admit(Some(&form(MAX_SPENT_FORMS)), &verifier),
        Err("identity_authorization_replayed")
    );
    assert_eq!(
        gate.admit(Some(&form(1)), &verifier),
        Err("identity_authorization_replayed")
    );
    assert_eq!(gate.admit(Some(&form(0)), &verifier), Ok(()));
}

#[test]
fn identity_authorization_rule_admits_only_a_non_shared_admin_authentication() {
    let registered = registered_definition(IDENTITY_RIGHT);
    assert!(right_admissible(&registered));
    // Stricter is still admissible.
    for timeout in [0, 1] {
        assert!(right_admissible(&RightDefinition {
            timeout: Some(timeout),
            ..registered.clone()
        }));
    }
    assert!(right_admissible(&RightDefinition {
        authenticate_user: None,
        allow_root: None,
        session_owner: None,
        ..registered.clone()
    }));
    type Weaken = fn(&mut RightDefinition);
    let weakened: [(&str, Weaken); 16] = [
        ("class allow", |d| d.class = Some("allow".into())),
        ("class rule", |d| d.class = Some("rule".into())),
        ("class absent", |d| d.class = None),
        ("group staff", |d| d.group = Some("staff".into())),
        ("group absent", |d| d.group = None),
        ("shared", |d| d.shared = Some(true)),
        ("shared absent", |d| d.shared = None),
        ("timeout long", |d| d.timeout = Some(RIGHT_TIMEOUT_SECS + 1)),
        ("timeout negative", |d| d.timeout = Some(-1)),
        ("timeout absent", |d| d.timeout = None),
        ("no authentication", |d| d.authenticate_user = Some(false)),
        ("root", |d| d.allow_root = Some(true)),
        ("session owner", |d| d.session_owner = Some(true)),
        ("delegated", |d| d.escalating = true),
        ("malformed", |d| d.malformed = true),
        ("empty", |d| *d = RightDefinition::default()),
    ];
    for (name, weaken) in weakened {
        let mut definition = registered.clone();
        weaken(&mut definition);
        assert!(!right_admissible(&definition), "{name}");
    }
}

/// v30: the AEGIS rights need a password-only rule with exactly their own
/// prompt; the v26 to v29 shape (Touch ID allowed) is refused.
#[test]
fn identity_authorization_aegis_rights_need_password_only_and_their_own_prompt() {
    for right in [IDENTITY_RIGHT, FILTER_RIGHT] {
        let registered = registered_definition(right);
        assert!(aegis_right_admissible(right, &registered), "{right:?}");
        assert_eq!(host_right_admitted(right, Some(&registered)), Ok(()));
        let other = if right == IDENTITY_RIGHT {
            FILTER_RIGHT
        } else {
            IDENTITY_RIGHT
        };
        type Weaken = fn(&mut RightDefinition);
        let weakened: [(&str, Weaken); 6] = [
            ("v26 shape: no password-only", |d| d.password_only = None),
            ("password-only false", |d| d.password_only = Some(false)),
            ("no prompt", |d| d.default_prompt = None),
            ("another prompt", |d| {
                d.default_prompt = Some("approve a routine update".into())
            }),
            ("a localized prompt beside it", |d| {
                d.prompt_localized = true
            }),
            ("shared", |d| d.shared = Some(true)),
        ];
        for (name, weaken) in weakened {
            let mut definition = registered.clone();
            weaken(&mut definition);
            assert!(!aegis_right_admissible(right, &definition), "{name}");
        }
        // One right's rule never stands in for the other's.
        assert!(!aegis_right_admissible(
            other,
            &registered_definition(right)
        ));
    }
    assert_ne!(IDENTITY_RIGHT, LEGACY_IDENTITY_RIGHT);
    assert_ne!(FILTER_RIGHT, LEGACY_FILTER_RIGHT);
    assert_ne!(IDENTITY_RIGHT, FILTER_RIGHT);
    for legacy in LEGACY_AUTHORIZATION_KEYS {
        assert_ne!(legacy, AUTHORIZATION_KEY);
    }
}

#[test]
fn identity_authorization_registered_cf_definitions_parse_back_admissible() {
    for right in [IDENTITY_RIGHT, FILTER_RIGHT] {
        let parsed = native_test::registered_round_trip(right);
        assert_eq!(parsed, registered_definition(right), "{right:?}");
        assert_eq!(parsed.password_only, Some(true));
        assert_eq!(host_right_admitted(right, Some(&parsed)), Ok(()));
    }
}

/// v30 audit merge: absent or weaker than the rule the host registers
/// refuses, with the right's own codes; the registered rule passes. The
/// leak-guard prompt names the leak guard, never the identity.
#[test]
fn identity_authorization_host_admits_only_the_registered_strict_rule() {
    for (right, unregistered, inadmissible) in [
        (
            FILTER_RIGHT,
            "filter_authorization_right_unregistered",
            "filter_authorization_right_inadmissible",
        ),
        (
            IDENTITY_RIGHT,
            "identity_authorization_right_unregistered",
            "identity_authorization_right_inadmissible",
        ),
    ] {
        assert_eq!(host_right_admitted(right, None), Err(unregistered));
        let registered = registered_definition(right);
        for weaken in [
            (|d: &mut RightDefinition| d.shared = Some(true)) as fn(&mut RightDefinition),
            |d| d.allow_root = Some(true),
            |d| d.session_owner = Some(true),
            |d| d.group = Some("staff".into()),
            |d| d.escalating = true,
            |d| d.timeout = Some(RIGHT_TIMEOUT_SECS + 1),
            |d| d.password_only = None,
        ] {
            let mut definition = registered.clone();
            weaken(&mut definition);
            assert_eq!(
                host_right_admitted(right, Some(&definition)),
                Err(inadmissible),
                "{definition:?}"
            );
        }
    }
    let (filter_prompt, filter_comment) = right_text(FILTER_RIGHT);
    let (identity_prompt, identity_comment) = right_text(IDENTITY_RIGHT);
    assert_eq!(identity_prompt, c"change the AEGIS VPN device identity");
    assert!(filter_prompt.to_str().unwrap().contains("leak guard"));
    assert!(!filter_prompt.to_str().unwrap().contains("identity"));
    assert!(filter_comment.to_str().unwrap().contains("leak guard"));
    assert_ne!(filter_comment, identity_comment);
}

#[test]
fn identity_authorization_parser_reads_rule_lists_prompts_and_types() {
    use Value::*;
    let proof = native_test::parse_entries(&[
        ("class", Text("rule")),
        ("k-of-n", Number(1)),
        ("rule", List(&PROOF_DELEGATES)),
        ("version", Number(2)),
        (
            "comment",
            Text("For making change to network configuration."),
        ),
    ]);
    assert_eq!(proof.class.as_deref(), Some("rule"));
    assert_eq!(proof.k_of_n, Some(1));
    assert_eq!(
        proof.rules,
        Some(PROOF_DELEGATES.map(String::from).to_vec())
    );
    assert!(proof.escalating && !proof.malformed && !proof.entitlement_keys);
    // One name instead of a list is still a delegate.
    let single = native_test::parse_entries(&[("rule", Text("authenticate-admin-nonshared"))]);
    assert_eq!(
        single.rules,
        Some(vec!["authenticate-admin-nonshared".into()])
    );
    let entitled = native_test::parse_entries(&[
        ("class", Text("evaluate-mechanisms")),
        ("mechanisms", List(&[ENTITLED_MECHANISM])),
        ("shared", Flag(true)),
        ("tries", Number(1)),
    ]);
    assert_eq!(entitled.mechanisms, Some(vec![ENTITLED_MECHANISM.into()]));
    let prompt = native_test::parse_entries(&[
        ("class", Text("user")),
        ("password-only", Flag(true)),
        (
            "default-prompt",
            Prompts(&[("", "change the AEGIS VPN device identity")]),
        ),
    ]);
    assert_eq!(prompt.password_only, Some(true));
    assert_eq!(
        prompt.default_prompt.as_deref(),
        Some("change the AEGIS VPN device identity")
    );
    assert!(!prompt.prompt_localized && !prompt.malformed);
    let localized = native_test::parse_entries(&[(
        "default-prompt",
        Prompts(&[
            ("", "change the AEGIS VPN device identity"),
            ("fr", "autre"),
        ]),
    )]);
    assert!(localized.prompt_localized);
    let only_localized = native_test::parse_entries(&[("default-prompt", Prompts(&[("de", "x")]))]);
    assert!(only_localized.prompt_localized);
    assert_eq!(only_localized.default_prompt, None);
    // Wrong types are malformed, never read as absent.
    for (key, value) in [
        ("k-of-n", Text("1")),
        ("rule", Number(3)),
        ("mechanisms", Text(ENTITLED_MECHANISM)),
        ("password-only", Text("true")),
        (
            "default-prompt",
            Text("change the AEGIS VPN device identity"),
        ),
        ("timeout", Flag(false)),
    ] {
        let parsed = native_test::parse_entries(&[(key, value)]);
        assert!(parsed.malformed, "{key}");
    }
    for key in ["entitled", "entitled-group", "vpn-entitled-group"] {
        let parsed = native_test::parse_entries(&[(key, Flag(true))]);
        assert!(parsed.entitlement_keys && parsed.escalating, "{key}");
    }
}

/// Apple's rules as `security authorizationdb read` shows them on macOS
/// 26.5 (25F84).
fn apple_rules() -> HashMap<String, RightDefinition> {
    let user =
        |group: Option<&str>, authenticate: bool, root: bool, timeout: i64| RightDefinition {
            class: Some("user".into()),
            group: group.map(str::to_owned),
            shared: Some(false),
            timeout: Some(timeout),
            authenticate_user: Some(authenticate),
            allow_root: Some(root),
            session_owner: Some(false),
            ..RightDefinition::default()
        };
    HashMap::from([
        (
            PROOF_RIGHT.to_str().unwrap().to_owned(),
            RightDefinition {
                class: Some("rule".into()),
                k_of_n: Some(1),
                rules: Some(PROOF_DELEGATES.map(String::from).to_vec()),
                escalating: true,
                ..RightDefinition::default()
            },
        ),
        ("is-root".into(), user(None, false, true, 2_147_483_647)),
        (
            "entitled".into(),
            RightDefinition {
                class: Some("evaluate-mechanisms".into()),
                shared: Some(true),
                mechanisms: Some(vec![ENTITLED_MECHANISM.into()]),
                escalating: true,
                ..RightDefinition::default()
            },
        ),
        (
            "_mbsetupuser-nonshared".into(),
            user(Some("_mbsetupuser"), false, false, 30),
        ),
        (
            PROOF_ADMIN_DELEGATE.into(),
            user(Some("admin"), true, false, 30),
        ),
    ])
}

fn reader(
    rules: &HashMap<String, RightDefinition>,
) -> impl Fn(&CStr) -> Result<Option<RightDefinition>, &'static str> + '_ {
    |right: &CStr| Ok(rules.get(right.to_str().unwrap()).cloned())
}

#[test]
fn identity_authorization_proof_rule_admits_only_apples_shape() {
    let apple = apple_rules();
    assert_eq!(proof_rule_admitted(reader(&apple)), Ok(()));
    assert_eq!(proof_rule_state(reader(&apple)), "admitted");
    // Fewer known delegates (an older macOS) still pass while the admin one is kept.
    let mut fewer = apple.clone();
    fewer.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().rules =
        Some(vec!["is-root".into(), PROOF_ADMIN_DELEGATE.into()]);
    assert_eq!(proof_rule_admitted(reader(&fewer)), Ok(()));
    let proof = PROOF_RIGHT.to_str().unwrap();
    type Edit = fn(&mut HashMap<String, RightDefinition>);
    let edits: [(&str, Edit); 22] = [
        ("absent", |r| {
            r.remove(PROOF_RIGHT.to_str().unwrap());
        }),
        ("k-of-n 0", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().k_of_n = Some(0)
        }),
        ("k-of-n 2", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().k_of_n = Some(2)
        }),
        ("k-of-n missing", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().k_of_n = None
        }),
        ("class user", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().class = Some("user".into())
        }),
        ("no delegates", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().rules = None
        }),
        ("unknown delegate", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap())
                .unwrap()
                .rules
                .as_mut()
                .unwrap()
                .push("allow".into())
        }),
        ("admin delegate missing", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().rules =
                Some(vec!["is-root".into(), "entitled".into()])
        }),
        ("top-level mechanisms", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().mechanisms =
                Some(vec!["builtin:authenticate".into()])
        }),
        ("top-level entitled", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap())
                .unwrap()
                .entitlement_keys = true
        }),
        ("malformed", |r| {
            r.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().malformed = true
        }),
        ("admin shared", |r| {
            r.get_mut(PROOF_ADMIN_DELEGATE).unwrap().shared = Some(true)
        }),
        ("admin timeout 300", |r| {
            r.get_mut(PROOF_ADMIN_DELEGATE).unwrap().timeout = Some(300)
        }),
        ("admin allow-root", |r| {
            r.get_mut(PROOF_ADMIN_DELEGATE).unwrap().allow_root = Some(true)
        }),
        ("admin session owner", |r| {
            r.get_mut(PROOF_ADMIN_DELEGATE).unwrap().session_owner = Some(true)
        }),
        ("admin delegate undefined", |r| {
            r.remove(PROOF_ADMIN_DELEGATE);
        }),
        ("is-root with a group", |r| {
            r.get_mut("is-root").unwrap().group = Some("staff".into())
        }),
        ("is-root authenticates", |r| {
            r.get_mut("is-root").unwrap().authenticate_user = Some(true)
        }),
        ("is-root session owner", |r| {
            r.get_mut("is-root").unwrap().session_owner = Some(true)
        }),
        ("_mbsetupuser group admin", |r| {
            r.get_mut("_mbsetupuser-nonshared").unwrap().group = Some("admin".into())
        }),
        ("entitled other mechanism", |r| {
            r.get_mut("entitled").unwrap().mechanisms = Some(vec!["builtin:authenticate".into()])
        }),
        ("entitled delegates", |r| {
            r.get_mut("entitled").unwrap().rules = Some(vec!["allow".into()])
        }),
    ];
    for (name, edit) in edits {
        let mut rules = apple.clone();
        edit(&mut rules);
        assert_eq!(
            proof_rule_admitted(reader(&rules)),
            Err("identity_authorization_proof_rule_unexpected"),
            "{name}"
        );
        assert_eq!(proof_rule_state(reader(&rules)), "unexpected", "{name}");
    }
    assert!(apple.contains_key(proof));
    // A reader that fails is unavailable, never admitted.
    let failing = |_: &CStr| Err("identity_authorization_unavailable");
    assert_eq!(
        proof_rule_admitted(failing),
        Err("identity_authorization_unavailable")
    );
    assert_eq!(proof_rule_state(failing), "unavailable");
}

#[test]
fn identity_authorization_identity_rule_state_reports_each_case() {
    let mut rules = HashMap::new();
    assert_eq!(identity_rule_state(reader(&rules)), "unregistered");
    rules.insert(
        IDENTITY_RIGHT.to_str().unwrap().to_owned(),
        registered_definition(IDENTITY_RIGHT),
    );
    assert_eq!(identity_rule_state(reader(&rules)), "admitted");
    rules.insert(
        IDENTITY_RIGHT.to_str().unwrap().to_owned(),
        RightDefinition {
            password_only: None,
            ..registered_definition(IDENTITY_RIGHT)
        },
    );
    assert_eq!(identity_rule_state(reader(&rules)), "inadmissible");
    assert_eq!(
        identity_rule_state(|_: &CStr| Err("identity_authorization_unavailable")),
        "unavailable"
    );
}

/// The proof statuses the provider tells apart; everything else is invalid.
#[test]
fn identity_authorization_proof_status_and_probe_names_each_outcome() {
    assert_eq!(proof_status(0), Ok(()));
    assert_eq!(proof_status(-60007), Err("identity_authorization_expired"));
    assert_eq!(proof_status(-60005), Err("identity_authorization_denied"));
    for status in [-60006, -60008, -60001, -60033, 1] {
        assert_eq!(proof_status(status), Err("identity_authorization_invalid"));
    }
    assert_eq!(ProofProbe::of_status(0), ProofProbe::Allowed);
    assert_eq!(ProofProbe::of_status(-60005), ProofProbe::Denied);
    assert_eq!(ProofProbe::of_status(-60007), ProofProbe::Failed(-60007));
    for (probe, token, status) in [
        (ProofProbe::Allowed, "allowed", Some(0)),
        (ProofProbe::Denied, "denied", Some(-60005)),
        (ProofProbe::Failed(-60008), "failed", Some(-60008)),
        (ProofProbe::Unavailable, "unavailable", None),
    ] {
        assert_eq!((probe.token(), probe.status()), (token, status));
    }
}

/// v30 review: a failed or unavailable probe (an authd error while the
/// provider starts) was kept for the whole provider process and closed the
/// identity gate until a restart. Only allowed and denied are kept.
#[test]
fn identity_authorization_probe_keeps_only_an_answer_and_retries_a_failure() {
    for answer in [ProofProbe::Allowed, ProofProbe::Denied] {
        let cache = ProbeCache::new();
        let calls = Cell::new(0);
        let script = [
            ProofProbe::Failed(-60008),
            ProofProbe::Unavailable,
            ProofProbe::Failed(-60001),
            answer,
        ];
        let probe = || {
            let next = script[calls.get()];
            calls.set(calls.get() + 1);
            next
        };
        for expected in script {
            assert_eq!(cache.get_or_probe(probe), expected);
        }
        assert_eq!(calls.get(), 4);
        // Kept from then on: no further probe runs.
        for _ in 0..3 {
            assert_eq!(cache.get_or_probe(|| unreachable!("answer kept")), answer);
        }
        assert_eq!(calls.get(), 4);
    }
    for (probe, answer) in [
        (ProofProbe::Allowed, true),
        (ProofProbe::Denied, true),
        (ProofProbe::Failed(-60006), false),
        (ProofProbe::Unavailable, false),
    ] {
        assert_eq!(probe.is_answer(), answer, "{probe:?}");
    }
    // The provider's probe goes through the cache, never a once-only cell.
    let source = include_str!("identity_authorization.rs");
    let body = source
        .split("pub(crate) fn proof_probe() -> ProofProbe {")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("proof_probe body");
    assert!(body.contains("static PROBE: ProbeCache"), "{body}");
    assert!(
        !source.contains("OnceLock"),
        "a once-only cell keeps a failure"
    );
}

/// v30: the provider's verifier reads the identity rule, then the proof
/// rule, then copies the form for `PROOF_RIGHT` alone; each failure
/// refuses, and through the gate the form stays spent.
#[test]
fn identity_authorization_provider_verifier_checks_rules_before_the_form() {
    let mut rules = apple_rules();
    rules.insert(
        IDENTITY_RIGHT.to_str().unwrap().to_owned(),
        registered_definition(IDENTITY_RIGHT),
    );
    let log = RefCell::new(Vec::<String>::new());
    let status = Cell::new(0);
    let make = |rules: HashMap<String, RightDefinition>| {
        let log = &log;
        let status = &status;
        ProofVerifier {
            read: move |right: &CStr| -> Result<Option<RightDefinition>, &'static str> {
                log.borrow_mut()
                    .push(format!("read {}", right.to_str().unwrap()));
                Ok(rules.get(right.to_str().unwrap()).cloned())
            },
            copy: move |_: &[u8; EXTERNAL_FORM_LENGTH],
                        right: &CStr|
                  -> Result<i32, &'static str> {
                log.borrow_mut()
                    .push(format!("copy {}", right.to_str().unwrap()));
                Ok(status.get())
            },
        }
    };
    let gate = AuthorizationGate::new();
    let form = test_support::fresh_form();
    assert_eq!(gate.admit(Some(&form), &make(rules.clone())), Ok(()));
    let calls = log.take();
    assert_eq!(
        calls[0],
        format!("read {}", IDENTITY_RIGHT.to_str().unwrap())
    );
    assert_eq!(calls[1], format!("read {}", PROOF_RIGHT.to_str().unwrap()));
    assert_eq!(
        calls.last().unwrap(),
        &format!("copy {}", PROOF_RIGHT.to_str().unwrap())
    );
    assert_eq!(calls.iter().filter(|c| c.starts_with("copy ")).count(), 1);
    assert!(!calls
        .iter()
        .any(|c| c.contains("dev.aegis") && c.starts_with("copy")));
    assert_eq!(
        gate.admit(Some(&form), &make(rules.clone())),
        Err("identity_authorization_replayed")
    );
    // Each refusal comes before the copy, or is the copy's own.
    let mut weak = rules.clone();
    weak.insert(
        IDENTITY_RIGHT.to_str().unwrap().to_owned(),
        RightDefinition {
            password_only: None,
            ..registered_definition(IDENTITY_RIGHT)
        },
    );
    let mut absent = rules.clone();
    absent.remove(IDENTITY_RIGHT.to_str().unwrap());
    let mut proof = rules.clone();
    proof.get_mut(PROOF_RIGHT.to_str().unwrap()).unwrap().k_of_n = Some(2);
    for (rules, code) in [
        (weak, "identity_authorization_right_inadmissible"),
        (absent, "identity_authorization_right_unregistered"),
        (proof, "identity_authorization_proof_rule_unexpected"),
    ] {
        let form = test_support::fresh_form();
        assert_eq!(gate.admit(Some(&form), &make(rules)), Err(code));
        assert!(!log.take().iter().any(|c| c.starts_with("copy ")), "{code}");
        assert_eq!(
            gate.admit(Some(&form), &Lenient::default()),
            Err("identity_authorization_replayed")
        );
    }
    for (raw, code) in [
        (-60007, "identity_authorization_expired"),
        (-60005, "identity_authorization_denied"),
        (-60008, "identity_authorization_invalid"),
    ] {
        status.set(raw);
        let form = test_support::fresh_form();
        assert_eq!(gate.admit(Some(&form), &make(rules.clone())), Err(code));
        assert!(log.take().last().unwrap().starts_with("copy "));
    }
    assert_eq!(PROVIDER_COPY_RIGHTS, [PROOF_RIGHT]);
}

/// The host's Authorization Services, faked: a call log, rules, and the
/// status of each copy.
struct FakeHost {
    log: RefCell<Vec<String>>,
    rules: RefCell<HashMap<String, RightDefinition>>,
    register: Result<(), &'static str>,
    prompt_status: i32,
    proof_status: i32,
}
impl FakeHost {
    fn new() -> Self {
        Self {
            log: RefCell::new(Vec::new()),
            rules: RefCell::new(apple_rules()),
            register: Ok(()),
            prompt_status: 0,
            proof_status: 0,
        }
    }
}
impl HostAuthority for FakeHost {
    type Reference = u32;
    fn create(&self) -> Result<u32, &'static str> {
        self.log.borrow_mut().push("create".into());
        Ok(7)
    }
    fn read(&self, right: &CStr) -> Result<Option<RightDefinition>, &'static str> {
        Ok(self.rules.borrow().get(right.to_str().unwrap()).cloned())
    }
    fn register(&self, _: &u32, right: &CStr) -> Result<(), &'static str> {
        self.log
            .borrow_mut()
            .push(format!("register {}", right.to_str().unwrap()));
        self.register?;
        self.rules
            .borrow_mut()
            .insert(right.to_str().unwrap().into(), registered_definition(right));
        Ok(())
    }
    fn copy(&self, _: &u32, right: &CStr, interactive: bool, prompt: Option<&CStr>) -> i32 {
        self.log.borrow_mut().push(format!(
            "copy {} interactive={interactive} prompt={}",
            right.to_str().unwrap(),
            prompt.is_some()
        ));
        if interactive {
            self.prompt_status
        } else {
            self.proof_status
        }
    }
    fn external_form(&self, _: &u32) -> Result<[u8; EXTERNAL_FORM_LENGTH], &'static str> {
        self.log.borrow_mut().push("form".into());
        Ok([0x42; EXTERNAL_FORM_LENGTH])
    }
}

#[test]
fn identity_authorization_host_prompts_once_then_proves_before_making_a_form() {
    let host = FakeHost::new();
    let prompt = IdentityChange::Forget.prompt();
    let (_, form) = host_approve(&host, IDENTITY_RIGHT, Some(&prompt)).unwrap();
    assert_eq!(form, Some([0x42; EXTERNAL_FORM_LENGTH]));
    let identity = IDENTITY_RIGHT.to_str().unwrap();
    let proof = PROOF_RIGHT.to_str().unwrap();
    assert_eq!(
        *host.log.borrow(),
        [
            "create".to_owned(),
            format!("register {identity}"),
            format!("copy {identity} interactive=true prompt=true"),
            format!("copy {proof} interactive=false prompt=false"),
            "form".to_owned(),
        ]
    );
    // Registered already: no second registration, still one prompt.
    host.log.borrow_mut().clear();
    host_approve(&host, IDENTITY_RIGHT, Some(&prompt)).unwrap();
    assert_eq!(
        host.log
            .borrow()
            .iter()
            .filter(|c| c.contains("interactive=true"))
            .count(),
        1
    );
    assert!(!host.log.borrow().iter().any(|c| c.starts_with("register")));
    // The leak guard's right: one prompt, no proof, no form.
    let host = FakeHost::new();
    let (_, form) = host_approve(&host, FILTER_RIGHT, None).unwrap();
    assert_eq!(form, None);
    assert_eq!(
        host.log.borrow()[2..],
        [format!(
            "copy {} interactive=true prompt=false",
            FILTER_RIGHT.to_str().unwrap()
        )]
    );
}

#[test]
fn identity_authorization_host_refuses_before_any_prompt_or_without_proof() {
    let identity = IDENTITY_RIGHT.to_str().unwrap().to_owned();
    let prompted = |host: &FakeHost| {
        host.log
            .borrow()
            .iter()
            .any(|c| c.contains("interactive=true"))
    };
    let formed = |host: &FakeHost| host.log.borrow().iter().any(|c| c == "form");
    // An inadmissible identity rule (registered first by someone else).
    let host = FakeHost::new();
    host.rules.borrow_mut().insert(
        identity.clone(),
        RightDefinition {
            password_only: None,
            ..registered_definition(IDENTITY_RIGHT)
        },
    );
    assert_eq!(
        host_approve(&host, IDENTITY_RIGHT, None).err(),
        Some("identity_authorization_right_inadmissible")
    );
    assert!(!prompted(&host));
    // A registration that fails.
    let host = FakeHost {
        register: Err("x"),
        ..FakeHost::new()
    };
    assert_eq!(
        host_approve(&host, IDENTITY_RIGHT, None).err(),
        Some("identity_authorization_right_unregistered")
    );
    assert!(!prompted(&host));
    // An unexpected proof rule.
    let host = FakeHost::new();
    host.rules
        .borrow_mut()
        .get_mut(PROOF_RIGHT.to_str().unwrap())
        .unwrap()
        .k_of_n = Some(2);
    assert_eq!(
        host_approve(&host, IDENTITY_RIGHT, None).err(),
        Some("identity_authorization_proof_rule_unexpected")
    );
    assert!(!prompted(&host));
    // The prompt cancelled or denied; the proof failing after the prompt.
    for (prompt_status, proof_status, code) in [
        (-60006, 0, "identity_authorization_cancelled"),
        (-60005, 0, "identity_authorization_denied"),
        (-60007, 0, "identity_authorization_denied"),
        (0, -60007, "identity_authorization_unprovable"),
        (0, -60005, "identity_authorization_unprovable"),
    ] {
        let host = FakeHost {
            prompt_status,
            proof_status,
            ..FakeHost::new()
        };
        assert_eq!(host_approve(&host, IDENTITY_RIGHT, None).err(), Some(code));
        assert!(!formed(&host), "{code}");
    }
    // The filter right keeps its own codes.
    let host = FakeHost {
        prompt_status: -60006,
        ..FakeHost::new()
    };
    assert_eq!(
        host_approve(&host, FILTER_RIGHT, None).err(),
        Some("filter_authorization_cancelled")
    );
}

#[test]
fn identity_authorization_prompts_name_the_change_and_never_a_path() {
    let forget = IdentityChange::Forget.prompt();
    let renew = IdentityChange::Renew.prompt();
    let import =
        IdentityChange::import_of(std::path::Path::new("/Users/x/private/aegis-src 1")).prompt();
    let bare = IdentityChange::Import { source: None }.prompt();
    let texts: Vec<&str> = [&forget, &renew, &import, &bare]
        .iter()
        .map(|t| t.to_str().unwrap())
        .collect();
    assert!(texts[0].contains("forget-identity") && texts[0].contains("remove"));
    assert!(texts[1].contains("(renew)"));
    assert!(texts[2].contains("\"aegis-src 1\"") && !texts[2].contains("/Users"));
    assert!(texts[3].contains("(import)") && !texts[3].contains('"'));
    for text in &texts {
        assert!(text.is_ascii() && text.starts_with("AEGIS will "), "{text}");
        assert!(text.ends_with("only if you started this."), "{text}");
    }
    let names: std::collections::BTreeSet<_> = texts.iter().collect();
    assert_eq!(names.len(), 4);
    // A name that is long, a link-like path or not plain ASCII is left out.
    for dir in [
        "/a/".to_owned() + &"x".repeat(65),
        "/a/b\"c".into(),
        "/a/naïve".into(),
        "/".into(),
    ] {
        assert_eq!(
            IdentityChange::import_of(std::path::Path::new(&dir)),
            IdentityChange::Import { source: None },
            "{dir}"
        );
    }
}

/// Source pins: the provider copies only `PROOF_RIGHT`, never writes the
/// authorization database or asks for interaction, and S23 renewal never
/// touches Authorization Services.
#[test]
fn identity_authorization_provider_never_writes_or_prompts() {
    let source = include_str!("identity_authorization.rs");
    let provider = source
        .split("// Provider side.")
        .nth(1)
        .and_then(|rest| rest.split("// Host side.").next())
        .unwrap();
    for forbidden in [
        "write_right",
        "AuthorizationRightSet",
        "FLAG_INTERACTION_ALLOWED",
        "IDENTITY_RIGHT",
    ] {
        assert!(!provider.contains(forbidden), "{forbidden}");
    }
    let verifier = source
        .split("impl<R, C> FormVerifier for ProofVerifier<R, C>")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .unwrap();
    assert!(verifier.contains("for right in PROVIDER_COPY_RIGHTS"));
    assert!(!verifier.contains("write_right") && !verifier.contains("register"));
    let xpc = include_str!("provider_xpc.rs");
    for forbidden in [
        "approve_identity_change",
        "approve_filter_weakening",
        "write_right",
    ] {
        assert!(!xpc.contains(forbidden), "{forbidden}");
    }
    let renewal = include_str!("identity_renewal.rs");
    for forbidden in ["Authorization", "identity_authorization", "authorization::"] {
        assert!(!renewal.contains(forbidden), "{forbidden}");
    }
}

/// The regression test v26 lacked: the shipped App Sandbox profile lets a
/// network-extension holder obtain every right the provider copies, and no
/// AEGIS right.
#[test]
fn identity_authorization_the_sandbox_profile_allows_every_provider_right() {
    let Ok(profile) = std::fs::read_to_string("/System/Library/Sandbox/Profiles/application.sb")
    else {
        eprintln!("application.sb absent: sandbox profile pin not run here");
        return;
    };
    // Each balanced `(when ...` form whose condition names the entitlement.
    let mut clauses = Vec::new();
    for (start, _) in profile.match_indices("(when ") {
        let mut depth = 0usize;
        let mut end = None;
        for (offset, byte) in profile[start..].bytes().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(start + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let clause = &profile[start..end.unwrap()];
        let condition = clause.split("(allow").next().unwrap();
        if condition.contains("(entitlement \"com.apple.developer.networking.networkextension\")") {
            clauses.push(clause);
        }
    }
    for right in PROVIDER_COPY_RIGHTS {
        let name = format!("(right-name \"{}\")", right.to_str().unwrap());
        assert!(
            clauses.iter().any(|clause| clause
                .split("(allow authorization-right-obtain")
                .skip(1)
                .any(|allowed| allowed.contains(&name))),
            "{name} is not allowed for network-extension holders"
        );
    }
    assert!(!profile.contains("dev.aegis"));
}

#[test]
fn identity_authorization_parser_judges_the_system_rules_read_only() {
    let Some(nonshared) = native_test::authd_reachable(read_right(c"authenticate-admin-nonshared"))
    else {
        return;
    };
    // Apple's own non-shared admin rule has the registered shape.
    let nonshared = nonshared.expect("authenticate-admin-nonshared is defined");
    assert_eq!(nonshared.class.as_deref(), Some("user"));
    assert_eq!(nonshared.shared, Some(false));
    assert!(right_admissible(&nonshared), "{nonshared:?}");
    // ...but it is no AEGIS rule: not password-only, no AEGIS prompt.
    assert!(!aegis_right_admissible(IDENTITY_RIGHT, &nonshared));
    // Shared, allow-everyone and delegating rules are not.
    for right in [c"authenticate-admin", c"config.add.", c"config.modify."] {
        let definition = read_right(right).unwrap().expect("system rule defined");
        assert!(!right_admissible(&definition), "{right:?}: {definition:?}");
    }
    assert!(read_right(c"config.modify.").unwrap().unwrap().escalating);
    assert_eq!(
        read_right(c"dev.aegis.macos.never-registered-right"),
        Ok(None)
    );
    // This Mac's proof rule has the shape the provider pins (fails loudly
    // on a macOS whose rule differs, before any installed run).
    assert_eq!(
        proof_rule_admitted(read_right),
        Ok(()),
        "{:?}",
        read_right(PROOF_RIGHT)
    );
}

#[test]
fn identity_authorization_native_form_without_a_live_credential_is_expired() {
    if unsafe { libc::geteuid() } == 0 {
        return; // is-root grants a root creator without a credential
    }
    // Garbage that no authd reference has: not a reference at all (and
    // refused just the same when authd refuses this binary).
    assert!(!matches!(
        copy_external(&[0x7E; EXTERNAL_FORM_LENGTH], PROOF_RIGHT),
        Ok(0)
    ));
    let Some((form, _held)) = native_test::uncredentialed_form() else {
        return;
    };
    // A real reference with no credential, checked without interaction (no
    // prompt can appear): for this unsandboxed, non-root creator only the
    // missing credential refuses it, never the sandbox.
    let status = copy_external(&form, PROOF_RIGHT).unwrap();
    assert_eq!(
        proof_status(status),
        Err("identity_authorization_expired"),
        "status {status}"
    );
    // Through the gate with the native verifier: refused once, then a
    // replay (the identity rule may be unregistered on this Mac).
    let gate = AuthorizationGate::new();
    let (form, _held) = native_test::uncredentialed_form().unwrap();
    assert!(gate.admit(Some(&form), &native_verifier()).is_err());
    assert_eq!(
        gate.admit(Some(&form), &native_verifier()),
        Err("identity_authorization_replayed")
    );
}
