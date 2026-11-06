use super::*;
use crate::app_group::{HOST_BUNDLE_ID, PROVIDER_BUNDLE_ID};
use crate::{bridge::LeasedPacketBridge, bridge::PacketBridge, provider_session::SessionHandle};
use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
use objc2_foundation::NSString;
use std::{
    cell::RefCell,
    ffi::CString,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

type CfRef = *const c_void;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecRequirementCreateWithString(text: CfRef, flags: u32, requirement: *mut CfRef) -> i32;
    fn SecRequirementCopyString(requirement: CfRef, flags: u32, text: *mut CfRef) -> i32;
    fn SecCodeCopySelf(flags: u32, code: *mut CfRef) -> i32;
    fn SecCodeCheckValidity(code: CfRef, flags: u32, requirement: CfRef) -> i32;
    fn SecCodeCopyDesignatedRequirement(code: CfRef, flags: u32, requirement: *mut CfRef) -> i32;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CfRef);
}
// Test-only libxpc constructors: in-process objects, no Mach service lookup.
unsafe extern "C" {
    fn xpc_connection_create(name: *const c_char, targetq: *mut c_void) -> XpcObject;
    fn xpc_endpoint_create(connection: XpcObject) -> XpcObject;
    fn xpc_connection_create_from_endpoint(endpoint: XpcObject) -> XpcObject;
    fn xpc_dictionary_set_string(dictionary: XpcObject, key: *const c_char, value: *const c_char);
    fn xpc_data_create(bytes: *const c_void, length: usize) -> XpcObject;
}

fn ping_report() -> PingReport {
    PingReport {
        euid: 0,
        sandboxed: true,
        container_url: Some(
            "file:///private/var/root/Library/Group%20Containers/group.TEAMID0000.dev.aegis.macos/"
                .into(),
        ),
        container_realpath: Some(
            "/private/var/root/Library/Group Containers/group.TEAMID0000.dev.aegis.macos".into(),
        ),
        realpath_errno: 0,
        custody: vec![
            CustodyStep {
                component: "/".into(),
                errno: 0,
            },
            CustodyStep {
                component: "private".into(),
                errno: 0,
            },
            CustodyStep {
                component: "var".into(),
                errno: libc::EPERM,
            },
        ],
        container_ancestors: vec![
            AncestorStep {
                component: "/".into(),
                lstat_errno: 0,
                policy_ok: true,
            },
            AncestorStep {
                component: "private".into(),
                lstat_errno: libc::EPERM,
                policy_ok: false,
            },
            AncestorStep {
                component: "Group Containers".into(),
                lstat_errno: 0,
                policy_ok: false,
            },
        ],
        container_open: Some(ContainerOpenProbe {
            errno: 0,
            getpath_errno: 0,
            path_matched: true,
            admitted: true,
        }),
        loopback_listen: ListenProbe {
            stage: "bind".into(),
            errno: libc::EPERM,
        },
        session_phase: "ready".into(),
        identity_present: true,
    }
}

#[test]
fn provider_xpc_codec_round_trips_ping_and_status() {
    assert_eq!(
        encode_request(Verb::Ping),
        br#"{"schema":"aegis-ne-xpc-v1","verb":"ping"}"#
    );
    for verb in [Verb::Ping, Verb::Status] {
        assert_eq!(decode_request(&encode_request(verb)), Ok(verb));
    }
    let replies = [
        Reply::Ping(ping_report()),
        Reply::Ping(PingReport {
            container_url: None,
            container_realpath: None,
            realpath_errno: libc::ENOENT,
            custody: Vec::new(),
            container_ancestors: Vec::new(),
            container_open: None,
            session_phase: "none".into(),
            identity_present: false,
            ..ping_report()
        }),
        Reply::Status(StatusReport {
            session_phase: "sealed".into(),
            session_refusal: Some("capture_lease_expired".into()),
        }),
        Reply::Status(StatusReport {
            session_phase: "none".into(),
            session_refusal: None,
        }),
    ];
    for reply in replies {
        let verb = match reply {
            Reply::Ping(_) => Verb::Ping,
            _ => Verb::Status,
        };
        let bytes = encode_reply(&reply).unwrap();
        assert!(bytes.len() <= MAX_REPLY_BYTES);
        assert_eq!(decode_reply(&bytes, verb), Ok(reply));
    }
    let refused = Reply::Refused("unknown_verb".into());
    let bytes = encode_reply(&refused).unwrap();
    for verb in [Verb::Ping, Verb::Status] {
        assert_eq!(decode_reply(&bytes, verb), Ok(refused.clone()));
    }
    assert_eq!(Verb::from_flag("--ping"), Some(Verb::Ping));
    assert_eq!(Verb::from_flag("--status"), Some(Verb::Status));
    assert_eq!(Verb::from_flag("--connect"), None);
}

#[test]
fn provider_xpc_codec_refuses_oversized_unknown_and_noncanonical_requests() {
    // Otherwise valid JSON padded past the bound: refused before parsing.
    let mut padded = encode_request(Verb::Ping);
    padded.extend(std::iter::repeat_n(b' ', MAX_REQUEST_BYTES));
    assert_eq!(decode_request(&padded), Err("request_oversized"));
    let at_bound = vec![b' '; MAX_REQUEST_BYTES];
    assert_eq!(decode_request(&at_bound), Err("request_malformed"));
    for (request, code) in [
        (
            &br#"{"schema":"aegis-ne-xpc-v1","verb":"connect"}"#[..],
            "unknown_verb",
        ),
        (
            br#"{"schema":"aegis-ne-xpc-v1","verb":"PING"}"#,
            "unknown_verb",
        ),
        (br#"{"schema":"aegis-ne-xpc-v1","verb":7}"#, "unknown_verb"),
        (
            br#"{"schema":"aegis-ne-xpc-v2","verb":"ping"}"#,
            "schema_mismatch",
        ),
        (br#"{"verb":"ping"}"#, "request_malformed"),
        (
            br#"{"schema":"aegis-ne-xpc-v1","verb":"ping","x":1}"#,
            "request_malformed",
        ),
        (br#"["aegis-ne-xpc-v1","ping"]"#, "request_malformed"),
        (b"", "request_malformed"),
        (b"\xff", "request_malformed"),
        (
            br#"{"verb":"ping","schema":"aegis-ne-xpc-v1"}"#,
            "request_noncanonical",
        ),
        (
            br#"{"schema":"aegis-ne-xpc-v1", "verb":"ping"}"#,
            "request_noncanonical",
        ),
        // A JSON escape spelling "ping" is not the canonical frame.
        (
            br#"{"schema":"aegis-ne-xpc-v1","verb":"pin\u0067"}"#,
            "request_noncanonical",
        ),
        // A duplicate key is not the canonical frame, whatever value wins.
        (
            br#"{"schema":"aegis-ne-xpc-v1","verb":"connect","verb":"ping"}"#,
            "request_noncanonical",
        ),
    ] {
        assert_eq!(
            decode_request(request),
            Err(code),
            "{}",
            String::from_utf8_lossy(request)
        );
    }
}

#[test]
fn provider_xpc_codec_refuses_malformed_mismatched_and_oversized_replies() {
    let ping = encode_reply(&Reply::Ping(ping_report())).unwrap();
    // A ping reply is never accepted as a status reply.
    assert_eq!(
        decode_reply(&ping, Verb::Status),
        Err("reply_verb_mismatch")
    );
    let mut padded = ping.clone();
    padded.extend(std::iter::repeat_n(b' ', MAX_REPLY_BYTES));
    assert_eq!(decode_reply(&padded, Verb::Ping), Err("reply_oversized"));
    let value: Value = serde_json::from_slice(&ping).unwrap();
    let mutate = |edit: &dyn Fn(&mut Value)| {
        let mut changed = value.clone();
        edit(&mut changed);
        serde_json::to_vec(&changed).unwrap()
    };
    for (bytes, code) in [
        (mutate(&|v| v["schema"] = json!("other")), "schema_mismatch"),
        (mutate(&|v| v["extra"] = json!(1)), "reply_malformed"),
        (mutate(&|v| v["report"]["extra"] = json!(1)), "reply_malformed"),
        (
            mutate(&|v| {
                v["report"].as_object_mut().unwrap().remove("euid");
            }),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["session_phase"] = json!("running")),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["realpath_errno"] = json!(-1)),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["euid"] = json!(u64::from(u32::MAX) + 1)),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["loopback_listen"]["stage"] = json!("accept")),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["custody"][0]["extra"] = json!(0)),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_url"] = json!("x".repeat(MAX_TEXT_BYTES + 1))),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["custody"] = json!(vec![json!({"component":"a","errno":0}); MAX_CUSTODY_STEPS + 1])),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_open"]["extra"] = json!(0)),
            "reply_malformed",
        ),
        (
            mutate(&|v| {
                v["report"]["container_open"]
                    .as_object_mut()
                    .unwrap()
                    .remove("getpath_errno");
            }),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_open"]["errno"] = json!(-1)),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_open"]["path_matched"] = json!(1)),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_open"] = json!([])),
            "reply_malformed",
        ),
        (
            mutate(&|v| {
                v["report"].as_object_mut().unwrap().remove("container_open");
            }),
            "reply_malformed",
        ),
        // Admission is never reported for an unmatched anchor.
        (
            mutate(&|v| v["report"]["container_open"]["path_matched"] = json!(false)),
            "reply_malformed",
        ),
        (
            mutate(&|v| {
                v["report"]["container_open"]
                    .as_object_mut()
                    .unwrap()
                    .remove("admitted");
            }),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_open"]["admitted"] = json!("yes")),
            "reply_malformed",
        ),
        // An ancestor whose lstat failed cannot have passed the policy.
        (
            mutate(&|v| v["report"]["container_ancestors"][1]["policy_ok"] = json!(true)),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_ancestors"][0]["extra"] = json!(0)),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_ancestors"][0]["lstat_errno"] = json!(-1)),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_ancestors"][0]["policy_ok"] = json!(0)),
            "reply_malformed",
        ),
        (
            mutate(&|v| {
                v["report"]["container_ancestors"][0]["component"] =
                    json!("x".repeat(MAX_TEXT_BYTES + 1))
            }),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_ancestors"] = json!(vec![json!({"component":"a","lstat_errno":0,"policy_ok":true}); MAX_CUSTODY_STEPS + 1])),
            "reply_malformed",
        ),
        (
            mutate(&|v| v["report"]["container_ancestors"] = json!(null)),
            "reply_malformed",
        ),
        (
            mutate(&|v| {
                v["report"]
                    .as_object_mut()
                    .unwrap()
                    .remove("container_ancestors");
            }),
            "reply_malformed",
        ),
        (b"not json".to_vec(), "reply_malformed"),
        (
            br#"{"schema":"aegis-ne-xpc-v1","refused":"Unstable Code"}"#.to_vec(),
            "reply_malformed",
        ),
        (
            br#"{"schema":"aegis-ne-xpc-v1","refused":"unknown_verb","verb":"ping"}"#.to_vec(),
            "reply_malformed",
        ),
        (
            br#"{"schema":"aegis-ne-xpc-v1","verb":"status","report":{"session_phase":"none","session_refusal":"/etc/passwd"}}"#.to_vec(),
            "reply_verb_mismatch",
        ),
    ] {
        assert_eq!(
            decode_reply(&bytes, Verb::Ping),
            Err(code),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
    let status = br#"{"schema":"aegis-ne-xpc-v1","verb":"status","report":{"session_phase":"none","session_refusal":"/etc/passwd"}}"#;
    assert_eq!(decode_reply(status, Verb::Status), Err("reply_malformed"));
}

struct FakeObserver;
impl Observer for FakeObserver {
    fn ping(&self) -> PingReport {
        ping_report()
    }
    fn status(&self) -> StatusReport {
        StatusReport {
            session_phase: "constructing".into(),
            session_refusal: None,
        }
    }
}
struct HugeObserver;
impl Observer for HugeObserver {
    fn ping(&self) -> PingReport {
        PingReport {
            custody: vec![
                CustodyStep {
                    component: "c".repeat(1000),
                    errno: 0,
                };
                40
            ],
            ..ping_report()
        }
    }
    fn status(&self) -> StatusReport {
        FakeObserver.status()
    }
}

#[test]
fn provider_xpc_responder_refuses_unknown_verbs_and_bounds_replies() {
    let ping = respond(Ok(encode_request(Verb::Ping)), &FakeObserver);
    assert_eq!(
        decode_reply(&ping, Verb::Ping),
        Ok(Reply::Ping(ping_report()))
    );
    let status = respond(Ok(encode_request(Verb::Status)), &FakeObserver);
    assert_eq!(
        decode_reply(&status, Verb::Status),
        Ok(Reply::Status(FakeObserver.status()))
    );
    let unknown = respond(
        Ok(br#"{"schema":"aegis-ne-xpc-v1","verb":"connect"}"#.to_vec()),
        &FakeObserver,
    );
    assert_eq!(
        decode_reply(&unknown, Verb::Ping),
        Ok(Reply::Refused("unknown_verb".into()))
    );
    let envelope = respond(Err("frame_oversized"), &FakeObserver);
    assert_eq!(
        decode_reply(&envelope, Verb::Status),
        Ok(Reply::Refused("frame_oversized".into()))
    );
    // An observation too large for one frame is refused, not truncated.
    assert_eq!(
        encode_reply(&Reply::Ping(HugeObserver.ping())),
        Err("reply_oversized")
    );
    let huge = respond(Ok(encode_request(Verb::Ping)), &HugeObserver);
    assert!(huge.len() <= MAX_REPLY_BYTES);
    assert_eq!(
        decode_reply(&huge, Verb::Ping),
        Ok(Reply::Refused("reply_oversized".into()))
    );
}

#[test]
fn provider_xpc_envelope_admits_exactly_one_bounded_data_frame() {
    let request = encode_request(Verb::Status);
    let message = framed(&request).unwrap();
    assert_eq!(
        read_frame(message.as_ptr(), MAX_REQUEST_BYTES),
        Ok(request.clone())
    );
    assert_eq!(
        read_frame(message.as_ptr(), request.len() - 1),
        Err("frame_oversized")
    );
    let oversized = framed(&vec![b'{'; MAX_REQUEST_BYTES + 1]).unwrap();
    assert_eq!(
        read_frame(oversized.as_ptr(), MAX_REQUEST_BYTES),
        Err("frame_oversized")
    );
    let empty = framed(b"").unwrap();
    assert_eq!(
        read_frame(empty.as_ptr(), MAX_REQUEST_BYTES),
        Err("frame_empty")
    );
    // A second key is refused even beside a valid frame.
    let extra = framed(&request).unwrap();
    unsafe { xpc_dictionary_set_string(extra.as_ptr(), c"verb".as_ptr(), c"ping".as_ptr()) };
    assert_eq!(
        read_frame(extra.as_ptr(), MAX_REQUEST_BYTES),
        Err("envelope_shape")
    );
    // The frame must be data, not a string.
    let string =
        XpcOwned::new(unsafe { xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0) })
            .unwrap();
    unsafe {
        xpc_dictionary_set_string(
            string.as_ptr(),
            FRAME_KEY.as_ptr(),
            c"{\"schema\":\"aegis-ne-xpc-v1\",\"verb\":\"ping\"}".as_ptr(),
        )
    };
    assert_eq!(
        read_frame(string.as_ptr(), MAX_REQUEST_BYTES),
        Err("envelope_shape")
    );
    let bare =
        XpcOwned::new(unsafe { xpc_data_create(request.as_ptr().cast(), request.len()) }).unwrap();
    assert_eq!(
        read_frame(bare.as_ptr(), MAX_REQUEST_BYTES),
        Err("envelope_not_dictionary")
    );
    assert_eq!(
        read_frame(std::ptr::null_mut(), MAX_REQUEST_BYTES),
        Err("envelope_not_dictionary")
    );
}

struct OwnedCf(CfRef);
impl Drop for OwnedCf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) }
    }
}
fn compile(text: &str) -> Result<OwnedCf, i32> {
    let text = NSString::from_str(text);
    let mut raw = std::ptr::null();
    let status =
        unsafe { SecRequirementCreateWithString((&*text as *const NSString).cast(), 0, &mut raw) };
    if status != 0 || raw.is_null() {
        return Err(status);
    }
    Ok(OwnedCf(raw))
}
fn canonical(requirement: &OwnedCf) -> String {
    let mut raw = std::ptr::null();
    assert_eq!(
        unsafe { SecRequirementCopyString(requirement.0, 0, &mut raw) },
        0
    );
    let text = OwnedCf(raw);
    unsafe { &*(text.0 as *const NSString) }.to_string()
}

#[test]
fn provider_xpc_requirements_compile_and_equal_the_committed_constants() {
    for (constant, identifier) in [
        (HOST_PEER_REQUIREMENT, HOST_BUNDLE_ID),
        (PROVIDER_PEER_REQUIREMENT, PROVIDER_BUNDLE_ID),
    ] {
        let committed = constant.to_str().unwrap();
        assert_eq!(developer_id_requirement(identifier), committed);
        let compiled = compile(committed).expect("requirement compiles");
        let text = canonical(&compiled);
        for clause in [
            format!("identifier \"{identifier}\""),
            "anchor apple generic".into(),
            "certificate 1[field.1.2.840.113635.100.6.2.6]".into(),
            "certificate leaf[field.1.2.840.113635.100.6.1.13]".into(),
            "certificate leaf[subject.OU] = TEAMID0000".into(),
        ] {
            assert!(text.contains(&clause), "{clause} missing from {text}");
        }
        // The canonical form is a fixed point: it recompiles to itself.
        assert_eq!(canonical(&compile(&text).unwrap()), text);
        // This unsigned (ad-hoc) test binary satisfies neither role.
        let mut raw = std::ptr::null();
        assert_eq!(unsafe { SecCodeCopySelf(0, &mut raw) }, 0);
        let code = OwnedCf(raw);
        assert_ne!(
            unsafe { SecCodeCheckValidity(code.0, 0, compiled.0) },
            0,
            "{identifier}"
        );
    }
    assert_ne!(HOST_PEER_REQUIREMENT, PROVIDER_PEER_REQUIREMENT);
    assert!(compile("identifier \"dev.aegis.macos\" and anchor").is_err());
}

#[test]
fn provider_xpc_libxpc_accepts_both_requirements_on_an_anonymous_connection() {
    for requirement in [HOST_PEER_REQUIREMENT, PROVIDER_PEER_REQUIREMENT] {
        // Anonymous, in-process: no Mach service is looked up or registered.
        let connection =
            XpcOwned::new(unsafe { xpc_connection_create(std::ptr::null(), std::ptr::null_mut()) })
                .unwrap();
        let endpoint = NativeConnection(connection.as_ptr());
        assert_eq!(endpoint.require_peer(requirement), 0);
        endpoint.set_handler(false);
        endpoint.cancel();
        endpoint.resume();
    }
}

#[test]
fn provider_xpc_mach_service_matches_the_packaged_ne_mach_service_name() {
    assert_eq!(
        MACH_SERVICE_NAME.to_str().unwrap(),
        format!("{PROVIDER_APP_GROUP}{MACH_SERVICE_SUFFIX}")
    );
    let assembler = include_str!("../assemble-unsigned.py");
    assert!(assembler.contains("'NEMachServiceName':a.app_group+'.packet-tunnel'"));
    assert!(assembler.contains("a.app_group!='group.TEAMID0000.dev.aegis.macos'"));
    // The host looks up only the privileged bootstrap; the provider listens.
    assert_eq!(CLIENT_FLAGS, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    assert_eq!(CLIENT_FLAGS & XPC_CONNECTION_MACH_SERVICE_LISTENER, 0);
    assert_eq!(LISTENER_FLAGS, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    assert_eq!((LISTENER_FLAGS, CLIENT_FLAGS), (1, 2));
}

#[derive(Default)]
struct FakeEndpoint {
    events: RefCell<Vec<String>>,
    requirement_status: c_int,
    reply: Option<Result<Vec<u8>, &'static str>>,
}
impl Endpoint for FakeEndpoint {
    fn require_peer(&self, requirement: &CStr) -> c_int {
        let role = if requirement == HOST_PEER_REQUIREMENT {
            "host"
        } else if requirement == PROVIDER_PEER_REQUIREMENT {
            "provider"
        } else {
            "other"
        };
        self.events.borrow_mut().push(format!("require:{role}"));
        self.requirement_status
    }
    fn set_handler(&self, serve: bool) {
        self.events
            .borrow_mut()
            .push(if serve { "serve" } else { "inert" }.into());
    }
    fn resume(&self) {
        self.events.borrow_mut().push("resume".into());
    }
    fn cancel(&self) {
        self.events.borrow_mut().push("cancel".into());
    }
}
impl ClientEndpoint for FakeEndpoint {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, &'static str> {
        assert!(matches!(
            decode_request(request),
            Ok(Verb::Status | Verb::ProfileTerms)
        ));
        self.events.borrow_mut().push("exchange".into());
        self.reply.clone().expect("unexpected exchange")
    }
    fn exchange_entries(&self, entries: &[(&CStr, &[u8])]) -> Result<Vec<u8>, &'static str> {
        // frame and authorization; an import then has its manifest and
        // exactly the manifest's files.
        assert_eq!(entries[0].0, FRAME_KEY);
        assert_eq!(entries[1].0, AUTHORIZATION_KEY);
        assert_eq!(entries[1].1.len(), EXTERNAL_FORM_LENGTH);
        let verb = decode_request(entries[0].1).unwrap();
        assert!(verb.requires_authorization());
        if verb == Verb::Import {
            assert_eq!(entries[2].0, MANIFEST_KEY);
            let manifest = decode_manifest(entries[2].1).unwrap();
            assert_eq!(entries.len(), 3 + manifest.entries().len());
        } else {
            assert_eq!(entries.len(), 2);
        }
        self.events.borrow_mut().push("exchange_entries".into());
        self.reply.clone().expect("unexpected exchange")
    }
}

#[test]
fn provider_xpc_peer_is_served_only_after_the_host_requirement_is_pinned() {
    let peer = FakeEndpoint::default();
    assert_eq!(admit_peer(&peer), Ok(()));
    assert_eq!(*peer.events.borrow(), ["require:host", "serve", "resume"]);
    // A requirement libxpc did not accept is never served.
    let peer = FakeEndpoint {
        requirement_status: libc::EINVAL,
        ..Default::default()
    };
    assert_eq!(admit_peer(&peer), Err("peer_requirement_not_set"));
    assert_eq!(
        *peer.events.borrow(),
        ["require:host", "inert", "cancel", "resume"]
    );
}

#[test]
fn provider_xpc_host_pins_the_provider_requirement_before_any_exchange() {
    let status = encode_reply(&Reply::Status(FakeObserver.status())).unwrap();
    let client = FakeEndpoint {
        reply: Some(Ok(status)),
        ..Default::default()
    };
    assert_eq!(
        query(&client, Verb::Status),
        Ok(Reply::Status(FakeObserver.status()))
    );
    assert_eq!(
        *client.events.borrow(),
        ["require:provider", "inert", "resume", "exchange", "cancel"]
    );
    let client = FakeEndpoint {
        requirement_status: libc::EINVAL,
        ..Default::default()
    };
    assert_eq!(
        query(&client, Verb::Status),
        Err("peer_requirement_not_set")
    );
    assert_eq!(
        *client.events.borrow(),
        ["require:provider", "inert", "cancel", "resume"]
    );
    // libxpc's requirement refusal, and a malformed reply, are both cancelled.
    for (reply, code) in [
        (
            Err("peer_requirement_unsatisfied"),
            "peer_requirement_unsatisfied",
        ),
        (Ok(b"{}".to_vec()), "reply_malformed"),
        (
            Ok(encode_reply(&Reply::Ping(ping_report())).unwrap()),
            "reply_verb_mismatch",
        ),
    ] {
        let client = FakeEndpoint {
            reply: Some(reply),
            ..Default::default()
        };
        assert_eq!(query(&client, Verb::Status), Err(code));
        assert_eq!(client.events.borrow().last().unwrap(), "cancel");
    }
}

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn temp_container() -> PathBuf {
    let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "aegis-provider-xpc-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(base.join("container/Aegis/identity")).unwrap();
    base
}

#[test]
fn provider_xpc_custody_walk_reports_each_component_errno_without_following_links() {
    let base = temp_container();
    let container = base.join("container");
    let (steps, identity) = custody_walk(&container, &["Aegis", "identity"]);
    let expected = container.components().count() + 2;
    assert_eq!(steps.len(), expected);
    assert!(steps.iter().all(|step| step.errno == 0), "{steps:?}");
    assert_eq!(steps[0].component, "/");
    assert_eq!(steps[expected - 1].component, "identity");
    let identity = identity.expect("identity directory held");
    assert!(!identity_present(&identity));
    std::fs::write(container.join("Aegis/identity/identity.json"), b"{}").unwrap();
    assert!(identity_present(&identity));
    // A link, or a directory, named identity.json is not an identity.
    std::fs::remove_file(container.join("Aegis/identity/identity.json")).unwrap();
    std::os::unix::fs::symlink(
        base.join("elsewhere.json"),
        container.join("Aegis/identity/identity.json"),
    )
    .unwrap();
    std::fs::write(base.join("elsewhere.json"), b"{}").unwrap();
    assert!(!identity_present(&identity));
    std::fs::remove_file(container.join("Aegis/identity/identity.json")).unwrap();
    std::fs::create_dir(container.join("Aegis/identity/identity.json")).unwrap();
    assert!(!identity_present(&identity));

    // A missing component is reported by name and errno, and the walk stops.
    std::fs::remove_dir_all(container.join("Aegis/identity")).unwrap();
    let (steps, identity) = custody_walk(&container, &["Aegis", "identity"]);
    assert!(identity.is_none());
    assert_eq!(steps.len(), expected);
    assert_eq!(
        steps.last().unwrap(),
        &CustodyStep {
            component: "identity".into(),
            errno: libc::ENOENT
        }
    );

    // A symlinked component is refused (O_NOFOLLOW), never traversed.
    std::fs::create_dir_all(base.join("real/Aegis/identity")).unwrap();
    std::os::unix::fs::symlink(base.join("real"), base.join("linked")).unwrap();
    let (steps, identity) = custody_walk(&base.join("linked"), &["Aegis", "identity"]);
    assert!(identity.is_none());
    let last = steps.last().unwrap();
    assert_eq!(last.component, "linked");
    assert!(
        [libc::ELOOP, libc::ENOTDIR].contains(&last.errno),
        "{last:?}"
    );
    let (steps, identity) = custody_walk(Path::new("/tmp/../etc"), &[]);
    assert!(identity.is_none());
    assert_eq!(steps.last().unwrap().errno, libc::EINVAL);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn provider_xpc_ping_observes_container_listen_and_sandbox_state() {
    // The unsigned test process is unsandboxed and may listen on loopback.
    assert!(!sandboxed());
    assert_eq!(
        loopback_listen_probe(),
        ListenProbe {
            stage: "ok".into(),
            errno: 0
        }
    );
    let base = temp_container();
    let container = base.join("container");
    std::fs::write(container.join("Aegis/identity/identity.json"), b"{}").unwrap();
    // Reported through a symlinked spelling, as NSFileManager reports /var.
    std::os::unix::fs::symlink(&container, base.join("reported")).unwrap();
    let url = "file:///reported/".to_string();
    let report = ping_from_container(
        Some((url.clone(), base.join("reported").to_string_lossy().into())),
        Some(SessionPhase::Ready),
    );
    assert_eq!(report.euid, unsafe { libc::geteuid() });
    assert!(!report.sandboxed);
    assert_eq!(report.container_url, Some(url));
    assert_eq!(
        report.container_realpath,
        Some(container.to_string_lossy().into_owned())
    );
    assert_eq!(report.realpath_errno, 0);
    assert!(report.custody.iter().all(|step| step.errno == 0));
    // Every directory above the canonical container, `/` first, passed.
    assert_eq!(
        report.container_ancestors.len(),
        container.components().count() - 1
    );
    assert_eq!(report.container_ancestors[0].component, "/");
    assert_eq!(
        report.container_ancestors.last().unwrap().component,
        base.file_name().unwrap().to_string_lossy()
    );
    assert!(report
        .container_ancestors
        .iter()
        .all(|step| step.lstat_errno == 0 && step.policy_ok));
    assert_eq!(
        report.container_open,
        Some(ContainerOpenProbe {
            errno: 0,
            getpath_errno: 0,
            path_matched: true,
            admitted: true,
        })
    );
    assert!(report.identity_present);
    assert_eq!(report.session_phase, "ready");
    assert_eq!(report.loopback_listen.stage, "ok");
    let bytes = encode_reply(&Reply::Ping(report.clone())).unwrap();
    assert_eq!(decode_reply(&bytes, Verb::Ping), Ok(Reply::Ping(report)));

    let missing = ping_from_container(
        Some((
            "file:///absent/".into(),
            base.join("absent").to_string_lossy().into(),
        )),
        None,
    );
    assert_eq!(missing.realpath_errno, libc::ENOENT);
    assert_eq!(missing.container_realpath, None);
    assert!(missing.custody.is_empty());
    assert!(missing.container_ancestors.is_empty());
    assert_eq!(missing.container_open, None);
    assert!(!missing.identity_present);
    assert_eq!(missing.session_phase, "none");
    let unresolved = ping_from_container(None, None);
    assert_eq!(unresolved.container_url, None);
    assert_eq!(unresolved.realpath_errno, 0);
    assert!(unresolved.custody.is_empty());
    assert!(unresolved.container_ancestors.is_empty());
    assert_eq!(unresolved.container_open, None);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn provider_xpc_container_open_probe_reports_errno_and_path_match() {
    let base = temp_container();
    let container = base.join("container");
    std::fs::write(container.join("Aegis/identity/identity.json"), b"{}").unwrap();
    let uid = unsafe { libc::geteuid() };
    let (open, anchor) = container_open_probe(&container, uid);
    assert_eq!(
        open,
        ContainerOpenProbe {
            errno: 0,
            getpath_errno: 0,
            path_matched: true,
            admitted: true,
        }
    );
    let identity = open_below(&anchor.unwrap(), &[c"Aegis", c"identity"]).unwrap();
    assert!(identity_present(&identity));

    // Opened through an intermediate symlink: the descriptor names the real
    // path, so the match is false and no descriptor is handed back.
    std::os::unix::fs::symlink(&base, base.with_extension("link")).unwrap();
    let (open, anchor) = container_open_probe(&base.with_extension("link").join("container"), uid);
    assert_eq!(
        open,
        ContainerOpenProbe {
            errno: 0,
            getpath_errno: 0,
            path_matched: false,
            admitted: false,
        }
    );
    assert!(anchor.is_none());
    std::fs::remove_file(base.with_extension("link")).unwrap();

    // The final component is never followed, and an absent one has ENOENT.
    std::os::unix::fs::symlink("container", base.join("alias")).unwrap();
    let (open, anchor) = container_open_probe(&base.join("alias"), uid);
    assert!(
        [libc::ELOOP, libc::ENOTDIR].contains(&open.errno),
        "{open:?}"
    );
    assert!(!open.path_matched && anchor.is_none());
    let (open, _) = container_open_probe(&base.join("absent"), uid);
    assert_eq!(open.errno, libc::ENOENT);
    assert!(!open.path_matched);

    // The ping resolves a reported alias with realpath first, then reports
    // identity presence below the matched anchor only.
    let report = ping_from_container(
        Some((
            "file:///alias/".into(),
            base.join("alias").to_string_lossy().into(),
        )),
        None,
    );
    assert_eq!(
        report.container_open.as_ref().map(|o| o.path_matched),
        Some(true)
    );
    assert!(report.identity_present);
    std::fs::remove_dir_all(container.join("Aegis/identity")).unwrap();
    let report = ping_from_container(
        Some(("file:///c/".into(), container.to_string_lossy().into())),
        None,
    );
    assert_eq!(
        report.container_open.as_ref().map(|o| o.path_matched),
        Some(true)
    );
    assert!(!report.identity_present);
    std::fs::remove_dir_all(&base).unwrap();
}

/// The ping runs capture's own ancestor and container admission, so a
/// refusal capture would raise is visible in the ping, and an lstat errno is
/// told apart from an owner/mode refusal.
#[test]
fn provider_xpc_ping_reports_capture_ancestor_and_container_admission() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &Path, bits: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap()
    };
    let base = temp_container();
    let ancestor = base.join("ancestor");
    std::fs::create_dir(&ancestor).unwrap();
    let container = ancestor.join("container");
    std::fs::rename(base.join("container"), &container).unwrap();
    let uid = unsafe { libc::geteuid() };
    let ping = || {
        ping_from_container(
            Some(("file:///c/".into(), container.to_string_lossy().into())),
            None,
        )
    };
    let step = |report: &PingReport, name: &str| {
        report
            .container_ancestors
            .iter()
            .find(|step| step.component == name)
            .cloned()
            .unwrap()
    };
    let admitted = |report: &PingReport| report.container_open.as_ref().map(|o| o.admitted);
    assert!(ping().container_ancestors.iter().all(|s| s.policy_ok));
    assert_eq!(admitted(&ping()), Some(true));

    // A group-writable ancestor: lstat works, the policy refuses it, and the
    // anchor still matches. Capture reports the same refusal.
    mode(&ancestor, 0o775);
    let report = ping();
    assert_eq!(
        step(&report, "ancestor"),
        AncestorStep {
            component: "ancestor".into(),
            lstat_errno: 0,
            policy_ok: false
        }
    );
    assert_eq!(
        report.container_open.as_ref().map(|o| o.path_matched),
        Some(true)
    );
    let bytes = encode_reply(&Reply::Ping(report.clone())).unwrap();
    assert_eq!(decode_reply(&bytes, Verb::Ping), Ok(Reply::Ping(report)));
    mode(&ancestor, 0o755);

    // A container other users can write: matched, but not admitted.
    mode(&container, 0o757);
    let report = ping();
    assert_eq!(
        report.container_open,
        Some(ContainerOpenProbe {
            errno: 0,
            getpath_errno: 0,
            path_matched: true,
            admitted: false,
        })
    );
    assert!(report.container_ancestors.iter().all(|s| s.policy_ok));
    mode(&container, 0o755);
    // Another non-root owner is refused for the container and the ancestor.
    if uid != 0 {
        assert!(!container_open_probe(&container, uid + 1).0.admitted);
        assert!(
            !container_ancestor_probe(&container, uid + 1)
                .iter()
                .find(|s| s.component == "ancestor")
                .unwrap()
                .policy_ok
        );
        // An ancestor whose parent cannot be searched: lstat fails with an
        // errno, reported as such and never as a policy refusal. realpath
        // fails first in a full ping, so the probe the ping runs is driven
        // directly; capture's matching sub-code is tested in app_group.
        mode(&base, 0o600);
        let steps = container_ancestor_probe(&container, uid);
        mode(&base, 0o755);
        assert_eq!(
            steps.iter().find(|s| s.component == "ancestor"),
            Some(&AncestorStep {
                component: "ancestor".into(),
                lstat_errno: libc::EACCES,
                policy_ok: false
            })
        );
    }
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn provider_xpc_ancestor_probe_past_the_bound_round_trips_its_too_deep_marker() {
    let mut deep = PathBuf::from("/");
    for _ in 0..MAX_CUSTODY_STEPS + 3 {
        deep.push("d");
    }
    let steps = container_ancestor_probe(&deep, 0);
    assert_eq!(steps.len(), MAX_CUSTODY_STEPS);
    assert_eq!(
        steps.last().unwrap(),
        &AncestorStep {
            component: "too_deep".into(),
            lstat_errno: libc::ENAMETOOLONG,
            policy_ok: false
        }
    );
    // Exactly at the bound every ancestor is reported, without a marker.
    let mut fits = PathBuf::from("/");
    for _ in 0..MAX_CUSTODY_STEPS {
        fits.push("d");
    }
    let steps = container_ancestor_probe(&fits, 0);
    assert_eq!(steps.len(), MAX_CUSTODY_STEPS);
    assert_ne!(steps.last().unwrap().component, "too_deep");
    let mut report = ping_report();
    report.container_ancestors = container_ancestor_probe(&deep, 0);
    let bytes = encode_reply(&Reply::Ping(report.clone())).unwrap();
    assert_eq!(decode_reply(&bytes, Verb::Ping), Ok(Reply::Ping(report)));
}

#[test]
fn provider_xpc_custody_walk_past_the_bound_round_trips_its_too_deep_marker() {
    let base = temp_container();
    // Deep enough that the walk stops on its bound before reaching the tail.
    let mut deep = base.join("container");
    for _ in 0..MAX_CUSTODY_STEPS {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).unwrap();
    let (steps, identity) = custody_walk(&deep, &["Aegis", "identity"]);
    assert!(identity.is_none());
    assert_eq!(steps.len(), MAX_CUSTODY_STEPS);
    assert_eq!(
        steps.last().unwrap(),
        &CustodyStep {
            component: "too_deep".into(),
            errno: libc::ENAMETOOLONG
        }
    );
    assert!(steps[..MAX_CUSTODY_STEPS - 1]
        .iter()
        .all(|step| step.errno == 0));
    // The host decodes the marker instead of refusing the whole ping.
    let mut report = ping_report();
    report.custody = steps;
    let bytes = encode_reply(&Reply::Ping(report.clone())).unwrap();
    assert_eq!(decode_reply(&bytes, Verb::Ping), Ok(Reply::Ping(report)));

    // A path whose last tail name is exactly the last permitted step opens.
    let mut fits = base.join("fits");
    let room = MAX_CUSTODY_STEPS - 1 - fits.components().count() - 2;
    for _ in 0..room {
        fits.push("d");
    }
    std::fs::create_dir_all(fits.join("Aegis/identity")).unwrap();
    let (steps, identity) = custody_walk(&fits, &["Aegis", "identity"]);
    assert_eq!(steps.len(), MAX_CUSTODY_STEPS - 1, "{steps:?}");
    assert!(identity.is_some(), "{steps:?}");
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn provider_xpc_status_reports_the_published_session_after_it_ends() {
    // OBSERVED is process-global: every publication is exercised in this one
    // test so parallel tests cannot interleave with it.
    assert_eq!(
        NativeObserver.status(),
        StatusReport {
            session_phase: "none".into(),
            session_refusal: None
        }
    );
    // A start refused before any session existed is reported, phase none.
    publish_start_refusal("file_missing:identity.json");
    assert_eq!(
        NativeObserver.status(),
        StatusReport {
            session_phase: "none".into(),
            session_refusal: Some("file_missing:identity.json".into())
        }
    );

    let clock = std::sync::Arc::new(AtomicU64::new(10));
    let now = clock.clone();
    let deadline = CaptureLeaseDeadline::default();
    let bridge =
        LeasedPacketBridge::with_clock(PacketBridge::default(), deadline.clone(), move || {
            Ok(now.load(Ordering::SeqCst))
        });
    deadline.replace(Some(1_000)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut session = SessionHandle::spawn(
        bridge,
        move |phase| tx.send(phase).unwrap(),
        |control| {
            control.mark_ready();
            while !control.stop_requested() {
                std::thread::park_timeout(Duration::from_millis(5));
            }
            Ok(())
        },
    )
    .unwrap();
    publish_session(session.probe().phase_reader());
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        SessionPhase::Ready
    );
    assert_eq!(
        NativeObserver.status(),
        StatusReport {
            session_phase: "ready".into(),
            session_refusal: None
        }
    );
    assert!(session.try_join(Duration::from_secs(5)));
    assert_eq!(
        NativeObserver.status(),
        StatusReport {
            session_phase: "joined".into(),
            session_refusal: Some("provider_stop".into())
        }
    );
    // The provider drops the engine as soon as the join is observed; the
    // outcome must outlive it rather than read as a session never started.
    drop(session);
    assert_eq!(
        NativeObserver.status(),
        StatusReport {
            session_phase: "joined".into(),
            session_refusal: Some("provider_stop".into())
        }
    );
    // A later pre-session refusal replaces the ended session's record.
    publish_start_refusal("wrong_provider_protocol");
    assert_eq!(
        NativeObserver.status(),
        StatusReport {
            session_phase: "none".into(),
            session_refusal: Some("wrong_provider_protocol".into())
        }
    );
}

// ---------------------------------------------------------------------------
// S14 identity verbs over real libxpc dictionaries (in-process, no service).

use crate::identity_import::{
    self as import,
    authorization::{
        test_support::{fresh_form, AdmitEveryForm},
        AuthorizationGate,
    },
    tests::{gate, payload_of, relay, snapshot, uid, FakePrincipals, TempContainer},
    TreeGate,
};
use crate::test_fixture::ReadyTree;

const CONSOLE: u32 = 501;

struct IdentityObserver {
    container: PathBuf,
    gate: &'static TreeGate,
    principals: FakePrincipals,
    imports: RefCell<u32>,
    authorizations: AuthorizationGate,
}
impl IdentityObserver {
    fn new(container: &Path) -> Self {
        Self {
            container: container.to_owned(),
            gate: gate(),
            principals: FakePrincipals {
                console: Ok(CONSOLE),
                admins: Ok(vec![CONSOLE]),
            },
            imports: RefCell::new(0),
            authorizations: AuthorizationGate::new(),
        }
    }
}
impl Observer for IdentityObserver {
    fn ping(&self) -> PingReport {
        ping_report()
    }
    fn status(&self) -> StatusReport {
        FakeObserver.status()
    }
    fn authorize(&self, peer_euid: u32) -> Result<(), &'static str> {
        import::authorize_identity_peer(peer_euid, &self.principals)
    }
    fn admit_authorization(&self, form: Option<&[u8]>) -> Result<(), &'static str> {
        self.authorizations.admit(form, &AdmitEveryForm)
    }
    fn import(&self, payload: &ImportPayload) -> Result<ImportReport, &'static str> {
        *self.imports.borrow_mut() += 1;
        import::import_tree(&self.container, uid(), self.gate, payload, |_| {})
    }
    fn forget(&self) -> Result<ForgetReport, &'static str> {
        import::forget_identity(&self.container, uid(), self.gate)
    }
}

/// The import dictionary the host sends, with a fresh administrator
/// approval, then `edit` applied to it.
fn import_message(payload: &ImportPayload, edit: impl FnOnce(XpcObject)) -> XpcOwned {
    let frame = encode_request(Verb::Import);
    let manifest = encode_manifest(&payload.manifest());
    let form = fresh_form();
    let message = framed_entries(&import_entries(&frame, &form, &manifest, payload)).unwrap();
    edit(message.as_ptr());
    message
}

/// The forget dictionary the host sends, with a fresh approval.
fn forget_message() -> XpcOwned {
    let frame = encode_request(Verb::ForgetIdentity);
    framed_entries(&[(FRAME_KEY, &frame), (AUTHORIZATION_KEY, &fresh_form())]).unwrap()
}

fn set_data(message: XpcObject, key: &CStr, bytes: &[u8]) {
    unsafe { xpc_dictionary_set_data(message, key.as_ptr(), bytes.as_ptr().cast(), bytes.len()) }
}

fn file_bytes(payload: &ImportPayload, name: &str) -> Vec<u8> {
    payload
        .files()
        .find(|(m, _)| m.name() == name)
        .map(|(_, b)| b.to_vec())
        .unwrap()
}

fn answer_of(
    message: &XpcOwned,
    peer: Option<u32>,
    observer: &IdentityObserver,
    verb: Verb,
) -> Reply {
    decode_reply(&respond_message(message.as_ptr(), peer, observer), verb).unwrap()
}

#[test]
fn provider_xpc_import_commits_a_tree_that_capture_admits() {
    let target = TempContainer::new();
    let observer = IdentityObserver::new(target.path());
    let source = ReadyTree::with_online_completed(relay());
    let payload = payload_of(&source);
    let message = import_message(&payload, |_| {});
    let Reply::Import(report) = answer_of(&message, Some(CONSOLE), &observer, Verb::Import) else {
        panic!("import refused");
    };
    import::verify_import_report(&payload.manifest(), &report).unwrap();
    assert!(report.retired_removed);
    let bytes = encode_reply(&Reply::Import(report.clone())).unwrap();
    assert!(bytes.len() <= MAX_REPLY_BYTES);
    assert_eq!(
        decode_reply(&bytes, Verb::Import),
        Ok(Reply::Import(report.clone()))
    );
    for file in &report.files {
        let committed = std::fs::read(target.path().join("Aegis").join(&file.path)).unwrap();
        assert_eq!(file.sha256, import::sha256_hex(&committed));
    }
    // No byte of a private file is echoed: the reply carries digests only.
    let key = file_bytes(&payload, "identity/device.key");
    let text = String::from_utf8_lossy(&key);
    let body = text
        .lines()
        .find(|line| !line.starts_with("-----"))
        .unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(body));
    let inputs =
        crate::app_group::CapturedAppGroupInputs::capture_test_root(target.path()).unwrap();
    let mut identity = crate::local_identity::CapturedLocalIdentity::from_claim(inputs).unwrap();
    let online = identity.revalidate().unwrap();
    assert_eq!(
        online.certificate_sha256,
        source.online().certificate_sha256
    );
    assert_eq!(online.issued_generation, Some(7));
    drop(identity);

    // forget-identity over the same channel removes the key material.
    let forget = forget_message();
    assert_eq!(
        answer_of(&forget, Some(CONSOLE), &observer, Verb::ForgetIdentity),
        Reply::Forget(ForgetReport {
            identity_was_present: true,
            key_material_removed: true
        })
    );
    assert!(!target.path().join("Aegis/identity").exists());
}

#[test]
fn provider_xpc_import_refusals_leave_the_installed_tree_untouched() {
    let target = TempContainer::new();
    let observer = IdentityObserver::new(target.path());
    let installed = ReadyTree::new(relay());
    import::import_tree(
        target.path(),
        uid(),
        observer.gate,
        &payload_of(&installed),
        |_| {},
    )
    .unwrap();
    let before = snapshot(target.path());
    let source = ReadyTree::with_online_completed(relay());
    let payload = payload_of(&source);
    let pem = file_bytes(&payload, "identity/device.pem");
    let manifest_value: Value =
        serde_json::from_slice(&encode_manifest(&payload.manifest())).unwrap();
    let manifest_with = |edit: &dyn Fn(&mut Value)| {
        let mut changed = manifest_value.clone();
        edit(&mut changed);
        serde_json::to_vec(&changed).unwrap()
    };
    type Edit<'a> = Box<dyn FnOnce(XpcObject) + 'a>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "import_file_truncated",
            Box::new(|m| set_data(m, c"identity/device.pem", &pem[..pem.len() - 1])),
        ),
        (
            "import_file_length_mismatch",
            Box::new(|m| set_data(m, c"identity/device.pem", &[&pem[..], b"\n"].concat())),
        ),
        (
            "import_file_oversized",
            Box::new(|m| set_data(m, c"identity/device.pem", &vec![b'a'; 64 * 1024 + 1])),
        ),
        (
            "import_file_oversized",
            Box::new(|m| {
                set_data(
                    m,
                    MANIFEST_KEY,
                    &manifest_with(&|v| v["files"][7]["length"] = json!(64 * 1024 + 1)),
                )
            }),
        ),
        (
            "import_digest_mismatch",
            Box::new(|m| {
                let mut flipped = pem.clone();
                flipped[40] ^= 1;
                set_data(m, c"identity/device.pem", &flipped)
            }),
        ),
        (
            "import_version_unknown",
            Box::new(|m| {
                set_data(
                    m,
                    MANIFEST_KEY,
                    &manifest_with(&|v| v["version"] = json!(2)),
                )
            }),
        ),
        (
            "import_manifest_oversized",
            Box::new(|m| set_data(m, MANIFEST_KEY, &vec![b' '; MAX_MANIFEST_BYTES + 1])),
        ),
        (
            "import_manifest_missing",
            Box::new(|m| unsafe {
                xpc_dictionary_set_string(m, MANIFEST_KEY.as_ptr(), c"{}".as_ptr())
            }),
        ),
        (
            // The manifest drops a required file the host still sends.
            "import_file_missing",
            Box::new(|m| {
                set_data(
                    m,
                    MANIFEST_KEY,
                    &manifest_with(&|v| {
                        v["files"]
                            .as_array_mut()
                            .unwrap()
                            .retain(|f| f["name"] != "identity/device.pem")
                    }),
                )
            }),
        ),
        (
            // A listed file replaced by a non-data value of the same key.
            "import_file_missing",
            Box::new(|m| unsafe {
                xpc_dictionary_set_string(m, c"identity/device.pem".as_ptr(), c"x".as_ptr())
            }),
        ),
        (
            "import_envelope_shape",
            Box::new(|m| set_data(m, c"identity/runtime.json", b"{}")),
        ),
    ];
    for (code, edit) in cases {
        let message = import_message(&payload, edit);
        assert_eq!(
            answer_of(&message, Some(CONSOLE), &observer, Verb::Import),
            Reply::Refused(code.into()),
            "{code}"
        );
        assert_eq!(snapshot(target.path()), before, "{code}");
    }
    // A required file absent from both the manifest and the envelope.
    let mut members: Vec<_> = payload
        .files()
        .map(|(m, b)| (m.name(), Zeroizing::new(b.to_vec())))
        .collect();
    members.retain(|(name, _)| *name != "identity/device.pem");
    let manifest = import::ImportManifest {
        entries: members
            .iter()
            .map(|(name, bytes)| import::ManifestEntry {
                member: IMPORT_MEMBERS
                    .iter()
                    .position(|m| m.name() == *name)
                    .unwrap(),
                length: bytes.len(),
                sha256: import::sha256_hex(bytes),
            })
            .collect(),
    };
    let manifest = encode_manifest(&manifest);
    let frame = encode_request(Verb::Import);
    let form = fresh_form();
    let mut entries: Vec<(&CStr, &[u8])> = vec![
        (FRAME_KEY, &frame),
        (AUTHORIZATION_KEY, &form),
        (MANIFEST_KEY, &manifest),
    ];
    for (name, bytes) in &members {
        let member = IMPORT_MEMBERS.iter().find(|m| m.name() == *name).unwrap();
        entries.push((member.key, bytes));
    }
    let message = framed_entries(&entries).unwrap();
    assert_eq!(
        answer_of(&message, Some(CONSOLE), &observer, Verb::Import),
        Reply::Refused("import_file_missing".into())
    );
    assert_eq!(snapshot(target.path()), before);
    // Without a payload at all (the frame-only responder).
    assert_eq!(
        decode_reply(
            &respond(Ok(encode_request(Verb::Import)), &observer),
            Verb::Import
        ),
        Ok(Reply::Refused("peer_unidentified".into()))
    );
    assert_eq!(snapshot(target.path()), before);
}

#[test]
fn provider_xpc_identity_verbs_refuse_an_unauthorized_peer_before_reading_the_payload() {
    let target = TempContainer::new();
    let source = ReadyTree::new(relay());
    let payload = payload_of(&source);
    let good = import_message(&payload, |_| {});
    // Even a malformed payload is never parsed for an unauthorized peer.
    let broken = import_message(&payload, |m| set_data(m, MANIFEST_KEY, b"not json"));
    for (principals, peer, code) in [
        (
            FakePrincipals {
                console: Ok(CONSOLE),
                admins: Ok(vec![CONSOLE]),
            },
            Some(CONSOLE + 1),
            "peer_not_console_user",
        ),
        (
            FakePrincipals {
                console: Ok(CONSOLE),
                admins: Ok(vec![]),
            },
            Some(CONSOLE),
            "peer_not_admin",
        ),
        (
            FakePrincipals {
                console: Ok(CONSOLE),
                admins: Ok(vec![0, CONSOLE]),
            },
            Some(0),
            "peer_not_console_user",
        ),
        (
            FakePrincipals {
                console: Err("console_user_absent"),
                admins: Ok(vec![CONSOLE]),
            },
            Some(CONSOLE),
            "console_user_absent",
        ),
        (
            FakePrincipals {
                console: Ok(CONSOLE),
                admins: Ok(vec![CONSOLE]),
            },
            None,
            "peer_unidentified",
        ),
    ] {
        let observer = IdentityObserver {
            principals,
            ..IdentityObserver::new(target.path())
        };
        for message in [&good, &broken] {
            assert_eq!(
                answer_of(message, peer, &observer, Verb::Import),
                Reply::Refused(code.into()),
                "{code}"
            );
        }
        let forget = forget_message();
        assert_eq!(
            answer_of(&forget, peer, &observer, Verb::ForgetIdentity),
            Reply::Refused(code.into())
        );
        assert_eq!(*observer.imports.borrow(), 0);
        assert!(std::fs::read_dir(target.path()).unwrap().next().is_none());
    }
    // An observer without the identity verbs refuses them.
    let message = import_message(&payload, |_| {});
    assert_eq!(
        decode_reply(
            &respond_message(message.as_ptr(), Some(CONSOLE), &FakeObserver),
            Verb::Import
        ),
        Ok(Reply::Refused("identity_verbs_unavailable".into()))
    );
}

#[test]
fn provider_xpc_identity_verbs_are_refused_while_a_session_is_live() {
    let target = TempContainer::new();
    let observer = IdentityObserver::new(target.path());
    let installed = ReadyTree::new(relay());
    import::import_tree(
        target.path(),
        uid(),
        observer.gate,
        &payload_of(&installed),
        |_| {},
    )
    .unwrap();
    let before = snapshot(target.path());
    let live = crate::app_group::CapturedAppGroupInputs::capture_test_root_leased(
        target.path(),
        observer.gate,
    )
    .unwrap();
    let source = ReadyTree::new(relay());
    let message = import_message(&payload_of(&source), |_| {});
    assert_eq!(
        answer_of(&message, Some(CONSOLE), &observer, Verb::Import),
        Reply::Refused("session_live".into())
    );
    let forget = forget_message();
    assert_eq!(
        answer_of(&forget, Some(CONSOLE), &observer, Verb::ForgetIdentity),
        Reply::Refused("session_live".into())
    );
    assert_eq!(snapshot(target.path()), before);
    drop(live);
    // The refused requests spent their approvals; a new one commits.
    assert_eq!(
        answer_of(&message, Some(CONSOLE), &observer, Verb::Import),
        Reply::Refused("identity_authorization_replayed".into())
    );
    let message = import_message(&payload_of(&source), |_| {});
    assert!(matches!(
        answer_of(&message, Some(CONSOLE), &observer, Verb::Import),
        Reply::Import(_)
    ));
}

#[test]
fn provider_xpc_frame_only_verbs_refuse_extra_keys() {
    let target = TempContainer::new();
    let observer = IdentityObserver::new(target.path());
    for verb in [Verb::Ping, Verb::Status, Verb::ForgetIdentity] {
        let message = framed(&encode_request(verb)).unwrap();
        set_data(message.as_ptr(), MANIFEST_KEY, b"{}");
        assert_eq!(
            decode_reply(
                &respond_message(message.as_ptr(), Some(CONSOLE), &observer),
                verb
            ),
            Ok(Reply::Refused("envelope_shape".into())),
            "{verb:?}"
        );
    }
    let ping = framed(&encode_request(Verb::Ping)).unwrap();
    assert_eq!(
        answer_of(&ping, None, &observer, Verb::Ping),
        Reply::Ping(ping_report())
    );
    let bare = XpcOwned::new(unsafe { xpc_data_create(b"x".as_ptr().cast(), 1) }).unwrap();
    assert_eq!(
        decode_reply(&respond_message(bare.as_ptr(), None, &observer), Verb::Ping),
        Ok(Reply::Refused("envelope_not_dictionary".into()))
    );
    assert!(std::fs::read_dir(target.path()).unwrap().next().is_none());
}

#[test]
fn provider_xpc_identity_codec_round_trips_and_refuses_malformed_reports() {
    for verb in [Verb::Import, Verb::ForgetIdentity] {
        assert_eq!(decode_request(&encode_request(verb)), Ok(verb));
    }
    assert_eq!(
        encode_request(Verb::ForgetIdentity),
        br#"{"schema":"aegis-ne-xpc-v1","verb":"forget-identity"}"#
    );
    assert_eq!(
        Verb::from_flag("--forget-identity"),
        Some(Verb::ForgetIdentity)
    );
    assert_eq!(Verb::from_flag("--import-identity"), None);
    assert_eq!(query_provider(Verb::Import), Err("import_requires_payload"));
    let report = ImportReport {
        files: vec![
            CommittedFile {
                path: "bundle/bundle.json".into(),
                length: 10,
                sha256: "a".repeat(64),
            },
            CommittedFile {
                path: "identity/.lock".into(),
                length: 0,
                sha256: import::sha256_hex(b""),
            },
        ],
        retired_removed: false,
    };
    let bytes = encode_reply(&Reply::Import(report.clone())).unwrap();
    assert_eq!(
        decode_reply(&bytes, Verb::Import),
        Ok(Reply::Import(report))
    );
    assert_eq!(decode_reply(&bytes, Verb::Ping), Err("reply_verb_mismatch"));
    let forget = Reply::Forget(ForgetReport {
        identity_was_present: true,
        key_material_removed: false,
    });
    let forget_bytes = encode_reply(&forget).unwrap();
    assert_eq!(
        decode_reply(&forget_bytes, Verb::ForgetIdentity),
        Ok(forget)
    );
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let mutate = |edit: &dyn Fn(&mut Value)| {
        let mut changed = value.clone();
        edit(&mut changed);
        serde_json::to_vec(&changed).unwrap()
    };
    for bytes in [
        mutate(&|v| v["report"]["files"][0]["path"] = json!("identity/runtime.json")),
        mutate(&|v| v["report"]["files"][0]["path"] = json!("../etc/passwd")),
        mutate(&|v| v["report"]["files"][1]["path"] = json!("bundle/bundle.json")),
        mutate(&|v| v["report"]["files"][0]["length"] = json!(64 * 1024 + 1)),
        mutate(&|v| v["report"]["files"][1]["length"] = json!(1)),
        mutate(&|v| v["report"]["files"][0]["sha256"] = json!("A".repeat(64))),
        mutate(&|v| v["report"]["files"][0]["extra"] = json!(1)),
        mutate(&|v| v["report"]["extra"] = json!(1)),
        mutate(&|v| v["report"]["retired_removed"] = json!("yes")),
        mutate(&|v| {
            v["report"]["files"] = json!(vec![
                json!({"path":"identity/.lock","length":0,"sha256":"0".repeat(64)});
                IMPORT_MEMBERS.len() + 2
            ])
        }),
    ] {
        assert_eq!(
            decode_reply(&bytes, Verb::Import),
            Err("reply_malformed"),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
    let forget_value: Value = serde_json::from_slice(&forget_bytes).unwrap();
    let mut extra = forget_value.clone();
    extra["report"]["extra"] = json!(1);
    let mut wrong = forget_value;
    wrong["report"]["key_material_removed"] = json!(0);
    for value in [extra, wrong] {
        assert_eq!(
            decode_reply(&serde_json::to_vec(&value).unwrap(), Verb::ForgetIdentity),
            Err("reply_malformed")
        );
    }
}

#[test]
fn provider_xpc_host_import_pins_the_provider_and_checks_the_committed_manifest() {
    let source = ReadyTree::new(relay());
    let payload = payload_of(&source);
    let target = TempContainer::new();
    let report = import::import_tree(target.path(), uid(), gate(), &payload, |_| {}).unwrap();
    let client = FakeEndpoint {
        reply: Some(Ok(encode_reply(&Reply::Import(report.clone())).unwrap())),
        ..Default::default()
    };
    assert_eq!(
        query_import(&client, &payload, &fresh_form()),
        Ok(Reply::Import(report.clone()))
    );
    assert_eq!(
        *client.events.borrow(),
        [
            "require:provider",
            "inert",
            "resume",
            "exchange_entries",
            "cancel"
        ]
    );
    // A reply whose committed digests differ from what was sent is refused.
    let mut altered = report.clone();
    altered.files[0].sha256 = "0".repeat(64);
    let mut missing = report.clone();
    missing.files.remove(1);
    for wrong in [altered, missing] {
        let client = FakeEndpoint {
            reply: Some(Ok(encode_reply(&Reply::Import(wrong)).unwrap())),
            ..Default::default()
        };
        assert_eq!(
            query_import(&client, &payload, &fresh_form()),
            Err("import_reply_mismatch")
        );
        assert_eq!(client.events.borrow().last().unwrap(), "cancel");
    }
    let client = FakeEndpoint {
        requirement_status: libc::EINVAL,
        ..Default::default()
    };
    assert_eq!(
        query_import(&client, &payload, &fresh_form()),
        Err("peer_requirement_not_set")
    );
    assert_eq!(
        *client.events.borrow(),
        ["require:provider", "inert", "cancel", "resume"]
    );
    // A refusal reply passes through unchanged.
    let client = FakeEndpoint {
        reply: Some(Ok(
            encode_reply(&Reply::Refused("session_live".into())).unwrap()
        )),
        ..Default::default()
    };
    assert_eq!(
        query_import(&client, &payload, &fresh_form()),
        Ok(Reply::Refused("session_live".into()))
    );
}

// ---------------------------------------------------------------------------
// S16a `profile-terms`: codec, responder over a held fixture, host query.

fn fixture_terms() -> ProfileTerms {
    ProfileTerms {
        relay: "192.168.1.107:443".parse().unwrap(),
        dns: vec![
            "198.19.255.2".parse().unwrap(),
            "fd00:ae61::2".parse().unwrap(),
        ],
        mtu: 1280,
        profile_sha256: "c".repeat(64),
    }
}

const TERMS_FRAME: &str = r#"{"schema":"aegis-ne-xpc-v1","verb":"profile-terms","report":{"relay":"192.168.1.107:443","dns":["198.19.255.2","fd00:ae61::2"],"mtu":1280,"profile_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}"#;

#[test]
fn provider_xpc_profile_terms_codec_round_trips_and_refuses_unknown_fields() {
    assert_eq!(
        encode_request(Verb::ProfileTerms),
        br#"{"schema":"aegis-ne-xpc-v1","verb":"profile-terms"}"#
    );
    assert_eq!(
        decode_request(&encode_request(Verb::ProfileTerms)),
        Ok(Verb::ProfileTerms)
    );
    assert_eq!(Verb::from_flag("--profile-terms"), Some(Verb::ProfileTerms));
    let reply = Reply::ProfileTerms(fixture_terms());
    let bytes = encode_reply(&reply).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        serde_json::from_str::<Value>(TERMS_FRAME).unwrap()
    );
    assert_eq!(decode_reply(&bytes, Verb::ProfileTerms), Ok(reply));
    // Decoded only for the verb it answers.
    assert_eq!(
        decode_reply(&bytes, Verb::Status),
        Err("reply_verb_mismatch")
    );
    let refused = |frame: String| {
        assert_eq!(
            decode_reply(frame.as_bytes(), Verb::ProfileTerms),
            Err("reply_malformed"),
            "{frame}"
        );
    };
    // An unknown, extra or missing field in the report or the envelope.
    for (from, to) in [
        (r#""mtu":1280,"#, r#""mtu":1280,"device_key":"x","#),
        (r#""mtu":1280,"#, r#""mtu":1280,"certificate_pem":"x","#),
        (r#""mtu":1280,"#, r#""mtu":1280,"bundle_path":"/a","#),
        (r#""mtu":1280,"#, ""),
        (r#""report":{"#, r#""extra":1,"report":{"#),
    ] {
        refused(TERMS_FRAME.replacen(from, to, 1));
    }
    let envelope = TERMS_FRAME.replacen(r#""report":{"#, r#""extra":1,"report":{"#, 1);
    assert!(decode_reply(envelope.as_bytes(), Verb::ProfileTerms).is_err());
    // Non-canonical or invalid values.
    for (from, to) in [
        ("192.168.1.107:443", "192.168.1.107"),
        ("192.168.1.107:443", "192.168.001.207:443"),
        ("192.168.1.107:443", "192.168.1.107:0"),
        ("192.168.1.107:443", "[2001:DB8::10]:443"),
        ("192.168.1.107:443", "127.0.0.1:443"),
        ("192.168.1.107:443", "198.18.0.1:443"),
        ("192.168.1.107:443", "relay.example:443"),
        (r#""fd00:ae61::2""#, r#""FD00:AE61::2""#),
        (r#""fd00:ae61::2""#, r#""fd00:ae61:0::2""#),
        (r#""fd00:ae61::2""#, r#""fd00:ae61::2","192.0.2.53""#),
        (r#""fd00:ae61::2""#, "2"),
        (r#""198.19.255.2","fd00:ae61::2""#, ""),
        ("1280", "1279"),
        ("1280", "70000"),
        ("1280", r#""1280""#),
        (&"c".repeat(64), &"C".repeat(64)),
        (&"c".repeat(64), &"c".repeat(63)),
    ] {
        refused(TERMS_FRAME.replacen(from, to, 1));
    }
}

/// The provider responder over a real capture of `container`, read-leased on
/// a test-local tree gate, as the native observer captures its own container
/// under `PROVIDER_TREE_GATE` (`capture_terms_claim`).
struct TermsObserver(PathBuf, &'static TreeGate);
impl TermsObserver {
    fn new(container: &Path) -> Self {
        Self(container.to_owned(), gate())
    }
}
impl Observer for TermsObserver {
    fn ping(&self) -> PingReport {
        ping_report()
    }
    fn status(&self) -> StatusReport {
        FakeObserver.status()
    }
    fn profile_terms(&self) -> Result<ProfileTerms, &'static str> {
        let gate = self.1;
        profile_terms::provider_terms(|| {
            let inputs = crate::app_group::CapturedAppGroupInputs::capture_test_root_read_leased(
                &self.0, gate,
            );
            // The capture holds a read lease while the terms are read; it
            // is never a session holder.
            assert!(gate.readers() >= usize::from(inputs.is_ok()));
            assert_eq!(gate.holders(), 0);
            inputs
        })
    }
}

#[test]
fn provider_xpc_profile_terms_returns_only_the_held_public_terms() {
    let tree = ReadyTree::new("192.0.2.10:443".parse().unwrap());
    let observer = TermsObserver::new(tree.root());
    // No peer euid: the verb needs no identity-verb authorization.
    let bytes = respond_entries(
        &[(FRAME_KEY, &encode_request(Verb::ProfileTerms))],
        None,
        &observer,
    );
    let expected = ProfileTerms {
        relay: tree.relay(),
        dns: tree.policy().dns().to_vec(),
        mtu: tree.policy().mtu(),
        profile_sha256: tree.profile_sha256().to_owned(),
    };
    assert_eq!(
        decode_reply(&bytes, Verb::ProfileTerms),
        Ok(Reply::ProfileTerms(expected.clone()))
    );
    // Exactly the four public keys: no key, certificate, secret or path.
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let mut keys: Vec<&String> = value["report"].as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["dns", "mtu", "profile_sha256", "relay"]);
    let text = String::from_utf8(bytes.clone()).unwrap();
    for leaked in [
        "BEGIN",
        "PRIVATE",
        "CERTIFICATE",
        tree.root().to_str().unwrap(),
        "/",
    ] {
        assert!(!text.contains(leaked), "{leaked}");
    }
    let key = std::fs::read(tree.identity_dir().join("device.key")).unwrap();
    assert!(!bytes.windows(key.len()).any(|window| window == key));
    // The held capture and its tree lease are released before the reply:
    // no holder remains, so an import or forget on this gate is admitted.
    assert_eq!(observer.1.holders(), 0);
    assert_eq!(observer.1.readers(), 0);
    assert_eq!(
        respond(Ok(encode_request(Verb::ProfileTerms)), &observer),
        bytes
    );
    assert_eq!(observer.1.holders(), 0);
    // An extra envelope key is refused like any non-import verb.
    let extra = respond_entries(
        &[
            (FRAME_KEY, &encode_request(Verb::ProfileTerms)),
            (c"manifest", b"{}"),
        ],
        None,
        &observer,
    );
    assert_eq!(
        decode_reply(&extra, Verb::ProfileTerms),
        Ok(Reply::Refused("envelope_shape".into()))
    );
}

#[test]
fn provider_xpc_profile_terms_refuses_without_an_identity() {
    let empty = TempContainer::new();
    let observer = TermsObserver::new(empty.path());
    let bytes = respond(Ok(encode_request(Verb::ProfileTerms)), &observer);
    assert_eq!(
        decode_reply(&bytes, Verb::ProfileTerms),
        Ok(Reply::Refused("aegis_tree_missing".into()))
    );
    assert_eq!(observer.1.holders(), 0);
    let tree = ReadyTree::new("192.0.2.10:443".parse().unwrap());
    let observer = TermsObserver::new(tree.root());
    std::fs::remove_file(tree.identity_dir().join("identity.json")).unwrap();
    let bytes = respond(Ok(encode_request(Verb::ProfileTerms)), &observer);
    assert_eq!(
        decode_reply(&bytes, Verb::ProfileTerms),
        Ok(Reply::Refused("file_missing:identity.json".into()))
    );
    assert_eq!(observer.1.holders(), 0);
    // An observer without the verb refuses it; so does the default.
    let bytes = respond(Ok(encode_request(Verb::ProfileTerms)), &FakeObserver);
    assert_eq!(
        decode_reply(&bytes, Verb::ProfileTerms),
        Ok(Reply::Refused("profile_terms_unavailable".into()))
    );
}

/// A refusal code a host could not decode is never sent as such.
struct OddTermsObserver;
impl Observer for OddTermsObserver {
    fn ping(&self) -> PingReport {
        ping_report()
    }
    fn status(&self) -> StatusReport {
        FakeObserver.status()
    }
    fn profile_terms(&self) -> Result<ProfileTerms, &'static str> {
        Err("Not A Stable/Code")
    }
}

#[test]
fn provider_xpc_profile_terms_host_query_pins_the_provider_first() {
    let bytes = respond(Ok(encode_request(Verb::ProfileTerms)), &OddTermsObserver);
    assert_eq!(
        decode_reply(&bytes, Verb::ProfileTerms),
        Ok(Reply::Refused(profile_terms::TERMS_REFUSED.into()))
    );
    let client = FakeEndpoint {
        reply: Some(Ok(TERMS_FRAME.as_bytes().to_vec())),
        ..Default::default()
    };
    assert_eq!(
        query(&client, Verb::ProfileTerms),
        Ok(Reply::ProfileTerms(fixture_terms()))
    );
    assert_eq!(client.events.borrow().first().unwrap(), "require:provider");
    assert_eq!(client.events.borrow().last().unwrap(), "cancel");
}

// ---------------------------------------------------------------------------
// Audit: administrator approval of the identity verbs, and public terms
// that cannot hold the identity verbs off.

/// An import dictionary with `authorization` replaced (or removed: `None`).
fn import_message_with(payload: &ImportPayload, authorization: Option<&[u8]>) -> XpcOwned {
    let frame = encode_request(Verb::Import);
    let manifest = encode_manifest(&payload.manifest());
    let mut entries = import_entries(&frame, &[], &manifest, payload);
    match authorization {
        Some(form) => entries[1].1 = form,
        None => {
            entries.remove(1);
        }
    }
    framed_entries(&entries).unwrap()
}

#[test]
fn provider_xpc_identity_verbs_need_one_fresh_administrator_approval() {
    let target = TempContainer::new();
    let observer = IdentityObserver::new(target.path());
    let source = ReadyTree::with_online_completed(relay());
    let payload = payload_of(&source);
    let oversized = vec![1u8; 4096];
    // Missing or malformed approval: refused before the payload is read or
    // anything is written.
    for (authorization, code) in [
        (None, "identity_authorization_missing"),
        (Some(&[7u8; 31][..]), "identity_authorization_malformed"),
        (Some(&oversized[..]), "identity_authorization_malformed"),
        (Some(&[0u8; 32][..]), "identity_authorization_malformed"),
    ] {
        let message = import_message_with(&payload, authorization);
        assert_eq!(
            answer_of(&message, Some(CONSOLE), &observer, Verb::Import),
            Reply::Refused(code.into()),
            "{code}"
        );
    }
    // A broken payload with no approval is never parsed.
    let broken = import_message_with(&payload, None);
    set_data(broken.as_ptr(), MANIFEST_KEY, b"not json");
    assert_eq!(
        answer_of(&broken, Some(CONSOLE), &observer, Verb::Import),
        Reply::Refused("identity_authorization_missing".into())
    );
    assert_eq!(*observer.imports.borrow(), 0);
    assert!(std::fs::read_dir(target.path()).unwrap().next().is_none());
    // A fresh approval commits once; the same request replayed is refused
    // before the payload is read again.
    let form = fresh_form();
    let message = import_message_with(&payload, Some(&form));
    assert!(matches!(
        answer_of(&message, Some(CONSOLE), &observer, Verb::Import),
        Reply::Import(_)
    ));
    assert_eq!(*observer.imports.borrow(), 1);
    let committed = snapshot(target.path());
    assert_eq!(
        answer_of(&message, Some(CONSOLE), &observer, Verb::Import),
        Reply::Refused("identity_authorization_replayed".into())
    );
    assert_eq!(*observer.imports.borrow(), 1);
    // The import's approval does not forget either.
    let frame = encode_request(Verb::ForgetIdentity);
    let reused = framed_entries(&[(FRAME_KEY, &frame), (AUTHORIZATION_KEY, &form)]).unwrap();
    let bare = framed(&frame).unwrap();
    for (message, code) in [
        (&bare, "identity_authorization_missing"),
        (&reused, "identity_authorization_replayed"),
    ] {
        assert_eq!(
            answer_of(message, Some(CONSOLE), &observer, Verb::ForgetIdentity),
            Reply::Refused(code.into()),
            "{code}"
        );
    }
    assert_eq!(snapshot(target.path()), committed);
    // A fresh approval forgets once; its replay changes nothing.
    let forget = forget_message();
    assert!(matches!(
        answer_of(&forget, Some(CONSOLE), &observer, Verb::ForgetIdentity),
        Reply::Forget(ForgetReport {
            identity_was_present: true,
            key_material_removed: true
        })
    ));
    assert_eq!(
        answer_of(&forget, Some(CONSOLE), &observer, Verb::ForgetIdentity),
        Reply::Refused("identity_authorization_replayed".into())
    );
    // The peer checks still run first: an approval never stands in for the
    // console admin, and an unauthorized peer does not spend it.
    let stranger = IdentityObserver {
        principals: FakePrincipals {
            console: Ok(CONSOLE),
            admins: Ok(vec![]),
        },
        ..IdentityObserver::new(target.path())
    };
    let form = fresh_form();
    let message = import_message_with(&payload, Some(&form));
    assert_eq!(
        answer_of(&message, Some(CONSOLE), &stranger, Verb::Import),
        Reply::Refused("peer_not_admin".into())
    );
    assert_eq!(stranger.authorizations.spent(), 0);
}

#[test]
fn provider_xpc_read_only_verbs_refuse_an_authorization_key() {
    let target = TempContainer::new();
    let observer = IdentityObserver::new(target.path());
    for verb in [
        Verb::Ping,
        Verb::Status,
        Verb::ProfileTerms,
        Verb::CertStatus,
        Verb::FilterStatus,
        Verb::IdentityGate,
    ] {
        let frame = encode_request(verb);
        // The current key and (v30) the legacy one alike.
        for key in [AUTHORIZATION_KEY, LEGACY_AUTHORIZATION_KEYS[0]] {
            let message = framed_entries(&[(FRAME_KEY, &frame), (key, &fresh_form())]).unwrap();
            assert_eq!(
                decode_reply(
                    &respond_message(message.as_ptr(), Some(CONSOLE), &observer),
                    verb
                ),
                Ok(Reply::Refused("envelope_shape".into())),
                "{verb:?} {key:?}"
            );
        }
    }
    // A forget with one key besides its approval is refused as a shape.
    let frame = encode_request(Verb::ForgetIdentity);
    let message = framed_entries(&[
        (FRAME_KEY, &frame),
        (AUTHORIZATION_KEY, &fresh_form()),
        (MANIFEST_KEY, b"{}"),
    ])
    .unwrap();
    assert_eq!(
        answer_of(&message, Some(CONSOLE), &observer, Verb::ForgetIdentity),
        Reply::Refused("envelope_shape".into())
    );
    assert_eq!(observer.authorizations.spent(), 0);
}

#[test]
fn provider_xpc_host_sends_the_approval_with_each_identity_verb() {
    let forgotten = Reply::Forget(ForgetReport {
        identity_was_present: false,
        key_material_removed: true,
    });
    let client = FakeEndpoint {
        reply: Some(Ok(encode_reply(&forgotten).unwrap())),
        ..Default::default()
    };
    assert_eq!(
        query_authorized(&client, Verb::ForgetIdentity, &fresh_form()),
        Ok(forgotten)
    );
    assert_eq!(
        *client.events.borrow(),
        [
            "require:provider",
            "inert",
            "resume",
            "exchange_entries",
            "cancel"
        ]
    );
    // Read-only verbs and import never go this way; identity verbs never
    // go without an approval.
    for verb in [Verb::Ping, Verb::ProfileTerms, Verb::Import] {
        let client = FakeEndpoint::default();
        assert_eq!(
            query_authorized(&client, verb, &fresh_form()),
            Err("verb_not_authorized_separately")
        );
        assert!(client.events.borrow().is_empty());
    }
    for verb in [Verb::ForgetIdentity, Verb::Renew] {
        assert!(verb.requires_authorization());
        assert_eq!(query_provider(verb), Err("identity_authorization_required"));
    }
    assert!(Verb::Import.requires_authorization());
    for verb in [
        Verb::Ping,
        Verb::Status,
        Verb::ProfileTerms,
        Verb::CertStatus,
        Verb::FilterStatus,
        Verb::IdentityGate,
    ] {
        assert!(!verb.requires_authorization(), "{verb:?}");
    }
}

#[test]
fn provider_xpc_profile_terms_flood_cannot_hold_off_import_or_forget() {
    let target = TempContainer::new();
    let observer = IdentityObserver::new(target.path());
    // A public relay address, so the held terms pass the full-wide policy.
    let public: std::net::SocketAddr = "192.0.2.10:443".parse().unwrap();
    let installed = ReadyTree::new(public);
    import::import_tree(
        target.path(),
        uid(),
        observer.gate,
        &payload_of(&installed),
        |_| {},
    )
    .unwrap();
    let terms = TermsObserver(target.path().to_owned(), observer.gate);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Four unauthenticated peers asking for the terms back to back.
    let flood: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            let terms = TermsObserver(terms.0.clone(), terms.1);
            std::thread::spawn(move || {
                let mut answered = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    // Terms while a tree is held; a refusal once it is gone.
                    let bytes = respond(Ok(encode_request(Verb::ProfileTerms)), &terms);
                    match decode_reply(&bytes, Verb::ProfileTerms) {
                        Ok(Reply::ProfileTerms(_)) => answered += 1,
                        Ok(Reply::Refused(_)) => {}
                        other => panic!("{other:?}"),
                    }
                }
                answered
            })
        })
        .collect();
    // Let the flood run before each identity verb.
    let flooding = || {
        let started = std::time::Instant::now();
        while observer.gate.readers() == 0 && started.elapsed() < Duration::from_secs(2) {
            std::thread::yield_now();
        }
    };
    flooding();
    let source = ReadyTree::with_online_completed(public);
    let started = std::time::Instant::now();
    let reply = answer_of(
        &import_message(&payload_of(&source), |_| {}),
        Some(CONSOLE),
        &observer,
        Verb::Import,
    );
    let import_took = started.elapsed();
    assert!(matches!(reply, Reply::Import(_)), "{reply:?}");
    flooding();
    let started = std::time::Instant::now();
    let reply = answer_of(
        &forget_message(),
        Some(CONSOLE),
        &observer,
        Verb::ForgetIdentity,
    );
    let forget_took = started.elapsed();
    assert!(matches!(reply, Reply::Forget(_)), "{reply:?}");
    stop.store(true, Ordering::Relaxed);
    let answered: u32 = flood.into_iter().map(|t| t.join().unwrap()).sum();
    assert!(answered > 0);
    // Bounded by the reader drain, never refused as a live session.
    for took in [import_took, forget_took] {
        assert!(
            took < import::READER_DRAIN + Duration::from_secs(1),
            "{took:?}"
        );
    }
    assert_eq!(observer.gate.holders(), 0);
}

struct FilterObserver(FilterStatusReport);
impl Observer for FilterObserver {
    fn ping(&self) -> PingReport {
        ping_report()
    }
    fn status(&self) -> StatusReport {
        FakeObserver.status()
    }
    fn filter_status(&self) -> Result<FilterStatusReport, &'static str> {
        Ok(self.0.clone())
    }
}

fn filter_report() -> FilterStatusReport {
    use crate::leak_guard::{Attachment, Counters, Gate, Peer, Reason};
    let gate = Gate::new();
    gate.arm(
        Some(Peer::from(
            "203.0.113.10:443".parse::<SocketAddr>().unwrap(),
        )),
        false,
    );
    let counters = Counters::new();
    counters.count(Reason::TcpOut);
    counters.count(Reason::TcpOut);
    counters.count(Reason::Relay);
    let attachment = Attachment::new();
    attachment.attach(4242);
    filter_status_of(&gate, &counters, &attachment, 4242)
}

/// One change to a decoded `filter-status` report.
type ReportEdit<'a> = &'a dyn Fn(&mut Map<String, Value>);

/// S20b: `filter-status` is read-only, carries the gate and counters and
/// never an address; its decoder refuses every inconsistent shape.
#[test]
fn provider_xpc_filter_status_round_trips_the_gate_and_counters_without_addresses() {
    use crate::leak_guard::{Attachment, Counters, Gate, COUNTED};
    let report = filter_report();
    assert!(report.attached && report.pid_match);
    assert_eq!(report.mode, "guarding");
    assert_eq!(report.armed_token, Some(1));
    assert!(report.relay_armed && !report.authority_armed && !report.udp_relay_allowed);
    assert_eq!(report.counters.len(), COUNTED.len());
    assert!(report.counters.contains(&("drop_tcp_out".into(), 2)));
    assert!(report.counters.contains(&("allow_relay".into(), 1)));
    // Another pid, a detached filter and an Open gate.
    let gate = Gate::new();
    let attachment = Attachment::new();
    let open = filter_status_of(&gate, &Counters::new(), &attachment, 1);
    assert!(!open.attached && !open.pid_match);
    assert_eq!((open.mode.as_str(), open.armed_token), ("open", None));
    attachment.attach(7);
    assert!(!filter_status_of(&gate, &Counters::new(), &attachment, 8).pid_match);
    attachment.detach();
    assert!(!filter_status_of(&gate, &Counters::new(), &attachment, 7).attached);

    assert_eq!(
        decode_request(&encode_request(Verb::FilterStatus)),
        Ok(Verb::FilterStatus)
    );
    assert_eq!(
        encode_request(Verb::FilterStatus),
        br#"{"schema":"aegis-ne-xpc-v1","verb":"filter-status"}"#
    );
    let bytes = respond(
        Ok(encode_request(Verb::FilterStatus)),
        &FilterObserver(report.clone()),
    );
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains("203.0.113.10"), "{text}");
    assert_eq!(
        decode_reply(&bytes, Verb::FilterStatus),
        Ok(Reply::FilterStatus(report.clone()))
    );
    // Without an implementation the verb is refused, never answered.
    let refused = respond(Ok(encode_request(Verb::FilterStatus)), &FakeObserver);
    assert_eq!(
        decode_reply(&refused, Verb::FilterStatus),
        Ok(Reply::Refused("filter_status_unavailable".into()))
    );
    assert_eq!(
        decode_reply(&bytes, Verb::Status),
        Err("reply_verb_mismatch")
    );

    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let edit = |change: &dyn Fn(&mut Map<String, Value>)| {
        let mut value = value.clone();
        change(value["report"].as_object_mut().unwrap());
        decode_reply(&serde_json::to_vec(&value).unwrap(), Verb::FilterStatus)
    };
    let refusals: [(&str, ReportEdit); 11] = [
        ("unknown mode", &|r| {
            r.insert("mode".into(), json!("strict"));
        }),
        ("generation while open", &|r| {
            r.insert("mode".into(), json!("open"));
            r.insert("relay_armed".into(), json!(false));
        }),
        ("open with a relay armed", &|r| {
            r.insert("mode".into(), json!("open"));
            r.insert("armed_token".into(), Value::Null);
        }),
        ("guarding without a generation", &|r| {
            r.insert("armed_token".into(), Value::Null);
        }),
        ("pid match without attachment", &|r| {
            r.insert("attached".into(), json!(false));
        }),
        ("missing counter", &|r| {
            r["counters"]
                .as_object_mut()
                .unwrap()
                .remove("drop_tcp_out");
        }),
        ("extra counter", &|r| {
            r["counters"]
                .as_object_mut()
                .unwrap()
                .insert("drop_extra".into(), json!(1));
        }),
        ("renamed counter", &|r| {
            let counters = r["counters"].as_object_mut().unwrap();
            let value = counters.remove("drop_tcp_out").unwrap();
            counters.insert("drop_tcp_outbound".into(), value);
        }),
        ("negative counter", &|r| {
            r["counters"]
                .as_object_mut()
                .unwrap()
                .insert("drop_tcp_out".into(), json!(-1));
        }),
        ("extra key", &|r| {
            r.insert("relay".into(), json!("203.0.113.10:443"));
        }),
        ("missing key", &|r| {
            r.remove("udp_relay_allowed");
        }),
    ];
    for (name, change) in refusals {
        assert_eq!(edit(change), Err("reply_malformed"), "{name}");
    }
    // A consistent Open report decodes.
    assert!(edit(&|r| {
        r.insert("mode".into(), json!("open"));
        r.insert("armed_token".into(), Value::Null);
        r.insert("relay_armed".into(), json!(false));
    })
    .is_ok());
}

/// v27 (S20f): a report whose gate, counters and ring hold drops on three
/// interface classes, with documentation addresses only.
fn observed_report() -> FilterStatusReport {
    use crate::leak_guard::{filter_packet, Attachment, Counters, Gate, Peer};
    let gate = Gate::new();
    gate.arm(
        Some(Peer::from(
            "203.0.113.10:443".parse::<SocketAddr>().unwrap(),
        )),
        false,
    );
    gate.set_primary(Some(b"en7"));
    let counters = Counters::new();
    let syn = |dst: [u8; 4]| {
        let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00];
        frame.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 192, 0, 2, 50]);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&[
            0xc3, 0x50, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        frame
    };
    for (name, direction) in [
        (&b"en7"[..], 2),
        (b"en0", 2),
        (b"awdl0", 1),
        (b"a user name", 0),
    ] {
        filter_packet(
            &gate,
            &counters,
            Some(name),
            direction,
            &syn([198, 51, 100, 9]),
        );
    }
    let attachment = Attachment::new();
    attachment.attach(4242);
    filter_status_of(&gate, &counters, &attachment, 4242)
}

/// v27 (S20f): `filter-status` carries the arm accounting, the drops by
/// class and direction and the drop ring under one added key, never an
/// address; a reply without it still decodes, and the decoder refuses every
/// token it does not know.
#[test]
fn provider_xpc_filter_status_observability_round_trips_without_addresses() {
    let report = observed_report();
    let observed = report.observability.clone().expect("observability");
    assert_eq!((observed.arm_seq, observed.disarms), (1, 0));
    assert!(observed.armed_for_ms.is_some());
    assert_eq!(observed.primary_iface.as_deref(), Some("en7"));
    assert_eq!(
        observed.drops,
        vec![
            ("primary".to_string(), [0, 1, 0]),
            ("en_other".to_string(), [0, 1, 0]),
            ("awdl_llw".to_string(), [1, 0, 0]),
            ("bridge_ap_anpi".to_string(), [0, 0, 0]),
            ("other".to_string(), [0, 0, 1]),
        ]
    );
    assert_eq!(
        (
            observed.ring_next,
            observed.ring_skipped,
            observed.ring_torn
        ),
        (4, 0, 0)
    );
    let entries: Vec<_> = observed
        .recent_drops
        .iter()
        .map(|e| {
            (
                e.index,
                e.class.as_str(),
                e.iface.as_str(),
                e.dir.as_str(),
                e.tcp.as_str(),
            )
        })
        .collect();
    assert_eq!(entries[0], (0, "primary", "en7", "out", "syn"));
    assert_eq!(entries[1], (1, "en_other", "en0", "out", "syn"));
    assert_eq!(entries[2], (2, "awdl_llw", "awdl0", "in", "syn"));
    assert_eq!(entries[3].1, "other");
    assert!(entries[3].2.starts_with("h:"));
    assert!(observed
        .recent_drops
        .iter()
        .all(|e| e.family == "v4" && e.proto == 6));

    let bytes = respond(
        Ok(encode_request(Verb::FilterStatus)),
        &FilterObserver(report.clone()),
    );
    let text = String::from_utf8(bytes.clone()).unwrap();
    for address in ["203.0.113.10", "198.51.100.9", "192.0.2.50", "a user name"] {
        assert!(!text.contains(address), "{address}: {text}");
    }
    assert_eq!(
        decode_reply(&bytes, Verb::FilterStatus),
        Ok(Reply::FilterStatus(report.clone()))
    );
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    // A v26 provider's reply, without the key, decodes as before.
    let mut old = value.clone();
    old["report"]
        .as_object_mut()
        .unwrap()
        .remove("observability");
    let mut without = report.clone();
    without.observability = None;
    assert_eq!(
        decode_reply(&serde_json::to_vec(&old).unwrap(), Verb::FilterStatus),
        Ok(Reply::FilterStatus(without.clone()))
    );
    assert_eq!(
        encode_reply(&Reply::FilterStatus(without)).unwrap(),
        serde_json::to_vec(&old).unwrap()
    );

    let edit = |change: &dyn Fn(&mut Map<String, Value>)| {
        let mut value = value.clone();
        change(value["report"]["observability"].as_object_mut().unwrap());
        decode_reply(&serde_json::to_vec(&value).unwrap(), Verb::FilterStatus)
    };
    let entry = |r: &mut Map<String, Value>, key: &str, v: Value| {
        r["ring"]["entries"][0][key] = v;
    };
    let refusals: [(&str, ReportEdit); 21] = [
        ("extra key", &|r| {
            r.insert("relay".into(), json!("203.0.113.10:443"));
        }),
        ("missing key", &|r| {
            r.remove("disarms");
        }),
        ("negative count", &|r| {
            r.insert("open_while_applied".into(), json!(-1));
        }),
        ("armed age not a number", &|r| {
            r.insert("armed_for_ms".into(), json!("5"));
        }),
        ("primary named none", &|r| {
            r.insert("primary_iface".into(), json!("none"));
        }),
        ("primary an address", &|r| {
            r.insert("primary_iface".into(), json!("192.0.2.1"));
        }),
        ("unknown class", &|r| {
            let drops = r["drops"].as_object_mut().unwrap();
            let row = drops.remove("other").unwrap();
            drops.insert("wifi".into(), row);
        }),
        ("missing class", &|r| {
            r["drops"].as_object_mut().unwrap().remove("awdl_llw");
        }),
        ("extra direction", &|r| {
            r["drops"]["primary"]["both"] = json!(1);
        }),
        ("ring extra key", &|r| {
            r["ring"]["dropped"] = json!(0);
        }),
        ("entry extra key", &|r| {
            entry(r, "dst", json!("198.51.100.9"))
        }),
        ("entry address as iface", &|r| {
            entry(r, "iface", json!("198.51.100.9"))
        }),
        ("entry unknown dir", &|r| entry(r, "dir", json!("up"))),
        ("entry unknown tcp", &|r| entry(r, "tcp", json!("syn-ack"))),
        ("entry unknown family", &|r| entry(r, "family", json!("v5"))),
        ("entry allow reason", &|r| {
            entry(r, "reason", json!("allow_relay"))
        }),
        ("entry protocol 256", &|r| entry(r, "proto", json!(256))),
        ("entry unknown class", &|r| {
            entry(r, "class", json!("primary_en"))
        }),
        ("entries out of order", &|r| entry(r, "index", json!(3))),
        ("too many entries", &|r| {
            let first = r["ring"]["entries"][0].clone();
            let entries = r["ring"]["entries"].as_array_mut().unwrap();
            entries.clear();
            for index in 0..=crate::leak_guard::RING_SLOTS {
                let mut e = first.clone();
                e["index"] = json!(index);
                entries.push(e);
            }
        }),
        ("observability emptied", &|r| {
            r.clear();
        }),
    ];
    for (name, change) in refusals {
        assert_eq!(edit(change), Err("reply_malformed"), "{name}");
    }
    // A null armed age (Open) and a null primary decode.
    assert!(edit(&|r| {
        r.insert("armed_for_ms".into(), Value::Null);
        r.insert("primary_iface".into(), Value::Null);
    })
    .is_ok());
}

/// v27: the largest possible ring still fits one reply frame.
#[test]
fn provider_xpc_the_fullest_observability_fits_one_reply() {
    let mut report = observed_report();
    let observed = report.observability.as_mut().unwrap();
    let template = observed.recent_drops[3].clone();
    observed.recent_drops = (0..crate::leak_guard::RING_SLOTS as u64)
        .map(|k| DropEntry {
            index: u64::MAX - 64 + k,
            arm_seq: u64::from(u32::MAX),
            ms: u64::from(u32::MAX),
            class: "bridge_ap_anpi".into(),
            dir: "any".into(),
            tcp: "ack_only".into(),
            reason: "drop_icmp6_other".into(),
            proto: 255,
            ..template.clone()
        })
        .collect();
    for (_, row) in &mut observed.drops {
        *row = [u64::MAX; 3];
    }
    observed.arm_seq = u64::MAX;
    observed.armed_ms_total = u64::MAX;
    for (_, value) in &mut report.counters {
        *value = u64::MAX;
    }
    let bytes = encode_reply(&Reply::FilterStatus(report.clone())).expect("fits");
    assert!(bytes.len() <= MAX_REPLY_BYTES, "{}", bytes.len());
    assert_eq!(
        decode_reply(&bytes, Verb::FilterStatus),
        Ok(Reply::FilterStatus(report))
    );
}

/// v29 (S20h): a report with outbound drops of the Mac to the LAN gateway on
/// the pinned `en0`: one bare ACK from a port of the marker range, one data
/// segment from another port, and an inbound segment that is never an
/// outbound drop.
fn outbound_report() -> FilterStatusReport {
    use crate::leak_guard::{filter_packet, Attachment, Counters, Gate, Peer, MARK_SPORT_FIRST};
    let gate = Gate::new();
    gate.arm(
        Some(Peer::from(
            "203.0.113.10:443".parse::<SocketAddr>().unwrap(),
        )),
        false,
    );
    gate.set_primary(Some(b"en0"));
    let counters = Counters::new();
    let segment = |sport: u16, flags: u8, payload: &[u8], inbound: bool| {
        let (src, dst) = if inbound {
            ([192, 0, 2, 1], [192, 0, 2, 50])
        } else {
            ([192, 0, 2, 50], [192, 0, 2, 1])
        };
        let total = (40 + payload.len()) as u16;
        let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00, 0x45, 0];
        frame.extend_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&sport.to_be_bytes());
        frame.extend_from_slice(&[
            0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        frame.extend_from_slice(payload);
        frame
    };
    for (frame, direction) in [
        (segment(MARK_SPORT_FIRST + 1, 0x10, b"", false), 2),
        (segment(50001, 0x18, b"aegis", false), 2),
        (segment(MARK_SPORT_FIRST + 1, 0x10, b"", true), 1),
    ] {
        filter_packet(&gate, &counters, Some(b"en0"), direction, &frame);
    }
    let attachment = Attachment::new();
    attachment.attach(4242);
    filter_status_of(&gate, &counters, &attachment, 4242)
}

/// v29 (S20h): `filter-status` observability carries the outbound drops by
/// class and kind, the marked ones and the ring of outbound drops under one
/// added key, never an address; a v28 provider's observability without it
/// still decodes, and the decoder refuses every token it does not know.
#[test]
fn provider_xpc_filter_status_outbound_round_trips_without_addresses() {
    use crate::leak_guard::{OutKind, MARK_SPORT_COUNT, MARK_SPORT_FIRST};
    let report = outbound_report();
    let observed = report.observability.clone().expect("observability");
    let outbound = observed.outbound.clone().expect("outbound");
    assert_eq!(
        (outbound.mark_sport_first, outbound.mark_sport_count),
        (MARK_SPORT_FIRST, MARK_SPORT_COUNT)
    );
    assert_eq!(outbound.kinds[0].0, "primary");
    let mut primary = [0u64; 8];
    primary[OutKind::AckOnly.slot()] = 1;
    primary[OutKind::Data.slot()] = 1;
    assert_eq!(outbound.kinds[0].1, primary);
    let mut marked = [0u64; 8];
    marked[OutKind::AckOnly.slot()] = 1;
    assert_eq!(outbound.marked[0].1, marked);
    assert!(outbound.kinds[1..].iter().all(|(_, row)| *row == [0; 8]));
    assert_eq!(
        (
            outbound.ring_next,
            outbound.ring_skipped,
            outbound.ring_torn
        ),
        (2, 0, 0)
    );
    assert_eq!(
        outbound
            .recent
            .iter()
            .map(|out| (
                out.entry.index,
                out.entry.dir.as_str(),
                out.entry.tcp.as_str(),
                out.entry.iface.as_str(),
                out.marked
            ))
            .collect::<Vec<_>>(),
        [
            (0, "out", "ack_only", "en0", true),
            (1, "out", "data", "en0", false)
        ]
    );
    // The v27 ring still holds every drop, the inbound one included.
    assert_eq!(observed.ring_next, 3);
    let bytes = respond(
        Ok(encode_request(Verb::FilterStatus)),
        &FilterObserver(report.clone()),
    );
    let text = String::from_utf8(bytes.clone()).unwrap();
    // No address and no port of a dropped segment; only the marker's range.
    let marked_port = (MARK_SPORT_FIRST + 1).to_string();
    for address in [
        "203.0.113.10",
        "192.0.2.1",
        "192.0.2.50",
        "50001",
        marked_port.as_str(),
    ] {
        assert!(!text.contains(address), "{address}: {text}");
    }
    assert_eq!(
        decode_reply(&bytes, Verb::FilterStatus),
        Ok(Reply::FilterStatus(report.clone()))
    );
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    // A v28 provider's observability, without the key, decodes without it
    // and encodes back to the same bytes.
    let mut old = value.clone();
    old["report"]["observability"]
        .as_object_mut()
        .unwrap()
        .remove("outbound");
    let mut without = report.clone();
    without.observability.as_mut().unwrap().outbound = None;
    assert_eq!(
        decode_reply(&serde_json::to_vec(&old).unwrap(), Verb::FilterStatus),
        Ok(Reply::FilterStatus(without.clone()))
    );
    assert_eq!(
        encode_reply(&Reply::FilterStatus(without)).unwrap(),
        serde_json::to_vec(&old).unwrap()
    );

    let edit = |change: &dyn Fn(&mut Map<String, Value>)| {
        let mut value = value.clone();
        change(
            value["report"]["observability"]["outbound"]
                .as_object_mut()
                .unwrap(),
        );
        decode_reply(&serde_json::to_vec(&value).unwrap(), Verb::FilterStatus)
    };
    let entry = |r: &mut Map<String, Value>, key: &str, v: Value| {
        r["ring"]["entries"][0][key] = v;
    };
    let refusals: [(&str, ReportEdit); 19] = [
        ("extra key", &|r| {
            r.insert("gateway".into(), json!("192.0.2.1"));
        }),
        ("missing key", &|r| {
            r.remove("marked");
        }),
        ("mark port above 65535", &|r| {
            r.insert("mark_sport_first".into(), json!(65_536));
        }),
        ("mark count negative", &|r| {
            r.insert("mark_sport_count".into(), json!(-1));
        }),
        ("unknown class", &|r| {
            let kinds = r["kinds"].as_object_mut().unwrap();
            let row = kinds.remove("other").unwrap();
            kinds.insert("wifi".into(), row);
        }),
        ("missing class", &|r| {
            r["marked"].as_object_mut().unwrap().remove("awdl_llw");
        }),
        ("missing kind", &|r| {
            r["kinds"]["primary"].as_object_mut().unwrap().remove("rst");
        }),
        ("extra kind", &|r| {
            r["marked"]["primary"]["keepalive"] = json!(1);
        }),
        ("kind not a count", &|r| {
            r["kinds"]["primary"]["ack_only"] = json!("1");
        }),
        ("ring extra key", &|r| {
            r["ring"]["lost"] = json!(0);
        }),
        ("entry without marked", &|r| {
            r["ring"]["entries"][0]
                .as_object_mut()
                .unwrap()
                .remove("marked");
        }),
        ("entry marked not a bool", &|r| entry(r, "marked", json!(1))),
        ("entry inbound", &|r| entry(r, "dir", json!("in"))),
        ("entry address as iface", &|r| {
            entry(r, "iface", json!("192.0.2.1"))
        }),
        ("entry extra key", &|r| entry(r, "dport", json!(80))),
        ("entry allow reason", &|r| {
            entry(r, "reason", json!("allow_relay"))
        }),
        ("entries out of order", &|r| entry(r, "index", json!(1))),
        ("too many entries", &|r| {
            let first = r["ring"]["entries"][0].clone();
            let entries = r["ring"]["entries"].as_array_mut().unwrap();
            entries.clear();
            for index in 0..=crate::leak_guard::RING_SLOTS {
                let mut e = first.clone();
                e["index"] = json!(index);
                entries.push(e);
            }
        }),
        ("outbound emptied", &|r| {
            r.clear();
        }),
    ];
    for (name, change) in refusals {
        assert_eq!(edit(change), Err("reply_malformed"), "{name}");
    }
    let mut null = value.clone();
    null["report"]["observability"]["outbound"] = Value::Null;
    assert_eq!(
        decode_reply(&serde_json::to_vec(&null).unwrap(), Verb::FilterStatus),
        Err("reply_malformed")
    );
}

/// v29: both rings at their largest, every count at its largest, still fit
/// one reply frame.
#[test]
fn provider_xpc_the_fullest_v29_observability_fits_one_reply() {
    let mut report = outbound_report();
    let observed = report.observability.as_mut().unwrap();
    let template = DropEntry {
        index: 0,
        arm_seq: u64::from(u32::MAX),
        ms: u64::from(u32::MAX),
        class: "bridge_ap_anpi".into(),
        iface: "h:7fffffff".into(),
        dir: "any".into(),
        family: "none".into(),
        proto: 255,
        tcp: "syn_ack".into(),
        reason: "drop_icmp6_other".into(),
    };
    observed.recent_drops = (0..crate::leak_guard::RING_SLOTS as u64)
        .map(|k| DropEntry {
            index: u64::MAX - 64 + k,
            ..template.clone()
        })
        .collect();
    for (_, row) in &mut observed.drops {
        *row = [u64::MAX; 3];
    }
    observed.arm_seq = u64::MAX;
    observed.disarms = u64::MAX;
    observed.armed_ms_total = u64::MAX;
    observed.armed_for_ms = Some(u64::MAX);
    observed.open_while_applied = u64::MAX;
    observed.applied_epochs = u64::MAX;
    observed.ring_next = u64::MAX;
    observed.ring_skipped = u64::MAX;
    observed.ring_torn = u64::MAX;
    let outbound = observed.outbound.as_mut().unwrap();
    for (_, row) in outbound.kinds.iter_mut().chain(outbound.marked.iter_mut()) {
        *row = [u64::MAX; 8];
    }
    outbound.ring_next = u64::MAX;
    outbound.ring_skipped = u64::MAX;
    outbound.ring_torn = u64::MAX;
    outbound.recent = (0..crate::leak_guard::RING_SLOTS as u64)
        .map(|k| OutDropEntry {
            entry: DropEntry {
                index: u64::MAX - 64 + k,
                dir: "out".into(),
                ..template.clone()
            },
            marked: false,
        })
        .collect();
    for (_, value) in &mut report.counters {
        *value = u64::MAX;
    }
    let bytes = encode_reply(&Reply::FilterStatus(report.clone())).expect("fits");
    assert!(bytes.len() <= MAX_REPLY_BYTES, "{}", bytes.len());
    assert_eq!(
        decode_reply(&bytes, Verb::FilterStatus),
        Ok(Reply::FilterStatus(report))
    );
}

// ---------------------------------------------------------------------------
// v30 (S21j): the identity gate under the provider sandbox.

/// The import, forget and renew dictionaries an earlier host (v26 to v29)
/// sends: its form under the legacy key `authorization`.
fn legacy_messages(payload: &ImportPayload) -> Vec<(Verb, XpcOwned)> {
    let legacy = LEGACY_AUTHORIZATION_KEYS[0];
    assert_eq!(legacy, c"authorization");
    // The current key replaced by the legacy one: exactly what a v29 host
    // sends.
    let frame = encode_request(Verb::Import);
    let manifest = encode_manifest(&payload.manifest());
    let form = fresh_form();
    let mut entries = import_entries(&frame, &form, &manifest, payload);
    entries[1].0 = legacy;
    let v29_import = framed_entries(&entries).unwrap();
    let mut messages = vec![(Verb::Import, v29_import)];
    for verb in [Verb::ForgetIdentity, Verb::Renew] {
        let frame = encode_request(verb);
        messages.push((
            verb,
            framed_entries(&[(FRAME_KEY, &frame), (legacy, &fresh_form())]).unwrap(),
        ));
    }
    messages
}

#[test]
fn provider_xpc_an_outdated_host_is_refused_before_any_other_check() {
    let target = TempContainer::new();
    let source = ReadyTree::with_online_completed(relay());
    let payload = payload_of(&source);
    let observer = IdentityObserver::new(target.path());
    let stranger = IdentityObserver {
        principals: FakePrincipals {
            console: Ok(CONSOLE),
            admins: Ok(vec![]),
        },
        ..IdentityObserver::new(target.path())
    };
    for (verb, message) in legacy_messages(&payload) {
        for (peer, observer) in [
            (Some(CONSOLE), &observer),
            (None, &observer),
            (Some(CONSOLE), &stranger),
        ] {
            assert_eq!(
                answer_of(&message, peer, observer, verb),
                Reply::Refused("identity_authorization_host_outdated".into()),
                "{verb:?} {peer:?}"
            );
        }
        // Even a broken payload is never read for it.
        if verb == Verb::Import {
            set_data(message.as_ptr(), MANIFEST_KEY, b"not json");
            assert_eq!(
                answer_of(&message, Some(CONSOLE), &observer, verb),
                Reply::Refused("identity_authorization_host_outdated".into())
            );
        }
    }
    assert_eq!(observer.authorizations.spent(), 0);
    assert_eq!(stranger.authorizations.spent(), 0);
    assert_eq!(*observer.imports.borrow(), 0);
    assert!(std::fs::read_dir(target.path()).unwrap().next().is_none());
    // Both keys at once is no host's message: a shape refusal.
    let frame = encode_request(Verb::ForgetIdentity);
    let both = framed_entries(&[
        (FRAME_KEY, &frame),
        (AUTHORIZATION_KEY, &fresh_form()),
        (LEGACY_AUTHORIZATION_KEYS[0], &fresh_form()),
    ])
    .unwrap();
    assert_eq!(
        answer_of(&both, Some(CONSOLE), &observer, Verb::ForgetIdentity),
        Reply::Refused("envelope_shape".into())
    );
    // An import with both is refused the same way, before its approval is
    // spent or its payload read.
    let both_import = import_message(&payload, |m| {
        let form = fresh_form();
        set_data(m, LEGACY_AUTHORIZATION_KEYS[0], &form);
    });
    assert_eq!(
        answer_of(&both_import, Some(CONSOLE), &observer, Verb::Import),
        Reply::Refused("envelope_shape".into())
    );
    assert_eq!(observer.authorizations.spent(), 0);
    // A host older than v26 sends no form at all.
    let bare = framed(&frame).unwrap();
    assert_eq!(
        answer_of(&bare, Some(CONSOLE), &observer, Verb::ForgetIdentity),
        Reply::Refused("identity_authorization_missing".into())
    );
    // The genuine v30 host's form, under the current key, is admitted.
    assert!(matches!(
        answer_of(
            &forget_message(),
            Some(CONSOLE),
            &observer,
            Verb::ForgetIdentity
        ),
        Reply::Forget(_)
    ));
    assert_eq!(AUTHORIZATION_KEY, c"identity-approval");
}

/// Every call an identity request reaches, so no refusal can be followed
/// by a change.
struct CallLog<'a> {
    inner: &'a IdentityObserver,
    calls: RefCell<Vec<&'static str>>,
}
impl Observer for CallLog<'_> {
    fn ping(&self) -> PingReport {
        self.inner.ping()
    }
    fn status(&self) -> StatusReport {
        self.inner.status()
    }
    fn authorize(&self, peer_euid: u32) -> Result<(), &'static str> {
        self.calls.borrow_mut().push("authorize");
        self.inner.authorize(peer_euid)
    }
    fn admit_authorization(&self, form: Option<&[u8]>) -> Result<(), &'static str> {
        self.calls.borrow_mut().push("admit");
        self.inner.admit_authorization(form)
    }
    fn import(&self, payload: &ImportPayload) -> Result<ImportReport, &'static str> {
        self.calls.borrow_mut().push("import");
        self.inner.import(payload)
    }
    fn forget(&self) -> Result<ForgetReport, &'static str> {
        self.calls.borrow_mut().push("forget");
        self.inner.forget()
    }
    fn renew(&self) -> Result<RenewReport, &'static str> {
        self.calls.borrow_mut().push("renew");
        Ok(RenewReport {
            outcome: "renew_scheduled".into(),
        })
    }
}

#[test]
fn provider_xpc_no_identity_verb_changes_anything_after_a_refusal() {
    let target = TempContainer::new();
    let source = ReadyTree::with_online_completed(relay());
    let payload = payload_of(&source);
    let inner = IdentityObserver::new(target.path());
    let log = CallLog {
        inner: &inner,
        calls: RefCell::new(Vec::new()),
    };
    let frame = |verb| encode_request(verb);
    let spent = fresh_form();
    // Spend one form first: its replay is a refusal too.
    let first = framed_entries(&[
        (FRAME_KEY, &frame(Verb::Renew)),
        (AUTHORIZATION_KEY, &spent),
    ])
    .unwrap();
    assert!(matches!(
        answer_of_with(&first, Some(CONSOLE), &log, Verb::Renew),
        Reply::Renew(_)
    ));
    assert_eq!(log.calls.take(), ["authorize", "admit", "renew"]);
    for verb in [Verb::Import, Verb::ForgetIdentity, Verb::Renew] {
        let broken = |key: &'static CStr, form: &[u8]| {
            if verb == Verb::Import {
                let message = import_message_with(&payload, Some(form));
                if key != AUTHORIZATION_KEY {
                    let entries_frame = frame(verb);
                    let manifest = encode_manifest(&payload.manifest());
                    let mut entries = import_entries(&entries_frame, form, &manifest, &payload);
                    entries[1].0 = key;
                    let rebuilt = framed_entries(&entries).unwrap();
                    set_data(rebuilt.as_ptr(), MANIFEST_KEY, b"not json");
                    return rebuilt;
                }
                set_data(message.as_ptr(), MANIFEST_KEY, b"not json");
                message
            } else {
                framed_entries(&[(FRAME_KEY, &frame(verb)), (key, form)]).unwrap()
            }
        };
        let cases: [(XpcOwned, Option<u32>, &str, &[&str]); 5] = [
            (
                broken(LEGACY_AUTHORIZATION_KEYS[0], &fresh_form()),
                Some(CONSOLE),
                "identity_authorization_host_outdated",
                &[],
            ),
            (
                broken(AUTHORIZATION_KEY, &fresh_form()),
                Some(CONSOLE + 1),
                "peer_not_console_user",
                &["authorize"],
            ),
            (
                broken(AUTHORIZATION_KEY, &fresh_form()),
                None,
                "peer_unidentified",
                &[],
            ),
            (
                broken(AUTHORIZATION_KEY, &[9u8; 31]),
                Some(CONSOLE),
                "identity_authorization_malformed",
                &["authorize", "admit"],
            ),
            (
                broken(AUTHORIZATION_KEY, &spent),
                Some(CONSOLE),
                "identity_authorization_replayed",
                &["authorize", "admit"],
            ),
        ];
        for (message, peer, code, calls) in cases {
            assert_eq!(
                answer_of_with(&message, peer, &log, verb),
                Reply::Refused(code.into()),
                "{verb:?} {code}"
            );
            assert_eq!(log.calls.take(), calls, "{verb:?} {code}");
        }
    }
    assert_eq!(*inner.imports.borrow(), 0);
    assert!(std::fs::read_dir(target.path()).unwrap().next().is_none());
}

fn answer_of_with(
    message: &XpcOwned,
    peer: Option<u32>,
    observer: &impl Observer,
    verb: Verb,
) -> Reply {
    decode_reply(&respond_message(message.as_ptr(), peer, observer), verb).unwrap()
}

/// An observer whose identity gate reports fixed rule states and the peer
/// as the verbs' own peer check sees it.
struct GateObserver(IdentityObserver);
impl Observer for GateObserver {
    fn ping(&self) -> PingReport {
        self.0.ping()
    }
    fn status(&self) -> StatusReport {
        self.0.status()
    }
    fn authorize(&self, peer_euid: u32) -> Result<(), &'static str> {
        self.0.authorize(peer_euid)
    }
    fn identity_gate(
        &self,
        peer: Result<(), &'static str>,
    ) -> Result<IdentityGateReport, &'static str> {
        Ok(IdentityGateReport {
            peer: peer.err().unwrap_or("admitted").into(),
            identity_rule: "unregistered".into(),
            proof_rule: "admitted".into(),
            proof_probe: "allowed".into(),
        })
    }
}

#[test]
fn provider_xpc_identity_gate_reports_without_a_form_or_a_change() {
    let target = TempContainer::new();
    let observer = GateObserver(IdentityObserver::new(target.path()));
    let request = framed(&encode_request(Verb::IdentityGate)).unwrap();
    for (peer, expected) in [
        (Some(CONSOLE), "admitted"),
        (Some(CONSOLE + 1), "peer_not_console_user"),
        (None, "peer_unidentified"),
    ] {
        let Reply::IdentityGate(report) =
            answer_of_with(&request, peer, &observer, Verb::IdentityGate)
        else {
            panic!("no gate report");
        };
        assert_eq!(report.peer, expected);
        assert_eq!(report.blocker().is_none(), expected == "admitted");
    }
    assert_eq!(observer.0.authorizations.spent(), 0);
    assert!(std::fs::read_dir(target.path()).unwrap().next().is_none());
    // An observer without it refuses.
    assert_eq!(
        answer_of_with(&request, Some(CONSOLE), &FakeObserver, Verb::IdentityGate),
        Reply::Refused("identity_gate_unavailable".into())
    );
    // The codec: exact keys and tokens; the peer a stable code.
    let open = IdentityGateReport {
        peer: "admitted".into(),
        identity_rule: "admitted".into(),
        proof_rule: "admitted".into(),
        proof_probe: "allowed".into(),
    };
    assert_eq!(open.blocker(), None);
    assert_eq!(
        open.line(),
        "identity_gate=open peer=admitted identity_rule=admitted proof_rule=admitted proof_probe=allowed"
    );
    let reply = Reply::IdentityGate(open.clone());
    assert_eq!(
        decode_reply(&encode_reply(&reply).unwrap(), Verb::IdentityGate),
        Ok(reply)
    );
    assert_eq!(
        decode_request(&encode_request(Verb::IdentityGate)),
        Ok(Verb::IdentityGate)
    );
    assert_eq!(Verb::from_flag("--identity-gate"), Some(Verb::IdentityGate));
    for (field, value, blocker) in [
        ("peer", "peer_not_admin", "peer_not_admin"),
        ("peer", "peer_in_setup_group", "peer_in_setup_group"),
        (
            "identity_rule",
            "inadmissible",
            "identity_rule_inadmissible",
        ),
        ("identity_rule", "unavailable", "identity_rule_unavailable"),
        ("proof_rule", "unexpected", "proof_rule_unexpected"),
        ("proof_probe", "denied", "proof_probe_denied"),
        ("proof_probe", "failed", "proof_probe_failed"),
    ] {
        let mut report = open.clone();
        match field {
            "peer" => report.peer = value.into(),
            "identity_rule" => report.identity_rule = value.into(),
            "proof_rule" => report.proof_rule = value.into(),
            _ => report.proof_probe = value.into(),
        }
        assert_eq!(
            report.blocker().as_deref(),
            Some(blocker),
            "{field}={value}"
        );
        assert!(report.line().starts_with("identity_gate=closed "));
        let reply = Reply::IdentityGate(report);
        assert_eq!(
            decode_reply(&encode_reply(&reply).unwrap(), Verb::IdentityGate),
            Ok(reply)
        );
    }
    let base = || {
        json!({"schema": SCHEMA, "verb": "identity-gate", "report": {
            "peer": "admitted", "identity_rule": "admitted", "proof_rule": "admitted", "proof_probe": "allowed"}})
    };
    let mut bad = Vec::new();
    for (key, value) in [
        ("identity_rule", json!("weak")),
        ("proof_rule", json!("admitted ")),
        ("proof_probe", json!(true)),
        ("peer", json!("Peer Admitted")),
        ("peer", json!("")),
        ("extra", json!(1)),
    ] {
        let mut value_json = base();
        value_json["report"][key] = value;
        bad.push(value_json);
    }
    let mut missing = base();
    missing["report"]
        .as_object_mut()
        .unwrap()
        .remove("proof_probe");
    bad.push(missing);
    for value in bad {
        assert_eq!(
            decode_reply(&serde_json::to_vec(&value).unwrap(), Verb::IdentityGate),
            Err("reply_malformed"),
            "{value}"
        );
    }
}

#[test]
fn provider_xpc_an_approval_is_sent_once_and_spent() {
    let approval = IdentityApproval::for_tests(fresh_form());
    assert_eq!(approval.external_form().len(), EXTERNAL_FORM_LENGTH);
    let client = FakeEndpoint {
        reply: Some(Ok(encode_reply(&Reply::Renew(RenewReport {
            outcome: "renew_scheduled".into(),
        }))
        .unwrap())),
        ..Default::default()
    };
    assert!(matches!(
        query_authorized(&client, Verb::Renew, approval.external_form()),
        Ok(Reply::Renew(_))
    ));
    approval.spend();
}

/// The test binary's own designated requirement (an ad-hoc `cdhash`).
fn own_requirement() -> CString {
    let mut code = std::ptr::null();
    assert_eq!(unsafe { SecCodeCopySelf(0, &mut code) }, 0);
    let code = OwnedCf(code);
    let mut requirement = std::ptr::null();
    assert_eq!(
        unsafe { SecCodeCopyDesignatedRequirement(code.0, 0, &mut requirement) },
        0
    );
    let requirement = OwnedCf(requirement);
    CString::new(canonical(&requirement)).unwrap()
}

/// One `status` request from this process to an anonymous in-process
/// listener that admits each peer exactly as the provider does, under
/// `requirement`. No Mach service is looked up or registered.
fn anonymous_round_trip(requirement: CString) -> Result<Reply, &'static str> {
    let listener =
        XpcOwned::new(unsafe { xpc_connection_create(std::ptr::null(), std::ptr::null_mut()) })
            .unwrap();
    let handler: RcBlock<dyn Fn(XpcObject)> = RcBlock::new(move |event: XpcObject| {
        if is_type(event, unsafe { &_xpc_type_connection }) {
            let _ = admit_peer_with(&NativeConnection(event), &requirement);
        }
    });
    unsafe {
        xpc_connection_set_event_handler(listener.as_ptr(), &handler);
        xpc_connection_resume(listener.as_ptr());
    }
    let endpoint = XpcOwned::new(unsafe { xpc_endpoint_create(listener.as_ptr()) }).unwrap();
    let client =
        XpcOwned::new(unsafe { xpc_connection_create_from_endpoint(endpoint.as_ptr()) }).unwrap();
    let connection = NativeConnection(client.as_ptr());
    connection.set_handler(false);
    connection.resume();
    let reply = connection
        .exchange(&encode_request(Verb::Status))
        .and_then(|bytes| decode_reply(&bytes, Verb::Status));
    connection.cancel();
    unsafe { xpc_connection_cancel(listener.as_ptr()) };
    reply
}

/// Real libxpc: a peer is served only under a requirement it satisfies.
/// The unsigned test binary is refused under the host requirement and its
/// wrong-team and wrong-identifier variants, and served under its own.
#[test]
fn provider_xpc_libxpc_serves_only_a_peer_that_satisfies_the_requirement() {
    assert!(matches!(
        anonymous_round_trip(own_requirement()),
        Ok(Reply::Status(_))
    ));
    let host = HOST_PEER_REQUIREMENT.to_str().unwrap();
    let wrong_team = host.replace("TEAMID0000", "AAAAAAAAAA");
    let wrong_identifier = host.replace("\"dev.aegis.macos\"", "\"dev.aegis.macos.other\"");
    assert_ne!(wrong_team, host);
    assert_ne!(wrong_identifier, host);
    for requirement in [host.to_owned(), wrong_team, wrong_identifier] {
        let reply = anonymous_round_trip(CString::new(requirement.clone()).unwrap());
        assert!(reply.is_err(), "{requirement}: {reply:?}");
    }
}

#[test]
fn cert_status_carries_parked_superseded_and_check_and_older_shapes_still_decode() {
    // v32 (T14): the live incident's window (macos-test-2).
    let superseded = CertStatusReport {
        state: "superseded".into(),
        not_before: Some(1_792_693_436),
        not_after: Some(1_793_187_830),
        renew_at: Some(1_793_023_032),
        attempts: 1,
        last_attempt_at: Some(1_793_082_041),
        next_attempt_at: Some(1_793_082_101),
        last_failure: Some("local_refused".into()),
        failing_since: Some(1_793_082_041),
        check: Some("renewal_successor_not_extending".into()),
    };
    let parked = CertStatusReport {
        state: "parked".into(),
        last_failure: Some("rejected".into()),
        check: None,
        ..superseded.clone()
    };
    for report in [&superseded, &parked] {
        let reply = Reply::CertStatus(report.clone());
        let bytes = encode_reply(&reply).unwrap();
        assert_eq!(decode_reply(&bytes, Verb::CertStatus), Ok(reply));
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.contains("\"check\""), report.check.is_some(), "{text}");
    }
    // A check is refused unless it is listed and beside local_refused, or
    // (v32 review) beside another class while the request stays journaled
    // (`pending`, `superseded`, `expired`).
    let text =
        String::from_utf8(encode_reply(&Reply::CertStatus(superseded.clone())).unwrap()).unwrap();
    let rejected = text.replace(
        "\"last_failure\":\"local_refused\"",
        "\"last_failure\":\"rejected\"",
    );
    for (from, to) in [
        (
            "\"check\":\"renewal_successor_not_extending\"",
            "\"check\":\"renewal_other\"",
        ),
        (
            "\"last_failure\":\"local_refused\"",
            "\"last_failure\":null",
        ),
        (
            "\"check\":\"renewal_successor_not_extending\"",
            "\"check\":1",
        ),
    ] {
        let changed = text.replace(from, to);
        assert_ne!(changed, text, "{from}");
        assert!(
            decode_reply(changed.as_bytes(), Verb::CertStatus).is_err(),
            "{to}"
        );
    }
    for (state, kept) in [
        ("superseded", true),
        ("pending", true),
        ("expired", true),
        ("parked", false),
        ("valid", false),
        ("failed:rejected", false),
    ] {
        let changed = rejected.replace(
            "\"state\":\"superseded\"",
            &format!("\"state\":\"{state}\""),
        );
        assert_eq!(
            decode_reply(changed.as_bytes(), Verb::CertStatus).is_ok(),
            kept,
            "{state}"
        );
    }
    // v32 review: a superseded request whose later attempt was rejected
    // still names its check in the host line.
    let later = CertStatusReport {
        last_failure: Some("rejected".into()),
        ..superseded.clone()
    };
    let reply = Reply::CertStatus(later.clone());
    assert_eq!(
        decode_reply(&encode_reply(&reply).unwrap(), Verb::CertStatus),
        Ok(reply)
    );
    assert!(later
        .renewal_line()
        .unwrap()
        .starts_with("renewal superseded (renewal_successor_not_extending) since "));
    // The v30 eight-key and v31 nine-key shapes still decode.
    let v31 = format!(
        "{{\"schema\":\"{SCHEMA}\",\"verb\":\"cert-status\",\"report\":{{\"state\":\"failed:connect_timeout\",\"not_before\":1,\"not_after\":4,\"renew_at\":3,\"attempts\":2,\"last_attempt_at\":3,\"next_attempt_at\":5,\"last_failure\":\"connect_timeout\",\"failing_since\":3}}}}"
    );
    let v30 = format!(
        "{{\"schema\":\"{SCHEMA}\",\"verb\":\"cert-status\",\"report\":{{\"state\":\"valid\",\"not_before\":1,\"not_after\":4,\"renew_at\":3,\"attempts\":0,\"last_attempt_at\":null,\"next_attempt_at\":null,\"last_failure\":null}}}}"
    );
    for shape in [v31, v30] {
        let Ok(Reply::CertStatus(report)) = decode_reply(shape.as_bytes(), Verb::CertStatus) else {
            panic!("{shape}");
        };
        assert_eq!(report.check, None);
    }
    // Every renewal check is a stable code.
    for check in RENEWAL_CHECKS {
        assert!(stable_code(check), "{check}");
    }
    // The host's lines: address-free, UTC only.
    assert_eq!(
        superseded.renewal_line().unwrap(),
        "renewal superseded (renewal_successor_not_extending) since 2026-10-27T06:20:41Z: the authority issued a successor this client refused; the relay no longer admits the installed certificate; import a new identity"
    );
    assert_eq!(
        parked.renewal_line().unwrap(),
        "renewal parked after rejected since 2026-10-27T06:20:41Z: the installed certificate is kept until 2026-10-28T11:43:50Z, 1 attempt; it retries at the next Connect after 2026-10-27T06:21:41Z; an import replaces the identity"
    );
    // v32 review: a parked request's later local check is named too (an
    // unpark the journal could not write).
    let unparked = CertStatusReport {
        last_failure: Some("local_refused".into()),
        check: Some("renewal_journal_write".into()),
        ..parked.clone()
    };
    assert!(unparked
        .renewal_line()
        .unwrap()
        .starts_with("renewal parked after local_refused (renewal_journal_write) since "));
    let failing = CertStatusReport {
        state: "pending".into(),
        check: Some("renewal_successor_not_yet_valid".into()),
        ..superseded.clone()
    };
    assert!(failing
        .renewal_line()
        .unwrap()
        .ends_with(", 1 attempt (renewal_successor_not_yet_valid)"));
    for line in [
        superseded.renewal_line().unwrap(),
        parked.renewal_line().unwrap(),
        failing.renewal_line().unwrap(),
    ] {
        assert!(
            !line.contains('/') && !line.contains("127.0.0.1") && !line.contains("BEGIN"),
            "{line}"
        );
    }
}
