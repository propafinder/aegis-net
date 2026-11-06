# AEGIS source map

This map indexes the current authored source directories. It is a navigation
guide; release status is recorded in the [beta-exit roadmap](ROADMAP.md). Start with [local development](development/local-development.md)
for source builds or [installation](../INSTALL.md) for an approved package.
The [directory index](PROJECT-MAP.md) accounts for every tracked directory;
local README files explain the responsibility and constraints of each authored subtree.

For exact responsibility boundaries and document placement, use
[component ownership](architecture/OWNERSHIP.md).

## Workspace and ownership

[Cargo.toml](../Cargo.toml) is the authoritative list of 15 workspace members.
Production transport, routing and algorithm logic is Rust. Host orchestration
also uses shell, PowerShell and Python; see [the language policy](development/shell-orchestration-policy.md).

| Directory | Responsibility | First source entry |
|---|---|---|
| [aegis-client](../aegis-client/README.md) | Ingress, route selection, device session and OS tunnel lifecycle | `src/main.rs`, `src/config.rs` |
| [aegis-server](../aegis-server/README.md) | Relay, forwarding policy, enrollment authority and device policy tools | `src/main.rs`, `src/config.rs` |
| [aegis-core](../aegis-core/README.md) | Shared protocols, TLS, Brain, direct strategies and optional traffic privacy | `src/lib.rs` |
| [aegis-geneva](../aegis-geneva/README.md) | Offline packet strategy engine and guarded Linux bridge | `src/lib.rs` |
| [aegis-quic-boring](../aegis-quic-boring/README.md) | Browser-like QUIC TLS adapter and native crypto boundary | `Cargo.toml`, `src/lib.rs` |
| [aegis-fingerprint](../aegis-fingerprint/README.md) | Fingerprint representations and comparison | `src/lib.rs` |
| [aegis-knowledge](../aegis-knowledge/README.md) | Knowledge and evidence representations | `src/lib.rs` |
| [aegis-android-jni](../aegis-android-jni/README.md) | JNI integration proof surface; not an accepted Android VPN | `src/lib.rs` |
| [aegis-web-carrier](../aegis-web-carrier/README.md) | Owned web-response framing and admission | `src/lib.rs` |
| [aegis-webrtc](../aegis-webrtc/README.md) | Optional owned DataChannel integration | `src/lib.rs` |
| [tools](../tools/README.md) | Measurement, transport lab, witness, macOS lab and Windows controller | Local tool READMEs and manifests |
| [tools/geneva](../tools/geneva/README.md) | Standalone Linux bridge and selected relay-profile installers; scoped native capture/lifecycle QA helpers | Local guide; not a separate workspace crate or general campaign manager |
| [tools/macos](../tools/macos/README.md) | SOCKS Keychain helper and opt-in NetworkExtension source | Local guides; separate credential and lifecycle authority |
| [tools/macos/aegis-network-extension](../tools/macos/aegis-network-extension/README.md) | Rust native host/provider, bounded packet bridge and shared packet-engine adapter | Standalone manifest with Apple/client-engine features; provider relay/credential custody and installed acceptance remain open |
| [scripts](../scripts/README.md) | Build, contract, installer and scoped operational orchestration | Script-local help and wrapper contracts |
| [packaging](../packaging/README.md) | Service definitions and platform package templates | Target-specific README files |
| [drivers](../drivers/README.md) | Platform driver/proof surfaces | Local platform README files |
| [tests](../tests/README.md) | Shared test fixtures and external contracts | Local fixture README files |
| [.github](../.github/README.md) | CI and release workflows | `workflows/ci.yml`, `workflows/release.yml` |
| [assets](../assets/README.md), [landing](../landing/README.md) | Branding, sample scripts and static site | Image assets are preserved unchanged |
| [third_party](../third_party/README.md) | Vendored h2 and uncommitted B-08 tungstenite privacy patch | `h2/AEGIS-PATCH.md`; `tungstenite/UPSTREAM.json` is pending the final source commit |
| artifacts (`evidence-archive/README.md`) | Dated evidence and retained attempts | Never infer current acceptance from an old PASS |

## Runtime path

```text
application → configured SOCKS / OS ingress → client policy + Brain
            → selected carrier → inner authenticated relay session
            → relay target policy → destination
```

Carrier selection and OS capture are separate responsibilities. SOCKS covers
applications configured to use it. Linux TUN, Windows Wintun/WFP and macOS lab
paths have distinct lifecycle and privilege requirements. A changed browser IP
does not prove all application traffic, DNS, UDP or native services are captured.

Cloudflare fronting selects `grpc_stream`; direct MASQUE exposes the relay IP.
Enrolled inner-TLS UDP is disabled or selects `grpc_datagram` only; legacy direct MASQUE and its
H2 fallback must not be substituted for that authenticated profile.
Owned HTTPS, web-response and WebRTC source paths are optional and preserve
separate device authentication. They are not evidence of deployed Snowflake,
Protozoa/SFU, Huma/Balboa or CensorLess service integration.

Geneva's offline grammar is broader than its live subset. The direct profile
exposes destination IPs; the managed outer profile targets the relay connection.
Read [Geneva boundaries](GENEVA-ROADMAP.md) before choosing a profile.

The [eleven-work matrix](research/implementation-and-composition.md) links
research algorithms to actual consumers and records composition restrictions.
Source integration does not certify model assumptions, physical traffic laws,
installed clients or target-network performance.

## Files at repository root

| File | Use |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | Workspace, pinned dependency resolution and compiler/components |
| `config.example.toml` | Broad client schema example; includes privileged wide/direct choices, not a safe default quickstart |
| `aegis-server.toml.example` | Relay schema example; certificate paths and credentials must be supplied privately |
| `install.sh`, `bootstrap-install.sh`, `install-server.sh` | Installer source and published-asset facades; verify the selected artifact before execution |
| `Dockerfile`, `compose.yaml` | Development relay container; Compose uses host networking and private local config/certs |
| `AGENTS.md` | Repository-specific change, evidence and secret-handling rules |
| `README.md`, `INSTALL.md`, `CONTRIBUTING.md` | Product overview, approved package operation, development workflow |
| `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE` | Source license texts and project/dependency notice boundary |
| `SECURITY.md`, `GOVERNANCE.md` | Vulnerability-reporting procedure and project decision/review responsibilities |

## Generated data is not disposable source

`target/` can contain compiler caches, Git worktrees, evidence staging and VM
homes. Ignored `dist/` also holds local distribution/VM data and release caches;
it is not tracked source and must not be erased as part of documentation cleanup.
Do not delete these trees wholesale or run an unscoped cleanup. `.git/` owns
object history and worktree metadata; it is never a documentation or scratch
output directory. See [storage management](development/storage-management.md).

There are no tracked root `platform/`, `deploy/`, `examples/`, `configs/` or
`certs/` directories in this snapshot. Example certificate paths refer to
private files supplied at deployment, not committed credentials.
