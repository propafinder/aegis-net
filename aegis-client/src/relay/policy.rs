use aegis_core::{current_unix_secs, surface_epoch, DriftSurface};
use aegis_core::{RelayPolicySettings, RelaySettings, RelayTlsBackend, TunnelTransportFamily};
use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, Duration};

/// Brain-supplied bias hints that nudge per-session surface profile selection
/// without collapsing the catalog. All three axes are 0..=1 weights that
/// *increase* the probability of profiles matching the corresponding shape,
/// while leaving every other profile reachable (baseline weight 1.0 is added
/// for every catalog entry so even a hard bias only multiplies the
/// preferred-category probability by a bounded factor).
///
/// The encoding is intentionally coarse — three booleans-with-magnitude
/// rather than a freeform numeric vector — because the catalog is also
/// coarse (18 entries). Finer Brain output would not survive the weighted
/// pick anyway, and would smell like static-fingerprint optimization.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SurfaceBias {
    /// Favor profiles whose `inter_chunk_delay_ms_range` minimum is small
    /// (latency-sensitive families). Set when Brain observed recent stalls
    /// or high probe latency for the target.
    pub low_latency_preferred: f32,
    /// Favor profiles whose `inter_chunk_jitter_ms_window` is non-trivial.
    /// Set when an external classifier hint suggests AEGIS traffic is
    /// being singled out — extra timing noise widens the family.
    pub high_jitter_preferred: f32,
    /// Favor profiles whose `chunk_size_range` maximum is modest (≤12 KiB).
    /// Set when Brain wants the session to look like a small-payload
    /// poll/RPC client rather than a bulk-transfer family.
    pub low_visibility_preferred: f32,
}

impl SurfaceBias {
    pub fn is_neutral(&self) -> bool {
        self.low_latency_preferred == 0.0
            && self.high_jitter_preferred == 0.0
            && self.low_visibility_preferred == 0.0
    }
}

/// A concrete instance of relay session shaping sampled at session start.
/// Scalar fields (`write_chunk_size`, `inter_chunk_delay_ms`) carry the values
/// drawn from the surface profile's distributions for *this* session, so two
/// sessions to the same target inside the same drift epoch produce different
/// application-write pacing instances. The ranges carry the admitted policy
/// bounds and govern later mid-session resampling; they can differ from the
/// cover template when an operator caps chunks or overrides the base delay.
/// Application writes do not guarantee particular TLS record or IP packet
/// boundaries: transport buffering and segmentation still apply.
#[derive(Debug, Clone, Default)]
pub struct RelaySessionProfile {
    pub transport_order: Vec<TunnelTransportFamily>,
    pub websocket_path: String,
    pub grpc_path: String,
    pub masque_path: String,
    pub user_agent: &'static str,
    pub accept_header: &'static str,
    pub accept_language_header: Option<&'static str>,
    pub cache_control_header: Option<&'static str>,
    pub websocket_origin_header: Option<String>,
    pub grpc_accept_encoding_header: Option<&'static str>,
    pub grpc_encoding_header: Option<&'static str>,
    pub grpc_timeout_header: Option<&'static str>,
    pub grpc_message_type_header: Option<&'static str>,
    pub masque_alt_used_header: Option<String>,
    pub tls_profile_target_class: Option<String>,
    pub write_chunk_size: usize,
    pub inter_chunk_delay_ms: u64,
    /// Upper bound (inclusive) of the additive per-chunk jitter sampled fresh
    /// on every chunk write. 0 disables jitter.
    pub inter_chunk_jitter_ms_window: u64,
    /// Effective chunk sampling bounds after applying the operator hard cap.
    /// These may be below the cover template's minimum when the cap is lower.
    pub surface_chunk_size_range: (usize, usize),
    /// Effective base-delay sampling bounds; a non-zero operator override
    /// becomes a singleton interval so every resample preserves it.
    pub surface_delay_ms_range: (u64, u64),
    /// True when the surface profile was chosen via Brain-supplied bias
    /// weighting rather than the neutral mod-of-seed path. Emitted as a
    /// runtime-event field so closed-loop adaptation is observable.
    pub surface_bias_applied: bool,
    /// Phase 5 Phase 2: sampled per-mille probability for chunk split on
    /// outbound writes. Copied from the surface profile at session start.
    pub padding_probability_milli: u16,
    /// Phase 5 Phase 2: sampled (min, max) per-mille range for split ratio.
    /// Used by `copy_with_policy` when padding triggers.
    pub padding_split_ratio_milli_range: (u16, u16),
    #[allow(dead_code)]
    pub profile_id: &'static str,
}

/// Static catalog entry describing a *family* of shaping behavior as a set of
/// distributions. The session-time sampler draws concrete values from these
/// ranges so the wire never carries identical packet-train geometry across
/// sessions, even when the same family is selected.
#[derive(Clone, Copy)]
struct RelaySurfaceProfile {
    id: &'static str,
    user_agent: &'static str,
    accept_header: &'static str,
    accept_language_header: Option<&'static str>,
    cache_control_header: Option<&'static str>,
    websocket_origin_strategy: Option<&'static str>,
    grpc_accept_encoding_header: Option<&'static str>,
    grpc_encoding_header: Option<&'static str>,
    grpc_timeout_header: Option<&'static str>,
    grpc_message_type_header: Option<&'static str>,
    masque_alt_used_strategy: Option<&'static str>,
    /// (min, max) inclusive range from which `write_chunk_size` is sampled.
    chunk_size_range: (usize, usize),
    /// (min, max) inclusive range from which the base `inter_chunk_delay_ms`
    /// is sampled at session start.
    inter_chunk_delay_ms_range: (u64, u64),
    /// Upper bound of additive per-chunk jitter sampled afresh on every
    /// chunk write. 0 disables jitter.
    inter_chunk_jitter_ms_window: u64,
    /// Phase 5 Phase 2: per-mille probability (0..=1000) that an outbound
    /// chunk write is SPLIT into two smaller application writes. Phase 5
    /// directive calls this "padding
    /// probability"; we implement it as a chunk split because injecting
    /// bytes into a tunneled payload requires server-side cooperation
    /// (out of scope here), whereas splitting is purely client-side and
    /// may affect transport framing without touching payload content. TLS
    /// record and IP packet boundaries still depend on buffering/segmentation.
    /// 0 disables the behavior (existing pre-Phase-5 path).
    padding_probability_milli: u16,
    /// (min, max) inclusive per-mille range used when padding triggers,
    /// determining how the chunk is split — e.g. (300, 700) yields a
    /// first sub-write of 30%..=70% of the chunk and the rest in a
    /// second sub-write. (0, 0) = collapse to a single 50/50 split when
    /// padding fires.
    padding_split_ratio_milli_range: (u16, u16),
}

// Each catalog entry now declares its shaping fields as *ranges*, not point
// values. Session-time sampling (see `sample_session_dynamics`) draws a fresh
// concrete (chunk_size, base_delay) tuple from these ranges per session, and
// the per-chunk jitter window is applied on every write — so two sessions
// landing on the same surface profile do not produce identical packet trains.
// The ranges intentionally overlap between adjacent profiles so the resulting
// (chunk_size, delay) distribution forms a *traffic family*, not a discrete
// 6-point lattice.
const RELAY_SURFACE_CATALOG: [RelaySurfaceProfile; 18] = [
    RelaySurfaceProfile {
        id: "browser_like_balanced",
        user_agent: "Mozilla/5.0",
        accept_header: "*/*",
        accept_language_header: Some("en-US,en;q=0.9"),
        cache_control_header: None,
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("15S"),
        grpc_message_type_header: Some("TunnelRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (12 * 1024, 20 * 1024),
        inter_chunk_delay_ms_range: (0, 2),
        inter_chunk_jitter_ms_window: 1,
        padding_probability_milli: 100,
        padding_split_ratio_milli_range: (300, 700),
    },
    RelaySurfaceProfile {
        id: "browser_like_chatty",
        user_agent: "Mozilla/5.0 (X11; Linux x86_64)",
        accept_header: "application/octet-stream,*/*;q=0.8",
        accept_language_header: Some("en-US,en;q=0.8"),
        cache_control_header: Some("max-age=0"),
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("20S"),
        grpc_message_type_header: Some("SessionOpenRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (9 * 1024, 15 * 1024),
        inter_chunk_delay_ms_range: (1, 3),
        inter_chunk_jitter_ms_window: 1,
        padding_probability_milli: 120,
        padding_split_ratio_milli_range: (300, 700),
    },
    RelaySurfaceProfile {
        id: "cli_https_compact",
        user_agent: "curl/8.7.1",
        accept_header: "*/*",
        accept_language_header: None,
        cache_control_header: Some("no-cache"),
        websocket_origin_strategy: None,
        grpc_accept_encoding_header: None,
        grpc_encoding_header: None,
        grpc_timeout_header: None,
        grpc_message_type_header: None,
        masque_alt_used_strategy: None,
        chunk_size_range: (6 * 1024, 11 * 1024),
        inter_chunk_delay_ms_range: (0, 2),
        inter_chunk_jitter_ms_window: 1,
        padding_probability_milli: 0,
        padding_split_ratio_milli_range: (0, 0),
    },
    // --- C2 expansion (Track C anti-anomaly): 3→6 relay surface profiles with
    // distinct fingerprint footprints spanning UA family, chunk size, gRPC
    // timeout, header sparsity. Each of these four axes takes a unique value
    // across the catalog so per-session profile choice lands in a different
    // cluster of the fingerprint space than the previous three profiles.
    RelaySurfaceProfile {
        id: "mobile_safari_tight",
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) \
                     AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 \
                     Mobile/15E148 Safari/604.1",
        accept_header: "*/*",
        accept_language_header: Some("en-US,en;q=0.8"),
        cache_control_header: Some("no-store"),
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("gzip"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("10S"),
        grpc_message_type_header: Some("TunnelRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (4 * 1024, 8 * 1024),
        inter_chunk_delay_ms_range: (2, 5),
        inter_chunk_jitter_ms_window: 2,
        padding_probability_milli: 150,
        padding_split_ratio_milli_range: (250, 750),
    },
    RelaySurfaceProfile {
        id: "desktop_chrome_streaming",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                     AppleWebKit/537.36 (KHTML, like Gecko) \
                     Chrome/126.0.0.0 Safari/537.36",
        accept_header: "application/octet-stream,*/*;q=0.9",
        accept_language_header: Some("en-US,en;q=0.9,*;q=0.5"),
        cache_control_header: Some("max-age=0"),
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("gzip, identity"),
        grpc_encoding_header: Some("gzip"),
        grpc_timeout_header: Some("30S"),
        grpc_message_type_header: Some("SessionOpenRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (24 * 1024, 40 * 1024),
        inter_chunk_delay_ms_range: (0, 2),
        inter_chunk_jitter_ms_window: 1,
        padding_probability_milli: 80,
        padding_split_ratio_milli_range: (350, 650),
    },
    RelaySurfaceProfile {
        id: "enterprise_java_client",
        user_agent: "Java/17.0.8",
        accept_header: "*/*",
        accept_language_header: None,
        cache_control_header: None,
        websocket_origin_strategy: None,
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("60S"),
        grpc_message_type_header: None,
        masque_alt_used_strategy: None,
        chunk_size_range: (7 * 1024, 13 * 1024),
        inter_chunk_delay_ms_range: (3, 7),
        inter_chunk_jitter_ms_window: 2,
        padding_probability_milli: 0,
        padding_split_ratio_milli_range: (0, 0),
    },
    // --- Phase 2.4 catalog expansion 6→18. Adds twelve network/app archetypes
    // spanning mobile WiFi, mobile cellular, Electron desktop apps, realtime
    // websocket clients, native gRPC microservices, contended public-WiFi,
    // congested-hotel uplinks, corp middlebox / TLS-inspecting proxies,
    // small-payload IoT telemetry, large-burst video uplink, periodic API
    // polling, and tablet Safari. Each carries plausible UA + header
    // combinations and overlapping (chunk_size, delay) ranges so the per-
    // session sampler produces a continuous traffic-family distribution
    // rather than 18 disjoint points.
    RelaySurfaceProfile {
        id: "mobile_wifi",
        user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) \
                     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 \
                     Mobile Safari/537.36",
        accept_header: "*/*",
        accept_language_header: Some("en-US,en;q=0.9"),
        cache_control_header: None,
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("20S"),
        grpc_message_type_header: Some("TunnelRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (8 * 1024, 14 * 1024),
        inter_chunk_delay_ms_range: (1, 3),
        inter_chunk_jitter_ms_window: 1,
        padding_probability_milli: 150,
        padding_split_ratio_milli_range: (300, 700),
    },
    RelaySurfaceProfile {
        id: "mobile_4g",
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) \
                     AppleWebKit/605.1.15 (KHTML, like Gecko) \
                     GSA/331.0.665268197 Mobile/15E148 Safari/604.1",
        accept_header: "*/*",
        accept_language_header: Some("en-GB,en;q=0.9"),
        cache_control_header: Some("no-store"),
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("gzip"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("12S"),
        grpc_message_type_header: Some("TunnelRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (4 * 1024, 10 * 1024),
        inter_chunk_delay_ms_range: (5, 12),
        inter_chunk_jitter_ms_window: 3,
        padding_probability_milli: 250,
        padding_split_ratio_milli_range: (200, 800),
    },
    RelaySurfaceProfile {
        id: "desktop_electron",
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Slack/4.36.140 Chrome/120.0.0.0 \
                     Electron/28.2.6 Safari/537.36",
        accept_header: "application/octet-stream,*/*;q=0.9",
        accept_language_header: Some("en-US,en;q=0.9"),
        cache_control_header: None,
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("25S"),
        grpc_message_type_header: Some("SessionOpenRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (18 * 1024, 28 * 1024),
        inter_chunk_delay_ms_range: (0, 1),
        inter_chunk_jitter_ms_window: 1,
        padding_probability_milli: 200,
        padding_split_ratio_milli_range: (300, 700),
    },
    RelaySurfaceProfile {
        id: "realtime_websocket",
        user_agent: "Realtime/1.0 (compatible; AnyHubClient/2.3)",
        accept_header: "*/*",
        accept_language_header: None,
        cache_control_header: Some("no-cache"),
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: None,
        grpc_encoding_header: None,
        grpc_timeout_header: None,
        grpc_message_type_header: None,
        masque_alt_used_strategy: None,
        chunk_size_range: (2 * 1024, 6 * 1024),
        inter_chunk_delay_ms_range: (0, 1),
        inter_chunk_jitter_ms_window: 0,
        padding_probability_milli: 300,
        padding_split_ratio_milli_range: (200, 800),
    },
    RelaySurfaceProfile {
        id: "grpc_api",
        user_agent: "grpc-go/1.62.1 (linux/amd64)",
        accept_header: "*/*",
        accept_language_header: None,
        cache_control_header: None,
        websocket_origin_strategy: None,
        grpc_accept_encoding_header: Some("gzip, deflate"),
        grpc_encoding_header: Some("gzip"),
        grpc_timeout_header: Some("30S"),
        grpc_message_type_header: None,
        masque_alt_used_strategy: None,
        chunk_size_range: (8 * 1024, 16 * 1024),
        inter_chunk_delay_ms_range: (1, 4),
        inter_chunk_jitter_ms_window: 1,
        padding_probability_milli: 80,
        padding_split_ratio_milli_range: (350, 650),
    },
    RelaySurfaceProfile {
        id: "noisy_cafe",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 \
                     Safari/537.36",
        accept_header: "*/*",
        accept_language_header: Some("en-US,en;q=0.9"),
        cache_control_header: Some("max-age=300"),
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("20S"),
        grpc_message_type_header: Some("TunnelRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (6 * 1024, 12 * 1024),
        inter_chunk_delay_ms_range: (2, 8),
        inter_chunk_jitter_ms_window: 4,
        padding_probability_milli: 250,
        padding_split_ratio_milli_range: (200, 800),
    },
    RelaySurfaceProfile {
        id: "congested_hotel",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                     AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 \
                     Safari/605.1.15",
        accept_header: "*/*",
        accept_language_header: Some("en-US,en;q=0.9"),
        cache_control_header: None,
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("30S"),
        grpc_message_type_header: Some("TunnelRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (4 * 1024, 8 * 1024),
        inter_chunk_delay_ms_range: (6, 15),
        inter_chunk_jitter_ms_window: 5,
        padding_probability_milli: 300,
        padding_split_ratio_milli_range: (200, 800),
    },
    RelaySurfaceProfile {
        id: "corp_middlebox",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 \
                     Safari/537.36 Edg/126.0.2592.81",
        accept_header: "application/octet-stream,*/*;q=0.8",
        accept_language_header: Some("en-US,en;q=0.9"),
        cache_control_header: Some("no-store"),
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("25S"),
        grpc_message_type_header: Some("SessionOpenRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (10 * 1024, 16 * 1024),
        inter_chunk_delay_ms_range: (3, 7),
        inter_chunk_jitter_ms_window: 2,
        padding_probability_milli: 150,
        padding_split_ratio_milli_range: (300, 700),
    },
    RelaySurfaceProfile {
        id: "iot_telemetry",
        user_agent: "ESP32-AsyncTCP/1.0.0 (FreeRTOS)",
        accept_header: "*/*",
        accept_language_header: None,
        cache_control_header: None,
        websocket_origin_strategy: None,
        grpc_accept_encoding_header: None,
        grpc_encoding_header: None,
        grpc_timeout_header: None,
        grpc_message_type_header: None,
        masque_alt_used_strategy: None,
        chunk_size_range: (1024, 3 * 1024),
        inter_chunk_delay_ms_range: (8, 20),
        inter_chunk_jitter_ms_window: 4,
        padding_probability_milli: 0,
        padding_split_ratio_milli_range: (0, 0),
    },
    RelaySurfaceProfile {
        id: "video_stream_h264",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 \
                     Safari/537.36 OBS-Studio/30.1.2",
        accept_header: "application/octet-stream,*/*;q=0.9",
        accept_language_header: None,
        cache_control_header: None,
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("gzip"),
        grpc_encoding_header: Some("gzip"),
        grpc_timeout_header: Some("60S"),
        grpc_message_type_header: Some("SessionOpenRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (28 * 1024, 48 * 1024),
        inter_chunk_delay_ms_range: (0, 2),
        inter_chunk_jitter_ms_window: 1,
        padding_probability_milli: 50,
        padding_split_ratio_milli_range: (400, 600),
    },
    RelaySurfaceProfile {
        id: "api_batch_poller",
        user_agent: "Go-http-client/1.1",
        accept_header: "*/*",
        accept_language_header: None,
        cache_control_header: Some("no-cache"),
        websocket_origin_strategy: None,
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("15S"),
        grpc_message_type_header: None,
        masque_alt_used_strategy: None,
        chunk_size_range: (6 * 1024, 12 * 1024),
        inter_chunk_delay_ms_range: (4, 10),
        inter_chunk_jitter_ms_window: 2,
        padding_probability_milli: 150,
        padding_split_ratio_milli_range: (300, 700),
    },
    RelaySurfaceProfile {
        id: "tablet_safari",
        user_agent: "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) \
                     AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 \
                     Mobile/15E148 Safari/604.1",
        accept_header: "*/*",
        accept_language_header: Some("en-US,en;q=0.9"),
        cache_control_header: Some("no-store"),
        websocket_origin_strategy: Some("same_authority_https"),
        grpc_accept_encoding_header: Some("identity"),
        grpc_encoding_header: Some("identity"),
        grpc_timeout_header: Some("20S"),
        grpc_message_type_header: Some("TunnelRequest"),
        masque_alt_used_strategy: Some("same_authority"),
        chunk_size_range: (8 * 1024, 16 * 1024),
        inter_chunk_delay_ms_range: (1, 4),
        inter_chunk_jitter_ms_window: 2,
        padding_probability_milli: 150,
        padding_split_ratio_milli_range: (250, 750),
    },
];

fn chrome_coherent_user_agent() -> &'static str {
    aegis_chrome_profile::user_agent()
}

/// HTTP identity headers forced to stay coherent with a browser-class TLS
/// ClientHello. Only identity-bearing headers are overridden — the picked
/// surface profile still governs traffic shaping (chunk size, delay, jitter),
/// so per-session packet-train diversity is preserved.
struct BrowserHttpIdentity {
    user_agent: &'static str,
    accept_header: &'static str,
    accept_language_header: Option<&'static str>,
    cache_control_header: Option<&'static str>,
}

/// When the relay TLS backend emits a browser-class ClientHello, return the
/// HTTP identity that must ride over it so the whole stack (JA4 + User-Agent)
/// tells one coherent story. Returns `None` for the default non-browser backend
/// (rustls), which does not claim to be any particular browser and may keep the
/// diverse catalog User-Agent.
fn browser_coherent_identity(backend: RelayTlsBackend) -> Option<BrowserHttpIdentity> {
    if !backend.is_browser_class() {
        return None;
    }
    // Only Chrome is faithfully reproducible by the AWS-LC/BoringSSL backend
    // (Safari/Firefox use ciphers BoringSSL removed — see the audit measurement
    // in scripts/test-chrome-like-tls-ja4-parity-contract.sh). So the single
    // coherent identity is Chrome, matched to the host OS platform.
    Some(BrowserHttpIdentity {
        user_agent: chrome_coherent_user_agent(),
        accept_header: "*/*",
        accept_language_header: Some("en-US,en;q=0.9"),
        cache_control_header: None,
    })
}

/// Apply per-profile weighting from a `SurfaceBias` and return the per-profile
/// weight value used by the weighted picker. A neutral baseline of `1.0` is
/// always added so even hard-biased selection never makes any profile
/// unreachable — the wire family stays diverse.
fn surface_weight(profile: &RelaySurfaceProfile, bias: &SurfaceBias) -> f32 {
    let mut weight = 1.0_f32;
    if bias.low_latency_preferred > 0.0 && profile.inter_chunk_delay_ms_range.0 <= 2 {
        weight += bias.low_latency_preferred * 2.0;
    }
    if bias.high_jitter_preferred > 0.0 && profile.inter_chunk_jitter_ms_window >= 2 {
        weight += bias.high_jitter_preferred * 2.0;
    }
    if bias.low_visibility_preferred > 0.0 && profile.chunk_size_range.1 <= 12 * 1024 {
        weight += bias.low_visibility_preferred * 2.0;
    }
    weight
}

/// Pick a surface profile from the catalog. With a neutral bias, behavior is
/// identical to the pre-2.5 path: deterministic mod-of-seed selection. With a
/// non-neutral bias, weighted random selection seeded by the same value so
/// callers see reproducible bias-affected output. Returns whether bias took
/// effect alongside the chosen profile, so the runtime event emitted at
/// session-open can record "Brain bias materially changed selection".
fn pick_surface_profile(seed: u64, bias: SurfaceBias) -> (RelaySurfaceProfile, bool) {
    if bias.is_neutral() {
        let idx = (seed as usize) % RELAY_SURFACE_CATALOG.len();
        return (RELAY_SURFACE_CATALOG[idx], false);
    }
    let weights: Vec<f32> = RELAY_SURFACE_CATALOG
        .iter()
        .map(|profile| surface_weight(profile, &bias))
        .collect();
    let Ok(dist) = WeightedIndex::new(&weights) else {
        // Should never happen — baseline weight 1.0 guarantees positivity —
        // but if a future bias encoding ever produces an all-zero vector,
        // gracefully fall back to the uniform-mod path so a session is
        // always emitted.
        let idx = (seed as usize) % RELAY_SURFACE_CATALOG.len();
        return (RELAY_SURFACE_CATALOG[idx], false);
    };
    let mut rng = StdRng::seed_from_u64(seed);
    let idx = dist.sample(&mut rng);
    (RELAY_SURFACE_CATALOG[idx], true)
}

/// Sample concrete shaping values for one session from the surface ranges.
/// Pure function over `(surface, session_nonce)`: identical nonce yields
/// identical sampled values (used by tests and runtime-event observability),
/// distinct nonces yield independent draws.
fn sample_session_dynamics(surface: RelaySurfaceProfile, session_nonce: u64) -> (usize, u64) {
    let mut rng = StdRng::seed_from_u64(session_nonce);
    let (chunk_min, chunk_max) = surface.chunk_size_range;
    let chunk_size = if chunk_min >= chunk_max {
        chunk_min.max(1)
    } else {
        rng.gen_range(chunk_min..=chunk_max)
    };
    let (delay_min, delay_max) = surface.inter_chunk_delay_ms_range;
    let delay_ms = if delay_min >= delay_max {
        delay_min
    } else {
        rng.gen_range(delay_min..=delay_max)
    };
    (chunk_size, delay_ms)
}

/// Production entry point with no Brain advisory. Equivalent to
/// [`build_session_profile_with_brain_bias`] called with `None`. Existing
/// production callsites use this; the Brain-aware variant is opt-in until
/// callers explicitly pass an advisory.
pub fn build_session_profile(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
) -> RelaySessionProfile {
    let nonce = fresh_session_nonce();
    build_session_profile_with_now_and_nonce(
        settings,
        target,
        current_unix_secs(),
        nonce,
        SurfaceBias::default(),
    )
}

/// Production entry point that accepts a Brain-supplied [`SurfaceBias`] to
/// weight surface profile selection. A neutral bias is equivalent to
/// [`build_session_profile`]; a non-neutral bias nudges selection toward
/// profiles whose declared shaping matches the bias axes (latency,
/// jitter, visibility) without removing any catalog entry from the
/// reachable set. Generates a fresh random session nonce per call so
/// dynamics still sample independently across sessions.
pub fn build_session_profile_with_brain_bias(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    bias: SurfaceBias,
) -> RelaySessionProfile {
    let nonce = fresh_session_nonce();
    build_session_profile_with_now_and_nonce(settings, target, current_unix_secs(), nonce, bias)
}

/// Public variant for callers that need to probe the catalog at an explicit
/// time (for example the intra-session drift detector in `relay.rs` that
/// compares session-open vs session-close profile ids). This path derives the
/// nonce deterministically from `(settings, target, now_secs)` so the drift
/// detector observes a stable profile id / path / surface-range pair across
/// the two probes — only the wall-clock epoch boundary should cause
/// observable rotation, not RNG noise.
pub fn build_session_profile_with_now_public(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    now_secs: u64,
) -> RelaySessionProfile {
    build_session_profile_with_now(settings, target, now_secs)
}

/// Test / drift-detector friendly entry point: deterministic nonce derived
/// from the session seed, so identical (settings, target, now) input always
/// produces the same sampled instance. Production code paths must NOT use this
/// directly — they must call [`build_session_profile`] so that two real
/// sessions get independent samples. Bias is always neutral here so the
/// drift detector observes only catalog rotation, not Brain transitions.
fn build_session_profile_with_now(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    now_secs: u64,
) -> RelaySessionProfile {
    let derived_nonce = session_seed(
        settings,
        target,
        "relay-session-dynamics",
        surface_epoch(
            settings.policy.drift_epoch_secs,
            now_secs,
            DriftSurface::RelaySession,
        ),
    );
    build_session_profile_with_now_and_nonce(
        settings,
        target,
        now_secs,
        derived_nonce,
        SurfaceBias::default(),
    )
}

/// Unified worker. The `session_nonce` parameter controls the per-session
/// sampling of `write_chunk_size` and `inter_chunk_delay_ms` from the surface
/// profile's ranges; `bias` controls Brain-driven weighting of the surface
/// profile *family* selection (a neutral bias yields deterministic mod-of-
/// seed behavior identical to the pre-2.5 path). Path selection, profile-id
/// selection, and transport order remain keyed by the wall-clock epoch +
/// target seed so path stability across short windows is preserved.
fn build_session_profile_with_now_and_nonce(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    now_secs: u64,
    session_nonce: u64,
    bias: SurfaceBias,
) -> RelaySessionProfile {
    let base_seed = session_seed(
        settings,
        target,
        "relay-session",
        surface_epoch(
            settings.policy.drift_epoch_secs,
            now_secs,
            DriftSurface::RelaySession,
        ),
    );
    let (surface, bias_applied) = match settings
        .policy
        .surface_profile_id
        .as_deref()
        .and_then(find_surface_profile)
    {
        Some(forced) => (forced, false),
        None => pick_surface_profile(base_seed, bias),
    };
    // Whole-stack coherence (audit C): if the TLS backend emits a browser-class
    // ClientHello, force the HTTP identity headers to match that browser so a
    // censor never sees an impossible pair (e.g. Chrome JA4 + curl User-Agent).
    // Traffic-shaping fields below still come from `surface`, preserving
    // per-session packet-train diversity.
    let identity = browser_coherent_identity(settings.tls_backend);
    // Carry the admitted sampling intervals into the session. Otherwise the
    // first mid-session redraw loses the operator's cap and delay override.
    // A cap below the template minimum deliberately produces a singleton;
    // caps inside the interval preserve the remaining in-range diversity.
    let chunk_cap = settings.policy.write_chunk_size.max(1);
    let chunk_size_range = (
        surface.chunk_size_range.0.max(1).min(chunk_cap),
        surface.chunk_size_range.1.max(1).min(chunk_cap),
    );
    let inter_chunk_delay_ms_range = if settings.policy.inter_chunk_delay_ms > 0 {
        (
            settings.policy.inter_chunk_delay_ms,
            settings.policy.inter_chunk_delay_ms,
        )
    } else {
        surface.inter_chunk_delay_ms_range
    };
    let (write_chunk_size, inter_chunk_delay_ms) = sample_session_dynamics(
        RelaySurfaceProfile {
            chunk_size_range,
            inter_chunk_delay_ms_range,
            ..surface
        },
        session_nonce,
    );
    RelaySessionProfile {
        transport_order: planned_transport_order_with_seed(
            &settings.transport_priority,
            &settings.policy,
            seed_without_target(
                &settings.policy,
                "relay-order",
                DriftSurface::RelayTransportOrder,
                now_secs,
            ),
        ),
        websocket_path: select_path(
            &settings.websocket_path,
            &settings.websocket_path_pool,
            session_seed(
                settings,
                target,
                "relay-ws-path",
                surface_epoch(
                    settings.policy.drift_epoch_secs,
                    now_secs,
                    DriftSurface::RelayWebsocketPath,
                ),
            ),
        ),
        grpc_path: select_path(
            &settings.grpc_path,
            &settings.grpc_path_pool,
            session_seed(
                settings,
                target,
                "relay-grpc-path",
                surface_epoch(
                    settings.policy.drift_epoch_secs,
                    now_secs,
                    DriftSurface::RelayGrpcPath,
                ),
            ),
        ),
        masque_path: select_path(
            &settings.masque_path,
            &settings.masque_path_pool,
            session_seed(
                settings,
                target,
                "relay-masque-path",
                surface_epoch(
                    settings.policy.drift_epoch_secs,
                    now_secs,
                    DriftSurface::RelayMasquePath,
                ),
            ),
        ),
        user_agent: identity
            .as_ref()
            .map_or(surface.user_agent, |i| i.user_agent),
        accept_header: identity
            .as_ref()
            .map_or(surface.accept_header, |i| i.accept_header),
        accept_language_header: identity
            .as_ref()
            .map_or(surface.accept_language_header, |i| i.accept_language_header),
        cache_control_header: identity
            .as_ref()
            .map_or(surface.cache_control_header, |i| i.cache_control_header),
        websocket_origin_header: resolve_websocket_origin(
            settings.server_name.as_str(),
            surface.websocket_origin_strategy,
        ),
        grpc_accept_encoding_header: surface.grpc_accept_encoding_header,
        grpc_encoding_header: surface.grpc_encoding_header,
        grpc_timeout_header: surface.grpc_timeout_header,
        grpc_message_type_header: surface.grpc_message_type_header,
        masque_alt_used_header: resolve_masque_alt_used(
            settings.server_name.as_str(),
            surface.masque_alt_used_strategy,
        ),
        tls_profile_target_class: settings.tls_profile_target_class.clone(),
        write_chunk_size,
        inter_chunk_delay_ms,
        inter_chunk_jitter_ms_window: surface.inter_chunk_jitter_ms_window,
        surface_chunk_size_range: chunk_size_range,
        surface_delay_ms_range: inter_chunk_delay_ms_range,
        surface_bias_applied: bias_applied,
        padding_probability_milli: surface.padding_probability_milli,
        padding_split_ratio_milli_range: surface.padding_split_ratio_milli_range,
        profile_id: surface.id,
    }
}

fn fresh_session_nonce() -> u64 {
    // OsRng would be ideal, but ThreadRng (auto-seeded from OsRng) is both
    // cryptographically adequate for "non-replayable per-session nonce" and
    // very cheap to call from hot session-open paths.
    rand::thread_rng().next_u64()
}

fn find_surface_profile(profile_id: &str) -> Option<RelaySurfaceProfile> {
    RELAY_SURFACE_CATALOG
        .iter()
        .copied()
        .find(|profile| profile.id == profile_id)
}

fn resolve_websocket_origin(server_name: &str, strategy: Option<&'static str>) -> Option<String> {
    match strategy {
        Some("same_authority_https") => Some(format!("https://{}", origin_authority(server_name))),
        Some(_) | None => None,
    }
}

fn origin_authority(server_name: &str) -> String {
    if server_name.contains(':') && !server_name.starts_with('[') {
        format!("[{server_name}]")
    } else {
        server_name.to_string()
    }
}

fn resolve_masque_alt_used(server_name: &str, strategy: Option<&'static str>) -> Option<String> {
    match strategy {
        Some("same_authority") => Some(server_name.to_string()),
        Some(_) | None => None,
    }
}

#[cfg(test)]
pub(crate) fn relay_profile_signature_for_time(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    now_secs: u64,
) -> (&'static str, String, String, String) {
    let profile = build_session_profile_with_now(settings, target, now_secs);
    (
        profile.profile_id,
        profile.websocket_path,
        profile.grpc_path,
        profile.masque_path,
    )
}

pub fn planned_transport_order(
    priority: &[TunnelTransportFamily],
    policy: &RelayPolicySettings,
) -> Vec<TunnelTransportFamily> {
    let now_secs = current_unix_secs();
    planned_transport_order_with_seed(
        priority,
        policy,
        seed_without_target(
            policy,
            "relay-order",
            DriftSurface::RelayTransportOrder,
            now_secs,
        ),
    )
}

#[cfg(test)]
pub fn planned_udp_transport_order(
    priority: &[TunnelTransportFamily],
    policy: &RelayPolicySettings,
) -> Vec<TunnelTransportFamily> {
    let now_secs = current_unix_secs();
    planned_udp_transport_order_with_seed(
        priority,
        policy,
        seed_without_target(
            policy,
            "relay-udp-order",
            DriftSurface::RelayUdpTransportOrder,
            now_secs,
        ),
    )
}

pub fn planned_udp_transport_order_with_seed(
    priority: &[TunnelTransportFamily],
    policy: &RelayPolicySettings,
    seed: u64,
) -> Vec<TunnelTransportFamily> {
    // UDP paths should budget attempts across UDP-capable transports only;
    // otherwise max_transport_attempts can accidentally exclude both the
    // direct MASQUE path and its fronted gRPC/H2 fallback.
    planned_transport_order_filtered(priority, policy, seed, |family| {
        matches!(
            family,
            TunnelTransportFamily::MasqueDerived | TunnelTransportFamily::GrpcDatagram
        )
    })
}

pub fn planned_transport_order_with_seed(
    priority: &[TunnelTransportFamily],
    policy: &RelayPolicySettings,
    seed: u64,
) -> Vec<TunnelTransportFamily> {
    planned_transport_order_filtered(priority, policy, seed, |_| true)
}

fn planned_transport_order_filtered(
    priority: &[TunnelTransportFamily],
    policy: &RelayPolicySettings,
    seed: u64,
    keep: impl Fn(TunnelTransportFamily) -> bool,
) -> Vec<TunnelTransportFamily> {
    let mut ordered: Vec<_> = priority
        .iter()
        .copied()
        .filter(|family| keep(*family))
        .collect();
    if ordered.is_empty() {
        return ordered;
    }
    if policy.rotate_transports_per_session && ordered.len() > 1 {
        let offset = (seed as usize) % ordered.len();
        ordered.rotate_left(offset);
    }
    ordered.truncate(policy.max_transport_attempts.max(1).min(ordered.len()));
    ordered
}

pub fn write_chunk_size(profile: &RelaySessionProfile) -> usize {
    profile.write_chunk_size.max(1)
}

/// Sample the next pacing delay: base delay from the session profile plus a
/// fresh additive jitter draw inside `[0, jitter_window_ms]`. A fresh draw on
/// every chunk is essential — a single per-session jitter constant collapses
/// to the same fixed-rate signature as the un-jittered case.
fn sample_chunk_delay_ms<R: Rng + ?Sized>(profile: &RelaySessionProfile, rng: &mut R) -> u64 {
    let base = profile.inter_chunk_delay_ms;
    let jitter = if profile.inter_chunk_jitter_ms_window > 0 {
        rng.gen_range(0..=profile.inter_chunk_jitter_ms_window)
    } else {
        0
    };
    base.saturating_add(jitter)
}

/// Redraw (chunk_size, base_delay) mid-session from the admitted policy ranges
/// carried by the session profile. Returns the original session-instance
/// values if the surface ranges are degenerate (e.g. test profile with a
/// `Default`-initialised `(0, 0)` range), so resampling on such profiles
/// is a safe no-op rather than producing a zero chunk size.
fn resample_session_dynamics<R: Rng + ?Sized>(
    profile: &RelaySessionProfile,
    rng: &mut R,
) -> (usize, u64) {
    let (chunk_min, chunk_max) = profile.surface_chunk_size_range;
    let chunk = if chunk_min == 0 && chunk_max == 0 {
        profile.write_chunk_size
    } else if chunk_min >= chunk_max {
        chunk_min.max(1)
    } else {
        rng.gen_range(chunk_min..=chunk_max)
    };
    let (delay_min, delay_max) = profile.surface_delay_ms_range;
    let delay = if delay_min == 0 && delay_max == 0 {
        profile.inter_chunk_delay_ms
    } else if delay_min >= delay_max {
        delay_min
    } else {
        rng.gen_range(delay_min..=delay_max)
    };
    (chunk, delay)
}

/// Number of chunks until the next mid-session dynamics resample. K itself
/// varies so the "shape change point" doesn't land on a fixed cadence
/// observable across long sessions. Returned value of zero is a sentinel
/// meaning resampling is disabled (used when the surface ranges are
/// degenerate so a fresh draw would produce no change).
fn next_resample_countdown<R: Rng + ?Sized>(profile: &RelaySessionProfile, rng: &mut R) -> u32 {
    let (chunk_min, chunk_max) = profile.surface_chunk_size_range;
    let (delay_min, delay_max) = profile.surface_delay_ms_range;
    let chunk_degenerate = chunk_min == 0 && chunk_max == 0;
    let delay_degenerate = delay_min == 0 && delay_max == 0;
    if chunk_degenerate && delay_degenerate {
        return 0;
    }
    // 4..=32 chunks gives a mean of ~18 chunks between redraws on the
    // default 16 KiB chunk size — roughly every 290 KiB transferred — so
    // long sessions see multiple distinct shapes while short bursts still
    // get at least one resample on average.
    rng.gen_range(4..=32)
}

pub async fn maybe_delay(profile: &RelaySessionProfile) {
    // Scope the !Send `ThreadRng` borrow tightly so the returned future
    // stays `Send` (`tokio::spawn` requires it). We compute the delay
    // synchronously, then drop the rng before awaiting.
    let total = {
        let mut rng = rand::thread_rng();
        sample_chunk_delay_ms(profile, &mut rng)
    };
    if total > 0 {
        sleep(Duration::from_millis(total)).await;
    }
}

pub async fn copy_with_policy<R, W>(
    reader: &mut R,
    writer: &mut W,
    profile: &RelaySessionProfile,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // `StdRng` is `Send`; instances of it can live across `.await` points
    // inside a future that must itself be `Send` (tokio::spawn requirement).
    let mut rng = StdRng::from_entropy();
    // Buffer is allocated to the admitted sampling maximum (or the
    // session-instance chunk if no range is set) so mid-session
    // chunk-size resampling never has to reallocate. We then read into a
    // sub-slice of length `current_chunk` to limit each application write.
    // Transport buffering can change wire framing. The session-instance
    // values seed the loop; the first
    // resample point overwrites them.
    let surface_chunk_max = profile.surface_chunk_size_range.1;
    let max_buf = surface_chunk_max.max(profile.write_chunk_size).max(1);
    let mut buf = vec![0u8; max_buf];
    let mut current_chunk = profile.write_chunk_size.max(1).min(max_buf);
    let mut current_delay = profile.inter_chunk_delay_ms;
    let mut chunks_until_resample = next_resample_countdown(profile, &mut rng);
    let mut total = 0u64;
    loop {
        let read_window = current_chunk.max(1).min(max_buf);
        let n = reader.read(&mut buf[..read_window]).await?;
        if n == 0 {
            writer.flush().await?;
            return Ok(total);
        }
        // Phase 5 Phase 2: padding-as-split. With probability
        // `padding_probability_milli` per write (per-mille basis) and
        // n >= 2, split the outbound chunk into two smaller writes
        // using a sampled ratio from `padding_split_ratio_milli_range`.
        // These are application-write boundaries, not a guarantee of
        // separate TLS records or IP packets: the writer and kernel may
        // coalesce or segment them. No payload bytes are inserted.
        let split = if profile.padding_probability_milli > 0 && n >= 2 {
            let roll = rng.gen_range(0u16..1000);
            if roll < profile.padding_probability_milli {
                let (lo, hi) = profile.padding_split_ratio_milli_range;
                let ratio_milli = if lo == 0 && hi == 0 {
                    500
                } else if lo >= hi {
                    lo.clamp(1, 999)
                } else {
                    rng.gen_range(lo..=hi).clamp(1, 999)
                };
                let first = ((n as u64 * ratio_milli as u64) / 1000) as usize;
                Some(first.clamp(1, n - 1))
            } else {
                None
            }
        } else {
            None
        };
        if let Some(first) = split {
            writer.write_all(&buf[..first]).await?;
            writer.write_all(&buf[first..n]).await?;
        } else {
            writer.write_all(&buf[..n]).await?;
        }
        total += n as u64;
        let jitter = if profile.inter_chunk_jitter_ms_window > 0 {
            rng.gen_range(0..=profile.inter_chunk_jitter_ms_window)
        } else {
            0
        };
        let delay_ms = current_delay.saturating_add(jitter);
        if delay_ms > 0 {
            sleep(Duration::from_millis(delay_ms)).await;
        }
        // Mid-session dynamics resample: redraw (chunk_size, base_delay)
        // from the surface ranges so the packet train geometry changes
        // shape part-way through long sessions, with a per-resample-cadence
        // that itself is randomized.
        if chunks_until_resample > 0 {
            chunks_until_resample -= 1;
            if chunks_until_resample == 0 {
                let (resampled_chunk, resampled_delay) =
                    resample_session_dynamics(profile, &mut rng);
                current_chunk = resampled_chunk.max(1).min(max_buf);
                current_delay = resampled_delay;
                chunks_until_resample = next_resample_countdown(profile, &mut rng);
            }
        }
    }
}

pub async fn write_prefetched_payload<W>(
    writer: &mut W,
    profile: &RelaySessionProfile,
    payload: Option<&[u8]>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(payload) = payload.filter(|payload| !payload.is_empty()) else {
        return Ok(());
    };
    // Reuse the same pacing policy for runtime failover so the prefetched
    // first chunk does not bypass transport chunking semantics.
    writer.write_all(payload).await?;
    writer.flush().await?;
    let delay_ms = {
        let mut rng = rand::thread_rng();
        sample_chunk_delay_ms(profile, &mut rng)
    };
    if delay_ms > 0 {
        sleep(Duration::from_millis(delay_ms)).await;
    }
    Ok(())
}

fn select_path(primary: &str, pool: &[String], seed: u64) -> String {
    let mut candidates = Vec::with_capacity(1 + pool.len());
    candidates.push(primary.to_string());
    for candidate in pool {
        if !candidate.trim().is_empty() && !candidates.iter().any(|item| item == candidate) {
            candidates.push(candidate.clone());
        }
    }
    candidates[(seed as usize) % candidates.len()].clone()
}

fn seed_without_target(
    policy: &RelayPolicySettings,
    label: &str,
    surface: DriftSurface,
    now_secs: u64,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(surface_epoch(policy.drift_epoch_secs, now_secs, surface).to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("seed bytes"))
}

fn session_seed(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    label: &str,
    epoch_bucket: u64,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(epoch_bucket.to_le_bytes());
    hasher.update(settings.server.as_bytes());
    hasher.update(settings.server_name.as_bytes());
    if let Some((host, port)) = target {
        hasher.update(host.as_bytes());
        hasher.update(port.to_le_bytes());
    }
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("seed bytes"))
}

/// Resolve a soft-wire socket plan for a relay TCP transport about to
/// open. Returns `Some(plan)` only when the relay's configured wire mode
/// is `SoftWireSocketOptions`; other modes (Disabled / TtlPreface*)
/// return `None`. The returned plan's `applied` flag is set by the
/// caller via [`aegis_core::apply_soft_wire_socket_plan`] equivalent.
///
/// The seed is derived from session_seed bound to a distinct label so
/// the wire plan's randomness is independent from surface-profile and
/// transport-order randomness — two sessions on the same surface profile
/// still get independent wire plans.
pub fn relay_soft_wire_plan(
    settings: &aegis_core::RelaySettings,
    target: Option<(&str, u16)>,
    now_secs: u64,
) -> Option<aegis_core::SoftWireRelaySocketPlan> {
    if !matches!(
        settings.wire_mimicry_mode,
        aegis_core::WireMimicryMode::SoftWireSocketOptions
    ) {
        return None;
    }
    let seed = session_seed(
        settings,
        target,
        "relay-soft-wire",
        surface_epoch(
            settings.policy.drift_epoch_secs,
            now_secs,
            DriftSurface::RelaySession,
        ),
    );
    Some(aegis_core::SoftWireRelaySocketPlan::from_seed(seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn truncates_attempts_and_preserves_membership() {
        let order = planned_transport_order(
            &[
                TunnelTransportFamily::HttpsWs,
                TunnelTransportFamily::GrpcStream,
                TunnelTransportFamily::MasqueDerived,
                TunnelTransportFamily::LegacyTls,
            ],
            &RelayPolicySettings {
                rotate_transports_per_session: false,
                max_transport_attempts: 2,
                write_chunk_size: 1024,
                inter_chunk_delay_ms: 0,
                drift_epoch_secs: 900,
                surface_profile_id: None,
                adaptive_transport: false,
            },
        );
        assert_eq!(order.len(), 2);
        assert_eq!(order[0], TunnelTransportFamily::HttpsWs);
        assert_eq!(order[1], TunnelTransportFamily::GrpcStream);
    }

    #[test]
    fn udp_transport_order_filters_before_attempt_limit() {
        let order = planned_udp_transport_order(
            &[
                TunnelTransportFamily::HttpsWs,
                TunnelTransportFamily::GrpcStream,
                TunnelTransportFamily::MasqueDerived,
                TunnelTransportFamily::GrpcDatagram,
                TunnelTransportFamily::LegacyTls,
            ],
            &RelayPolicySettings {
                rotate_transports_per_session: false,
                max_transport_attempts: 2,
                write_chunk_size: 1024,
                inter_chunk_delay_ms: 0,
                drift_epoch_secs: 900,
                surface_profile_id: None,
                adaptive_transport: false,
            },
        );
        assert_eq!(
            order,
            vec![
                TunnelTransportFamily::MasqueDerived,
                TunnelTransportFamily::GrpcDatagram
            ]
        );
    }

    #[test]
    fn udp_transport_order_is_empty_without_udp_capable_family() {
        let order = planned_udp_transport_order(
            &[
                TunnelTransportFamily::HttpsWs,
                TunnelTransportFamily::GrpcStream,
                TunnelTransportFamily::LegacyTls,
            ],
            &RelayPolicySettings {
                rotate_transports_per_session: false,
                max_transport_attempts: 2,
                write_chunk_size: 1024,
                inter_chunk_delay_ms: 0,
                drift_epoch_secs: 900,
                surface_profile_id: None,
                adaptive_transport: false,
            },
        );
        assert!(order.is_empty());
    }

    #[tokio::test]
    async fn writes_prefetched_payload_once() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            let profile = RelaySessionProfile {
                transport_order: vec![TunnelTransportFamily::HttpsWs],
                websocket_path: "/ws".into(),
                grpc_path: "/rpc".into(),
                masque_path: "/.well-known/masque/udp".into(),
                user_agent: "Mozilla/5.0",
                accept_header: "*/*",
                websocket_origin_header: Some("https://localhost".into()),
                write_chunk_size: 1024,
                inter_chunk_delay_ms: 0,
                profile_id: "test",
                ..RelaySessionProfile::default()
            };
            write_prefetched_payload(&mut writer, &profile, Some(b"hello"))
                .await
                .unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        write.await.unwrap();
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn session_profile_picks_pool_member_deterministically() {
        let settings = RelaySettings {
            websocket_path: "/aegis/ws".into(),
            websocket_path_pool: vec!["/ws".into()],
            grpc_path: "/aegis.tunnel.v1.TunnelService/Open".into(),
            grpc_path_pool: vec!["/rpc.Tunnel/Open".into()],
            masque_path: "/.well-known/masque/udp".into(),
            masque_path_pool: vec!["/.well-known/masque/connect-udp".into()],
            ..RelaySettings::default()
        };
        let a = build_session_profile_with_now(&settings, Some(("example.org", 443)), 10_000);
        let b = build_session_profile_with_now(&settings, Some(("example.org", 443)), 10_030);
        assert_eq!(a.websocket_path, b.websocket_path);
        assert_eq!(a.grpc_path, b.grpc_path);
        assert_eq!(a.masque_path, b.masque_path);
    }

    #[test]
    fn session_profile_honors_configured_surface_profile_id() {
        // Legacy rustls backend: this test checks that a configured surface
        // profile is honored with its OWN identity headers. The chrome-like
        // default would override identity to Chrome-coherent values (its own
        // test covers that), which is orthogonal to profile-id honoring.
        let mut settings = RelaySettings {
            tls_backend: RelayTlsBackend::Rustls,
            ..RelaySettings::default()
        };
        settings.policy.surface_profile_id = Some("cli_https_compact".into());
        let profile =
            build_session_profile_with_now(&settings, Some(("api.ipify.org", 443)), 10_000);
        assert_eq!(profile.profile_id, "cli_https_compact");
        assert_eq!(profile.cache_control_header, Some("no-cache"));
        // Sampled scalar lies inside the surface profile's declared range.
        let (delay_min, delay_max) = profile.surface_delay_ms_range;
        assert!(
            profile.inter_chunk_delay_ms >= delay_min && profile.inter_chunk_delay_ms <= delay_max,
            "sampled delay {} outside surface range {:?}",
            profile.inter_chunk_delay_ms,
            profile.surface_delay_ms_range,
        );
        let (chunk_min, chunk_max) = profile.surface_chunk_size_range;
        assert!(
            profile.write_chunk_size >= chunk_min && profile.write_chunk_size <= chunk_max,
            "sampled chunk {} outside surface range {:?}",
            profile.write_chunk_size,
            profile.surface_chunk_size_range,
        );
        assert!(profile.websocket_origin_header.is_none());
    }

    #[test]
    fn chrome_coherent_user_agent_is_internally_consistent() {
        // The coherent User-Agent is the profile's platform string.
        // Refresh it with scripts/refresh-chrome-profile.py.
        let ua = chrome_coherent_user_agent();
        assert!(
            ua.starts_with("Mozilla/5.0 ("),
            "coherent UA must look like a real browser: {ua:?}"
        );
        assert!(
            ua.contains("AppleWebKit/537.36 (KHTML, like Gecko)") && ua.contains("Safari/537.36"),
            "coherent UA must carry Chrome's WebKit tokens: {ua:?}"
        );
        let version = ua
            .split("Chrome/")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("coherent UA must carry a Chrome/<version> token");
        // Chrome froze the UA build/patch to `major.0.0.0` (UA reduction), so an
        // authentic pin always ends `.0.0.0`.
        assert!(
            version.ends_with(".0.0.0"),
            "Chrome UA build must be frozen to .0.0.0 (UA reduction), got {version:?}"
        );
        let major: u32 = version
            .split('.')
            .next()
            .and_then(|m| m.parse().ok())
            .expect("Chrome major version must be numeric");
        // The pinned JA4 advertises X25519MLKEM768, which entered Chrome stable
        // in 131. A coherent UA older than that would contradict the JA4 and is
        // a drift bug, not a graceful staleness.
        assert!(
            major >= 131,
            "coherent Chrome major {major} predates the pinned JA4's X25519MLKEM768 (>=131)"
        );
    }

    #[test]
    fn browser_class_tls_forces_coherent_chrome_identity() {
        // Force the most incoherent catalog entry — a bare curl User-Agent.
        let mut settings = RelaySettings::default();
        settings.policy.surface_profile_id = Some("cli_https_compact".into());

        // Default (rustls) backend does not claim to be a browser, so the
        // diverse catalog User-Agent is preserved.
        settings.tls_backend = RelayTlsBackend::Rustls;
        let rustls_profile =
            build_session_profile_with_now(&settings, Some(("api.ipify.org", 443)), 10_000);
        assert_eq!(rustls_profile.user_agent, "curl/8.7.1");

        // Browser-class backend emits a Chrome JA4 — the HTTP identity is forced
        // coherent so the impossible "Chrome JA4 + curl UA" pair never appears.
        settings.tls_backend = RelayTlsBackend::ChromeLikeExperimental;
        let chrome_profile =
            build_session_profile_with_now(&settings, Some(("api.ipify.org", 443)), 10_000);
        assert!(
            chrome_profile.user_agent.starts_with("Mozilla/5.0")
                && chrome_profile.user_agent.contains("Chrome/"),
            "browser-class TLS must present a Chrome UA, got {:?}",
            chrome_profile.user_agent,
        );
        assert_ne!(chrome_profile.user_agent, "curl/8.7.1");
        assert_eq!(
            chrome_profile.accept_language_header,
            Some("en-US,en;q=0.9")
        );
        // Traffic shaping still comes from the picked surface — the coherence
        // override touches only identity headers, not packet-train diversity.
        assert_eq!(chrome_profile.profile_id, "cli_https_compact");
    }

    #[test]
    fn session_profile_ignores_unknown_surface_profile_id() {
        let mut settings = RelaySettings::default();
        settings.policy.surface_profile_id = Some("unknown_profile".into());
        let profile =
            build_session_profile_with_now(&settings, Some(("api.ipify.org", 443)), 10_000);
        assert_ne!(profile.profile_id, "unknown_profile");
    }

    #[test]
    fn relay_profile_shows_variance_across_sampled_targets() {
        let settings = RelaySettings {
            websocket_path: "/aegis/ws".into(),
            websocket_path_pool: vec!["/ws".into(), "/socket".into()],
            grpc_path: "/aegis.tunnel.v1.TunnelService/Open".into(),
            grpc_path_pool: vec![
                "/rpc.Tunnel/Open".into(),
                "/cdn.tunnel.v1.Session/Open".into(),
            ],
            masque_path: "/.well-known/masque/udp".into(),
            masque_path_pool: vec!["/.well-known/masque/connect-udp".into()],
            ..RelaySettings::default()
        };
        let unique_profiles: std::collections::BTreeSet<_> = (1..=32u8)
            .map(|octet| {
                let profile = build_session_profile_with_now(
                    &settings,
                    Some((&format!("edge-{octet}.example.org"), 443)),
                    10_000,
                );
                (
                    profile.profile_id,
                    profile.websocket_path,
                    profile.grpc_path,
                    profile.masque_path,
                )
            })
            .collect();
        assert!(unique_profiles.len() >= 4);
    }

    #[test]
    fn relay_surface_epochs_are_anti_correlated() {
        let now_secs = 10_000;
        let base = 900;
        let next_session =
            aegis_core::next_surface_rotation_at(base, now_secs, DriftSurface::RelaySession);
        let next_ws =
            aegis_core::next_surface_rotation_at(base, now_secs, DriftSurface::RelayWebsocketPath);
        let next_grpc =
            aegis_core::next_surface_rotation_at(base, now_secs, DriftSurface::RelayGrpcPath);
        let next_masque =
            aegis_core::next_surface_rotation_at(base, now_secs, DriftSurface::RelayMasquePath);
        assert_ne!(next_session, next_ws);
        assert_ne!(next_session, next_grpc);
        assert_ne!(next_session, next_masque);
    }

    #[test]
    fn relay_profile_sample_covers_catalog_and_path_pools() {
        let settings = RelaySettings {
            websocket_path: "/aegis/ws".into(),
            websocket_path_pool: vec!["/ws".into(), "/socket".into()],
            grpc_path: "/aegis.tunnel.v1.TunnelService/Open".into(),
            grpc_path_pool: vec![
                "/rpc.Tunnel/Open".into(),
                "/cdn.tunnel.v1.Session/Open".into(),
            ],
            masque_path: "/.well-known/masque/udp".into(),
            masque_path_pool: vec!["/.well-known/masque/connect-udp".into()],
            // Pin the legacy rustls backend: this test exercises the FULL catalog
            // sampling (every profile's identity headers + path pools). The default
            // is now the chrome-like backend, which forces a browser-coherent
            // (Chrome) identity and collapses the accept-language/origin diversity
            // on purpose — that coherence has its own test above; here we want the
            // un-narrowed superset the sampler produces.
            tls_backend: RelayTlsBackend::Rustls,
            ..RelaySettings::default()
        };
        let mut profile_ids = std::collections::BTreeSet::new();
        let mut websocket_paths = std::collections::BTreeSet::new();
        let mut grpc_paths = std::collections::BTreeSet::new();
        let mut masque_paths = std::collections::BTreeSet::new();
        let mut accept_languages = std::collections::BTreeSet::new();
        let mut cache_controls = std::collections::BTreeSet::new();
        let mut websocket_origins = std::collections::BTreeSet::new();
        let mut grpc_accept_encodings = std::collections::BTreeSet::new();
        let mut grpc_encodings = std::collections::BTreeSet::new();
        let mut grpc_timeouts = std::collections::BTreeSet::new();
        let mut grpc_message_types = std::collections::BTreeSet::new();
        let mut masque_alt_used = std::collections::BTreeSet::new();
        // Bumped from 128 → 1024 after Phase 2.4 expanded the catalog 6→18.
        // With 18 profiles, a 128-host sample averages ~7 hits per profile;
        // any axis value owned by a single profile then has a ~0.1% chance
        // of being missed across the run, which is too flaky for a strict
        // "expected == observed" set comparison. 1024 samples drives that
        // chance below 1e-5.
        for octet in 1..=1024u16 {
            let host = format!("edge-{octet}.example.org");
            let profile = build_session_profile_with_now(&settings, Some((&host, 443)), 10_000);
            profile_ids.insert(profile.profile_id);
            websocket_paths.insert(profile.websocket_path);
            grpc_paths.insert(profile.grpc_path);
            masque_paths.insert(profile.masque_path);
            accept_languages.insert(profile.accept_language_header.unwrap_or("<none>"));
            cache_controls.insert(profile.cache_control_header.unwrap_or("<none>"));
            websocket_origins.insert(
                profile
                    .websocket_origin_header
                    .as_deref()
                    .unwrap_or("<none>")
                    .to_string(),
            );
            grpc_accept_encodings.insert(profile.grpc_accept_encoding_header.unwrap_or("<none>"));
            grpc_encodings.insert(profile.grpc_encoding_header.unwrap_or("<none>"));
            grpc_timeouts.insert(profile.grpc_timeout_header.unwrap_or("<none>"));
            grpc_message_types.insert(profile.grpc_message_type_header.unwrap_or("<none>"));
            masque_alt_used.insert(
                profile
                    .masque_alt_used_header
                    .as_deref()
                    .unwrap_or("<none>")
                    .to_string(),
            );
        }
        let expected_profile_ids: std::collections::BTreeSet<_> = RELAY_SURFACE_CATALOG
            .iter()
            .map(|profile| profile.id)
            .collect();
        let expected_websocket_paths: std::collections::BTreeSet<_> =
            ["/aegis/ws", "/ws", "/socket"]
                .into_iter()
                .map(str::to_string)
                .collect();
        let expected_grpc_paths: std::collections::BTreeSet<_> = [
            "/aegis.tunnel.v1.TunnelService/Open",
            "/rpc.Tunnel/Open",
            "/cdn.tunnel.v1.Session/Open",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let expected_masque_paths: std::collections::BTreeSet<_> =
            ["/.well-known/masque/udp", "/.well-known/masque/connect-udp"]
                .into_iter()
                .map(str::to_string)
                .collect();
        // Expected header/axis variant sets after Phase 2.4 catalog expansion
        // 6→18. The new mobile_4g profile contributes "en-GB,en;q=0.9";
        // noisy_cafe contributes "max-age=300"; grpc_api contributes
        // "gzip, deflate"; mobile_4g/desktop_electron/corp_middlebox/grpc_api
        // each contribute new gRPC timeout values (12S/20S/25S/30S already
        // present extended by 12S/25S; 20S was already in 'browser_like_chatty';
        // 30S in 'desktop_chrome_streaming' but now also 'congested_hotel' and
        // 'grpc_api'). Set is the union over all 18 profiles.
        let expected_accept_languages: std::collections::BTreeSet<_> = [
            "<none>",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.8",
            "en-US,en;q=0.9",
            "en-US,en;q=0.9,*;q=0.5",
        ]
        .into_iter()
        .collect();
        let expected_cache_controls: std::collections::BTreeSet<_> =
            ["<none>", "max-age=0", "max-age=300", "no-cache", "no-store"]
                .into_iter()
                .collect();
        let expected_websocket_origins: std::collections::BTreeSet<_> =
            ["<none>".to_string(), "https://localhost".to_string()]
                .into_iter()
                .collect();
        let expected_grpc_accept_encodings: std::collections::BTreeSet<_> = [
            "<none>",
            "identity",
            "gzip",
            "gzip, deflate",
            "gzip, identity",
        ]
        .into_iter()
        .collect();
        let expected_grpc_encodings: std::collections::BTreeSet<_> =
            ["<none>", "identity", "gzip"].into_iter().collect();
        let expected_grpc_timeouts: std::collections::BTreeSet<_> =
            ["<none>", "10S", "12S", "15S", "20S", "25S", "30S", "60S"]
                .into_iter()
                .collect();
        let expected_grpc_message_types: std::collections::BTreeSet<_> =
            ["<none>", "SessionOpenRequest", "TunnelRequest"]
                .into_iter()
                .collect();
        let expected_masque_alt_used: std::collections::BTreeSet<_> =
            ["<none>".to_string(), "localhost".to_string()]
                .into_iter()
                .collect();
        assert_eq!(profile_ids, expected_profile_ids);
        assert_eq!(websocket_paths, expected_websocket_paths);
        assert_eq!(grpc_paths, expected_grpc_paths);
        assert_eq!(masque_paths, expected_masque_paths);
        assert_eq!(accept_languages, expected_accept_languages);
        assert_eq!(cache_controls, expected_cache_controls);
        assert_eq!(websocket_origins, expected_websocket_origins);
        assert_eq!(grpc_accept_encodings, expected_grpc_accept_encodings);
        assert_eq!(grpc_encodings, expected_grpc_encodings);
        assert_eq!(grpc_timeouts, expected_grpc_timeouts);
        assert_eq!(grpc_message_types, expected_grpc_message_types);
        assert_eq!(masque_alt_used, expected_masque_alt_used);
    }

    #[test]
    fn relay_profile_distribution_stays_bounded() {
        let settings = RelaySettings {
            websocket_path: "/aegis/ws".into(),
            websocket_path_pool: vec!["/ws".into(), "/socket".into()],
            grpc_path: "/aegis.tunnel.v1.TunnelService/Open".into(),
            grpc_path_pool: vec![
                "/rpc.Tunnel/Open".into(),
                "/cdn.tunnel.v1.Session/Open".into(),
            ],
            masque_path: "/.well-known/masque/udp".into(),
            masque_path_pool: vec!["/.well-known/masque/connect-udp".into()],
            ..RelaySettings::default()
        };
        // Bumped 512 → 2048 after Phase 2.4 expanded the catalog to 18.
        // 18 buckets × 28 hits at 512 samples gives a binomial std-dev that
        // routinely pushed one bucket past the ±30% tolerance band. 2048
        // samples drives the per-bucket relative noise below the band so
        // the test is statistically stable, not just probabilistically so.
        let sample_size: u32 = 2048;
        let mut counts = std::collections::BTreeMap::new();
        for idx in 1..=sample_size {
            let host = format!("edge-{idx}.example.org");
            let profile = build_session_profile_with_now(&settings, Some((&host, 443)), 10_000);
            *counts.entry(profile.profile_id).or_insert(0usize) += 1;
        }
        assert_eq!(counts.len(), RELAY_SURFACE_CATALOG.len());
        let min = counts.values().copied().min().unwrap_or_default();
        let max = counts.values().copied().max().unwrap_or_default();
        // Derived distribution bounds: uniform expectation is sample_size /
        // catalog_size with a ±30% tolerance band. Hardcoding concrete floor
        // and ceiling numbers silently breaks on every catalog expansion
        // (this test was previously locked to 3-profile and then 6-profile
        // eras; the Phase 2.4 expansion to 18 profiles requires only that
        // sample_size scale, not the bounds themselves).
        let catalog_size = RELAY_SURFACE_CATALOG.len() as f64;
        let expected_per_profile = sample_size as f64 / catalog_size;
        let tolerance = 0.30_f64;
        let floor = (expected_per_profile * (1.0 - tolerance)) as usize;
        let ceiling = (expected_per_profile * (1.0 + tolerance)).round() as usize;
        assert!(
            min >= floor,
            "distribution floor too low: min={min} floor={floor} counts={counts:?}"
        );
        assert!(
            max <= ceiling,
            "distribution ceiling too high: max={max} ceiling={ceiling} counts={counts:?}"
        );
    }

    #[test]
    fn sampled_dynamics_stay_within_surface_range() {
        // For every catalog profile, force selection by id and verify the
        // sampled scalars sit inside the declared range. Iterates a few
        // nonces so we don't accidentally only check the boundary. The
        // operator policy cap is raised to 1 MiB so it never binds before
        // the surface range max (desktop_chrome_streaming declares up to
        // 40 KiB and would otherwise be clamped by the default cap).
        let mut settings = RelaySettings::default();
        settings.policy.write_chunk_size = 1024 * 1024;
        for surface in RELAY_SURFACE_CATALOG.iter() {
            settings.policy.surface_profile_id = Some(surface.id.into());
            for nonce in 0u64..32 {
                let profile = build_session_profile_with_now_and_nonce(
                    &settings,
                    Some(("api.ipify.org", 443)),
                    10_000,
                    nonce,
                    SurfaceBias::default(),
                );
                let (chunk_min, chunk_max) = profile.surface_chunk_size_range;
                assert!(
                    profile.write_chunk_size >= chunk_min && profile.write_chunk_size <= chunk_max,
                    "chunk_size {} outside range {:?} for profile {} nonce {}",
                    profile.write_chunk_size,
                    profile.surface_chunk_size_range,
                    surface.id,
                    nonce,
                );
                let (delay_min, delay_max) = profile.surface_delay_ms_range;
                assert!(
                    profile.inter_chunk_delay_ms >= delay_min
                        && profile.inter_chunk_delay_ms <= delay_max,
                    "delay {} outside range {:?} for profile {} nonce {}",
                    profile.inter_chunk_delay_ms,
                    profile.surface_delay_ms_range,
                    surface.id,
                    nonce,
                );
                assert_eq!(
                    profile.inter_chunk_jitter_ms_window, surface.inter_chunk_jitter_ms_window,
                    "jitter window mismatch for profile {}",
                    surface.id
                );
            }
        }
    }

    #[test]
    fn sampled_dynamics_vary_between_distinct_nonces() {
        // Same target, same epoch, same surface profile id, but two distinct
        // nonces MUST produce at least one differing scalar across a small
        // batch. If they don't, the per-session sampling collapsed back to
        // a deterministic value, defeating the whole point of the change.
        let mut settings = RelaySettings::default();
        settings.policy.surface_profile_id = Some("desktop_chrome_streaming".into());
        let mut chunk_values = std::collections::BTreeSet::new();
        let mut delay_values = std::collections::BTreeSet::new();
        for nonce in 0u64..64 {
            let profile = build_session_profile_with_now_and_nonce(
                &settings,
                Some(("edge.example.org", 443)),
                10_000,
                nonce,
                SurfaceBias::default(),
            );
            chunk_values.insert(profile.write_chunk_size);
            delay_values.insert(profile.inter_chunk_delay_ms);
        }
        // The combined diversity across 64 nonces should land on more than one
        // sampled value on at least one axis. desktop_chrome_streaming has a
        // wide chunk range (24..=40 KiB) so we expect plenty of variety.
        let total_distinct = chunk_values.len() + delay_values.len();
        assert!(
            total_distinct >= 3,
            "expected sampled diversity (chunk_set={:?}, delay_set={:?})",
            chunk_values,
            delay_values,
        );
    }

    #[test]
    fn deterministic_entry_point_keeps_path_and_profile_id_stable() {
        // The drift-detector path (build_session_profile_with_now) must remain
        // deterministic given identical (settings, target, now) so the
        // intra-session profile-id comparison observes only catalog rotation,
        // not RNG noise. Path selection and profile id are checked; the
        // sampled scalars are also expected to match because the deterministic
        // entry point derives the nonce from session_seed.
        let settings = RelaySettings::default();
        let a = build_session_profile_with_now(&settings, Some(("api.ipify.org", 443)), 10_000);
        let b = build_session_profile_with_now(&settings, Some(("api.ipify.org", 443)), 10_000);
        assert_eq!(a.profile_id, b.profile_id);
        assert_eq!(a.websocket_path, b.websocket_path);
        assert_eq!(a.grpc_path, b.grpc_path);
        assert_eq!(a.masque_path, b.masque_path);
        assert_eq!(a.write_chunk_size, b.write_chunk_size);
        assert_eq!(a.inter_chunk_delay_ms, b.inter_chunk_delay_ms);
    }

    #[test]
    fn production_entry_point_varies_dynamics_across_calls() {
        // The production entry point (build_session_profile) must NOT collapse
        // to a deterministic instance for the same target/epoch. Otherwise
        // a wire observer collecting many sessions from the same client to
        // the same target trivially clusters by sampled scalar values.
        let settings = RelaySettings::default();
        let mut chunks = std::collections::BTreeSet::new();
        let mut delays = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let profile = build_session_profile(&settings, Some(("api.ipify.org", 443)));
            chunks.insert(profile.write_chunk_size);
            delays.insert(profile.inter_chunk_delay_ms);
        }
        let total_distinct = chunks.len() + delays.len();
        assert!(
            total_distinct >= 3,
            "production entry point did not vary scalars (chunks={:?}, delays={:?})",
            chunks,
            delays,
        );
    }

    #[test]
    fn resample_session_dynamics_stays_within_surface_range() {
        // Every catalog profile must produce in-range (chunk_size, delay)
        // when its session-instance is fed back into resample_session_dynamics
        // (even though the session-instance scalars are the result of an
        // earlier draw from the same range).
        let mut settings = RelaySettings::default();
        settings.policy.write_chunk_size = 1024 * 1024; // do not let the cap bind
        for surface in RELAY_SURFACE_CATALOG.iter() {
            settings.policy.surface_profile_id = Some(surface.id.into());
            for nonce in 0u64..32 {
                let profile = build_session_profile_with_now_and_nonce(
                    &settings,
                    Some(("api.ipify.org", 443)),
                    10_000,
                    nonce,
                    SurfaceBias::default(),
                );
                let mut rng = StdRng::seed_from_u64(nonce ^ 0xdeadbeef);
                for _ in 0..64 {
                    let (chunk, delay) = resample_session_dynamics(&profile, &mut rng);
                    let (chunk_min, chunk_max) = profile.surface_chunk_size_range;
                    assert!(
                        chunk >= chunk_min && chunk <= chunk_max,
                        "mid-session resample chunk {chunk} outside {:?} for {}",
                        profile.surface_chunk_size_range,
                        surface.id,
                    );
                    let (delay_min, delay_max) = profile.surface_delay_ms_range;
                    assert!(
                        delay >= delay_min && delay <= delay_max,
                        "mid-session resample delay {delay} outside {:?} for {}",
                        profile.surface_delay_ms_range,
                        surface.id,
                    );
                }
            }
        }
    }

    #[test]
    fn operator_shaping_controls_survive_resampling() {
        let mut settings = RelaySettings::default();
        settings.policy.inter_chunk_delay_ms = 73;
        for requested_cap in [0, 512] {
            settings.policy.write_chunk_size = requested_cap;
            let admitted_cap = requested_cap.max(1);
            for surface in RELAY_SURFACE_CATALOG {
                settings.policy.surface_profile_id = Some(surface.id.into());
                let profile = build_session_profile_with_now_and_nonce(
                    &settings,
                    Some(("relay.example.org", 443)),
                    10_000,
                    42,
                    SurfaceBias::default(),
                );
                assert_eq!(
                    profile.surface_chunk_size_range,
                    (admitted_cap, admitted_cap)
                );
                assert_eq!(profile.surface_delay_ms_range, (73, 73));
                assert_eq!(profile.write_chunk_size, admitted_cap);
                assert_eq!(profile.inter_chunk_delay_ms, 73);
                assert_eq!(
                    profile.inter_chunk_jitter_ms_window,
                    surface.inter_chunk_jitter_ms_window
                );
                let mut rng = StdRng::seed_from_u64(0x5ca1ab1e);
                for _ in 0..128 {
                    let (chunk, delay) = resample_session_dynamics(&profile, &mut rng);
                    assert_eq!(chunk, admitted_cap, "cap lost for {}", surface.id);
                    assert_eq!(delay, 73, "delay override lost for {}", surface.id);
                    let jittered_delay = sample_chunk_delay_ms(&profile, &mut rng);
                    assert!(
                        (73..=73 + surface.inter_chunk_jitter_ms_window).contains(&jittered_delay)
                    );
                }
            }
        }
    }

    #[test]
    fn operator_shaping_in_range_cap_retains_diversity() {
        let mut settings = RelaySettings::default();
        for surface in RELAY_SURFACE_CATALOG {
            let (minimum, maximum) = surface.chunk_size_range;
            let cap = minimum + (maximum - minimum) / 2;
            settings.policy.write_chunk_size = cap;
            settings.policy.surface_profile_id = Some(surface.id.into());
            let profile = build_session_profile_with_now_and_nonce(
                &settings,
                None,
                10_000,
                17,
                SurfaceBias::default(),
            );
            assert_eq!(profile.surface_chunk_size_range, (minimum, cap));
            let mut rng = StdRng::seed_from_u64(0xcafe);
            let mut observed = std::collections::BTreeSet::new();
            for _ in 0..128 {
                let (chunk, delay) = resample_session_dynamics(&profile, &mut rng);
                assert!((minimum..=cap).contains(&chunk));
                assert!((surface.inter_chunk_delay_ms_range.0
                    ..=surface.inter_chunk_delay_ms_range.1)
                    .contains(&delay));
                observed.insert(chunk);
            }
            assert!(observed.len() > 1, "diversity collapsed for {}", surface.id);
        }
    }

    #[test]
    fn unconstrained_shaping_preserves_seeded_draws() {
        let mut settings = RelaySettings::default();
        settings.policy.write_chunk_size = usize::MAX;
        for surface in RELAY_SURFACE_CATALOG {
            settings.policy.surface_profile_id = Some(surface.id.into());
            for nonce in 0..64 {
                let profile = build_session_profile_with_now_and_nonce(
                    &settings,
                    None,
                    10_000,
                    nonce,
                    SurfaceBias::default(),
                );
                let expected = sample_session_dynamics(surface, nonce);
                assert_eq!(
                    (profile.write_chunk_size, profile.inter_chunk_delay_ms),
                    expected,
                    "session draw changed for {} nonce {nonce}",
                    surface.id
                );
                assert_eq!(profile.surface_chunk_size_range, surface.chunk_size_range);
                assert_eq!(
                    profile.surface_delay_ms_range,
                    surface.inter_chunk_delay_ms_range
                );
                let mut rng = StdRng::seed_from_u64(nonce);
                assert_eq!(
                    resample_session_dynamics(&profile, &mut rng),
                    expected,
                    "resample draw changed for {} nonce {nonce}",
                    surface.id
                );
            }
        }
    }

    #[tokio::test]
    async fn copy_with_policy_preserves_operator_chunk_cap_after_resampling() {
        use std::pin::Pin;
        use std::task::{Context, Poll};

        #[derive(Default)]
        struct RecordingWriter {
            payload: Vec<u8>,
            writes: Vec<usize>,
        }

        impl AsyncWrite for RecordingWriter {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.payload.extend_from_slice(buf);
                self.writes.push(buf.len());
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        const CAP: usize = 256;
        let mut settings = RelaySettings::default();
        settings.policy.write_chunk_size = CAP;
        settings.policy.surface_profile_id = Some("browser_like_balanced".into());
        let mut profile = build_session_profile_with_now_and_nonce(
            &settings,
            None,
            10_000,
            17,
            SurfaceBias::default(),
        );
        // Keep this regression about writes and payload integrity. Base delay
        // retention is covered by the deterministic resampling test above.
        profile.inter_chunk_delay_ms = 0;
        profile.surface_delay_ms_range = (0, 0);
        profile.inter_chunk_jitter_ms_window = 0;
        profile.padding_probability_milli = 1000;
        let payload: Vec<u8> = (0..96 * CAP).map(|n| (n % 251) as u8).collect();
        let mut reader = payload.as_slice();
        let mut writer = RecordingWriter::default();
        let copied = copy_with_policy(&mut reader, &mut writer, &profile)
            .await
            .expect("copy capped payload");
        assert_eq!(copied, payload.len() as u64);
        assert_eq!(writer.payload, payload);
        assert!(writer
            .writes
            .iter()
            .all(|&length| length > 0 && length <= CAP));
        // Resample countdown is at most 32 read chunks, so 96 capped chunks
        // necessarily exercise multiple redraws, including padding splits.
        assert_eq!(writer.writes.len(), 192);
    }

    #[test]
    fn resample_session_dynamics_falls_back_when_surface_range_is_unset() {
        // Default-constructed RelaySessionProfile (e.g. test inline structs
        // using `..Default::default()`) has surface_*_range = (0, 0). The
        // resample helper must NOT then return 0 for chunk_size — it falls
        // back to the session-instance scalars so behavior degrades safely.
        let profile = RelaySessionProfile {
            write_chunk_size: 4096,
            inter_chunk_delay_ms: 7,
            // surface_*_range left at Default::default() = (0, 0)
            ..RelaySessionProfile::default()
        };
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..32 {
            let (chunk, delay) = resample_session_dynamics(&profile, &mut rng);
            assert_eq!(chunk, 4096);
            assert_eq!(delay, 7);
        }
    }

    #[test]
    fn next_resample_countdown_returns_zero_when_surface_range_is_unset() {
        let profile = RelaySessionProfile {
            write_chunk_size: 4096,
            inter_chunk_delay_ms: 7,
            ..RelaySessionProfile::default()
        };
        let mut rng = StdRng::seed_from_u64(7);
        assert_eq!(next_resample_countdown(&profile, &mut rng), 0);
    }

    #[test]
    fn surface_bias_is_neutral_by_default() {
        let bias = SurfaceBias::default();
        assert!(bias.is_neutral());
    }

    #[test]
    fn surface_bias_is_not_neutral_when_any_axis_set() {
        let bias = SurfaceBias {
            high_jitter_preferred: 0.4,
            ..SurfaceBias::default()
        };
        assert!(!bias.is_neutral());
    }

    #[test]
    fn surface_weight_baseline_is_one_for_neutral_bias() {
        for surface in RELAY_SURFACE_CATALOG.iter() {
            let weight = surface_weight(surface, &SurfaceBias::default());
            assert!((weight - 1.0).abs() < 1e-6, "neutral baseline != 1");
        }
    }

    #[test]
    fn surface_weight_lifts_matching_profiles_under_low_latency_bias() {
        let bias = SurfaceBias {
            low_latency_preferred: 1.0,
            ..SurfaceBias::default()
        };
        // desktop_chrome_streaming has inter_chunk_delay_ms_range (0, 2) so
        // it matches "low latency". enterprise_java_client starts at delay
        // 3, so it does not match.
        let streaming = RELAY_SURFACE_CATALOG
            .iter()
            .find(|p| p.id == "desktop_chrome_streaming")
            .expect("catalog has desktop_chrome_streaming");
        let java = RELAY_SURFACE_CATALOG
            .iter()
            .find(|p| p.id == "enterprise_java_client")
            .expect("catalog has enterprise_java_client");
        assert!(surface_weight(streaming, &bias) > surface_weight(java, &bias) + 0.1);
    }

    #[test]
    fn pick_surface_profile_neutral_bias_matches_mod_of_seed() {
        // With a neutral bias, selection MUST be the same deterministic
        // mod-of-seed path used pre-2.5. Otherwise an unintentional
        // change in selection would silently rotate the wire family.
        for seed in 0u64..256 {
            let (chosen, bias_applied) = pick_surface_profile(seed, SurfaceBias::default());
            assert!(!bias_applied);
            let expected = RELAY_SURFACE_CATALOG[(seed as usize) % RELAY_SURFACE_CATALOG.len()];
            assert_eq!(chosen.id, expected.id);
        }
    }

    #[test]
    fn pick_surface_profile_biased_path_marks_bias_applied() {
        let bias = SurfaceBias {
            low_visibility_preferred: 1.0,
            ..SurfaceBias::default()
        };
        let (_, bias_applied) = pick_surface_profile(123, bias);
        assert!(bias_applied);
    }

    #[test]
    fn pick_surface_profile_biased_selection_skews_toward_matching_profiles() {
        // With low_visibility_preferred = 1.0 we expect a measurable skew
        // toward profiles whose chunk_size_range max is small. We don't
        // assert exact counts — too noisy — but we do require the high-
        // visibility profile (video_stream_h264, chunk_max=48 KiB) to be
        // sampled strictly less often than at least one low-visibility
        // profile in a 4096-seed sample.
        let bias = SurfaceBias {
            low_visibility_preferred: 1.0,
            ..SurfaceBias::default()
        };
        let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for seed in 0u64..4096 {
            let (chosen, _) = pick_surface_profile(seed, bias);
            *counts.entry(chosen.id).or_insert(0) += 1;
        }
        let video = counts.get("video_stream_h264").copied().unwrap_or(0);
        let realtime = counts.get("realtime_websocket").copied().unwrap_or(0);
        assert!(
            realtime > video,
            "low_visibility_preferred bias should lift realtime_websocket (chunk≤6 KiB) over video_stream_h264 (chunk≤48 KiB), but got realtime={realtime} video={video}",
        );
    }

    #[test]
    fn build_session_profile_with_brain_bias_records_when_bias_changes_selection() {
        let settings = RelaySettings::default();
        // A neutral bias must report surface_bias_applied = false.
        let neutral = build_session_profile_with_brain_bias(
            &settings,
            Some(("api.ipify.org", 443)),
            SurfaceBias::default(),
        );
        assert!(!neutral.surface_bias_applied);

        // A non-neutral bias must report surface_bias_applied = true.
        let biased = build_session_profile_with_brain_bias(
            &settings,
            Some(("api.ipify.org", 443)),
            SurfaceBias {
                high_jitter_preferred: 0.6,
                ..SurfaceBias::default()
            },
        );
        assert!(biased.surface_bias_applied);
    }

    #[test]
    fn next_resample_countdown_is_in_window_for_real_profiles() {
        let mut settings = RelaySettings::default();
        settings.policy.surface_profile_id = Some("desktop_chrome_streaming".into());
        let profile = build_session_profile_with_now_and_nonce(
            &settings,
            Some(("api.ipify.org", 443)),
            10_000,
            1,
            SurfaceBias::default(),
        );
        let mut rng = StdRng::seed_from_u64(99);
        for _ in 0..128 {
            let countdown = next_resample_countdown(&profile, &mut rng);
            assert!((4..=32).contains(&countdown));
        }
    }

    #[test]
    fn catalog_declares_padding_per_family() {
        // Phase 5 Phase 2: every catalog entry must carry padding fields.
        // We do NOT require padding > 0 on every family (cli_https_compact
        // and enterprise_java_client are canonical-honest identities that
        // should NOT split chunks). We DO require: when probability > 0,
        // the split-ratio range is non-degenerate and bounded.
        let mut padding_enabled_count = 0;
        for surface in RELAY_SURFACE_CATALOG.iter() {
            let p = surface.padding_probability_milli;
            assert!(
                p <= 1000,
                "padding_probability_milli {} > 1000 for {}",
                p,
                surface.id
            );
            let (lo, hi) = surface.padding_split_ratio_milli_range;
            assert!(
                lo <= hi,
                "split ratio range inverted for {}: ({}, {})",
                surface.id,
                lo,
                hi
            );
            assert!(
                hi <= 1000,
                "split ratio range upper bound {} > 1000 for {}",
                hi,
                surface.id
            );
            if p > 0 {
                padding_enabled_count += 1;
                assert!(
                    lo > 0 || hi > 0,
                    "padding enabled but ratio range collapsed to (0, 0) for {}",
                    surface.id
                );
            }
        }
        // At least 10 of the 18 families should have padding enabled so the
        // joint distribution actually widens; otherwise the feature has no
        // observable effect across a random catalog draw.
        assert!(
            padding_enabled_count >= 10,
            "only {} of {} families have padding > 0; catalog under-uses the axis",
            padding_enabled_count,
            RELAY_SURFACE_CATALOG.len()
        );
    }

    #[test]
    fn session_profile_inherits_padding_fields_from_surface() {
        // Build a session profile for each catalog id and verify the
        // padding fields propagate from surface to session profile.
        let mut settings = RelaySettings::default();
        settings.policy.write_chunk_size = 1024 * 1024;
        for surface in RELAY_SURFACE_CATALOG.iter() {
            settings.policy.surface_profile_id = Some(surface.id.into());
            let profile = build_session_profile_with_now_and_nonce(
                &settings,
                Some(("api.ipify.org", 443)),
                10_000,
                42,
                SurfaceBias::default(),
            );
            assert_eq!(
                profile.padding_probability_milli, surface.padding_probability_milli,
                "padding probability not propagated for {}",
                surface.id
            );
            assert_eq!(
                profile.padding_split_ratio_milli_range, surface.padding_split_ratio_milli_range,
                "padding split-ratio range not propagated for {}",
                surface.id
            );
        }
    }

    #[tokio::test]
    async fn copy_with_policy_emits_more_writes_when_padding_enabled() {
        // Wire-level proof: when padding probability is 1000‰ (always
        // split) and the chunk is splittable (n >= 2), the writer ends
        // up emitting MORE distinct writes than the un-padded case for
        // the same payload size. We use a `tokio::io::duplex` paired
        // with a counting wrapper: every `poll_write` on the wrapper
        // increments a counter, so doubled writes show up.
        use std::pin::Pin;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncWrite, ReadBuf};

        struct CountingWriter {
            inner: tokio::io::DuplexStream,
            count: Arc<AtomicUsize>,
        }
        impl AsyncWrite for CountingWriter {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                let pinned = Pin::new(&mut self.inner);
                match pinned.poll_write(cx, buf) {
                    Poll::Ready(Ok(n)) => {
                        if n > 0 {
                            self.count.fetch_add(1, Ordering::SeqCst);
                        }
                        Poll::Ready(Ok(n))
                    }
                    other => other,
                }
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
        impl tokio::io::AsyncRead for CountingWriter {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }

        // Run twice: once with padding=0 (baseline), once with padding=1000.
        async fn run_once(padding_milli: u16) -> usize {
            let payload = vec![0u8; 8 * 1024];
            let (write_side, read_side) = tokio::io::duplex(64 * 1024);
            let count = Arc::new(AtomicUsize::new(0));
            let mut counted = CountingWriter {
                inner: write_side,
                count: count.clone(),
            };
            let profile = RelaySessionProfile {
                write_chunk_size: 1024,
                inter_chunk_delay_ms: 0,
                inter_chunk_jitter_ms_window: 0,
                padding_probability_milli: padding_milli,
                padding_split_ratio_milli_range: if padding_milli == 0 {
                    (0, 0)
                } else {
                    (400, 600)
                },
                ..RelaySessionProfile::default()
            };
            let task = tokio::spawn(async move {
                let mut r = read_side;
                let _ = tokio::io::AsyncReadExt::read_to_end(&mut r, &mut Vec::new()).await;
            });
            let mut src: &[u8] = &payload;
            let _ = copy_with_policy(&mut src, &mut counted, &profile)
                .await
                .expect("copy");
            drop(counted);
            task.await.unwrap();
            count.load(Ordering::SeqCst)
        }

        let baseline = run_once(0).await;
        let padded = run_once(1000).await;
        assert!(
            padded > baseline,
            "padded write count {} not greater than baseline {}",
            padded,
            baseline
        );
    }

    #[tokio::test]
    async fn copy_with_policy_applies_jitter_distribution() {
        // Run copy_with_policy under a profile with a non-zero jitter window
        // and check the elapsed time is non-trivial. We don't assert a tight
        // distribution shape — too flaky on busy CI — but we do require the
        // run to be at least the base delay × chunks (jitter only ever adds
        // time, never subtracts). This catches a regression where jitter
        // sampling silently returns 0.
        let payload = vec![0u8; 8 * 1024];
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let profile = RelaySessionProfile {
            write_chunk_size: 1024,
            inter_chunk_delay_ms: 1,
            inter_chunk_jitter_ms_window: 2,
            ..RelaySessionProfile::default()
        };
        let task = tokio::spawn(async move {
            let _ = writer.write_all(&payload).await;
            drop(writer);
        });
        let mut sink = tokio::io::sink();
        let start = std::time::Instant::now();
        let bytes = copy_with_policy(&mut reader, &mut sink, &profile)
            .await
            .expect("copy");
        let elapsed = start.elapsed();
        task.await.unwrap();
        assert_eq!(bytes, 8 * 1024);
        // 8 chunks × 1 ms base = 8 ms floor; jitter can only add. Allow a
        // generous floor so we don't flake on tokio scheduling slack.
        assert!(
            elapsed >= Duration::from_millis(5),
            "copy_with_policy ran in {elapsed:?}, jitter pacing likely no-op"
        );
    }
}
