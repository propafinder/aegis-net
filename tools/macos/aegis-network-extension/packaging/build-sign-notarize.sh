#!/bin/bash
# B-06 S09: two-role (host app + PacketTunnel system extension) product
# build, assembly, Developer ID signing, verification, ZIP, notarization,
# stapling and Gatekeeper assessment. Each stage is separately selectable.
#
# Stages, always executed in this order:
#   build     nice -n 10 cargo build --release -j 4 (host + provider only);
#             only together with assemble, so the receipt binds the binaries
#   assemble  product-mode assembly; CFBundleVersion from --version must be
#             greater than every receipt, every version-ledger entry and the
#             installed app; embeds the two Developer ID profiles given as
#             paths outside Git
#   sign      codesign inside-out, --options runtime --timestamp, committed
#             packaging/entitlements, with the certificate pinned at assembly
#   verify    codesign --verify --strict, Developer ID authority, the leaf
#             certificate listed in both embedded profiles, an empty diff of
#             signed entitlements against the committed file and the
#             profile-decoded (security cms -D) values, distributable modes
#   zip       ditto ZIP of the verified app
#   notarize  notarytool submit --keychain-profile --wait (requires
#             --approve-zip-sha256 equal to the ZIP's SHA-256)
#   staple    stapler staple + validate, then a stapled ZIP
#   assess    spctl -a -vv (must report source=Notarized Developer ID)
#
# A stage runs only when its predecessor's latest real result is ok and no
# earlier stage ran again after it. --dry-run prints the exact commands and
# writes nothing except dry-run entries in an existing receipt; dry-run
# entries never satisfy or block a gate. Receipts (commit, version, SHA-256
# values, signer, submissions) go to the gitignored artifacts directory; the
# version ledger lives outside every worktree. Network-touching stages (sign
# timestamp, notarize, staple) refuse inside a capture window.
set -euo pipefail
# Receipts, logs and run directories stay owner-only; the distributable
# bundle is produced under in_bundle_umask (0755 directories, 0644 files).
umask 077

PKG=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PACKAGING="$PKG/packaging"
PIPELINE=(python3 -I -B "$PACKAGING/pipeline.py")
TEAM=TEAMID0000
APP_ID=dev.aegis.macos
PROVIDER_ID=dev.aegis.macos.PacketTunnel
APP_GROUP=group.TEAMID0000.dev.aegis.macos
TARGET=aarch64-apple-darwin
TOOLCHAIN=1.97.1
ALL_STAGES="build assemble sign verify zip notarize staple assess"
DEFAULT_LEDGER="$HOME/Library/Application Support/aegis-packaging/version-ledger"
DEFAULT_INSTALLED_APP=/Applications/AEGIS.app

usage() {
    cat >&2 <<'EOF'
usage: build-sign-notarize.sh --stages LIST [options]
  --stages LIST            comma list (no spaces) of: build,assemble,sign,verify,zip,notarize,staple,assess
  --version N              CFBundleVersion (assemble); must exceed every receipt,
                           every version-ledger entry and the installed app
  --short-version S        CFBundleShortVersionString (default 0.1.0)
  --features NAME          build only: apple (default), apple,sfu-media-vp8,
                           or apple,sfu-media-vp8,enrolled-quic
  --native-vp8-receipt P   required with optional VP8: reviewed Darwin recipe receipt
  --native-vp8-prefix P    required with optional VP8: exact verified native prefix
  --artifacts-dir DIR      default $AEGIS_PACKAGING_ARTIFACTS or packaging/artifacts (gitignored)
  --run-dir DIR            existing run directory (required when assemble is not selected)
  --host-profile PATH      or $AEGIS_HOST_PROFILE (Developer ID profile for dev.aegis.macos)
  --provider-profile PATH  or $AEGIS_PROVIDER_PROFILE (dev.aegis.macos.PacketTunnel)
  --identity SHA1          or $AEGIS_SIGN_IDENTITY; default: the unique
                           "Developer ID Application: ... (TEAMID0000)" identity;
                           later stages reuse the certificate pinned at assembly
  --notary-profile NAME    or $AEGIS_NOTARY_PROFILE (default aegis-notary)
  --host-binary PATH       prebuilt stand-in host binary (not with build)
  --provider-binary PATH   prebuilt stand-in provider binary (not with build)
  --approve-zip-sha256 HEX owner approval binding notarize to one exact ZIP
  --dry-run                print the exact commands; do not execute stages
Environment overrides (tests only; such runs cannot be notarized):
  AEGIS_PACKAGING_LEDGER   default ~/Library/Application Support/aegis-packaging/version-ledger
  AEGIS_INSTALLED_APP      default /Applications/AEGIS.app
EOF
    exit 2
}

die() { echo "build-sign-notarize: $*" >&2; exit 1; }
note() { echo "== $*"; }
quote() { local out='' arg; for arg in "$@"; do out="$out $(printf '%q' "$arg")"; done; printf '%s\n' "${out# }"; }
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
sha1_upper() { shasum -a 1 "$1" | awk '{print toupper($1)}'; }
upper() { printf '%s' "$1" | tr 'a-f' 'A-F'; }
utc() { date -u +%Y%m%dT%H%M%SZ; }
# Bounded execution without depending on coreutils: SIGALRM survives exec.
bounded() { local secs=$1; shift; perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' "$secs" "$@"; }
# Everything that lands inside AEGIS.app or its ZIPs uses distributable modes.
in_bundle_umask() { ( umask 022; "$@" ); }

STAGES='' VERSION='' SHORT_VERSION=0.1.0 RUN_DIR='' DRY_RUN=0 APPROVED_ZIP_SHA=''
BUILD_FEATURES=apple FEATURES_GIVEN=0 NATIVE_VP8_RECEIPT='' NATIVE_VP8_PREFIX=''
NATIVE_VP8_PROOF=null
native_vp8_enabled() {
    case "$BUILD_FEATURES" in
        apple,sfu-media-vp8|apple,sfu-media-vp8,enrolled-quic) return 0 ;;
    esac
    return 1
}
ARTIFACTS=${AEGIS_PACKAGING_ARTIFACTS:-$PACKAGING/artifacts}
LEDGER=${AEGIS_PACKAGING_LEDGER:-$DEFAULT_LEDGER}
INSTALLED_APP=${AEGIS_INSTALLED_APP:-$DEFAULT_INSTALLED_APP}
HOST_PROFILE=${AEGIS_HOST_PROFILE:-} PROVIDER_PROFILE=${AEGIS_PROVIDER_PROFILE:-}
IDENTITY=${AEGIS_SIGN_IDENTITY:-} NOTARY_PROFILE=${AEGIS_NOTARY_PROFILE:-aegis-notary}
HOST_BIN='' PROVIDER_BIN='' BINARIES_SOURCE='' RUN_ID=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --stages) STAGES=${2:-}; shift 2 ;;
        --version) VERSION=${2:-}; shift 2 ;;
        --short-version) SHORT_VERSION=${2:-}; shift 2 ;;
        --features) BUILD_FEATURES=${2:-}; FEATURES_GIVEN=1; shift 2 ;;
        --native-vp8-receipt) NATIVE_VP8_RECEIPT=${2:-}; shift 2 ;;
        --native-vp8-prefix) NATIVE_VP8_PREFIX=${2:-}; shift 2 ;;
        --artifacts-dir) ARTIFACTS=${2:-}; shift 2 ;;
        --run-dir) RUN_DIR=${2:-}; shift 2 ;;
        --host-profile) HOST_PROFILE=${2:-}; shift 2 ;;
        --provider-profile) PROVIDER_PROFILE=${2:-}; shift 2 ;;
        --identity) IDENTITY=${2:-}; shift 2 ;;
        --notary-profile) NOTARY_PROFILE=${2:-}; shift 2 ;;
        --host-binary) HOST_BIN=${2:-}; shift 2 ;;
        --provider-binary) PROVIDER_BIN=${2:-}; shift 2 ;;
        --approve-zip-sha256) APPROVED_ZIP_SHA=${2:-}; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done
[ -n "$STAGES" ] || usage

# One parse of --stages serves both validation and selection.
# An explicit ASCII set is stable under Darwin's locale collation, where
# the range a-z can also match uppercase letters.
case "$STAGES" in *[!abcdefghijklmnopqrstuvwxyz,]*) die "--stages takes a comma list without spaces: '$STAGES'" ;; esac
case ",$STAGES," in *,,*) die "--stages has an empty entry: '$STAGES'" ;; esac
IFS=',' read -r -a STAGE_LIST <<< "$STAGES"
SEEN=' '
for stage in "${STAGE_LIST[@]}"; do
    case " $ALL_STAGES " in *" $stage "*) ;; *) die "unknown stage: $stage" ;; esac
    case "$SEEN" in *" $stage "*) die "duplicate stage: $stage" ;; esac
    SEEN="$SEEN$stage "
done
selected() { case "$SEEN" in *" $1 "*) return 0 ;; esac; return 1; }

case "$ARTIFACTS" in /*) ;; *) die 'absolute --artifacts-dir required' ;; esac
case "$LEDGER" in /*) ;; *) die 'absolute AEGIS_PACKAGING_LEDGER required' ;; esac
if [ -n "$HOST_BIN$PROVIDER_BIN" ]; then
    [ -n "$HOST_BIN" ] && [ -n "$PROVIDER_BIN" ] || die 'host and provider stand-in binaries go together'
    selected build && die 'stand-in binaries and the build stage are mutually exclusive'
fi
if selected build && ! selected assemble && [ "$DRY_RUN" = 0 ]; then
    die 'build runs only together with assemble, so the run receipt binds the built binaries'
fi
[ "$FEATURES_GIVEN" = 0 ] || selected build || die '--features requires the build stage'
case "$BUILD_FEATURES" in
    apple)
        [ -z "$NATIVE_VP8_RECEIPT$NATIVE_VP8_PREFIX" ] \
            || die 'native VP8 inputs require apple,sfu-media-vp8'
        ;;
    apple,sfu-media-vp8|apple,sfu-media-vp8,enrolled-quic)
        selected build && selected assemble || die 'native VP8 requires build and assemble together'
        case "$NATIVE_VP8_RECEIPT:$NATIVE_VP8_PREFIX" in
            /*:/*) ;;
            *) die 'native VP8 requires absolute receipt and prefix paths' ;;
        esac
        NATIVE_VP8_PROOF=$(python3 -I -B "$PACKAGING/verify-native-vp8.py" \
            --receipt "$NATIVE_VP8_RECEIPT" --prefix "$NATIVE_VP8_PREFIX") \
            || die 'native VP8 receipt/prefix verification failed'
        ;;
    *) die 'unsupported build feature set' ;;
esac
[ -z "$IDENTITY" ] || IDENTITY=$(upper "$IDENTITY")
REPO=$(git -C "$PKG" rev-parse --show-toplevel)
# Profiles stay outside Git: never inside this checkout, never tracked by any
# repository that happens to contain them.
for path in "$HOST_PROFILE" "$PROVIDER_PROFILE"; do
    [ -n "$path" ] || continue
    case "$path" in /*) ;; *) die 'absolute profile paths required' ;; esac
    case "$path" in "$REPO"/*) die 'profiles must come from a path outside this checkout' ;; esac
    if git -C "$(dirname "$path")" ls-files --error-unmatch -- "$(basename "$path")" >/dev/null 2>&1; then
        die "profile is tracked by Git: $path"
    fi
done

tree_dirty() { if [ -n "$(git -C "$REPO" status --porcelain)" ]; then echo true; else echo false; fi; }
COMMIT=$(git -C "$PKG" rev-parse HEAD)
DIRTY=$(tree_dirty)
if native_vp8_enabled && [ "$DIRTY" != false ]; then
    die 'native VP8 product build requires clean committed source'
fi
RECEIPTS="$ARTIFACTS/receipts"
if [ "$LEDGER" = "$DEFAULT_LEDGER" ] && [ "$INSTALLED_APP" = "$DEFAULT_INSTALLED_APP" ]; then
    VERSION_CHECKS_DEFAULT=true
else
    VERSION_CHECKS_DEFAULT=false
fi

# Run directory and receipt naming: one run per version reservation; a retry
# of assembly is a new run with a new version, so failed receipts stay.
if selected assemble; then
    [ -n "$RUN_DIR" ] && die '--run-dir is for continuing a run; assemble creates a new one'
    [ -n "$VERSION" ] || die '--version is required for assemble'
    RUN_ID="v$VERSION-$(utc)-${COMMIT:0:12}"
    RUN_DIR="$ARTIFACTS/runs/$RUN_ID"
else
    [ -n "$RUN_DIR" ] || selected build || die '--run-dir is required without assemble'
    if [ -n "$RUN_DIR" ]; then
        case "$RUN_DIR" in /*) ;; *) die 'absolute --run-dir required' ;; esac
        [ -d "$RUN_DIR" ] || die "run directory not found: $RUN_DIR"
        RUN_ID=$(basename "$RUN_DIR")
        ARTIFACTS=$(dirname "$(dirname "$RUN_DIR")")
        RECEIPTS="$ARTIFACTS/receipts"
        [ -f "$RECEIPTS/$RUN_ID.json" ] || die "no receipt for run $RUN_ID"
    fi
fi
RECEIPT="$RECEIPTS/${RUN_ID:-none}.json"
APP="$RUN_DIR/bundle/AEGIS.app"
EXT="$APP/Contents/Library/SystemExtensions/$PROVIDER_ID.systemextension"
LOGS="$RUN_DIR/logs"
CURRENT_STAGE=''

receipt() { [ "$DRY_RUN" = 1 ] && [ ! -f "$RECEIPT" ] && return 0; "${PIPELINE[@]}" receipt --receipt "$RECEIPT" "$@"; }
receipt_get() { [ -f "$RECEIPT" ] || return 0; "${PIPELINE[@]}" receipt --receipt "$RECEIPT" --get "$1"; }
# Order aware: '' (never ran), ok, failed, or stale (an earlier stage reran).
stage_status() { [ -f "$RECEIPT" ] || return 0; "${PIPELINE[@]}" receipt --receipt "$RECEIPT" --stage-status "$1"; }
require_stage() {
    local status
    status=$(stage_status "$1")
    [ "$status" = ok ] && return 0
    [ "$DRY_RUN" = 1 ] && { echo "note: stage $1 is not current in this run (${status:-not run}); printed commands use planned paths"; return 0; }
    die "stage $1 must be current (latest real result ok, not superseded) before $CURRENT_STAGE; it is ${status:-not run}"
}
on_exit() {
    local code=$?
    if [ "$code" -ne 0 ] && [ -n "$CURRENT_STAGE" ] && [ "$DRY_RUN" = 0 ] && [ -f "$RECEIPT" ]; then
        "${PIPELINE[@]}" receipt --receipt "$RECEIPT" --stage "$CURRENT_STAGE" --status failed \
            --detail "exit $code" || true
        echo "stage $CURRENT_STAGE failed; receipt $RECEIPT retains the failure" >&2
    fi
}
trap on_exit EXIT

# Signing (timestamp server), upload and stapling contact Apple. They must
# never run while an independent packet capture window is open.
refuse_capture_window() {
    if [ -n "${AEGIS_CAPTURE_WINDOW:-}" ] || [ -e "$ARTIFACTS/capture-window.active" ]; then
        die "$CURRENT_STAGE refused: a capture window is marked active"
    fi
    if pgrep -x tcpdump >/dev/null 2>&1 || pgrep -x dumpcap >/dev/null 2>&1 || pgrep -x tshark >/dev/null 2>&1; then
        die "$CURRENT_STAGE refused: a packet capture process is running"
    fi
}

resolve_identity() {
    local listing count
    listing=$(security find-identity -v -p codesigning)
    if [ -z "$IDENTITY" ]; then
        count=$(printf '%s\n' "$listing" | grep -c "\"Developer ID Application: .* ($TEAM)\"" || true)
        [ "$count" = 1 ] || die "expected exactly one Developer ID Application ($TEAM) identity, found $count"
        IDENTITY=$(printf '%s\n' "$listing" | grep "\"Developer ID Application: .* ($TEAM)\"" | awk '{print $2}')
    fi
    printf '%s\n' "$listing" | grep -q "^ *[0-9]*) $IDENTITY \"Developer ID Application: .* ($TEAM)\"$" \
        || die "identity $IDENTITY is not a valid Developer ID Application ($TEAM) code-signing identity"
}

# The certificate checked against both profiles at assembly is the only one
# allowed to sign this run; a different --identity is refused, not adopted.
pinned_identity() {
    local pinned
    pinned=$(receipt_get profile_signer_sha1)
    if [ -n "$pinned" ]; then
        if [ -z "$IDENTITY" ]; then
            IDENTITY=$pinned
        elif [ "$IDENTITY" != "$pinned" ]; then
            die "identity $IDENTITY differs from $pinned, which both profiles were checked against at assembly"
        fi
    elif [ "$DRY_RUN" = 0 ]; then
        die 'receipt has no profile_signer_sha1; assemble a new run'
    fi
    resolve_identity
}

# Sources that decide what is signed and uploaded must be the ones recorded
# at assembly; the dirty flag is sampled again, not trusted from assembly.
recheck_source() {
    [ -f "$RECEIPT" ] || return 0
    [ "$(git -C "$PKG" rev-parse HEAD)" = "$(receipt_get commit)" ] \
        || die "$CURRENT_STAGE refused: HEAD differs from the commit recorded at assembly"
    if [ "$(receipt_get source_dirty)" = False ] && [ "$(tree_dirty)" != false ]; then
        die "$CURRENT_STAGE refused: the tree was clean at assembly and is dirty now"
    fi
    local role file key
    for role in host provider; do
        file="$PACKAGING/entitlements/$role.entitlements"
        "${PIPELINE[@]}" check-committed --role "$role" --entitlements "$file" >/dev/null
        [ "$(sha256 "$file")" = "$(receipt_get "${role}_entitlements_sha256")" ] \
            || die "$CURRENT_STAGE refused: $role entitlements changed since assembly"
    done
    for key in pipeline:"$PACKAGING/pipeline.py" script:"$PACKAGING/build-sign-notarize.sh" \
               assembler:"$PKG/assemble-unsigned.py" \
               native_verifier:"$PACKAGING/verify-native-vp8.py"; do
        [ "$(sha256 "${key#*:}")" = "$(receipt_get "${key%%:*}_sha256")" ] \
            || die "$CURRENT_STAGE refused: ${key#*:} changed since assembly"
    done
}

# An existing file is never overwritten: it is kept under a unique name
# unless Apple already received it, in which case a new run is required.
preserve_existing() {
    local path=$1
    [ -e "$path" ] || return 0
    if [ -n "$(receipt_get notary_submissions)" ]; then
        die "$path exists and this run already submitted to Apple; start a new run"
    fi
    mv "$path" "$path.superseded-$(utc)"
    echo "kept previous $(basename "$path") as $(basename "$path").superseded-*"
}

# Version checks, profile/identity checks and the version reservation happen
# before any long build, so a failed build still leaves a receipt.
preflight_run() {
    note "preflight: CFBundleVersion $VERSION, profiles, identity, committed entitlements"
    local version_args=(--receipts-dir "$RECEIPTS" --ledger-dir "$LEDGER"
        --installed-app "$INSTALLED_APP" --version "$VERSION")
    "${PIPELINE[@]}" check-version "${version_args[@]}"
    [ -n "$HOST_PROFILE" ] && [ -n "$PROVIDER_PROFILE" ] || die 'assemble requires --host-profile and --provider-profile'
    [ -f "$HOST_PROFILE" ] && [ -f "$PROVIDER_PROFILE" ] || die 'profile file not found'
    # Both profiles must name the exact certificate that will sign.
    resolve_identity
    "${PIPELINE[@]}" check-profile --role host --profile "$HOST_PROFILE" --signer-sha1 "$IDENTITY"
    "${PIPELINE[@]}" check-profile --role provider --profile "$PROVIDER_PROFILE" --signer-sha1 "$IDENTITY"
    "${PIPELINE[@]}" check-committed --role host --entitlements "$PACKAGING/entitlements/host.entitlements"
    "${PIPELINE[@]}" check-committed --role provider --entitlements "$PACKAGING/entitlements/provider.entitlements"
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $(quote "${PIPELINE[@]}" ledger-reserve "${version_args[@]}" --run-id "$RUN_ID" --commit "$COMMIT" --receipt "$RECEIPT")"
        echo "+ mkdir -p $(quote "$RUN_DIR/logs") $(quote "$RECEIPTS")"
        return 0
    fi
    mkdir -p "$ARTIFACTS/runs" "$RECEIPTS"
    mkdir "$RUN_DIR" "$LOGS"
    "${PIPELINE[@]}" ledger-reserve "${version_args[@]}" --run-id "$RUN_ID" --commit "$COMMIT" --receipt "$RECEIPT"
    "${PIPELINE[@]}" receipt --receipt "$RECEIPT" --create \
        --set run_id="$RUN_ID" --set commit="$COMMIT" --set-json source_dirty="$DIRTY" \
        --set bundle_version="$VERSION" --set short_version="$SHORT_VERSION" \
        --set app_id="$APP_ID" --set provider_id="$PROVIDER_ID" --set team_id="$TEAM" \
        --set app_group="$APP_GROUP" --set profile_signer_sha1="$IDENTITY" \
        --set ledger_dir="$LEDGER" --set installed_app_checked="$INSTALLED_APP" \
        --set-json version_checks_default="$VERSION_CHECKS_DEFAULT" \
        --set run_dir="$RUN_DIR" --set-json diagnostic_helpers_included=false \
        --set build_features="$(if selected build; then echo "$BUILD_FEATURES"; else echo stand-in-unverified; fi)" \
        --set-json native_vp8="$NATIVE_VP8_PROOF" \
        --set-json installed=false
}

stage_build() {
    note 'build: release host + provider (nice, -j 4)'
    # rustup run selects the pinned toolchain even when a non-rustup cargo
    # (e.g. Homebrew) is first on PATH, where `cargo +TOOLCHAIN` fails.
    # Explicit target dir: CARGO_TARGET_DIR or a config target-dir must not
    # redirect the build while stale binaries stay at the path read below.
    local build_env=(env -u CARGO_TARGET_DIR -u CARGO_BUILD_TARGET_DIR)
    if native_vp8_enabled; then
        build_env+=(-u VPX_LIB_DIR -u VPX_INCLUDE_DIR -u PKG_CONFIG
            -u PKG_CONFIG_PATH_aarch64-apple-darwin
            -u PKG_CONFIG_LIBDIR_aarch64-apple-darwin
            -u PKG_CONFIG_SYSROOT_DIR_aarch64-apple-darwin
            -u PKG_CONFIG_PATH_aarch64_apple_darwin
            -u PKG_CONFIG_LIBDIR_aarch64_apple_darwin
            -u PKG_CONFIG_SYSROOT_DIR_aarch64_apple_darwin
            -u TARGET_PKG_CONFIG_PATH -u TARGET_PKG_CONFIG_LIBDIR
            -u TARGET_PKG_CONFIG_SYSROOT_DIR)
    fi
    build_env+=(MACOSX_DEPLOYMENT_TARGET=14.4)
    if native_vp8_enabled; then
        build_env+=("PKG_CONFIG_PATH=$NATIVE_VP8_PREFIX/lib/pkgconfig"
            "PKG_CONFIG_LIBDIR=$NATIVE_VP8_PREFIX/lib/pkgconfig"
            PKG_CONFIG_SYSROOT_DIR= VPX_VERSION=1.17.0)
    fi
    local build_cmd=("${build_env[@]}"
        nice -n 10 rustup run "$TOOLCHAIN" cargo build --locked --release -j 4
        --manifest-path "$PKG/Cargo.toml" --target "$TARGET" --target-dir "$PKG/target"
        --features "$BUILD_FEATURES" --bin aegis-ne-host --bin aegis-ne-provider)
    HOST_BIN="$PKG/target/$TARGET/release/aegis-ne-host"
    PROVIDER_BIN="$PKG/target/$TARGET/release/aegis-ne-provider"
    BINARIES_SOURCE=build-stage
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $(quote "${build_cmd[@]}") 2>&1 | tee $(quote "$LOGS/build.log")"
        return 0
    fi
    : > "$LOGS/build.start"
    "${build_cmd[@]}" 2>&1 | tee "$LOGS/build.log"
    if native_vp8_enabled; then
        local after
        after=$(python3 -I -B "$PACKAGING/verify-native-vp8.py" \
            --receipt "$NATIVE_VP8_RECEIPT" --prefix "$NATIVE_VP8_PREFIX") \
            || die 'native VP8 input changed during build'
        [ "$after" = "$NATIVE_VP8_PROOF" ] || die 'native VP8 input changed during build'
    fi
    local bin
    for bin in "$HOST_BIN" "$PROVIDER_BIN"; do
        [ -f "$bin" ] && [ "$bin" -nt "$LOGS/build.start" ] || die "build did not produce a fresh $bin"
    done
    receipt --set build_log_sha256="$(sha256 "$LOGS/build.log")" --stage build --status ok
}

stage_assemble() {
    note "assemble: product mode, CFBundleVersion $VERSION"
    if [ -z "$HOST_BIN" ]; then
        HOST_BIN="$PKG/target/$TARGET/release/aegis-ne-host"
        PROVIDER_BIN="$PKG/target/$TARGET/release/aegis-ne-provider"
        BINARIES_SOURCE=cargo-target
    fi
    BINARIES_SOURCE=${BINARIES_SOURCE:-stand-in}
    local assemble_cmd=(python3 -I -B "$PKG/assemble-unsigned.py" --product
        --output "$RUN_DIR/bundle" --host-binary "$HOST_BIN" --provider-binary "$PROVIDER_BIN"
        --app-id "$APP_ID" --provider-id "$PROVIDER_ID" --app-group "$APP_GROUP" --team-id "$TEAM"
        --bundle-version "$VERSION" --short-version "$SHORT_VERSION")
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ (umask 022; $(quote "${assemble_cmd[@]}"))"
        echo "+ (umask 022; $(quote cp "$HOST_PROFILE" "$APP/Contents/embedded.provisionprofile"))"
        echo "+ (umask 022; $(quote cp "$PROVIDER_PROFILE" "$EXT/Contents/embedded.provisionprofile"))"
        echo "+ $(quote chmod -R u=rwX,go=rX "$APP")"
        return 0
    fi
    # The tree state recorded at reservation must still hold after the build.
    [ "$(git -C "$PKG" rev-parse HEAD)" = "$COMMIT" ] || die 'HEAD changed during the run'
    [ "$(tree_dirty)" = "$DIRTY" ] || die "tree dirty state changed during the run (was $DIRTY)"
    in_bundle_umask "${assemble_cmd[@]}"
    in_bundle_umask cp "$HOST_PROFILE" "$APP/Contents/embedded.provisionprofile"
    in_bundle_umask cp "$PROVIDER_PROFILE" "$EXT/Contents/embedded.provisionprofile"
    chmod -R u=rwX,go=rX "$APP"
    [ ! -e "$APP/Contents/Library/Helpers" ] || die 'diagnostic helpers present in product bundle'
    "${PIPELINE[@]}" check-modes --bundle "$APP"
    # Hash the bytes the assembler captured and copied, not the source paths.
    receipt --set binaries_source="$BINARIES_SOURCE" \
        --set host_binary="$HOST_BIN" --set provider_binary="$PROVIDER_BIN" \
        --set host_binary_sha256="$(sha256 "$APP/Contents/MacOS/aegis-ne-host")" \
        --set provider_binary_sha256="$(sha256 "$EXT/Contents/MacOS/aegis-ne-provider")" \
        --set assembly_json_sha256="$(sha256 "$RUN_DIR/bundle/assembly.json")" \
        --set assembler_sha256="$(sha256 "$PKG/assemble-unsigned.py")" \
        --set pipeline_sha256="$(sha256 "$PACKAGING/pipeline.py")" \
        --set script_sha256="$(sha256 "$PACKAGING/build-sign-notarize.sh")" \
        --set native_verifier_sha256="$(sha256 "$PACKAGING/verify-native-vp8.py")" \
        --set cargo_lock_sha256="$(sha256 "$PKG/Cargo.lock")" \
        --set host_entitlements_sha256="$(sha256 "$PACKAGING/entitlements/host.entitlements")" \
        --set provider_entitlements_sha256="$(sha256 "$PACKAGING/entitlements/provider.entitlements")" \
        --set host_profile_sha256="$(sha256 "$HOST_PROFILE")" \
        --set provider_profile_sha256="$(sha256 "$PROVIDER_PROFILE")" \
        --set host_info_plist_sha256="$(sha256 "$APP/Contents/Info.plist")" \
        --set provider_info_plist_sha256="$(sha256 "$EXT/Contents/Info.plist")" \
        --stage assemble --status ok
}

stage_sign() {
    note 'sign: provider system extension, then host app'
    require_stage assemble
    refuse_capture_window
    recheck_source
    pinned_identity
    local provider_cmd=(codesign --force --sign "$IDENTITY" --options runtime --timestamp
        --entitlements "$PACKAGING/entitlements/provider.entitlements" "$EXT")
    local host_cmd=(codesign --force --sign "$IDENTITY" --options runtime --timestamp
        --entitlements "$PACKAGING/entitlements/host.entitlements" "$APP")
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ (umask 022; $(quote "${provider_cmd[@]}"))"; echo "+ (umask 022; $(quote "${host_cmd[@]}"))"; return 0
    fi
    # A keychain access prompt would block; bound each call and record.
    in_bundle_umask bounded 300 "${provider_cmd[@]}" > "$LOGS/sign-provider.log" 2>&1 \
        || { cat "$LOGS/sign-provider.log" >&2; die 'provider codesign failed (keychain access or timestamp)'; }
    in_bundle_umask bounded 300 "${host_cmd[@]}" > "$LOGS/sign-host.log" 2>&1 \
        || { cat "$LOGS/sign-host.log" >&2; die 'host codesign failed (keychain access or timestamp)'; }
    receipt --set signer_sha1="$IDENTITY" --stage sign --status ok
}

stage_verify() {
    note 'verify: strict signatures, Developer ID authority, profile certificate, entitlement diff, modes'
    require_stage sign
    recheck_source
    local host_profile provider_profile
    host_profile="$APP/Contents/embedded.provisionprofile"
    provider_profile="$EXT/Contents/embedded.provisionprofile"
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $(quote codesign --verify --strict --verbose=2 "$EXT")"
        echo "+ $(quote codesign --verify --deep --strict --verbose=2 "$APP")"
        echo "+ $(quote codesign -dvv "$EXT") ; $(quote codesign -dvv "$APP")"
        echo "+ $(quote codesign -d --extract-certificates="$LOGS/cert-provider-" "$EXT")  # leaf SHA-1 = pinned, in embedded profile DeveloperCertificates"
        echo "+ $(quote codesign -d --extract-certificates="$LOGS/cert-host-" "$APP")  # leaf SHA-1 = pinned, in embedded profile DeveloperCertificates"
        echo "+ $(quote codesign -d --entitlements - --xml "$EXT") vs committed + security cms -D profile"
        echo "+ $(quote codesign -d --entitlements - --xml "$APP") vs committed + security cms -D profile"
        echo "+ $(quote "${PIPELINE[@]}" check-modes --bundle "$APP")"
        return 0
    fi
    bounded 120 codesign --verify --strict --verbose=2 "$EXT" > "$LOGS/verify-provider.log" 2>&1 \
        || { cat "$LOGS/verify-provider.log" >&2; die 'provider strict verification failed'; }
    bounded 120 codesign --verify --deep --strict --verbose=2 "$APP" > "$LOGS/verify-host.log" 2>&1 \
        || { cat "$LOGS/verify-host.log" >&2; die 'host strict verification failed'; }
    bounded 60 codesign -dvv "$EXT" > "$LOGS/display-provider.log" 2>&1
    bounded 60 codesign -dvv "$APP" > "$LOGS/display-host.log" 2>&1
    "${PIPELINE[@]}" check-signature --identifier "$PROVIDER_ID" --display-text "$LOGS/display-provider.log"
    "${PIPELINE[@]}" check-signature --identifier "$APP_ID" --display-text "$LOGS/display-host.log"
    [ "$(sha256 "$host_profile")" = "$(receipt_get host_profile_sha256)" ] || die 'embedded host profile changed'
    [ "$(sha256 "$provider_profile")" = "$(receipt_get provider_profile_sha256)" ] || die 'embedded provider profile changed'
    # The leaf certificate that actually signed each role must be the one
    # pinned at assembly and must be listed in that role's embedded profile.
    local role bundle profile leaf pinned
    pinned=$(receipt_get profile_signer_sha1)
    [ -n "$pinned" ] || die 'receipt has no profile_signer_sha1'
    for role in provider host; do
        if [ "$role" = host ]; then bundle=$APP profile=$host_profile; else bundle=$EXT profile=$provider_profile; fi
        rm -f "$LOGS/cert-$role-"*
        bounded 60 codesign -d --extract-certificates="$LOGS/cert-$role-" "$bundle" > "$LOGS/certs-$role.log" 2>&1
        [ -f "$LOGS/cert-$role-0" ] || die "$role: no leaf certificate extracted"
        leaf=$(sha1_upper "$LOGS/cert-$role-0")
        [ "$leaf" = "$pinned" ] || die "$role: signed by certificate $leaf, not $pinned checked at assembly"
        "${PIPELINE[@]}" check-profile --role "$role" --profile "$profile" --signer-sha1 "$leaf"
    done
    bounded 60 codesign -d --entitlements - --xml "$EXT" > "$LOGS/signed-provider.entitlements" 2>"$LOGS/signed-provider.stderr"
    bounded 60 codesign -d --entitlements - --xml "$APP" > "$LOGS/signed-host.entitlements" 2>"$LOGS/signed-host.stderr"
    "${PIPELINE[@]}" diff-signed --role provider --profile "$provider_profile" \
        --entitlements "$PACKAGING/entitlements/provider.entitlements" \
        --signed-xml "$LOGS/signed-provider.entitlements" --out "$LOGS/entitlement-diff-provider.json"
    "${PIPELINE[@]}" diff-signed --role host --profile "$host_profile" \
        --entitlements "$PACKAGING/entitlements/host.entitlements" \
        --signed-xml "$LOGS/signed-host.entitlements" --out "$LOGS/entitlement-diff-host.json"
    "${PIPELINE[@]}" check-modes --bundle "$APP"
    local authority
    authority=$(grep -m1 '^Authority=' "$LOGS/display-host.log" | cut -d= -f2-)
    receipt --set authority="$authority" --set verified_leaf_sha1="$leaf" \
        --set signed_host_sha256="$(sha256 "$APP/Contents/MacOS/aegis-ne-host")" \
        --set signed_provider_sha256="$(sha256 "$EXT/Contents/MacOS/aegis-ne-provider")" \
        --set host_code_resources_sha256="$(sha256 "$APP/Contents/_CodeSignature/CodeResources")" \
        --set provider_code_resources_sha256="$(sha256 "$EXT/Contents/_CodeSignature/CodeResources")" \
        --set-json entitlement_diff_empty=true --stage verify --status ok
}

zip_path() {
    local version commit
    version=$(receipt_get bundle_version); [ -n "$version" ] || version=$VERSION
    commit=$(receipt_get commit); [ -n "$commit" ] || commit=$COMMIT
    printf '%s/AEGIS-%s-%s.zip' "$RUN_DIR" "$version" "${commit:0:12}"
}

# The signed bytes must still be the ones verify inspected.
recheck_verified_bundle() {
    [ "$(sha256 "$APP/Contents/MacOS/aegis-ne-host")" = "$(receipt_get signed_host_sha256)" ] \
        && [ "$(sha256 "$EXT/Contents/MacOS/aegis-ne-provider")" = "$(receipt_get signed_provider_sha256)" ] \
        && [ "$(sha256 "$APP/Contents/_CodeSignature/CodeResources")" = "$(receipt_get host_code_resources_sha256)" ] \
        && [ "$(sha256 "$EXT/Contents/_CodeSignature/CodeResources")" = "$(receipt_get provider_code_resources_sha256)" ] \
        || die "$CURRENT_STAGE refused: signed bundle differs from the one verify inspected"
}

stage_zip() {
    note 'zip: ditto archive of the verified app'
    require_stage verify
    local zip
    zip=$(zip_path)
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ (umask 022; $(quote ditto -c -k --sequesterRsrc --keepParent "$APP" "$zip"))"
        echo "+ $(quote "${PIPELINE[@]}" check-modes --zip "$zip")"
        return 0
    fi
    recheck_verified_bundle
    preserve_existing "$zip"
    in_bundle_umask ditto -c -k --sequesterRsrc --keepParent "$APP" "$zip"
    "${PIPELINE[@]}" check-modes --zip "$zip"
    receipt --set zip="$zip" --set zip_sha256="$(sha256 "$zip")" --stage zip --status ok
    echo "zip: $zip"
    echo "zip sha256: $(sha256 "$zip")"
}

stage_notarize() {
    note 'notarize: notarytool submit --wait (uploads to Apple)'
    require_stage zip
    local zip zip_sha submit attempt submit_json log_json
    zip=$(receipt_get zip); [ -n "$zip" ] || zip=$(zip_path)
    zip_sha=$(receipt_get zip_sha256)
    # Every attempt keeps its own files and its own receipt entry.
    attempt=1
    while [ -e "$LOGS/notary-submit-$attempt.json" ]; do attempt=$((attempt + 1)); done
    submit_json="$LOGS/notary-submit-$attempt.json"
    log_json="$LOGS/notary-log-$attempt.json"
    submit=(xcrun notarytool submit "$zip" --keychain-profile "$NOTARY_PROFILE" --wait --timeout 2h --output-format json)
    if [ "$DRY_RUN" = 1 ]; then
        echo "zip: $zip"
        echo "zip sha256: ${zip_sha:-<not yet produced>}"
        echo "attempt: $attempt"
        echo "+ $(quote "${submit[@]}") > $(quote "$submit_json")"
        echo "+ xcrun notarytool log <submission-id> --keychain-profile $(quote "$NOTARY_PROFILE") $(quote "$log_json")"
        echo "owner approval: rerun with --stages notarize --run-dir $(quote "$RUN_DIR") --approve-zip-sha256 ${zip_sha:-<sha256>}"
        receipt --stage notarize --status dry-run --detail "zip_sha256=${zip_sha:-none}"
        return 0
    fi
    [ "$(stage_status notarize)" != ok ] || die "run already notarized (submission $(receipt_get submission_id)); staple it instead"
    refuse_capture_window
    recheck_source
    [ "$(receipt_get binaries_source)" = build-stage ] || die 'notarize refused: binaries were not built by the build stage of this run'
    [ "$(receipt_get source_dirty)" = False ] || die 'notarize refused: source tree was dirty at assembly'
    [ "$(receipt_get version_checks_default)" = True ] || die 'notarize refused: the version rule used a test ledger or installed-app override'
    [ -n "$APPROVED_ZIP_SHA" ] || die 'notarize requires --approve-zip-sha256 from the owner'
    [ "$(sha256 "$zip")" = "$zip_sha" ] || die 'ZIP changed since the zip stage'
    [ "$APPROVED_ZIP_SHA" = "$zip_sha" ] || die 'approved SHA-256 does not match the ZIP'
    bounded 7500 "${submit[@]}" > "$submit_json" || true
    local id status log_sha='' entry
    id=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("id",""))' "$submit_json" 2>/dev/null || true)
    status=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("status",""))' "$submit_json" 2>/dev/null || true)
    if [ -n "$id" ]; then
        bounded 300 xcrun notarytool log "$id" --keychain-profile "$NOTARY_PROFILE" "$log_json" || true
        if [ -f "$log_json" ]; then log_sha=$(sha256 "$log_json"); fi
    fi
    entry=$(python3 -I -c 'import json,sys
a = sys.argv
print(json.dumps({"attempt": int(a[1]), "id": a[2], "status": a[3], "zip_sha256": a[4],
                  "submit_json": a[5], "submit_sha256": a[6],
                  "log_json": a[7] if a[8] else "", "log_sha256": a[8]}, sort_keys=True))' \
        "$attempt" "$id" "$status" "$zip_sha" "$submit_json" "$(sha256 "$submit_json")" "$log_json" "$log_sha")
    receipt --set submission_id="$id" --set notary_status="$status" --append-json notary_submissions="$entry"
    [ "$status" = Accepted ] || die "notarization status: ${status:-unknown} (submission ${id:-none}, attempt $attempt)"
    receipt --stage notarize --status ok --detail "submission $id Accepted (attempt $attempt)"
}

stage_staple() {
    note 'staple: stapler staple + validate, stapled ZIP'
    require_stage notarize
    local stapled
    stapled="${RUN_DIR}/$(basename "$(zip_path)" .zip)-stapled.zip"
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ (umask 022; $(quote xcrun stapler staple -v "$APP"))"
        echo "+ $(quote xcrun stapler validate -v "$APP")"
        echo "+ (umask 022; $(quote ditto -c -k --sequesterRsrc --keepParent "$APP" "$stapled"))"
        echo "+ $(quote "${PIPELINE[@]}" check-modes --zip "$stapled")"
        receipt --stage staple --status dry-run
        return 0
    fi
    refuse_capture_window
    [ "$(receipt_get notary_status)" = Accepted ] || die 'staple requires an Accepted notarization'
    recheck_verified_bundle
    if [ -e "$stapled" ]; then mv "$stapled" "$stapled.superseded-$(utc)"; fi
    in_bundle_umask bounded 300 xcrun stapler staple -v "$APP"
    bounded 300 xcrun stapler validate -v "$APP"
    in_bundle_umask ditto -c -k --sequesterRsrc --keepParent "$APP" "$stapled"
    "${PIPELINE[@]}" check-modes --zip "$stapled"
    receipt --set stapled_zip="$stapled" --set stapled_zip_sha256="$(sha256 "$stapled")" --stage staple --status ok
    echo "stapled zip: $stapled"
    echo "stapled zip sha256: $(sha256 "$stapled")"
}

stage_assess() {
    note 'assess: Gatekeeper'
    require_stage staple
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $(quote spctl -a -vv -t exec "$APP")  # expect: accepted, source=Notarized Developer ID"
        receipt --stage assess --status dry-run
        return 0
    fi
    local out
    out=$(bounded 120 spctl -a -vv -t exec "$APP" 2>&1) || true
    printf '%s\n' "$out" | tee "$LOGS/spctl.log"
    receipt --set spctl_sha256="$(sha256 "$LOGS/spctl.log")"
    printf '%s\n' "$out" | grep -q '^source=Notarized Developer ID$' || die 'Gatekeeper did not report source=Notarized Developer ID'
    receipt --stage assess --status ok
}

note "run: ${RUN_ID:-none} commit ${COMMIT:0:12} dirty=$DIRTY dry_run=$DRY_RUN"
if selected assemble; then
    preflight_run
fi
for stage in $ALL_STAGES; do
    selected "$stage" || continue
    CURRENT_STAGE=$stage
    "stage_$stage"
    CURRENT_STAGE=''
done
if [ -f "$RECEIPT" ]; then echo "receipt: $RECEIPT"; fi
exit 0
