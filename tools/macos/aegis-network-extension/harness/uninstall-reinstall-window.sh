#!/bin/bash
# B-06 S21i: one bounded installed uninstall/reinstall cycle. Owner-attended
# since the audit fix: the identity changes (uninstall-app.sh's forget and
# the host import below) and, from v26, uninstall-app.sh's filter removal
# each show the system administrator prompt, which the owner answers;
# nothing here answers, skips or works around it.
#   preflight   refuses (exit 3, or 4 for the peer timing lock) while any
#               timing lock is held, an AEGIS tunnel is not Disconnected, a
#               utun holds the tunnel address or the default route is on a
#               utun, or the reinstall inputs are not usable: the stapled ZIP
#               and its approved SHA-256, its CFBundleVersion (the installed
#               app's, if any), the install receipt of that ZIP (current ok
#               staple and assess stages, same bundle_version), no stale
#               .AEGIS.app.incoming-<version>, the private identity source
#               and the relay IP. An installed app must answer host --ping
#               with its identity present below an admitted container, or
#               have an uninstall-app.sh resume marker of its version, or a
#               pending reinstall of this ZIP (below): otherwise
#               uninstall-app.sh could not verify the forget and would stop
#               with the profile removed. Nothing is uninstalled that could
#               not be put back
#   baseline    app version, extension state (systemextensionsctl list),
#               saved profile (host --list), identity (host --ping), the
#               leak-guard filter (host --filter-status) and the network
#               baseline (default routes, resolver, no tunnel). A filter
#               configured and enabled at the baseline (exit 0, 33 or 69) is
#               to be restored; <state>/uninstall-reinstall-window/filter.txt
#               records that before the uninstall removes it, so a re-run
#               after an interrupted cycle restores it too
#   uninstall   packaging/uninstall-app.sh for real (never --dry-run); the
#               app must be moved to <state>/uninstalled/ and not deleted,
#               the profile gone, the identity absence verified, the
#               extension deactivated (or pending a reboot: exit 7, reboot
#               and run this again), no utun or tunnel route left and the
#               network baseline intact
#   reinstall   packaging/install-app.sh --replace --activate with the same
#               stapled ZIP and its receipt, host --import of the identity
#               source (kept, never --remove-source) and host --save-profile
#               --replace-existing; intent_valid=true and identity_present
#               =true must follow. A filter to be restored is enabled again
#               with host --enable-filter (the owner clicks Allow) and
#               --filter-status must exit 0 (filter_restored); otherwise
#               filter_restored is an info row
# Every step is bounded; every row goes to $OUT/results.tsv. It never
# deletes anything (uninstall-app.sh moves the app aside, the identity
# source is kept), never uses sudo and never calls systemextensionsctl
# except `list`. A re-run is safe at any point: an app already absent is
# reported by uninstall-app.sh as already-absent and the cycle continues
# with the reinstall; a pending deactivation resumes from its markers. Once
# the uninstall checks pass, <state>/uninstall-reinstall-window/reinstall.txt
# records a pending reinstall of this ZIP (phase=completed after a pass): a
# re-run with the app of this ZIP installed but its identity not restored
# (an activation pending approval or a reboot, a failed import or profile)
# does not uninstall again; it resumes with install-app.sh
# --activate-installed (only while the provider is unreachable), the import
# and the profile.
# Exit codes: 0 pass, 1 a check failed, 2 usage, 3 refused, 4 Codex timing
# lock, 7 deactivation completes after a reboot, 8 activation pending
# approval or a reboot (approve or reboot, then run this again).
set -u
umask 077
APP=${APP:-/Applications/AEGIS.app}
OUT=${OUT:?set OUT to a new private directory}
ZIP=${ZIP:-}
ZIP_SHA256=${ZIP_SHA256:-}
IDENTITY_SRC=${IDENTITY_SRC:-}
HANDOFF=${HANDOFF:-$HOME/.aegis-local/handoff/macos-relay.json}
RELAY_IP=${RELAY_IP:-}
STATE_DIR=${STATE_DIR:-$HOME/Library/Application Support/aegis-packaging/install}
HARNESS_DIR=$(cd "$(dirname "$0")" && pwd)
UNINSTALL_SH=${UNINSTALL_SH:-$HARNESS_DIR/../packaging/uninstall-app.sh}
INSTALL_SH=${INSTALL_SH:-$HARNESS_DIR/../packaging/install-app.sh}
INSTALL_RECEIPT=${INSTALL_RECEIPT:-}
# uninstall-app.sh: deactivation 150 s plus five forget attempts of at most
# 150 s each and (v26) the filter removal of at most 180 s (prompts
# included); install-app.sh: four 120 s Apple checks plus activation 150 s.
# Outer bounds only.
UNINSTALL_BOUND_S=${UNINSTALL_BOUND_S:-1500}
INSTALL_BOUND_S=${INSTALL_BOUND_S:-900}
HOST_BOUND_S=45 TOOL_BOUND_S=30
# The host bounds --enable-filter at 120 s (the owner's Allow).
FILTER_BOUND_S=150
# The host import waits at most 120 s for the administrator prompt, then
# makes its bounded XPC exchange.
IMPORT_BOUND_S=150
PIPELINE=$HARNESS_DIR/../packaging/pipeline.py
# The provider service is unavailable (host_lifecycle EXIT_XPC_UNAVAILABLE).
EXIT_XPC_UNAVAILABLE=69
WINDOW_STATE="$STATE_DIR/uninstall-reinstall-window"
REINSTALL_MARKER="$WINDOW_STATE/reinstall.txt"
FILTER_MARKER="$WINDOW_STATE/filter.txt"
TEAM=TEAMID0000
PROVIDER_ID=dev.aegis.macos.PacketTunnel
LOCKS="$HOME/.aegis-local/locks"
LOCK="$LOCKS/timing-self"
TOKEN=''

mkdir -m 700 "$OUT" || exit 2
exec > >(tee "$OUT/window.log") 2>&1
now() { date -u +%Y%m%dT%H%M%SZ; }
say() { echo "$(now) $*"; }
bounded() { local secs=$1; shift; perl -e 'alarm shift; exec { $ARGV[0] } @ARGV; print STDERR "exec: $!\n"; exit 127' "$secs" "$@"; }
FAILED=0
result() {
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(now)" >> "$OUT/results.tsv"
    printf '%s\t%s\t%s\n' "$1" "$2" "$3"
    case "$2" in pass|info|skip) ;; *) FAILED=1 ;; esac
}
refuse() { result "refused_$1" refused "$2"; say "refused: $2"; exit "${3:-3}"; }
finish() {
    result outcome "$1" "$2"
    say "done: $1"
    exit "$3"
}
release_lock() {
    [ -n "$TOKEN" ] && grep -qx "token=$TOKEN" "$LOCK" 2>/dev/null && rm -f "$LOCK"
    return 0
}
trap release_lock EXIT
HOST="$APP/Contents/MacOS/aegis-ne-host"
# Each step's stdout/stderr stays in OUT as <step>.stdout / <step>.stderr.
RC=0
step() {
    local name=$1 secs=$2; shift 2
    bounded "$secs" "$@" > "$OUT/$name.stdout" 2> "$OUT/$name.stderr"
    RC=$?
}
# The first stderr line that is not the host's administrator-approval banner
# (written first by --import and the other identity verbs).
APPROVAL_BANNER='^administrator approval required for this (identity|leak-guard) change; '
first_err() { { grep -Ev "$APPROVAL_BANNER" "$OUT/$1.stderr" 2>/dev/null || true; } | head -n 1 | cut -c1-200; }
app_version() { plutil -extract CFBundleVersion raw -o - "$1/Contents/Info.plist" 2>/dev/null; }
# The provider's systemextensionsctl lines, as their bracketed states;
# `unreadable rc=<n>` unless the tool exited 0 with its `N extension(s)`
# header, so a failed or empty listing never reads as no extension.
sysext_states() {
    step "$1" "$TOOL_BOUND_S" systemextensionsctl list
    if [ "$RC" != 0 ] || ! grep -qE '^[0-9]+ extension\(s\)$' "$OUT/$1.stdout"; then
        echo "unreadable rc=$RC"
        return 0
    fi
    grep -F "$TEAM" "$OUT/$1.stdout" | grep -F "$PROVIDER_ID (" | sed -n 's/.*\(\[[^]]*\]\)[[:space:]]*$/\1/p' | paste -sd, -
}
# identity_present=<b> container_admitted=<b> from one --ping JSON line.
ping_identity() {
    python3 -I -B -c '
import json, sys
lines = [line for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
try:
    value = json.loads(lines[-1]) if lines else None
except ValueError:
    value = None
report = value.get("report") if isinstance(value, dict) and value.get("verb") == "ping" else None
if not isinstance(report, dict):
    print("malformed")
    raise SystemExit
opened = report.get("container_open")
print("identity_present=%s container_admitted=%s" % (
    "true" if report.get("identity_present") is True else "false",
    "true" if isinstance(opened, dict) and opened.get("admitted") is True else "false"))
' "$OUT/$1.stdout" 2>/dev/null || echo malformed
}
receipt_field() { python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$1" "$2" 2>/dev/null; }
install_receipt() { python3 -I -B "$PIPELINE" receipt --receipt "$INSTALL_RECEIPT" "$@" 2>/dev/null; }
# CFBundleVersion of AEGIS.app inside the stapled ZIP (read in memory).
zip_version() {
    python3 -I -B -c '
import plistlib, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    print(plistlib.loads(archive.read("AEGIS.app/Contents/Info.plist"))["CFBundleVersion"])
' "$1" 2>/dev/null
}
# One key=value line of a marker file ("" when absent).
marker_value() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1; }
# A regular marker file of this user.
marker_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -f %u "$1")" = "$(id -u)" ]; }
default_if() { route -n get "$@" default 2>/dev/null | awk '/interface:/{print $2}'; }
tunnel_addrs() { ifconfig 2>/dev/null | grep -cE 'inet 198\.19\.255\.1 |inet6 fd00:ae61::1 '; }
resolver0() { scutil --dns 2>/dev/null | awk '/resolver #1/{f=1} f&&/nameserver\[0\]/{print $3; exit}'; }
# Non-Disconnected AEGIS services in `scutil --nc list`.
live_services() { scutil --nc list 2>/dev/null | grep -F dev.aegis.macos | grep -vF '(Disconnected)' | grep -c .; }
# Every file under a directory as <size> <sha256> <path>; held in memory
# only, never written: the identity source is key material.
tree_manifest() { (cd "$1" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256 2>/dev/null; find . | sort) | shasum -a 256 | awk '{print $1}'; }

# ---------------------------------------------------------------- preflight
for lock in "$LOCKS"/timing-*; do
    [ -e "$lock" ] || continue
    case "$lock" in
        */timing-peer) refuse timing_lock "timing-peer lock held" 4 ;;
        *) refuse timing_lock "$(basename "$lock") lock held" ;;
    esac
done
case "$APP" in /*/AEGIS.app) ;; *) refuse inputs "APP must be an absolute path ending in /AEGIS.app" ;; esac
DEST=${APP%/AEGIS.app}
[ -n "$RELAY_IP" ] || RELAY_IP=$(python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1]))["relay"]; print(r.rsplit(":",1)[0].strip("[]"))' "$HANDOFF" 2>/dev/null)
python3 -I -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$RELAY_IP" 2>/dev/null \
    || refuse inputs "no numeric relay IP (RELAY_IP or the handoff relay field)"
case "$ZIP" in /*) ;; *) refuse inputs "ZIP must be an absolute stapled ZIP path" ;; esac
[ -f "$ZIP" ] && [ ! -L "$ZIP" ] || refuse inputs "stapled ZIP not found: $ZIP"
zip_actual=$(shasum -a 256 "$ZIP" | awk '{print $1}')
[ -n "$ZIP_SHA256" ] && [ "$zip_actual" = "$ZIP_SHA256" ] || refuse inputs "ZIP_SHA256 does not match the stapled ZIP ($zip_actual)"
case "$IDENTITY_SRC" in /*) ;; *) refuse inputs "IDENTITY_SRC must be an absolute private directory" ;; esac
[ -d "$IDENTITY_SRC" ] && [ ! -L "$IDENTITY_SRC" ] || refuse inputs "identity source is not a directory: $IDENTITY_SRC"
[ "$(stat -f %u "$IDENTITY_SRC")" = "$(id -u)" ] && [ "$(stat -f %Lp "$IDENTITY_SRC")" = 700 ] \
    || refuse inputs "identity source must be 0700 and owned by $(id -un)"
[ -f "$UNINSTALL_SH" ] && [ -f "$INSTALL_SH" ] && [ -f "$PIPELINE" ] || refuse inputs "packaging scripts missing"
[ "$(id -u)" != 0 ] || refuse inputs "do not run as root"
# What install-app.sh checks only after the uninstall, checked before it.
ZIP_VERSION=$(zip_version "$ZIP")
[ -n "$ZIP_VERSION" ] || refuse inputs "no AEGIS.app/Contents/Info.plist CFBundleVersion in the stapled ZIP"
case "$INSTALL_RECEIPT" in /*) ;; *) refuse inputs "INSTALL_RECEIPT must be the absolute run receipt of the stapled ZIP" ;; esac
[ -f "$INSTALL_RECEIPT" ] && [ ! -L "$INSTALL_RECEIPT" ] || refuse inputs "install receipt not found: $INSTALL_RECEIPT"
[ "$(install_receipt --get stapled_zip_sha256)" = "$zip_actual" ] \
    || refuse inputs "install receipt belongs to a different stapled ZIP (stapled_zip_sha256 differs)"
for st in staple assess; do
    [ "$(install_receipt --stage-status "$st")" = ok ] || refuse inputs "install receipt stage $st is not current ok"
done
[ "$(install_receipt --get bundle_version)" = "$ZIP_VERSION" ] \
    || refuse inputs "install receipt bundle_version differs from the ZIP's $ZIP_VERSION"
incoming="$DEST/.AEGIS.app.incoming-$ZIP_VERSION"
[ ! -e "$incoming" ] && [ ! -L "$incoming" ] || refuse inputs "stale $incoming exists; install-app.sh would refuse the reinstall"
live=$(live_services)
[ "$live" = 0 ] || refuse tunnel_live "$live AEGIS service(s) not Disconnected"
APP_PRESENT=false
[ -d "$APP" ] && [ ! -L "$APP" ] && APP_PRESENT=true
VERSION=''
if [ "$APP_PRESENT" = true ]; then
    VERSION=$(app_version "$APP")
    [ "$VERSION" = "$ZIP_VERSION" ] \
        || refuse inputs "installed AEGIS.app is ${VERSION:-unreadable}, the stapled ZIP is $ZIP_VERSION: this cycle reinstalls the same build"
    [ -x "$HOST" ] || refuse inputs "installed AEGIS.app has no executable host"
fi
# Every saved profile's service, by the id the host reports.
if [ "$APP_PRESENT" = true ] && [ -x "$HOST" ]; then
    step baseline-list "$HOST_BOUND_S" "$HOST" --list
    LIST_RC=$RC
    for sid in $(sed -n 's/^profile index=[0-9]* .*scutil_service_id=\([0-9A-F-]*\) .*/\1/p' "$OUT/baseline-list.stdout"); do
        st=$(bounded 10 scutil --nc status "$sid" 2>/dev/null | head -1)
        [ "$st" = Disconnected ] || refuse tunnel_live "service $sid is ${st:-unreadable}, not Disconnected"
    done
fi
[ "$(tunnel_addrs)" = 0 ] || refuse tunnel_live "an interface holds the tunnel address"
PHYS=$(default_if)
case "$PHYS" in ''|utun*) refuse tunnel_live "default route on '${PHYS:-none}', not a physical interface" ;; esac
# MODE cycle: uninstall, then reinstall. MODE resume: the app of this ZIP is
# installed after an earlier uninstall of this window, its identity not
# restored; only the reinstall steps run.
MODE=cycle PING_RC='' PING=''
if [ "$APP_PRESENT" = true ]; then
    step baseline-ping "$HOST_BOUND_S" "$HOST" --ping
    PING_RC=$RC PING=$(ping_identity baseline-ping)
    reachable=false
    [ "$PING_RC" = 0 ] && case "$PING" in *" container_admitted=true") true ;; *) false ;; esac && reachable=true
    resumable=false
    [ "$reachable" = true ] || [ "$PING_RC" = "$EXIT_XPC_UNAVAILABLE" ] && resumable=true
    uninstall_marker=''
    for m in "$STATE_DIR/uninstall/deactivated.txt" "$STATE_DIR/uninstall/identity-absent.txt"; do
        marker_file "$m" && [ "$(marker_value "$m" bundle_version)" = "$VERSION" ] && { uninstall_marker=$m; break; }
    done
    if [ "$PING_RC" = 0 ] && [ "$PING" = "identity_present=true container_admitted=true" ]; then
        MODE=cycle
    elif [ "$resumable" = true ] && [ -n "$uninstall_marker" ]; then
        # uninstall-app.sh resumes from its own marker (it re-checks the
        # CDHashes and honours the marker only while the provider is gone).
        MODE=cycle
    elif [ "$resumable" = true ] && marker_file "$REINSTALL_MARKER" \
        && [ "$(marker_value "$REINSTALL_MARKER" phase)" = reinstall-pending ] \
        && [ "$(marker_value "$REINSTALL_MARKER" zip_sha256)" = "$zip_actual" ] \
        && [ "$(marker_value "$REINSTALL_MARKER" bundle_version)" = "$VERSION" ]; then
        MODE=resume
    else
        refuse provider "installed AEGIS.app $VERSION: host --ping exit $PING_RC ($PING), no uninstall-app.sh resume marker of this version and no pending reinstall of this ZIP; uninstall-app.sh could not verify the forget and would stop with the profile removed. Activate it first (install-app.sh --activate-installed --receipt ...), then run this again"
    fi
fi
TOKEN=$(uuidgen)
( set -o noclobber; printf 'start=%s purpose=b06-uninstall-reinstall-window\ntoken=%s\n' "$(now)" "$TOKEN" > "$LOCK" ) \
    || { TOKEN=''; refuse timing_lock "lock busy"; }
result preflight pass "zip_sha256=$zip_actual version=$ZIP_VERSION mode=$MODE relay=$RELAY_IP physical=$PHYS"

# ---------------------------------------------------------------- baseline
PHYS6=$(default_if -inet6)
RES0=$(resolver0)
SID=''
result baseline_app info "present=$APP_PRESENT version=${VERSION:-none}"
result baseline_extension info "$(sysext_states baseline-sysext)"
if [ "$APP_PRESENT" = true ] && [ -x "$HOST" ]; then
    RC=$LIST_RC
    SID=$(sed -n 's/^profile index=0 .*scutil_service_id=\([0-9A-F-]*\) .*/\1/p' "$OUT/baseline-list.stdout")
    result baseline_profile info "rc=$RC profiles=$(grep -c '^profile ' "$OUT/baseline-list.stdout") sid=${SID:-none} $(grep -o 'intent_valid=[a-z]*' "$OUT/baseline-list.stdout" | head -1)"
    result baseline_identity info "rc=$PING_RC $PING"
else
    result baseline_profile info "app absent: not listed"
    result baseline_identity info "app absent: not pinged"
fi
# The leak-guard filter the owner chose: configured and enabled (exit 0,
# or 33 not attached, or 69 provider unavailable) is restored after the
# reinstall; so is one an earlier run of this cycle recorded before its
# uninstall removed it.
FILTER_RESTORE=false FILTER_SOURCE=none
if [ "$APP_PRESENT" = true ] && [ -x "$HOST" ]; then
    step baseline-filter "$HOST_BOUND_S" "$HOST" --filter-status
    FILTER_BASE_RC=$RC
    FILTER_BASE_LINE=$(grep '^filter_result=' "$OUT/baseline-filter.stdout" | tail -n 1 | cut -c1-200)
    case "$FILTER_BASE_RC" in 0|33|69) FILTER_RESTORE=true FILTER_SOURCE=baseline ;; esac
else
    FILTER_BASE_RC=none FILTER_BASE_LINE='app absent: not queried'
fi
if [ "$FILTER_RESTORE" = false ] && marker_file "$FILTER_MARKER" \
    && [ "$(marker_value "$FILTER_MARKER" phase)" = restore-pending ] \
    && [ "$(marker_value "$FILTER_MARKER" zip_sha256)" = "$zip_actual" ] \
    && [ "$(marker_value "$FILTER_MARKER" bundle_version)" = "$ZIP_VERSION" ]; then
    FILTER_RESTORE=true FILTER_SOURCE=earlier-run
fi
result baseline_filter info "rc=$FILTER_BASE_RC restore=$FILTER_RESTORE source=$FILTER_SOURCE $FILTER_BASE_LINE"
if [ "$FILTER_SOURCE" = baseline ]; then
    mkdir -p -m 700 "$WINDOW_STATE" \
        && printf 'phase=restore-pending\nzip_sha256=%s\nbundle_version=%s\nbaseline=%s\nutc=%s\n' \
            "$zip_actual" "$ZIP_VERSION" "$FILTER_BASE_LINE" "$(now)" > "$FILTER_MARKER" \
        || finish fail "cannot record the leak-guard filter to restore in $FILTER_MARKER; nothing was uninstalled" 1
fi
result baseline_network info "default=$PHYS default_v6=${PHYS6:-none} resolver0=${RES0:-none}"
src_manifest=$(tree_manifest "$IDENTITY_SRC")
src_files=$(find "$IDENTITY_SRC" -type f | grep -c .)

# ---------------------------------------------------------------- uninstall
ARTIFACTS="$OUT/packaging-artifacts"
BACKUP=''
if [ "$MODE" = resume ]; then
    result uninstall info "resumed: the pending reinstall of this ZIP follows the uninstall of $(marker_value "$REINSTALL_MARKER" uninstall_receipt)"
else
    say "uninstall: $UNINSTALL_SH"
    step uninstall "$UNINSTALL_BOUND_S" /bin/bash "$UNINSTALL_SH" --dest "$DEST" --state-dir "$STATE_DIR" --artifacts-dir "$ARTIFACTS"
    UNINSTALL_RC=$RC
    RECEIPT=$(ls "$ARTIFACTS"/uninstall/receipts/*.json 2>/dev/null | tail -1)
    U_RESULT=$( [ -n "$RECEIPT" ] && receipt_field "$RECEIPT" uninstall_result )
    result uninstall "$([ "$UNINSTALL_RC" = 0 ] && echo pass || echo fail)" "rc=$UNINSTALL_RC result=${U_RESULT:-none} receipt=${RECEIPT:+${RECEIPT#"$OUT"/}} $(first_err uninstall)"
    if [ "$U_RESULT" = pending-reboot ]; then
        result extension_deactivated pending-reboot "$(receipt_field "$RECEIPT" deactivation_result)"
        finish pending_reboot "deactivation completes after a reboot; reboot, then run this again with a new OUT" 7
    fi
    [ "$UNINSTALL_RC" = 0 ] || finish fail "uninstall-app.sh failed; nothing was reinstalled" 1

    # The app moved aside, never deleted.
    BACKUP=$(receipt_field "$RECEIPT" uninstalled_app_path)
    if [ "$U_RESULT" = already-absent ]; then
        BACKUP=$(receipt_field "$RECEIPT" latest_uninstalled_copy)
    fi
    moved=fail
    case "$BACKUP" in
        "$STATE_DIR/uninstalled/"*)
            # v26: a v25 copy keeps aegis-ne-host.removed instead of its host.
            [ ! -e "$APP" ] && [ -d "$BACKUP" ] && [ ! -L "$BACKUP" ] \
                && { [ -f "$BACKUP/Contents/MacOS/aegis-ne-host" ] || [ -f "$BACKUP/Contents/MacOS/aegis-ne-host.removed" ]; } \
                && { [ -z "$VERSION" ] || [ "$(app_version "$BACKUP")" = "$VERSION" ]; } && moved=pass ;;
    esac
    result app_moved "$moved" "result=$U_RESULT backup=${BACKUP:-none} app_present=$([ -e "$APP" ] && echo true || echo false)"

    if [ "$U_RESULT" = already-absent ]; then
        result profile_gone info "already absent: verified by an earlier uninstall receipt"
        result identity_absent info "already absent: verified by an earlier uninstall receipt"
    else
        rp=$(receipt_field "$RECEIPT" remove_profile_line)
        pg=fail
        printf '%s\n' "$rp" | grep -qE ' profiles_remaining=0$' && { [ -z "$SID" ] || ! scutil --nc list 2>/dev/null | grep -qF "$SID"; } && pg=pass
        result profile_gone "$pg" "${rp:-no remove_profile_line} sid=${SID:-none}"
        ia=$(receipt_field "$RECEIPT" identity_absence)
        pi=$(receipt_field "$RECEIPT" ping_identity)
        idv=fail
        case "$ia" in
            verified) [ "$pi" = "identity_present=false container_admitted=true" ] && idv=pass ;;
            verified-earlier) idv=pass ;;
        esac
        result identity_absent "$idv" "identity_absence=${ia:-none} ${pi:-}"
    fi
    states=$(sysext_states after-uninstall-sysext)
    # Any activated state, or a listing that could not be read, is not deactivated.
    de=fail
    case ",$states," in ,unreadable*|*"[activated"*) ;; *) de=pass ;; esac
    result extension_deactivated "$de" "outcome=$(receipt_field "$RECEIPT" deactivation_outcome) states=${states:-none}"
    nt=pass
    [ "$(tunnel_addrs)" = 0 ] || nt=fail
    d4=$(default_if) d6=$(default_if -inet6)
    case "$d4 $d6" in utun*|*" utun"*) nt=fail ;; esac
    result no_tunnel_left "$nt" "default=${d4:-none} default_v6=${d6:-none} tunnel_addrs=$(tunnel_addrs)"
    r0=$(resolver0)
    nb=fail
    [ "$d4" = "$PHYS" ] && [ "$d6" = "$PHYS6" ] && [ "$r0" = "$RES0" ] && [ "$r0" != 198.19.255.2 ] && nb=pass
    result network_baseline "$nb" "default=${d4:-none}/${PHYS} default_v6=${d6:-none}/${PHYS6:-none} resolver0=${r0:-none}/${RES0:-none}"
    [ "$FAILED" = 0 ] || finish fail "uninstall checks failed; nothing was reinstalled" 1
    # A re-run from here on resumes the reinstall instead of uninstalling again.
    mkdir -p -m 700 "$WINDOW_STATE" \
        && printf 'phase=reinstall-pending\nzip_sha256=%s\nbundle_version=%s\nuninstall_receipt=%s\nutc=%s\n' \
            "$zip_actual" "$ZIP_VERSION" "$RECEIPT" "$(now)" > "$REINSTALL_MARKER" \
        || finish fail "cannot record the pending reinstall in $REINSTALL_MARKER; nothing was reinstalled" 1
fi

# ---------------------------------------------------------------- reinstall
ACT_RC=0
if [ "$MODE" = cycle ]; then
    install_args=(--stapled-zip "$ZIP" --approve-sha256 "$ZIP_SHA256" --dest "$DEST" --state-dir "$STATE_DIR" --replace --activate --receipt "$INSTALL_RECEIPT")
elif [ "$PING_RC" = "$EXIT_XPC_UNAVAILABLE" ]; then
    # Only the activation of the app this receipt installed, re-checked by
    # install-app.sh (path, version, CDHashes, signature, staple, Gatekeeper).
    install_args=(--activate-installed --receipt "$INSTALL_RECEIPT" --dest "$DEST" --state-dir "$STATE_DIR")
else
    install_args=()
fi
if [ "${#install_args[@]}" = 0 ]; then
    result install info "resumed: AEGIS.app $VERSION of this ZIP is installed and its provider answers; activation not repeated"
else
    say "reinstall: $INSTALL_SH ${install_args[0]}"
    step install "$INSTALL_BOUND_S" /bin/bash "$INSTALL_SH" "${install_args[@]}"
    ACT_RC=$RC
    act=$(grep '^activation_result=' "$OUT/install.stdout" | tail -1)
    pending=false
    case "$act" in
        activation_result=will_complete_after_reboot|"activation_result=will_complete_after_reboot "*) pending=true ;;
        activation_result=timeout_awaiting_approval|"activation_result=timeout_awaiting_approval "*) pending=true ;;
    esac
    [ "$ACT_RC" != 0 ] && [ "$pending" = true ] && v=pending || v=$([ "$ACT_RC" = 0 ] && echo pass || echo fail)
    result install "$v" "rc=$ACT_RC mode=${install_args[0]} $act $(first_err install)"
    [ "$v" = pending ] && finish activation_pending "the activation completes after an approval in System Settings or a reboot; then run this again with a new OUT: it resumes with install-app.sh --activate-installed, the import and the profile" 8
    [ "$ACT_RC" = 0 ] || finish fail "install-app.sh failed" 1
fi
NEW_VERSION=$(app_version "$APP")
before=${VERSION:-$( [ -n "$BACKUP" ] && app_version "$BACKUP" )}
result reinstalled_version "$([ "$NEW_VERSION" = "$ZIP_VERSION" ] && { [ -z "$before" ] || [ "$before" = "$ZIP_VERSION" ]; } && echo pass || echo fail)" \
    "installed=${NEW_VERSION:-none} zip=$ZIP_VERSION before=${before:-none}"
states=$(sysext_states after-install-sysext)
ea=fail
case ",$states," in *",[activated enabled],"*) ea=pass ;; esac
result extension_activated "$ea" "states=${states:-none}"

echo "identity import: type an administrator password in the system prompt (v30: password only, no Touch ID) to put the AEGIS identity back"
step import "$IMPORT_BOUND_S" "$HOST" --import "$IDENTITY_SRC"
im=fail
[ "$RC" = 0 ] && grep -qE '^import_result=committed manifest_match=true .* source=kept$' "$OUT/import.stdout" && im=pass
result identity_import "$im" "rc=$RC $(tail -1 "$OUT/import.stdout" 2>/dev/null) $(first_err import)"
kept=fail
[ -d "$IDENTITY_SRC" ] && [ "$(tree_manifest "$IDENTITY_SRC")" = "$src_manifest" ] && kept=pass
result identity_source_kept "$kept" "files=$src_files unchanged=$([ "$kept" = pass ] && echo true || echo false)"

step save-profile "$HOST_BOUND_S" "$HOST" --save-profile "$PROVIDER_ID" "$RELAY_IP" --replace-existing
sp=fail
[ "$RC" = 0 ] && grep -qE '^owner_generation=[^ ]+ saved=true ' "$OUT/save-profile.stdout" && sp=pass
result profile_saved "$sp" "rc=$RC $(tail -1 "$OUT/save-profile.stdout" 2>/dev/null | cut -c1-200) $(first_err save-profile)"

step final-list "$HOST_BOUND_S" "$HOST" --list
lines=$(grep -c '^profile ' "$OUT/final-list.stdout")
iv=fail
[ "$RC" = 0 ] && [ "$lines" = 1 ] && grep -q '^profile index=0 .* intent_valid=true ' "$OUT/final-list.stdout" && iv=pass
result intent_valid "$iv" "rc=$RC profiles=$lines $(grep -o 'intent_valid=[a-z]*' "$OUT/final-list.stdout" | head -1)"
step final-ping "$HOST_BOUND_S" "$HOST" --ping
pi=$(ping_identity final-ping)
result identity_present "$([ "$RC" = 0 ] && [ "$pi" = "identity_present=true container_admitted=true" ] && echo pass || echo fail)" "rc=$RC $pi"
# The leak guard the baseline had: enabled again (the owner clicks Allow),
# then configured, enabled and attached.
if [ "$FILTER_RESTORE" = true ]; then
    echo "leak-guard filter: click Allow if macOS asks to allow AEGIS to filter network content"
    step enable-filter "$FILTER_BOUND_S" "$HOST" --enable-filter
    result filter_enable "$([ "$RC" = 0 ] && echo pass || echo fail)" "rc=$RC $(grep '^filter_result=' "$OUT/enable-filter.stdout" | tail -n 1 | cut -c1-200) $(first_err enable-filter)"
    # v30 installed run: the filter attaches a few seconds after the
    # enable (exit 33 not_attached right after it), so only that answer is
    # read again, every 2 s up to FILTER_ATTACH_WAIT_S; the row still needs
    # configured, enabled and attached (exit 0).
    waited=0
    while :; do
        step final-filter "$HOST_BOUND_S" "$HOST" --filter-status
        [ "$RC" = 33 ] && [ "$waited" -lt "${FILTER_ATTACH_WAIT_S:-30}" ] || break
        sleep 2; waited=$((waited + 2))
    done
    result filter_restored "$([ "$RC" = 0 ] && echo pass || echo fail)" "rc=$RC source=$FILTER_SOURCE $(grep '^filter_result=' "$OUT/final-filter.stdout" | tail -n 1 | cut -c1-200) waited=${waited}s"
else
    result filter_restored info "not configured and enabled at the baseline (rc=$FILTER_BASE_RC): not enabled"
fi
d4=$(default_if) d6=$(default_if -inet6) r0=$(resolver0)
result network_after_reinstall "$([ "$d4" = "$PHYS" ] && [ "$d6" = "$PHYS6" ] && [ "$r0" = "$RES0" ] && [ "$(tunnel_addrs)" = 0 ] && echo pass || echo fail)" \
    "default=${d4:-none} default_v6=${d6:-none} resolver0=${r0:-none} tunnel_addrs=$(tunnel_addrs)"
if [ "$FAILED" = 0 ]; then
    printf 'phase=completed\nzip_sha256=%s\nbundle_version=%s\nout=%s\nutc=%s\n' "$zip_actual" "$ZIP_VERSION" "$OUT" "$(now)" > "$REINSTALL_MARKER" \
        || result reinstall_marker fail "cannot mark $REINSTALL_MARKER completed"
fi
if [ "$FAILED" = 0 ] && [ "$FILTER_RESTORE" = true ]; then
    printf 'phase=restored\nzip_sha256=%s\nbundle_version=%s\nout=%s\nutc=%s\n' "$zip_actual" "$ZIP_VERSION" "$OUT" "$(now)" > "$FILTER_MARKER" \
        || result filter_marker fail "cannot mark $FILTER_MARKER restored"
fi
restored='identity and profile restored'
[ "$FILTER_RESTORE" = false ] || restored='identity, profile and leak-guard filter restored'
if [ "$FAILED" = 0 ]; then finish pass "$([ "$MODE" = resume ] && echo "resumed: reinstalled" || echo "uninstalled, reinstalled"), $restored" 0; fi
finish fail "a reinstall check failed" 1
