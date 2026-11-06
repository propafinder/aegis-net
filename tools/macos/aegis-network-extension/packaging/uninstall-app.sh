#!/bin/bash
# B-06 S21: clean stop and uninstall of the installed AEGIS.app. Owner-only:
# run it yourself. In order, each step bounded and each refusal stopping the
# run before the next step:
#   verify                 the installed app is the notarized product bundle
#                          and its host parses --deactivate (a parse-only probe)
#   identity-gate          v30: host --identity-gate (read-only, no prompt): the
#                          active provider would admit the forget below, or
#                          nothing is stopped, removed or forgotten (a v29 run
#                          stopped at the forget after the profile and the
#                          filter were gone). A host before v26 has no gate to
#                          pass; a v26 to v29 host is refused while its
#                          provider answers (its forget can never be approved)
#   emergency-stop         host --emergency-stop (every profile of this provider)
#   remove-profile         host --remove-profile (none may remain)
#   remove-filter          host --remove-filter (S20b: the leak-guard packet
#                          filter configuration names this extension; a host
#                          before CFBundleVersion 25 that answers the probe
#                          with unknown_command is recorded as
#                          filter_removal=unsupported_by_host); from v26 an
#                          administrator approves it at the system prompt
#   verify-filter-absent   host --filter-status: not_configured (exit 30)
#   forget-identity        host --forget-identity (key material removed); an
#                          administrator types a password at the system prompt
#                          (v30: password-only, no Touch ID)
#   verify-identity-absent host --ping: identity absent below an admitted container
#   deactivate             host --deactivate (bounded 120 s, distinct exit codes)
#   move-app               AEGIS.app moves to <state>/uninstalled/ (never deleted;
#                          v26: a v25 copy, whose host has the filter verbs
#                          without the administrator prompt, and (v30 review)
#                          a v26 to v29 copy, whose prompt offers Touch ID,
#                          lose their host executable there, pipeline.py
#                          disarm-weak-host)
#   report-container       the user-side App Group container is reported, kept
# Owner-attended: the filter removal (v26 and later) and each forget attempt
# show the system administrator prompt
# (the host asks Authorization Services; this script never answers, skips
# or works around it). It never deletes the app or the container, never
# calls systemextensionsctl, never uses sudo and never changes trust
# settings. A second run after a
# completed uninstall finds no app and changes nothing. One receipt JSON per
# run under <artifacts>/uninstall/receipts (gitignored packaging/artifacts by
# default); host output goes to <artifacts>/uninstall/runs/<run-id>/.
set -euo pipefail
umask 077

APP_ID=dev.aegis.macos
PROVIDER_ID=dev.aegis.macos.PacketTunnel
TEAM=TEAMID0000
GROUP="group.$TEAM.$APP_ID"
DEST=/Applications
STATE="$HOME/Library/Application Support/aegis-packaging/install"
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
PIPELINE="$HERE/pipeline.py"
ARTIFACTS=${AEGIS_PACKAGING_ARTIFACTS:-$HERE/artifacts}
DRY_RUN=0 IDENTITY_UNVERIFIED=0
# The host bounds profile verbs at 30 s, XPC verbs at 10 s and deactivation
# at 120 s; these outer watchdogs only catch a broken host bound.
PROFILE_WATCHDOG=45 XPC_WATCHDOG=20 DEACTIVATION_WATCHDOG=150 TOOL_WATCHDOG=120
# The forget first waits (at most 120 s) for the administrator prompt, then
# makes its 10 s XPC exchange.
IDENTITY_WATCHDOG=150
# v26: --remove-filter first waits (at most 120 s) for the administrator
# prompt, then makes its 30 s NEFilterManager operation.
FILTER_REMOVE_WATCHDOG=180
# A forget is refused while the provider session is still live; the stop
# that precedes it is a request, not an observed disconnect.
FORGET_ATTEMPTS=5 FORGET_RETRY_SECS=2
# Host exit when its provider service is unavailable (host_lifecycle).
EXIT_XPC_UNAVAILABLE=69
# Host exit when no administrator approved the change; nothing was sent or
# changed (host_lifecycle). Its refusal code (first stderr line after the
# approval banner) tells whether a prompt was shown: only a cancelled,
# denied or unanswered prompt is fixed by running this script again
# (authorization_advice).
EXIT_AUTHORIZATION_REFUSED=67
# Not this provider's id: a host with --deactivate refuses it while parsing
# (provider_id_mismatch, exit 2) and submits nothing; an older host answers
# unknown_command. host_lifecycle's parser test binds this value.
CAPABILITY_PROBE=capability-probe
# S20b: every host above this CFBundleVersion has the filter verbs; the same
# probe operand makes them answer filter_operand_refused (exit 2).
FILTER_MIN_PRIOR=24
# v30: hosts from this CFBundleVersion answer --identity-gate; from
# AUDIT_GATE_MIN (v26) to below it a host's forget can never be approved
# (its provider's sandbox refuses the check); below AUDIT_GATE_MIN the forget
# has no administrator gate at all.
IDENTITY_GATE_MIN=30 AUDIT_GATE_MIN=26
IDENTITY_RIGHT=dev.aegis.macos.identity-change FILTER_RIGHT=dev.aegis.macos.leak-guard-change
PROOF_RIGHT=system.services.systemconfiguration.network

usage() {
    cat >&2 <<'EOF'
usage: uninstall-app.sh [--dest DIR] [--state-dir DIR] [--artifacts-dir DIR]
                        [--identity-unverified] [--dry-run]
  --dest DIR             directory holding AEGIS.app (default /Applications)
  --state-dir DIR        packaging state; the app moves to DIR/uninstalled/
                         (default ~/Library/Application Support/aegis-packaging/install)
  --artifacts-dir DIR    receipts and host logs (default $AEGIS_PACKAGING_ARTIFACTS
                         or packaging/artifacts, gitignored)
  --identity-unverified  only when the provider is unavailable (its extension
                         was never activated or is already inactive) and no
                         earlier run of this app verified the forget: request
                         deactivation and move the app anyway; the receipt
                         records identity_absence=unverified. A reachable
                         provider still runs the forget and its verification.
  --dry-run              print the exact commands only; runs and writes nothing
EOF
    exit 2
}
die() { echo "uninstall-app: $*" >&2; exit 1; }
quote() { local out='' arg; for arg in "$@"; do out="$out $(printf '%q' "$arg")"; done; printf '%s\n' "${out# }"; }
# A failed exec exits 127; perl's die would exit with errno. The block form
# never goes through a shell.
bounded() { local secs=$1; shift; perl -e 'alarm shift; exec { $ARGV[0] } @ARGV; print STDERR "exec: $!\n"; exit 127' "$secs" "$@"; }
utc() { date -u +%Y%m%dT%H%M%SZ; }
# A timestamped path that does not exist yet (PREFIX-UTC[.N]SUFFIX).
fresh() {
    local base="$1-$(utc)" suffix=${2:-} path n=1
    path="$base$suffix"
    while [ -e "$path" ] || [ -L "$path" ]; do path="$base.$n$suffix"; n=$((n + 1)); done
    printf '%s\n' "$path"
}
pipeline() { python3 -I -B "$PIPELINE" "$@"; }
run() { if [ "$DRY_RUN" = 1 ]; then echo "+ $(quote "$@")"; else "$@"; fi; }
record() { if [ "$DRY_RUN" = 0 ]; then pipeline receipt --receipt "$RECEIPT" "$@"; fi; }
stage() { local name=$1 status=$2 detail=$3; shift 3; record "$@" --stage "$name" --status "$status" --detail "$detail"; }
fail() {
    local name=$1 detail=$2; shift 2
    stage "$name" failed "$detail" --set uninstall_result="failed-at-$name" "$@"
    die "$name: $detail${RUN_DIR:+ (receipt $RECEIPT, logs $RUN_DIR)}"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dest) DEST=${2:-}; shift 2 ;;
        --state-dir) STATE=${2:-}; shift 2 ;;
        --artifacts-dir) ARTIFACTS=${2:-}; shift 2 ;;
        --identity-unverified) IDENTITY_UNVERIFIED=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done
case "$DEST" in /*) ;; *) die 'absolute --dest required' ;; esac
case "$STATE" in /*) ;; *) die 'absolute --state-dir required' ;; esac
case "$ARTIFACTS" in /*) ;; *) die 'absolute --artifacts-dir required' ;; esac
[ "$(id -u)" != 0 ] || die 'do not run as root'

target="$DEST/AEGIS.app"
HOST="$target/Contents/MacOS/aegis-ne-host"
EXT="$target/Contents/Library/SystemExtensions/$PROVIDER_ID.systemextension"
CONTAINER="$HOME/Library/Group Containers/$GROUP"
UNINSTALLED="$STATE/uninstalled"
# Resume markers, each bound to both CDHashes of the app and to the host's
# identity import journal (every host --import appends to it before sending,
# so a marker written before an import that may have put key material back
# never matches), and honoured only while its provider is unreachable (a
# probe --ping exits 69); a reachable provider retires them (moved aside,
# never deleted) and runs every step:
#   identity-absent.txt  verify-identity-absent passed; written before the
#                        deactivation request, so a rerun after Apple finished
#                        it (approval, timeout, watchdog) does not need the
#                        provider for the forget
#   deactivated.txt      a completed (or after-reboot) deactivation followed
ABSENT_MARKER="$STATE/uninstall/identity-absent.txt"
MARKER="$STATE/uninstall/deactivated.txt"
IMPORT_JOURNAL="$HOME/Library/Application Support/dev.aegis.macos/identity-import-journal"
LOCK="$STATE/uninstall/.lock"

base="uninstall-$(utc)" RUN_ID='' n=0
RUN_ID=$base
while [ -e "$ARTIFACTS/uninstall/receipts/$RUN_ID.json" ] || [ -e "$ARTIFACTS/uninstall/runs/$RUN_ID" ]; do
    n=$((n + 1)); RUN_ID="$base.$n"
done
RECEIPT="$ARTIFACTS/uninstall/receipts/$RUN_ID.json"
RUN_DIR="$ARTIFACTS/uninstall/runs/$RUN_ID"
if [ "$DRY_RUN" = 1 ]; then
    echo "dry run: nothing is executed or written; receipt would be $RECEIPT"
    RUN_DIR=''
else
    mkdir -p "$STATE/uninstall"
    mkdir "$LOCK" 2>/dev/null || die "another uninstall holds $LOCK (remove it only if no uninstall is running)"
    trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT
    mkdir -p "$ARTIFACTS/uninstall/receipts" "$RUN_DIR"
    pipeline receipt --receipt "$RECEIPT" --create --set kind=uninstall --set run_id="$RUN_ID" \
        --set app_path="$target" --set state_dir="$STATE" --set run_dir="$RUN_DIR" \
        --set app_group_container_path="$CONTAINER" --set-json identity_unverified_allowed="$(
            [ "$IDENTITY_UNVERIFIED" = 1 ] && echo true || echo false)"
fi

report_container() {
    local present=false
    if [ -e "$CONTAINER" ] || [ -L "$CONTAINER" ]; then present=true; fi
    echo "app group container left in place (the owner decides whether to remove it): $CONTAINER (present=$present)"
    stage report-container ok "left in place (present=$present)" \
        --set app_group_container_path="$CONTAINER" --set-json app_group_container_present="$present"
}

plist() { bounded 30 /usr/libexec/PlistBuddy -c "Print :$2" "$1/Contents/Info.plist" 2>/dev/null || true; }
cdhash() {
    local out
    out=$(bounded "$TOOL_WATCHDOG" codesign -d --verbose=4 "$1" 2>&1 | sed -n 's/^CDHash=//p' | head -n 1) || true
    case "$out" in ''|*[!0-9a-f]*) return 1 ;; esac
    printf '%s\n' "$out"
}

# One bounded host verb; its stdout and stderr are kept in the run directory
# and echoed unless QUIET=1.
OUT='' ERR='' RC=0 QUIET=0
host() {
    local name=$1 secs=$2; shift 2
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $(quote bounded "$secs" "$HOST" "$@")  # step $name"
        RC=0
        return 0
    fi
    OUT="$RUN_DIR/$name.stdout" ERR="$RUN_DIR/$name.stderr"
    set +e
    bounded "$secs" "$HOST" "$@" > "$OUT" 2> "$ERR"
    RC=$?
    set -e
    if [ "$QUIET" = 0 ]; then
        cat "$OUT"
        cat "$ERR" >&2
    fi
}
# The first stderr line that is not the host's administrator-approval banner
# (written first on every identity verb and, from v26, on --remove-filter),
# so a refusal or XPC code is reported, never the banner in its place.
APPROVAL_BANNER='^administrator approval required for this (identity|leak-guard) change; '
first_err() { { grep -Ev "$APPROVAL_BANNER" "$ERR" 2>/dev/null || true; } | head -n 1 | cut -c1-200 || true; }
# What to do after a host exit 67, by its refusal code. A right that cannot
# be registered or admitted, or an unavailable Authorization Services, shows
# no prompt, so running this script again cannot help until an
# administrator has acted (troubleshooting.md, exit 67).
authorization_advice() {
    local code=$1 right=$IDENTITY_RIGHT
    case "$code" in filter_*) right=$FILTER_RIGHT ;; esac
    case "$code" in
        *_authorization_cancelled|*_authorization_denied|*_authorization_timeout)
            echo 'Run this script again and approve the prompt' ;;
        identity_authorization_proof_rule_unexpected)
            echo "No prompt was shown: Apple's right $PROOF_RIGHT does not have the rule the AEGIS identity check rests on, and running this script again will not help. Compare it with docs/platforms/macos/troubleshooting.md (security authorizationdb read $PROOF_RIGHT); an administrator restores Apple's rule" ;;
        identity_authorization_unprovable)
            echo "The prompt was approved but the approval could not be proved for $PROOF_RIGHT (expired or refused); run this script again and type the password promptly; if it repeats, see docs/platforms/macos/troubleshooting.md (exit 67)" ;;
        *_authorization_right_inadmissible)
            echo "No prompt was shown: the authorization right $right has a rule weaker than administrator authentication, and running this script again will not help. An administrator removes it (sudo security authorizationdb remove $right); the host then registers its own rule on the next run" ;;
        *_authorization_right_unregistered|*_authorization_unavailable)
            echo "No prompt was shown: the authorization right $right could not be registered or Authorization Services was unavailable, and running this script again will not help. Check it with: security authorizationdb read $right; an administrator registers the rule or lifts the policy that blocks it" ;;
        *) echo "Unrecognized refusal; see docs/platforms/macos/troubleshooting.md (exit 67) before running this script again" ;;
    esac
}

# What to do after a closed identity gate (v30), by the host's code.
gate_advice() {
    case "$1" in
        'provider_refused unknown_verb'*)
            echo "The active provider predates v30 (the installed app is $version): activate this build's extension first (install-app.sh --activate-installed with its install receipt), then run this script again" ;;
        'identity_gate_closed peer_'*)
            echo 'Run this script as the user logged in at the console, an administrator outside Setup Assistant' ;;
        'identity_gate_closed identity_rule_inadmissible'*)
            echo "The authorization right $IDENTITY_RIGHT has a rule other than the one the host registers (password-only administrator); an administrator removes it (sudo security authorizationdb remove $IDENTITY_RIGHT) and the host registers its own on the next run" ;;
        'identity_gate_closed proof_rule_'*)
            echo "Apple's right $PROOF_RIGHT does not have the rule the AEGIS identity check rests on (security authorizationdb read $PROOF_RIGHT); see docs/platforms/macos/troubleshooting.md" ;;
        'identity_gate_closed proof_probe_denied'*)
            echo "The provider's sandbox did not let it check an administrator approval on this macOS: no identity change can be approved; see docs/platforms/macos/known-limits.md and troubleshooting.md" ;;
        # v30 review: failed or unavailable is an Authorization Services
        # error in the provider's own check, not the sandbox's answer; the
        # provider keeps only allowed or denied and checks again next time.
        'identity_gate_closed proof_probe_'*)
            echo "The provider's own check of $PROOF_RIGHT failed (an Authorization Services error, not a sandbox refusal); it checks again on the next request: run this script again; if it repeats, see docs/platforms/macos/troubleshooting.md (identity gate)" ;;
        *) echo 'See docs/platforms/macos/troubleshooting.md (identity gate) before running this script again' ;;
    esac
}

if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    echo "uninstall-app: $target is absent: nothing to stop, forget, deactivate or move"
    echo "uninstall-app: this run verified nothing about profiles, identity or the extension; an earlier uninstall receipt records them" >&2
    latest=$(pipeline latest-uninstalled --dir "$UNINSTALLED") || latest=''
    [ -z "$latest" ] || echo "latest uninstalled copy: $latest"
    for name in verify identity-gate emergency-stop remove-profile remove-filter verify-filter-absent forget-identity \
        verify-identity-absent deactivate move-app; do
        stage "$name" skipped 'AEGIS.app absent'
    done
    report_container
    record --set uninstall_result=already-absent --set latest_uninstalled_copy="$latest"
    exit 0
fi

# verify: run only the notarized product host of this team.
[ -d "$target" ] && [ ! -L "$target" ] || fail verify "$target is not an app directory"
[ "$(plist "$target" CFBundleIdentifier)" = "$APP_ID" ] || fail verify 'unexpected host bundle identifier'
[ -d "$EXT" ] && [ ! -L "$EXT" ] || fail verify 'PacketTunnel system extension missing'
[ -f "$HOST" ] && [ ! -L "$HOST" ] || fail verify 'host executable missing'
version=$(plist "$target" CFBundleVersion)
[ -n "$version" ] && [ "$(plist "$EXT" CFBundleVersion)" = "$version" ] || fail verify 'host/provider CFBundleVersion differ'
host_cdhash='' provider_cdhash=''
if [ "$DRY_RUN" = 1 ]; then
    run bounded "$TOOL_WATCHDOG" codesign --verify --deep --strict --verbose=2 "$target"
    echo "+ $(quote bounded "$TOOL_WATCHDOG" spctl -a -vv -t exec "$target")  # expect source=Notarized Developer ID ($TEAM)"
else
    bounded "$TOOL_WATCHDOG" codesign --verify --deep --strict --verbose=2 "$target" \
        || fail verify 'strict signature verification failed'
    assessment=$(bounded "$TOOL_WATCHDOG" spctl -a -vv -t exec "$target" 2>&1) || true
    printf '%s\n' "$assessment"
    printf '%s\n' "$assessment" | grep -q '^source=Notarized Developer ID$' \
        || fail verify 'installed app is not accepted as Notarized Developer ID'
    printf '%s\n' "$assessment" | grep -q "($TEAM)" || fail verify 'unexpected Developer ID team'
    host_cdhash=$(cdhash "$target") || fail verify 'no host CDHash'
    provider_cdhash=$(cdhash "$EXT") || fail verify 'no provider CDHash'
fi
# The forget below cannot be undone, so a host that cannot deactivate is
# refused before any verb with an effect runs. The probe only reaches the
# host's argument parser: a foreign provider id is refused before anything
# is submitted.
QUIET=1 host capability-probe "$XPC_WATCHDOG" --deactivate "$CAPABILITY_PROBE"
if [ "$DRY_RUN" = 0 ]; then
    [ "$RC" = 2 ] && [ "$(head -n 1 "$ERR")" = provider_id_mismatch ] \
        && grep -qF -- '--deactivate [PROVIDER_ID]' "$ERR" \
        || fail verify "installed host $version does not support --deactivate (probe exit $RC: $(first_err)); nothing was stopped, removed or forgotten; install a build with --deactivate first"
fi
stage verify ok "AEGIS.app $version" --set bundle_version="$version" \
    --set host_cdhash="$host_cdhash" --set provider_cdhash="$provider_cdhash"

# v30 identity-gate: read-only; nothing has an effect before it passes.
QUIET=1 host identity-gate "$XPC_WATCHDOG" --identity-gate
if [ "$DRY_RUN" = 0 ]; then
    gate_line=$(grep -E '^identity_gate=(open|closed) ' "$OUT" | tail -n 1 || true)
    gate_first=$(first_err)
    nothing='nothing was stopped, removed or forgotten'
    if [ "$RC" = 0 ] && [ "${gate_line#identity_gate=open }" != "$gate_line" ]; then
        stage identity-gate ok "$gate_line" --set identity_gate="$gate_line"
    elif [ "$RC" = "$EXIT_XPC_UNAVAILABLE" ]; then
        stage identity-gate ok "provider unavailable (host exit $RC): the forget step decides" \
            --set identity_gate=provider-unavailable
    elif [ "$RC" = 2 ] && [ "$(head -n 1 "$ERR" 2>/dev/null || true)" = unknown_command ] \
        && pipeline compare-version --new "$IDENTITY_GATE_MIN" --installed "$version" >/dev/null 2>&1; then
        if pipeline compare-version --new "$AUDIT_GATE_MIN" --installed "$version" >/dev/null 2>&1; then
            stage identity-gate skipped "host $version predates the administrator approval of identity changes" \
                --set identity_gate=predates-audit
        else
            QUIET=1 host identity-gate-ping "$XPC_WATCHDOG" --ping
            if [ "$RC" = "$EXIT_XPC_UNAVAILABLE" ]; then
                stage identity-gate skipped "host $version has no identity gate; provider unavailable (the forget step decides)" \
                    --set identity_gate=unsupported-provider-unavailable
            else
                fail identity-gate "installed host $version (v$AUDIT_GATE_MIN to v$((IDENTITY_GATE_MIN - 1))) cannot forget its identity while its provider answers: that provider's sandbox refuses the administrator approval check (provider_refused identity_authorization_denied); $nothing. Install v$IDENTITY_GATE_MIN or later (install-app.sh --replace --activate), then run this script again"
            fi
        fi
    else
        fail identity-gate "identity gate closed (host exit $RC: $gate_first); $nothing. $(gate_advice "$gate_first")" \
            --set identity_gate="${gate_line:-none}"
    fi
fi

host emergency-stop "$PROFILE_WATCHDOG" --emergency-stop
if [ "$DRY_RUN" = 0 ]; then
    line=$(grep -E '^emergency_stop_requested=[0-9]+ disconnected=unknown$' "$OUT" | tail -n 1 || true)
    [ "$RC" = 0 ] && [ -n "$line" ] || fail emergency-stop "host exit $RC: $(first_err)"
    stage emergency-stop ok "$line" --set emergency_stop_line="$line"
fi

host remove-profile "$PROFILE_WATCHDOG" --remove-profile
if [ "$DRY_RUN" = 0 ]; then
    line=$(grep -E '^profiles_found=[0-9]+ profiles_removed=[0-9]+ removal_failed=0 profiles_remaining=0$' "$OUT" \
        | tail -n 1 || true)
    [ "$RC" = 0 ] && [ -n "$line" ] \
        || fail remove-profile "host exit $RC: $(tail -n 1 "$OUT" | cut -c1-200) $(first_err)"
    stage remove-profile ok "$line" --set remove_profile_line="$line"
fi

# S20b: the packet filter configuration names this extension, so it goes
# (verified absent) before the forget and the deactivation; deactivating an
# extension a filter configuration still names is undocumented. The probe
# only reaches the host's argument parser.
QUIET=1 host filter-probe "$XPC_WATCHDOG" --remove-filter "$CAPABILITY_PROBE"
filter_supported=1
if [ "$DRY_RUN" = 0 ]; then
    probe_first=$(head -n 1 "$ERR" 2>/dev/null || true)
    if [ "$RC" = 2 ] && [ "$probe_first" = filter_operand_refused ] && grep -qF -- '--remove-filter' "$ERR"; then
        filter_supported=1
    elif [ "$RC" = 2 ] && [ "$probe_first" = unknown_command ] \
        && ! pipeline compare-version --new "$version" --installed "$FILTER_MIN_PRIOR" >/dev/null 2>&1; then
        filter_supported=0
    else
        fail remove-filter "installed host $version answered the filter probe with exit $RC: $(first_err); nothing was forgotten or deactivated"
    fi
fi
if [ "$filter_supported" = 1 ]; then
    [ "$DRY_RUN" = 1 ] || echo "remove-filter: type an administrator password in the system prompt to remove the AEGIS leak guard (host v26 and later; v30: password only)"
    host remove-filter "$FILTER_REMOVE_WATCHDOG" --remove-filter
    if [ "$DRY_RUN" = 0 ]; then
        if [ "$RC" = "$EXIT_AUTHORIZATION_REFUSED" ]; then
            code=$(first_err)
            fail remove-filter "administrator approval not given (host exit $RC: $code); the packet filter was not removed and nothing was forgotten or deactivated. $(authorization_advice "$code")"
        fi
        line=$(grep -E '^filter_result=ok exit_code=0 filter_found=[01] filter_remaining=0$' "$OUT" | tail -n 1 || true)
        [ "$RC" = 0 ] && [ -n "$line" ] \
            || fail remove-filter "host exit $RC: $(grep '^filter_result=' "$OUT" | tail -n 1 | cut -c1-200) $(first_err)"
        stage remove-filter ok "$line" --set remove_filter_line="$line" --set filter_removal=removed
    fi
    host verify-filter-absent "$PROFILE_WATCHDOG" --filter-status
    if [ "$DRY_RUN" = 0 ]; then
        line=$(grep -E '^filter_result=not_configured exit_code=30 configured=false ' "$OUT" | tail -n 1 || true)
        [ "$RC" = 30 ] && [ -n "$line" ] \
            || fail verify-filter-absent "packet filter still configured or unverified (host exit $RC: $(grep '^filter_result=' "$OUT" | tail -n 1 | cut -c1-200))"
        stage verify-filter-absent ok "$line" --set filter_status_line="$line"
    fi
else
    stage remove-filter skipped "host $version predates the S20b filter verbs (unknown_command)" \
        --set filter_removal=unsupported_by_host
    stage verify-filter-absent skipped "host $version predates the S20b filter verbs"
fi

# The SHA-256 of the host's identity import journal, `none` while there is
# none; refused (status 1) for a link, a non-regular file or another owner's.
journal_digest() {
    local out
    if [ ! -e "$IMPORT_JOURNAL" ] && [ ! -L "$IMPORT_JOURNAL" ]; then echo none; return 0; fi
    [ -f "$IMPORT_JOURNAL" ] && [ ! -L "$IMPORT_JOURNAL" ] || return 1
    [ "$(stat -f %u "$IMPORT_JOURNAL")" = "$(id -u)" ] || return 1
    out=$(shasum -a 256 < "$IMPORT_JOURNAL") || return 1
    out=${out%% *}
    case "$out" in ''|*[!0-9a-f]*) return 1 ;; esac
    printf '%s\n' "$out"
}
# The journal digest a marker of this run binds: read before the forget
# that was then verified (or when a marker of this app was honoured); never
# matches when unreadable.
journal_bound=unreadable
marker_matches() {
    local file=$1 journal
    [ -n "$host_cdhash" ] && [ -f "$file" ] && [ ! -L "$file" ] || return 1
    [ "$(stat -f %u "$file")" = "$(id -u)" ] || return 1
    journal=$(journal_digest) || return 1
    grep -qx "host_cdhash=$host_cdhash" "$file" && grep -qx "provider_cdhash=$provider_cdhash" "$file" \
        && grep -qx "import_journal=$journal" "$file"
}
# Moves a marker aside under a fresh name; markers are never deleted.
retire() {
    local file=$1 kind=$2
    if [ -e "$file" ] || [ -L "$file" ]; then mv "$file" "$(fresh "$STATE/uninstall/$kind" .txt)"; fi
}
write_marker() {
    local file=$1; shift
    retire "$file" "$(basename "$file" .txt)-stale"
    {
        printf 'host_cdhash=%s\nprovider_cdhash=%s\nbundle_version=%s\n' "$host_cdhash" "$provider_cdhash" "$version"
        printf 'import_journal=%s\n' "$journal_bound"
        printf '%s\n' "$@"
        printf 'receipt=%s\n' "$RECEIPT"
    } > "$file.tmp"
    mv "$file.tmp" "$file"
}

# resume: the newest marker of this exact app, if any.
resume='' provider_gone=0
if [ "$DRY_RUN" = 0 ]; then
    if marker_matches "$MARKER"; then resume=deactivated
    elif marker_matches "$ABSENT_MARKER"; then resume=identity-absent
    fi
fi
if [ -n "$resume" ]; then
    host provider-probe "$XPC_WATCHDOG" --ping
    if [ "$RC" = "$EXIT_XPC_UNAVAILABLE" ]; then
        provider_gone=1
    elif [ "$RC" != 0 ]; then
        fail forget-identity "provider probe exit $RC: $(first_err)"
    fi
fi

# identity_absence: verified (this run), verified-earlier (a marker of this
# app and an unreachable provider) or unverified (--identity-unverified).
identity_absence=verified deactivate_needed=1 accept_not_found=0
if [ "$provider_gone" = 1 ]; then
    identity_absence=verified-earlier
    journal_bound=$(journal_digest) || journal_bound=unreadable
    if [ "$resume" = deactivated ]; then marker_file=$MARKER; else marker_file=$ABSENT_MARKER; fi
    earlier=$(sed -n 's/^receipt=//p' "$marker_file" | head -n 1)
    for name in forget-identity verify-identity-absent; do
        stage "$name" done-earlier "provider unavailable; done by $earlier" --set earlier_receipt="$earlier"
    done
    if [ "$resume" = deactivated ]; then
        deactivate_needed=0
        stage deactivate done-earlier "provider unavailable; done by $earlier"
        echo "provider unavailable and $MARKER binds this app: forget, verification and deactivation were done by $earlier"
    else
        # The earlier run verified the forget and asked for the deactivation;
        # Apple may have finished it after that host exited, so not-found is
        # accepted here (and only here) as already inactive.
        accept_not_found=1
        echo "provider unavailable and $ABSENT_MARKER binds this app: forget and verification were done by $earlier; deactivation is requested again"
    fi
else
    # Markers count only while the provider is unreachable: a reachable
    # provider, or a marker of another app, retires them here.
    if [ "$DRY_RUN" = 0 ]; then
        retire "$MARKER" deactivated-stale
        retire "$ABSENT_MARKER" identity-absent-stale
    fi
    # Read before the forget: an import from here on changes it, so no
    # marker of this run can match after one.
    journal_before=unreadable
    if [ "$DRY_RUN" = 0 ]; then journal_before=$(journal_digest) || journal_before=unreadable; fi
    attempt=1
    while :; do
        if [ "$DRY_RUN" = 0 ]; then
            echo "forget-identity attempt $attempt: type an administrator password in the system prompt to remove the AEGIS identity (v30: password only)"
        fi
        host "forget-identity-$attempt" "$IDENTITY_WATCHDOG" --forget-identity
        [ "$DRY_RUN" = 0 ] || break
        if [ "$RC" = 65 ] && grep -qx 'provider_refused session_live' "$ERR" && [ "$attempt" -lt "$FORGET_ATTEMPTS" ]; then
            echo "provider session still live; forget retry in ${FORGET_RETRY_SECS}s (the prompt appears again)"
            sleep "$FORGET_RETRY_SECS"
            attempt=$((attempt + 1))
            continue
        fi
        break
    done
    if [ "$DRY_RUN" = 0 ]; then
        [ "$RC" != 74 ] || fail forget-identity 'the provider could not remove its key material (host exit 74)'
        if [ "$RC" = "$EXIT_AUTHORIZATION_REFUSED" ]; then
            code=$(first_err)
            fail forget-identity "administrator approval not given (host exit $RC: $code); nothing was forgotten and deactivation was not requested. $(authorization_advice "$code")"
        fi
        if [ "$RC" = "$EXIT_XPC_UNAVAILABLE" ] && [ "$IDENTITY_UNVERIFIED" = 1 ]; then
            identity_absence=unverified accept_not_found=1
            echo "uninstall-app: provider unavailable and --identity-unverified given: identity absence is NOT verified; requesting deactivation and moving the app anyway" >&2
            stage forget-identity unverified "provider unavailable (host exit $RC: $(first_err)); --identity-unverified"
            stage verify-identity-absent unverified 'provider unavailable; identity absence not verified'
        elif [ "$RC" = "$EXIT_XPC_UNAVAILABLE" ]; then
            fail forget-identity "provider unavailable (host exit $RC: $(first_err)): its extension is not active (never activated, or deactivated outside this script) or not reachable, and no earlier run of this app verified the forget, so identity absence cannot be verified; deactivation was not requested and the app stays in place. Activate it (install-app.sh --activate) and run this script again, or run it again with --identity-unverified to deactivate and move the app recording identity_absence=unverified"
        else
            if [ "$RC" = 65 ]; then
                code=$(first_err)
                case "$code" in
                    'provider_refused identity_authorization_host_outdated'*)
                        fail forget-identity "host exit $RC after $attempt attempt(s): $code; the active provider (v$IDENTITY_GATE_MIN or later) refuses this v$version host's approval; install the same build as the active extension, then run this script again" ;;
                    'provider_refused identity_authorization_'*)
                        fail forget-identity "host exit $RC after $attempt attempt(s): $code; nothing was forgotten and deactivation was not requested. If the active provider is v$AUDIT_GATE_MIN to v$((IDENTITY_GATE_MIN - 1)), its sandbox refuses every approval: install and activate v$IDENTITY_GATE_MIN or later first; otherwise see docs/platforms/macos/troubleshooting.md (exit 65)" ;;
                esac
            fi
            [ "$RC" = 0 ] || fail forget-identity "host exit $RC after $attempt attempt(s): $(first_err)"
            forget=$(pipeline forget-reply --line "$(tail -n 1 "$OUT")") || fail forget-identity 'unparsed forget reply'
            case "$forget" in
                'identity_was_present='*' key_material_removed=true') ;;
                *) fail forget-identity "key material not removed ($forget)" ;;
            esac
            stage forget-identity ok "$forget" --set forget_report="$forget" --set-json forget_attempts="$attempt"
        fi
    fi

    if [ "$identity_absence" = verified ]; then
        host verify-identity-absent "$XPC_WATCHDOG" --ping
        if [ "$DRY_RUN" = 0 ]; then
            [ "$RC" = 0 ] || fail verify-identity-absent "ping exit $RC: $(first_err)"
            ping=$(pipeline ping-identity --line "$(tail -n 1 "$OUT")") || fail verify-identity-absent 'unparsed ping reply'
            case "$ping" in
                'identity_present=false container_admitted=true') ;;
                'identity_present=true '*)
                    fail verify-identity-absent "identity still present after --forget-identity; not deactivating" \
                        --set ping_identity="$ping" ;;
                *) fail verify-identity-absent "identity absence not verified ($ping)" --set ping_identity="$ping" ;;
            esac
            stage verify-identity-absent ok "$ping" --set ping_identity="$ping"
            journal_bound=$journal_before
            write_marker "$ABSENT_MARKER" phase=identity-absent
        fi
    fi
fi
record --set identity_absence="$identity_absence"

again="run $(quote "$0") again"
if [ "$identity_absence" = unverified ]; then again="$again with --identity-unverified"; fi
if [ "$deactivate_needed" = 1 ]; then
    host deactivate "$DEACTIVATION_WATCHDOG" --deactivate "$PROVIDER_ID"
    if [ "$DRY_RUN" = 0 ]; then
        result_line=$(grep '^deactivation_result=' "$OUT" | tail -n 1 || true)
        outcome='' status=''
        read -r outcome status < <(pipeline deactivation-outcome --exit-code "$RC" --result-line "$result_line") || true
        [ -n "$outcome" ] && [ -n "$status" ] || fail deactivate "unmapped host exit $RC"
        approval=false
        if grep -q 'System Settings approval required' "$ERR"; then approval=true; fi
        record --set deactivation_outcome="$outcome" --set-json deactivation_exit_code="$RC" \
            --set deactivation_result="$result_line" --set-json deactivation_needed_approval="$approval"
        case "$outcome" in
            completed|will-complete-after-reboot)
                # An unverified forget never leaves a marker that a later run
                # would read as a verified one.
                if [ "$identity_absence" != unverified ]; then
                    write_marker "$MARKER" "outcome=$outcome"
                fi ;;
        esac
        case "$outcome" in
            completed) stage deactivate ok "$result_line" ;;
            will-complete-after-reboot)
                stage deactivate pending-reboot "$result_line" --set uninstall_result=pending-reboot
                die "deactivation completes after a reboot; the app stays in place. Reboot, then $again" ;;
            timeout-awaiting-approval)
                fail deactivate "approval still pending after 120s: approve in System Settings, then $again" ;;
            not-found)
                if [ "$accept_not_found" = 1 ]; then
                    stage deactivate ok "not found while the provider is unavailable: already inactive ($result_line)" \
                        --set deactivation_accepted_as=already-inactive
                else
                    fail deactivate "Apple reports no such extension for this app although its provider answered; the app stays in place"
                fi ;;
            *) fail deactivate "deactivation $outcome (host exit $RC); the app stays in place, $again" ;;
        esac
    fi
fi

# move-app: a Trash-equivalent move into the packaging state, never a delete.
backup=$(fresh "$UNINSTALLED/AEGIS.app.uninstalled-$version")
run mkdir -p "$UNINSTALLED" || fail move-app "cannot create $UNINSTALLED"
if [ "$DRY_RUN" = 1 ]; then
    run bounded "$TOOL_WATCHDOG" mv "$target" "$backup"
else
    bounded "$TOOL_WATCHDOG" mv "$target" "$backup" || fail move-app "could not move $target to $backup"
    [ ! -e "$target" ] && [ -d "$backup" ] || fail move-app "$target still present or $backup missing"
    consumed='' consumed_absent=''
    if [ -f "$MARKER" ] && [ ! -L "$MARKER" ]; then
        consumed=$(fresh "$STATE/uninstall/deactivated-consumed" .txt)
        mv "$MARKER" "$consumed"
    fi
    if [ -f "$ABSENT_MARKER" ] && [ ! -L "$ABSENT_MARKER" ]; then
        consumed_absent=$(fresh "$STATE/uninstall/identity-absent-consumed" .txt)
        mv "$ABSENT_MARKER" "$consumed_absent"
    fi
    # v26: a kept v25 host could disable or remove a later install's leak
    # guard with no prompt, a kept v26 to v29 host (v30 review) with one
    # resting Touch ID touch; any other copy is unchanged.
    if ! disarm=$(pipeline disarm-weak-host --app "$backup" 2>&1); then
        echo "uninstall-app: warning: $backup not checked for a host without the password-only leak-guard prompt: $disarm" >&2
        disarm="unchecked: $disarm"
    fi
    case "$disarm" in 'weak_host=disarmed '*) echo "uninstalled copy $backup: $disarm (its host predates the v30 password-only leak-guard prompt)" ;; esac
    stage move-app ok "$backup" --set uninstalled_app_path="$backup" --set consumed_marker="$consumed" \
        --set consumed_identity_marker="$consumed_absent" --set uninstalled_host_disarm="$disarm"
fi
echo "uninstalled app kept at: $backup (not deleted; remove it yourself once it is no longer needed)"
report_container
record --set uninstall_result=uninstalled
if [ "$DRY_RUN" = 1 ]; then echo 'dry run complete: nothing was executed or written'; else echo "uninstall complete; receipt $RECEIPT"; fi
