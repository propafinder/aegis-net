#!/bin/bash
# B-06 S09: install a notarized, stapled AEGIS.app from one exact stapled ZIP
# into /Applications. Owner-only: run it yourself after approving the ZIP
# SHA-256. It never calls systemextensionsctl, never uses sudo and never
# changes trust settings. System-extension activation is a separate, optional
# host request (--activate) that macOS asks the user to approve; the host
# bounds it at 120 s and exits with a distinct code per outcome, which is
# recorded. The host replaces an active extension only with a numerically
# newer CFBundleVersion (B-06 S11). --activate-installed repeats only the
# activation of the app this receipt installed (after a reboot or a late
# approval), so its result is recorded against the same stapled ZIP.
# --enable-filter (S20b) follows a completed activation with the host's
# bounded --enable-filter: the first save asks the owner to allow AEGIS to
# filter network content (one click on Allow); the host waits at most 120 s
# and the outcome is recorded as the enable-filter stage.
# v26: a build whose host has the S20b filter verbs but not their
# administrator prompt (CFBundleVersion above FILTER_MIN_PRIOR and below
# WEAKEN_PROMPT_MIN, that is v25) is never installed, and once an install is
# verified every kept copy of such a build (replaced or uninstalled, under
# the state directory) loses its host executable (pipeline.py
# disarm-weak-host, its SHA-256 kept beside it): any process of the console
# user could otherwise run it to disable or remove the leak guard with no
# prompt. The build itself stays in its stapled ZIP.
# v30 review: the same holds for v26 to v29 (below LEAK_GUARD_PASSWORD_MIN):
# their prompt for dev.aegis.macos.leak-guard-weaken offers Touch ID, and one
# resting touch approved two v29 prompts. The host alone changes
# NEFilterManager, so the leak guard is only as strong as the weakest signed
# host that can still run: they are never installed and lose their host
# executable like v25.
set -euo pipefail
umask 022

APP_ID=dev.aegis.macos
PROVIDER_ID=dev.aegis.macos.PacketTunnel
TEAM=TEAMID0000
DEST=/Applications
STATE="$HOME/Library/Application Support/aegis-packaging/install"
ZIP='' APPROVED='' DRY_RUN=0 REPLACE=0 ACTIVATE=0 ACTIVATE_INSTALLED=0 RECEIPT='' ENABLE_FILTER=0
# The host gives up after 120 s; this outer watchdog only catches a broken bound.
HOST_ACTIVATION_SECS=120 ACTIVATION_WATCHDOG=150
# S20b: the host bounds --enable-filter at 120 s (the owner's Allow).
HOST_FILTER_SECS=120 FILTER_WATCHDOG=150
# v26: hosts above FILTER_MIN_PRIOR have the filter verbs; from
# WEAKEN_PROMPT_MIN they ask for an administrator, from
# LEAK_GUARD_PASSWORD_MIN (v30) at the password-only prompt (pipeline.py
# binds all three).
FILTER_MIN_PRIOR=24 WEAKEN_PROMPT_MIN=26 LEAK_GUARD_PASSWORD_MIN=30
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
PIPELINE="$HERE/pipeline.py"
SELF="$HERE/$(basename -- "$0")"
# Printed and recorded on every --replace: an app backup is not an extension
# rollback.
ROLLBACK_NOTE='the backup restores only the app: moving it back does not change the active system extension, and the host never replaces an active extension with an equal or older CFBundleVersion (exit 13). This tooling has no extension rollback; undoing an extension replacement needs a deliberate deactivation of the newer extension first (for example deleting AEGIS.app in Finder, which Apple documents as uninstalling its system extensions; not exercised before S12), then a fresh install and activation of the older build'

usage() {
    cat >&2 <<'EOF'
usage: install-app.sh --stapled-zip ABS_ZIP --approve-sha256 HEX [options]
       install-app.sh --activate-installed --receipt PATH [--dest DIR]
                      [--state-dir DIR] [--dry-run]
  --dest DIR                install directory (default /Applications)
  --replace                 replace an existing AEGIS.app with a strictly lower
                            CFBundleVersion; with --activate the host replaces
                            the active extension only when this bundle's
                            CFBundleVersion is numerically newer. The kept
                            backup restores only the app, never the extension
  --activate                afterwards run the host's --request-activation
                            (user approval); the host stops after 120 s
  --activate-installed      only re-run the activation of the app installed
                            from this receipt's ZIP (installed path, version,
                            CDHashes, signature, staple and Gatekeeper
                            re-checked); records a new activate stage
  --enable-filter           with --activate or --activate-installed: after a
                            completed activation run the host's --enable-filter
                            (the S20b leak-guard packet filter; macOS asks once
                            to allow filtering network content); the host
                            stops after 120 s
  --receipt PATH            run receipt of this exact stapled ZIP; the install
                            and activation results are appended to it
  --state-dir DIR           durable backups and activation logs (default
                            ~/Library/Application Support/aegis-packaging/install)
  --dry-run                 print the exact commands only
EOF
    exit 2
}
die() { echo "install-app: $*" >&2; exit 1; }
quote() { local out='' arg; for arg in "$@"; do out="$out $(printf '%q' "$arg")"; done; printf '%s\n' "${out# }"; }
run() { if [ "$DRY_RUN" = 1 ]; then echo "+ $(quote "$@")"; else "$@"; fi; }
# A failed exec exits 127, outside the host's exit-code table; perl's die
# would exit with errno (EACCES 13 = "replacement declined"). The block form
# never goes through a shell.
bounded() { local secs=$1; shift; perl -e 'alarm shift; exec { $ARGV[0] } @ARGV; print STDERR "exec: $!\n"; exit 127' "$secs" "$@"; }
utc() { date -u +%Y%m%dT%H%M%SZ; }
# A timestamped path that does not exist yet (PREFIX-UTC[.N]SUFFIX): a retry
# within the same second never moves into, or overwrites, an earlier attempt.
fresh() {
    local base="$1-$(utc)" suffix=${2:-} path n=1
    path="$base$suffix"
    while [ -e "$path" ] || [ -L "$path" ]; do path="$base.$n$suffix"; n=$((n + 1)); done
    printf '%s\n' "$path"
}
pipeline() { python3 -I -B "$PIPELINE" "$@"; }
# A host with the filter verbs and without their password-only prompt.
weak_host_version() {
    pipeline compare-version --new "$1" --installed "$FILTER_MIN_PRIOR" >/dev/null 2>&1 \
        && pipeline compare-version --new "$LEAK_GUARD_PASSWORD_MIN" --installed "$1" >/dev/null 2>&1
}
# Of those, a host without any administrator prompt (v25).
promptless_host_version() {
    pipeline compare-version --new "$WEAKEN_PROMPT_MIN" --installed "$1" >/dev/null 2>&1
}
receipt_get() { pipeline receipt --receipt "$RECEIPT" --get "$1"; }
record() { if [ -n "$RECEIPT" ] && [ "$DRY_RUN" = 0 ]; then pipeline receipt --receipt "$RECEIPT" "$@"; fi; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --stapled-zip) ZIP=${2:-}; shift 2 ;;
        --approve-sha256) APPROVED=${2:-}; shift 2 ;;
        --dest) DEST=${2:-}; shift 2 ;;
        --replace) REPLACE=1; shift ;;
        --activate) ACTIVATE=1; shift ;;
        --activate-installed) ACTIVATE_INSTALLED=1; shift ;;
        --enable-filter) ENABLE_FILTER=1; shift ;;
        --receipt) RECEIPT=${2:-}; shift 2 ;;
        --state-dir) STATE=${2:-}; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done
case "$DEST" in /*) ;; *) die 'absolute --dest required' ;; esac
case "$STATE" in /*) ;; *) die 'absolute --state-dir required' ;; esac
if [ "$ENABLE_FILTER" = 1 ] && [ "$ACTIVATE$ACTIVATE_INSTALLED" = 00 ]; then
    die '--enable-filter follows an activation: pass --activate or --activate-installed'
fi
if [ "$ACTIVATE_INSTALLED" = 1 ]; then
    [ -n "$RECEIPT" ] || die '--activate-installed requires --receipt'
    [ -z "$ZIP$APPROVED" ] && [ "$REPLACE$ACTIVATE" = 00 ] \
        || die '--activate-installed takes only --receipt, --dest, --state-dir, --enable-filter and --dry-run'
else
    [ -n "$ZIP" ] && [ -n "$APPROVED" ] || usage
    case "$ZIP" in /*) ;; *) die 'absolute stapled ZIP path required' ;; esac
fi
[ "$(id -u)" != 0 ] || die 'do not run as root'
if [ -n "$RECEIPT" ]; then
    case "$RECEIPT" in /*) ;; *) die 'absolute --receipt required' ;; esac
    [ -f "$RECEIPT" ] || die "receipt not found: $RECEIPT"
fi
plist() { /usr/libexec/PlistBuddy -c "Print :$2" "$1/Contents/Info.plist"; }
# The code directory hash of a signed bundle's main executable.
cdhash() {
    local out
    out=$(bounded 120 codesign -d --verbose=4 "$1" 2>&1 | sed -n 's/^CDHash=//p' | head -n 1) || true
    case "$out" in ''|*[!0-9a-f]*) die "no CDHash for $1" ;; esac
    printf '%s\n' "$out"
}
# Layout, modes, strict signature, stapled ticket and Gatekeeper assessment
# of one AEGIS.app (read-only; Gatekeeper may consult Apple).
check_app() {
    local app=$1 what=$2 ext assessment
    [ "$(plist "$app" CFBundleIdentifier)" = "$APP_ID" ] || die "$what: unexpected host bundle identifier"
    ext="$app/Contents/Library/SystemExtensions/$PROVIDER_ID.systemextension"
    [ -d "$ext" ] || die "$what: PacketTunnel system extension missing"
    [ ! -e "$app/Contents/Library/Helpers" ] || die "$what: diagnostic helpers present; not a product bundle"
    [ "$(plist "$ext" CFBundleVersion)" = "$(plist "$app" CFBundleVersion)" ] \
        || die "$what: host/provider CFBundleVersion differ"
    pipeline check-modes --bundle "$app"
    bounded 120 codesign --verify --deep --strict --verbose=2 "$app" || die "$what: strict signature verification failed"
    bounded 120 xcrun stapler validate -v "$app" || die "$what: no valid stapled notarization ticket"
    assessment=$(bounded 120 spctl -a -vv -t exec "$app" 2>&1) || true
    printf '%s\n' "$assessment"
    printf '%s\n' "$assessment" | grep -q '^source=Notarized Developer ID$' \
        || die "$what is not accepted as Notarized Developer ID"
    printf '%s\n' "$assessment" | grep -q "($TEAM)" || die "$what: unexpected Developer ID team"
}
# A receipt only records a result when its staple and assess stages are current.
receipt_current() {
    local stage
    for stage in staple assess; do
        [ "$(pipeline receipt --receipt "$RECEIPT" --stage-status "$stage")" = ok ] \
            || die "receipt stage $stage is not current ok"
    done
}

target="$DEST/AEGIS.app"
host_cdhash='' provider_cdhash='' old_version=''
activation_cmd=("$target/Contents/MacOS/aegis-ne-host" --request-activation "$PROVIDER_ID")
filter_cmd=("$target/Contents/MacOS/aegis-ne-host" --enable-filter)
# The command printed when an activation is still pending or separate; it
# keeps a requested --enable-filter so the filter is never silently dropped.
if [ -n "$RECEIPT" ]; then
    followup=("$SELF" --activate-installed --receipt "$RECEIPT" --dest "$DEST" --state-dir "$STATE")
    if [ "$ENABLE_FILTER" = 1 ]; then followup+=(--enable-filter); fi
    followup_text=$(quote "${followup[@]}")
else
    followup_text=$(quote "${activation_cmd[@]}")
    if [ "$ENABLE_FILTER" = 1 ]; then followup_text="$followup_text, then $(quote "${filter_cmd[@]}")"; fi
fi

# S20b: one bounded host --enable-filter after a completed activation; the
# outcome is the host's exit code confirmed by its own filter_result= line.
enable_filter() {
    local version=$1 log host_exit outcome='' status='' result_line
    log=$(fresh "$STATE/enable-filter-$version" .log)
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $(quote bounded "$FILTER_WATCHDOG" "${filter_cmd[@]}") > $(quote "$log") 2>&1  # macOS asks once to allow filtering network content; host stops after ${HOST_FILTER_SECS}s; exit 0 enabled, 31 disabled, 32 field mismatch, 34 failed, 35 permission denied, 36 timeout"
        return 0
    fi
    mkdir -p "$STATE"
    set +e
    bounded "$FILTER_WATCHDOG" "${filter_cmd[@]}" > "$log" 2>&1
    host_exit=$?
    set -e
    cat "$log"
    result_line=$(grep '^filter_result=' "$log" | tail -n 1 || true)
    read -r outcome status < <(pipeline filter-outcome --exit-code "$host_exit" --result-line "$result_line") || true
    [ -n "$outcome" ] && [ -n "$status" ] || die "unmapped host filter exit $host_exit (log $log)"
    record --set filter_outcome="$outcome" --set-json filter_exit_code="$host_exit" \
        --set filter_result="$result_line" --set filter_log="$log" \
        --stage enable-filter --status "$status" --detail "$outcome (host exit $host_exit)"
    case "$outcome" in
        ok) echo 'leak-guard packet filter enabled; its attachment is a separate check (aegis-ne-host --filter-status)' ;;
        permission-denied)
            die "the packet filter was not allowed (host exit $host_exit): run $(quote "${filter_cmd[@]}") again and click Allow (log $log)" ;;
        *) die "enable-filter $outcome (host exit $host_exit, log $log)" ;;
    esac
}

# One bounded host activation request; the outcome is the host's exit code
# confirmed by its own activation_result= line.
activate() {
    local version=$1 log host_exit outcome='' status='' result_line approval=false
    log=$(fresh "$STATE/activation-$version" .log)
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $(quote bounded "$ACTIVATION_WATCHDOG" "${activation_cmd[@]}") > $(quote "$log") 2>&1  # host stops on its finish/failure callback or after ${HOST_ACTIVATION_SECS}s; exit 0 completed, 10 after reboot, 11 failed, 12 cancelled, 13 replacement declined, 14/75 timeout"
        if [ "$ENABLE_FILTER" = 1 ]; then enable_filter "$version"; fi
        exit 0
    fi
    mkdir -p "$STATE"
    set +e
    bounded "$ACTIVATION_WATCHDOG" "${activation_cmd[@]}" > "$log" 2>&1
    host_exit=$?
    set -e
    cat "$log"
    result_line=$(grep '^activation_result=' "$log" | tail -n 1 || true)
    read -r outcome status < <(pipeline activation-outcome --exit-code "$host_exit" --result-line "$result_line") || true
    [ -n "$outcome" ] && [ -n "$status" ] || die "unmapped host exit $host_exit (log $log)"
    if grep -q 'System Settings approval required' "$log"; then approval=true; fi
    record --set activation_outcome="$outcome" --set-json activation_exit_code="$host_exit" \
        --set activation_result="$result_line" --set-json activation_needed_approval="$approval" \
        --set activation_log="$log" --stage activate --status "$status" --detail "$outcome (host exit $host_exit)"
    if [ "$outcome" != completed ] && [ -n "$old_version" ]; then
        echo "install-app: warning: host $version is installed (replacing app $old_version) but the previously active provider stays active until an activation completes" >&2
    fi
    case "$outcome" in
        completed) echo 'activation request completed; tunnel readiness is a separate check' ;;
        will-complete-after-reboot)
            die "activation completes after a reboot; reboot, then run $followup_text to confirm (log $log)" ;;
        timeout-awaiting-approval)
            die "approval still pending after ${HOST_ACTIVATION_SECS}s: approve in System Settings > General > Login Items & Extensions, then run $followup_text" ;;
        replacement-declined)
            die "the active extension was not replaced: this bundle's CFBundleVersion $version is not newer (log $log)" ;;
        *) die "activation $outcome (host exit $host_exit, log $log)" ;;
    esac
}

# v26: every kept copy of a weak host (v30 review: v25 to v29) loses its
# host executable, after a verified install (never before: the replaced
# app is the rollback of a failed one). An unreadable copy is reported and
# left as it is.
disarm_kept_weak_hosts() {
    local copy line disarmed=''
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $(quote pipeline disarm-weak-host --app "$STATE/backups/AEGIS.app.replaced-*") (and $STATE/uninstalled/AEGIS.app.uninstalled-*)  # hosts above v$FILTER_MIN_PRIOR and below v$LEAK_GUARD_PASSWORD_MIN lose their executable"
        return 0
    fi
    for copy in "$STATE"/backups/AEGIS.app.replaced-* "$STATE"/uninstalled/AEGIS.app.uninstalled-*; do
        [ -d "$copy" ] && [ ! -L "$copy" ] || continue
        if ! line=$(pipeline disarm-weak-host --app "$copy" 2>&1); then
            echo "install-app: warning: kept copy $copy not checked for a host without the password-only leak-guard prompt: $line" >&2
            continue
        fi
        case "$line" in
            'weak_host=disarmed '*)
                echo "kept app $copy: $line (its host predates the v$LEAK_GUARD_PASSWORD_MIN password-only leak-guard prompt; the build stays in its stapled ZIP)"
                disarmed="$disarmed${disarmed:+; }$copy $line" ;;
        esac
    done
    record --set weak_hosts_disarmed="$disarmed"
}

if [ "$ACTIVATE_INSTALLED" = 1 ]; then
    # Only the app this receipt installed, unchanged since: same path, ZIP,
    # version and CDHashes, and still signed, stapled and notarized.
    receipt_current
    [ "$(pipeline receipt --receipt "$RECEIPT" --stage-status install)" = ok ] \
        || die 'receipt has no current ok install stage'
    [ "$(receipt_get installed_path)" = "$target" ] || die "receipt did not install $target"
    zip_sha=$(receipt_get stapled_zip_sha256)
    [ -n "$zip_sha" ] && [ "$(receipt_get installed_zip_sha256)" = "$zip_sha" ] \
        || die 'receipt install is not bound to its stapled ZIP'
    [ -d "$target" ] && [ ! -L "$target" ] || die "$target not found"
    version=$(plist "$target" CFBundleVersion)
    [ "$(receipt_get bundle_version)" = "$version" ] || die "installed CFBundleVersion $version differs from the receipt"
    check_app "$target" 'installed app'
    [ "$(cdhash "$target")" = "$(receipt_get installed_host_cdhash)" ] \
        || die 'installed host CDHash differs from the receipt'
    [ "$(cdhash "$target/Contents/Library/SystemExtensions/$PROVIDER_ID.systemextension")" \
        = "$(receipt_get installed_provider_cdhash)" ] || die 'installed provider CDHash differs from the receipt'
    echo "installed app $version matches receipt stapled zip sha256: $zip_sha"
    activate "$version"
    if [ "$ENABLE_FILTER" = 1 ]; then enable_filter "$version"; fi
    exit 0
fi

[ -f "$ZIP" ] && [ ! -L "$ZIP" ] || die "stapled ZIP not found: $ZIP"
actual=$(shasum -a 256 "$ZIP" | awk '{print $1}')
echo "stapled zip: $ZIP"
echo "stapled zip sha256: $actual"
[ "$actual" = "$APPROVED" ] || die 'approved SHA-256 does not match the stapled ZIP'

# A receipt only records this install when it belongs to this exact ZIP.
if [ -n "$RECEIPT" ]; then
    [ "$(receipt_get stapled_zip_sha256)" = "$actual" ] \
        || die 'receipt belongs to a different stapled ZIP (stapled_zip_sha256 differs)'
    receipt_current
fi

stage=$(mktemp -d "${TMPDIR:-/tmp}/aegis-install.XXXXXX")
trap 'rm -rf "$stage"' EXIT
ditto -x -k "$ZIP" "$stage"
NEW="$stage/AEGIS.app"
[ -d "$NEW" ] || die 'ZIP does not contain AEGIS.app at its root'
new_version=$(plist "$NEW" CFBundleVersion)
if [ -n "$RECEIPT" ]; then
    [ "$(receipt_get bundle_version)" = "$new_version" ] || die 'receipt bundle_version differs from the ZIP'
fi
if weak_host_version "$new_version"; then
    ! promptless_host_version "$new_version" \
        || die "CFBundleVersion $new_version has --disable-filter and --remove-filter without the administrator prompt (v$WEAKEN_PROMPT_MIN); install v$LEAK_GUARD_PASSWORD_MIN or later"
    die "CFBundleVersion $new_version asks for --disable-filter and --remove-filter at a prompt that offers Touch ID (before v$LEAK_GUARD_PASSWORD_MIN, the password-only leak-guard prompt); install v$LEAK_GUARD_PASSWORD_MIN or later"
fi
# Pre-install checks on the extracted copy.
check_app "$NEW" 'extracted app'
host_cdhash=$(cdhash "$NEW")
provider_cdhash=$(cdhash "$NEW/Contents/Library/SystemExtensions/$PROVIDER_ID.systemextension")
backup=''
if [ -e "$target" ]; then
    [ "$REPLACE" = 1 ] || die "$target exists; pass --replace for an upgrade"
    old_version=$(plist "$target" CFBundleVersion)
    pipeline compare-version --new "$new_version" --installed "$old_version" \
        || die "CFBundleVersion $new_version is not greater than installed $old_version"
    # Durable rollback copy: never in $TMPDIR, which macOS cleans.
    backup=$(fresh "$STATE/backups/AEGIS.app.replaced-$old_version")
    echo "previous app $old_version is moved to $backup (app-only rollback: move it back)"
    echo "install-app: note: $ROLLBACK_NOTE" >&2
    run mkdir -p "$STATE/backups"
fi
incoming="$DEST/.AEGIS.app.incoming-$new_version"
[ ! -e "$incoming" ] || die "stale $incoming exists; inspect and remove it first"
run ditto "$NEW" "$incoming"
if [ -n "$backup" ]; then run mv "$target" "$backup"; fi
run mv "$incoming" "$target"
if [ "$DRY_RUN" = 1 ]; then
    echo "+ $(quote spctl -a -vv "$target")  # expect: source=Notarized Developer ID; otherwise restore $backup"
else
    installed=$(bounded 120 spctl -a -vv "$target" 2>&1) || true
    printf '%s\n' "$installed"
    problem=''
    if ! printf '%s\n' "$installed" | grep -q '^source=Notarized Developer ID$'; then
        problem='installed app is not accepted as Notarized Developer ID'
    elif [ "$(cdhash "$target")" != "$host_cdhash" ] \
        || [ "$(cdhash "$target/Contents/Library/SystemExtensions/$PROVIDER_ID.systemextension")" != "$provider_cdhash" ]; then
        problem='installed app differs from the verified extracted app (CDHash)'
    fi
    if [ -n "$problem" ]; then
        mkdir -p "$STATE/failed"
        failed=$(fresh "$STATE/failed/AEGIS.app.failed-$new_version")
        mv "$target" "$failed"
        if [ -n "$backup" ]; then mv "$backup" "$target"; fi
        record --set install_failed_copy="$failed" --stage install --status failed \
            --detail "$problem${backup:+; previous app restored}"
        die "$problem; moved it to $failed${backup:+ and restored the previous app}"
    fi
    record --set installed_path="$target" --set installed_zip_sha256="$actual" \
        --set installed_host_cdhash="$host_cdhash" --set installed_provider_cdhash="$provider_cdhash" \
        --set installed_backup="$backup" --set rollback_note="${backup:+$ROLLBACK_NOTE}" \
        --set-json installed=true --stage install --status ok
fi
disarm_kept_weak_hosts

if [ "$ACTIVATE" = 0 ]; then
    echo "activation (separate step): $followup_text"
    if [ -n "$old_version" ]; then
        echo "install-app: warning: until an activation completes, the previously active provider stays active beside host $new_version" >&2
    fi
    exit 0
fi
activate "$new_version"
if [ "$ENABLE_FILTER" = 1 ]; then enable_filter "$new_version"; fi
