#!/usr/bin/env bash
# Executes the actual pure source preflight on the host. No Linux/systemd proof.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
source_file="${1:-$repo/aegis-client/src/profile_auto_backend.rs}"
check_dir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-capture-witness.XXXXXX")"
trap 'rm -rf "$check_dir"' EXIT
python3 - "$source_file" "$check_dir/check.rs" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
start = source.find('const ACTIVATION_OWNER_UNAVAILABLE: &str =')
assert start >= 0, 'missing activation-owner refusal preflight'
constant_end = source.index('\nconst ACTIVATION_RECOVERY_REQUIRED:', start)
helper_start = source.index('fn require_activation_authority(args: &CommandArgs) -> Result<()>', constant_end)
end = source.index('\nfn command_with_lock(', helper_start)
helper = source[start:constant_end] + '\n' + source[helper_start:end]
dispatch = source[end:source.index('\nmod tests {', end)]
preflight = dispatch[:dispatch.index('let mut stage = admit_worker_stage(')]
# Marker uncertainty must retain recovery precedence, without admitting a stage.
assert preflight.index('Store::marker_preflight_for_worker(stage_path(&args), 0)') < preflight.index('require_activation_authority(&args)?;')
assert '.map_err(|_| ACTIVATION_RECOVERY_REQUIRED.to_owned())?;' in preflight
assert preflight.index('require_activation_authority(&args)?;') < preflight.index('lock.revalidate()')
assert preflight.index('require_activation_authority(&args)?;') < preflight.index('libc::geteuid()')
assert 'Store::reopen' not in preflight
assert 'StageGuard::admit' not in preflight
admit = source[source.index('fn admit_worker_stage('):helper_start]
assert 'Store::reopen_for_worker(stage, 0)' in admit
assert 'StageGuard::admit(store)' in admit
capture = dispatch[dispatch.index('CommandArgs::BeginCapture { .. } => {'):dispatch.index('CommandArgs::Finalize { .. } => {')]
assert 'return Err(super::refuse());' in capture, 'BeginCapture dispatch must still refuse'
assert 'capture_started = true' not in capture, 'READY must not mint capture receipt'
assert 'ActiveGuard::observe' not in capture, 'READY is not native capture witness'
assert 'let mut stage = admit_worker_stage(stage_path(&args))?;' in dispatch
harness = '''
use std::path::PathBuf;
type Result<T> = std::result::Result<T, String>;
enum CommandArgs { BeginCapture { stage: PathBuf }, Finalize { stage: PathBuf }, Inspect }
'''+helper+'''
fn main() {
    let stage = PathBuf::from("/unopened/administrator/private/stage");
    let args = CommandArgs::BeginCapture { stage: stage.clone() };
    assert_eq!(require_activation_authority(&args).unwrap_err(),
        "AUTO native capture requires actual native capture/guard readiness; private stage retained");
    match args { CommandArgs::BeginCapture { stage: after } => assert_eq!(after, stage), _ => unreachable!() }
    let args = CommandArgs::Finalize { stage: stage.clone() };
    assert_eq!(require_activation_authority(&args).unwrap_err(),
        "AUTO finalization requires transaction-owned systemd job, invocation and enablement compensation; private stage retained");
    match args { CommandArgs::Finalize { stage: after } => assert_eq!(after, stage), _ => unreachable!() }
    require_activation_authority(&CommandArgs::Inspect).unwrap();
}
'''
pathlib.Path(sys.argv[2]).write_text(harness)
PY
"${RUSTC:-rustc}" --edition=2021 -D warnings "$check_dir/check.rs" -o "$check_dir/check"
"$check_dir/check"
printf '%s\n' 'PASS: recovery marker preflight precedes capture/finalization refusal; refusal precedes root/lock/stage admission (host source helper only)'
