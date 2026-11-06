#!/bin/sh
set -eu

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
run_root=$(mktemp -d /private/tmp/aegis-r75-diagnostic.XXXXXX)
cleanup() {
    rm -rf -- "$run_root"
}
trap cleanup EXIT HUP INT TERM

common='-std=c11 -fblocks -Wall -Wextra -Werror -mmacosx-version-min=14.4'
# Compile the two production-shaped objects against the actual macOS SDK.
# The test translation unit mocks only the absent XPC service's peer EUID.
clang $common -I "$source_dir" -c "$source_dir/diagnostic_gate.c" -o "$run_root/gate.o"
clang $common -I "$source_dir" -c "$source_dir/diagnostic_reap_owner.c" -o "$run_root/reap.o"
clang $common -I "$source_dir" "$source_dir/link_probe.c" \
    "$run_root/gate.o" "$run_root/reap.o" -o "$run_root/link_probe"
"$run_root/link_probe"
if nm -g "$run_root/gate.o" | grep -q 'aegis_r66_gate_accept_terminal'; then
    echo 'raw dictionary terminal symbol must not be exported' >&2
    exit 1
fi
clang $common "$source_dir/test_child.c" -o "$run_root/child"
clang $common -I "$source_dir" "$source_dir/test_diagnostic_chain.c" -o "$run_root/test"
: > "$run_root/lock"
"$run_root/test" "$run_root/child" "$run_root/lock" "$run_root/ready"
