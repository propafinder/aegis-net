#!/usr/bin/env bash
# Guard the operator-facing shell entry points against constructs that bash 3.2
# mis-parses.
#
# bash 3.2 is still /bin/bash on macOS, and `#!/usr/bin/env bash` picks it up
# whenever a newer bash is not first in PATH. The dangerous part is that the
# failure is not a syntax error: bash 3.2 mis-tracks quoting across a heredoc
# nested inside command substitution and silently swallows whatever follows.
#
# That is not hypothetical. `install.sh` had
#
#     install_text_file "${dropin}/10-dedicated-uid.conf" 0644 "$(cat <<EOF
#     ...
#     EOF
#     )"
#
# and bash 3.2 ate the next function definition whole, so a client install died
# with `remove_client_dedicated_uid_dropin: command not found` roughly 2000
# lines later. `bash -n` passes on the file, so nothing caught it.
#
# Use a variable instead:
#
#     local content=''
#     IFS= read -r -d '' content <<EOF || true
#     ...
#     EOF
#     install_text_file "${dest}" 0644 "${content%$'\n'}"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

status=0

# Scope: the two scripts an operator executes on their own machine. Everything
# under scripts/ is developer and fleet tooling that runs on Linux with a modern
# bash, so holding it to bash 3.2 would be busywork.
ENTRY_POINTS=(
  "install.sh"
  "bootstrap-install.sh"
)

# Strip comments before matching: the explanation at the top of this file, and
# the notes left at each fixed call site, both contain the pattern verbatim.
without_comments() {
  sed 's/[[:space:]]*#.*$//' "$1"
}

for script in "${ENTRY_POINTS[@]}"; do
  [[ -f "${script}" ]] || {
    echo "FAIL: operator entry point missing: ${script}" >&2
    status=1
    continue
  }

  # A heredoc opened inside a command substitution. bash 3.2 parses the body
  # for quotes here, so whether the script survives depends on the parity of
  # the apostrophe count in the body — one edit away from silent breakage.
  hits="$(without_comments "${script}" | grep -nE '\$\(.*<<-?[[:space:]]*'"'"'?[A-Za-z_]' || true)"
  if [[ -n "${hits}" ]]; then
    echo "FAIL: ${script}: heredoc nested inside command substitution" >&2
    printf '%s\n' "${hits}" >&2
    echo "  Read the heredoc into a variable and pipe it (see this script's header)." >&2
    status=1
  fi

  # bash 4+ constructs. These do error clearly on 3.2, but they still break a
  # macOS operator, so an entry point must not use them.
  check_bash4() {
    local pattern="$1" label="$2"
    local found
    found="$(without_comments "${script}" | grep -nE "${pattern}" || true)"
    if [[ -n "${found}" ]]; then
      echo "FAIL: ${script}: ${label}" >&2
      printf '%s\n' "${found}" >&2
      status=1
    fi
  }
  check_bash4 '(^|[^[:alnum:]_])(mapfile|readarray)([^[:alnum:]_]|$)' 'mapfile/readarray is bash 4+'
  check_bash4 'declare[[:space:]]+-[A-Za-z]*A[[:space:]]' 'associative arrays are bash 4+'
  check_bash4 '\$\{[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?(,,|\^\^)' '${var,,} / ${var^^} is bash 4+'
done

# Parse under whatever /bin/bash this host has. On macOS that is 3.2, which is
# the case that matters; on Linux runners it is a modern bash and this is just
# a cheap extra syntax check.
if [[ -x /bin/bash ]]; then
  for script in "${ENTRY_POINTS[@]}"; do
    [[ -f "${script}" ]] || continue
    /bin/bash -n "${script}" || {
      echo "FAIL: ${script}: /bin/bash cannot parse it" >&2
      status=1
    }
  done
fi

if [[ "${status}" -eq 0 ]]; then
  echo "shell bash 3.2 portability contract: ok"
fi
exit "${status}"
