# Never execute verified bytes through a daemon-writable TMPDIR ancestor.
# Resolve the OS temp directory once, then require root-owned protected
# ancestors. A root-owned sticky temp directory permits private child creation.
temp_root="$(cd /tmp && pwd -P)"
checked="$temp_root"
while [[ "$checked" != / ]]; do
  [[ -d "$checked" && ! -L "$checked" ]] || { echo 'Unsafe installer temporary directory.' >&2; exit 1; }
  if [[ "${OSTYPE:-}" == darwin* ]]; then
    owner="$(stat -f %u "$checked")"; mode="$(stat -f %Op "$checked")"
  else
    owner="$(stat -c %u "$checked")"; mode="$(stat -c %a "$checked")"
  fi
  [[ "$owner" == 0 ]] || { echo 'Installer temporary ancestors must belong to root.' >&2; exit 1; }
  if (( (8#$mode & 022) != 0 && (8#$mode & 01000) == 0 )); then
    echo 'Installer temporary ancestors are writable without sticky protection.' >&2; exit 1
  fi
  checked="$(dirname "$checked")"
done
work="$(mktemp -d "$temp_root/aegis-client-launcher.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
