# Pins must have arrived through the operator's authenticated channel.
[[ "$(uname -s)" == Linux ]] || { printf '%s\n' 'This installer is for Linux.' >&2; exit 1; }
case "$(uname -m)" in
  x86_64|amd64)
    manifest_name=client-release.manifest.json
    manifest_sha="$x86_manifest_sha"; signature_sha="$x86_signature_sha" ;;
  aarch64|arm64)
    manifest_name=client-release.manifest-aarch64.json
    manifest_sha="$arm_manifest_sha"; signature_sha="$arm_signature_sha" ;;
  *) printf '%s\n' 'This release supports Linux x86_64 and ARM64.' >&2; exit 1 ;;
esac
hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    printf '%s\n' 'A SHA-256 utility is required.' >&2; return 1
  fi
}
fetch_pinned() {
  local leaf="$1" expected="$2" output="$3" base
  for base in "${sources[@]}"; do
    rm -f -- "$output"
    if command -v curl >/dev/null 2>&1; then
      if ! curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 90 "$base/$leaf" -o "$output"; then continue; fi
    elif command -v wget >/dev/null 2>&1; then
      if ! wget --https-only --timeout=30 --tries=1 -q -O "$output" "$base/$leaf"; then continue; fi
    else
      printf '%s\n' 'Install curl or wget from your operating system repository.' >&2; return 1
    fi
    if [ "$(hash_file "$output")" = "$expected" ]; then return 0; fi
    printf '%s\n' 'Download differs from the selected release.' >&2
  done
  printf '%s\n' 'The selected release is unavailable from these sources.' >&2; return 1
}
fetch_pinned bootstrap-install.sh "$bootstrap_sha" "$work/bootstrap-install.sh"
fetch_pinned "$manifest_name" "$manifest_sha" "$work/release.manifest.json"
fetch_pinned "$manifest_name.sig" "$signature_sha" "$work/release.manifest.json.sig"
source_args=(--source "file://$work/release.manifest.json")
for base in "${sources[@]}"; do
  source_args+=(--source "$base/client-release.manifest.json")
done
# Clear permissive environment overrides. The bootstrap verifies the pinned
# local manifest signature, then fetches only the named archive by signed hash.
AEGIS_INSTALL_ALLOW_UNSIGNED=0 bash "$work/bootstrap-install.sh" client "${source_args[@]}" "$@"
