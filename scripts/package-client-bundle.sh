#!/usr/bin/env bash
set -euo pipefail

# The archive contains the relay auth token.  Never inherit a permissive caller
# umask and never expose a partially written final archive path.
umask 077

usage() {
  cat <<'EOF'
Usage:
  scripts/package-client-bundle.sh <bundle-dir> <output-archive>

Packages a rendered client-bundle directory into a tar.gz archive suitable for
transport or remote bundle-url installation.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 1
fi

BUNDLE_DIR="$1"
OUTPUT_ARCHIVE="$2"

if [[ ! -d "${BUNDLE_DIR}" ]]; then
  echo "Bundle directory is missing: ${BUNDLE_DIR}" >&2
  exit 1
fi
if [[ -f "${BUNDLE_DIR}/bundle.json" ]]; then
  echo "Public device bundles use the local directory enrollment path; this legacy archive format is not supported for them." >&2
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR}/aegis-client.toml" || ! -f "${BUNDLE_DIR}/ca.pem" ]]; then
  echo "Bundle directory must contain aegis-client.toml and ca.pem" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT_ARCHIVE}")"
OUTPUT_DIR="$(cd "$(dirname "${OUTPUT_ARCHIVE}")" && pwd)"
OUTPUT_NAME="$(basename "${OUTPUT_ARCHIVE}")"
TEMP_ARCHIVE="$(mktemp "${OUTPUT_DIR}/.${OUTPUT_NAME}.tmp.XXXXXX")"
cleanup_temp_archive() {
  rm -f "${TEMP_ARCHIVE}"
}
trap cleanup_temp_archive EXIT
chmod 0600 "${TEMP_ARCHIVE}"

tar -C "$(dirname "${BUNDLE_DIR}")" -czf "${TEMP_ARCHIVE}" "$(basename "${BUNDLE_DIR}")"
mv -f "${TEMP_ARCHIVE}" "${OUTPUT_ARCHIVE}"
chmod 0600 "${OUTPUT_ARCHIVE}"
trap - EXIT

cat <<EOF
Client bundle archive created
---------------------------
Bundle directory:
  ${BUNDLE_DIR}

Archive:
  ${OUTPUT_ARCHIVE}
EOF
