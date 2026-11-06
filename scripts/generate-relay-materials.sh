#!/usr/bin/env bash
set -euo pipefail

# The private keys below are written unencrypted. Under the default umask 022 they
# would land world-readable (0644), and ca-key.pem is the relay's root of trust —
# anyone who can read it can mint certificates a pinning client will accept.
# install.sh tightens these afterwards, but this script is also documented for
# standalone operator use, where nothing else would.
umask 077

usage() {
  cat <<'EOF'
Usage:
  scripts/generate-relay-materials.sh <output-dir> <server-name> [relay-host]

Generates:
  ca.pem
  ca-key.pem
  server.pem
  server-key.pem

`server-name` is used as the primary TLS identity.
`relay-host` is optionally added to SAN if it differs from `server-name`.
The local CA uses the same deployment identity as its subject; it adds no
product-wide issuer tag. Existing certificates and client trust do not migrate.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage >&2
  exit 1
fi

OUT_DIR="$1"
SERVER_NAME="$2"
RELAY_HOST="${3:-$2}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate relay certificates" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

is_ip_literal() {
  local value="$1"
  if [[ "${value}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 0
  fi
  if [[ "${value}" == *:* ]]; then
    return 0
  fi
  return 1
}

append_san_entry() {
  local identity="$1"
  local entry=""
  local existing=""
  if is_ip_literal "${identity}"; then
    entry="IP:${identity}"
  else
    entry="DNS:${identity}"
  fi
  for existing in "${san_entries[@]:-}"; do
    if [[ "${existing}" == "${entry}" ]]; then
      return 0
    fi
  done
  san_entries+=("${entry}")
}

san_entries=("DNS:localhost" "IP:127.0.0.1")
append_san_entry "${SERVER_NAME}"
if [[ "${RELAY_HOST}" != "${SERVER_NAME}" ]]; then
  append_san_entry "${RELAY_HOST}"
fi

san_csv=""
for entry in "${san_entries[@]}"; do
  if [[ -n "${san_csv}" ]]; then
    san_csv+=","
  fi
  san_csv+="${entry}"
done

ext_file="${OUT_DIR}/server.ext"
cat > "${ext_file}" <<EOF
basicConstraints = CA:FALSE
subjectAltName = ${san_csv}
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment
EOF

# Reuse the already disclosed TLS identity instead of a product-wide issuer tag.
# This private CA still requires explicit client trust; it is not a public CA.
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
  -keyout "${OUT_DIR}/ca-key.pem" \
  -out "${OUT_DIR}/ca.pem" \
  -subj "/CN=${SERVER_NAME}" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
  -keyout "${OUT_DIR}/server-key.pem" \
  -out "${OUT_DIR}/server.csr" \
  -subj "/CN=${SERVER_NAME}" >/dev/null 2>&1

openssl x509 -req -in "${OUT_DIR}/server.csr" \
  -CA "${OUT_DIR}/ca.pem" \
  -CAkey "${OUT_DIR}/ca-key.pem" \
  -CAcreateserial \
  -out "${OUT_DIR}/server.pem" \
  -days 825 \
  -extfile "${ext_file}" >/dev/null 2>&1

rm -f "${OUT_DIR}/server.csr" "${OUT_DIR}/ca.srl" "${ext_file}"

# Belt and braces on top of the umask above: state the intent explicitly so the
# keys stay owner-only even if this script is sourced somewhere that resets it.
chmod 0600 "${OUT_DIR}/ca-key.pem" "${OUT_DIR}/server-key.pem"
chmod 0644 "${OUT_DIR}/ca.pem" "${OUT_DIR}/server.pem"

# v0.3.1 SPKI public-key pin for TLS bootstrap.
# Computed once при cert generation; install.sh reads this file и
# embeds в напечатанный CLIENT ONBOARDING URL (&pin=sha256//<base64>)
# чтобы client-side curl мог validate cert через --pinnedpubkey без
# доверия системному CA store. Solves the chicken-and-egg of bundle
# download over self-signed TLS (CA is INSIDE the bundle).
openssl x509 -pubkey -noout -in "${OUT_DIR}/server.pem" \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64 \
  | tr -d '\n' > "${OUT_DIR}/server.spki.b64"
chmod 0644 "${OUT_DIR}/server.spki.b64"
echo "Wrote SPKI public-key pin to ${OUT_DIR}/server.spki.b64"

echo "Generated relay CA and server certs in ${OUT_DIR}"
