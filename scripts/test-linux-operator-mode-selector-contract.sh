#!/usr/bin/env bash
# Contract: the Linux operator mode selector exposes a stable, honest mode
# vocabulary via `aegis-client operator`. Known modes plan cleanly; invalid modes
# are rejected; privilege requirements are present; wide modes need confirm/root;
# bundle tokens are redacted; and no plan overclaims.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
command -v python3 >/dev/null || fail "python3 required"

# Always build the current checkout. Preferring an arbitrary pre-existing
# release binary made this source contract validate stale code on developer
# hosts while CI happened to validate debug code.
BIN="${AEGIS_CLIENT_BIN:-${ROOT}/target/debug/aegis-client}"
if [[ -z "${AEGIS_CLIENT_BIN:-}" ]]; then
  ( cd "$ROOT" && cargo build -q -p aegis-client ) || fail "cargo build failed"
fi
[[ -x "$BIN" ]] || fail "aegis-client binary not found"

MODES=(server client-socks client-wide-redirect client-wide-tproxy client-wide-nfqueue-observer client-ipv6-tun-lab cloudflare-fronted masque-direct)

# 1) Every known mode plans cleanly with the required fields + no overclaim.
TMP="$(mktemp)"
PRIVATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-operator-private.XXXXXX")"
chmod 0700 "$PRIVATE_DIR"
trap 'rm -f "$TMP"; rm -rf "$PRIVATE_DIR"' EXIT
for m in "${MODES[@]}"; do
  "$BIN" operator plan --mode "$m" >"$TMP" 2>/dev/null || fail "plan failed for mode $m"
  python3 - "$m" "$TMP" <<'PY'
import json, sys
m = sys.argv[1]
d = json.load(open(sys.argv[2]))
assert d["verdict"] == "PLAN_OK", f"{m}: verdict"
p = d["plan"]
for k in ("mode","privilege","requires_root","backend","traffic_coverage",
          "transport","config_template","systemd_unit","rollback_steps",
          "claimed","not_claimed"):
    assert k in p, f"{m}: missing plan.{k}"
assert p["mode"] == m, f"{m}: slug mismatch"
assert isinstance(p["rollback_steps"], list) and p["rollback_steps"], f"{m}: rollback_steps"
# Scan affirmative parts only; not_claimed legitimately negates these phrases.
scan = dict(p); scan.pop("not_claimed", None)
blob = json.dumps(scan).lower()
for bad in ("undetectable","browser-identical","perfect stealth","production-wide ipv6"):
    assert bad not in blob, f"{m}: overclaim {bad}"
PY
done

# 2) Wide modes require root; light modes do not.
for m in client-wide-redirect client-wide-tproxy client-wide-nfqueue-observer client-ipv6-tun-lab; do
  out="$("$BIN" operator plan --mode "$m")"
  case "$out" in *'"requires_root": true'*) ;; *) fail "$m must require root" ;; esac
done
for m in client-socks cloudflare-fronted masque-direct; do
  out="$("$BIN" operator plan --mode "$m")"
  case "$out" in *'"requires_root": false'*) ;; *) fail "$m must not require root" ;; esac
done

# 3) Invalid + missing mode are rejected (fail fast).
if "$BIN" operator plan --mode bogus-mode >/dev/null 2>&1; then fail "invalid mode accepted"; fi
if "$BIN" operator plan >/dev/null 2>&1; then fail "missing mode accepted"; fi

# 4) The verified Cloudflare contour is gRPC-only. Auto resolves to gRPC;
# RFC 8441 WebSocket, legacy TLS and MASQUE are rejected.
out="$("$BIN" operator plan --mode cloudflare-fronted)"
case "$out" in *'"transport": "grpc_stream"'*) ;; *) fail "cloudflare-fronted auto must resolve to grpc_stream" ;; esac
"$BIN" operator plan --mode cloudflare-fronted --transport grpc_stream >/dev/null 2>&1 \
  || fail "cloudflare-fronted + grpc_stream should be accepted"
if "$BIN" operator plan --mode cloudflare-fronted --transport https_ws >/dev/null 2>&1; then
  fail "cloudflare-fronted + https_ws should be rejected until forced edge proof"
fi
if "$BIN" operator plan --mode cloudflare-fronted --transport legacy_tls >/dev/null 2>&1; then
  fail "cloudflare-fronted + legacy_tls should be rejected"
fi
if "$BIN" operator plan --mode cloudflare-fronted --transport masque_direct >/dev/null 2>&1; then
  fail "cloudflare-fronted + masque_direct should be rejected"
fi

# 5) ipv6-tun-lab refuses a global/default prefix.
if "$BIN" operator plan --mode client-ipv6-tun-lab --controlled-prefix 2001:db8::/64 >/dev/null 2>&1; then
  fail "global prefix accepted for ipv6-tun-lab"
fi
"$BIN" operator plan --mode client-ipv6-tun-lab --controlled-prefix fd00:ae61::/64 >/dev/null 2>&1 \
  || fail "ULA prefix should be accepted"

# 6) Bundle token is redacted (never printed).
( umask 077; printf '%s' 'https://h.example.org/b.tgz?token=SUPERSECRET' > "$PRIVATE_DIR/access-url" )
out="$("$BIN" operator plan --mode client-socks --bundle-url-file "$PRIVATE_DIR/access-url" 2>/dev/null)"
echo "$out" | grep -q 'h.example.org' || fail "bundle host should be echoed"
echo "$out" | grep -q 'SUPERSECRET' && fail "bundle token must be redacted"

# 7) Apply without confirm is plan-only (no privileged mutation).
out="$("$BIN" operator apply --mode client-socks 2>/dev/null)"
echo "$out" | grep -q 'PLAN_ONLY_NEEDS_CONFIRM' || fail "apply without --apply-confirm must be plan-only"
echo "$out" | grep -q '"applied": false' || fail "apply without confirm must not apply"

# Deprecated split/equals forms refuse before writing a result and never
# reflect synthetic URL material through Clap's unknown-argument diagnostics.
for form in split equals; do
  result="$PRIVATE_DIR/rejected-$form.json"
  if [[ "$form" == split ]]; then
    deprecated=(--bundle-url 'https://fixture.invalid/?token=INLINE_PRIVATE_SENTINEL')
  else
    deprecated=('--bundle-url=https://fixture.invalid/?token=INLINE_PRIVATE_SENTINEL')
  fi
  if "$BIN" operator plan --mode client-socks --result-json "$result" "${deprecated[@]}" >"$PRIVATE_DIR/refusal-output" 2>&1; then
    fail "deprecated inline form accepted"
  fi
  [[ ! -e "$result" ]] || fail "deprecated form created operator output"
  grep -q 'INLINE_PRIVATE_SENTINEL' "$PRIVATE_DIR/refusal-output" && fail "deprecated form reflected private URL"
  grep -q 'Use --bundle-url-file' "$PRIVATE_DIR/refusal-output" || fail "static migration guidance missing"
done

echo "PASS: linux operator mode selector contract"
