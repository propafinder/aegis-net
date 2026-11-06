# AEGIS secret handling

The rules for the secret classes AEGIS touches. Applies to operators,
scripts, CI, docs, and artifacts.

## The secrets

| Secret | What it is | Blast radius if leaked |
|---|---|---|
| **Cloudflare API token** (`CF_API_TOKEN`) | Manages the fronting DNS zone | Zone takeover / traffic redirection |
| **Origin private key** (`cf-origin-key.pem`, `server-key.pem`) | Relay TLS identity | Impersonation of the relay origin |
| **Legacy relay `auth_token`** | Shared client↔relay authentication for legacy profiles | Anyone can use that relay profile |
| **Bundle token** (`/bundle?token=…`) | One-time download credential for a legacy private access bundle | One bundle download; may contain legacy shared credentials |
| **Device private key / invitation** | Individual inner-TLS identity / enrollment authority | Device impersonation / invitation redemption |

## Rules

- **Never put a secret in `argv`.** It shows in `ps`, shell history, and process
  listings. Read tokens from a protected file, not environment values or an inline
  command-line flag, when
  generating bundles. (`scripts/issue-fronted-bundle.sh` reads `auth_token` from the
  server config and never echoes it.)
- **Never print** `auth_token`, the CF API token, or any private key to stdout/stderr/logs.
- **Bundle URLs** remain only in private records. Issue with
  `--url-output /absolute/private/client-access-url.txt`; transfer the record
  privately and install with `--bundle-url-file /absolute/private/client-access-url.txt`.
  Use mode `0600`, one hard link, a regular file, and trusted private ancestors;
  root invocations require root ownership. Inline `--bundle-url` is refused.
  Prefer bounded TTL and one-time redemption; inspect issuance receipts before retrying.
- **Never commit** secrets to the repo, artifacts, docs, tickets, or screenshots.
  Artifacts record *status* (`http_code`, `verdict`, `version_matches`), never the
  secret value. Public integrity hashes (release `sha256`) are not secrets.
- **Temp files** holding a key or bundle: `chmod 600`, delete after use
  (`trap 'rm -rf "$WORK"' EXIT`). Unsafe input ownership, links and writable
  files/directories are refused. Published root:service config is `0640` in
  `0750` directories; owner-only identity/URL files remain `0600`.
- **CA delivery vs pinning:** a legacy fronted client may validate the Cloudflare
  edge with system roots or an explicitly supplied trusted edge CA. An enrolled
  client requires the independently authenticated profile's pinned
  `outer-ca.pem`; it does not silently substitute system roots. Keep that outer
  edge trust separate from `inner-ca.pem` and the device issuer CA. Cloudflare
  *Origin* CA authenticates the edge-to-origin connection, or an explicitly
  configured direct-origin path; it is not the client-to-edge trust root.
  Independently trusted Origin CA/SPKI pins for direct-origin downloads belong
  only to that selected direct path.
- **Generated commands and reports** contain private input paths and status only.
  They never carry a real token/URL value, even in the operator-facing command.
  Private paths and retained records still require careful custody.
- **Rotate / revoke** any secret that was exposed: regenerate the relay `auth_token`
  (re-issues bundles), rotate the Origin cert/key, and **revoke a Cloudflare API
  token immediately after the change it was needed for** — do not leave it live.

## Secret scan before commit

```bash
git diff --cached | grep -iE 'PRIVATE KEY|auth_token|bundle\?token=|CF_API_TOKEN|Authorization: Bearer|cfat_' \
  && echo "STOP: possible secret" || echo "clean"
```
A match on a `<redacted>`/placeholder or a public `sha256` is fine; a real value is not.
