#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 -I - "$root" <<'PY'
import json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
policy = json.loads((root / "tools/windows/release/authenticode-policy.json").read_text())
assert policy == {
    "schema": "aegis_windows_authenticode_policy_v2",
    "publisher_certificate_sha256": None,
    "timestamp_protocol": "rfc3161",
    "timestamp_attribute_oid": "1.3.6.1.4.1.311.3.3.1",
    "rfc3161_structural_verifier": None,
    "provider_attestation_verifier": None,
    "authenticode_provider_sha256": None,
    "rfc3161_structural_verifier_sha256": None,
    "provider_attestation_verifier_sha256": None,
    "wintun_sha256": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
}
build = (root / "tools/windows/build-kit.ps1").read_text()
assert "signed_release = $false" in build
provider = (root / "tools/windows/release/Invoke-AuthenticodeProvider.ps1").read_text()
assert all(name in provider for name in ("Test-UnsignedCandidate.ps1", "ExpectedSourceCommit", "TimestampUrl"))
assert provider.index("Test-UnsignedCandidate.ps1") < provider.index("[IO.Directory]::CreateDirectory")
assert provider.index("Test-UnsignedCandidate.ps1") < provider.index("Invoke-PinnedAdapter -Lease $adapters.Provider")
assert provider.count("Test-UnsignedCandidate.ps1") == 2
assert "aegis-signing-input-" in provider and "Join-Path $snapshot $name" in provider
assert provider.rindex("Test-UnsignedCandidate.ps1") < provider.index("Invoke-PinnedAdapter -Lease $adapters.Provider")
assert "$providerInvocationSucceeded" in provider and "$providerExitCode -ne 0" in provider
assert "Read-AuthenticodePolicy.ps1" in provider
assert provider.index("$policyData = Read-AuthenticodePolicy") < provider.index("Test-UnsignedCandidate.ps1")
assert provider.index("$policyData = Read-AuthenticodePolicy") < provider.index("[IO.Directory]::CreateDirectory")
assert provider.index("$policyData = Read-AuthenticodePolicy") < provider.index("Open-AuthenticodeAdapters")
assert provider.index("Open-AuthenticodeAdapters") < provider.index("[IO.Directory]::CreateDirectory")
assert "RequireExactInputBinding = $true" in provider and "AttestationOutput = $attestationPath" in provider
assert "Close-AuthenticodeAdapters" in provider and "Assert-AuthenticodeAdaptersCurrent" in provider
assert "-RawSha256 ([ref]$policySha256)" in provider
assert "-ExpectedPolicySha256 $policySha256" in provider
preflight = (root / "tools/windows/release/Test-UnsignedCandidate.ps1").read_text()
for required in ("Get-FileHash", "Candidate payload SHA-256 mismatch", "Assert-PeMachine",
                 "duplicate or unexpected JSON keys", "ExpectedSourceCommit",
                 "pinned Wintun distribution", "Assert-NoReparseAncestry"):
    assert required in preflight
assert "windows-aarch64" in preflight and "[byte[]]@(0x64,0xaa)" in preflight
assert "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80" in preflight
inventory = (root / "tools/windows/release/ResearchInventory.ps1").read_text()
assert "Get-WindowsKitInventory" in preflight and "Assert-WindowsResearchMetadata" in preflight
for name in ("aegis-client.exe", "aegis-winctl.exe", "aegis-measure.exe", "aegis-transport-lab.exe"):
    assert name in inventory
assert "@(2,3,4,5)" in inventory
assert not re.search(r"&\s+.*aegis-(?:client|winctl)\.exe", preflight)
finalize = (root / "tools/windows/release/Finalize-WindowsRelease.ps1").read_text()
assert finalize.index("Test-AuthenticodePolicy.ps1") < finalize.index("schema = $(if ($inventory.Research) { 5 } else { 3 })")
assert finalize.index("schema = $(if ($inventory.Research) { 5 } else { 3 })") < finalize.index("CreateFromDirectory")
assert "signed_release = $true" in finalize
assert "manifest_signature_status = 'required_external_sidecar'" in finalize
assert "signed_release = $false" in finalize and ".authenticode-handoff.json" in finalize
assert ".delivery.json" not in finalize
assert "ProviderAttestations" in finalize and "UnsignedSha256 = $unsignedHash" in finalize
assert "Invoke-PinnedAdapter -Lease $adapters.Attestation" in finalize
assert finalize.index("Open-AuthenticodeAdapters") < finalize.index("New-PrivateReleaseSnapshot")
assert "-RawSha256 ([ref]$policySha256)" in finalize
assert "-ExpectedPolicySha256 $policySha256" in finalize
assert "New-PrivateReleaseSnapshot" in finalize and "Open-PrivateSnapshotLocks" in finalize
complete = (root / "tools/windows/release/Complete-WindowsRelease.ps1").read_text()
assert complete.index("Verify-WindowsRelease.ps1") < complete.index("signed_release = $true")
assert "manifest_signature_external_sidecar = $true" in complete
assert "Final ZIP/package mismatch" in complete and "signature must remain an external sidecar" in complete
assert "Detached manifest signature must remain outside" in complete
assert "PrivateSnapshot.ps1" in complete and "Open-PrivateSnapshotLocks" in complete
for required in ("ExpectedSourceCommit", "ExpectedWorkflow", "ExpectedRef", "ExpectedInnerZipSha256",
                 "ExpectedGithubArtifactDigest", "verify-provenance", "ProvenanceSignature"):
    assert required in complete
verify = (root / "tools/windows/release/Verify-WindowsRelease.ps1").read_text()
assert verify.index("-BootstrapOnly") < verify.index("& $winctl package verify-signature")
assert verify.count("Test-AuthenticodePolicy.ps1") == 2
assert "PrivateSnapshot.ps1" in verify and "--authenticode-policy $Policy" in verify
trust = (root / "tools/windows/aegis-winctl/src/package.rs").read_text()
assert "verify_signed_authenticode" in trust
assert "#[cfg(not(windows))]" in trust
assert "Err(invalid())" in trust
assert "trusted_policy.ok_or_else(invalid)?" in trust
assert "rfc3161_structural_verifier" in trust and "Has-Rfc3161" not in trust
assert "provider_attestation_verifier" in trust and "VerifyProvenance" in trust
assert "aegis_windows_authenticode_policy_v2" in trust and "adapter::AdapterLease::acquire" in trust
assert trust.index("let structural = adapter::AdapterLease::acquire") < trust.index("let result = authenticode::invoke(")
rust_custody = (root / "tools/windows/aegis-winctl/src/package/adapter.rs").read_text()
for required in ("FILE_SHARE_READ", "GetFileInformationByHandle", "GetFinalPathNameByHandleW",
                 "nNumberOfLinks != 1", "held_entry_denies"):
    assert required in rust_custody
auth = (root / "tools/windows/release/Test-AuthenticodePolicy.ps1").read_text()
assert "Structural RFC3161 verification failed" in auth and "Test-ContainsBytes" not in auth
assert "Read-AuthenticodePolicy.ps1" in auth
assert auth.index("$policyData = Read-AuthenticodePolicy") < auth.index("Get-AuthenticodeSignature")
assert "Invoke-PinnedAdapter -Lease $adapters.Structural" in auth
assert "$expectedPolicy.ExpectedSha256 = $ExpectedPolicySha256" in auth
policy_reader = (root / "tools/windows/release/Read-AuthenticodePolicy.ps1").read_text()
for required in ("ConvertFrom-Json", "Captures", "StringComparer]::Ordinal", "UTF8Encoding",
                 "65536", "duplicate or unexpected JSON keys", "-isnot [string]",
                 "unpaired Unicode escape", "wintun_sha256 -cne", "timestamp_protocol -cne",
                 "timestamp_attribute_oid -cne", "RegexOptions]::CultureInvariant",
                 "FromSeconds(1)", "RegexMatchTimeoutException"):
    assert required in policy_reader
assert "& $" not in policy_reader and "CreateDirectory" not in policy_reader
assert policy_reader.index("$sha.ComputeHash($bytes)") < policy_reader.index("$policyData = $raw | ConvertFrom-Json")
assert policy_reader.index("$digest -cne $ExpectedSha256.ToLowerInvariant()") < policy_reader.index("$raw = [Text.UTF8Encoding]")
assert "$RawSha256.Value = $digest" in policy_reader
custody = (root / "tools/windows/release/AdapterCustody.ps1").read_text()
for required in ("CreateFileW", "GetFinalPathNameByHandleW", "GetFileInformationByHandle",
                 "info.Links!=1", "directory ? 3u : 1u", "lease.Verify()"):
    assert required in custody
signer = (root / "scripts/sign-windows-release-manifest.sh").read_text()
assert signer.index("verify-windows-manifest-signing-handoff.py") < signer.index("openssl pkeyutl -sign")
assert 'aegis-manifest-sign.' in signer and 'windows-release.provenance.json' in signer
assert 'SIDECAR_DIRECTORY' in signer and 'manifest_sig="$4/manifest.json.sig"' in signer
assert 'archive_name="${2##*/}"' in signer and '--archive "$private/$archive_name"' in signer
raw_signer = (root / "scripts/sign-release-manifest.sh").read_text()
assert "Windows manifests must use sign-windows-release-manifest.sh" in raw_signer
assert 'aegis-manifest-sign.' in raw_signer and '-in "$private/manifest.json"' in raw_signer
workflow = (root / ".github/workflows/windows-package.yml").read_text()
assert "windows-candidate/**" in workflow
assert "Candidate only: no signing key" in workflow
assert "build-kit.ps1 -IncludeResearchOperators -Output" in workflow
assert "foreach ($name in $inventory.Executables)" in provider
assert "$expectedAttestations = $inventory.Attestations" in finalize
assert "-Signed -UnsignedFiles $candidate.files" in finalize
assert finalize.index("-Signed -UnsignedFiles $candidate.files") < finalize.index("[IO.Directory]::CreateDirectory($destination)")
assert "Research unsigned metadata/candidate digest mismatch" in inventory
assert "research::validate_for_build" in trust
print("windows Authenticode release contract: PASS (promotion intentionally unprovisioned)")
PY
if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoLogo -NoProfile -NonInteractive -File "$root/scripts/windows/test-authenticode-preflight.ps1" -RepoRoot "$root"
  pwsh -NoLogo -NoProfile -NonInteractive -File "$root/scripts/windows/test-authenticode-policy-digest.ps1" -RepoRoot "$root"
elif command -v powershell.exe >/dev/null 2>&1; then
  powershell.exe -NoLogo -NoProfile -NonInteractive -File "$root/scripts/windows/test-authenticode-preflight.ps1" -RepoRoot "$root"
  powershell.exe -NoLogo -NoProfile -NonInteractive -File "$root/scripts/windows/test-authenticode-policy-digest.ps1" -RepoRoot "$root"
elif [[ "${CI:-}" == "true" ]]; then
  echo 'PowerShell is required for the Authenticode preflight refusal regression in CI' >&2
  exit 1
else
  echo 'Authenticode runtime preflight regression not run: PowerShell unavailable locally'
fi
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
python3 -I - "$fixture" <<'PY'
import hashlib, json, pathlib, sys, zipfile
r = pathlib.Path(sys.argv[1]); source = "a" * 40
manifest = {"schema": 3, "platform": "windows-x86_64", "source_commit": source,
            "signed_release": True, "authenticode": {}, "files": {}}
(r / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
names = ["README.txt", "WINTUN-LICENSE.txt", "aegis-client.exe", "aegis-winctl.exe", "manifest.json", "wintun.dll"]
for name in names:
    if name != "manifest.json": (r / name).write_bytes(name.encode())
with zipfile.ZipFile(r / "windows-signed-release.zip", "w") as z:
    for name in names: z.write(r / name, name)
archive_hash = hashlib.sha256((r / "windows-signed-release.zip").read_bytes()).hexdigest()
handoff = {"schema":"aegis_windows_authenticode_handoff_v1", "source_commit":source,
           "workflow":"example-org/aegis:.github/workflows/windows-package.yml", "ref":"refs/heads/main",
           "archive":"windows-signed-release.zip", "archive_sha256":archive_hash,
           "manifest_sha256":hashlib.sha256((r / "manifest.json").read_bytes()).hexdigest(),
           "signed_release":False, "manifest_signature_status":"required_external_sidecar"}
(r / "handoff.json").write_text(json.dumps(handoff), encoding="utf-8")
(r / "digest").write_text(archive_hash)
PY
digest="$(<"$fixture/digest")"
python3 -I "$root/scripts/verify-windows-manifest-signing-handoff.py" \
  --manifest "$fixture/manifest.json" --archive "$fixture/windows-signed-release.zip" --handoff "$fixture/handoff.json" \
  --expected-source "$(printf 'a%.0s' {1..40})" \
  --expected-workflow 'example-org/aegis:.github/workflows/windows-package.yml' \
  --expected-ref refs/heads/main --expected-inner-zip-sha256 "$digest" \
  --expected-github-artifact-digest "$(printf 'c%.0s' {1..64})" \
  --provenance-output "$fixture/provenance.json"
python3 -I - "$fixture/provenance.json" "$digest" <<'PY'
import json, pathlib, sys
p = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert p["inner_zip_sha256"] == sys.argv[2]
assert p["github_artifact_digest"] == "c" * 64
assert p["inner_zip_sha256"] != p["github_artifact_digest"]
PY
# Exercise the wrapper's private staging with the finalizer's real basename.
# A temporary wrong key must fail at the pinned-key check, after the handoff
# verifier has accepted windows-signed-release.zip rather than a renamed ZIP.
mkdir "$fixture/sidecars"
openssl genpkey -algorithm Ed25519 -out "$fixture/wrong-key.pem" >/dev/null 2>&1
set +e
wrapper_output="$(AEGIS_MANIFEST_SIGNING_KEY="$fixture/wrong-key.pem" \
  "$root/scripts/sign-windows-release-manifest.sh" "$fixture/manifest.json" \
  "$fixture/windows-signed-release.zip" "$fixture/handoff.json" "$fixture/sidecars" \
  "$(printf 'a%.0s' {1..40})" 'example-org/aegis:.github/workflows/windows-package.yml' \
  refs/heads/main "$digest" "$(printf 'c%.0s' {1..64})" 2>&1)"
wrapper_status=$?
set -e
[[ $wrapper_status -ne 0 && "$wrapper_output" == *"bounded Windows manifest signing handoff: PASS"* ]]
[[ -z "$(find "$fixture/sidecars" -mindepth 1 -maxdepth 1 -print -quit)" ]]
if python3 -I "$root/scripts/verify-windows-manifest-signing-handoff.py" \
  --manifest "$fixture/manifest.json" --archive "$fixture/windows-signed-release.zip" --handoff "$fixture/handoff.json" \
  --expected-source "$(printf 'a%.0s' {1..40})" \
  --expected-workflow 'example-org/aegis:.github/workflows/windows-package.yml' \
  --expected-ref refs/heads/main --expected-inner-zip-sha256 "$(printf 'b%.0s' {1..64})" \
  --expected-github-artifact-digest not-used --provenance-output "$fixture/rejected.json" >/dev/null 2>&1; then
  echo 'signing handoff accepted a wrong trusted inner ZIP digest' >&2; exit 1
fi
