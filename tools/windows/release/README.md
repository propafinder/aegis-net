# Private candidate and signed-release tooling

PowerShell stages unsigned candidates, snapshots private inputs, reads signing policy, invokes the reviewed Authenticode provider, finalizes and verifies release inventories.

### Contracts and limits

Legacy schemas 2/3 and research-enabled schemas 4/5 are distinct. The existing research-enabled kit includes the restricted measure and transport-lab with client/winctl, validating PE architecture and paired producer metadata. It is a mixed engineering kit. `build-kit.ps1 -IncludeResearchOperators` additionally writes a separate `KIT.research.zip` output containing only the restricted pair and the exact bound research guide/capture tree. Its manifest and every ZIP member are checked separately; this unsigned research-only sibling is not a signed output of the existing Authenticode kit finalizer. Missing production certificate/timestamp/provider inputs remain blockers; an unsigned private CI kit cannot claim production signing.

### Project license inventory and signing handoff

The Rust package builder declares `project_licenses = true` and includes the
exact root `LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE` files with manifest
SHA-256 entries. The declaration is an optional Boolean; absent or `false`
retains the exact previous payload set, while `true` requires all three files.
Wrong declaration types, partial inventories and undeclared extras are refused.
Schemas 2/3 and 4/5, executable lists, Wintun licensing and research-tool
requirements retain their existing meaning.

[ResearchInventory.ps1](ResearchInventory.ps1) and
[Test-UnsignedCandidate.ps1](Test-UnsignedCandidate.ps1) bind the declared files
and verify their actual hashes. [PrivateSnapshot.ps1](PrivateSnapshot.ps1)
retains that same inventory. [Finalize-WindowsRelease.ps1](Finalize-WindowsRelease.ps1)
checks the project texts before copying and again against the original
candidate hashes after copying, and carries the Boolean into the final manifest.
The [Python signing-handoff verifier](../../../scripts/verify-windows-manifest-signing-handoff.py)
checks the same declared project texts in the bound ZIP. These checks do not
change independently provisioned signing trust or make an unsigned kit signed.

Eight selected portable Rust package tests passed locally. The synthetic
finalizer regression covers legacy and licensed controls plus refusal cases;
it has not run locally because PowerShell is unavailable. Windows PowerShell
5.1/PowerShell 7 execution and exact-commit CI acceptance remain pending.
Package delivery does not assert that installation copies these project texts,
or that full third-party/vendored notices, runtime SBOM or native lifecycle
acceptance are complete.

### Entry points and maintenance

KitCargoBuild.ps1 builds each package with its intended feature set. ResearchStage/ResearchInventory bind tools and unsigned hashes; Finalize-WindowsRelease binds original candidate files before output. AdapterCustody/PrivateSnapshot preserve input custody; Verify-WindowsRelease verifies output. Never copy secrets into examples or bypass policy with a development result.

### Local map

- [AdapterCustody.ps1](AdapterCustody.ps1)
- [Complete-WindowsRelease.ps1](Complete-WindowsRelease.ps1)
- [Finalize-WindowsRelease.ps1](Finalize-WindowsRelease.ps1)
- [Invoke-AuthenticodeProvider.ps1](Invoke-AuthenticodeProvider.ps1)
- [KitCargoBuild.ps1](KitCargoBuild.ps1)
- [PrivateSnapshot.ps1](PrivateSnapshot.ps1)
- [Read-AuthenticodePolicy.ps1](Read-AuthenticodePolicy.ps1)
- [ResearchInventory.ps1](ResearchInventory.ps1)
- [ResearchStage.ps1](ResearchStage.ps1)
- [Test-AuthenticodePolicy.ps1](Test-AuthenticodePolicy.ps1)
- [Test-UnsignedCandidate.ps1](Test-UnsignedCandidate.ps1)
- [Verify-WindowsRelease.ps1](Verify-WindowsRelease.ps1)
- [authenticode-policy.json](authenticode-policy.json)
