# Windows build and control tools

Build preparation, Wintun acquisition and private kit assembly sit beside Rust winctl, the controlled WFP C controller and release verification scripts.

### Contracts and limits

Building a kit is separate from driver load, system-wide lifecycle and production signing. fetch-wintun.ps1 is an explicit dependency acquisition path, not an offline read-only check. The experimental WFP controller and supported Rust tunnel/install paths have different coverage.

### Entry points and maintenance

build-kit.ps1 is the kit front door; release/ owns candidate/finalizer/provider verification; aegis-winctl owns typed package/install/service controls. Follow their local READMEs before a platform operation.

### Local map

- [build-kit.ps1](build-kit.ps1)
- [fetch-wintun.ps1](fetch-wintun.ps1)
- [prepare-build.ps1](prepare-build.ps1)
- [aegis-wfpctl/](aegis-wfpctl/README.md)
- [aegis-winctl/](aegis-winctl/README.md)
- [release/](release/README.md)


### Native build dependency integrity

The bootstrap keeps CMake3.31.6, Ninja1.11.1.4 and libclang18.1.1, selecting the
exact Windows x64 wheels in [the requirements file](build-tools-win_amd64.requirements.txt).
[The inventory](build-tools-wheel-inventory.json) records their official PyPI
release metadata, filenames, URLs and SHA256 hashes. Updates require reviewed
metadata and source changes; bootstrap does not learn new hashes from an index.
It disables pip configuration files and uses isolated, hash-required,
wheel-only acquisition without dependency resolution or package-index selection.

The actual interpreter must be CPython3.8 or newer3.x with the win_amd64
platform before pip writes. This is a dependency-closure floor, not a supported
or secure-Python recommendation: use a maintained CPython release. CMake's
upstream wheel floor is3.7, but below3.8 it needs an additional dependency that
is not in this inventory. ARM64/32-bit interpreters are refused; this does not
add an ARM64 kit or change the package versions.

[The no-install hash contract](../../scripts/test-windows-build-tools-hash-contract.sh)
uses real pip with tiny owned local wheels to verify hash refusal and a matching
hash control. It does not install packages or download official wheel assets.
Its source/argument checks do not substitute for the real Windows bootstrap and
native build in the exact candidate CI. Every explicit `-Bootstrap` repeats
interpreter/platform admission and hashed wheel acquisition with `--upgrade`
before executing native tools, even when its three cached executables exist.
This verifies acquired wheels, not all files already in the target directory or
unrelated leftover executable paths. Without `-Bootstrap`, external/local tools
remain unverified. The installed interpreter/pip and local directory ownership
are separate trust inputs.
