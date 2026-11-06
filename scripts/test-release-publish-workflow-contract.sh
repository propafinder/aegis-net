#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKFLOW="${ROOT}/.github/workflows/release.yml"
CI_WORKFLOW="${ROOT}/.github/workflows/ci.yml"

require_snippet() {
  local snippet="$1"
  if ! grep -Fq -- "${snippet}" "${WORKFLOW}"; then
    echo "missing release workflow snippet: ${snippet}" >&2
    exit 1
  fi
}

require_snippet "name: Release"
require_snippet "push:"
require_snippet "tags:"
require_snippet '- "v*"'
require_snippet "workflow_dispatch:"
require_snippet "publish_release:"
require_snippet "include_macos:"
require_snippet "inputs.include_macos"
require_snippet "github.event_name != 'workflow_dispatch' || inputs.include_macos"
require_snippet "contents: read"
require_snippet "RELEASE_REPOSITORY: propafinder/aegis-release"
require_snippet 'GH_TOKEN: ${{ secrets.AEGIS_RELEASE_REPO_TOKEN }}'
require_snippet "bash ./scripts/build-container-release-delivery.sh"
require_snippet "build-linux-x86_64:"
require_snippet "almalinux:9"
require_snippet "build-linux-arm64:"
require_snippet "runs-on: ubuntu-24.04-arm"
require_snippet '[[ "$(uname -m)" == "aarch64" ]]'
require_snippet "needs.build-linux-arm64.result == 'success'"
require_snippet '[[ -f "${arm_manifest}" ]]'
require_snippet 'for manifest in release.manifest.json release.manifest-aarch64.json client-release.manifest.json client-release.manifest-aarch64.json; do'
require_snippet "binutils cpio"
require_snippet "name: linux-x86_64"
require_snippet "Download portable x86_64 Linux delivery"
require_snippet '[[ "${built_git_sha}" == "${GITHUB_SHA}" ]]'
require_snippet "The signing job must never rebuild Linux"
require_snippet "--prerelease"
require_snippet 'gh release create "${tag_name}"'
require_snippet '--notes-file "${release_body}"'
require_snippet "stage-public-client-mirror"
require_snippet 'release_asset_base="https://github.com/${release_repo}/releases/download/${tag_name}"'
require_snippet 'client --source %s/client-release.manifest.json'
require_snippet '--repo "${release_repo}"'
require_snippet "--target main"
require_snippet "name: verified-public-client"
require_snippet "./public-client/bootstrap-install.sh"
require_snippet "propafinder/aegis-release"
require_snippet '-e AEGIS_RELEASE_CHANNEL="${release_channel}"'
require_snippet '-e AEGIS_RELEASE_PRERELEASE="${release_prerelease}"'
require_snippet '.channel == $channel and .prerelease == $prerelease'
require_snippet '.git_sha == $sha and .version == $version'

require_snippet 'private_administrative_operator'
require_snippet 'aegis_private_research_delivery_v1'
require_snippet 'private_research_only'
require_snippet 'research.manifest.json'
require_snippet 'private research asset binding invalid'

for workflow in "${ROOT}/.github/workflows/ci.yml" "${WORKFLOW}"; do
  if grep -Eq 'dnf install .*([[:space:]])curl([[:space:]]|$)' "${workflow}"; then
    echo "AlmaLinux build must use the preinstalled curl-minimal provider: ${workflow}" >&2
    exit 1
  fi
done

ci_sha_env_count="$(grep -Fc -- '-e AEGIS_BUILD_GIT_SHA="${GITHUB_SHA}"' \
  "${CI_WORKFLOW}" || true)"
release_sha_env_count="$(grep -Fc -- '-e AEGIS_BUILD_GIT_SHA="${GITHUB_SHA}"' \
  "${WORKFLOW}" || true)"
if [[ "${ci_sha_env_count}" -ne 3 || "${release_sha_env_count}" -ne 2 ]]; then
  echo "every AlmaLinux delivery builder must receive the exact GITHUB_SHA" >&2
  exit 1
fi

release_channel_env_count="$(grep -Fc -- '-e AEGIS_RELEASE_CHANNEL="${release_channel}"' \
  "${WORKFLOW}" || true)"
release_prerelease_env_count="$(grep -Fc -- '-e AEGIS_RELEASE_PRERELEASE="${release_prerelease}"' \
  "${WORKFLOW}" || true)"
if [[ "${release_channel_env_count}" -ne 2 || "${release_prerelease_env_count}" -ne 2 ]]; then
  echo "every Linux release builder must receive the requested channel/prerelease metadata" >&2
  exit 1
fi
if grep -Fq -- '--channel stable --prerelease false' "${WORKFLOW}"; then
  echo "release builders must not hard-code stable metadata for workflow_dispatch" >&2
  exit 1
fi
if grep -Fq 'gh release delete' "${WORKFLOW}"; then
  echo "release publisher must fail on an existing tag instead of deleting it" >&2
  exit 1
fi

if ! grep -Fxq -- '          sudo chown -R "$(id -u):$(id -g)" ./target' \
  "${CI_WORKFLOW}" ||
   grep -Fq -- 'sudo chown -R "$(id -u):$(id -g)" ./target ./dist/linux-arm64' \
  "${CI_WORKFLOW}"; then
  echo "ARM64 CI must restore its Rust cache; the isolated wrapper owns delivery handoff" >&2
  exit 1
fi

if ! grep -Fq -- 'Restore Rust cache ownership after privileged smokes' \
  "${CI_WORKFLOW}" ||
   ! grep -Fq -- 'sudo chown -R "$(id -u):$(id -g)" "${GITHUB_WORKSPACE}/target"' \
  "${CI_WORKFLOW}"; then
  echo "extended Linux CI must restore target ownership after privileged smokes" >&2
  exit 1
fi

if grep -REq -- 'actions/(checkout|upload-artifact)@[0-9a-f]+ # v4|actions/download-artifact@[0-9a-f]+ # v4' \
  "${ROOT}/.github/workflows"; then
  echo "root workflows must not use the deprecated Node 20 artifact/checkout actions" >&2
  exit 1
fi

publish_block="$(sed -n '/^  publish:/,$p' "${WORKFLOW}")"
if grep -Fq 'releases/latest/download' <<<"${publish_block}"; then
  echo "prerelease publisher must not point quick-start at the stable latest release" >&2
  exit 1
fi
if grep -Fq 'bash ./scripts/build-release-delivery.sh ./dist/release' <<<"${publish_block}"; then
  echo "publish job must consume the AlmaLinux artifact, not rebuild on ubuntu-latest" >&2
  exit 1
fi

arm_block="$(sed -n '/^  build-linux-arm64:/,/^  build-linux-x86_64:/p' "${WORKFLOW}")"
if grep -Fq 'continue-on-error: true' <<<"${arm_block}"; then
  echo "Linux ARM64 release build must be mandatory" >&2
  exit 1
fi
if grep -Fq 'setup-qemu-action' <<<"${arm_block}"; then
  echo "Linux ARM64 release build must run on a native ARM64 runner" >&2
  exit 1
fi

python3 - "${ROOT}" <<'PY'
import os
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])


def workflow_steps(path):
    # This contract deliberately uses only the standard library. The selected
    # workflows use six-space named steps and eight-space run fields; reject
    # unreadable steps instead of silently missing a changed structure.
    steps = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("      - name: "):
            current = line.removeprefix("      - name: ").strip('"\'')
            if current in steps:
                current = f"{current} (step {len(steps) + 1})"
            steps[current] = []
        elif current is not None:
            if line and not line.startswith("        "):
                current = None
            else:
                steps[current].append(line)
    return steps


def run_script(lines):
    for index, line in enumerate(lines):
        if line == "        run: |":
            script = []
            for body_line in lines[index + 1:]:
                if body_line and not body_line.startswith("          "):
                    break
                script.append(body_line[10:] if body_line else "")
            return "\n".join(script) + "\n"
        if line.startswith("        run: "):
            inline = line.removeprefix("        run: ")
            assert not inline.startswith(("|", ">")), "unsupported multiline run style"
            return inline + "\n"
    return None


release_steps = workflow_steps(root / ".github/workflows/release.yml")
opsec_steps = workflow_steps(root / ".github/workflows/release-opsec-gate.yml")
for filename, workflow in (
    ("release.yml", release_steps), ("release-opsec-gate.yml", opsec_steps),
):
    scripts = [run_script(lines) for lines in workflow.values()]
    expected_runs = sum(
        line.lstrip().startswith("run:")
        for line in (root / ".github/workflows" / filename).read_text(encoding="utf-8").splitlines()
    )
    assert expected_runs > 0 and sum(script is not None for script in scripts) == expected_runs, "every workflow run block must be inspectable"
    for script in filter(None, scripts):
        assert "${{" not in script, "workflow expressions must reach shell via env, never run source"

metadata_lines = release_steps["Resolve release metadata"]
for input_name in ("tag_name", "release_name", "channel", "prerelease"):
    expected = f"AEGIS_INPUT_{input_name.upper()}: ${{{{ inputs.{input_name} }}}}"
    assert any(line.strip() == expected for line in metadata_lines), expected
metadata_script = run_script(metadata_lines)
assert metadata_script and "python3" in metadata_script, "metadata validator missing"
release_names = list(release_steps)
assert release_names.index("Resolve release metadata") < release_names.index("Sign release manifest (ed25519 anchor)")

version = re.search(
    r'^version = "([^"]+)"$',
    (root / "aegis-client/Cargo.toml").read_text(encoding="utf-8"),
    re.MULTILINE,
)[1]
stable_tag = f"v{version}"
rc_tag = f"{stable_tag}-rc.13"
nightly_tag = f"{stable_tag}-nightly.20260902"


def validate(tag, channel, prerelease, title="", event="workflow_dispatch", valid=True):
    # Execute only the real metadata-validation block. No signing, publishing,
    # configured credentials, network access or release binaries are involved.
    with tempfile.TemporaryDirectory(prefix="aegis-release-metadata-") as temp:
        output = Path(temp) / "outputs"
        env = {
            "PATH": os.environ["PATH"],
            "GITHUB_EVENT_NAME": event,
            "GITHUB_REF_NAME": tag,
            "GITHUB_OUTPUT": str(output),
            "AEGIS_INPUT_TAG_NAME": tag,
            "AEGIS_INPUT_RELEASE_NAME": title,
            "AEGIS_INPUT_CHANNEL": channel,
            "AEGIS_INPUT_PRERELEASE": prerelease,
        }
        result = subprocess.run(
            ["bash", "-c", metadata_script], cwd=root, env=env,
            text=True, capture_output=True, timeout=10,
        )
        if not valid:
            assert result.returncode != 0, (tag, channel, prerelease, "invalid metadata accepted")
            assert not output.exists(), "rejected metadata must not emit trusted outputs"
            return
        assert result.returncode == 0, result.stderr
        fields = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
        assert fields == {
            "tag_name": tag,
            "release_name": title or tag,
            "channel": channel,
            "prerelease": prerelease,
        }, fields


validate(stable_tag, "stable", "false")
validate(stable_tag, "stable", "false", event="push")
validate(rc_tag, "rc", "true")
validate(nightly_tag, "nightly", "true")
# Harmless punctuation must survive as literal title data, including quotes,
# dollars, semicolons and equals signs. This is not an executable test payload.
validate(rc_tag, "rc", "true", title='AEGIS "RC" — operator\'s $budget; review & notes = ready')
for tag, channel, prerelease in (
    (rc_tag, "stable", "false"),
    (rc_tag, "rc", "false"),
    (stable_tag, "stable", "true"),
    (stable_tag, "preview", "false"),
    (nightly_tag, "rc", "true"),
    (stable_tag, "stable", "False"),
    (stable_tag + " notes", "stable", "false"),
    (stable_tag + "-rc.01", "rc", "true"),
    ("v999.999.999", "stable", "false"),
):
    validate(tag, channel, prerelease, valid=False)
validate(rc_tag, "rc", "true", event="push", valid=False)
for title in ("first\nsecond", "first\rsecond", "first\x1fsecond"):
    validate(rc_tag, "rc", "true", title=title, valid=False)

publisher = (root / ".github/workflows/release.yml").read_text().split("\n  publish:\n", 1)[1]
for forbidden in ("actions/checkout@", "rust-toolchain@", "SIGNING_KEY", "private-signed-operator-delivery", "*.tar.gz", "*.json"):
    assert forbidden not in publisher, (forbidden, "publisher must receive only approved client files")
assert "needs: [prepare-public-client, publishing-governance]" in publisher
# Keep the dormant cancellation/preparation guards while B-05 holds hosted
# publication unreachable pending independent custody and credential migration.
assert "if: ${{ !cancelled() && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && !inputs.build_only && inputs.publish_release && needs.prepare-public-client.result == 'success' && needs.publishing-governance.result == 'success' && false }}" in publisher, 'B-05 hosted publisher hold missing'
publish = release_steps["Publish GitHub release assets"]
for output_name, env_name in (
    ("tag_name", "AEGIS_RELEASE_TAG_NAME"),
    ("release_name", "AEGIS_RELEASE_NAME"),
    ("prerelease", "AEGIS_RELEASE_PRERELEASE"),
):
    expected = f"{env_name}: ${{{{ needs.prepare-public-client.outputs.{output_name} }}}}"
    assert any(line.strip() == expected for line in publish), expected
assert 'tag_name="${AEGIS_RELEASE_TAG_NAME}"' in run_script(publish)
assert 'release_name="${AEGIS_RELEASE_NAME}"' in run_script(publish)

scan = opsec_steps["Scan selected artifact"]
assert any(line.strip() == "AEGIS_OPSEC_ARTIFACT_PATH: ${{ inputs.artifact_path }}" for line in scan)
assert '--input "${AEGIS_OPSEC_ARTIFACT_PATH}"' in run_script(scan)

ci_path = root / ".github/workflows/ci.yml"
ci_text = ci_path.read_text(encoding="utf-8")
ci_steps = workflow_steps(ci_path)
# Exercise the actual three container-entry scripts with a real throwaway Git
# checkout and an inert Docker recorder. No container, package install, signing
# or network request occurs. The recorder stops before later packaging checks.
with tempfile.TemporaryDirectory(prefix="aegis-container-provenance-") as temp:
    fixture = Path(temp).resolve()
    bin_dir = fixture / "bin"
    bin_dir.mkdir()
    recorder = fixture / "docker-argv.json"
    docker = bin_dir / "docker"
    docker.write_text("#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ['AEGIS_DOCKER_RECEIPT']).write_text(json.dumps(sys.argv[1:]))\nsys.exit(78)\n")
    docker.chmod(0o700)
    uname = bin_dir / "uname"
    uname.write_text("#!/bin/sh\nprintf '%s\\n' \"${AEGIS_FIXTURE_UNAME:-aarch64}\"\n")
    uname.chmod(0o700)
    base_env = {
        "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
        "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-09-11T00:00:00Z", "GIT_COMMITTER_DATE": "2026-09-11T00:00:00Z",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "AEGIS_INPUT_CHANNEL": "rc", "AEGIS_INPUT_PRERELEASE": "true",
        "AEGIS_DOCKER_RECEIPT": str(recorder),
    }
    subprocess.run(["git", "init", "-q", str(fixture)], env=base_env, check=True, capture_output=True)
    subprocess.run(["git", "-C", str(fixture), "commit", "-q", "--allow-empty", "-m", "fixture"], env=base_env, check=True, capture_output=True)
    def fixture_git(*argv):
        return subprocess.check_output(["git", "-C", str(fixture), *argv], env=base_env, text=True).strip()
    sha, timestamp = fixture_git("rev-parse", "HEAD"), fixture_git("show", "-s", "--format=%cI", "HEAD")
    for lines, output in (
        (ci_steps["Build portable ARM64 delivery on AlmaLinux 9"], "linux-arm64"),
        (ci_steps["Build unsigned ARM64 package in pinned Linux container"], "linux-arm64"),
        (ci_steps["Build unsigned x86_64 package in pinned Linux container"], "linux-x86_64"),
        (release_steps["Build aarch64 Linux delivery (native ARM64)"], "arm64"),
        (release_steps["Build portable x86_64 Linux delivery on AlmaLinux 9"], "linux-x86_64"),
    ):
        script = run_script(lines)
        assert script
        assert script.count('-e AEGIS_BUILD_GIT_SHA="${GITHUB_SHA}"') == 1, "every independently executed builder needs one exact SHA env"
        for valid in (True, False):
            recorder.unlink(missing_ok=True)
            env = dict(base_env, GITHUB_SHA=sha if valid else "0" * 40, AEGIS_FIXTURE_UNAME="x86_64" if output == "linux-x86_64" else "aarch64")
            result = subprocess.run(["bash", "-c", script], cwd=fixture, env=env, capture_output=True, text=True, timeout=10)
            if not valid:
                assert result.returncode != 0 and not recorder.exists(), "changed checkout must fail before Docker"
                continue
            assert result.returncode == 78, result.stderr
            argv = json.loads(recorder.read_text())
            values = [argv[index + 1] for index, arg in enumerate(argv[:-1]) if arg == "-e"]
            assert "AEGIS_BUILD_GIT_SHA=" + sha in values
            assert "AEGIS_BUILD_TIMESTAMP=" + timestamp in values, "container must receive the verified checkout timestamp"
            assert "AEGIS_DELIVERY_UID=" + str(os.getuid()) in values
            assert "AEGIS_DELIVERY_GID=" + str(os.getgid()) in values
            mounts = [argv[index + 1] for index, arg in enumerate(argv[:-1]) if arg == "-v"]
            assert mounts == [str(fixture / "dist" / output) + ":/aegis-delivery", str(fixture) + ":/src"], "container must preserve isolated output and source mounts"
            assert argv[argv.index("-w") + 1] == "/src"
            active = "\n".join(line for line in argv[-1].splitlines() if not line.lstrip().startswith("#"))
            assert len(re.findall(r"^\s+bash \./scripts/build-container-release-delivery\.sh \\$", active, re.M)) == 1, "each real container entry must delegate to the strict wrapper"
            assert "bash ./scripts/build-release-delivery.sh" not in active, "direct builder bypasses isolated output handoff"
print("PASS: all five portable build entries pin host provenance and reject checkout drift before Docker")
lightweight = workflow_steps(ci_path)["Lightweight release contracts"]
assert not any(line.startswith("        if:") for line in lightweight), "lightweight release contracts must run on PRs"
lightweight_script = run_script(lightweight)
ci_jobs = {
    match[1]: match[2] for match in re.finditer(
        r'^  ([a-z0-9_-]+):\n(.*?)(?=^  [a-z0-9_-]+:\n|\Z)',
        ci_text.split('\njobs:\n', 1)[1], re.M | re.S,
    )
}
for job_name in ("linux-arm64", "linux-arm64-private-deb", "linux-x86_64-private-deb"):
    block = ci_jobs[job_name]
    assert block.count('-e AEGIS_BUILD_GIT_SHA="${GITHUB_SHA}"') == 1, (job_name, "exact SHA container handoff")
    assert block.count('[[ "$(git rev-parse HEAD)" == "${GITHUB_SHA}" ]]') >= 1, (job_name, "checkout identity")
private_arm = ci_jobs["linux-arm64-private-deb"]
assert "github.event_name == 'workflow_dispatch'" in private_arm
assert "github.ref == 'refs/heads/codex/beta-stabilization-20261012'" in private_arm
assert "inputs.build_linux_arm64_deb == 'true'" in private_arm
assert "permissions:\n      contents: read" in private_arm
assert "persist-credentials: false" in private_arm
assert "secrets." not in private_arm and "environment:" not in private_arm
assert "aegis-client_*.deb" in private_arm and "aegis-server_*.deb" not in private_arm
for release_name, step_name in (("ARM64", "Build aarch64 Linux delivery (native ARM64)"), ("x86_64", "Build portable x86_64 Linux delivery on AlmaLinux 9")):
    release_block = run_script(release_steps[step_name])
    for line in (
        'export GIT_CONFIG_COUNT=1',
        'export GIT_CONFIG_KEY_0=safe.directory',
        'export GIT_CONFIG_VALUE_0=/src',
        '[[ "$(git -C /src rev-parse --show-toplevel)" == /src ]]',
        '[[ "$(git -C /src rev-parse HEAD)" == "$AEGIS_BUILD_GIT_SHA" ]]',
    ):
        assert release_block.count(line) == 1, (release_name, line, "exact release container Git trust")
    assert release_block.index('export GIT_CONFIG_VALUE_0=/src') < release_block.index('bash ./scripts/build-container-release-delivery.sh'), "release Git trust must precede packaging"
    assert 'safe.directory=*' not in release_block and 'git config --global' not in release_block
private_x86 = ci_jobs["linux-x86_64-private-deb"]
assert "github.event_name == 'workflow_dispatch'" in private_x86
assert "github.ref == 'refs/heads/codex/beta-stabilization-20261012'" in private_x86
assert "inputs.build_linux_x86_64_deb == 'true'" in private_x86
assert "permissions:\n      contents: read" in private_x86
assert "persist-credentials: false" in private_x86
assert "secrets." not in private_x86 and "environment:" not in private_x86
assert "aegis-client_*.deb" in private_x86 and "aegis-server_*.deb" not in private_x86
assert "ubuntu-24.04-arm" not in private_x86 and "runs-on: ubuntu-24.04" in private_x86
assert '[[ "$(uname -m)" == "x86_64" ]]' in private_x86
assert '.arch == "x86_64"' in private_x86 and '.target_triple == "x86_64-unknown-linux-gnu"' in private_x86
assert "aegis-client_*_amd64.deb" in private_x86 and 'Architecture)" == \'amd64\'' in private_x86
assert "'schema': 'aegis_unsigned_x86_64_deb_ci_v1'" in private_x86
assert "'cargo_lock_sha256': hashlib.sha256(pathlib.Path('Cargo.lock').read_bytes()).hexdigest()" in private_x86
assert "'source_sha': sha" in private_x86 and "'package_sha256': hashlib.sha256(package.read_bytes()).hexdigest()" in private_x86
assert '[[ "$(find "${output}" -maxdepth 1 -type f | wc -l)" == 3 ]]' in private_x86
assert "name: linux-x86_64-client-deb-unsigned" in private_x86
for job_name, block in (("ARM64 delivery", ci_jobs["linux-arm64"]), ("ARM64 private", private_arm), ("x86_64 private", private_x86)):
    for line in (
        'export GIT_CONFIG_COUNT=1',
        'export GIT_CONFIG_KEY_0=safe.directory',
        'export GIT_CONFIG_VALUE_0=/src',
        '[[ "$(git -C /src rev-parse --show-toplevel)" == /src ]]',
        '[[ "$(git -C /src rev-parse HEAD)" == "$AEGIS_BUILD_GIT_SHA" ]]',
    ):
        assert block.count(line) == 1, (job_name, line, "exact container Git trust")
    assert block.index('export GIT_CONFIG_VALUE_0=/src') < block.index('bash ./scripts/build-container-release-delivery.sh'), "Git trust must precede packaging"
    assert 'safe.directory=*' not in block and 'git config --global' not in block, "container Git trust must stay path scoped"
windows_block = ci_jobs["windows-rust"]
assert "inputs.build_linux_arm64_deb != 'true' && inputs.build_linux_x86_64_deb != 'true'" in windows_block, "both package dispatches must skip Windows"
for name in (
    "generate-relay-materials", "release-publish-workflow",
    "host-arch-naming", "rpm-spec-no-duplicate-files",
):
    command = f"bash ./scripts/test-{name}-contract.sh"
    assert command in lightweight_script, (name, "must run ungated")
    assert ci_jobs['rust'].count(command) == 1, (name, "must run exactly once in the rust lane, not again in its extended steps")
    if name == 'release-publish-workflow':
        assert ci_jobs['dependency-security'].count(command) == 1, "independent security job must also validate actual release wiring"
        assert ci_text.count(command) == 2, "release wiring contract must run once per required owning job"
    else:
        assert ci_text.count(command) == 1, (name, "unexpected duplicate outside the rust lane")
print("PASS: release metadata is validated, workflow text uses env, lightweight contracts are ungated")
PY

bash "${ROOT}/scripts/test-release-signer-isolation-contract.sh"
bash "${ROOT}/scripts/test-bootstrap-release-floor-contract.sh"
bash "${ROOT}/scripts/test-release-build-only-contract.sh"

echo "PASS: release publish workflow contract"
