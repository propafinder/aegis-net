#!/usr/bin/env python3
"""Execute the SBOM wrapper with a deterministic inert CycloneDX producer."""

from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent / "security/generate-sbom.sh"


def run(*argv, cwd=None, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    assert result.returncode == 0, (argv, result.stdout, result.stderr)
    return result


with tempfile.TemporaryDirectory(prefix="aegis-sbom-source-") as temporary:
    base = Path(temporary).resolve()
    root = base / "repo"
    (root / "scripts/security").mkdir(parents=True)
    (root / "crate").mkdir()
    (root / "third_party/h2").mkdir(parents=True)
    (root / "third_party/tungstenite").mkdir(parents=True)
    shutil.copyfile(SOURCE, root / "scripts/security/generate-sbom.sh")
    (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crate"]\n')
    (root / "Cargo.lock").write_text('version = 4\n')
    (root / "crate/Cargo.toml").write_text('[package]\nname = "sbom-fixture"\nversion = "0.0.0"\n')
    for name in ("h2", "tungstenite"):
        (root / f"third_party/{name}/Cargo.toml").write_text(f'[package]\nname = "fixture-{name}"\nversion = "0.0.0"\n')
    bin_dir = base / "bin"
    bin_dir.mkdir()
    cargo = bin_dir / "cargo"
    cargo.write_text("""#!/usr/bin/env python3
import json,pathlib,sys
a=sys.argv[1:]
if a==['cyclonedx','--version']:
 print('cargo-cyclonedx-cyclonedx 0.5.9');sys.exit(0)
if a[:1]!=['cyclonedx'] or '--override-filename' not in a:sys.exit(2)
name=a[a.index('--override-filename')+1]+'.json'
(pathlib.Path.cwd()/'crate'/name).write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','components':[]}))
""")
    cargo.chmod(0o755)
    run("git", "init", "-q", cwd=root)
    run("git", "add", ".", cwd=root)
    run("git", "-c", "user.name=Aegis test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture", cwd=root)
    head = run("git", "rev-parse", "HEAD", cwd=root).stdout.strip()
    env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
    clean = run("bash", str(root / "scripts/security/generate-sbom.sh"), str(base / "clean"), "aarch64-unknown-linux-gnu", cwd=root, env=env)
    assert "PASS:" in clean.stdout
    with (root / "Cargo.toml").open("a") as f:
        f.write("# uncommitted dependency selection\n")
    dirty = subprocess.run(["bash", str(root / "scripts/security/generate-sbom.sh"), str(base / "dirty"), "aarch64-unknown-linux-gnu"], cwd=root, env=env, capture_output=True, text=True)
    assert dirty.returncode != 0, "uncommitted manifest was accepted as committed-source SBOM"
    assert "source input differs from HEAD" in dirty.stderr
    assert not (base / "dirty/receipt.json").exists()
    receipt = json.loads((base / "clean/receipt.json").read_text())
    assert receipt["source_commit"] == head

print("PASS: SBOM receipt binds HEAD and refuses dirty manifest before generation")
