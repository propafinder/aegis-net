#!/usr/bin/env bash
# Filesystem-only fixtures, running as the current user. No systemd/root access.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
FIXTURE="$(mktemp -d)"
FIXTURE="$(cd "${FIXTURE}" && pwd -P)"
trap 'rm -rf -- "${FIXTURE}"' EXIT
sed -n '/^client_config_boundary_tree() {$/,/^}$/p' "${ROOT}/install.sh" > "${FIXTURE}/function.sh"
python3 - "${FIXTURE}" <<'PY'
import os, stat, subprocess, sys
from pathlib import Path
work = Path(sys.argv[1])
root = work / "client"
root.mkdir(mode=0o700)
(root / "aegis.toml").write_text("synthetic-configuration\n")
(root / "ca.pem").write_text("synthetic-ca\n")
for path in root.iterdir():
    path.chmod(0o600)
def call(path, operation):
    return subprocess.run(["bash", "-c", 'source "$1"; client_config_boundary_tree "$2" "$3" root',
                           "fixture", str(work / "function.sh"), str(path), operation], capture_output=True, text=True)
assert call(root, "check").stdout.strip() == "trusted"
old = os.open(root / "aegis.toml", os.O_RDWR)
before = os.fstat(old)
result = call(root, "apply")
assert result.returncode == 0, result.stderr
snapshot = Path(result.stdout.strip())
assert snapshot.is_dir()
assert stat.S_IMODE(snapshot.stat().st_mode) == 0o700
assert (snapshot / "aegis.toml").read_text() == "synthetic-configuration\n"
assert (root / "aegis.toml").stat().st_ino != before.st_ino
os.write(old, b"old fd changed")
os.close(old)
assert (root / "aegis.toml").read_text() == "synthetic-configuration\n"
assert (snapshot / "aegis.toml").read_text() == "synthetic-configuration\n"
assert stat.S_IMODE((root / "aegis.toml").stat().st_mode) == 0o600
assert (root / "aegis.toml").stat().st_uid == os.geteuid()

for kind in ("symlink", "hardlink", "writable", "fifo", "oversized"):
    source = work / kind
    source.mkdir(mode=0o700)
    good = source / "aegis.toml"
    good.write_text("previous-config\n"); good.chmod(0o600)
    bad = source / "bad"
    if kind == "symlink": bad.symlink_to(root / "aegis.toml")
    elif kind == "hardlink": os.link(root / "ca.pem", bad)
    elif kind == "writable": bad.write_text("fixture"); bad.chmod(0o666)
    elif kind == "fifo": os.mkfifo(bad)
    else:
        with bad.open("wb") as output: output.truncate(16777217)
        bad.chmod(0o600)
    result = call(source, "apply")
    assert result.returncode != 0, kind
    assert good.read_text() == "previous-config\n", kind
    assert not list(work.glob(f".{kind}.root-*")), kind
    if kind == "hardlink": bad.unlink()
parent_link = work / "parent-link"
parent_link.symlink_to(root, target_is_directory=True)
assert call(parent_link, "check").returncode != 0
print("PASS: config snapshot/new inodes, old-fd isolation, private recovery, permissions, link/special-file/size rejection, failure preserves original")
PY
