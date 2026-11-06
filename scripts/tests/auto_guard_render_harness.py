"""Run only the v2 device guard render() function, never the guard helper.

The function body is extracted from the committed helper text. Its two fixed
AUTO intent paths are pointed at a private directory (each substitution must
match exactly once) and the two authority readers it calls are stubbed with
the caller's values. No top-level helper code, lock, nft, systemd or state
file is touched; the renderer only prints the batch text.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

GUARD = Path(__file__).resolve().parents[1] / "aegis-device-egress-guard.sh"
TABLE = "aegis_device_guard"
REFUSED = "aegis-scoped-reply-twin-refused"
LOCAL_INTENT = ("( -e /var/lib/aegis-install/client/auto-local-redirect-intent.json || "
                "-L /var/lib/aegis-install/client/auto-local-redirect-intent.json )")
SCOPED_INTENT = ("( -e /var/lib/aegis-install/client/auto-redirect-intent.json || "
                 "-L /var/lib/aegis-install/client/auto-redirect-intent.json )")
LOCAL_DNAT_READER = 'local_dnat_ports="$(python3 -I -B - "$(dirname "${BASH_SOURCE[0]}")/lib"'


class HarnessRefused(RuntimeError):
    """The committed helper no longer has the reviewed render() shape."""


def bash() -> str:
    """bash >= 4 is required (the guest runs bash 5); never skip without it."""
    candidates = (("/opt/homebrew/bin/bash",) if sys.platform == "darwin"
                  else ("/bin/bash", "/usr/bin/bash"))
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            version = subprocess.run([path, "-c", "echo ${BASH_VERSINFO[0]}"],
                                     capture_output=True, text=True, timeout=10,
                                     env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            if version.returncode == 0 and int(version.stdout.strip() or 0) >= 4:
                return path
    raise HarnessRefused("bash4_required")


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise HarnessRefused("render_substitution_not_unique")
    return text.replace(old, new)


def render_function(source: str | None = None) -> str:
    source = GUARD.read_text(encoding="utf-8") if source is None else source
    header = "\nrender() {\n"
    if source.count(header) != 1:
        raise HarnessRefused("render_function_not_unique")
    start = source.index(header) + 1
    end = source.index("\n}\n", start) + 3
    body = source[start:end]
    if not body.endswith("  '\n}\n") or body.count("render() {") != 1:
        raise HarnessRefused("render_function_bounds_changed")
    return body


def client_marker(binding: dict, role: str = "client") -> str:
    material = [binding["boot_id"], binding["state_sha256"], role,
                binding["path"], binding["inode"], binding["invocation"]]
    return "aegis-v2-" + hashlib.sha256(json.dumps(
        material, separators=(",", ":")).encode()).hexdigest()


def render(*, profile: str, uplink: str, management_ports: str,
           client: dict | None, scoped: dict | None,
           manager: dict | None = None, dhcp4: str = "0", dhcp6: str = "0",
           mutate: tuple[str, str] | None = None,
           local_dnat: tuple[tuple[str, int], ...] | None = None,
           tun_ifindex: int | None = None) -> tuple[int, str, str]:
    """Return (returncode, stdout, stderr) of render "$client" "$manager".

    local_dnat, when given, creates the private local intent and replaces only
    the protected local DNAT port reader with these (protocol, port) rows.
    """
    body = render_function()
    if mutate is not None:
        body = replace_once(body, *mutate)
    if local_dnat is not None:
        body = replace_once(body, LOCAL_DNAT_READER,
                            'local_dnat_ports="$(aegis_test_local_dnat "$(dirname "${BASH_SOURCE[0]}")/lib"')
    with tempfile.TemporaryDirectory(prefix="aegis-guard-render-") as work:
        work_path = Path(work)
        os.chmod(work_path, 0o700)
        local_intent = work_path / "auto-local-redirect-intent.json"
        scoped_intent = work_path / "auto-redirect-intent.json"
        if scoped is not None:
            scoped_intent.write_text("{}\n")
        if local_dnat is not None:
            local_intent.write_text("{}\n")
        body = replace_once(body, LOCAL_INTENT,
                            '( -e "$AEGIS_TEST_LOCAL_INTENT" || -L "$AEGIS_TEST_LOCAL_INTENT" )')
        body = replace_once(body, SCOPED_INTENT,
                            '( -e "$AEGIS_TEST_SCOPED_INTENT" || -L "$AEGIS_TEST_SCOPED_INTENT" )')
        if "/var/lib/aegis-install" in body:
            raise HarnessRefused("render_fixed_path_remains")
        script = work_path / "render.sh"
        script.write_text(
            "set -euo pipefail\n"
            f"TABLE={TABLE}\nschema=aegis_device_guard_v2\nSTATE=/nonexistent\n"
            'capture_profile="$AEGIS_TEST_PROFILE"\ncapture_interface=aegis-tun0\n'
            'uplink="$AEGIS_TEST_UPLINK"\nmanagement_ports="$AEGIS_TEST_PORTS"\n'
            'dhcp4="$AEGIS_TEST_DHCP4"\ndhcp6="$AEGIS_TEST_DHCP6"\n'
            'capture_ifindex="$AEGIS_TEST_TUN_IFINDEX"\n'
            "management_ipv4=''\nmanagement_ipv6=''\n"
            'client_path="$AEGIS_TEST_CLIENT_PATH"\nclient_unit="$AEGIS_TEST_CLIENT_UNIT"\n'
            'client_inode="$AEGIS_TEST_CLIENT_INODE"\n'
            'client_invocation="$AEGIS_TEST_CLIENT_INVOCATION"\n'
            'manager_inode="$AEGIS_TEST_MANAGER_INODE"\n'
            'manager_invocation="$AEGIS_TEST_MANAGER_INVOCATION"\n'
            'manager_ifindex="$AEGIS_TEST_MANAGER_IFINDEX"\n'
            'manager_dhcp4_server="$AEGIS_TEST_MANAGER_DHCP4_SERVER"\n'
            'manager_dhcp6_server="$AEGIS_TEST_MANAGER_DHCP6_SERVER"\n'
            "binding_marker() {\n"
            '  case "$1" in\n'
            '    client) printf \'%s\\n\' "$AEGIS_TEST_CLIENT_MARKER";;\n'
            '    manager) printf \'%s\\n\' "$AEGIS_TEST_MANAGER_MARKER";;\n'
            "    *) return 1;;\n"
            "  esac\n"
            "}\n"
            "aegis_test_local_dnat() {\n"
            "  cat >/dev/null\n"
            '  printf \'%s\' "$AEGIS_TEST_LOCAL_DNAT"\n'
            "}\n"
            "scoped_reply_fields() {\n"
            '  [[ -n "$AEGIS_TEST_SCOPED_IF" ]] || return 1\n'
            "  printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$AEGIS_TEST_SCOPED_IF\" "
            '"$AEGIS_TEST_SCOPED_IP" "$AEGIS_TEST_SCOPED_PORT" "$AEGIS_TEST_SCOPED_MARK" '
            '"$AEGIS_TEST_SCOPED_MARKER"\n'
            "}\n"
            + body +
            'render "$AEGIS_TEST_CLIENT_PATH" "$AEGIS_TEST_MANAGER_PATH"\n',
            encoding="utf-8")
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
               "AEGIS_TEST_PROFILE": profile, "AEGIS_TEST_UPLINK": uplink,
               "AEGIS_TEST_PORTS": management_ports,
               "AEGIS_TEST_DHCP4": dhcp4, "AEGIS_TEST_DHCP6": dhcp6,
               "AEGIS_TEST_TUN_IFINDEX": str(tun_ifindex or ""),
               "AEGIS_TEST_LOCAL_INTENT": str(local_intent),
               "AEGIS_TEST_SCOPED_INTENT": str(scoped_intent),
               "AEGIS_TEST_CLIENT_PATH": "", "AEGIS_TEST_CLIENT_UNIT": "",
               "AEGIS_TEST_CLIENT_INODE": "", "AEGIS_TEST_CLIENT_INVOCATION": "",
               "AEGIS_TEST_CLIENT_MARKER": "",
               "AEGIS_TEST_MANAGER_PATH": "", "AEGIS_TEST_MANAGER_INODE": "",
               "AEGIS_TEST_MANAGER_INVOCATION": "", "AEGIS_TEST_MANAGER_MARKER": "",
               "AEGIS_TEST_MANAGER_IFINDEX": "", "AEGIS_TEST_MANAGER_DHCP4_SERVER": "",
               "AEGIS_TEST_MANAGER_DHCP6_SERVER": "",
               "AEGIS_TEST_SCOPED_IF": "", "AEGIS_TEST_SCOPED_IP": "",
               "AEGIS_TEST_SCOPED_PORT": "", "AEGIS_TEST_SCOPED_MARK": "",
               "AEGIS_TEST_SCOPED_MARKER": "",
               "AEGIS_TEST_LOCAL_DNAT": "\n".join(
                   f"{protocol} {port}" for protocol, port in local_dnat or ())}
        if client is not None:
            env.update(AEGIS_TEST_CLIENT_PATH=client["path"],
                       AEGIS_TEST_CLIENT_UNIT=client["path"].rsplit("/", 1)[-1],
                       AEGIS_TEST_CLIENT_INODE=client["inode"],
                       AEGIS_TEST_CLIENT_INVOCATION=client["invocation"],
                       AEGIS_TEST_CLIENT_MARKER=client_marker(client))
        if manager is not None:
            env.update(AEGIS_TEST_MANAGER_PATH=manager["path"],
                       AEGIS_TEST_MANAGER_INODE=manager["inode"],
                       AEGIS_TEST_MANAGER_INVOCATION=manager["invocation"],
                       AEGIS_TEST_MANAGER_IFINDEX=str(manager.get("ifindex", 1)),
                       AEGIS_TEST_MANAGER_DHCP4_SERVER=manager.get("dhcp4_server") or "",
                       AEGIS_TEST_MANAGER_DHCP6_SERVER=manager.get("dhcp6_server") or "",
                       AEGIS_TEST_MANAGER_MARKER=client_marker(manager, "manager"))
        if scoped is not None:
            binding = scoped["binding"]
            env.update(AEGIS_TEST_SCOPED_IF=binding["interface"],
                       AEGIS_TEST_SCOPED_IP=binding["listen_ipv4"],
                       AEGIS_TEST_SCOPED_PORT=str(binding["listen_port"]),
                       AEGIS_TEST_SCOPED_MARK=f"0x{scoped['mark']:08x}",
                       AEGIS_TEST_SCOPED_MARKER=scoped["marker"])
        done = subprocess.run([bash(), str(script)], capture_output=True, text=True,
                              timeout=60, env=env, stdin=subprocess.DEVNULL)
        return done.returncode, done.stdout, done.stderr


def output_mirror(line: str) -> str:
    """The generic awk mirror of one non-scoped OUTPUT rule, in Python."""
    fields = line.split()
    if "socket cgroupv2" in line:
        raise HarnessRefused("socket_rule_needs_tag_mirror")
    fields[4] = "postroute"
    return " ".join(fields)
