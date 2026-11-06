#!/usr/bin/env python3
"""Exercise the exact staged-owner account and queued-job admission predicates."""

import ast
import re
import subprocess
from pathlib import Path


source = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
marker = "<<'PY_STAGE_OWNER'\n"
assert source.count(marker) == 1
body = source.split(marker, 1)[1].split("\nPY_STAGE_OWNER\n", 1)[0]
tree = ast.parse(body)


def predicate(needle):
    found = []
    for node in tree.body:
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "need"
                and needle in ast.unparse(node.value)):
            found.append(node)
    assert len(found) == 1, needle
    return compile(ast.Expression(found[0].value.args[0]), "install.sh:PY_STAGE_OWNER", "eval")


shape = predicate("set(user)")
account = predicate("user['home']")
supplementary = predicate("user['groups']")
jobs = predicate("aegis-client.service' not in jobs")
assert "aegis-auto@" in ast.unparse(ast.parse(body))
assert "user['groups']" in body and "user['reverse_user']" in body


def accepts(home="/var/lib/aegis-client", shell="/usr/sbin/nologin", members=None,
            groups=None, queue="", **changed):
    user = {"name": "aegis-svc", "uid": 991, "gid": 991,
            "home": home, "shell": shell, "group": "aegis-svc",
            "group_gid": 991, "members": [] if members is None else members,
            "reverse_user": "aegis-svc", "reverse_group": "aegis-svc",
            "groups": [991] if groups is None else groups}
    user.update(changed)
    context = {"user": user, "receipt": {"uid": 991, "gid": 991},
               "jobs": queue, "re": re}
    builtins = {"type": type, "int": int, "set": set, "dict": dict}
    return all(eval(code, {"__builtins__": builtins}, context)
               for code in (shape, account, supplementary, jobs))


assert accepts()
assert not accepts(home="/root")
assert not accepts(shell="/bin/bash")
assert not accepts(members=["other"])
assert not accepts(groups=[991, 27])
assert not accepts(uid=990)
assert not accepts(gid=990)
assert not accepts(group_gid=990)
assert not accepts(reverse_user="other")
assert not accepts(reverse_group="other")
assert not accepts(group="other")
assert not accepts(queue="14 aegis-client.service start running\n")
assert not accepts(queue="14 aegis-auto@" + "a" * 64 + ".service start running\n")
assert accepts(queue="14 unrelated.service start running\n")


def nss_program():
    def assignment(index, name):
        return (isinstance(tree.body[index], ast.Assign) and
                len(tree.body[index].targets) == 1 and
                isinstance(tree.body[index].targets[0], ast.Name) and
                tree.body[index].targets[0].id == name)
    begin = [index for index in range(len(tree.body)) if assignment(index, "nss")]
    end = [index for index in range(len(tree.body)) if assignment(index, "nss_query")]
    assert len(begin) == len(end) == 1 and begin[0] < end[0]
    nodes = tree.body[begin[0]:end[0]]
    assert any(isinstance(node, ast.For) for node in nodes)
    return compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                   "install.sh:PY_STAGE_OWNER:nss", "exec")


NSS = nss_program()


def nss_accepts(data):
    def require(ok):
        if not ok:
            raise ValueError("embedded NSS admission refused")
    def read(path, maximum, mode):
        assert path == Path("/etc/nsswitch.conf")
        assert maximum == 1 << 20 and mode == 0o644
        return data
    try:
        exec(NSS, {"need": require, "read": read, "pathlib": __import__("pathlib")})
    except (ValueError, UnicodeError):
        return False
    return True


assert nss_accepts(b"passwd: files\ngroup: files\n")
assert nss_accepts(b"passwd: files systemd\ngroup: files systemd\n"
                   b"initgroups: files systemd # stock fallback\n")
for bad in (b"passwd : sss\npasswd: files\ngroup: files\n",
            b"passwd : files\ngroup: files\n",
            b"passwd: files\ngroup : systemd\ngroup: files\n",
            b"passwd: systemd files\ngroup: files\n",
            b"passwd: files sss\ngroup: files\n",
            b"passwd: files [SUCCESS=return] systemd\ngroup: files\n",
            b"passwd: files systemd systemd\ngroup: files\n",
            b"passwd: files\npasswd: files systemd\ngroup: files\n",
            b"passwd: files\ngroup: files\ninitgroups: files ldap\n",
            b"passwd: files\\\n systemd\ngroup: files\n",
            b"passwd: files#comment\ngroup: files\n",
            b"passwd: files systemd#comment\ngroup: files\n",
            b"passwd: files\ngroup: files\x00\n",
            b"passwd: files\ngroup: files\x1b\n",
            b"passwd: files\ngroup: files\ninitgroups: files syst\xc3\xa9md\n"):
    assert not nss_accepts(bad), bad
conflicting_bundle_sources = subprocess.run(
    ["/bin/bash", str(Path(__file__).resolve().parents[1] / "install.sh"),
     "client", "--stage-auto-device-guard", "--stage-auto-owner-receipt", "/nonexistent/owner.json",
     "--bundle", "/nonexistent/bundle", "--bundle-url-file", "/nonexistent/url",
     "--device-id", "qa-fulltun-device", "--device-certificate", "/nonexistent/cert.pem",
     "--profile", "full-wide-tun"],
    stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
assert conflicting_bundle_sources.returncode == 2
assert b"Staged AUTO guard requires" in conflicting_bundle_sources.stderr
print("PASS: staged owner account, queued-job and bundle-source countercases")
