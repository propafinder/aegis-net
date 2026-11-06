#!/usr/bin/env python3
"""Create one private, short-lived own-bridge pilot material set on this Mac.

No network, host install, profile signing, or public trust is implied.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

os.umask(0o077)
OPENSSL = "/opt/homebrew/opt/openssl@3/bin/openssl"
OUTER_NAME = "bridge.example.com"
INNER_NAMES = ("inner-bridge.example.com", "enroll-bridge.example.com")
ROLES = ("relay", "authority")
KEY_LABELS = {
    "relay_outer_key": "private/relay/outer-key.pem",
    "relay_inner_key": "private/relay/inner-key.pem",
    "relay_admission": "private/relay/admission.hex",
    "authority_outer_key": "private/authority/outer-key.pem",
    "authority_inner_key": "private/authority/inner-key.pem",
    "authority_admission": "private/authority/admission.hex",
    "issuer_ca_key": "private/authority/issuer-ca-key.pem",
}


def need(ok, label):
    if not ok:
        raise ValueError(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_bound(source):
    need(re.fullmatch(r"[0-9a-f]{40}", source) is not None, "source_sha_shape")
    repo = Path(__file__).resolve().parents[1]
    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, capture_output=True,
                              timeout=15, check=False)
    kind = git("cat-file", "-t", source)
    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=all")
    blob = git("show", source + ":scripts/generate-own-https-bridge-pilot-material.py")
    need(all(row.returncode == 0 for row in (kind, head, status, blob)) and
         kind.stdout == b"commit\n" and head.stdout.strip() == source.encode() and
         not status.stdout and blob.stdout == Path(__file__).read_bytes(),
         "source_checkout_or_generator_not_exact")


class PrivateStage:
    def __init__(self, output):
        need(output.is_absolute() and output.name not in ("", ".", "..") and
             output.parent.resolve(strict=True) == output.parent and
             not output.exists() and not output.is_symlink(),
             "fresh_private_output_required")
        self.parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.output = output
        self.dirs = {}
        self.dir_identity = {}
        try:
            parent = os.fstat(self.parent_fd)
            need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
                 stat.S_IMODE(parent.st_mode) == 0o700, "private_parent_required")
            os.mkdir(output.name, mode=0o700, dir_fd=self.parent_fd)
            self.root_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=self.parent_fd)
            self.dirs[""] = self.root_fd
            self.identity = os.fstat(self.root_fd)
        except BaseException:
            os.close(self.parent_fd)
            raise

    def close(self):
        for fd in reversed(list(self.dirs.values())):
            os.close(fd)
        os.close(self.parent_fd)

    def mkdir(self, rel):
        parent, _, name = rel.rpartition("/")
        need(parent in self.dirs and name not in ("", ".", ".."), "private_dir_roster")
        os.mkdir(name, mode=0o700, dir_fd=self.dirs[parent])
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=self.dirs[parent])
        item = os.fstat(fd)
        need(stat.S_ISDIR(item.st_mode) and item.st_uid == os.geteuid() and
             stat.S_IMODE(item.st_mode) == 0o700, "private_dir_identity")
        self.dirs[rel] = fd
        self.dir_identity[rel] = (item.st_dev, item.st_ino)

    def path(self, rel):
        parent, _, name = rel.rpartition("/")
        need(parent in self.dirs and re.fullmatch(r"[a-z0-9.-]+", name) is not None,
             "private_leaf_roster")
        return rel

    def write_new(self, rel, data):
        parent, _, name = rel.rpartition("/")
        need(parent in self.dirs and re.fullmatch(r"[a-z0-9.-]+", name) is not None,
             "private_leaf_roster")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.dirs[parent])
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def read(self, rel):
        parent, _, name = rel.rpartition("/")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.dirs[parent])
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
                 before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                 before.st_size <= 32768, "private_leaf_identity")
            data = stream.read(32769)
            after = os.fstat(stream.fileno())
            need(len(data) == before.st_size and
                 (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                  after.st_ctime_ns), "private_leaf_changed")
            return data

    def run(self, *args):
        command = [OPENSSL, *args]
        # macOS /dev/fd/N is not traversable as a directory by a child.
        # fchdir before exec keeps all relative opens under the held output
        # inode even if its original pathname is renamed concurrently.
        result = subprocess.run(command, pass_fds=(self.root_fd,),
                                preexec_fn=lambda: os.fchdir(self.root_fd),
                                capture_output=True, timeout=30, check=False)
        need(result.returncode == 0 and len(result.stdout) <= 4096,
             "openssl_operation_refused")
        return result.stdout

    def finish(self):
        for rel, identity in self.dir_identity.items():
            parent, _, name = rel.rpartition("/")
            named_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=self.dirs[parent])
            try:
                named = os.fstat(named_fd)
                need((named.st_dev, named.st_ino, stat.S_IMODE(named.st_mode)) ==
                     (*identity, 0o700), "private_dir_path_changed")
            finally:
                os.close(named_fd)
        named_fd = os.open(self.output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                           dir_fd=self.parent_fd)
        try:
            named = os.fstat(named_fd)
            need((named.st_dev, named.st_ino, stat.S_IMODE(named.st_mode)) ==
                 (self.identity.st_dev, self.identity.st_ino, 0o700),
                 "output_path_identity_changed")
        finally:
            os.close(named_fd)
        for fd in self.dirs.values():
            os.fsync(fd)
        os.fsync(self.parent_fd)


def generate(stage, source):
    for directory in ("operator", "public", "private", "private/relay",
                      "private/authority", "state"):
        stage.mkdir(directory)
    version = stage.run("version").decode().strip()
    need(version.startswith("OpenSSL 3.6.3 "), "openssl_version_refused")

    def ca(label, key_rel, cert_rel, algorithm):
        key_args = ("genpkey", "-algorithm", "ED25519") if algorithm == "ed25519" else (
            "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
        stage.run(*key_args, "-out", stage.path(key_rel))
        stage.run("req", "-new", "-x509", "-key", stage.path(key_rel),
                  "-out", stage.path(cert_rel), "-days", "3",
                  "-subj", "/CN=Aegis Own Bridge Pilot " + label,
                  "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                  "-addext", "keyUsage=critical,keyCertSign,cRLSign")

    ca("Outer CA", "operator/outer-ca-key.pem", "public/outer-ca-cert.pem", "p256")
    ca("Inner CA", "operator/inner-ca-key.pem", "public/inner-ca-cert.pem", "p256")
    ca("Device Issuer CA", "private/authority/issuer-ca-key.pem",
       "private/authority/issuer-ca-cert.pem", "ed25519")
    for key, cert in (("operator/outer-ca-key.pem", "public/outer-ca-cert.pem"),
                      ("operator/inner-ca-key.pem", "public/inner-ca-cert.pem"),
                      ("private/authority/issuer-ca-key.pem",
                       "private/authority/issuer-ca-cert.pem")):
        key_pub = stage.run("pkey", "-in", stage.path(key), "-pubout")
        cert_pub = stage.run("x509", "-in", stage.path(cert), "-pubkey", "-noout")
        need(sha(key_pub) == sha(cert_pub), "ca_key_certificate_mismatch")
        stage.run("verify", "-CAfile", stage.path(cert), stage.path(cert))
        constraints = stage.run("x509", "-in", stage.path(cert), "-noout",
                                "-ext", "basicConstraints")
        need(b"CA:TRUE" in constraints, "ca_constraints_refused")

    leaf_roster = (
        ("relay", "outer", OUTER_NAME, "operator/outer-ca-key.pem", "public/outer-ca-cert.pem"),
        ("authority", "outer", OUTER_NAME, "operator/outer-ca-key.pem", "public/outer-ca-cert.pem"),
        ("relay", "inner", INNER_NAMES[0], "operator/inner-ca-key.pem", "public/inner-ca-cert.pem"),
        ("authority", "inner", INNER_NAMES[1], "operator/inner-ca-key.pem", "public/inner-ca-cert.pem"),
    )
    for role, layer, name, ca_key, ca_cert in leaf_roster:
        prefix = f"private/{role}/{layer}"
        key, csr, cert, ext = (prefix + suffix for suffix in
                               ("-key.pem", "-request.pem", "-cert.pem", "-extensions.cnf"))
        stage.run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                  "-out", stage.path(key))
        stage.run("req", "-new", "-key", stage.path(key), "-out", stage.path(csr),
                  "-subj", "/CN=" + name)
        stage.write_new(ext, ("basicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth\n"
                              "subjectAltName=DNS:" + name + "\n").encode())
        stage.run("x509", "-req", "-in", stage.path(csr), "-CA", stage.path(ca_cert),
                  "-CAkey", stage.path(ca_key), "-set_serial", "0x" + os.urandom(16).hex(),
                  "-days", "2", "-extfile", stage.path(ext), "-out", stage.path(cert))
        stage.run("verify", "-CAfile", stage.path(ca_cert), "-purpose", "sslserver",
                  "-verify_hostname", name, stage.path(cert))
        leaf_pub = stage.run("pkey", "-in", stage.path(key), "-pubout")
        cert_pub = stage.run("x509", "-in", stage.path(cert), "-pubkey", "-noout")
        need(sha(leaf_pub) == sha(cert_pub), "leaf_key_certificate_mismatch")
        san = stage.run("x509", "-in", stage.path(cert), "-noout", "-ext", "subjectAltName")
        need(san.count(b"DNS:") == 1 and b"DNS:" + name.encode() in san,
             "leaf_san_mismatch")

    issuer = stage.read("private/authority/issuer-ca-cert.pem")
    stage.write_new("state/device-ca.pem", issuer)
    stage.write_new("public/device-issuer-ca-cert.pem", issuer)
    admission = os.urandom(32).hex().encode()
    need(len(admission) == 64 and admission != b"0" * 64, "admission_entropy_refused")
    for rel in ("private/relay/admission.hex", "private/authority/admission.hex",
                "operator/client-admission.hex"):
        stage.write_new(rel, admission)
    pins = {name: sha(stage.read(rel)) for name, rel in KEY_LABELS.items()}
    need(pins["relay_admission"] == pins["authority_admission"] and
         len(set(pins.values())) == 6, "material_pin_relationship_refused")
    stage.write_new("pins.json", (json.dumps(pins, sort_keys=True, indent=2) + "\n").encode())
    roster = sorted(["pins.json", "state/device-ca.pem", "public/device-issuer-ca-cert.pem",
                     "public/outer-ca-cert.pem", "public/inner-ca-cert.pem",
                     "operator/outer-ca-key.pem", "operator/inner-ca-key.pem",
                     "operator/client-admission.hex", "private/authority/issuer-ca-key.pem",
                     "private/authority/issuer-ca-cert.pem"] +
                    [f"private/{role}/{layer}{suffix}" for role in ROLES
                     for layer in ("outer", "inner") for suffix in
                     ("-key.pem", "-request.pem", "-cert.pem", "-extensions.cnf")] +
                    ["private/relay/admission.hex", "private/authority/admission.hex"])
    file_hashes = {rel: sha(stage.read(rel)) for rel in roster}
    stage.write_new("receipt.json", (json.dumps({
        "schema": "aegis_ownbridge_private_material_r1", "source_commit": source,
        "openssl_version": version, "outer_ca_trust": "own_ca_not_public_browser_trust",
        "outer_san": OUTER_NAME, "inner_sans": list(INNER_NAMES),
        "ca_days": 3, "leaf_days": 2, "four_leaf_chains_and_keys_verified": True,
        "three_ca_keys_and_certs_verified": True,
        "shared_admission_verified": True, "six_unique_material_values": True,
        "file_sha256": file_hashes, "host_mutation": False,
        "installed_or_signed_profile_accepted": False,
    }, sort_keys=True, indent=2) + "\n").encode())
    stage.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        source_bound(args.source_commit)
        stage = PrivateStage(args.output_dir)
        try:
            generate(stage, args.source_commit)
        finally:
            stage.close()
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, "REFUSE: private pilot material generation rejected\n")
    print("PASS: private pilot material generated locally; no host or public trust accepted")


if __name__ == "__main__":
    main()
