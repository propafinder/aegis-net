#!/usr/bin/env python3
"""Verify a separately staged text-only public tree; never export or alter it.

Both control files are UTF-8 JSON arrays. The manifest lists exact relative
POSIX file paths. The private denylist lists case-sensitive strings forbidden
anywhere in a candidate path or text. Diagnostics never contain source text,
denylist values, or control-file paths. This is not a history/secret audit.
"""

import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import parse_qsl, urlsplit


MAX_INPUT_BYTES = 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_FILES = 10000
MAX_DENYLIST_STRINGS = 1000
MAX_TREE_ENTRIES = 20000
MAX_FINDINGS = 100
VCS_COMPONENTS = {".git", ".hg", ".svn", ".bzr"}
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
)
IPV4 = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
DOMAIN = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")
DOMAIN_CANDIDATE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")
RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}


def network_identity_classes(text, approved_domains=()):
    findings = set()
    for match in IPV4.finditer(text):
        try:
            if ipaddress.IPv4Address(match.group()).is_global:
                findings.add("public-ipv4-form")
        except ipaddress.AddressValueError:
            continue
    # Consume each candidate once before the DNS grammar check. This avoids
    # repeatedly backtracking over megabytes of malformed dotted text.
    for match in DOMAIN_CANDIDATE.finditer(text):
        candidate = match.group().removesuffix(".")
        if len(candidate) > 253 or DOMAIN.fullmatch(candidate) is None:
            continue
        domain = candidate.lower()
        if domain.endswith((".invalid", ".test", ".localhost", ".example")) or any(
            domain == reserved or domain.endswith("." + reserved)
            for reserved in RESERVED_DOMAINS
        ):
            continue
        if domain not in approved_domains:
            findings.add("unapproved-domain-form")
    return findings
TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_])"
)
URL = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
URL_SECRET_KEYS = {
    "access_token", "api_key", "apikey", "auth", "authorization", "credential",
    "key", "password", "secret", "sig", "signature", "token", "x-amz-signature",
}


class GateError(Exception):
    """A static finding class; deliberately carries no input or OS message."""


def credential_classes(text):
    findings = set()
    if PRIVATE_KEY.search(text):
        findings.add("private-key-form")
    if TOKEN.search(text):
        findings.add("token-form")
    for match in URL.finditer(text):
        try:
            url = urlsplit(match.group())
            if url.username is not None or any(
                key.casefold() in URL_SECRET_KEYS and value
                for key, value in parse_qsl(url.query, keep_blank_values=True)
            ):
                findings.add("credential-url-form")
        except ValueError:
            # A malformed apparent URL is not safe to silently admit.
            findings.add("malformed-url-form")
    return findings


def _safe_absolute(value):
    if not value or not value.strip() or any(
        ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value
    ):
        raise GateError("unsafe-input-path")
    # Normalizing a symlink/.. pair can select a different tree or control file.
    if ".." in Path(value).parts:
        raise GateError("unsafe-input-path")
    return os.path.abspath(value)


def _require_platform():
    if (
        not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd
        or os.scandir not in os.supports_fd
    ):
        raise GateError("unsupported-safe-filesystem-api")


def _open_component(name, parent_fd, directory):
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        raise GateError("symlink")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise GateError("invalid-directory")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise GateError("non-regular-file")
    if not info.st_mode & 0o444 or directory and not info.st_mode & 0o111:
        raise GateError("unreadable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= os.O_DIRECTORY
    else:
        # A file replaced by a FIFO must not turn verification into a wait.
        flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(fd)
        if (directory and not stat.S_ISDIR(opened.st_mode)) or (
            not directory and not stat.S_ISREG(opened.st_mode)
        ) or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino) or (
            not directory and _signature(info) != _signature(opened)
        ):
            raise GateError("filesystem-changed")
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_absolute(path, directory):
    """Open each component relative to a held directory fd, without symlinks."""
    parts = Path(path).parts
    current = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, component in enumerate(parts[1:], start=1):
            child = _open_component(
                component, current, directory or index < len(parts) - 1
            )
            os.close(current)
            current = child
        result = current
        current = None
        return result
    finally:
        if current is not None:
            os.close(current)


def _signature(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def _read_bounded(fd, limit):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise GateError("non-regular-file")
    if not before.st_mode & 0o444:
        raise GateError("unreadable")
    if before.st_size > limit:
        raise GateError("too-large")
    chunks = []
    size = 0
    while size <= limit:
        chunk = os.read(fd, min(65536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    if size > limit:
        raise GateError("too-large")
    if _signature(before) != _signature(os.fstat(fd)):
        raise GateError("filesystem-changed")
    return b"".join(chunks), (before.st_dev, before.st_ino)


def _read_array(path, category, maximum):
    fd = None
    try:
        fd = _open_absolute(path, directory=False)
        raw, identity = _read_bounded(fd, MAX_INPUT_BYTES)
        values = json.loads(raw.decode("utf-8-sig"))
        if (
            not isinstance(values, list) or not 1 <= len(values) <= maximum
            or any(not isinstance(value, str) or not value.strip() for value in values)
            or any(0xD800 <= ord(c) <= 0xDFFF for value in values for c in value)
            or len(values) != len(set(values))
        ):
            raise GateError("invalid-" + category)
        return values, identity
    except (UnicodeError, ValueError, TypeError, OSError, GateError):
        raise GateError("invalid-" + category) from None
    finally:
        if fd is not None:
            os.close(fd)


def _manifest_paths(values):
    for value in values:
        parts = value.split("/")
        if (
            len(value) > 4096 or len(parts) > 64 or "\\" in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(part in {"", ".", ".."} or part in VCS_COMPONENTS for part in parts)
            or any(any(c in part for c in "*?[]") for part in parts)
        ):
            raise GateError("invalid-manifest-path")
    return set(values)


def check_tree(tree, manifest_file, denylist_file, approved_domains_file=None):
    """Return bounded, content-free diagnostics and an exit code (0, 1, or 2)."""
    result = {"status": "FAIL", "checked_files": 0, "findings": []}
    root_fd = None
    denylist = []
    omitted = 0
    approved_domains = set()

    def finding(category, path=None):
        nonlocal omitted
        if len(result["findings"]) >= MAX_FINDINGS:
            omitted += 1
            return
        item = {"class": category}
        if path is not None:
            # All paths are opaque: even an otherwise harmless filename may
            # carry an identity that a narrow detector does not recognize.
            item["file_index"] = len(result["findings"]) + 1
        result["findings"].append(item)

    def finish(code):
        if omitted:
            result["omitted_findings"] = omitted
        return result, code

    try:
        _require_platform()
        tree = _safe_absolute(tree)
        manifest_file = _safe_absolute(manifest_file)
        denylist_file = _safe_absolute(denylist_file)
        controls = [manifest_file, denylist_file]
        if approved_domains_file is not None:
            approved_domains_file = _safe_absolute(approved_domains_file)
            controls.append(approved_domains_file)
        if tree == os.path.abspath(os.sep) or len(controls) != len(set(controls)):
            raise GateError("unsafe-control-inputs")
        if any(os.path.commonpath([tree, control]) == tree
               for control in controls):
            raise GateError("control-input-inside-tree")
        denylist, denylist_identity = _read_array(
            denylist_file, "denylist", MAX_DENYLIST_STRINGS
        )
        if any("\x00" in value or len(value) > MAX_INPUT_BYTES for value in denylist):
            raise GateError("invalid-denylist")
        manifest_values, manifest_identity = _read_array(
            manifest_file, "manifest", MAX_MANIFEST_FILES
        )
        manifest = _manifest_paths(manifest_values)
        control_identities = {manifest_identity, denylist_identity}
        if approved_domains_file is not None:
            domains, domain_identity = _read_array(
                approved_domains_file, "approved-domains", MAX_DENYLIST_STRINGS
            )
            if any(len(domain) > 253 or DOMAIN.fullmatch(domain) is None or domain != domain.lower()
                   for domain in domains):
                raise GateError("invalid-approved-domains")
            approved_domains = set(domains)
            control_identities.add(domain_identity)
        expected_dirs = set()
        for path in manifest:
            parts = path.split("/")
            expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
        root_fd = _open_absolute(tree, directory=True)
        seen = set()
        total_bytes = 0
        entries = 0

        def walk(directory_fd, prefix=""):
            nonlocal total_bytes, entries
            before = os.fstat(directory_fd)
            try:
                with os.scandir(directory_fd) as listing:
                    for entry in listing:
                        entries += 1
                        if entries > MAX_TREE_ENTRIES:
                            raise GateError("tree-entry-limit")
                        relative = prefix + entry.name
                        info = entry.stat(follow_symlinks=False)
                        if any(value in relative for value in denylist):
                            finding("denylist-path-match", relative)
                        for category in sorted(credential_classes(relative)):
                            finding(category, relative)
                        # Domain syntax in file extensions is ambiguous; path
                        # identities are covered by the mandatory exact denylist.
                        for match in IPV4.finditer(relative):
                            if "public-ipv4-form" in network_identity_classes(match.group()):
                                finding("public-ipv4-form", relative)
                        if stat.S_ISLNK(info.st_mode):
                            finding("symlink", relative)
                            continue
                        if entry.name in VCS_COMPONENTS:
                            finding("version-control-metadata", relative)
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            if relative not in expected_dirs:
                                finding("unlisted-directory", relative)
                                continue
                            child = None
                            try:
                                child = _open_component(entry.name, directory_fd, True)
                                walk(child, relative + "/")
                            except (OSError, GateError) as error:
                                finding(str(error) if isinstance(error, GateError) else "unreadable", relative)
                            finally:
                                if child is not None:
                                    os.close(child)
                            continue
                        if relative not in manifest:
                            finding("unlisted-file", relative)
                            continue
                        seen.add(relative)
                        if not stat.S_ISREG(info.st_mode):
                            finding("non-regular-file", relative)
                            continue
                        fd = None
                        try:
                            fd = _open_component(entry.name, directory_fd, False)
                            raw, identity = _read_bounded(fd, min(
                                MAX_FILE_BYTES, MAX_TOTAL_BYTES - total_bytes
                            ))
                            if identity in control_identities:
                                raise GateError("control-file-in-tree")
                            total_bytes += len(raw)
                            text = raw.decode("utf-8")
                            if any(ord(c) < 32 and c not in "\n\r\t" or ord(c) == 127 for c in text):
                                raise GateError("binary-or-unsupported-text")
                            result["checked_files"] += 1
                            if any(value in text for value in denylist):
                                finding("denylist-content-match", relative)
                            for category in sorted(credential_classes(text)):
                                finding(category, relative)
                            for category in sorted(network_identity_classes(text, approved_domains)):
                                finding(category, relative)
                        except UnicodeError:
                            finding("binary-or-unsupported-text", relative)
                        except (OSError, GateError) as error:
                            finding(str(error) if isinstance(error, GateError) else "unreadable", relative)
                        finally:
                            if fd is not None:
                                os.close(fd)
                if _signature(before) != _signature(os.fstat(directory_fd)):
                    finding("filesystem-changed", prefix.rstrip("/") or ".")
            except OSError:
                finding("unreadable-directory", prefix.rstrip("/") or ".")

        walk(root_fd)
        for missing in sorted(manifest - seen):
            finding("missing-manifest-file", missing)
        if not result["findings"] and not omitted:
            result["status"] = "PASS"
            return finish(0)
        return finish(1)
    except GateError as error:
        finding(str(error))
        return finish(2)
    except OSError as error:
        finding("symlink" if error.errno == errno.ELOOP else "unreadable-input")
        return finish(2)
    except Exception:
        # An unexpected failure must not expose paths or parser/source excerpts.
        finding("internal-verification-error")
        return finish(2)
    finally:
        if root_fd is not None:
            os.close(root_fd)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({"status": "FAIL", "findings": [{"class": "invalid-cli"}]}))
        raise SystemExit(2)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--tree", required=True, help="separately staged candidate directory")
    parser.add_argument("--manifest-file", required=True, help="external JSON file of exact relative paths")
    parser.add_argument("--denylist-file", required=True, help="external private JSON file of forbidden strings")
    parser.add_argument("--approved-domains-file", help="external owner-reviewed JSON array of exact permitted domain names")
    args = parser.parse_args(argv)
    result, code = check_tree(args.tree, args.manifest_file, args.denylist_file, args.approved_domains_file)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
