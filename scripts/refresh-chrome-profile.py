#!/usr/bin/env python3
"""Capture Chrome stable and show drift against the mimicry profile.

Reads aegis-chrome-profile/chrome-stable.toml. With --write, updates that
file when TCP TLS, HTTP/2, QUIC or the User-Agent drifted, then the caller
runs the profile tests. Live comparisons are local only: a TCP ClientHello
listener, a self-signed HTTP/2 server, and a QUIC Initial catcher. No TLS
key log is written.

Exit 0 when the profile matches, 2 when drift was reported or written,
1 when Chrome could not be measured. --require-chrome turns a missing
browser into exit 1 instead of a quiet skip.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "aegis-chrome-profile" / "chrome-stable.toml"
PREFACE_FIXTURE = ROOT / "aegis-chrome-profile" / "fixtures" / "h2-connection-preface.hex"

GREASE = lambda v: (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)

TLS13 = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
TLS12 = {
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xC013: "ECDHE-RSA-AES128-SHA",
    0xC014: "ECDHE-RSA-AES256-SHA",
    0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384",
    0x002F: "AES128-SHA",
    0x0035: "AES256-SHA",
}
GROUPS = {
    0x11EC: "X25519MLKEM768",
    0x001D: "X25519",
    0x0017: "P-256",
    0x0018: "P-384",
    0x0019: "P-521",
}
SETTING_NAMES = {
    1: "HEADER_TABLE_SIZE",
    2: "ENABLE_PUSH",
    3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE",
    5: "MAX_FRAME_SIZE",
    6: "MAX_HEADER_LIST_SIZE",
    8: "ENABLE_CONNECT_PROTOCOL",
}


def find_chrome(explicit: str | None) -> str | None:
    if explicit and os.access(explicit, os.X_OK):
        return explicit
    home = Path.home()
    candidates = [
        home
        / ".aegis-local/chrome/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        home
        / ".aegis-local/chrome/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path("/usr/bin/google-chrome"),
        Path("/usr/bin/google-chrome-stable"),
    ]
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def chrome_version(binary: str) -> str:
    out = subprocess.check_output([binary, "--version"], text=True, stderr=subprocess.DEVNULL)
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", out)
    return match.group(1) if match else "unknown"


def parse_client_hello(record: bytes) -> dict:
    if len(record) < 5 or record[0] != 22:
        raise ValueError("not a handshake record")
    body = record[5 : 5 + struct.unpack(">H", record[3:5])[0]]
    if not body or body[0] != 1:
        raise ValueError("not a ClientHello")
    ch = body[4:]
    o = 2 + 32
    sid_len = ch[o]
    o += 1 + sid_len
    cs_len = struct.unpack(">H", ch[o : o + 2])[0]
    o += 2
    ciphers = [struct.unpack(">H", ch[o + i : o + i + 2])[0] for i in range(0, cs_len, 2)]
    o += cs_len
    comp_len = ch[o]
    o += 1 + comp_len
    ext_len = struct.unpack(">H", ch[o : o + 2])[0]
    o += 2
    end = o + ext_len
    extensions = []
    groups = []
    sigalgs = []
    alpn = []
    while o + 4 <= end and o + 4 <= len(ch):
        et, el = struct.unpack(">HH", ch[o : o + 4])
        payload = ch[o + 4 : o + 4 + el]
        extensions.append(et)
        if et == 10 and len(payload) >= 2:
            glen = struct.unpack(">H", payload[:2])[0]
            groups = [
                struct.unpack(">H", payload[2 + i : 4 + i])[0] for i in range(0, glen, 2)
            ]
        if et == 13 and len(payload) >= 2:
            slen = struct.unpack(">H", payload[:2])[0]
            sigalgs = [
                struct.unpack(">H", payload[2 + i : 4 + i])[0] for i in range(0, slen, 2)
            ]
        if et == 16 and payload:
            i = 2
            while i < len(payload):
                n = payload[i]
                alpn.append(payload[i + 1 : i + 1 + n].decode("ascii", "replace"))
                i += 1 + n
        o += 4 + el
    real = [c for c in ciphers if not GREASE(c)]
    return {
        "ciphers": real,
        "tls13": [TLS13[c] for c in real if c in TLS13],
        "tls12": [TLS12[c] for c in real if c in TLS12],
        "unknown_ciphers": [c for c in real if c not in TLS13 and c not in TLS12],
        "groups": [GROUPS.get(g, f"0x{g:04x}") for g in groups if not GREASE(g)],
        "group_ids": [g for g in groups if not GREASE(g)],
        "sigalgs": [f"0x{s:04x}" for s in sigalgs if not GREASE(s)],
        "extensions": extensions,
        "alpn": alpn,
        "grease": any(GREASE(v) for v in ciphers + extensions + groups),
    }


def read_tls_record(conn: socket.socket) -> bytes:
    header = b""
    while len(header) < 5:
        chunk = conn.recv(5 - len(header))
        if not chunk:
            break
        header += chunk
    if len(header) < 5:
        raise ValueError("short TLS record")
    need = struct.unpack(">H", header[3:5])[0]
    body = b""
    while len(body) < need:
        chunk = conn.recv(need - len(body))
        if not chunk:
            break
        body += chunk
    return header + body


def capture_tcp_hello(chrome: str, user_dir: str) -> dict:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(20)
    port = server.getsockname()[1]
    holder: dict = {}

    def accept() -> None:
        try:
            conn, _ = server.accept()
            conn.settimeout(10)
            holder["record"] = read_tls_record(conn)
            conn.close()
        except Exception as exc:  # noqa: BLE001 - reported by the caller
            holder["error"] = exc

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    launch_chrome(chrome, user_dir, f"https://127.0.0.1:{port}/", quic_port=None)
    thread.join(timeout=25)
    server.close()
    if "record" not in holder:
        raise RuntimeError(f"no TCP ClientHello ({holder.get('error')})")
    return parse_client_hello(holder["record"])


def launch_chrome(chrome: str, user_dir: str, url: str, quic_port: int | None) -> None:
    # Only a throwaway profile under the system temporary directory. A real
    # browser profile, or Chrome's macOS keychain item, must never be opened:
    # an earlier run without the mock keychain raised a keychain prompt.
    temp_root = Path(tempfile.gettempdir()).resolve()
    if not user_dir or not Path(user_dir).resolve().is_relative_to(temp_root):
        raise RuntimeError(f"refusing a Chrome user-data-dir outside {temp_root}")
    args = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--ignore-certificate-errors",
        "--allow-insecure-localhost",
        "--disable-background-networking",
        "--use-mock-keychain",
        "--password-store=basic",
        f"--user-data-dir={user_dir}",
        "--virtual-time-budget=8000",
        url,
    ]
    if quic_port is not None:
        args.insert(-1, f"--origin-to-force-quic-on=127.0.0.1:{quic_port}")
        args.insert(-1, "--enable-quic")
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def make_cert(directory: Path) -> tuple[Path, Path]:
    key = directory / "key.pem"
    cert = directory / "cert.pem"
    openssl = os.environ.get("OPENSSL", "openssl")
    for candidate in ("/opt/homebrew/bin/openssl", "/usr/bin/openssl", "openssl"):
        if candidate == "openssl" or Path(candidate).exists():
            openssl = candidate
            break
    subprocess.check_call(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


def parse_h2_frames(data: bytes) -> list[dict]:
    magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if data.startswith(magic):
        data = data[len(magic) :]
    frames = []
    o = 0
    while o + 9 <= len(data):
        length = int.from_bytes(data[o : o + 3], "big")
        kind = data[o + 3]
        flags = data[o + 4]
        stream = int.from_bytes(data[o + 5 : o + 9], "big")
        payload = data[o + 9 : o + 9 + length]
        if len(payload) < length:
            break
        item = {"type": kind, "flags": flags, "stream": stream, "payload": payload}
        if kind == 4:
            item["settings"] = [
                (struct.unpack(">H", payload[i : i + 2])[0], struct.unpack(">I", payload[i + 2 : i + 6])[0])
                for i in range(0, len(payload) - len(payload) % 6, 6)
            ]
        if kind == 8 and len(payload) == 4:
            item["increment"] = struct.unpack(">I", payload)[0] & 0x7FFFFFFF
        if kind == 1:
            item["priority"] = bool(flags & 0x20)
            if item["priority"] and len(payload) >= 5:
                dep = struct.unpack(">I", payload[:4])[0]
                item["exclusive"] = bool(dep & 0x80000000)
                item["dependency"] = dep & 0x7FFFFFFF
                item["weight"] = payload[4]
        frames.append(item)
        o += 9 + length
    return frames


def capture_h2(chrome: str, user_dir: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="aegis-chrome-h2-") as tmp:
        cert, key = make_cert(Path(tmp))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["h2"])
        raw = socket.socket()
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(("127.0.0.1", 0))
        raw.listen(1)
        raw.settimeout(20)
        port = raw.getsockname()[1]
        holder: dict = {}

        def accept() -> None:
            # Chrome may open and reset a probe connection before the one
            # that carries the HTTP/2 preface.
            deadline = time.time() + 18
            while time.time() < deadline and "bytes" not in holder:
                try:
                    raw.settimeout(max(0.5, deadline - time.time()))
                    conn, _ = raw.accept()
                    tls = context.wrap_socket(conn, server_side=True)
                    tls.settimeout(3)
                    blob = b""
                    while len(blob) < 256:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        blob += chunk
                        if b"PRI * HTTP/2.0" in blob and len(blob) > 40:
                            tls.settimeout(0.4)
                            try:
                                extra = tls.recv(8192)
                                if extra:
                                    blob += extra
                            except Exception:
                                pass
                            break
                    if blob:
                        holder["bytes"] = blob
                        holder["alpn"] = tls.selected_alpn_protocol()
                        holder["preview"] = blob[:80]
                    tls.close()
                except Exception as exc:  # noqa: BLE001
                    holder["error"] = exc

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        launch_chrome(chrome, user_dir, f"https://127.0.0.1:{port}/", quic_port=None)
        thread.join(timeout=25)
        raw.close()
    if "bytes" not in holder:
        raise RuntimeError(f"no HTTP/2 frames ({holder.get('error')})")
    frames = parse_h2_frames(holder["bytes"])
    settings = next((frame["settings"] for frame in frames if frame["type"] == 4), [])
    window = next((frame.get("increment") for frame in frames if frame["type"] == 8 and frame["stream"] == 0), None)
    headers = next((frame for frame in frames if frame["type"] == 1), None)
    return {
        "alpn": holder.get("alpn"),
        "preview": holder.get("preview", b""),
        "settings": settings,
        "window_increment": window,
        "headers_priority": None
        if headers is None
        else {
            "present": headers.get("priority", False),
            "exclusive": headers.get("exclusive"),
            "dependency": headers.get("dependency"),
            "weight": headers.get("weight"),
            "flags": headers.get("flags"),
        },
        "frame_types": [frame["type"] for frame in frames],
    }


# --- QUIC Initial decryption (RFC 9001), pure Python AES-128-GCM ---

SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def xtime(value: int) -> int:
    return ((value << 1) ^ 0x1B) & 0xFF if value & 0x80 else (value << 1) & 0xFF


def expand_key(key: bytes) -> list[bytes]:
    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    rounds = []
    for r in range(11):
        block = []
        for word in words[r * 4 : r * 4 + 4]:
            block.extend(word)
        rounds.append(bytes(block))
    return rounds


def aes_encrypt_block(block: bytes, rounds: list[bytes]) -> bytes:
    state = [block[i] ^ rounds[0][i] for i in range(16)]
    for rnd in range(1, 10):
        state = [SBOX[b] for b in state]
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]
        mixed = []
        for col in range(4):
            s = state[col * 4 : col * 4 + 4]
            mixed.extend(
                [
                    xtime(s[0]) ^ xtime(s[1]) ^ s[1] ^ s[2] ^ s[3],
                    s[0] ^ xtime(s[1]) ^ xtime(s[2]) ^ s[2] ^ s[3],
                    s[0] ^ s[1] ^ xtime(s[2]) ^ xtime(s[3]) ^ s[3],
                    xtime(s[0]) ^ s[0] ^ s[1] ^ s[2] ^ xtime(s[3]),
                ]
            )
        state = [a ^ b for a, b in zip(mixed, rounds[rnd])]
    state = [SBOX[b] for b in state]
    state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11],
    ]
    return bytes(a ^ b for a, b in zip(state, rounds[10]))


def ghash(h: bytes, aad: bytes, ct: bytes) -> bytes:
    rounds = expand_key(h)

    def mul(x: int, y: int) -> int:
        z = 0
        v = y
        for i in range(128):
            if x & (1 << (127 - i)):
                z ^= v
            v = (v >> 1) ^ (0xE1000000000000000000000000000000 if v & 1 else 0)
        return z

    h_int = int.from_bytes(aes_encrypt_block(b"\x00" * 16, rounds), "big")
    acc = 0
    for data in (aad, ct):
        padded = data + b"\x00" * ((16 - len(data) % 16) % 16)
        for i in range(0, len(padded), 16):
            acc = mul(acc ^ int.from_bytes(padded[i : i + 16], "big"), h_int)
    lengths = (len(aad) * 8 << 64) | (len(ct) * 8)
    acc = mul(acc ^ lengths, h_int)
    return acc.to_bytes(16, "big")


def aes_gcm_decrypt(key: bytes, iv: bytes, aad: bytes, blob: bytes) -> bytes | None:
    if len(blob) < 16 or len(iv) != 12:
        return None
    ct, tag = blob[:-16], blob[-16:]
    rounds = expand_key(key)
    # 96-bit IV: J0 is IV || 1, and the first counter block is inc32(J0).
    j0 = int.from_bytes(iv + b"\x00\x00\x00\x01", "big")
    stream = b""
    blocks = (len(ct) + 15) // 16
    for i in range(1, blocks + 1):
        stream += aes_encrypt_block((j0 + i).to_bytes(16, "big"), rounds)
    plain = bytes(a ^ b for a, b in zip(ct, stream))
    expected = bytes(a ^ b for a, b in zip(ghash(key, aad, ct), aes_encrypt_block(j0.to_bytes(16, "big"), rounds)))
    return plain if hmac.compare_digest(expected, tag) else None


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    return hkdf_expand(secret, info, length)


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    prefix = first >> 6
    length = 1 << prefix
    raw = int.from_bytes(data[offset : offset + length], "big")
    return raw & ((1 << (8 * length - 2)) - 1), offset + length


def decrypt_quic_initial(packet: bytes) -> list[tuple[int, bytes]] | None:
    if len(packet) < 7 or packet[0] & 0x80 == 0 or packet[0] & 0x30 != 0:
        return None
    version = packet[1:5]
    if version != b"\x00\x00\x00\x01":
        return None
    offset = 5
    dcid_len = packet[offset]
    offset += 1
    dcid = packet[offset : offset + dcid_len]
    offset += dcid_len
    scid_len = packet[offset]
    offset += 1 + scid_len
    token_len, offset = read_varint(packet, offset)
    offset += token_len
    _length, offset = read_varint(packet, offset)
    pn_offset = offset
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    initial = hmac.new(salt, dcid, hashlib.sha256).digest()
    client = hkdf_label(initial, b"client in", 32)
    key = hkdf_label(client, b"quic key", 16)
    iv = hkdf_label(client, b"quic iv", 12)
    hp = hkdf_label(client, b"quic hp", 16)
    sample = packet[pn_offset + 4 : pn_offset + 20]
    if len(sample) < 16:
        return None
    mask = aes_encrypt_block(sample, expand_key(hp))
    first = packet[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn = bytes(packet[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
    packet_number = int.from_bytes(pn, "big")
    header = bytes([first]) + packet[1:pn_offset] + pn
    payload = packet[pn_offset + pn_len :]
    nonce = (int.from_bytes(iv, "big") ^ packet_number).to_bytes(12, "big")
    plain = aes_gcm_decrypt(key, nonce, header, payload)
    if plain is None:
        return None
    # CRYPTO frames inside the plaintext. A Chrome Initial splits the
    # ClientHello across packets because the ML-KEM key share is large.
    cursor = 0
    chunks = []
    while cursor < len(plain):
        frame_type = plain[cursor]
        cursor += 1
        if frame_type in (0x00, 0x01):
            continue
        if frame_type == 0x06:
            offset_value, cursor = read_varint(plain, cursor)
            length, cursor = read_varint(plain, cursor)
            chunks.append((offset_value, plain[cursor : cursor + length]))
            cursor += length
            continue
        break
    return chunks or None


def assemble_client_hello(chunks: list[tuple[int, bytes]]) -> bytes | None:
    occupied: dict[int, int] = {}
    end = 0
    for offset, data in chunks:
        for index, byte in enumerate(data):
            occupied[offset + index] = byte
        end = max(end, offset + len(data))
    if end < 4 or any(index not in occupied for index in range(end)):
        return None
    blob = bytes(occupied[index] for index in range(end))
    if blob[0] != 1:
        return None
    hello_len = int.from_bytes(blob[1:4], "big")
    if len(blob) < 4 + hello_len:
        return None
    return blob[: 4 + hello_len]


def capture_quic(chrome: str, user_dir: str) -> dict | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.5)
    port = sock.getsockname()[1]
    chunks: list[tuple[int, bytes]] = []

    def listen() -> None:
        deadline = time.time() + 18
        while time.time() < deadline and len(chunks) < 32:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                if assemble_client_hello(chunks) is not None:
                    return
                continue
            piece = decrypt_quic_initial(data)
            if piece:
                chunks.extend(piece)
                if assemble_client_hello(chunks) is not None:
                    return

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    launch_chrome(chrome, user_dir, f"https://127.0.0.1:{port}/", quic_port=port)
    thread.join(timeout=20)
    sock.close()
    body = assemble_client_hello(chunks)
    if body is None:
        return None
    # Wrap as a TLS record so the TCP parser can reuse the handshake body.
    record = bytes([22, 3, 1]) + len(body).to_bytes(2, "big") + body
    parsed = parse_client_hello(record)
    parsed["grease_extensions"] = any(GREASE(item) for item in parsed["extensions"])
    return parsed


def quoted_list(values: list[str]) -> str:
    return "[" + ", ".join(f'"{item}"' for item in values) + "]"


def hex_list(values: list[str]) -> str:
    return "[" + ", ".join(f'"{item}"' for item in values) + "]"


def replace_array(text: str, key: str, rendered: str) -> str:
    pattern = re.compile(rf"(?m)^({re.escape(key)}\s*=\s*)\[[^\]]*\]")
    if not pattern.search(text):
        raise RuntimeError(f"profile is missing {key}")
    return pattern.sub(rf"\1{rendered}", text, count=1)


def section_array(text: str, section: str, key: str, rendered: str) -> str:
    """Replace key = [...] inside one [section] block."""
    match = re.search(rf"(?m)^\[{re.escape(section)}\]\s*$", text)
    if not match:
        raise RuntimeError(f"missing [{section}]")
    start = match.end()
    nxt = re.search(r"(?m)^\[", text[start:])
    end = start + nxt.start() if nxt else len(text)
    block = text[start:end]
    updated = replace_array(block, key, rendered)
    return text[:start] + updated + text[end:]


def load_profile_text() -> str:
    return PROFILE.read_text()


def profile_value(text: str, key: str) -> str | None:
    match = re.search(rf'(?m)^{re.escape(key)}\s*=\s*"([^"]*)"', text)
    return match.group(1) if match else None


def profile_int(text: str, key: str) -> int | None:
    match = re.search(rf"(?m)^{re.escape(key)}\s*=\s*(\d+)", text)
    return int(match.group(1)) if match else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="update the profile when it drifted")
    parser.add_argument("--chrome", default=None, help="Chrome binary to measure")
    parser.add_argument("--require-chrome", action="store_true")
    args = parser.parse_args()
    binary = find_chrome(args.chrome)
    if not binary:
        print("SKIP: Chrome is not installed")
        return 1 if args.require_chrome else 0
    version = chrome_version(binary)
    major = version.split(".", 1)[0]
    print(f"chrome {version} at {binary}")
    with tempfile.TemporaryDirectory(prefix="aegis-chrome-profile-") as user_dir:
        tcp = capture_tcp_hello(binary, user_dir + "/tcp")
        try:
            h2 = capture_h2(binary, user_dir + "/h2")
        except RuntimeError as exc:
            print(f"h2 local preface not observed ({exc})")
            h2 = {
                "alpn": None,
                "preview": b"",
                "settings": [],
                "window_increment": None,
                "headers_priority": None,
                "frame_types": [],
            }
        quic = capture_quic(binary, user_dir + "/quic")
    print("tcp ciphers", tcp["tls13"], tcp["tls12"])
    print("tcp groups", tcp["groups"])
    print("tcp sigalgs", " ".join(tcp["sigalgs"]))
    print("tcp alpn", tcp["alpn"], "grease", tcp["grease"])
    print(
        "h2 settings",
        [(SETTING_NAMES.get(i, i), v) for i, v in h2["settings"]],
        "window",
        h2["window_increment"],
        "priority",
        h2["headers_priority"],
        "alpn",
        h2["alpn"],
        "preview",
        h2.get("preview"),
    )
    if quic is not None and (not quic["sigalgs"] or quic["alpn"] != ["h3"]):
        print("quic capture incomplete", "alpn", quic["alpn"], "sigalgs", quic["sigalgs"])
        quic = None
    if quic is None:
        print("quic capture missed")
    else:
        print("quic groups", quic["groups"])
        print("quic sigalgs", " ".join(quic["sigalgs"]))
        print("quic grease", quic["grease"], "ext grease", quic["grease_extensions"])
        print("quic alpn", quic["alpn"])
    text = load_profile_text()
    drift = []
    pinned_major = str(profile_int(text, "major") or "")
    if pinned_major != major:
        drift.append(f"user-agent major {pinned_major} -> {major}")
    # Compare the TLS lists currently in the file by their rendered form.
    def current_array(section: str, key: str) -> str:
        match = re.search(rf"(?ms)^\[{section}\].*?^{key}\s*=\s*(\[[^\]]*\])", text)
        return re.sub(r"\s+", "", match.group(1)) if match else ""

    wanted_tls13 = quoted_list(tcp["tls13"])
    wanted_tls12 = quoted_list(tcp["tls12"])
    wanted_groups = quoted_list(tcp["groups"])
    wanted_sigs = hex_list(tcp["sigalgs"])
    if current_array("tls", "tls13_ciphers") != re.sub(r"\s+", "", wanted_tls13):
        drift.append("tcp tls1.3 ciphers")
    if current_array("tls", "tls12_ciphers") != re.sub(r"\s+", "", wanted_tls12):
        drift.append("tcp tls1.2 ciphers")
    if current_array("tls", "groups") != re.sub(r"\s+", "", wanted_groups):
        drift.append("tcp groups")
    if current_array("tls", "signature_algorithms") != re.sub(r"\s+", "", wanted_sigs):
        drift.append("tcp signature algorithms")
    window = h2["window_increment"]
    if window is not None and profile_int(text, "connection_window_increment") != window:
        drift.append(f"http2 window {profile_int(text, 'connection_window_increment')} -> {window}")
    if h2["settings"]:
        current_settings = re.findall(
            r"(?ms)^\[\[http2\.settings\]\]\s*^id\s*=\s*(\d+)\s*^value\s*=\s*(\d+)",
            text,
        )
        wanted_settings = [(str(sid), str(value)) for sid, value in h2["settings"]]
        if current_settings != wanted_settings:
            drift.append(f"http2 settings {current_settings} -> {wanted_settings}")
    if quic is not None and quic["sigalgs"]:
        qgroups = quoted_list(quic["groups"])
        qsigs = hex_list(quic["sigalgs"])
        if current_array("quic", "groups") != re.sub(r"\s+", "", qgroups):
            drift.append("quic groups")
        if current_array("quic", "signature_algorithms") != re.sub(r"\s+", "", qsigs):
            drift.append("quic signature algorithms")
    if not drift:
        print("OK: profile matches this Chrome")
        return 0
    print("DRIFT:")
    for item in drift:
        print(" -", item)
    if not args.write:
        return 2
    today = time.strftime("%Y-%m-%d")
    text = re.sub(r'(?m)^measured_chrome\s*=\s*"[^"]*"', f'measured_chrome = "{major}"', text, count=1)
    text = re.sub(r'(?m)^measured_on\s*=\s*"[^"]*"', f'measured_on = "{today}"', text, count=1)
    text = re.sub(r"(?m)^major\s*=\s*\d+", f"major = {major}", text, count=1)
    text = re.sub(r"Chrome/\d+\.0\.0\.0", f"Chrome/{major}.0.0.0", text)
    text = section_array(text, "tls", "tls13_ciphers", wanted_tls13)
    text = section_array(text, "tls", "tls12_ciphers", wanted_tls12)
    text = section_array(text, "tls", "groups", wanted_groups)
    text = section_array(text, "tls", "signature_algorithms", wanted_sigs)
    if window is not None:
        text = re.sub(
            r"(?m)^(connection_window_increment\s*=\s*)\d+",
            rf"\g<1>{window}",
            text,
            count=1,
        )
    if quic is not None:
        text = section_array(text, "quic", "groups", quoted_list(quic["groups"]))
        text = section_array(text, "quic", "signature_algorithms", hex_list(quic["sigalgs"]))
        text = section_array(text, "quic", "tls13_ciphers", quoted_list(quic["tls13"]))
        grease = "true" if quic["grease"] or quic["grease_extensions"] else "false"
        # Only the cipher/extension/group GREASE bit. ECH grease is separate.
        text = re.sub(
            r"(?ms)(\[quic\][^\[]*?^grease\s*=\s*)(true|false)",
            rf"\g<1>{grease}",
            text,
            count=1,
        )
    # HTTP/2 settings: rewrite the [[http2.settings]] tables when the list changed.
    if h2["settings"]:
        block = "\n".join(
            f"[[http2.settings]]\nid = {sid}\nvalue = {value}\n" for sid, value in h2["settings"]
        )
        text = re.sub(r"(?ms)^\[\[http2\.settings\]\].*\Z", block, text, count=1)
    PROFILE.write_text(text)
    if h2["settings"]:
        preface = h2_preface(h2["settings"], window or 0)
        PREFACE_FIXTURE.write_text(preface.hex() + "\n")
    print(f"wrote {PROFILE.relative_to(ROOT)}")
    return 2


def h2_preface(settings: list[tuple[int, int]], window: int) -> bytes:
    def frame(kind: int, payload: bytes) -> bytes:
        return len(payload).to_bytes(3, "big") + bytes([kind, 0]) + (0).to_bytes(4, "big") + payload

    payload = b"".join(sid.to_bytes(2, "big") + value.to_bytes(4, "big") for sid, value in settings)
    out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, payload)
    if window:
        out += frame(8, window.to_bytes(4, "big"))
    return out


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
