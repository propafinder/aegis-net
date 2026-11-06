#!/usr/bin/env python3
"""One-shot TCP listener that saves the raw TLS ClientHello to a file.

Exists so a ClientHello can be turned into a pcap and dissected by the SAME
tshark that the witness scorer uses. The other capture helper in this directory
(`ja4-clienthello-capture.py`) computes its own sorted-cipher/extension hashes,
which are NOT the canonical JA4 string tshark emits — comparing the two
dialects manufactures a mismatch. Capturing bytes and letting one tshark
compute both sides removes the question.

Usage: clienthello-raw-capture.py <port> <output.raw> [timeout_secs]
"""
import socket
import struct
import sys

port = int(sys.argv[1])
out_path = sys.argv[2]
timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 20

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
srv.settimeout(timeout)
print("LISTEN %d" % port, flush=True)

conn, _ = srv.accept()
# The listener timeout does NOT apply to the accepted socket, so a peer that
# connects and then stalls would block recv() forever despite a timeout being
# requested. Set it on the connection too.
conn.settimeout(timeout)

buf = b""
try:
    while len(buf) < 5:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    if len(buf) >= 5:
        record_len = struct.unpack(">H", buf[3:5])[0]
        while len(buf) < 5 + record_len:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
except socket.timeout:
    pass
finally:
    conn.close()
    srv.close()

if len(buf) < 5:
    print("SHORT: only %d bytes, no TLS record header" % len(buf), flush=True)
    sys.exit(1)

record_len = struct.unpack(">H", buf[3:5])[0]
# A truncated record must NOT be written. raw-clienthello-to-ja4.sh would
# happily compute a JA4 over the partial bytes and report a parity result that
# looks real and is not.
if len(buf) < 5 + record_len:
    print(
        "TRUNCATED: got %d of %d bytes; refusing to write a partial ClientHello"
        % (len(buf), 5 + record_len),
        flush=True,
    )
    sys.exit(1)

record = buf[: 5 + record_len]
with open(out_path, "wb") as handle:
    handle.write(record)
print("WROTE %s %d bytes" % (out_path, len(record)), flush=True)
