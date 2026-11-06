#!/usr/bin/env python3
# One-shot TCP listener: capture a TLS ClientHello and print JA3 + JA4 hashes.
# Used by the chrome-like-tls JA4-parity proof harness. Prints:
#   JA3=<str>
#   JA4C=<12hex sorted-cipher sha256>  JA4E=<12hex sorted-ext sha256>
# GREASE values (RFC 8701) are excluded; extension 0 (SNI) is excluded from the
# JA4 ext hash so hostname/IP captures compare apples-to-apples.
import socket, sys, hashlib, struct

def is_grease(v):
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)

def parse(ch):
    o = 2 + 32
    sidlen = ch[o]; o += 1 + sidlen
    cslen = struct.unpack('>H', ch[o:o+2])[0]; o += 2
    ciphers = [struct.unpack('>H', ch[o+i:o+i+2])[0] for i in range(0, cslen, 2)]; o += cslen
    complen = ch[o]; o += 1 + complen
    extlen = struct.unpack('>H', ch[o:o+2])[0]; o += 2
    end = o + extlen
    exts, curves, pointfmts = [], [], []
    while o + 4 <= end:
        et = struct.unpack('>H', ch[o:o+2])[0]
        el = struct.unpack('>H', ch[o+2:o+4])[0]
        body = ch[o+4:o+4+el]
        exts.append(et)
        if et == 10 and len(body) >= 2:
            gl = struct.unpack('>H', body[0:2])[0]
            curves = [struct.unpack('>H', body[2+i:4+i])[0] for i in range(0, gl, 2)]
        if et == 11 and len(body) >= 1:
            pointfmts = list(body[1:1+body[0]])
        o += 4 + el
    ver = struct.unpack('>H', ch[0:2])[0]
    f = lambda xs: [x for x in xs if not is_grease(x)]
    ja3 = "%d,%s,%s,%s,%s" % (ver, '-'.join(map(str, f(ciphers))),
                             '-'.join(map(str, f(exts))),
                             '-'.join(map(str, f(curves))),
                             '-'.join(map(str, pointfmts)))
    ja4c = hashlib.sha256('-'.join('%04x' % x for x in sorted(f(ciphers))).encode()).hexdigest()[:12]
    ja4e = hashlib.sha256('-'.join('%04x' % x for x in sorted(x for x in f(exts) if x != 0)).encode()).hexdigest()[:12]
    return ja3, ja4c, ja4e

port = int(sys.argv[1])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port)); s.listen(1); s.settimeout(int(sys.argv[2]) if len(sys.argv) > 2 else 20)
print("LISTEN %d" % port, flush=True)
c, _ = s.accept()
buf = b''
while len(buf) < 5:
    d = c.recv(4096)
    if not d: break
    buf += d
reclen = struct.unpack('>H', buf[3:5])[0]
while len(buf) < 5 + reclen:
    d = c.recv(4096)
    if not d: break
    buf += d
ja3, ja4c, ja4e = parse(buf[5:5+reclen][4:])
print("JA3=" + ja3)
print("JA4C=%s JA4E=%s" % (ja4c, ja4e))
c.close(); s.close()
