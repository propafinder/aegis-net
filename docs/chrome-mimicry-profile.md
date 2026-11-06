# Chrome mimicry profile

TCP TLS, QUIC and HTTP/2 read one file, `aegis-chrome-profile/chrome-stable.toml`.
The crate parses it at build time and again in tests. A profile whose HTTP/2
SETTINGS or connection window do not match
`aegis-chrome-profile/fixtures/h2-connection-preface.hex` does not build.

What the file drives:

- TLS 1.3 and TLS 1.2 cipher order, groups, signature algorithms, GREASE,
  extension permutation, OCSP, SCTs, certificate compression, ALPS and ECH GREASE.
- The same lists for QUIC, with GREASE, OCSP and SCTs off unless the file says
  otherwise. QUIC transport numbers are recorded under `[quic.transport]` and
  applied to the MASQUE client only when `apply = true`. `max_ack_delay_ms` is
  recorded and not applied: the quinn version in this tree has no setter for it.
- HTTP/2 SETTINGS in the listed order, the connection WINDOW_UPDATE
  (`65535 + connection_window_increment`), and the order of ordinary headers.
  Pseudo-header order is `:method`, `:authority`, `:scheme`, `:path`. That
  order is applied by the vendored `h2` patch (`third_party/h2/AEGIS-PATCH.md`);
  the profile parser rejects any other order.

## Update it by hand

Install Chrome stable or Chrome for Testing somewhere other than the system
applications folder. Then, from the repository root:

```
python3 scripts/refresh-chrome-profile.py --chrome /path/to/chrome --write
```

The tool opens a local TCP listener, a self-signed HTTP/2 server and a UDP
Initial catcher. It does not export TLS keys. Exit 0 means the file already
matches. Exit 2 means it wrote a new profile and preface fixture. Then run:

```
cargo test -p aegis-chrome-profile
cargo test -p aegis-client --bin aegis-client h2_preface_matches_the_profile_fixture
cargo test -p aegis-quic-boring --features boring --test chrome_quic_clienthello
```

Ignored live tests (`chrome_live_ja4`) compare a fresh capture with this file.
The weekly workflow `.github/workflows/chrome-profile-refresh.yml` does the
same on a GitHub runner and opens a pull request when the profile changes.
It uses the runner's `GITHUB_TOKEN` only. It does not run on push.

## ECH

AWS-LC 0.44 exposes real client ECH (`SSL_set1_ech_config_list`). When a relay
profile carries an ECHConfigList, the Chrome-like backend offers that list on
the same TLS stack as the rest of the profile and does not add ECH GREASE.
`SSL_ech_accepted` must be true after the handshake. An authenticated rejection
is the same `AuthenticatedEchRetry` the rustls path already admits into the
in-memory rotation cache. The socket that failed cannot be reused, so the next
dial is the one that offers the retry list.

`tls_backend = rustls` is still the explicit opt-out. Its ClientHello is not
Chrome's: no GREASE, no extension permutation, and not the profile's cipher,
group or signature lists. JA4 for that path will not match Chrome. Full parity
on the rustls path would mean teaching rustls the same lists, GREASE and
permutation, which this profile does not do.

Chrome 157 prepends one GREASE value to the TCP signature_algorithms
extension. The profile stores the real schemes only. AWS-LC's GREASE switch
does not add that signature scheme; JA4 ignores GREASE, so the hashed
fingerprint is unchanged. QUIC, measured on the same Chrome, sends no GREASE
and the same signature list the profile already had, including the trailing
`rsa_pkcs1_sha1` (`0x0201`) that TCP does not send.

## Not in this profile

Firefox and Safari ClientHellos, and DTLS or WebRTC fingerprints, are out of
scope. A local self-signed HTTP/2 server completes TLS with Chrome 157 and
then receives no preface, because Chrome closes that connection before the
request. SETTINGS, the connection window and HEADERS priority were taken from
Chrome's own net log of a real HTTPS request on 2026-11-06: SETTINGS
65536 / push 0 / 6291456 / 262144, window increment 15663105, and an exclusive
HEADERS dependency on stream 0 with weight octet 109. QUIC transport
`apply` stays false until a reviewed transport-parameter capture says
otherwise. A required QUIC ECH rejection is remembered for the next dial; the
socket that failed is not redialed in the same call.
