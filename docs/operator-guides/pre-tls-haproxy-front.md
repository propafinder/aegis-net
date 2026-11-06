# Optional pre-TLS reverse-proxy front

Current guidance, reconciled 2026-10-11. AEGIS already inspects the initial byte
before its TLS acceptor and serves an HTTP decoy for plain HTTP on the TLS port.
The old assertion that only an external proxy could handle such a request is
obsolete. This built-in response is separate from authenticated tunnel delivery
and does not establish active-probe resistance.

## Historical motivation

The preserved `evidence-archive/live/2026-05-16/active-probe-corpus-v2-decoy/` measurement
observed a short TLS error fragment for its plain-HTTP and random-byte probes.
That observation belongs to the recorded build and corpus. It does not describe
the current pre-TLS dispatcher, and it did not measure any proposed HAProxy or
Caddy deployment. Predicted corpus score improvements are not acceptance results.

## Current response boundaries

Plain HTTP arriving before TLS can receive the built-in HTTP 400 response.
A request inside established TLS to an unknown or unauthorized route can receive
the process's web decoy status **403, 404, or 410**. These are different layers;
neither provides a blanket “400, never 404” health check. A normal GET to a
legacy or enrolled tunnel path is not an authenticated session proof.

Device-enrolled ordinary gRPC uses `/tunnel.v1.Channel/Connect` and separate inner
device trust. An opt-in HTTPS bridge uses its explicitly provisioned path and
admission credential. Legacy transport catalogs do not change those paths.
See [transport profiles](protocols-and-transports.md).

## When an external proxy is appropriate

HAProxy, a deliberately configured layer-4 Caddy deployment, or another reviewed
proxy can be an optional operator routing layer. Use it for a defined deployment
requirement and verify its exact package/configuration; its presence does not
supply browser equivalence, allowlist admission, or general DPI resistance.
The historical generic examples were not verified production configurations
and are not retained as copy-paste deployment instructions.

TLS passthrough keeps edge-to-relay TLS at AEGIS. TLS termination at a proxy
creates a separate trust hop whose upstream authentication and confidentiality
must be configured explicitly. Do not enable PROXY-protocol headers unless the
AEGIS listener is configured to accept them. Preserve the selected gRPC/H2 path,
inner device authentication and endpoint trust; ordinary HTTP reverse proxying
is not raw TLS passthrough.

If issuing a legacy distribution token through a reviewed proxy, use a fresh
private access record and the actual public authority:

```bash
sudo -u aegis aegis-server \
  --config /etc/aegis/server/aegis-server.toml bundle-token issue \
  --bundle-path /var/lib/aegis/client-bundle-NEW.tar.gz \
  --url-output /var/lib/aegis/client-access-NEW.txt \
  --public-host relay.example.com --public-port 443 --ttl-secs 3600
```

Transfer that record privately and redeem using `--bundle-url-file` from an
exact verified client distribution. This token is legacy bundle delivery; it
cannot replace enrolled device issuance.

No reverse proxy was installed or measured during the 2026-10-11 documentation
reconciliation. Historical corpus bytes remain unchanged. Protected gRPC
implementation/native tests and exact-candidate deployment acceptance were not
independently revalidated here.
