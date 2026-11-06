FROM rust:1-bookworm AS builder

WORKDIR /app

# NOTE: the previous stub-prebuild dependency-cache trick only materialised the
# aegis-core/client/server crates, but the workspace now has 11 members
# (aegis-fingerprint, aegis-knowledge, aegis-android-jni, tools/*). With those
# members absent, `cargo build` failed workspace resolution (exit 101), which
# broke the release image build. Build the real workspace directly instead.
COPY . .

RUN cargo build --locked --release -p aegis-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/aegis --shell /usr/sbin/nologin aegis

WORKDIR /var/lib/aegis

COPY --from=builder /app/target/release/aegis-server /usr/local/bin/aegis-server
COPY aegis-server.toml.example /etc/aegis/aegis-server.toml.example

RUN mkdir -p /etc/aegis/certs && chown -R aegis:aegis /var/lib/aegis /etc/aegis

USER aegis

EXPOSE 8443/tcp
EXPOSE 8443/udp

ENTRYPOINT ["/usr/local/bin/aegis-server"]
CMD ["--config", "/etc/aegis/aegis-server.toml"]
