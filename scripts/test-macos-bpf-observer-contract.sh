#!/usr/bin/env bash
set -euo pipefail

cargo test -p aegis-core packet_observer --features macos-bpf -- --test-threads=1
cargo test -p aegis-client runtime_event_stream::tests::runtime_event_stream_writes_packet_observer --features macos-bpf -- --test-threads=1
