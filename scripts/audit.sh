#!/usr/bin/env bash
# Строгий аудит: форматирование, clippy, тесты (все фичи), один поток для env-тестов.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/.cargo/bin:${PATH}"

cd "${ROOT}"
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo не найден. Установите Rust: https://rustup.rs" >&2
  exit 1
fi

echo "== cargo fmt =="
cargo fmt --all -- --check

echo "== cargo clippy (workspace, all targets, all features) =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== cargo test (all features, test-threads=1 для env) =="
cargo test --workspace --all-features -- --test-threads=1

echo "OK: audit passed"
