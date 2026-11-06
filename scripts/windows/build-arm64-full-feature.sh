#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 7 && $# -ne 9 ]]; then
  echo "usage: $0 CLANG XWIN XWIN_ROOT LLD_LINK WORK_DIR TARGET_DIR EXPECTED_HEAD [PROPOSAL_PATCH PROPOSAL_SHA256]" >&2
  exit 64
fi
clang="$1"
xwin="$2"
xwin_root="$3"
lld_link="$4"
work_dir="$5"
target_dir="$6"
expected_head="$7"
proposal_patch="${8:-}"
proposal_sha="${9:-}"
for path in "$clang" "$xwin" "$xwin_root" "$lld_link" "$work_dir" "$target_dir"; do
  [[ "$path" = /* ]] || { echo "absolute paths required: $path" >&2; exit 64; }
done
[[ -x "$clang" && -x "$xwin" && -x "$lld_link" ]] || { echo "cross tool missing" >&2; exit 66; }
[[ -d "$xwin_root" ]] || { echo "xwin root missing" >&2; exit 66; }
if [[ -e "$work_dir" || -e "$target_dir" ]]; then
  echo "work and target directories must be absent for a clean build" >&2
  exit 73
fi
repo_root="$(cd "$(dirname "$0")/../.." && pwd -P)"
# Cargo reads ignored local/parent config and ambient overrides. Refuse these
# inputs so a clean Git status actually binds the build configuration.
config_dir="$repo_root"
while :; do
  [[ ! -e "$config_dir/.cargo" ]] || { echo "untracked Cargo config directory: $config_dir/.cargo" >&2; exit 65; }
  [[ "$config_dir" == / ]] && break
  config_dir="$(dirname "$config_dir")"
done
[[ ! -e "$HOME/.cargo/config" && ! -e "$HOME/.cargo/config.toml" ]] || { echo "global Cargo config present" >&2; exit 65; }
while IFS='=' read -r name _; do
  case "$name" in
    CARGO_*|RUSTC|RUSTC_*|RUSTFLAGS|RUSTDOC*|RUSTUP_*|CC|CC_*|CXX|CXX_*|AR|AR_*|RANLIB|RANLIB_*|CFLAGS*|CXXFLAGS*|CMAKE*|BINDGEN*|AWS_LC*|AEGIS_BUILD_*|PKG_CONFIG*|OPENSSL*|LLVM_CONFIG_PATH|LIBCLANG_PATH|SDKROOT|CPATH|LIBRARY_PATH|C_INCLUDE_PATH|CPLUS_INCLUDE_PATH|LDFLAGS|CL|LINK|LIB|INCLUDE|RC)
      echo "ambient build override refused: $name" >&2; exit 65 ;;
  esac
done < <(env)
[[ "$(git -C "$repo_root" rev-parse --show-toplevel)" == "$repo_root" ]] || { echo "Git checkout missing" >&2; exit 65; }
[[ "$expected_head" =~ ^[a-f0-9]{40}$ ]] || { echo "expected HEAD must be a full SHA-1" >&2; exit 64; }
check_source() {
  [[ "$(git -C "$repo_root" rev-parse HEAD)" == "$expected_head" ]] || { echo "source HEAD changed" >&2; exit 65; }
  git -C "$repo_root" diff --quiet HEAD -- || { echo "tracked source changed" >&2; exit 65; }
  git -C "$repo_root" diff --cached --quiet || { echo "staged source changed" >&2; exit 65; }
  local status
  status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)"
  if [[ -n "$proposal_patch" ]]; then
    [[ "$proposal_patch" = /* && -f "$proposal_patch" && "$proposal_sha" =~ ^[a-f0-9]{64}$ ]] || { echo "proposal input invalid" >&2; exit 64; }
    [[ "$(shasum -a 256 "$proposal_patch" | awk '{print $1}')" == "$proposal_sha" ]] || { echo "proposal hash changed" >&2; exit 65; }
    [[ "$status" == $'?? scripts/windows/aws-lc-arm64-archive-prefix.cmake\n?? scripts/windows/build-arm64-full-feature.sh' ]] || { echo "proposal source inventory changed" >&2; exit 65; }
    git -C "$repo_root" apply --reverse --check "$proposal_patch" || { echo "proposal patch does not match source" >&2; exit 65; }
  else
    [[ -z "$status" ]] || { echo "committed source checkout is dirty" >&2; exit 65; }
  fi
}
check_source
lock_sha="$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')"
build_timestamp="$(git -C "$repo_root" show -s --format=%cI HEAD)"
[[ -n "$build_timestamp" ]] || { echo "commit timestamp missing" >&2; exit 65; }
llvm_bin="$(dirname "$clang")"
llvm_lib="$llvm_bin/llvm-lib"
llvm_ar="$llvm_bin/llvm-ar"
[[ -x "$llvm_lib" && -x "$llvm_ar" ]] || { echo "LLVM archivers missing" >&2; exit 66; }
mkdir -p "$work_dir" "$target_dir"
wrapper="$(python3 -I "$repo_root/scripts/windows/prepare-arm64-clang-neon.py" \
  --clang "$clang" --xwin "$xwin" --xwin-root "$xwin_root" \
  --out "$work_dir/verified-clang")"
[[ -x "$wrapper" ]] || { echo "verified Clang wrapper missing" >&2; exit 70; }
archive_hook="$repo_root/scripts/windows/aws-lc-arm64-archive-prefix.cmake"
cat > "$work_dir/cmake-toolchain.cmake" <<TOOLCHAIN
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR ARM64)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_C_COMPILER "$wrapper")
set(CMAKE_CXX_COMPILER "$wrapper")
set(CMAKE_ASM_COMPILER "$wrapper")
set(CMAKE_AR "$llvm_ar")
set(CMAKE_C_BYTE_ORDER LITTLE_ENDIAN)
set(CMAKE_CXX_BYTE_ORDER LITTLE_ENDIAN)
set(CMAKE_PROJECT_AWS_LC_RUST_INCLUDE "$archive_hook")
TOOLCHAIN
export PATH="$(dirname "$lld_link"):$llvm_bin:$PATH"
export RUSTC="$(rustup which --toolchain 1.97.1 rustc)"
export CC="$wrapper" CXX="$wrapper" AR="$llvm_lib"
export CC_aarch64_pc_windows_msvc="$wrapper"
export CXX_aarch64_pc_windows_msvc="$wrapper"
export AR_aarch64_pc_windows_msvc="$llvm_lib"
export CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER="$lld_link"
export CARGO_TARGET_DIR="$target_dir"
export RUSTFLAGS="-Lnative=$xwin_root/sdk/lib/um/aarch64 -Lnative=$xwin_root/sdk/lib/ucrt/aarch64 -Lnative=$xwin_root/crt/lib/aarch64"
export BINDGEN_EXTRA_CLANG_ARGS="--target=aarch64-pc-windows-msvc -I$work_dir/verified-clang/headers -isystem$xwin_root/sdk/include/ucrt -isystem$xwin_root/sdk/include/shared -isystem$xwin_root/sdk/include/um -isystem$xwin_root/crt/include"
# Windows SDK wincrypt.h defines X509_NAME and PKCS7_SIGNER_INFO macros that
# collide with AWS-LC's OpenSSL types. AWS-LC uses BCrypt, not WinCrypt here.
export CFLAGS_aarch64_pc_windows_msvc=-DNOCRYPT
export CXXFLAGS_aarch64_pc_windows_msvc=-DNOCRYPT
export CMAKE_GENERATOR=Ninja
export CMAKE_TOOLCHAIN_FILE="$work_dir/cmake-toolchain.cmake"
export AEGIS_BUILD_GIT_SHA="$expected_head"
export AEGIS_BUILD_TIMESTAMP="$build_timestamp"
export AEGIS_BUILD_TARGET=aarch64-pc-windows-msvc
export AEGIS_BUILD_FEATURES=chrome-like-tls,chrome-like-quic
export AEGIS_CARGO_LOCK_SHA256="$lock_sha"
cd "$repo_root"
rustup run 1.97.1 cargo build --offline --locked --no-default-features \
  --target aarch64-pc-windows-msvc \
  -p aegis-client -p aegis-winctl \
  --features aegis-client/chrome-like-tls,aegis-client/chrome-like-quic -j 2

check_source
[[ "$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')" == "$lock_sha" ]] || { echo "Cargo.lock changed after build" >&2; exit 65; }
printf "SOURCE_HEAD=%s\n" "$expected_head"
printf "SOURCE_PROPOSAL_SHA256=%s\n" "${proposal_sha:-none}"
printf "CARGO_LOCK_SHA256=%s\n" "$lock_sha"
