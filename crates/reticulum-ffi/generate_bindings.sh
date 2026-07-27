#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "$(uname -s)" in
  Darwin) LIBRARY="$ROOT/target/debug/libreticulum_ffi.dylib" ;;
  Linux) LIBRARY="$ROOT/target/debug/libreticulum_ffi.so" ;;
  MINGW*|MSYS*|CYGWIN*) LIBRARY="$ROOT/target/debug/reticulum_ffi.dll" ;;
  *) echo "unsupported host platform" >&2; exit 1 ;;
esac

cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-ffi
rm -rf \
  "$ROOT/crates/reticulum-ffi/bindings/kotlin" \
  "$ROOT/crates/reticulum-ffi/bindings/swift"
mkdir -p \
  "$ROOT/crates/reticulum-ffi/bindings/kotlin" \
  "$ROOT/crates/reticulum-ffi/bindings/swift"

cargo run --manifest-path "$ROOT/Cargo.toml" -p reticulum-ffi \
  --bin uniffi-bindgen -- generate --no-format \
  --library "$LIBRARY" --language kotlin \
  --out-dir "$ROOT/crates/reticulum-ffi/bindings/kotlin"
cargo run --manifest-path "$ROOT/Cargo.toml" -p reticulum-ffi \
  --bin uniffi-bindgen -- generate --no-format \
  --library "$LIBRARY" --language swift \
  --out-dir "$ROOT/crates/reticulum-ffi/bindings/swift"
