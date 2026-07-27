#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RNSD="${RNSD:-$ROOT/.venv/bin/rnsd}"
RUST_DAEMON="$ROOT/target/debug/reticulumd"
RUST_CONFIG="$ROOT/tools/interop/reticulumd.toml"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-resource-interop.XXXXXX")"
RNS_CONFIG="$WORK_DIR/rns"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

wait_for_pattern() {
  local file="$1" pattern="$2" attempts="${3:-600}" count=0
  while ! grep -q "$pattern" "$file" 2>/dev/null; do
    count=$((count + 1))
    if [[ "$count" -ge "$attempts" ]]; then
      echo "timed out waiting for '$pattern' in $file" >&2
      sed -n '1,300p' "$file" >&2 || true
      return 1
    fi
    sleep 0.1
  done
}

wait_for_count() {
  local file="$1" pattern="$2" expected="$3" attempts="${4:-600}" count=0
  while [[ "$(grep -c "$pattern" "$file" 2>/dev/null || true)" -lt "$expected" ]]; do
    count=$((count + 1))
    if [[ "$count" -ge "$attempts" ]]; then
      echo "timed out waiting for $expected occurrences of '$pattern'" >&2
      sed -n '1,300p' "$file" >&2 || true
      return 1
    fi
    sleep 0.1
  done
}

if [[ ! -x "$PYTHON" || ! -x "$RNSD" ]]; then
  echo "RNS 1.4.1 is required in .venv" >&2
  exit 1
fi
"$PYTHON" -c 'import RNS; assert RNS.__version__ == "1.4.1"'
cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-cli

mkdir -p "$RNS_CONFIG" "$WORK_DIR/python-received" "$WORK_DIR/rust-received"
cp "$ROOT/tools/interop/rns_server_config/config" "$RNS_CONFIG/config"
"$PYTHON" - "$WORK_DIR" <<'PY'
import os, sys
root = sys.argv[1]
with open(os.path.join(root, "uncompressed.bin"), "wb") as f:
    f.write(bytes((i * 73 + 19) % 256 for i in range(12289)))
with open(os.path.join(root, "compressible.bin"), "wb") as f:
    f.write((b"reticulum-resource-compression-check\n" * 512))
PY

PYTHONUNBUFFERED=1 "$RNSD" --config "$RNS_CONFIG" -v >"$WORK_DIR/rnsd.log" 2>&1 &
PIDS+=("$!")
wait_for_pattern "$WORK_DIR/rnsd.log" "Started shared instance interface"

# Rust sends an incompressible and a compressible Resource to Python.
PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/resource_peer.py" accept \
  --config "$RNS_CONFIG" --identity "$WORK_DIR/python-accept.identity" \
  --app-name python_resource --aspects receive \
  --output-dir "$WORK_DIR/python-received" --count 2 \
  >"$WORK_DIR/python_accept.log" 2>&1 &
PYTHON_ACCEPT_PID=$!
PIDS+=("$PYTHON_ACCEPT_PID")
wait_for_pattern "$WORK_DIR/python_accept.log" "PYTHON_RESOURCE_DESTINATION"
PYTHON_DEST="$(awk '/PYTHON_RESOURCE_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_accept.log")"

for name in uncompressed compressible; do
  RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-send-$name.identity" \
    "$RUST_DAEMON" send-file "$PYTHON_DEST" "$WORK_DIR/$name.bin" \
    --config "$RUST_CONFIG" >"$WORK_DIR/rust_send_$name.log" 2>&1 &
  send_pid=$!
  PIDS+=("$send_pid")
  wait_for_pattern "$WORK_DIR/rust_send_$name.log" "file transfer complete"
  wait "$send_pid"
done
wait "$PYTHON_ACCEPT_PID"
cmp "$WORK_DIR/uncompressed.bin" "$WORK_DIR/python-received/received-1.bin"
cmp "$WORK_DIR/compressible.bin" "$WORK_DIR/python-received/received-2.bin"

# Python sends both Resource forms to one long-running Rust receiver.
RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-accept.identity" \
  "$RUST_DAEMON" receive-file "$WORK_DIR/rust-received" \
  --config "$RUST_CONFIG" >"$WORK_DIR/rust_accept.log" 2>&1 &
RUST_ACCEPT_PID=$!
PIDS+=("$RUST_ACCEPT_PID")
wait_for_pattern "$WORK_DIR/rust_accept.log" "local destination"
RUST_DEST="$(awk '/local destination/ {print $3; exit}' "$WORK_DIR/rust_accept.log")"
wait_for_pattern "$WORK_DIR/rnsd.log" "$RUST_DEST"

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/resource_peer.py" connect \
  --config "$RNS_CONFIG" --destination "$RUST_DEST" \
  --file "$WORK_DIR/uncompressed.bin" --no-compress \
  >"$WORK_DIR/python_send_uncompressed.log" 2>&1
PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/resource_peer.py" connect \
  --config "$RNS_CONFIG" --destination "$RUST_DEST" \
  --file "$WORK_DIR/compressible.bin" \
  >"$WORK_DIR/python_send_compressible.log" 2>&1
wait_for_count "$WORK_DIR/rust_accept.log" "resource written" 2

uncompressed_hash="$(shasum -a 256 "$WORK_DIR/uncompressed.bin" | awk '{print $1}')"
compressible_hash="$(shasum -a 256 "$WORK_DIR/compressible.bin" | awk '{print $1}')"
received_hashes="$(find "$WORK_DIR/rust-received" -type f -exec shasum -a 256 {} +)"
grep -q "$uncompressed_hash" <<<"$received_hashes"
grep -q "$compressible_hash" <<<"$received_hashes"

kill "$RUST_ACCEPT_PID" 2>/dev/null || true
wait "$RUST_ACCEPT_PID" 2>/dev/null || true

echo "PASS Rust -> Python Resources: uncompressed + bz2, SHA-256 matched"
echo "PASS Python -> Rust Resources: uncompressed + bz2, SHA-256 matched"
echo "Resource interop logs: $WORK_DIR"
