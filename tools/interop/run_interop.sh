#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RNSD="${RNSD:-$ROOT/.venv/bin/rnsd}"
RNPATH="${RNPATH:-$ROOT/.venv/bin/rnpath}"
RUST_DAEMON="$ROOT/target/debug/reticulumd"
RUST_CONFIG="$ROOT/tools/interop/reticulumd.toml"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-interop.XXXXXX")"
RNS_CONFIG="$WORK_DIR/rns"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

wait_for_pattern() {
  local file="$1"
  local pattern="$2"
  local attempts="${3:-200}"
  local count=0
  while ! grep -q "$pattern" "$file" 2>/dev/null; do
    count=$((count + 1))
    if [[ "$count" -ge "$attempts" ]]; then
      echo "timed out waiting for '$pattern' in $file" >&2
      sed -n '1,240p' "$file" >&2 || true
      return 1
    fi
    sleep 0.1
  done
}

if [[ ! -x "$PYTHON" || ! -x "$RNSD" ]]; then
  echo "RNS 1.4.1 is required in .venv (pip install rns==1.4.1)" >&2
  exit 1
fi

"$PYTHON" -c 'import RNS; assert RNS.__version__ == "1.4.1", RNS.__version__'
cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-cli

mkdir -p "$RNS_CONFIG"
cp "$ROOT/tools/interop/rns_server_config/config" "$RNS_CONFIG/config"
PYTHONUNBUFFERED=1 "$RNSD" --config "$RNS_CONFIG" -v >"$WORK_DIR/rnsd.log" 2>&1 &
RNSD_PID=$!
PIDS+=("$RNSD_PID")

"$PYTHON" - 127.0.0.1 42428 <<'PY'
import socket
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
deadline = time.monotonic() + 10
while True:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            break
    except OSError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.1)
PY

# Rust -> Python
"$PYTHON" "$ROOT/tools/interop/recv_and_print.py" \
  --config "$RNS_CONFIG" \
  --identity "$WORK_DIR/python.identity" \
  --output "$WORK_DIR/rust_to_python.txt" \
  --timeout 20 >"$WORK_DIR/python_receive.log" 2>&1 &
RECEIVER_PID=$!
PIDS+=("$RECEIVER_PID")
wait_for_pattern "$WORK_DIR/python_receive.log" "PYTHON_DESTINATION"
PYTHON_DEST="$(awk '/PYTHON_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_receive.log")"

RETICULUM_IDENTITY_PATH="$WORK_DIR/rust.identity" \
  "$RUST_DAEMON" send "$PYTHON_DEST" "hello from rust" \
  --config "$RUST_CONFIG" >"$WORK_DIR/rust_send.log" 2>&1
wait "$RECEIVER_PID"
grep -q '^PYTHON_RECEIVED hello from rust$' "$WORK_DIR/python_receive.log"

# Python -> Rust
RETICULUM_IDENTITY_PATH="$WORK_DIR/rust.identity" \
  "$RUST_DAEMON" run --config "$RUST_CONFIG" \
  >"$WORK_DIR/rust_receive.log" 2>&1 &
RUST_PID=$!
PIDS+=("$RUST_PID")
wait_for_pattern "$WORK_DIR/rust_receive.log" "local destination"
RUST_DEST="$(awk '/local destination/ {print $3; exit}' "$WORK_DIR/rust_receive.log")"
wait_for_pattern "$WORK_DIR/rnsd.log" "$RUST_DEST"
"$RNPATH" --config "$RNS_CONFIG" -t >"$WORK_DIR/rnpath.log"
grep -q "$RUST_DEST" "$WORK_DIR/rnpath.log"

"$PYTHON" "$ROOT/tools/interop/send_from_python.py" \
  --config "$RNS_CONFIG" \
  --destination "$RUST_DEST" \
  --message "hello from python" \
  --timeout 20 >"$WORK_DIR/python_send.log" 2>&1
wait_for_pattern "$WORK_DIR/rust_receive.log" "hello from python"
grep -q "message $RUST_DEST hello from python" "$WORK_DIR/rust_receive.log"

kill "$RUST_PID" 2>/dev/null || true
wait "$RUST_PID" 2>/dev/null || true

echo "PASS Rust -> Python: hello from rust"
echo "PASS Python -> Rust: hello from python"
echo "Interop logs: $WORK_DIR"
