#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RNSD="${RNSD:-$ROOT/.venv/bin/rnsd}"
HARNESS="$ROOT/target/debug/ffi-interop"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-ffi-interop.XXXXXX")"
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

wait_for_port() {
  "$PYTHON" - "$1" "$2" <<'PY'
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
}

"$PYTHON" -c 'import RNS; assert RNS.__version__ == "1.4.1", RNS.__version__'
cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-ffi --bin ffi-interop

mkdir -p "$RNS_CONFIG"
cp "$ROOT/tools/interop/rns_server_config/config" "$RNS_CONFIG/config"
PYTHONUNBUFFERED=1 "$RNSD" --config "$RNS_CONFIG" -v \
  >"$WORK_DIR/rnsd.log" 2>&1 &
PIDS+=("$!")
wait_for_port 127.0.0.1 42428

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/recv_and_print.py" \
  --config "$RNS_CONFIG" \
  --identity "$WORK_DIR/python-receive.identity" \
  --app-name ffi_python \
  --timeout 60 >"$WORK_DIR/python_receive.log" 2>&1 &
RECEIVER_PID=$!
PIDS+=("$RECEIVER_PID")
wait_for_pattern "$WORK_DIR/python_receive.log" "PYTHON_DESTINATION"
PYTHON_DEST="$(awk '/PYTHON_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_receive.log")"

"$HARNESS" 127.0.0.1:42428 "$PYTHON_DEST" \
  >"$WORK_DIR/ffi.log" 2>&1 &
FFI_PID=$!
PIDS+=("$FFI_PID")
wait_for_pattern "$WORK_DIR/ffi.log" "FFI_DESTINATION"
FFI_DEST="$(awk '/FFI_DESTINATION/ {print $2; exit}' "$WORK_DIR/ffi.log")"

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/send_from_python.py" \
  --config "$RNS_CONFIG" \
  --destination "$FFI_DEST" \
  --app-name ffi_mobile \
  --message "hello from python to ffi" \
  --timeout 60 >"$WORK_DIR/python_send.log" 2>&1

wait "$RECEIVER_PID"
wait "$FFI_PID"
grep -q "^PYTHON_RECEIVED hello from ffi to python$" "$WORK_DIR/python_receive.log"
grep -q "^FFI_SENT hello from ffi to python$" "$WORK_DIR/ffi.log"
grep -q "^FFI_RECEIVED hello from python to ffi$" "$WORK_DIR/ffi.log"

echo "PASS UniFFI façade -> Python RNS"
echo "PASS Python RNS -> UniFFI façade"
echo "FFI interop logs: $WORK_DIR"
