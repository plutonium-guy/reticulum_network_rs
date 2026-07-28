#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RNSD="${RNSD:-$ROOT/.venv/bin/rnsd}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-wasm-interop.XXXXXX")"
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

"$PYTHON" -c 'import RNS; assert RNS.__version__ == "1.4.1"'
"$PYTHON" -m pip install --quiet --disable-pip-version-check \
  -r "$ROOT/tools/wasm/requirements.txt"
wasm-pack build "$ROOT/crates/reticulum-wasm" \
  --target web --dev --out-dir "$ROOT/tools/wasm/pkg"

mkdir -p "$RNS_CONFIG"
cp "$ROOT/tools/interop/rns_server_config/config" "$RNS_CONFIG/config"
PYTHONUNBUFFERED=1 "$RNSD" --config "$RNS_CONFIG" -v \
  >"$WORK_DIR/rnsd.log" 2>&1 &
PIDS+=("$!")
wait_for_port 127.0.0.1 42428

# Bridge is pluggable: default to the Python reference, or set BRIDGE_CMD to the
# Rust binary (both print WS_BRIDGE_READY). e.g.
#   BRIDGE_CMD="$ROOT/target/debug/reticulum-bridge" ./run_wasm_interop.sh
if [[ -n "${BRIDGE_CMD:-}" ]]; then
  PYTHONUNBUFFERED=1 $BRIDGE_CMD >"$WORK_DIR/bridge.log" 2>&1 &
else
  PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/wasm/bridge.py" \
    >"$WORK_DIR/bridge.log" 2>&1 &
fi
PIDS+=("$!")
wait_for_pattern "$WORK_DIR/bridge.log" "WS_BRIDGE_READY"

"$PYTHON" -m http.server 8766 --bind 127.0.0.1 \
  --directory "$ROOT/tools/wasm" >"$WORK_DIR/http.log" 2>&1 &
PIDS+=("$!")

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/recv_and_print.py" \
  --config "$RNS_CONFIG" \
  --identity "$WORK_DIR/python-receive.identity" \
  --timeout 60 >"$WORK_DIR/python_receive.log" 2>&1 &
RECEIVER_PID=$!
PIDS+=("$RECEIVER_PID")
wait_for_pattern "$WORK_DIR/python_receive.log" "PYTHON_DESTINATION"
PYTHON_DEST="$(awk '/PYTHON_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_receive.log")"

PAGE_URL="http://127.0.0.1:8766/?python_dest=$PYTHON_DEST"
node "$ROOT/tools/wasm/headless_gate.mjs" "$PAGE_URL" \
  >"$WORK_DIR/browser.log" 2>&1 &
BROWSER_PID=$!
PIDS+=("$BROWSER_PID")
wait_for_pattern "$WORK_DIR/browser.log" "BROWSER_DESTINATION"
BROWSER_DEST="$(awk '/BROWSER_DESTINATION/ {print $2; exit}' "$WORK_DIR/browser.log")"

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/send_from_python.py" \
  --config "$RNS_CONFIG" \
  --destination "$BROWSER_DEST" \
  --app-name wasm_browser \
  --message "hello from python to wasm" \
  --timeout 60 >"$WORK_DIR/python_send.log" 2>&1

wait "$RECEIVER_PID"
wait "$BROWSER_PID"
grep -q "^PYTHON_RECEIVED hello from wasm to python$" "$WORK_DIR/python_receive.log"
grep -q "^WASM_SENT$" "$WORK_DIR/browser.log"
grep -q "^WASM_RECEIVED$" "$WORK_DIR/browser.log"

echo "PASS browser WASM -> WS/TCP bridge -> Python RNS"
echo "PASS Python RNS -> WS/TCP bridge -> browser WASM"
echo "WASM interop logs: $WORK_DIR"
