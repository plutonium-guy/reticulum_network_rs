#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RNSD="${RNSD:-$ROOT/.venv/bin/rnsd}"
RNPATH="${RNPATH:-$ROOT/.venv/bin/rnpath}"
RUST_DAEMON="$ROOT/target/debug/reticulumd"
RELAY_CONFIG="$ROOT/tools/interop/transport_relay.toml"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-transport-interop.XXXXXX")"
RNS_A_CONFIG="$WORK_DIR/rns-a"
RNS_C_CONFIG="$WORK_DIR/rns-c"
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
  local attempts="${3:-300}"
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

wait_for_multihop_path() {
  local config="$1"
  local destination="$2"
  local output="$3"
  local count=0
  while true; do
    "$RNPATH" --config "$config" -t -j >"$output" 2>/dev/null || true
    if "$PYTHON" - "$output" "$destination" <<'PY'
import json
import sys

try:
    paths = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit(1)
target = sys.argv[2].lower()
raise SystemExit(
    0 if any(path.get("hash", "").lower() == target and path.get("hops", 0) > 1 for path in paths)
    else 1
)
PY
    then
      return 0
    fi
    count=$((count + 1))
    if [[ "$count" -ge 120 ]]; then
      echo "timed out waiting for multi-hop path to $destination" >&2
      sed -n '1,240p' "$output" >&2 || true
      return 1
    fi
    sleep 0.25
  done
}

if [[ ! -x "$PYTHON" || ! -x "$RNSD" || ! -x "$RNPATH" ]]; then
  echo "RNS 1.4.1 is required in .venv (pip install rns==1.4.1)" >&2
  exit 1
fi

"$PYTHON" -c 'import RNS; assert RNS.__version__ == "1.4.1", RNS.__version__'
cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-cli

mkdir -p "$RNS_A_CONFIG" "$RNS_C_CONFIG"
cp "$ROOT/tools/interop/rns_transport_a_config/config" "$RNS_A_CONFIG/config"
cp "$ROOT/tools/interop/rns_transport_c_config/config" "$RNS_C_CONFIG/config"

PYTHONUNBUFFERED=1 "$RNSD" --config "$RNS_A_CONFIG" -v >"$WORK_DIR/rns-a.log" 2>&1 &
PIDS+=("$!")
PYTHONUNBUFFERED=1 "$RNSD" --config "$RNS_C_CONFIG" -v >"$WORK_DIR/rns-c.log" 2>&1 &
PIDS+=("$!")
wait_for_port 127.0.0.1 42429
wait_for_port 127.0.0.1 42430

RETICULUM_IDENTITY_PATH="$WORK_DIR/relay.identity" \
  "$RUST_DAEMON" run --config "$RELAY_CONFIG" >"$WORK_DIR/relay.log" 2>&1 &
RELAY_PID=$!
PIDS+=("$RELAY_PID")
wait_for_pattern "$WORK_DIR/relay.log" "local destination"

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/recv_and_print.py" \
  --config "$RNS_A_CONFIG" \
  --identity "$WORK_DIR/python-a.identity" \
  --output "$WORK_DIR/received-a.txt" \
  --timeout 60 >"$WORK_DIR/python-a.log" 2>&1 &
PYTHON_A_PID=$!
PIDS+=("$PYTHON_A_PID")

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/recv_and_print.py" \
  --config "$RNS_C_CONFIG" \
  --identity "$WORK_DIR/python-c.identity" \
  --output "$WORK_DIR/received-c.txt" \
  --timeout 60 >"$WORK_DIR/python-c.log" 2>&1 &
PYTHON_C_PID=$!
PIDS+=("$PYTHON_C_PID")

wait_for_pattern "$WORK_DIR/python-a.log" "PYTHON_DESTINATION"
wait_for_pattern "$WORK_DIR/python-c.log" "PYTHON_DESTINATION"
DEST_A="$(awk '/PYTHON_DESTINATION/ {print $2; exit}' "$WORK_DIR/python-a.log")"
DEST_C="$(awk '/PYTHON_DESTINATION/ {print $2; exit}' "$WORK_DIR/python-c.log")"

wait_for_multihop_path "$RNS_C_CONFIG" "$DEST_A" "$WORK_DIR/rnpath-c.json"
wait_for_multihop_path "$RNS_A_CONFIG" "$DEST_C" "$WORK_DIR/rnpath-a.json"

"$PYTHON" "$ROOT/tools/interop/send_from_python.py" \
  --config "$RNS_C_CONFIG" \
  --destination "$DEST_A" \
  --app-name python_peer \
  --aspects message \
  --message "from endpoint c to endpoint a" \
  --timeout 20 >"$WORK_DIR/send-c-to-a.log" 2>&1
wait_for_pattern "$WORK_DIR/python-a.log" "PYTHON_RECEIVED from endpoint c to endpoint a"

"$PYTHON" "$ROOT/tools/interop/send_from_python.py" \
  --config "$RNS_A_CONFIG" \
  --destination "$DEST_C" \
  --app-name python_peer \
  --aspects message \
  --message "from endpoint a to endpoint c" \
  --timeout 20 >"$WORK_DIR/send-a-to-c.log" 2>&1
wait_for_pattern "$WORK_DIR/python-c.log" "PYTHON_RECEIVED from endpoint a to endpoint c"

if grep -q -e "from endpoint c to endpoint a" -e "from endpoint a to endpoint c" "$WORK_DIR/relay.log"; then
  echo "relay log exposed end-to-end plaintext" >&2
  exit 1
fi

echo "PASS endpoint C -> Rust relay -> endpoint A"
echo "PASS endpoint A -> Rust relay -> endpoint C"
echo "PASS both endpoint path tables report multi-hop routes"
echo "PASS relay log contains no end-to-end plaintext"
echo "Transport interop logs: $WORK_DIR"
