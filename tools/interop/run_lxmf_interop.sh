#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RNSD="${RNSD:-$ROOT/.venv/bin/rnsd}"
RUST_DAEMON="$ROOT/target/debug/reticulumd"
RUST_CONFIG="$ROOT/tools/interop/reticulumd.toml"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-lxmf-interop.XXXXXX")"
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
  local attempts="${3:-300}"
  local count=0
  while ! grep -q "$pattern" "$file" 2>/dev/null; do
    count=$((count + 1))
    if [[ "$count" -ge "$attempts" ]]; then
      echo "timed out waiting for '$pattern' in $file" >&2
      sed -n '1,260p' "$file" >&2 || true
      return 1
    fi
    sleep 0.1
  done
}

if [[ ! -x "$PYTHON" || ! -x "$RNSD" ]]; then
  echo "RNS 1.4.1 and LXMF 1.1.0 are required in .venv" >&2
  exit 1
fi
"$PYTHON" -c 'import RNS, LXMF; assert RNS.__version__ == "1.4.1"; assert LXMF.__version__ == "1.1.0"'
cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-cli

mkdir -p "$RNS_CONFIG"
cp "$ROOT/tools/interop/rns_server_config/config" "$RNS_CONFIG/config"
PYTHONUNBUFFERED=1 "$RNSD" --config "$RNS_CONFIG" -v >"$WORK_DIR/rnsd.log" 2>&1 &
RNSD_PID=$!
PIDS+=("$RNSD_PID")
wait_for_pattern "$WORK_DIR/rnsd.log" "Started shared instance interface"

# Rust -> Python, direct over an authenticated Link.
PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/lxmf_peer.py" receive \
  --config "$RNS_CONFIG" \
  --identity "$WORK_DIR/python-receive.identity" \
  --storage "$WORK_DIR/python-receive-storage" \
  --timeout 40 >"$WORK_DIR/python_receive.log" 2>&1 &
PYTHON_RECEIVER_PID=$!
PIDS+=("$PYTHON_RECEIVER_PID")
wait_for_pattern "$WORK_DIR/python_receive.log" "PYTHON_LXMF_DESTINATION"
PYTHON_DEST="$(awk '/PYTHON_LXMF_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_receive.log")"

RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-send.identity" \
  "$RUST_DAEMON" lxmf send "$PYTHON_DEST" "Rust title" "hello from rust lxmf" --direct \
  --config "$RUST_CONFIG" >"$WORK_DIR/rust_send.log" 2>&1
wait "$PYTHON_RECEIVER_PID"
grep -q '^PYTHON_LXMF_RECEIVED title=Rust title content=hello from rust lxmf ' \
  "$WORK_DIR/python_receive.log"

# Python -> Rust, opportunistic single-packet delivery.
RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-receive.identity" \
  "$RUST_DAEMON" lxmf recv --config "$RUST_CONFIG" \
  >"$WORK_DIR/rust_receive.log" 2>&1 &
RUST_RECEIVER_PID=$!
PIDS+=("$RUST_RECEIVER_PID")
wait_for_pattern "$WORK_DIR/rust_receive.log" "local lxmf destination"
RUST_DEST="$(awk '/local lxmf destination/ {print $4; exit}' "$WORK_DIR/rust_receive.log")"

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/lxmf_peer.py" send \
  --config "$RNS_CONFIG" \
  --identity "$WORK_DIR/python-send.identity" \
  --storage "$WORK_DIR/python-send-storage" \
  --destination "$RUST_DEST" \
  --method opportunistic \
  --title "Python title" \
  --content "hello from python lxmf" \
  --timeout 40 >"$WORK_DIR/python_send.log" 2>&1
wait_for_pattern "$WORK_DIR/rust_receive.log" "title=Python title content=hello from python lxmf"
grep -q "lxmf message $RUST_DEST .*title=Python title content=hello from python lxmf" \
  "$WORK_DIR/rust_receive.log"

kill "$RUST_RECEIVER_PID" 2>/dev/null || true
wait "$RUST_RECEIVER_PID" 2>/dev/null || true

echo "PASS Rust -> Python LXMF direct: Rust title / hello from rust lxmf"
echo "PASS Python -> Rust LXMF opportunistic: Python title / hello from python lxmf"
echo "LXMF interop logs: $WORK_DIR"
