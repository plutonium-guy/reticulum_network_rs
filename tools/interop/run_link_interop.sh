#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RNSD="${RNSD:-$ROOT/.venv/bin/rnsd}"
RUST_DAEMON="$ROOT/target/debug/reticulumd"
RUST_CONFIG="$ROOT/tools/interop/reticulumd.toml"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-link-interop.XXXXXX")"
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
  echo "RNS 1.4.1 is required in .venv (pip install rns==1.4.1)" >&2
  exit 1
fi
"$PYTHON" -c 'import RNS; assert RNS.__version__ == "1.4.1", RNS.__version__'
cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-cli

mkdir -p "$RNS_CONFIG"
cp "$ROOT/tools/interop/rns_server_config/config" "$RNS_CONFIG/config"
PYTHONUNBUFFERED=1 "$RNSD" --config "$RNS_CONFIG" -v >"$WORK_DIR/rnsd.log" 2>&1 &
PIDS+=("$!")
wait_for_pattern "$WORK_DIR/rnsd.log" "Started shared instance interface"

# Rust initiator -> Python responder -> Rust echo.
PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/link_peer.py" accept \
  --config "$RNS_CONFIG" \
  --identity "$WORK_DIR/python-accept.identity" \
  --app-name python_link \
  --aspects echo >"$WORK_DIR/python_accept.log" 2>&1 &
PYTHON_ACCEPT_PID=$!
PIDS+=("$PYTHON_ACCEPT_PID")
wait_for_pattern "$WORK_DIR/python_accept.log" "PYTHON_LINK_DESTINATION"
PYTHON_DEST="$(awk '/PYTHON_LINK_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_accept.log")"

RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-send.identity" \
  "$RUST_DAEMON" link-send "$PYTHON_DEST" "link hello from rust" \
  --config "$RUST_CONFIG" >"$WORK_DIR/rust_send.log" 2>&1 &
RUST_SEND_PID=$!
PIDS+=("$RUST_SEND_PID")
wait_for_pattern "$WORK_DIR/rust_send.log" "link data .* link hello from rust"
wait "$RUST_SEND_PID"
wait "$PYTHON_ACCEPT_PID"
grep -q '^PYTHON_LINK_RECEIVED link hello from rust$' "$WORK_DIR/python_accept.log"
grep -q 'link data .* link hello from rust' "$WORK_DIR/rust_send.log"

# Python initiator -> Rust responder -> Python echo.
RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-accept.identity" \
RETICULUM_LINK_ECHO=true \
  "$RUST_DAEMON" run --config "$RUST_CONFIG" >"$WORK_DIR/rust_accept.log" 2>&1 &
RUST_ACCEPT_PID=$!
PIDS+=("$RUST_ACCEPT_PID")
wait_for_pattern "$WORK_DIR/rust_accept.log" "local destination"
RUST_DEST="$(awk '/local destination/ {print $3; exit}' "$WORK_DIR/rust_accept.log")"
wait_for_pattern "$WORK_DIR/rnsd.log" "$RUST_DEST"

PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/link_peer.py" connect \
  --config "$RNS_CONFIG" \
  --destination "$RUST_DEST" \
  --message "link hello from python" >"$WORK_DIR/python_connect.log" 2>&1
grep -q "link data $RUST_DEST\\|link data .* link hello from python" "$WORK_DIR/rust_accept.log"
grep -q '^PYTHON_LINK_RECEIVED link hello from python$' "$WORK_DIR/python_connect.log"

kill "$RUST_ACCEPT_PID" 2>/dev/null || true
wait "$RUST_ACCEPT_PID" 2>/dev/null || true

echo "PASS Rust -> Python Link: link hello from rust (echo received)"
echo "PASS Python -> Rust Link: link hello from python (echo received)"
echo "Link interop logs: $WORK_DIR"
