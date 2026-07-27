#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUST_DAEMON="$ROOT/target/debug/reticulumd"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-interfaces-interop.XXXXXX")"
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

run_roundtrip() {
  local label="$1" rust_config="$2" python_template="$3"
  local case_dir="$WORK_DIR/$label"
  local python_config="$case_dir/python-rns"
  mkdir -p "$python_config"
  cp "$python_template/config" "$python_config/config"

  PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/recv_and_print.py" \
    --config "$python_config" \
    --identity "$case_dir/python-receive.identity" \
    --timeout 60 >"$case_dir/python_receive.log" 2>&1 &
  local receiver_pid=$!
  PIDS+=("$receiver_pid")
  wait_for_pattern "$case_dir/python_receive.log" "PYTHON_DESTINATION"
  local python_dest
  python_dest="$(awk '/PYTHON_DESTINATION/ {print $2; exit}' "$case_dir/python_receive.log")"

  RETICULUM_IDENTITY_PATH="$case_dir/rust-send.identity" \
    "$RUST_DAEMON" send "$python_dest" "hello over $label from rust" \
    --config "$rust_config" >"$case_dir/rust_send.log" 2>&1
  wait "$receiver_pid"
  grep -q "^PYTHON_RECEIVED hello over $label from rust$" "$case_dir/python_receive.log"

  RETICULUM_IDENTITY_PATH="$case_dir/rust-receive.identity" \
    "$RUST_DAEMON" run --config "$rust_config" \
    >"$case_dir/rust_receive.log" 2>&1 &
  CASE_RUST_PID=$!
  PIDS+=("$CASE_RUST_PID")
  wait_for_pattern "$case_dir/rust_receive.log" "local destination"
  local rust_dest
  rust_dest="$(awk '/local destination/ {print $3; exit}' "$case_dir/rust_receive.log")"

  PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/send_from_python.py" \
    --config "$python_config" \
    --destination "$rust_dest" \
    --message "hello over $label from python" \
    --timeout 60 >"$case_dir/python_send.log" 2>&1
  wait_for_pattern "$case_dir/rust_receive.log" "hello over $label from python"
  grep -q "message $rust_dest hello over $label from python" "$case_dir/rust_receive.log"
  echo "PASS $label Rust <-> Python"
}

if [[ ! -x "$PYTHON" ]]; then
  echo "RNS 1.4.1 is required in .venv" >&2
  exit 1
fi
"$PYTHON" -c 'import RNS; assert RNS.__version__ == "1.4.1", RNS.__version__'
cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-cli

run_roundtrip \
  tcp-server \
  "$ROOT/tools/interop/reticulumd_tcp_server.toml" \
  "$ROOT/tools/interop/rns_tcp_client_config"
kill "$CASE_RUST_PID" 2>/dev/null || true
wait "$CASE_RUST_PID" 2>/dev/null || true

run_roundtrip \
  udp \
  "$ROOT/tools/interop/reticulumd_udp.toml" \
  "$ROOT/tools/interop/rns_udp_config"
kill "$CASE_RUST_PID" 2>/dev/null || true
wait "$CASE_RUST_PID" 2>/dev/null || true

run_roundtrip \
  ifac \
  "$ROOT/tools/interop/reticulumd_ifac.toml" \
  "$ROOT/tools/interop/rns_ifac_config"

MISMATCH_CONFIG="$WORK_DIR/ifac-mismatch-python-rns"
mkdir -p "$MISMATCH_CONFIG"
cp "$ROOT/tools/interop/rns_ifac_mismatch_config/config" "$MISMATCH_CONFIG/config"
RUST_DEST="$(awk '/local destination/ {print $3; exit}' "$WORK_DIR/ifac/rust_receive.log")"
if PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/send_from_python.py" \
  --config "$MISMATCH_CONFIG" \
  --destination "$RUST_DEST" \
  --message "IFAC mismatch must not arrive" \
  --timeout 5 >"$WORK_DIR/ifac/python_mismatch.log" 2>&1; then
  echo "mismatched IFAC unexpectedly learned the Rust path" >&2
  exit 1
fi
grep -q "PYTHON_PATH_TIMEOUT" "$WORK_DIR/ifac/python_mismatch.log"
if grep -q "IFAC mismatch must not arrive" "$WORK_DIR/ifac/rust_receive.log"; then
  echo "mismatched IFAC packet was delivered" >&2
  exit 1
fi
echo "PASS IFAC mismatched passphrase rejected"
kill "$CASE_RUST_PID" 2>/dev/null || true
wait "$CASE_RUST_PID" 2>/dev/null || true

echo "SKIP AutoInterface live gate: one-host RNS/Rust peers cannot both bind the same link-local data port; use two LAN hosts"
echo "Interface interop logs: $WORK_DIR"
