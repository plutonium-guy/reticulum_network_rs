#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUST_DAEMON="$ROOT/target/debug/reticulumd"
RUST_CONFIG="$ROOT/tools/interop/reticulumd_desttypes.toml"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reticulum-desttypes-interop.XXXXXX")"
PYTHON_CONFIG="$WORK_DIR/python-rns"
GROUP_KEY="$(printf 'a5%.0s' {1..64})"
RUST_PRIVATE="$(printf '11%.0s' {1..32})$(printf '22%.0s' {1..32})"
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

if [[ ! -x "$PYTHON" ]]; then
  echo "RNS 1.4.1 is required in .venv" >&2
  exit 1
fi
"$PYTHON" -c 'import RNS; assert RNS.__version__ == "1.4.1"'
cargo build --manifest-path "$ROOT/Cargo.toml" -p reticulum-cli

mkdir -p "$PYTHON_CONFIG"
cp "$ROOT/tools/interop/rns_desttypes_config/config" "$PYTHON_CONFIG/config"
"$PYTHON" -c \
  'import sys; open(sys.argv[1], "wb").write(bytes.fromhex(sys.argv[2]))' \
  "$WORK_DIR/rust-serve.identity" "$RUST_PRIVATE"

# Python owns the TCP interface so GROUP packets remain single-hop. It first
# receives all three Rust cases, then sends all three cases to the deterministic
# long-running Rust destination on the same direct interface.
PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tools/interop/desttypes_peer.py" serve \
  --config "$PYTHON_CONFIG" --group-key "$GROUP_KEY" \
  --identity "$WORK_DIR/python-serve.identity" \
  --rust-private "$RUST_PRIVATE" \
  >"$WORK_DIR/python_peer.log" 2>&1 &
PYTHON_PID=$!
PIDS+=("$PYTHON_PID")
wait_for_pattern "$WORK_DIR/python_peer.log" "PYTHON_GROUP_DESTINATION"
PYTHON_PLAIN="$(awk '/PYTHON_PLAIN_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_peer.log")"
PYTHON_GROUP="$(awk '/PYTHON_GROUP_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_peer.log")"
PYTHON_PROOF="$(awk '/PYTHON_PROOF_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_peer.log")"

RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-plain-send.identity" \
  "$RUST_DAEMON" send-plain "$PYTHON_PLAIN" "plain hello from rust" \
  --config "$RUST_CONFIG" >"$WORK_DIR/rust_plain_send.log" 2>&1
RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-group-send.identity" \
RETICULUM_APP_NAME="python_group" RETICULUM_ASPECTS="message" \
RETICULUM_GROUP_KEY="$GROUP_KEY" \
  "$RUST_DAEMON" send-group "$PYTHON_GROUP" "group hello from rust" \
  --config "$RUST_CONFIG" >"$WORK_DIR/rust_group_send.log" 2>&1
RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-proof-send.identity" \
  "$RUST_DAEMON" send "$PYTHON_PROOF" "proved hello from rust" --prove \
  --config "$RUST_CONFIG" >"$WORK_DIR/rust_proof_send.log" 2>&1

grep -q "PYTHON_PLAIN_RECEIVED plain hello from rust" "$WORK_DIR/python_peer.log"
grep -q "PYTHON_GROUP_RECEIVED group hello from rust" "$WORK_DIR/python_peer.log"
grep -q "PYTHON_PROOF_RECEIVED proved hello from rust" "$WORK_DIR/python_peer.log"
grep -q "delivery confirmed" "$WORK_DIR/rust_proof_send.log"

RETICULUM_IDENTITY_PATH="$WORK_DIR/rust-serve.identity" \
RETICULUM_APP_NAME="reticulum_rust" RETICULUM_ASPECTS="message" \
RETICULUM_GROUP_KEY="$GROUP_KEY" RETICULUM_PROVE=true \
  "$RUST_DAEMON" run --config "$RUST_CONFIG" \
  >"$WORK_DIR/rust_serve.log" 2>&1 &
RUST_PID=$!
PIDS+=("$RUST_PID")
wait_for_pattern "$WORK_DIR/rust_serve.log" "local group destination"

EXPECTED_PROOF="$(awk '/EXPECTED_RUST_PROOF_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_peer.log")"
EXPECTED_PLAIN="$(awk '/EXPECTED_RUST_PLAIN_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_peer.log")"
EXPECTED_GROUP="$(awk '/EXPECTED_RUST_GROUP_DESTINATION/ {print $2; exit}' "$WORK_DIR/python_peer.log")"
grep -q "local destination $EXPECTED_PROOF" "$WORK_DIR/rust_serve.log"
grep -q "local plain destination $EXPECTED_PLAIN" "$WORK_DIR/rust_serve.log"
grep -q "local group destination $EXPECTED_GROUP" "$WORK_DIR/rust_serve.log"

wait "$PYTHON_PID"
wait_for_pattern "$WORK_DIR/rust_serve.log" "plain hello from python"
wait_for_pattern "$WORK_DIR/rust_serve.log" "group hello from python"
wait_for_pattern "$WORK_DIR/rust_serve.log" "proved hello from python"
grep -q "PYTHON_PROOF_DELIVERED" "$WORK_DIR/python_peer.log"

kill "$RUST_PID" 2>/dev/null || true
wait "$RUST_PID" 2>/dev/null || true

echo "PASS Rust -> Python: PLAIN + GROUP + explicit delivery proof"
echo "PASS Python -> Rust: PLAIN + GROUP + explicit delivery proof"
echo "Destination-type interop logs: $WORK_DIR"
