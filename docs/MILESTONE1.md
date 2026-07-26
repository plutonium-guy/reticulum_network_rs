# Milestone 1: first encrypted message

Milestone 1 implements a sans-I/O Reticulum node in Rust and demonstrates
encrypted `SINGLE` destination messages in both directions with Python RNS
1.4.1 over TCP.

## Prerequisites

- Rust toolchain from `rust-toolchain.toml`
- Python 3 and a local virtual environment containing exactly RNS 1.4.1:

```bash
python3 -m venv .venv
.venv/bin/pip install rns==1.4.1
```

## Run the end-to-end gate

From the repository root:

```bash
./tools/interop/run_interop.sh
```

Expected output:

```text
PASS Rust -> Python: hello from rust
PASS Python -> Rust: hello from python
```

The script builds `reticulumd`, starts an isolated `rnsd` with the committed
TCP server config, sends both plaintexts, asserts both received values, and
prints the directory containing all process logs.

## Run the Rust daemon manually

Start an RNS 1.4.1 daemon:

```bash
.venv/bin/rnsd --config tools/interop/rns_server_config -v
```

In another terminal:

```bash
cargo build -p reticulum-cli
target/debug/reticulumd run --config tools/interop/reticulumd.toml
```

The identity path, TCP address, application name, aspects, and announce data
can be set in TOML. Environment variables named `RETICULUM_IDENTITY_PATH`,
`RETICULUM_TCP_ADDR`, `RETICULUM_APP_NAME`, `RETICULUM_ASPECTS`, and
`RETICULUM_APP_DATA` override the file. Periodic announces default to 30
seconds and can be configured with `announce_interval_secs` or
`RETICULUM_ANNOUNCE_INTERVAL_SECS`.

## Architecture

`reticulum-core` owns byte-exact packet, announce, identity, and Token crypto
logic. `reticulum-node` is a deterministic `no_std + alloc` state machine.
`reticulum-tokio` only frames and moves packets and dispatches commands/events.
`reticulum-cli` supplies OS entropy, persistent identity storage, and process
wiring.
