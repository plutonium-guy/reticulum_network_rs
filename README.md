# reticulum_network_rs

A wire-compatible Rust implementation of the [Reticulum Network Stack](https://reticulum.network/) (RNS), interoperable with **Python RNS 1.4.1** and **LXMF 1.1.0**, built on a sans-I/O core that runs on desktop/server, in the browser (WASM), and on embedded `no_std` targets.

> Status: **feature-complete (M1–M8)** against the RNS 1.4.1 reference. Every layer is proven byte-exact against captured vectors and against a live Python RNS node. MIT licensed · Rust edition 2024.

## What it does

Reticulum is a cryptography-based networking stack for building resilient mesh networks over any medium (TCP/IP, radio, serial, …), with no dependence on IP addresses, DNS, CAs, or central infrastructure. This crate reimplements it in Rust with a strict **sans-I/O** design: all protocol logic is a pure, deterministic state machine, and every platform supplies its own I/O.

Interoperability is the contract — a Rust node exchanges announces, encrypted messages, links, resources, and LXMF messages with a stock Python RNS node.

## Feature status

| Milestone | Capability | Proven vs Python RNS |
|---|---|---|
| M1 | Identity, packets, encryption, direct 1-hop encrypted messaging | ✅ live |
| M2 | Multi-hop **Transport** (path discovery, forwarding, HEADER_2) | ✅ live (3-node relay) |
| M3 | **Links** (LINKREQUEST/PROOF, ECDH session, encrypted channel) | ✅ live |
| M4 | **Resources** (chunked transfer, windowed flow control, bz2) | ✅ live (SHA-256 matched) |
| M5 | **GROUP** + **PLAIN** destinations, delivery **proofs/receipts** | ✅ live |
| M6 | Interfaces: TCP client/server, UDP, AutoInterface, Serial/KISS, **IFAC** | ✅ live (incl. IPv6) |
| M7 | Platform: **WASM** (browser), **embedded** (`no_std`/embassy), **mobile** (uniffi) | ✅ per-platform gate |
| M8 | **LXMF** messaging (direct + opportunistic) + `rnstatus`/`rnpath` tooling | ✅ live |

Cryptography matches RNS 1.4.1 exactly: X25519 + Ed25519, HKDF-SHA256, AES-256-CBC, HMAC-SHA256, truncated SHA-256 addressing.

## Architecture

Sans-I/O. Protocol logic lives entirely in the `no_std + alloc` core; I/O and async live only in the outer crates. Randomness is injected via an `EntropySource` trait and time via a `Clock` trait, so the whole stack is deterministic and unit-testable with no runtime.

```
crates/
  reticulum-core        no_std  identity · destination · token (crypto) · packet · announce
                                · link · resource · proof
  reticulum-interface   no_std  HDLC + KISS framing · IFAC frame authentication
  reticulum-node        no_std  sans-I/O Node state machine: transport, links, resources,
                                path table, dedup, delivery receipts
  reticulum-lxmf        no_std  LXMF message build/pack/sign/verify + routing
  reticulum-tokio       std     TCP/UDP/Auto/Serial interfaces · async driver · OS entropy
  reticulum-cli         std     `reticulumd` daemon + CLI (send, link, lxmf, status, path)
  reticulum-wasm        wasm32  browser node bindings (WebSocket transport)
  reticulum-embedded    thumbv7 no_std node over embassy + UART/KISS
  reticulum-ffi         std     uniffi bindings (Kotlin + Swift)
```

The three `no_std` crates (`core`, `interface`, `node`, plus `lxmf`) cross-compile to `wasm32-unknown-unknown` and `thumbv7em-none-eabihf`, enforced in CI.

## Quick start

```bash
# build + test the whole workspace
cargo test --workspace

# run the daemon (see crates/reticulum-cli for config)
cargo run -p reticulum-cli -- run --config tools/interop/reticulumd.toml

# CLI verbs: send / send-plain / send-group / link / lxmf / status / path
cargo run -p reticulum-cli -- --help
```

Optional features: `--features compression` (bz2 Resources, `reticulum-core`), `--features serial` (serial interface, `reticulum-cli`).

## Browser console (WASM)

`tools/wasm/app.html` is an operator console for a browser-resident node, with a **passphrase-encrypted identity vault** (PBKDF2-SHA256 → AES-256-GCM, keys generated and stored only in-browser). Browsers can't open raw TCP, so it reaches the mesh through a WebSocket↔TCP bridge (`tools/wasm/bridge.py`). See `tools/wasm/README.md`.

## Interoperability testing

Correctness is proven two ways: byte-exact **vectors** captured from Python RNS 1.4.1 (`vectors/`), and **live interop gates** that run a real Python RNS node against the Rust implementation.

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install rns==1.4.1 lxmf==1.1.0

./tools/interop/run_interop.sh            # M1  direct encrypted message
./tools/interop/run_transport_interop.sh  # M2  multi-hop across a Rust relay
./tools/interop/run_link_interop.sh       # M3  link establishment + data
./tools/interop/run_resource_interop.sh   # M4  file transfer (bz2 + plain)
./tools/interop/run_desttypes_interop.sh  # M5  GROUP/PLAIN + delivery proofs
./tools/interop/run_interfaces_interop.sh # M6  TCP(+IPv6)/UDP/IFAC
./tools/interop/run_wasm_interop.sh       # M7  browser node via WS bridge
./tools/interop/run_ffi_interop.sh        # M7  uniffi façade
./tools/interop/run_lxmf_interop.sh       # M8  LXMF message exchange
```

Each script exits non-zero on failure and prints `PASS`/`SKIP` per case.

## Design & plans

Full specs and per-milestone implementation plans live in `docs/superpowers/`:
- `specs/2026-07-26-reticulum-rust-port-design.md` — architecture + goals
- `plans/` — the M1–M8 implementation plans (TDD, vector-driven)

## Known limitations

Scoped-out and deferred (documented in the plans):
- Multi-segment Resources (payloads > 1 MiB)
- LXMF propagation-node sync (upload implemented; download deferred) and stamp *generation* (verification implemented)
- Request/response over links
- LoRa/RNODE and I2P interfaces (integration points documented; hardware/overlay-gated)
- AutoInterface live interop needs two hosts (one-host loopback can't bind the same link-local port)

## License

MIT. Reticulum is an open protocol by Mark Qvist; this is an independent Rust implementation targeting wire compatibility, not affiliated with the upstream project.
