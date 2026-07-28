# Reticulum (RNS) Rust Port — Design

**Date:** 2026-07-26
**Status:** Approved (design phase)
**Author:** amiyamandal

## Goal

Build a wire-compatible Rust reimplementation of the Reticulum Network Stack
(RNS) that interoperates with existing Python RNS nodes and runs across
desktop/server, embedded `no_std`, and WASM/browser targets.

**Milestone 1 goal:** a running Rust node exchanges one encrypted message
end-to-end with a Python RNS node over a TCP interface.

### Success criteria

- Rust node and Python RNS node exchange announces over TCP; the Rust node
  appears in the Python node's `rnstatus` / path table.
- Rust node encrypts and sends, and receives and decrypts, a `DATA` packet to a
  `SINGLE` destination — both directions — interoperating with Python RNS.
- Core protocol logic builds for `std`, `wasm32-unknown-unknown`, and a
  `no_std` embedded target (e.g. `thumbv7em-none-eabihf`) in CI.
- All crypto, packet, and announce encoding is validated byte-exact against
  vectors captured from a pinned Python RNS version.

### Non-goals (Milestone 1)

Multi-hop Transport routing, full Link lifecycle, Resources, interfaces beyond
TCP (UDP/serial/LoRa/I2P), a WASM full node, an embedded full node, mobile FFI,
and LXMF messaging. These are later specs. (Link establishment is a stretch
goal inside Phase 4, not required.)

## Architecture

Sans-I/O core. The protocol logic is a pure, deterministic state machine with
zero I/O and zero async: bytes/events in → bytes/events out. Each platform
supplies its own I/O loop around the same core. This maximizes portability
(the same core builds for std, `no_std`, and WASM) and testability (protocol
logic is unit-testable with no runtime).

### Workspace layout

```
reticulum/                      (cargo workspace)
├── crates/
│   ├── reticulum-core          no_std + alloc. Identity, crypto/Token,
│   │                           Destination, Packet codec, constants.
│   │                           CI-built for wasm32 + a no_std target.
│   ├── reticulum-node          no_std + alloc. Sans-I/O state machine:
│   │                           announce, path table (direct-delivery first),
│   │                           packet in/out queues, link state. Pure logic.
│   ├── reticulum-interface     Interface trait (byte source/sink) + HDLC
│   │                           framing. no_std trait; std impls behind feature.
│   ├── reticulum-tokio         std. tokio I/O loop, TCPClientInterface,
│   │                           drives node + interfaces. The daemon core.
│   └── reticulum-cli           std. rnsd-style daemon + CLI binary.
└── vectors/                    Test vectors captured from Python RNS for
                                byte-exact validation (crypto, packet, announce).
```

**Invariant:** all protocol logic lives in `reticulum-core` + `reticulum-node`
(portable, unit-testable, no runtime). `reticulum-tokio` and embedded layers
only move bytes. The Milestone 1 "first message" demo runs as
the std `reticulum-cli` daemon; `core` + `node` build for wasm32 and a no_std
target from day 1 in CI even though the running node is std.

### Crate boundaries (what/how/depends-on)

- **reticulum-core** — encode/decode + crypto primitives. Used by every other
  crate. Depends only on RustCrypto crates (all `no_std`). No I/O, no async, no
  panics on untrusted input.
- **reticulum-node** — owns node state (identities, destinations, path table,
  in/out packet queues, link state). API: `node.handle_inbound(bytes, iface_id)
  -> Vec<Event>` and `node.poll_outbound() -> Vec<(iface_id, bytes)>`. Depends
  on `reticulum-core`. No I/O.
- **reticulum-interface** — `Interface` trait (byte source/sink) + HDLC framing
  codec. `no_std` trait definition; concrete std impls feature-gated.
- **reticulum-tokio** — tokio-based I/O loop that pumps interfaces into the node
  and node outbound back to interfaces. Hosts `TCPClientInterface`.
- **reticulum-cli** — daemon + CLI binary wiring config → node → interfaces.

## Protocol primitives (RNS conformance)

All primitives are byte-exact against a pinned Python RNS version, validated via
captured `vectors/`. Crypto is not a design choice — it must match RNS.

### Identity (`reticulum-core`)

- X25519 keypair (encryption) + Ed25519 keypair (signing).
- Public identity = 32B X25519 public ‖ 32B Ed25519 public = 64 bytes.
- Identity hash = truncated SHA-256 → 16 bytes (128-bit `TRUNCATED_HASHLENGTH`).
- Ratchets (rotating X25519 keys): decode and store now; full rotation logic is
  a later phase.

### Destination

- Name = `app_name` + aspects → name hash (truncated SHA-256; 10 bytes used in
  announce).
- Destination hash = truncated SHA-256(name_hash ‖ identity_hash) → 16 bytes.
- Types: `SINGLE`, `GROUP`, `PLAIN`, `LINK`. Directions `IN` / `OUT`.
- Milestone 1 scope: `SINGLE` + `PLAIN`.

### Token (RNS encryption primitive, Fernet-like)

- Ephemeral X25519 ECDH → HKDF-SHA256 key derivation → AES-CBC (PKCS7 padding)
  + HMAC-SHA256 authentication.
- Match the target RNS version's key sizes exactly (AES-128 vs AES-256 differs
  by version). Pin the version; prove equivalence via vectors.

### Packet codec

- Byte 0 flags: `[IFAC(1)][header_type(1)][context_flag(1)][propagation_type(1)]
  [dest_type(2)][packet_type(2)]`.
- Byte 1: hops.
- Then destination hash(es): 16B (HEADER_1) or 32B (HEADER_2 / transport).
- Context byte (1). Then payload.
- Packet types: `DATA`, `ANNOUNCE`, `LINKREQUEST`, `PROOF`. MTU 500.

### Announce

- ANNOUNCE payload: pubkey(64B) ‖ name_hash(10B) ‖ random_hash(10B) ‖ [ratchet]
  ‖ signature(64B) ‖ app_data.
- Signature = Ed25519 over dest_hash ‖ pubkey ‖ name_hash ‖ random_hash ‖
  [ratchet] ‖ app_data. Verified on receive.

### Framing (`reticulum-interface`)

- HDLC byte-stuffing (flag `0x7E`, escape `0x7D`) for TCP/serial — matches RNS
  `TCPClientInterface`.

### Conformance gate

A `vectors/` harness captures known-good bytes from Python RNS (identity keys,
encrypted tokens, packets, announces). The Rust implementation must reproduce
and parse them byte-exact. This is the interop insurance.

## Cryptography stack

RustCrypto crates (all `no_std`):

- `ed25519-dalek` — signing.
- `x25519-dalek` — ECDH.
- `aes` + `cbc` — AES-CBC.
- `hmac` + `sha2` — HMAC-SHA256, SHA-256.
- `hkdf` — key derivation.

Exact key sizes and construction are pinned to the target RNS version and
proven via vectors.

## Roadmap (phases → first message)

Each phase is its own implementation plan, built test-first.

| Phase | Deliverable | Interop / verification gate |
|---|---|---|
| **0. Scaffold** | Workspace, CI matrix (std + `wasm32-unknown-unknown` + a `no_std` target such as `thumbv7em-none-eabihf`), `vectors/` capture script against pinned Python RNS. | CI green on all three targets (empty crates). |
| **1. Core primitives** | Identity, Token, Destination, Packet codec, HDLC framing. `no_std`. | Byte-exact vs vectors: keygen, encrypt/decrypt, packet parse/build. |
| **2. Node state machine** | Sans-I/O `Node`: `handle_inbound(bytes, iface)` → events / outbound. Announce build/parse/verify, direct-delivery path table (no multi-hop). | Two in-memory Rust nodes announce and see each other, deterministically, with no I/O. |
| **3. TCP interface** | `reticulum-tokio` I/O loop + `TCPClientInterface` + `reticulum-cli` daemon. | Rust daemon connects to a Python RNS `TCPServerInterface`; announces cross the wire and are visible in `rnstatus`. |
| **4. First message** | Encrypt→send / receive→decrypt a `DATA` packet to a `SINGLE` destination, both directions, over TCP. | Milestone goal: Rust ↔ Python RNS exchange one encrypted message end-to-end. Link establishment is a stretch. |

### Later specs (out of Milestone 1 scope)

Multi-hop Transport routing, full Links, Resources, additional interfaces
(UDP/serial/LoRa/I2P), WASM full node + browser I/O, embedded HAL, mobile FFI,
LXMF.

## Testing strategy

- **Unit:** pure functions in `core` / `node` — no runtime needed (the sans-I/O
  payoff).
- **Vector conformance:** the byte-exact harness against pinned Python RNS —
  the interop contract.
- **Property tests:** `decode(encode(p)) == p` for packets;
  `decrypt(encrypt(m)) == m` for tokens.
- **Integration:** two Rust nodes over an in-memory transport (Phase 2), then
  live Rust ↔ Python (Phases 3–4).
- **CI cross-compile gate every phase:** std + `wasm32` + `no_std` must all
  build.
- **Fuzzing:** `cargo-fuzz` on packet and announce decoders.

## Error handling

- `no_std`-friendly typed errors (hand-rolled enums in `core`; `thiserror` in
  std layers).
- No panics in `core` / `node` — malformed or untrusted input returns `Err`,
  never crashes.
- All parsing is fallible and fuzzed.
- I/O errors are isolated to edge crates; the node state machine treats
  interface up/down as events, not errors.

## Pinned target version

- **Python RNS 1.4.1** (latest stable at design time, PyPI package `rns`). All
  vectors are captured from this version; record it in `vectors/README`. Bump
  deliberately in a later spec, never silently.

## Open questions / risks

- **AES key size:** confirm AES-128 vs AES-256 for RNS 1.4.1 via captured
  vectors before writing the Token implementation.
- **Ratchet handling:** Milestone 1 decodes/stores ratchets but does not rotate;
  confirm this is acceptable for interop with the target Python version.
