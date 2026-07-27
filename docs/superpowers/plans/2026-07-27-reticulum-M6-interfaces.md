# Reticulum Rust Port — Milestone 6: Interfaces (full TDD)

> **For Codex:** Full TDD plan expanding M6 from the master program plan. Execute task-by-task, in order; each ends green with a commit. Interfaces are I/O-heavy: unit-test the framing/parsing in isolation, and prove each interface with a loopback and/or live RNS 1.4.1 gate. Confirm every wire/framing detail against RNS source (`RNS/Interfaces/*.py`) and a live node — never guess. Stop for review at the milestone gate (Task M6.8).

**Goal:** Interface parity so the node runs over the mediums RNS supports: introduce a common `Interface` abstraction, then add TCP **server**, UDP, AutoInterface (LAN discovery), Serial/KISS, and IFAC (interface access codes). LoRa/RNODE + I2P are documented stretch. **Acceptance:** TCP-server, UDP, and AutoInterface each interop with Python RNS 1.4.1 on loopback/LAN, and an IFAC-protected link works both directions (`tools/interop/run_interfaces_interop.sh` exits 0 with captured evidence).

## RNS 1.4.1 facts (from source — authoritative, still verify)

- **Framing (`TCPInterface.py`):** HDLC (`FLAG=0x7E`, `ESC=0x7D`, `ESC_MASK=0x20` — our `hdlc` module) OR KISS (`FEND=0xC0`, `FESC=0xDB`, ...). TCP uses HDLC by default (`bytes([HDLC.FLAG]) + HDLC.escape(data) + bytes([HDLC.FLAG])`). `HW_MTU = 262144` for TCP. Frame validity: `frame_len <= HW_MTU + ifac_size`, else drop.
- **TCPServerInterface (`TCPInterface.py:75+`):** accepts inbound TCP connections; each connected socket is a "spawned" interface using the same HDLC read loop as the client. We need the server side (Python currently is the server in our M1–M5 gates; now Rust can be the server).
- **UDPInterface (`UDPInterface.py`):** `HW_MTU = 1064`; binds `listen_ip:listen_port`; sends to a broadcast/peer address. NO HDLC — each UDP datagram carries exactly one packet (datagram boundary = frame boundary). Read `processIncoming`/`sendOutgoing` for the exact send/recv (raw packet bytes per datagram).
- **AutoInterface (`AutoInterface.py`):** IPv6 link-local multicast peer discovery on a group/port; discovers peers, then exchanges packets (confirm: multicast for discovery, per-peer send). Desktop/std only. Read for the multicast group, port, and discovery cadence.
- **Serial/KISS (`SerialInterface.py`, `KISSInterface.py`):** raw serial port with KISS framing (`FEND`-delimited, `FESC` escaping). std + `serialport` crate; feature-gated.
- **IFAC (interface access codes):** an optional per-interface authentication/obfuscation layer. When configured with a `network_name` + `passphrase`, RNS derives an IFAC key (read the derivation — HKDF over the passphrase/name) and signs/obfuscates every frame; the packet byte-0 `IFAC` flag (already in our `Packet`) signals presence, and an `ifac_size` prefix carries the auth tag. IFAC processing is applied at the Transport boundary (read `RNS/Transport.py` inbound/outbound IFAC handling + `Interface.py` `ifac_*` fields). This is the least-documented piece — pin it with a captured vector + live gate.

---

## File structure

```
crates/reticulum-interface/src/
  lib.rs         + Interface trait; re-exports
  kiss.rs        NEW: KISS framing (FEND/FESC escape/unescape)
  ifac.rs        NEW (no_std): IFAC frame transform (key derivation + sign/verify/obfuscate)
crates/reticulum-tokio/src/
  interface.rs   NEW: async Interface trait object model; driver holds Vec<Box<dyn AsyncInterface>>
  tcp.rs         + TcpServerInterface (accept loop, per-conn spawned interface)
  udp.rs         NEW: UdpInterface (datagram)
  auto.rs        NEW: AutoInterface (IPv6 multicast discovery)
  serial.rs      NEW (feature "serial"): SerialInterface (KISS over serialport)
  driver.rs      multi-interface driver: route node outbound by interface id; ingest all
crates/reticulum-cli/  config: [[interface]] list (type + params); wire them up
tools/
  capture_vectors.py     + ifac_frame.json
  interop/run_interfaces_interop.sh, iface_peer configs
vectors/ ifac_frame.json  NEW
```

## Global constraints (inherited)

Target RNS 1.4.1. `reticulum-interface` stays `no_std + alloc` (KISS + IFAC framing are pure transforms — no_std, cross-compile to wasm32 + thumbv7em). Networking interfaces live in `reticulum-tokio` (std). Sans-I/O node unchanged. No panics on untrusted frames. TDD + vector/live-driven. Commit per task.

---

### Task M6.0: `Interface` abstraction + multi-interface driver

**Files:** `crates/reticulum-interface/src/lib.rs`, `crates/reticulum-tokio/src/interface.rs`, `driver.rs`, tests.

**Interfaces:**
- no_std trait in `reticulum-interface` describing a framed byte medium at the type level (framing kind + MTU); the async I/O trait lives in tokio.
- `reticulum-tokio`: `pub trait AsyncInterface: Send { fn id(&self) -> u16; async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>>; async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()>; }` (use `async-trait` or return boxed futures). Refactor `Driver` to hold `Vec<Box<dyn AsyncInterface>>` and `select!` across all of them; route `node.poll_outbound()`'s `(interface_id, bytes)` to the interface with that id; ingest from every interface tagging inbound with its id. `TcpClientInterface` implements `AsyncInterface`.

- [ ] TDD: driver-level test with TWO interfaces (two loopback TCP pairs) on one node — the node announces on both, receives on both, and outbound to interface 1 goes to interface 1 only. Commit `refactor(tokio): multi-interface driver over an AsyncInterface trait`.

> This refactor is the enabler; keep the existing M1–M5 driver tests green (single-interface is the N=1 case).

### Task M6.1: TCPServerInterface

**Files:** `crates/reticulum-tokio/src/tcp.rs`, tests.

**Interfaces:** `TcpServerInterface::bind(addr) -> io::Result<Self>`; an accept loop that, per inbound connection, yields a spawned `AsyncInterface` (HDLC framed, same codec as the client) registered with the driver under a fresh interface id. Handle multiple concurrent peers.

- [ ] **Step 1:** Loopback test: a `TcpServerInterface` accepts a `TcpClientInterface`; a packet sent by the client is received by the server-side spawned interface and echoes back.
- [ ] **Step 2–4:** Implement (accept loop feeding new interfaces to the driver via a channel); run (pass); clippy; cross-compile (tokio is std — no no_std requirement here). Commit `feat(tokio): TCP server interface (accept inbound peers)`.
- [ ] **Live check** (folded into M6.8): Python `TCPClientInterface` connects to the Rust server; announces cross.

### Task M6.2: UDPInterface

**Files:** `crates/reticulum-tokio/src/udp.rs`, tests.

**Interfaces:** `UdpInterface::bind(listen_addr, peer_or_broadcast_addr) -> io::Result<Self>` implementing `AsyncInterface`; `recv_packet` = one datagram → one raw packet (no HDLC); `send_packet` = one datagram to the peer/broadcast addr; enforce `HW_MTU = 1064` (drop oversize). Confirm against `UDPInterface.py` whether any per-datagram framing/prefix exists (it does not — raw packet per datagram).

- [ ] **Step 1:** Loopback test: two `UdpInterface`s on localhost exchange a raw packet each way; an oversize (>1064) datagram is dropped.
- [ ] **Step 2–4:** Implement; run (pass); clippy. Commit `feat(tokio): UDP datagram interface`.

### Task M6.3: AutoInterface (LAN discovery)

**Files:** `crates/reticulum-tokio/src/auto.rs`, tests.

**Interfaces:** `AutoInterface::new(group_id, port, iface_name) -> io::Result<Self>` — join the IPv6 link-local multicast group RNS uses (read the exact group/port/derivation from `AutoInterface.py`), discover peers, and exchange packets (multicast or per-discovered-peer unicast, per RNS). Implements `AsyncInterface`.

- [ ] **Step 1:** Loopback/self test: two `AutoInterface` instances on the loopback/link-local scope discover each other and exchange a packet. (If CI lacks multicast, gate this test behind `#[ignore]` and rely on the live gate; note it.)
- [ ] **Step 2–4:** Implement; run (pass); clippy. Commit `feat(tokio): AutoInterface IPv6 multicast discovery`.

### Task M6.4: Serial/KISS interface (feature "serial")

**Files:** `crates/reticulum-interface/src/kiss.rs` (no_std KISS framing), `crates/reticulum-tokio/src/serial.rs` (feature-gated), tests.

**Interfaces:**
- `kiss::{frame(&[u8]) -> Vec<u8>, deframe(&[u8]) -> Option<Vec<u8>>}` — FEND(0xC0)-delimited, FESC(0xDB) escaping (`FEND→FESC TFEND(0xDC)`, `FESC→FESC TFESC(0xDD)`), CMD_DATA(0x00) leading byte. Confirm against `KISSInterface.py`.
- `SerialInterface` behind `#[cfg(feature="serial")]` using the `serialport` crate: read/write KISS frames over a serial port. Implements `AsyncInterface` (spawn a blocking reader task).

- [ ] **Step 1:** Vector/unit test for KISS framing: `frame`/`deframe` round-trip incl. escaped FEND/FESC bytes; a captured KISS frame (optional vector `kiss.json`) decodes byte-exact.
- [ ] **Step 2–4:** Implement KISS (no_std) + the feature-gated serial transport; run (pass) incl. `--features serial`; keep default build no_std-clean. Commit `feat(interface): KISS framing + feature-gated serial interface`.

### Task M6.5: IFAC (interface access codes)

**Files:** `crates/reticulum-interface/src/ifac.rs` (no_std), `capture_vectors.py`, `vectors/ifac_frame.json`, wiring in the tokio interfaces, tests.

> **Read first:** `RNS/Transport.py` inbound/outbound IFAC handling and `RNS/Interfaces/Interface.py` `ifac_*` fields. IFAC derives a key from `network_name` + `passphrase` (HKDF), and on each outbound frame prepends/signs an auth section (size `ifac_size`), setting the byte-0 `IFAC` flag; inbound frames are verified/stripped before the packet reaches the node. Pin the exact derivation + frame transform with a captured vector.

**Interfaces (no_std):**
- `ifac::derive_key(network_name: &str, passphrase: &str) -> [u8; N]` (match RNS).
- `ifac::apply(frame: &[u8], key) -> Vec<u8>` (wrap an outbound frame; set IFAC flag + auth tag).
- `ifac::strip(frame: &[u8], key) -> Result<Vec<u8>, CoreError>` (verify + unwrap an inbound frame; reject on bad auth).

- [ ] **Step 1:** `vectors/ifac_frame.json`: from an RNS interface configured with a fixed `network_name`+`passphrase`, capture `{ network_name, passphrase, ifac_key, plain_frame, ifac_frame }`.
- [ ] **Step 2:** Failing tests: `derive_key` matches; `apply(plain_frame) == ifac_frame`; `strip(ifac_frame) == plain_frame`; a tampered ifac_frame → `Err`.
- [ ] **Step 3–4:** Implement (no_std); run (pass); clippy; cross-compile. Wire `apply`/`strip` into the tokio interfaces when an IFAC config is present (transform on send after framing? confirm ordering vs HDLC from source). Commit `feat(interface): IFAC frame authentication`.

### Task M6.6: LoRa/RNODE + I2P (documented stretch)

**Files:** `docs/INTERFACES.md`.

- [ ] Document what RNODE (LoRa) and I2P interfaces require (hardware / I2P router), the RNS config shape, and how they'd map onto `AsyncInterface`. Do NOT implement unless hardware/an I2P router is available; explicitly mark as deferred with the integration points identified. Commit `docs: RNODE/LoRa + I2P interface integration notes (deferred)`.

### Task M6.7: CLI multi-interface config

**Files:** `crates/reticulum-cli/src/config.rs`, `main.rs`, tests.

- [ ] Config supports a list of interfaces (`[[interface]]` with `type = "tcp_client"|"tcp_server"|"udp"|"auto"|"serial"` + per-type params + optional `ifac = { network_name, passphrase }`). Build the corresponding `AsyncInterface`s and register them with the driver. TDD: config parse for each interface type; identity/receipt behavior unchanged. Commit `feat(cli): configure multiple interfaces (tcp/udp/auto/serial + ifac)`.

### Task M6.8: Live interop gate (Milestone 6 gate)

**Files:** `tools/interop/run_interfaces_interop.sh`, interface configs, README.

- [ ] **TCP server:** Rust runs a `TcpServerInterface`; a Python `TCPClientInterface` connects; announces cross; a message round-trips.
- [ ] **UDP:** Rust `UdpInterface` ↔ Python `UDPInterface` on loopback; message round-trips.
- [ ] **AutoInterface:** Rust ↔ Python `AutoInterface` on the loopback/link-local scope discover + exchange (if the environment supports multicast; else document + skip with a clear message).
- [ ] **IFAC:** an IFAC-protected TCP link (matching `network_name`+`passphrase`) works Rust↔Python; a MISMATCHED passphrase is rejected (no packets delivered).
- [ ] Exit 0 only for the cases the environment supports; capture evidence. Commit `test(interop): live Rust<->Python across TCP-server/UDP/Auto/IFAC`.

**M6 acceptance:** `cargo test --workspace` (+ `--features serial`) green; clippy `-D warnings` clean; no_std cross-compile (interface crate default features) green; `run_interfaces_interop.sh` exits 0 for TCP-server + UDP + IFAC (AutoInterface if supported) with committed evidence.

---

## Self-Review

**Coverage vs M6 outline:** interface abstraction (M6.0), TCPServer (M6.1), UDP (M6.2), AutoInterface (M6.3), Serial/KISS (M6.4), IFAC (M6.5), LoRa/I2P documented-deferred (M6.6), CLI wiring (M6.7), live gate (M6.8).

**Placeholder scan:** none. AutoInterface multicast params, IFAC key derivation + frame transform, and UDP/KISS framing specifics are marked "read from RNS source / capture vector" with an oracle — verification steps, not deferred work. LoRa/I2P are explicitly deferred (hardware-gated) with integration points identified, not silently dropped.

**Type consistency:** `AsyncInterface` (id/recv_packet/send_packet) is the single interface contract all transports implement; `kiss::{frame,deframe}` mirror `hdlc::{frame,deframe}`; `ifac::{derive_key,apply,strip}` are used consistently in interfaces + CLI. The multi-interface driver reuses the node's existing `(interface_id, bytes)` outbound contract from M2 — no node change.

**Reuse (DRY):** HDLC framing reused from M1; KISS is a parallel framing module; IFAC is a no_std transform layered on any framed interface. The node/core are untouched (interfaces only move bytes) — preserving the sans-I/O boundary.

**Risk:** IFAC (M6.5) is the least-documented feature — pinned to a vector before wiring, and mismatched-passphrase rejection is explicitly tested in the live gate. AutoInterface multicast may not work in all CI/sandbox environments — its unit test is `#[ignore]`-able and it leans on the live gate, which degrades gracefully if multicast is unavailable.
