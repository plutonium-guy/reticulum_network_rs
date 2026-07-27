# Reticulum Rust Port — Master Program Plan (Milestones 2–8: full RNS parity)

> **For the implementing agent (Codex):** This is a MASTER program plan covering all remaining work to full Reticulum parity. It is deliberately structured as sequenced milestones (M2–M8), NOT one flat task list, because later milestones depend on APIs earlier ones create and cannot be code-specified until those exist.
>
> **Execution protocol (mandatory):**
> 1. Build **one milestone at a time, in order**. Do not start Mn+1 until Mn's acceptance gate passes.
> 2. Milestone **M2 is specified to full TDD task detail** below — execute it directly.
> 3. Milestones **M3–M8 are specified as task + interface + acceptance-gate outlines**. Before building each, EXPAND it into full TDD steps (same style as M2 / the Phase 0–4 plans) using the concrete APIs that exist by then, then execute. Announce the expansion; do not improvise code against non-existent APIs.
> 4. After each milestone: full `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, no_std cross-compile of no_std crates, and the milestone's interop gate vs Python RNS 1.4.1. Commit per task. Stop for review at each milestone boundary.
> 5. Every wire-format detail is confirmed against captured RNS 1.4.1 vectors and/or live interop — never guessed. Read RNS source in `.venv/lib/python3.*/site-packages/RNS/` when a layout is unknown.

**Goal:** Take the Rust port from Milestone 1 (direct 1-hop encrypted messaging) to full Reticulum 1.4.1 feature parity across desktop/server, WASM, and embedded, plus mobile FFI and LXMF messaging.

**Architecture (unchanged):** Sans-I/O core. Protocol logic lives in `reticulum-core` + `reticulum-node` (`no_std + alloc`, deterministic, RNG injected). I/O + async live only in outer crates. Correctness proven by RNS 1.4.1 vectors + live interop.

## Current state (built, on master)

- `reticulum-core` (`no_std`): `hash`, `identity`, `destination`, `token` (X25519+HKDF-SHA256+AES-256-CBC+HMAC), `packet` (HEADER_1 only; HEADER_2 decode is lossy), `announce` (build/parse/verify, ratchet-aware parse).
- `reticulum-interface` (`no_std`): `hdlc`.
- `reticulum-node` (`no_std`): `EntropySource` trait, `PathTable`, `Node` (register SINGLE dest, announce emit, handle_inbound for announce+DATA, send_message direct-delivery).
- `reticulum-tokio` (std): `TcpClientInterface`, `Driver`, `OsEntropy`.
- `reticulum-cli` (std): `reticulumd` daemon, config, persistent identity.
- Milestone 1 proven: live Rust↔Python RNS 1.4.1 encrypted message both directions.

## Global Constraints (bind every milestone)

- **Target RNS version:** Python RNS **1.4.1** exactly. All vectors from it; all interop against it. Never bump silently.
- **`reticulum-core`, `reticulum-interface`, `reticulum-node` stay `no_std + alloc`** and MUST keep building for `wasm32-unknown-unknown` and `thumbv7em-none-eabihf` (CI enforces via the scoped cross-compile jobs — extend those jobs to any new no_std crate).
- **Sans-I/O**: no I/O, no async, no direct RNG in the three no_std crates. Randomness via `EntropySource`. Time via an injected clock trait (introduced in M2 — see Task M2.1), never `std::time` in core/node.
- **No panics on untrusted input** anywhere in decoders/handlers.
- **CSPRNG discipline**: IVs, ephemeral keys, link keys, and any nonces drawn fresh per use from an OS CSPRNG in the std layer; seeded deterministic source in tests.
- **std/async confined** to `reticulum-tokio`, `reticulum-cli`, and future `reticulum-wasm`/`reticulum-embedded`/`reticulum-ffi` crates.
- **Existing public API is stable** unless a task explicitly amends it with a documented reason (mirror the M1 process: amend the plan text + note in the commit).
- **TDD + frequent commits + vector-driven verification** for every task.

## Milestone dependency graph

```
M1 (done)
  └─ M2 Transport (multi-hop) ── depends on: packet HEADER_2, node
       └─ M3 Links ──────────── depends on: M2 (deliver to non-local dest), token, identity
            ├─ M4 Resources ─── depends on: M3 (links carry resources)
            └─ M5 Dest types + Proofs ── depends on: M2/M3
       └─ M6 Interfaces ─────── depends on: M2 (interface abstraction), independent of M3/M4
  └─ M7 Platform (wasm/embedded/mobile) ── depends on: stable core+node (after M2+), M6 interface trait
  └─ M8 LXMF + tooling ──────── depends on: M3 (links) + M4 (resources) + M5 (proofs)
```

Recommended build order: **M2 → M3 → M4 → M5 → M6 → M7 → M8**. M6 may be interleaved after M2 (it only needs the interface abstraction).

---

# MILESTONE 2 — Transport (multi-hop routing) — FULL TDD

**Goal:** The node routes packets it is not the destination for, discovers paths via announces + path requests, and forwards over multiple hops. Fixes HEADER_2 losslessness. Acceptance: a 3-node line (Rust ↔ Rust-relay ↔ Python RNS, and Python ↔ Rust-relay ↔ Rust) delivers an encrypted message across the relay.

**Prereqs to read in RNS source before starting:** `RNS/Transport.py` (packet forwarding, path table, `PATH_REQUEST`, announce retransmission, hop limits `PATHFINDER_M`), `RNS/Packet.py` (HEADER_2 layout: `[flags][hops][transport_id(16)][dest_hash(16)][context][data]`), `RNS/Destination.py`.

### Task M2.1: Injected clock + HEADER_2 lossless packet

**Files:**
- Modify: `crates/reticulum-node/src/lib.rs` (add `pub trait Clock { fn now_secs(&self) -> u64; }`)
- Modify: `crates/reticulum-core/src/packet.rs` (add `transport_id: Option<[u8;16]>` field; HEADER_2 encode/decode round-trips it)
- Test: `crates/reticulum-core/tests/vectors.rs`, inline node test

**Interfaces:**
- `Packet` gains `pub transport_id: Option<[u8;16]>`. For HEADER_2, `encode` writes `transport_id ‖ dest_hash` (32 bytes); `decode` populates both. HEADER_1 keeps `transport_id = None`.
- `pub trait Clock { fn now_secs(&self) -> u64; }` + a `TestClock` (fixed/advanceable) in node; `SystemClock` (std) added in the tokio crate.

- [ ] **Step 1: Capture a HEADER_2 vector.** Extend `tools/capture_vectors.py` to emit `vectors/packet_header2.json` — a transport/HEADER_2 packet from RNS (e.g. a forwarded packet). Read `RNS/Packet.py` to construct or capture one; record `{bytes, transport_id(16), dest_hash(16), hops, packet_type, context, data}`.
- [ ] **Step 2: Failing test** — decode `packet_header2.json`, assert `transport_id == Some(vector.transport_id)`, `dest_hash == vector.dest_hash`, and `encode()` is byte-exact.
- [ ] **Step 3: Run (fail), implement** the `transport_id` field + HEADER_2 encode/decode (remove the M1 lossiness carry-forward). Keep HEADER_1 tests green (`transport_id = None`).
- [ ] **Step 4: Run (pass)**, clippy clean, cross-compile.
- [ ] **Step 5: Commit** `feat(core): lossless HEADER_2 packet with transport_id + Clock trait`.

### Task M2.2: Transport path table with metadata

**Files:** Modify `crates/reticulum-node/src/path_table.rs`, tests inline.

**Interfaces:** Extend `PathEntry` with `next_hop_transport_id: Option<[u8;16]>` (the relay to send via), `expires_at: u64`, `timestamp: u64`. Add `PathTable::prune(now: u64)`; `insert` keeps the entry with fewer hops / newer timestamp per RNS rules (read `Transport.py` announce-handling for the tie-break + expiry `PATHFINDER_E`).

- [ ] TDD: insert two paths for same dest (different hops) → fewer-hops wins; expired entry pruned by `prune(now)`. Commit.

### Task M2.3: Announce propagation (retransmit with incremented hops)

**Files:** Modify `crates/reticulum-node/src/node.rs`, tests inline.

**Interfaces:** `Node` gains a transport-enabled mode (`Node::enable_transport(true)`). On receiving a valid announce for a non-local dest while transport is enabled: learn the path AND enqueue a re-announce on all OTHER interfaces with `hops + 1`, respecting the hop limit (`PATHFINDER_M`, read from RNS). De-duplicate via the announce `random_hash` (keep a seen-set with expiry).

- [ ] TDD: node with transport on, two interfaces; inbound announce on iface 0 → path learned + re-announce enqueued on iface 1 with hops incremented; duplicate announce (same random_hash) not re-propagated. Commit.

### Task M2.4: Packet forwarding to next hop

**Files:** Modify `crates/reticulum-node/src/node.rs`, tests inline.

**Interfaces:** In `handle_inbound`, when a DATA/other packet's `dest_hash` is NOT local but IS in the path table and transport is enabled: rewrite as HEADER_2 toward the next hop (set `transport_id`), decrement/track hops, drop if hops exceed limit, and enqueue on the path's interface. Emit no `Message` event (we're a relay). Non-routable + non-local → drop.

- [ ] TDD: relay node knows a path to dest D via iface 2; inbound DATA for D on iface 0 → forwarded on iface 2 as HEADER_2, plaintext never decrypted (relay has no key). Commit.

### Task M2.5: Path requests

**Files:** Modify `crates/reticulum-node/src/node.rs` + a `path_request` helper in core, tests inline.

**Interfaces:** Implement RNS `PATH_REQUEST` (read `Transport.py`): `Node::request_path(dest_hash)` enqueues a path-request packet; on receiving a path request for a dest we have a path to (or are), respond with an announce. Confirm the path-request packet format against a captured vector `vectors/path_request.json`.

- [ ] TDD: node A requests path for D; node B (knows D) receives request → emits announce for D. Commit.

### Task M2.6: Transport driver wiring + multi-interface driver

**Files:** Modify `crates/reticulum-tokio/src/driver.rs` (support N interfaces, `SystemClock`), `crates/reticulum-cli` (config: `transport_enabled`, multiple TCP peers).

- [ ] TDD: driver-level test with 3 in-process drivers in a line (A—B—C over two loopback TCP pairs); A announces, C learns path via B; A sends message to C, C decrypts. Commit.

### Task M2.7: Live 3-node interop gate (Milestone 2 gate)

**Files:** `tools/interop/run_transport_interop.sh`, updated interop README.

- [ ] Stand up: Python RNS node ── Rust relay (transport on) ── Python or Rust endpoint. Prove an encrypted message crosses the Rust relay in both directions, and the relay never sees plaintext. Confirm with `rnpath` showing the multi-hop path. Capture evidence. Commit.

**M2 acceptance:** all workspace tests green, clippy clean, no_std cross-compile green, `run_transport_interop.sh` exits 0 with a message delivered across the relay. HEADER_2 carry-forward closed.

---

# MILESTONE 3 — Links — TASK OUTLINE (expand to full TDD before building)

**Goal:** Full RNS Link lifecycle: an initiator establishes an encrypted, authenticated session to a destination; both sides exchange link-encrypted packets; keepalive + teardown. Acceptance: Rust establishes a Link to a Python RNS destination and exchanges a request/response, and vice-versa.

**Read first:** `RNS/Link.py` (LINKREQUEST payload, ECDH with the destination + ephemeral keys, HKDF link key derivation, link id, PROOF, `RTT`, keepalive, `ECPUBSIZE`), `RNS/Packet.py` (LINKREQUEST/PROOF contexts), `RNS/Destination.py` (link callbacks, `request`/`response`).

**New module:** `crates/reticulum-core/src/link.rs` (no_std) + `crates/reticulum-node` link state in `Node`.

**Tasks (each: capture vector(s) → TDD → commit):**
- **M3.1 Link key derivation** — given initiator ephemeral X25519 + destination identity, derive the shared link key + link id exactly as RNS. Vector: `vectors/link_keys.json` (deterministic ephemerals). Interface: `link::derive(initiator_eph_prv, dest_enc_pub, ...) -> LinkKeys{ link_id:[u8;16], enc_key, ... }`.
- **M3.2 LINKREQUEST build/parse** — packet_type `LINKREQUEST`, payload = initiator ephemeral pub keys. Vector `vectors/linkrequest.json`. Byte-exact.
- **M3.3 PROOF build/verify** — responder proves possession; both derive session. Vector `vectors/link_proof.json`.
- **M3.4 Link session encrypt/decrypt** — link-encrypted packets (AES/token over the link key; read RNS `Link.encrypt`/`decrypt`). Vector for a real link packet.
- **M3.5 Node link state machine** — `Node::establish_link(dest_hash) -> LinkId`; states (PENDING→ACTIVE→CLOSED); handle inbound LINKREQUEST (as destination) → send PROOF → ACTIVE; `Node::link_send(link_id, data)`; emit `Event::LinkEstablished/LinkData/LinkClosed`. Keepalive + teardown via the injected `Clock`.
- **M3.6 Requests/responses over links** — RNS `request`/`response` semantics (path IDs, response callbacks).
- **M3.7 Driver + CLI wiring** — `DriverHandle::establish_link/link_send`; CLI `link`/`request` commands.
- **M3.8 Live interop gate** — Rust↔Python link + request/response both directions; capture evidence.

**M3 acceptance:** Rust↔Python RNS link established both directions, request→response round-trips, tests+clippy+cross-compile green.

---

# MILESTONE 4 — Resources — TASK OUTLINE (expand before building)

**Goal:** Chunked/segmented transfer of arbitrary-size data over a Link, with compression and integrity, matching RNS Resource. Acceptance: transfer a multi-KB file Rust↔Python over a link.

**Read first:** `RNS/Resource.py` (segmentation, `MAPHASH`, hashmap, windowing/flow control, compression (bz2), part proofs, `SDU`).

**Tasks:**
- **M4.1** Resource hashing + segmentation (parts, map hashes) — vector-validated.
- **M4.2** Compression (RNS uses bz2 — pick a no_std-compatible bz2 or gate compression behind a std feature; confirm RNS's exact algorithm/params). Flag: if bz2 has no viable no_std crate, make Resources a std-feature-gated capability and document it.
- **M4.3** Resource advertisement + accept handshake over a link.
- **M4.4** Windowed part transfer + part proofs + retransmit.
- **M4.5** Reassembly + integrity verify + completion.
- **M4.6** Node/driver/CLI wiring (`send_resource`, `Event::ResourceProgress/ResourceComplete`).
- **M4.7** Live interop gate — file transfer Rust↔Python both directions; capture evidence.

**M4 acceptance:** multi-KB payload transfers intact Rust↔Python over a link.

---

# MILESTONE 5 — Destination types + Proofs/Receipts — TASK OUTLINE (expand before building)

**Goal:** Support GROUP (shared-key) and PLAIN (unencrypted) destinations, and delivery proofs/receipts. Acceptance: PLAIN + GROUP round-trip vs Python; a proof confirms delivery.

**Read first:** `RNS/Destination.py` (GROUP `create_keys`/`encrypt` with a shared symmetric key; PLAIN), `RNS/Packet.py` + `RNS/PacketReceipt` (proof packets, `prove()`), `RNS/Identity.py` proof validation.

**Tasks:** GROUP key mgmt + encrypt/decrypt (vector); PLAIN dest handling; proof/receipt build+verify (vector); node emits/consumes proofs; `Event::Delivered`; driver/CLI wiring; live interop gate. Commit per task.

**M5 acceptance:** PLAIN + GROUP interop vs Python; delivery proof verified both directions.

---

# MILESTONE 6 — Interfaces — TASK OUTLINE (expand before building)

**Goal:** Interface parity so the node runs over the mediums RNS supports. Acceptance: each interface passes a live/loopback interop gate.

**First introduce an interface abstraction** (Task M6.0): a common `Interface` trait in `reticulum-interface` (byte frames in/out + connect/status) that `TcpClientInterface` already fits; refactor the driver to hold `Vec<Box<dyn Interface>>` (or an enum) keyed by the `u16` interface id the node already uses. Keep no_std trait definition; std impls behind features.

**Tasks (each: read RNS `Interfaces/<X>.py`, vector/loopback TDD, live gate, commit):**
- **M6.1 TCPServerInterface** — accept inbound TCP peers (Rust as the server Python connects to).
- **M6.2 UDPInterface** — datagram framing (read RNS UDP framing; no HDLC, length-based).
- **M6.3 AutoInterface** — IPv6 link-local multicast peer discovery (std/desktop).
- **M6.4 Serial / KISS interface** — over a serial port (feature-gated; `serialport` crate in std).
- **M6.5 IFAC** — interface access codes (auth/obfuscation) layered on any interface; read `RNS/Interfaces/Interface.py` IFAC. Vector-validated (the IFAC flag already exists in our packet byte 0).
- **M6.6 (stretch) LoRa/RNODE + I2P** — hardware/overlay; specify but may defer. Document hardware needs.

**M6 acceptance:** TCP-server, UDP, and AutoInterface each interop with Python RNS on a LAN/loopback; IFAC-protected link works both directions.

---

# MILESTONE 7 — Platform reach (WASM / embedded / mobile) — TASK OUTLINE (expand before building)

**Goal:** Deliver the three targets the project committed to as real runnable nodes (beyond core just compiling for them).

**Tasks:**
- **M7.1 `reticulum-wasm`** — wasm-bindgen wrapper exposing `Node` + a WebSocket/`fetch`-based interface (browser has no raw TCP; RNS supports TCP-over-nothing in browser, so use a WS bridge or the RNS `TCPInterface` behind a WS proxy — document the bridge). Acceptance: a browser page establishes a link to a Python RNS node via a WS↔TCP bridge and exchanges a message. Runs entirely from a self-contained page where possible.
- **M7.2 `reticulum-embedded`** — a no_std example node on `thumbv7em` (or an emulator/QEMU target) using `embassy` for async + a UART/serial interface HAL. Acceptance: the embedded node announces + receives a message over serial to a host running the Rust daemon. Document hardware/QEMU setup.
- **M7.3 `reticulum-ffi`** — `uniffi`-based bindings exposing Node/Link/Resource to Kotlin (Android) + Swift (iOS). Acceptance: a minimal Android/iOS sample (or the uniffi test harness) drives a link. Document the FFI surface.

**M7 acceptance:** each platform runs a real node passing its documented gate.

---

# MILESTONE 8 — LXMF messaging + tooling parity — TASK OUTLINE (expand before building)

**Goal:** Implement LXMF (the message-format layer most Reticulum apps use) and CLI tooling parity. Acceptance: exchange an LXMF message with a Python LXMF peer; provide `rnstatus`/`rnpath`-equivalent tooling.

**Read first:** the LXMF spec + Python `LXMF` library (message structure: fields, hashing, signing, delivery via direct link / opportunistic / propagation nodes).

**Tasks:**
- **M8.1 `reticulum-lxmf` crate** — LXMF message build/parse/sign/verify (vector-validated against Python LXMF).
- **M8.2 Direct delivery** over a Link (uses M3).
- **M8.3 Opportunistic delivery** (single packet) + **propagation node** client (store-and-forward) — read LXMF propagation.
- **M8.4 CLI tooling** — `reticulum-cli` subcommands mirroring `rnstatus` (interface/path stats), `rnpath` (path table), `rnid`/`rnprobe` equivalents.
- **M8.5 Live interop gate** — send/receive an LXMF message with a Python LXMF peer both directions; capture evidence.

**M8 acceptance:** LXMF message round-trips with Python LXMF; tooling reports node state.

---

## Cross-milestone verification (run at every milestone boundary)

- `cargo test --workspace` — all green.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo build -p reticulum-core -p reticulum-interface -p reticulum-node [ + any new no_std crate] --target wasm32-unknown-unknown` and `--target thumbv7em-none-eabihf` — green.
- `cargo fmt --all -- --check` — clean.
- The milestone's live interop gate script — exits 0 with captured evidence committed under `tools/interop/`.
- Update `docs/superpowers/` with the milestone's expanded plan (M3–M8) before building it.

## Self-Review (of this master plan)

**Coverage vs "everything remaining":** Transport (M2), Links (M3), Resources (M4), GROUP/PLAIN + proofs (M5), all interfaces incl. TCP-server/UDP/Auto/Serial/IFAC + LoRa/I2P stretch (M6), WASM + embedded + mobile FFI (M7), LXMF + tooling (M8). All items from the "what's left" list are placed in a milestone.

**Decomposition rationale (explicit):** later milestones are outlines, not full TDD, ON PURPOSE — their exact code depends on APIs M2/M3 introduce (Link keys, Resource parts, interface trait) that do not exist yet; specifying line-by-line code now would be fiction. The protocol mandates expanding each to full TDD (via the writing-plans method) at build time. M2 is full-detail because it builds on today's real APIs.

**Placeholder scan:** no TBD/TODO. "Read RNS source / capture vector / confirm layout" are mandatory verification steps with an authoritative oracle (RNS 1.4.1), consistent with how M1 was proven — not deferred work.

**Risk flags:** bz2 compression may lack a no_std crate (M4.2 — may become std-feature-gated); browser lacks raw TCP (M7.1 — needs a WS↔TCP bridge, documented); LoRa/I2P need hardware/overlay (M6.6 — may defer). Each is called out at its task.

**Consistency:** the injected `Clock` trait (M2.1) is used by all time-dependent logic (path expiry, link keepalive, resource windows, LXMF) to keep core/node sans-I/O and testable — no `std::time` in the no_std crates.
