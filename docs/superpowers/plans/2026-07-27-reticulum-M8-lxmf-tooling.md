# Reticulum Rust Port — Milestone 8: LXMF messaging + tooling parity (full TDD)

> **For Codex:** Full TDD plan expanding M8 from the master program plan — the final milestone. Execute task-by-task, in order; each ends green with a commit. Every LXMF wire detail is confirmed against a captured vector from Python **LXMF 1.1.0** (`.venv/.../LXMF/`) and/or live interop with a Python LXMF peer — never guessed. Stop for review at the milestone gate (Task M8.9).

**Goal:** Implement LXMF (the message-format + routing layer most Reticulum apps use) and CLI tooling parity (`rnstatus`/`rnpath`-equivalents). **Acceptance:** exchange an LXMF message with a Python LXMF 1.1.0 peer both directions (direct-over-link and opportunistic), and provide tooling that reports node/path state (`tools/interop/run_lxmf_interop.sh` exits 0 with captured evidence).

## LXMF 1.1.0 facts (from source — authoritative, still vector-verify)

- **Lengths:** `DESTINATION_LENGTH = TRUNCATED_HASHLENGTH/8 = 16`, `SIGNATURE_LENGTH = SIGLENGTH/8 = 64`, `TIMESTAMP_SIZE = 8` (double). msgpack via RNS's umsgpack.
- **Payload:** `payload = [timestamp(float), title(bytes), content(bytes), fields(map)]` → `msgpack.packb(payload)`.
- **Hash / message_id:** `hashed_part = destination.hash(16) ‖ source.hash(16) ‖ msgpack(payload)`; `hash = full_hash(hashed_part)` (32 bytes) = `message_id`.
- **Signature:** `signed_part = hashed_part ‖ hash`; `signature = source_identity.sign(signed_part)` (64 bytes).
- **Packed (wire) form:** `packed = destination.hash(16) ‖ source.hash(16) ‖ signature(64) ‖ msgpack(payload)`. `unpack_from_bytes` reverses: `dest=bytes[0:16]`, `source=bytes[16:32]`, `signature=bytes[32:96]`, `payload=msgpack.unpackb(bytes[96:])`.
- **Delivery destination:** a SINGLE destination with app_name `"lxmf"`, aspect `"delivery"` (the recipient's LXMF address). Confirm the exact aspects from `LXMF.py`/`LXMRouter.py`.
- **Delivery methods:**
  - **Direct over a Link (M3):** open a link to the delivery destination; send `packed[DESTINATION_LENGTH:]` (i.e. strip the leading 16-byte dest hash, since the link already addresses the destination) as link data.
  - **Opportunistic (single packet):** a single `DATA` packet to the delivery destination carrying the LXMF payload (the destination hash prefix is the packet's dest_hash).
  - **Propagation node (store-and-forward):** `propagation_packed = msgpack([timestamp, [lxmf_data]])` where `lxmf_data = packed[:16] ‖ destination.encrypt(packed[16:])`. Client uploads to a propagation node; recipient later downloads. Larger scope — see M8.6 (basic client, may be marked partial).
- **Stamps (spam mitigation, `LXStamper.py`):** optional proof-of-work (`stamp_cost`). NOT required for basic delivery — implement stamp VERIFICATION as optional and stamp GENERATION as a deferred sub-task (M8.7); a message without a stamp is still deliverable when the peer's `stamp_cost` is 0/unset.
- **Fields:** LXMF `fields` is a msgpack map of typed fields (e.g. attachments, telemetry). For M8, support arbitrary `fields` pass-through (encode/decode the map) without interpreting each field type.

---

## File structure

```
crates/reticulum-lxmf/          NEW no_std + alloc crate
  Cargo.toml                    deps: reticulum-core, reticulum-node, rmp
  src/lib.rs
  src/message.rs                LxmfMessage: pack/unpack/sign/verify, message_id
  src/router.rs                 delivery routing (direct/opportunistic) over a Node
  tests/vectors.rs
crates/reticulum-cli/           tooling subcommands (status/path/lxmf send/recv)
tools/
  capture_vectors.py            + lxmf_message.json
  interop/run_lxmf_interop.sh, lxmf_peer.py
vectors/ lxmf_message.json      NEW
```

## Global constraints (inherited)

Target RNS 1.4.1 + LXMF 1.1.0. `reticulum-lxmf` is `no_std + alloc`, cross-compiles to wasm32 + thumbv7em. Sans-I/O (randomness via `EntropySource`, time via `Clock` — LXMF timestamp is injected, not `std::time`). No panics on untrusted input. TDD + vector-driven. Commit per task.

---

### Task M8.1: `reticulum-lxmf` crate + LxmfMessage pack/sign

**Files:** `crates/reticulum-lxmf/Cargo.toml`, `src/lib.rs`, `src/message.rs`, tests.

**Interfaces:**
- `pub struct LxmfMessage { pub destination: [u8;16], pub source: [u8;16], pub timestamp: f64, pub title: Vec<u8>, pub content: Vec<u8>, pub fields: Vec<u8> /* raw msgpack map bytes */, pub signature: [u8;64], pub hash: [u8;32] }`
- `pub fn build(source_identity: &Identity, destination: [u8;16], source: [u8;16], timestamp: f64, title: &[u8], content: &[u8], fields_msgpack: &[u8]) -> LxmfMessage` — compute payload msgpack, `hashed_part`, `hash`, `signed_part`, `signature`.
- `pub fn pack(&self) -> Vec<u8>` — `dest(16) ‖ source(16) ‖ signature(64) ‖ payload_msgpack`.

- [ ] **Step 1:** `capture_vectors.py` → `lxmf_message.json`: build a Python `LXMessage` with fixed source identity, fixed dest/source hashes, fixed timestamp/title/content/fields; record `{ source_prv_x/ed, destination(16), source(16), timestamp, title, content, fields_msgpack, packed_hex, hash(32), signature(64) }`.
- [ ] **Step 2:** Failing tests: `build(...).hash == vector.hash`, `.signature == vector.signature`, `pack() == vector.packed_hex` (byte-exact — msgpack payload determinism: build the payload array `[timestamp,title,content,fields]` with the SAME field encoding RNS uses; if bytes differ, reconcile the msgpack encoding of the payload against umsgpack).
- [ ] **Step 3–4:** Add crate (+ CI wasm32/thumbv7em jobs); implement; run (pass); clippy; cross-compile. Commit `feat(lxmf): LXMF message build, pack, sign`.

### Task M8.2: LxmfMessage unpack + verify

**Files:** `crates/reticulum-lxmf/src/message.rs`, tests.

**Interfaces:** `pub fn unpack(bytes: &[u8]) -> Result<LxmfMessage, CoreError>` (reverse of pack; recompute hash; length-checked, no panic). `pub fn verify(&self, source_public: &PublicIdentity) -> Result<(), CoreError>` — recompute `hashed_part`+`hash`, check `hash == self.hash`, verify `signature` over `hashed_part ‖ hash` with `source_public`.

- [ ] TDD: `unpack(vector.packed_hex)` yields the recorded fields + hash; `verify` succeeds with the correct source public key and fails on a tampered payload/signature. Commit `feat(lxmf): LXMF message unpack + signature verification`.

### Task M8.3: LXMF delivery destination + router (direct over link)

**Files:** `crates/reticulum-lxmf/src/router.rs`, tests.

**Interfaces:** helper to compute an LXMF delivery destination hash for an identity (`app="lxmf"`, aspects per source — confirm). `LxmfRouter` that, given a `Node` + an established link (M3) to the delivery destination, sends `pack()[16:]` as link data; and on inbound link data reconstructs the LXMF message (prepend the known destination hash) → `unpack` + `verify` → emit an `LxmfEvent::Message`.

- [ ] TDD (two in-memory nodes with a link, reusing M3 setup): node A builds+sends an LXMF message to node B over a link; B unpacks+verifies and surfaces the title/content/fields. Commit `feat(lxmf): direct LXMF delivery over a link`.

### Task M8.4: Opportunistic delivery (single packet)

**Files:** `crates/reticulum-lxmf/src/router.rs`, `crates/reticulum-node` glue if needed, tests.

**Interfaces:** send an LXMF message as a single `DATA` packet to the delivery destination (the full `packed` rides the packet, addressed by the destination hash); inbound path recognizes an LXMF delivery packet, unpacks+verifies, emits the message.

- [ ] TDD: A sends opportunistic LXMF to B (direct path pre-seeded) → B surfaces the message. Commit `feat(lxmf): opportunistic single-packet LXMF delivery`.

### Task M8.5: Node/driver/CLI LXMF integration

**Files:** `crates/reticulum-node` (LXMF event surface), `reticulum-tokio` driver, `reticulum-cli`, tests.

**Interfaces:** driver commands `lxmf_send_direct(dest, title, content, fields)` / `lxmf_send_opportunistic(...)`; surface inbound LXMF messages as events; CLI `lxmf send <dest_hash> <title> <content> [--direct|--opportunistic]` and `lxmf recv` (print inbound). Reuse the M3 link machinery for direct.

- [ ] TDD: driver-level over loopback TCP — an LXMF message delivered both direct and opportunistic; recipient prints title+content. Commit `feat(cli): LXMF send/receive (direct + opportunistic)`.

### Task M8.6: Propagation-node client (store-and-forward, basic)

**Files:** `crates/reticulum-lxmf/src/router.rs`, tests.

**Interfaces:** `propagation_packed = msgpack([timestamp, [lxmf_data]])`, `lxmf_data = packed[:16] ‖ destination_encrypt(packed[16:])`. Implement: upload a message to a propagation node (a SINGLE destination with the LXMF propagation aspect) and download queued messages for our delivery destination. Read `LXMRouter.py` for the propagation request/response protocol.

- [ ] TDD + partial gate: build/parse `propagation_packed`; upload to a Python LXMF propagation node and have it accept; download our messages. If the full propagation handshake is too large for M8, deliver upload-side + parsing and mark download/sync as a documented follow-up. Commit `feat(lxmf): propagation-node upload (+ download or documented follow-up)`.

### Task M8.7: Stamps (optional PoW) — verification now, generation deferred

**Files:** `crates/reticulum-lxmf/src/stamp.rs`, tests.

- [ ] Implement stamp VERIFICATION (`stamp == truncated_hash(ticket ‖ message_id)` / workblock check — read `LXStamper.py`) so we can validate stamped inbound messages. Stamp GENERATION (the PoW search) is a deferred sub-task — a message with no stamp is deliverable to peers with `stamp_cost = 0`. TDD: verify a captured stamped message; unstamped messages pass when stamp_cost is unset. Commit `feat(lxmf): stamp verification (generation deferred)`.

### Task M8.8: Tooling parity (rnstatus / rnpath equivalents)

**Files:** `crates/reticulum-cli/src/main.rs` + a `status` module, tests.

**Interfaces:** CLI subcommands: `status` (interfaces + their state + counters, mirroring `rnstatus`), `path [dest_hash]` (path table entries + hops, mirroring `rnpath`), `identity` (show/create identity hash), and `probe <dest_hash>` (send a path request + report). These read node/driver state (add read-only accessors to `Node`: `paths_snapshot()`, `interfaces_snapshot()`).

- [ ] TDD: unit-test the formatting given a node with seeded paths/interfaces; `status`/`path` render the expected lines. Commit `feat(cli): rnstatus/rnpath-equivalent tooling`.

### Task M8.9: Live LXMF interop gate (Milestone 8 gate — project completion)

**Files:** `tools/interop/lxmf_peer.py`, `run_lxmf_interop.sh`, README.

- [ ] `lxmf_peer.py`: a Python **LXMF 1.1.0** program (using `import LXMF`) that runs an `LXMRouter`, registers a delivery destination, sends an LXMF message to a given destination, and prints received LXMF messages (title/content/fields).
- [ ] `run_lxmf_interop.sh`:
  - **Rust→Python (direct-over-link):** Rust sends an LXMF message to the Python LXMF delivery destination over a link; Python's router surfaces the exact title+content.
  - **Python→Rust (opportunistic and/or direct):** Python LXMF sends to the Rust delivery destination; Rust unpacks+verifies and prints the exact title+content.
  - Exit 0 only if both directions match; capture evidence.
- [ ] Run it; capture evidence in README. Commit `test(interop): live Rust<->Python LXMF message exchange`.

> If exchange fails: diff the packed LXMF bytes against `lxmf_message.json` for the same inputs. Common culprits: payload msgpack encoding (float timestamp, field map), the `hashed_part`/`signed_part` composition, or the delivery destination aspects.

**M8 acceptance:** `cargo test --workspace` green; clippy `-D warnings` clean; no_std cross-compile (lxmf default features) green; `run_lxmf_interop.sh` exits 0 (LXMF both directions) with committed evidence. **This completes the Reticulum parity roadmap (M1–M8).**

---

## Self-Review

**Coverage vs M8 outline:** LXMF message build/pack/sign (M8.1), unpack/verify (M8.2), direct-over-link delivery (M8.3), opportunistic delivery (M8.4), node/driver/CLI integration (M8.5), propagation-node client (M8.6, basic/partial allowed), stamps (M8.7, verify now / generate deferred), tooling parity rnstatus/rnpath (M8.8), live LXMF interop (M8.9).

**Placeholder scan:** none. Payload msgpack encoding, delivery-destination aspects, propagation protocol, and stamp workblock are marked "confirm from LXMF source / capture vector" with an oracle. Propagation download and stamp generation are explicitly scoped as documented follow-ups (not silent gaps) since each is a substantial sub-protocol.

**Type consistency:** `LxmfMessage` (build/pack/unpack/verify), `LxmfRouter`, and the delivery-destination helper are named consistently across the crate → node → cli. LXMF reuses `Identity::sign`/`PublicIdentity::verify`, `full_hash`, `rmp` msgpack (from M4), the M3 link machinery (direct delivery), and the M5 delivery-destination/proof concepts — no new crypto.

**Reuse (DRY):** LXMF is a pure message-format + routing layer on top of M1–M5 (identity, links, single/plain destinations) — it adds no cryptographic primitive; only message packing, signing over the existing hash, and routing.

**Risk:** two sub-protocols are large — propagation-node sync (M8.6) and stamp generation (M8.7). Both are scoped so basic LXMF delivery (the acceptance gate) does not depend on them: the live gate uses direct + opportunistic delivery, which are fully specified. Propagation/stamps can complete as follow-ups without blocking M8 acceptance.
