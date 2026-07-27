# Reticulum Rust Port — Milestone 5: Destination types (GROUP/PLAIN) + Proofs/Receipts (full TDD)

> **For Codex:** Full TDD plan expanding M5 from the master program plan. Execute task-by-task, in order; each ends green with a commit. Fail-first every test. Every wire detail is confirmed against a captured RNS 1.4.1 vector and/or the RNS source (`Destination.py`, `Packet.py`, `Identity.py`) — never guessed. Stop for review at the milestone gate (Task M5.8).

**Goal:** Support GROUP (shared symmetric key) and PLAIN (unencrypted) destinations, and explicit delivery proofs/receipts. **Acceptance:** PLAIN and GROUP messages round-trip Rust↔Python RNS 1.4.1, and a delivery proof confirms a message both directions (`tools/interop/run_desttypes_interop.sh` exits 0 with captured evidence).

## RNS 1.4.1 facts (from source — authoritative, still vector-verify)

- **Destination types** (`Destination.py:63-66`): `SINGLE = 0x00`, `GROUP = 0x01`, `PLAIN = 0x02`, `LINK = 0x03`. (Our `packet.rs` already has SINGLE/PLAIN/LINK; add `GROUP = 0x01`.)
- **GROUP** (`create_keys`): symmetric key `prv_bytes = Token.generate_key()`; `encrypt/decrypt` use `Token(prv_bytes)` — the SAME keyed Token as links. So GROUP crypto REUSES M3's `token::{seal_with_key, open_with_key}` with the shared group key. Confirm the group key LENGTH from `Token.generate_key()` (AES256 ⇒ 64 bytes = HMAC[0:32]‖AES[32:64], matching `seal_with_key`'s `[u8;64]`). The group key is shared out-of-band (both peers load the same key).
- **GROUP destination hash:** derived from the destination NAME (app_name + aspects), no identity. Read `Destination.__init__`/`hash` for the exact input to the hash for GROUP type (likely `truncated_hash(name_hash)` or `destination_hash(name_hash, <something>)`). Vector-verify.
- **PLAIN** (`type = 0x02`): holds no keys; `data` is sent as cleartext. Packets use `dest_type = PLAIN`. (We already send PLAIN path-requests, so the packet path exists.)
- **Explicit proofs** (`Identity.prove`, `PacketReceipt.validate_proof`): `EXPL_LENGTH = HASHLENGTH/8 + SIGLENGTH/8 = 16 + 64 = 80`. Proof data = `packet_hash(16) ‖ signature(64)` where `signature = destination_identity.sign(packet_hash)` and `packet_hash` = our `Packet::packet_hash()` (truncated full hash, 16 bytes — already implemented and used for dedup). Sent as a `PROOF` packet to the packet's ProofDestination.
- **ProofDestination:** the proof is addressed to `generate_proof_destination()` = `ProofDestination(packet)`. Read `Destination.py` for `ProofDestination.hash` (it is derived from the original packet's `packet_hash` so both sides compute the same routing address). Vector-verify the exact derivation.
- **Proof strategy** (`Destination.py`): `PROVE_NONE` (default), `PROVE_ALL`, `PROVE_APP`. Proofs are OPT-IN — a destination only replies with a proof if its strategy is `PROVE_ALL` (or `PROVE_APP` + callback returns true). For interop, both peers set `PROVE_ALL`.
- **Validate (sender side):** on receiving a PROOF, split `proof_hash = data[0:16]`, `signature = data[16:80]`; if `proof_hash == the packet_hash of a packet we sent (and are awaiting proof for)` and `destination_identity.verify(proof_hash, signature)` succeeds → DELIVERED.

---

## File structure

```
crates/reticulum-core/src/
  packet.rs      + GROUP dest_type const; proof packet constructor; ProofDestination hash helper
  destination.rs + group_destination_hash(...) (confirm derivation from source/vector)
  proof.rs       NEW: build_proof(identity, packet_hash) -> Vec<u8>; verify_proof(dest_pub, proof) -> Result<[u8;16] /*proved hash*/>
  lib.rs         + pub mod proof;
  tests/vectors.rs
crates/reticulum-node/src/
  node.rs        + register_group_destination(key)/register_plain_destination; GROUP encrypt/decrypt on send/recv;
                   PLAIN send/recv; proof strategy per local dest; receipt tracking + proof emit/validate; tick integration
  lib.rs         + Event::{Delivered{packet_hash}, ProofRequested?} (Delivered required)
crates/reticulum-tokio/  driver: send with-receipt, surface Delivered
crates/reticulum-cli/    subcommands: send-plain, send-group, and proof-on flag
tools/
  capture_vectors.py     + group_destination.json, proof.json, proof_destination.json
  interop/run_desttypes_interop.sh, desttypes_peer.py
vectors/
  group_destination.json, proof.json, proof_destination.json   NEW
```

## Global constraints (inherited)

Target RNS 1.4.1; core/node stay `no_std + alloc` and cross-compile to wasm32 + thumbv7em; sans-I/O (randomness via `EntropySource`, time via `Clock`); no panics on untrusted input; TDD + vector-driven; commit per task.

---

### Task M5.1: GROUP dest_type + destination hash

**Files:** `crates/reticulum-core/src/packet.rs` (add `GROUP = 0x01`), `src/destination.rs`, `capture_vectors.py`, `vectors/group_destination.json`, tests.

**Interfaces:** `pub fn group_destination_hash(app_name: &str, aspects: &[&str]) -> [u8;16]` (match RNS GROUP hashing — read `Destination` hash code; vector-verify).

- [ ] **Step 1:** `capture_vectors.py` → `group_destination.json`: build an RNS GROUP destination with fixed name; record `{ app_name, aspects, dest_hash(16), group_key(hex) }` (the `Token.generate_key()` bytes; monkeypatch to a fixed key for determinism).
- [ ] **Step 2:** Failing test: `group_destination_hash(app, aspects) == vector.dest_hash`.
- [ ] **Step 3–4:** Add `GROUP` const; implement; run (pass); clippy; cross-compile. If mismatch, read the exact GROUP hash input in `Destination.py`. Commit `feat(core): GROUP destination type + hashing`.

### Task M5.2: GROUP encryption via keyed Token (node)

**Files:** `crates/reticulum-node/src/node.rs`, tests.

**Interfaces:** `Node::register_group_destination(app_name, aspects, group_key: [u8;64]) -> [u8;16]` (stores a local GROUP dest with its shared key). `Node::send_group_message<R>(dest_hash, plaintext, rng)` → `seal_with_key(group_key, plaintext, iv)` in a `Packet::data` with `dest_type = GROUP`; inbound DATA with `dest_type == GROUP` to a known group dest → `open_with_key(group_key, data)` → `Event::Message`.

- [ ] TDD (two in-memory nodes sharing a group key): node A `send_group_message` → node B (same group key registered) decrypts → `Event::Message` with the plaintext; wrong key → decrypt error, no message. Commit `feat(node): GROUP destination encrypt/decrypt via keyed Token`.

### Task M5.3: PLAIN destinations (node)

**Files:** `crates/reticulum-node/src/node.rs`, tests.

**Interfaces:** `Node::register_plain_destination(app_name, aspects) -> [u8;16]`; `Node::send_plain_message(dest_hash, data)` → `Packet::data` with `dest_type = PLAIN`, `data = plaintext` (no crypto); inbound DATA with `dest_type == PLAIN` to a known plain dest → `Event::Message{plaintext = data}` (cleartext). Guard: never attempt token decrypt on PLAIN.

- [ ] TDD: A `send_plain_message` → B receives `Event::Message` with the exact cleartext bytes; a PLAIN packet's data is not treated as ciphertext. Commit `feat(node): PLAIN destination send/receive`.

### Task M5.4: Proof build + verify (core)

**Files:** `crates/reticulum-core/src/proof.rs`, `src/lib.rs`, `capture_vectors.py`, `vectors/proof.json`, tests.

**Interfaces:**
- `pub fn build_proof(identity: &Identity, packet_hash: &[u8;16]) -> Vec<u8>` = `packet_hash ‖ identity.sign(packet_hash)` (80 bytes).
- `pub fn verify_proof(destination_public: &PublicIdentity, proof: &[u8]) -> Result<[u8;16], CoreError>` — require `len == 80`; `proof_hash = proof[0:16]`, `signature = proof[16:80]`; `destination_public.verify(proof_hash, signature)`; return `proof_hash` on success, else `BadSignature`/`Truncated`.

- [ ] **Step 1:** `vectors/proof.json`: fixed identity + a fixed `packet_hash`; RNS `identity.prove`-equivalent → record `{ dest_prv_x/ed, packet_hash(16), proof_data(80), dest_pub(64) }`.
- [ ] **Step 2:** Failing tests: `build_proof(id, packet_hash) == vector.proof_data`; `verify_proof(dest_pub, proof_data) == Ok(packet_hash)`; tampered signature → `Err`.
- [ ] **Step 3–4:** Implement; run (pass); clippy; cross-compile. Commit `feat(core): explicit delivery proof build + verify`.

### Task M5.5: ProofDestination addressing

**Files:** `crates/reticulum-core/src/packet.rs` (or `proof.rs`), `capture_vectors.py`, `vectors/proof_destination.json`, tests.

**Interfaces:** `pub fn proof_destination_hash(packet_hash: &[u8;16]) -> [u8;16]` (the routing address a proof is sent to; both sender and receiver derive it from the original packet's `packet_hash`). Read `ProofDestination` in `Destination.py` for the exact derivation.

- [ ] **Step 1:** `vectors/proof_destination.json`: for a fixed packet, record `{ packet_hash(16), proof_destination_hash(16) }`.
- [ ] **Step 2:** Failing test: `proof_destination_hash(packet_hash) == vector.proof_destination_hash`.
- [ ] **Step 3–4:** Implement; run (pass). Commit `feat(core): proof destination address derivation`.

### Task M5.6: Node proof lifecycle (receipts + emit + validate)

**Files:** `crates/reticulum-node/src/node.rs`, `src/lib.rs`, tests.

**Interfaces:**
- Per local SINGLE destination: a proof strategy flag (`set_prove(dest_hash, bool)` — default off = PROVE_NONE). When a DATA packet is successfully received+decrypted for a local dest whose strategy is on, build a proof (`build_proof(identity, packet.packet_hash())`) and enqueue it as a `PROOF` packet addressed to `proof_destination_hash(packet_hash)` (route via the path table / reverse of arrival interface).
- Sender receipts: `Node::send_message_with_receipt<R>(dest_hash, plaintext, rng) -> Result<[u8;16] /*packet_hash awaited*/>` records `(packet_hash → pending, expires via Clock)`. On inbound `PROOF` packet whose data verifies via `verify_proof(dest_pub, data)` and whose returned hash matches a pending receipt → remove it and emit `Event::Delivered{packet_hash}`.
- Add `Event::Delivered{packet_hash:[u8;16]}`. Expire unproven receipts in `tick()`.

- [ ] **Step 1:** TDD (two in-memory nodes, path pre-seeded): receiver sets prove on its dest; sender `send_message_with_receipt` → receiver `handle_inbound` emits `Message` AND enqueues a PROOF; sender `handle_inbound(proof)` emits `Delivered{packet_hash}` matching the sent hash. Also: a receiver with prove OFF sends no proof (no Delivered).
- [ ] **Step 2–4:** Implement; run (pass); `cargo test --workspace`; clippy; cross-compile. Commit `feat(node): delivery proof lifecycle (receipts, emit, validate)`.

### Task M5.7: Driver + CLI wiring

**Files:** `crates/reticulum-tokio/src/driver.rs`, `crates/reticulum-cli/src/main.rs` + `config.rs`, tests.

- [ ] `DriverHandle::{send_group, send_plain, send_with_receipt}`; surface `Delivered`. CLI: `send-plain <dest> <text>`, `send-group <dest> <text>` (group key from config/env), and a `--prove` flag / config for local dests. Driver-level test over loopback TCP: a proved SINGLE message yields a `Delivered` event; a GROUP and a PLAIN message round-trip. Commit `feat(tokio,cli): GROUP/PLAIN sends + delivery receipts`.

### Task M5.8: Live interop gate (Milestone 5 gate)

**Files:** `tools/interop/desttypes_peer.py`, `run_desttypes_interop.sh`, README.

- [ ] `desttypes_peer.py`: RNS program supporting: a PLAIN destination (echo cleartext), a GROUP destination with a shared key (loaded from a fixed hex), and a SINGLE destination with `PROVE_ALL` (so it proves inbound), plus a sender mode that requests a receipt and reports delivery.
- [ ] `run_desttypes_interop.sh`:
  - **PLAIN both directions:** Rust↔Python PLAIN message round-trips (assert cleartext).
  - **GROUP both directions:** Rust and Python load the same group key; a GROUP message decrypts on the other side (assert plaintext).
  - **Proof both directions:** Rust sends a proved message to a Python `PROVE_ALL` SINGLE dest and gets `Delivered`; Python sends to a Rust `PROVE_ALL` dest and RNS reports delivery.
  - Exit 0 only if all pass; capture evidence.
- [ ] Run it; capture evidence in README. Commit `test(interop): live Rust<->Python GROUP/PLAIN + delivery proofs`.

> If a case fails: diff against the relevant vector (group dest hash, proof bytes, proof destination hash). Common culprits: GROUP hash input, group key length, proof signature message (must be the 16-byte packet_hash), or the proof destination derivation.

**M5 acceptance:** `cargo test --workspace` green; clippy `-D warnings` clean; no_std cross-compile green; `run_desttypes_interop.sh` exits 0 (PLAIN + GROUP + proofs, both directions) with committed evidence.

---

## Self-Review

**Coverage vs M5 outline:** GROUP key mgmt + encrypt/decrypt (M5.1/M5.2, reusing M3 keyed Token), PLAIN handling (M5.3), proof/receipt build+verify (M5.4/M5.5), node emits/consumes proofs + `Delivered` (M5.6), driver/CLI (M5.7), live interop (M5.8).

**Placeholder scan:** none. GROUP destination hash input, group key length, and ProofDestination derivation are marked "confirm from source" with captured vectors as the oracle — verification steps, not deferred work.

**Type consistency:** `group_destination_hash`, `register_group_destination`/`register_plain_destination`, `build_proof`/`verify_proof`, `proof_destination_hash`, `send_message_with_receipt`, and `Event::{Message, Delivered}` are named consistently core→node→driver→cli. GROUP crypto reuses `seal_with_key`/`open_with_key` (M3); proof signing reuses `Identity::sign`/`PublicIdentity::verify`; `packet_hash()` reuses the M2 dedup hash.

**Reuse (DRY):** no new crypto primitives — GROUP is the keyed Token, proofs are Ed25519 sign/verify over the existing packet hash. Only new logic is destination-type routing + receipt bookkeeping.

**Risk:** proof addressing (ProofDestination) is the one routing-sensitive derivation — M5.5 pins it to a vector before the node lifecycle (M5.6) depends on it. Proofs are opt-in (PROVE strategy), so default behavior is unchanged for existing SINGLE messaging.
