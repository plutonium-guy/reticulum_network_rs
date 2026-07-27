# Reticulum Rust Port — Milestone 3: Links (full TDD)

> **For Codex:** Full TDD plan expanding M3 from the master program plan. Execute task-by-task, in order; each ends green with a commit. Fail-first every test. Every wire detail is confirmed against a captured RNS 1.4.1 vector and/or the RNS source in `.venv/lib/python3.14/site-packages/RNS/` — never guessed. Stop for review at the milestone gate (Task M3.9).

**Goal:** Implement the RNS Link lifecycle: an initiator establishes an encrypted, authenticated session (Link) to a destination via LINKREQUEST → PROOF, both sides exchange link-encrypted packets, with keepalive + teardown. **Acceptance:** Rust establishes a Link to a Python RNS 1.4.1 destination and exchanges data both ways, and a Python RNS node establishes a Link to a Rust destination and exchanges data both ways (`tools/interop/run_link_interop.sh` exits 0 with captured evidence).

## RNS 1.4.1 facts (from source — treat as authoritative, still vector-verify)

- **Mode:** `MODE_AES256_CBC = 0x01` is default/only enabled mode. `derived_key_length = 64`.
- **Link crypto = keyed Token.** RNS `Link.encrypt/decrypt` uses `Token(self.derived_key)` — the SAME Token/Fernet primitive as identity encryption BUT with a fixed 64-byte derived key and NO ephemeral-pubkey prefix. Layout: `iv(16) ‖ AES256-CBC(pkcs7) ‖ HMAC-SHA256(32)`; the 64-byte key splits as `hmac_key = key[0:32]`, `aes_key = key[32:64]` (identical split to our existing `token.rs`). This differs from our current `token::{encrypt,decrypt}` (which prepend an ephemeral X25519 pub and do per-message ECDH). M3 must add a raw-keyed entry point.
- **Link ephemeral keys:** each side generates a fresh X25519 keypair (`pub_bytes`, 32B) AND a fresh Ed25519 keypair (`sig_pub_bytes`, 32B) for the link. `ECPUBSIZE = 64` (32+32).
- **LINKREQUEST payload** (`request_data`): `initiator_x25519_pub(32) ‖ initiator_ed25519_pub(32) ‖ [signalling_bytes(3)]`. Sent as `packet_type = LINKREQUEST (0x02)` to the destination. Signalling (MTU/mode) is OPTIONAL — for M3, DO NOT send signalling bytes (omit them; RNS handles a 64-byte LR). Confirm RNS accepts a 64-byte LINKREQUEST (it does: `validate_request` checks `len(data) == ECPUBSIZE`).
- **link_id** = `truncated_hash(packet.get_hashable_part())` of the LINKREQUEST packet (trimmed of any signalling diff beyond ECPUBSIZE). `get_hashable_part()` is the same hashable region used by `packet_hash` (dest_type+packet_type byte ‖ dest_hash ‖ context ‖ data). Vector-verify.
- **handshake:** `shared_key = X25519(own_link_prv, peer_link_pub)`; `derived_key = HKDF-SHA256(length=64, ikm=shared_key, salt=link_id, info=None/empty)`.
- **prove (responder):** `signed = link_id ‖ responder_x25519_pub ‖ responder_ed25519_pub [‖ signalling]`; `signature = destination_identity.sign(signed)` (signs with the DESTINATION's long-term Ed25519 identity key, proving destination ownership). `proof_data = signature(64) ‖ responder_x25519_pub(32) [‖ signalling(3)]`. Sent as `packet_type = PROOF (0x03)`, `context = LRPROOF (0xFF)`, addressed to the link.
- **validate_proof (initiator):** extract `signature = data[0:64]`, `peer_x25519_pub = data[64:96]`; `peer_ed25519_pub = destination.identity.ed25519_pub` (the initiator already knows the destination identity from its announce); `load_peer` + `handshake`; verify `destination_identity.verify(signed = link_id ‖ peer_x25519_pub ‖ peer_ed25519_pub [‖ signalling], signature)`. On success → ACTIVE; RNS then sends an `LRRTT (0xFE)` packet (RTT measurement) — for M3 we may send an empty/minimal LRRTT or skip it; confirm the Python side does not require it to consider the link active (it does not gate ACTIVE on receiving LRRTT).
- **Link data packets:** `packet_type = DATA`, addressed with the `link_id` as the destination hash and the LINK destination type. The numeric `dest_type` for LINK is NOT SINGLE — measure it from a captured link data packet vector (Task M3.6 Step 1). `data = link.encrypt(plaintext)` (keyed Token).
- **contexts:** `LRPROOF = 0xFF`, `LRRTT = 0xFE`. Add these to `packet.rs`.

---

## File structure

```
crates/reticulum-core/src/
  token.rs        + seal_with_key / open_with_key (raw 64-byte keyed Token)
  packet.rs       + LRPROOF, LRRTT, LINK dest_type consts; link_request/proof/link_data constructors; hashable_part() exposed
  link.rs         NEW: LinkKeys, link_id, LINKREQUEST build/parse, PROOF build/verify, handshake derive
  lib.rs          + pub mod link;
  tests/vectors.rs
crates/reticulum-node/src/
  link_state.rs   NEW: LinkRegistry + Link state (PENDING/HANDSHAKE/ACTIVE/CLOSED)
  node.rs         + link initiation, inbound LINKREQUEST/PROOF handling, link data, keepalive/teardown
  lib.rs          + Event::LinkEstablished/LinkData/LinkClosed
crates/reticulum-tokio/src/driver.rs   + establish_link / link_send handle commands
crates/reticulum-cli/src/main.rs       + link / link-send subcommands
tools/
  capture_vectors.py                   + link_* vectors
  interop/run_link_interop.sh, link_peer.py
vectors/
  token_keyed.json, linkrequest.json, link_handshake.json, link_proof.json, link_data.json   NEW
```

## Global constraints (inherited)

Target RNS 1.4.1; core/node stay `no_std + alloc` and cross-compile to wasm32 + thumbv7em; sans-I/O (randomness via `EntropySource`, time via `Clock`); no panics on untrusted input; CSPRNG per link/IV; TDD + vector-driven; commit per task.

---

### Task M3.1: Raw-keyed Token (link cipher)

**Files:** `crates/reticulum-core/src/token.rs`, `tools/capture_vectors.py`, `vectors/token_keyed.json`, `crates/reticulum-core/tests/vectors.rs`

**Interfaces (add to `token`):**
- `pub fn seal_with_key(derived_key: &[u8;64], plaintext: &[u8], iv: &[u8;16]) -> Vec<u8>` — `iv ‖ AES256-CBC(pkcs7, key=derived_key[32..64]) ‖ HMAC-SHA256(key=derived_key[0..32], over iv‖ciphertext)`. No ephemeral prefix.
- `pub fn open_with_key(derived_key: &[u8;64], token: &[u8]) -> Result<Vec<u8>, CoreError>` — inverse; constant-time HMAC verify; `Truncated` if `< 16+16+32`, `DecryptFailed` on HMAC/padding failure.
- Refactor: extract the existing AES/HMAC/HKDF-split helpers so the identity `encrypt`/`decrypt` and these keyed fns share one implementation (DRY). Keep existing `encrypt`/`decrypt` signatures + tests unchanged.

- [ ] **Step 1:** Extend `capture_vectors.py` to emit `vectors/token_keyed.json`: `{ derived_key: hex(64), iv: hex(16), plaintext: hex, token: hex }` by calling RNS `Token(derived_key)` with a monkeypatched fixed IV (read `RNS/Cryptography/Token.py`). Regenerate; confirm populated.
- [ ] **Step 2:** Failing test `token_keyed_matches_rns` (open the vector token → plaintext; seal with the vector iv → byte-exact token).
- [ ] **Step 3:** Run (fail); implement seal/open + shared-helper refactor.
- [ ] **Step 4:** Run (pass); `cargo test --workspace`; clippy `-D warnings`; cross-compile. If bytes differ, reconcile against `Token.py` (IV position, HMAC coverage). Vector authoritative.
- [ ] **Step 5:** Commit `feat(core): raw-keyed Token (seal/open) for link encryption`.

### Task M3.2: Packet constants + link packet constructors

**Files:** `crates/reticulum-core/src/packet.rs`, tests.

**Interfaces:** add consts `LRPROOF = 0xFF`, `LRRTT = 0xFE`; `pub fn hashable_part(&self) -> Vec<u8>` (the bytes `packet_hash` hashes, exposed for link_id); constructors `Packet::link_request(dest_hash, payload)`, `Packet::proof(link_id, proof_data, context)`, `Packet::link_data(link_id, ciphertext)`. The LINK `dest_type` value is measured in Task M3.6; for M3.2 add a `pub const LINK: u8` placeholder and set it correctly in M3.6 (or capture first).

- [ ] TDD: construct a LINKREQUEST packet and assert `packet_type == LINKREQUEST`, round-trips through `decode`; `hashable_part()` equals the region hashed by `packet_hash`. Commit.

### Task M3.3: Link keys — ephemeral keypair, link_id, LINKREQUEST build/parse

**Files:** `crates/reticulum-core/src/link.rs`, `crates/reticulum-core/src/lib.rs`, `capture_vectors.py`, `vectors/linkrequest.json`, tests.

**Interfaces:**
- `pub struct LinkEphemeral { pub x25519_prv: [u8;32], pub x25519_pub: [u8;32], pub ed25519_prv: [u8;32], pub ed25519_pub: [u8;32] }` with `LinkEphemeral::generate<R: EntropySource>(rng)` (draw both secrets, derive pubs).
- `pub fn link_request_payload(eph: &LinkEphemeral) -> Vec<u8>` = `x25519_pub ‖ ed25519_pub` (64 bytes, no signalling for M3).
- `pub fn parse_link_request(data: &[u8]) -> Result<(/*x25519_pub*/[u8;32], /*ed25519_pub*/[u8;32]), CoreError>` (expects exactly 64 bytes for M3; reject otherwise).
- `pub fn link_id_from_request(packet: &Packet) -> [u8;16]` = `truncated_hash(packet.hashable_part())` (data is 64 bytes so no signalling trim needed).

- [ ] **Step 1:** `capture_vectors.py` → `vectors/linkrequest.json`: build an RNS `Link` toward a known destination with a monkeypatched fixed ephemeral keypair; record `{ x25519_prv, x25519_pub, ed25519_prv, ed25519_pub, dest_hash, lr_packet_bytes, link_id }`.
- [ ] **Step 2:** Failing tests: `link_request_payload` matches the vector's LR packet data; `link_id_from_request(decode(lr_packet_bytes))` equals `vector.link_id`.
- [ ] **Step 3:** Run (fail); implement.
- [ ] **Step 4:** Run (pass); clippy; cross-compile. Commit `feat(core): link ephemeral keys, LINKREQUEST payload + link_id`.

### Task M3.4: Handshake key derivation

**Files:** `crates/reticulum-core/src/link.rs`, `capture_vectors.py`, `vectors/link_handshake.json`, tests.

**Interfaces:** `pub fn derive_link_key(own_x25519_prv: &[u8;32], peer_x25519_pub: &[u8;32], link_id: &[u8;16]) -> [u8;64]` = `HKDF-SHA256(len=64, ikm=X25519(own_prv, peer_pub), salt=link_id, info=&[])`.

- [ ] **Step 1:** `vectors/link_handshake.json`: from an RNS link handshake with fixed keys, record `{ own_x25519_prv, peer_x25519_pub, link_id, derived_key(64) }` (read `Link.handshake`; `get_salt()=link_id`, `get_context()=None`).
- [ ] **Step 2:** Failing test: `derive_link_key(...) == vector.derived_key`.
- [ ] **Step 3–4:** Implement; run (pass); clippy; cross-compile. If mismatch, verify HKDF salt/info + the exact ECDH input against `Link.handshake`/`Cryptography.hkdf`. Commit `feat(core): link handshake key derivation`.

### Task M3.5: PROOF build + verify

**Files:** `crates/reticulum-core/src/link.rs`, `capture_vectors.py`, `vectors/link_proof.json`, tests.

**Interfaces:**
- `pub fn build_link_proof(destination_identity: &Identity, link_id: &[u8;16], responder_eph: &LinkEphemeral) -> Vec<u8>` = `proof_data = sign(dest_identity, link_id ‖ responder_x25519_pub ‖ responder_ed25519_pub) ‖ responder_x25519_pub` (no signalling in M3; signature 64B + pub 32B = 96B).
- `pub fn verify_link_proof(destination_pub: &PublicIdentity, link_id: &[u8;16], proof_data: &[u8]) -> Result<[u8;32] /*peer_x25519_pub*/, CoreError>` — parse `signature=data[0:64]`, `peer_x25519_pub=data[64:96]`; reconstruct `signed = link_id ‖ peer_x25519_pub ‖ destination_pub.sig_pub`; `destination_pub.verify(signed, signature)`; return `peer_x25519_pub` on success, `BadSignature`/`Truncated` otherwise.

> Note the asymmetry RNS uses: the responder's Ed25519 pub in the signed message is the DESTINATION identity's long-term sig key (`peer_sig_pub_bytes = destination.identity.get_public_key()[32:64]`), NOT the link ephemeral Ed25519. Confirm against `validate_proof` (lines ~400–410). The vector is authoritative — match it.

- [ ] **Step 1:** `vectors/link_proof.json`: `{ dest_identity_prv_x/ed, link_id, responder_x25519_pub, proof_data, dest_pub(64) }` from an RNS proof with fixed keys.
- [ ] **Step 2:** Failing tests: `build_link_proof` reproduces `vector.proof_data`; `verify_link_proof(dest_pub, link_id, proof_data)` returns `Ok(responder_x25519_pub)` and `Err` on a tampered signature.
- [ ] **Step 3–4:** Implement; run (pass); clippy; cross-compile. Commit `feat(core): link PROOF build + verify`.

### Task M3.6: LINK dest_type + link data packet crypto (self-consistency)

**Files:** `crates/reticulum-core/src/packet.rs` (set `LINK` const), `capture_vectors.py`, `vectors/link_data.json`, tests.

- [ ] **Step 1:** Capture `vectors/link_data.json`: an established RNS link's data packet — `{ derived_key(64), link_id, plaintext, packet_bytes }`. Decode `packet_bytes` to read the LINK `dest_type` value; set `packet::LINK` to it. Record the measured value in a comment.
- [ ] **Step 2:** Failing tests: decode `packet_bytes` → `dest_type == LINK`, `dest_hash == link_id`, `packet_type == DATA`; `token::open_with_key(derived_key, packet.data) == plaintext`; and `Packet::link_data(link_id, seal_with_key(derived_key, plaintext, iv)).encode()` decodes back to the same fields (self-consistent; exact bytes vary by IV).
- [ ] **Step 3–4:** Implement `Packet::link_data` + `LINK` const; run (pass); clippy; cross-compile. Commit `feat(core): link data packets over keyed Token`.

### Task M3.7: Node link state machine

**Files:** `crates/reticulum-node/src/link_state.rs`, `crates/reticulum-node/src/node.rs`, `crates/reticulum-node/src/lib.rs`, tests.

**Interfaces:**
- `pub enum LinkStatus { Pending, Handshake, Active, Closed }`
- `pub struct LinkId(pub [u8;16]);` (or reuse `[u8;16]`)
- On `Node`:
  - `pub fn establish_link<R: EntropySource>(&mut self, dest_hash: &[u8;16], rng: &mut R) -> Result<[u8;16] /*link_id*/, NodeError>` — requires a known path + the destination's `PublicIdentity` (from its announce, already in `PathTable`); generate `LinkEphemeral`, build LINKREQUEST, compute `link_id`, store link (initiator, Pending), enqueue on the path's interface (HEADER_2 if multi-hop). Returns `link_id`.
  - inbound `LINKREQUEST` for a LOCAL destination → create responder link, `derive_link_key`, `build_link_proof` (sign with local `identity`), store (responder, Active), enqueue PROOF; emit `Event::LinkEstablished{link_id}`.
  - inbound `PROOF` (context LRPROOF) for a Pending initiator link → `verify_link_proof` using the destination's known `PublicIdentity`; on success `derive_link_key`, mark Active, emit `Event::LinkEstablished{link_id}`.
  - `pub fn link_send<R: EntropySource>(&mut self, link_id: &[u8;16], plaintext: &[u8], rng: &mut R) -> Result<(), NodeError>` — Active links only; `seal_with_key` with a fresh IV; `Packet::link_data`; enqueue on the link's interface.
  - inbound `DATA` addressed to a known Active `link_id` (dest_type LINK) → `open_with_key` → emit `Event::LinkData{link_id, plaintext}`.
  - `pub fn close_link(&mut self, link_id: &[u8;16])` → mark Closed, emit `Event::LinkClosed`; teardown/keepalive timing via the injected `Clock` (add `pub fn tick(&mut self) -> Vec<Event>` that expires links past keepalive).
- Add to `lib.rs`: `Event::{LinkEstablished{link_id:[u8;16]}, LinkData{link_id:[u8;16], plaintext:Vec<u8>}, LinkClosed{link_id:[u8;16]}}`.

- [ ] **Step 1:** Failing test (two in-memory nodes, no I/O): initiator `establish_link` toward responder's dest (path pre-seeded via announce as in M2 tests) → LINKREQUEST bytes; responder `handle_inbound` → emits `LinkEstablished` + a PROOF; initiator `handle_inbound(proof)` → emits `LinkEstablished`; initiator `link_send` → responder `handle_inbound` emits `LinkData{plaintext}`; and reverse direction.
- [ ] **Step 2–4:** Run (fail); implement the state machine; run (pass); `cargo test --workspace`; clippy; cross-compile. Commit `feat(node): link lifecycle state machine (establish/proof/data/close)`.

### Task M3.8: Driver + CLI wiring

**Files:** `crates/reticulum-tokio/src/driver.rs`, `crates/reticulum-cli/src/main.rs`, `crates/reticulum-cli/src/config.rs` (if needed), tests.

**Interfaces:** `DriverHandle::{establish_link(dest_hash)->link_id via a oneshot reply, link_send(link_id, data), close_link(link_id)}`; surface `LinkEstablished/LinkData/LinkClosed` on the event channel; run `node.tick()` on a timer (tokio interval) for keepalive/teardown. CLI: `reticulumd link <dest_hash_hex>` (establish + print link_id), `reticulumd link-send <link_id_hex> <text>`, and log inbound `LinkData`.

- [ ] TDD: driver-level test — two `Driver`s over loopback TCP establish a link and exchange link data both ways (mirror the M2 driver test). Commit `feat(tokio,cli): drive link establishment + data over TCP`.

### Task M3.9: Live interop gate (Milestone 3 gate)

**Files:** `tools/interop/link_peer.py`, `tools/interop/run_link_interop.sh`, interop README.

- [ ] **Step 1:** `link_peer.py`: an RNS program that (mode A) registers a destination + accepts inbound links and echoes received data, and (mode B) establishes a link to a given destination hash and sends data, printing received data.
- [ ] **Step 2:** `run_link_interop.sh`:
  - **Rust→Python:** Python runs mode A (announces its destination); Rust daemon establishes a link to it and sends "link hello from rust"; assert Python prints it and its echo returns to Rust (`LinkData`).
  - **Python→Rust:** Rust daemon announces a destination; Python mode B establishes a link and sends "link hello from python"; assert the Rust daemon logs `LinkData` with that text and echoes back.
  - Exit 0 only if both directions succeed; capture logs.
- [ ] **Step 3:** Run it; capture evidence into the interop README.
- [ ] **Step 4:** Commit `test(interop): live Rust<->Python RNS link establishment + data`.

> If link establishment fails against Python: diff the Rust LINKREQUEST / PROOF bytes against RNS-captured equivalents for the same fixed keys (the vectors from M3.3–M3.6). The mismatch is the bug. Common culprits: signalling bytes present/absent, the responder-Ed25519-in-signed-data asymmetry, HKDF salt = link_id, or the LINK dest_type value.

**M3 acceptance:** `cargo test --workspace` green, clippy `-D warnings` clean, no_std cross-compile green, `run_link_interop.sh` exits 0 both directions with committed evidence.

---

## Self-Review

**Coverage vs M3 outline:** link key derivation (M3.4), LINKREQUEST build/parse (M3.3), PROOF build/verify (M3.5), link session encrypt/decrypt (M3.1 keyed Token + M3.6), node link state machine (M3.7), driver/CLI (M3.8), live interop (M3.9). Requests/responses over links (the outline's M3.6 "requests") are deferred to M8/LXMF where they are actually consumed — noted here to avoid scope creep; base link data transfer (LinkData) is delivered.

**Placeholder scan:** none. LINK `dest_type` is explicitly measured from a vector in M3.6 (with a placeholder const set correctly there); "read RNS source / capture vector" are verification steps with an authoritative oracle.

**Type consistency:** `LinkEphemeral`, `derive_link_key`, `build/verify_link_proof`, `seal/open_with_key`, `link_id_from_request`, and `Event::Link*` are named consistently across core → node → driver → cli. Keyed Token (M3.1) is the single cipher used by M3.6/M3.7.

**Key risk:** the responder-Ed25519 asymmetry in the PROOF signed-data (RNS uses the destination identity's long-term sig key, not the link ephemeral Ed25519). M3.5 calls this out and the vector enforces it. Second risk: whether to send signalling bytes — M3 omits them (64-byte LR / 96-byte proof), which RNS accepts; revisit only if the live gate shows Python requires MTU signalling.
