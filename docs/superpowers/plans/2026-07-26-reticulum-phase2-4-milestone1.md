# Reticulum Rust Port — Phases 2–4: Node → First Message (Milestone 1) Implementation Plan

> **For the implementing agent (Codex):** This is a self-contained TDD plan. Execute it task-by-task, in order. Each task ends with a green test and a commit. Steps use checkbox (`- [ ]`) syntax. Do NOT skip the fail-first test runs. Where a step says "read RNS 1.4.1 source" or "capture a vector", that is mandatory — wire bytes must be confirmed against real RNS, never guessed.

**Goal:** Build the sans-I/O node state machine, a tokio TCP interface + daemon, and reach Milestone 1: a running Rust node exchanges one encrypted message end-to-end with a Python RNS 1.4.1 node over TCP.

**Architecture:** Sans-I/O. `reticulum-node` is a pure, deterministic state machine (`no_std + alloc`): bytes/events in → bytes/events out, no I/O, no async, randomness injected via a trait. `reticulum-tokio` + `reticulum-cli` (std) wrap it with a tokio TCP I/O loop and HDLC framing. Interop correctness is proven against vectors captured from Python RNS 1.4.1 and against a live Python RNS node.

**Tech Stack:** Rust edition 2024, existing `reticulum-core` + `reticulum-interface` crates, RustCrypto (already wired), tokio (std layer only), Python `rns==1.4.1` for vectors and live interop.

## Global Constraints

- **Target RNS version:** Python RNS **1.4.1** exactly. All new vectors captured from it. Never bump silently.
- **`reticulum-node` is `no_std + alloc`**: `#![no_std]`, `extern crate alloc;`, no `std` imports in `src/`. Must build for `wasm32-unknown-unknown` and `thumbv7em-none-eabihf` (CI already enforces this for the workspace — add the crate to CI coverage).
- **Sans-I/O**: `reticulum-node` has NO I/O, NO async, NO direct RNG calls. All entropy enters through the `EntropySource` trait (Task 2.1). This makes every state transition deterministic and unit-testable.
- **No panics on untrusted input**: every decoder/handler returns `Result`/`Option` or emits an error event; never `unwrap`/`expect`/index on network-derived data.
- **CSPRNG discipline (std layer)**: the tokio/cli layer MUST supply an `EntropySource` backed by an OS CSPRNG (`rand::rngs::OsRng` via `getrandom`), fresh per call. Tests use a seeded/counter source. IV and ephemeral X25519 keys are drawn per message — never reused.
- **`reticulum-tokio` / `reticulum-cli` are std**: async is confined here. They only move bytes and own I/O; all protocol logic stays in `core`/`node`.
- **Existing core API (do not change signatures without a documented reason):**
  - `identity::Identity::{from_private_bytes(&[u8;32],&[u8;32]), public()->PublicIdentity, hash()->[u8;16], sign(&[u8])->[u8;64]}`
  - `identity::PublicIdentity{enc_pub:[u8;32],sig_pub:[u8;32]}::{from_bytes(&[u8])->Result<_,CoreError>, to_bytes()->[u8;64], hash()->[u8;16], verify(&[u8],&[u8;64])->Result<(),CoreError>}`
  - `destination::{name_hash(&str,&[&str])->[u8;10], destination_hash(&[u8;10],&[u8;16])->[u8;16]}`
  - `token::{encrypt(&PublicIdentity,&[u8],&[u8;32] ephemeral,&[u8;16] iv)->Vec<u8>, decrypt(&Identity,&[u8])->Result<Vec<u8>,CoreError>}`
  - `packet::{Packet{ifac,header_type,context_flag,propagation,dest_type,packet_type,hops,dest_hash:Vec<u8>,context,data:Vec<u8>}, Packet::decode(&[u8])->Result<Packet,CoreError>, Packet::encode()->Vec<u8>, consts DATA=0,ANNOUNCE=1,LINKREQUEST=2,PROOF=3}`
  - `announce::Announce{public:[u8;64],name_hash:[u8;10],random_hash:[u8;10],signature:[u8;64],app_data:Vec<u8>}::{parse(&[u8])->Result<_,CoreError>, verify(&[u8;16])->Result<(),CoreError>}`
  - `hdlc::{frame(&[u8])->Vec<u8>, deframe(&[u8])->Option<Vec<u8>>}` (in `reticulum-interface`)
  - RNS constants observed in Phase 1: SINGLE destination `dest_type` value and ANNOUNCE `packet_type=1` are as captured in `vectors/`. Confirm every new wire field against a vector.
- **Carry-forwards from Phase 1 that THIS plan resolves:** (a) token ENCRYPT vector validation → Task 2.3; (b) CSPRNG discipline → Task 2.1 + std layer; (c) ratcheted announce parsing → Task 3.5. HEADER_2/multi-hop remains out of scope (direct delivery only for Milestone 1).

---

## File structure (created/modified by this plan)

```
Cargo.toml                              add crates/reticulum-node, reticulum-tokio, reticulum-cli to members
crates/
  reticulum-core/
    src/announce.rs                     +build/sign + to_payload (Task 2.2)
    src/token.rs                        (unchanged; validated by Task 2.3)
    src/packet.rs                       +Packet constructors for announce/data (Task 2.4)
    tests/vectors.rs                    +encrypt vector test (2.3), +announce build test (2.2)
  reticulum-node/                       NEW no_std crate
    Cargo.toml
    src/
      lib.rs                            #![no_std], EntropySource trait, Event, NodeError
      rng.rs                            EntropySource trait + test SeededRng
      path_table.rs                     PathTable (dest_hash -> PathEntry)
      node.rs                           Node state machine
    tests/
      node.rs                           in-memory two-node integration tests
  reticulum-interface/
    src/lib.rs                          (hdlc already present)
  reticulum-tokio/                      NEW std crate
    Cargo.toml
    src/
      lib.rs
      tcp.rs                            TcpClientInterface (connect, framed read/write)
      driver.rs                         async loop: pump interface <-> Node
  reticulum-cli/                        NEW std binary crate
    Cargo.toml
    src/main.rs                         daemon: config, identity persistence, run driver
    src/config.rs
tools/
  capture_vectors.py                    +token_encrypt.json (2.3), +announce_ratchet.json (3.5)
vectors/
  token_encrypt.json                    NEW (2.3)
  announce_ratchet.json                 NEW (3.5)
docs/
  MILESTONE1.md                         how to run the live interop demo (Task 4.3)
```

---

# PHASE 2 — Sans-I/O Node State Machine

### Task 2.1: `reticulum-node` crate + `EntropySource` trait

**Files:**
- Modify: `Cargo.toml` (add `crates/reticulum-node` to `members`)
- Create: `crates/reticulum-node/Cargo.toml`, `crates/reticulum-node/src/lib.rs`, `crates/reticulum-node/src/rng.rs`
- Test: `crates/reticulum-node/src/rng.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces:
  - `pub trait EntropySource { fn fill(&mut self, out: &mut [u8]); }`
  - `pub struct SeededRng { state: u64 }` with `SeededRng::new(seed:u64)` implementing `EntropySource` (deterministic SplitMix64 — TEST/dev use only, documented as NOT cryptographic).
  - `pub enum NodeError { Core(reticulum_core::CoreError), Unknown }`

- [ ] **Step 1: Add crate to workspace + manifest**

Add `"crates/reticulum-node",` to `members` in root `Cargo.toml`. Create `crates/reticulum-node/Cargo.toml`:

```toml
[package]
name = "reticulum-node"
edition.workspace = true
version.workspace = true
license.workspace = true

[dependencies]
reticulum-core = { path = "../reticulum-core" }

[dev-dependencies]
```

- [ ] **Step 2: Write the failing test** (append to `src/rng.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seeded_rng_is_deterministic_and_fills() {
        let mut a = SeededRng::new(42);
        let mut b = SeededRng::new(42);
        let mut ba = [0u8; 32];
        let mut bb = [0u8; 32];
        a.fill(&mut ba);
        b.fill(&mut bb);
        assert_eq!(ba, bb);
        assert_ne!(ba, [0u8; 32]); // actually produces entropy
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p reticulum-node seeded_rng`
Expected: FAIL — crate/type not found.

- [ ] **Step 4: Implement**

`crates/reticulum-node/src/lib.rs`:

```rust
#![no_std]
extern crate alloc;

pub mod rng;

/// Errors surfaced by node operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    Core(reticulum_core::CoreError),
    Unknown,
}

impl From<reticulum_core::CoreError> for NodeError {
    fn from(e: reticulum_core::CoreError) -> Self { NodeError::Core(e) }
}
```

`crates/reticulum-node/src/rng.rs`:

```rust
/// Source of randomness, injected so the node stays sans-I/O and deterministic
/// in tests. Production impls MUST wrap an OS CSPRNG.
pub trait EntropySource {
    fn fill(&mut self, out: &mut [u8]);
}

/// Deterministic SplitMix64 generator. FOR TESTS/DEV ONLY — not cryptographic.
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub fn new(seed: u64) -> Self { Self { state: seed } }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

impl EntropySource for SeededRng {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p reticulum-node seeded_rng` → PASS.
Also: `cargo clippy --workspace --all-targets -- -D warnings` → clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/reticulum-node
git commit -m "feat(node): reticulum-node crate with EntropySource trait + SeededRng

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.2: Announce build + sign (in `reticulum-core`)

Phase 1 only parses/verifies announces. The node must build and sign its own. Ed25519 is deterministic, so building with the SAME inputs that produced `vectors/announce.json` MUST reproduce its bytes exactly — that is the test oracle.

**Files:**
- Modify: `crates/reticulum-core/src/announce.rs`
- Test: `crates/reticulum-core/tests/vectors.rs`

**Interfaces:**
- Produces (on `Announce`):
  - `pub fn build(identity: &Identity, name_hash: &[u8;10], random_hash: &[u8;10], app_data: &[u8]) -> Announce` — computes the destination hash internally is NOT possible (needs dest_hash for the signed message); instead sign over `dest_hash ‖ public ‖ name_hash ‖ random_hash ‖ app_data`. So signature is: `pub fn build(identity: &Identity, dest_hash: &[u8;16], name_hash: &[u8;10], random_hash: &[u8;10], app_data: &[u8]) -> Announce`.
  - `pub fn to_payload(&self) -> Vec<u8>` — serializes `public(64) ‖ name_hash(10) ‖ random_hash(10) ‖ signature(64) ‖ app_data`.

- [ ] **Step 1: Write the failing test** (append to `tests/vectors.rs`)

```rust
#[test]
fn announce_build_reproduces_rns_vector() {
    use reticulum_core::announce::Announce;
    use reticulum_core::identity::Identity;

    let idv = load("identity.json");
    let x: [u8;32] = hexf(&idv, "prv_x25519").try_into().unwrap();
    let e: [u8;32] = hexf(&idv, "prv_ed25519").try_into().unwrap();
    let id = Identity::from_private_bytes(&x, &e);

    let av = load("announce.json");
    let dest_hash: [u8;16] = hexf(&av, "dest_hash").try_into().unwrap();
    let name_hash: [u8;10] = hexf(&av, "name_hash").try_into().unwrap();
    let random_hash: [u8;10] = hexf(&av, "random_hash").try_into().unwrap();
    let app_data = hexf(&av, "app_data");

    let built = Announce::build(&id, &dest_hash, &name_hash, &random_hash, &app_data);
    // Ed25519 is deterministic -> signature must match the RNS-produced one.
    assert_eq!(built.signature.to_vec(), hexf(&av, "signature"));
    // to_payload must equal the announce packet's payload (bytes[19..]).
    let raw = hexf(&av, "bytes");
    assert_eq!(built.to_payload(), raw[19..].to_vec());
    // round-trips through verify
    assert!(built.verify(&dest_hash).is_ok());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reticulum-core announce_build` → FAIL (`build`/`to_payload` not found).

- [ ] **Step 3: Implement** (add to `announce.rs`; import `Identity`)

```rust
use crate::identity::Identity;

impl Announce {
    pub fn build(
        identity: &Identity,
        dest_hash: &[u8; 16],
        name_hash: &[u8; 10],
        random_hash: &[u8; 10],
        app_data: &[u8],
    ) -> Announce {
        let public = identity.public().to_bytes();
        let mut signed = Vec::with_capacity(16 + 64 + 10 + 10 + app_data.len());
        signed.extend_from_slice(dest_hash);
        signed.extend_from_slice(&public);
        signed.extend_from_slice(name_hash);
        signed.extend_from_slice(random_hash);
        signed.extend_from_slice(app_data);
        let signature = identity.sign(&signed);
        Announce {
            public,
            name_hash: *name_hash,
            random_hash: *random_hash,
            signature,
            app_data: app_data.to_vec(),
        }
    }

    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 10 + 10 + 64 + self.app_data.len());
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.name_hash);
        out.extend_from_slice(&self.random_hash);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.app_data);
        out
    }
}
```

> If the signature does not match, the RNS signed-data order differs from what Phase 1's `verify` assumed. Since Phase 1's `verify` already passes against this same vector, `build` MUST use the identical composition — reconcile the two so both use one shared helper (extract a private `fn signed_data(dest_hash, public, name_hash, random_hash, app_data) -> Vec<u8>` used by both `build` and `verify`). Vector is authoritative.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reticulum-core announce` → all announce tests PASS. Clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/reticulum-core/src/announce.rs crates/reticulum-core/tests/vectors.rs
git commit -m "feat(core): announce build/sign + to_payload (reproduces RNS vector)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.3: Deterministic token-encrypt vector (resolves carry-forward #1)

Phase 1 validated token DECRYPT byte-exact but only self-tested ENCRYPT. Capture a deterministic encrypt vector from RNS 1.4.1 by pinning the ephemeral key + IV, then prove `token::encrypt` is byte-exact.

**Files:**
- Modify: `tools/capture_vectors.py`
- Create (committed): `vectors/token_encrypt.json`
- Test: `crates/reticulum-core/tests/vectors.rs`

**Interfaces:**
- `vectors/token_encrypt.json` schema: `{ "recipient_pub": hex(64), "ephemeral_prv_x25519": hex(32), "iv": hex(16), "plaintext": hex, "token": hex }`.

- [ ] **Step 1: Extend the capture script**

In `tools/capture_vectors.py`, add a block that monkeypatches RNS's ephemeral X25519 generation and IV source to fixed values, calls `Identity.encrypt`, and records inputs+output. Read `.venv/lib/python3.*/site-packages/RNS/Cryptography/Token.py` and `RNS/Identity.py::encrypt` first to find exactly where the ephemeral key and the AES IV are generated (e.g. `os.urandom(16)` for the IV, `X25519PrivateKey.generate()` for the ephemeral), and patch those. Emit `token_encrypt.json` with `recipient_pub` = recipient's 64-byte public identity, `ephemeral_prv_x25519` = the fixed 32-byte ephemeral private key you injected, `iv` = the fixed 16-byte IV, `plaintext`, and `token` = the produced ciphertext.

- [ ] **Step 2: Regenerate vectors**

Run:
```bash
source .venv/bin/activate 2>/dev/null || (python3 -m venv .venv && source .venv/bin/activate && pip install rns==1.4.1)
python tools/capture_vectors.py
cat vectors/token_encrypt.json
```
Expected: populated JSON, `token` non-empty.

- [ ] **Step 3: Write the failing test** (append to `tests/vectors.rs`)

```rust
#[test]
fn token_encrypt_matches_rns_vector() {
    use reticulum_core::identity::PublicIdentity;
    use reticulum_core::token;
    let v = load("token_encrypt.json");
    let recipient = PublicIdentity::from_bytes(&hexf(&v, "recipient_pub")).unwrap();
    let eph: [u8;32] = hexf(&v, "ephemeral_prv_x25519").try_into().unwrap();
    let iv: [u8;16] = hexf(&v, "iv").try_into().unwrap();
    let plaintext = hexf(&v, "plaintext");
    let out = token::encrypt(&recipient, &plaintext, &eph, &iv);
    assert_eq!(out, hexf(&v, "token"));
}
```

- [ ] **Step 4: Run test to verify it fails then passes**

Run: `cargo test -p reticulum-core token_encrypt_matches` — first ensure it FAILS if the vector is absent/misnamed, then PASSES with the captured vector.

> If it fails on bytes, reconcile against RNS: the difference is almost certainly the IV position or whether RNS derives the ephemeral public differently. Read `Token.py` and align `token::encrypt`'s layout. Vector is authoritative. This is the send-direction interop proof for Phase 4 — do not mark done until byte-exact.

- [ ] **Step 5: Commit**

```bash
git add tools/capture_vectors.py vectors/token_encrypt.json crates/reticulum-core/tests/vectors.rs
git commit -m "test(core): deterministic token-encrypt vector proves RNS send-direction interop

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.4: Packet constructors (announce packet + data packet)

Add ergonomic constructors so the node builds valid RNS packets without hand-filling every field. Validate the announce packet against `announce.json` (its `bytes` is a full announce packet) and the data packet shape against `packet_data.json`.

**Files:**
- Modify: `crates/reticulum-core/src/packet.rs`
- Test: `crates/reticulum-core/tests/vectors.rs`

**Interfaces:**
- Produces (on `Packet`):
  - `pub fn announce(dest_hash: &[u8;16], payload: Vec<u8>) -> Packet` — HEADER_1, `packet_type = ANNOUNCE`, `dest_type = SINGLE_VALUE`, `context = 0`, `hops = 0`, flags cleared, `data = payload`.
  - `pub fn data_single(dest_hash: &[u8;16], ciphertext: Vec<u8>) -> Packet` — HEADER_1, `packet_type = DATA`, `dest_type = SINGLE_VALUE`, `context = 0`, `hops = 0`, `data = ciphertext`.
  - `pub const SINGLE: u8` — the `dest_type` value for SINGLE destinations, taken from the vectors (confirm the numeric value in Step 1 against `announce.json`/`packet_data.json` decoded `dest_type`).

- [ ] **Step 1: Determine SINGLE dest_type from vectors, write failing test**

First decode the announce packet to read its `dest_type`:
```bash
python3 -c "import json; d=json.load(open('vectors/announce.json')); b=bytes.fromhex(d['bytes']); print('flags',hex(b[0]),'dest_type',(b[0]>>2)&3,'ptype',b[0]&3)"
```
Use that `dest_type` value as `Packet::SINGLE`. Then append test:

```rust
#[test]
fn packet_announce_constructor_matches_vector() {
    use reticulum_core::packet::Packet;
    let av = load("announce.json");
    let raw = hexf(&av, "bytes");
    let dest_hash: [u8;16] = hexf(&av, "dest_hash").try_into().unwrap();
    let payload = raw[19..].to_vec();
    let p = Packet::announce(&dest_hash, payload);
    assert_eq!(p.encode(), raw); // byte-exact announce packet
}

#[test]
fn packet_data_single_shape() {
    use reticulum_core::packet::{Packet, DATA};
    let dest_hash = [7u8;16];
    let p = Packet::data_single(&dest_hash, vec![1,2,3]);
    assert_eq!(p.packet_type, DATA);
    assert_eq!(p.dest_hash, dest_hash.to_vec());
    let re = Packet::decode(&p.encode()).unwrap();
    assert_eq!(re, p);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reticulum-core packet_announce_constructor` → FAIL.

- [ ] **Step 3: Implement** (add to `packet.rs`, with the `SINGLE` value from Step 1 — shown here as `SINGLE = 1`; REPLACE with the value you measured)

```rust
impl Packet {
    /// dest_type value for SINGLE destinations (confirm against vectors).
    pub const SINGLE: u8 = 1; // <-- set to the measured value from Step 1

    pub fn announce(dest_hash: &[u8; 16], payload: Vec<u8>) -> Packet {
        Packet {
            ifac: false,
            header_type: 0,
            context_flag: false,
            propagation: 0,
            dest_type: Self::SINGLE,
            packet_type: ANNOUNCE,
            hops: 0,
            dest_hash: dest_hash.to_vec(),
            context: 0,
            data: payload,
        }
    }

    pub fn data_single(dest_hash: &[u8; 16], ciphertext: Vec<u8>) -> Packet {
        Packet {
            ifac: false,
            header_type: 0,
            context_flag: false,
            propagation: 0,
            dest_type: Self::SINGLE,
            packet_type: DATA,
            hops: 0,
            dest_hash: dest_hash.to_vec(),
            context: 0,
            data: ciphertext,
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reticulum-core packet` → PASS (byte-exact announce packet). Clippy clean. If `packet_announce_constructor_matches_vector` fails, the announce vector's flags byte reveals the exact dest_type/propagation/context values — set the constructor fields to reproduce byte 0 exactly.

- [ ] **Step 5: Commit**

```bash
git add crates/reticulum-core/src/packet.rs crates/reticulum-core/tests/vectors.rs
git commit -m "feat(core): Packet::announce + Packet::data_single constructors

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.5: PathTable

**Files:**
- Create: `crates/reticulum-node/src/path_table.rs`
- Modify: `crates/reticulum-node/src/lib.rs` (`pub mod path_table;`)
- Test: inline `#[cfg(test)]` in `path_table.rs`

**Interfaces:**
- Produces:
  - `pub struct PathEntry { pub interface: u16, pub hops: u8, pub public: PublicIdentity }`
  - `pub struct PathTable { /* alloc::collections::BTreeMap<[u8;16], PathEntry> */ }`
  - `impl PathTable`: `new()`, `insert(dest_hash:[u8;16], entry:PathEntry)`, `get(&self, dest_hash:&[u8;16]) -> Option<&PathEntry>`, `len()`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::identity::Identity;
    #[test]
    fn insert_and_get() {
        let id = Identity::from_private_bytes(&[1u8;32], &[2u8;32]);
        let mut t = PathTable::new();
        let dh = [9u8;16];
        t.insert(dh, PathEntry { interface: 3, hops: 0, public: id.public() });
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&dh).unwrap().interface, 3);
        assert!(t.get(&[0u8;16]).is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reticulum-node insert_and_get` → FAIL.

- [ ] **Step 3: Implement**

```rust
use alloc::collections::BTreeMap;
use reticulum_core::identity::PublicIdentity;

pub struct PathEntry {
    pub interface: u16,
    pub hops: u8,
    pub public: PublicIdentity,
}

pub struct PathTable {
    entries: BTreeMap<[u8; 16], PathEntry>,
}

impl PathTable {
    pub fn new() -> Self { Self { entries: BTreeMap::new() } }
    pub fn insert(&mut self, dest_hash: [u8; 16], entry: PathEntry) {
        self.entries.insert(dest_hash, entry);
    }
    pub fn get(&self, dest_hash: &[u8; 16]) -> Option<&PathEntry> {
        self.entries.get(dest_hash)
    }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl Default for PathTable {
    fn default() -> Self { Self::new() }
}
```

Add `pub mod path_table;` to `lib.rs`. (`PublicIdentity` must be `Clone` — if it is not yet, add `#[derive(Clone)]` to it in `reticulum-core/src/identity.rs` as part of this task and note it in the commit.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reticulum-node path_table` → PASS. Clippy clean (note the `is_empty` + `Default` satisfy clippy).

- [ ] **Step 5: Commit**

```bash
git add crates/reticulum-node/src/path_table.rs crates/reticulum-node/src/lib.rs crates/reticulum-core/src/identity.rs
git commit -m "feat(node): PathTable mapping destination hash to next hop + identity

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.6: `Node` — construction, local destination, announce emission

**Files:**
- Create: `crates/reticulum-node/src/node.rs`
- Modify: `crates/reticulum-node/src/lib.rs` (`pub mod node;`, `pub enum Event`)
- Test: `crates/reticulum-node/tests/node.rs`

**Interfaces:**
- Produces:
  - `pub enum Event { Announce { dest_hash: [u8;16], hops: u8 }, Message { dest_hash: [u8;16], plaintext: Vec<u8> }, Error(NodeError) }` (in `lib.rs`)
  - `pub struct Node { /* identity, local destinations, path table, outbound queue */ }`
  - `impl Node`:
    - `pub fn new(identity: Identity) -> Node`
    - `pub fn register_single_destination(&mut self, app_name: &str, aspects: &[&str]) -> [u8;16]` — computes name_hash + dest_hash, stores it as local IN destination, returns dest_hash.
    - `pub fn send_announce<R: EntropySource>(&mut self, dest_hash: &[u8;16], app_data: &[u8], rng: &mut R, interface: u16)` — builds a random_hash via `rng`, builds+signs an Announce, wraps in a `Packet::announce`, enqueues `(interface, bytes)` on the outbound queue.
    - `pub fn poll_outbound(&mut self) -> Option<(u16, Vec<u8>)>` — pops one queued outbound frame (raw packet bytes; framing happens in the I/O layer).

- [ ] **Step 1: Write the failing test** (`tests/node.rs`)

```rust
use reticulum_node::node::Node;
use reticulum_node::rng::SeededRng;
use reticulum_core::identity::Identity;
use reticulum_core::packet::{Packet, ANNOUNCE};

#[test]
fn node_emits_announce_packet() {
    let id = Identity::from_private_bytes(&[1u8;32], &[2u8;32]);
    let mut node = Node::new(id);
    let dh = node.register_single_destination("chat", &["v1"]);
    let mut rng = SeededRng::new(7);
    node.send_announce(&dh, b"hi", &mut rng, 0);
    let (iface, bytes) = node.poll_outbound().expect("one outbound");
    assert_eq!(iface, 0);
    let p = Packet::decode(&bytes).unwrap();
    assert_eq!(p.packet_type, ANNOUNCE);
    assert_eq!(p.dest_hash, dh.to_vec());
    assert!(node.poll_outbound().is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reticulum-node node_emits_announce` → FAIL.

- [ ] **Step 3: Implement** (`node.rs`)

```rust
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use reticulum_core::announce::Announce;
use reticulum_core::destination::{destination_hash, name_hash};
use reticulum_core::identity::Identity;
use reticulum_core::packet::Packet;

use crate::path_table::PathTable;
use crate::rng::EntropySource;

struct LocalDestination {
    name_hash: [u8; 10],
    dest_hash: [u8; 16],
}

pub struct Node {
    identity: Identity,
    locals: Vec<LocalDestination>,
    paths: PathTable,
    outbound: VecDeque<(u16, Vec<u8>)>,
}

impl Node {
    pub fn new(identity: Identity) -> Node {
        Node {
            identity,
            locals: Vec::new(),
            paths: PathTable::new(),
            outbound: VecDeque::new(),
        }
    }

    pub fn register_single_destination(&mut self, app_name: &str, aspects: &[&str]) -> [u8; 16] {
        let nh = name_hash(app_name, aspects);
        let dh = destination_hash(&nh, &self.identity.hash());
        self.locals.push(LocalDestination { name_hash: nh, dest_hash: dh });
        dh
    }

    pub fn send_announce<R: EntropySource>(
        &mut self,
        dest_hash: &[u8; 16],
        app_data: &[u8],
        rng: &mut R,
        interface: u16,
    ) {
        let local = self.locals.iter().find(|l| &l.dest_hash == dest_hash);
        let name_hash = match local {
            Some(l) => l.name_hash,
            None => return, // unknown local destination; ignore
        };
        let mut random_hash = [0u8; 10];
        rng.fill(&mut random_hash);
        let ann = Announce::build(&self.identity, dest_hash, &name_hash, &random_hash, app_data);
        let packet = Packet::announce(dest_hash, ann.to_payload());
        self.outbound.push_back((interface, packet.encode()));
    }

    pub fn poll_outbound(&mut self) -> Option<(u16, Vec<u8>)> {
        self.outbound.pop_front()
    }

    // used by later tasks
    pub(crate) fn identity(&self) -> &Identity { &self.identity }
    pub(crate) fn paths_mut(&mut self) -> &mut PathTable { &mut self.paths }
    pub(crate) fn paths(&self) -> &PathTable { &self.paths }
    pub(crate) fn is_local(&self, dest_hash: &[u8; 16]) -> bool {
        self.locals.iter().any(|l| &l.dest_hash == dest_hash)
    }
    pub(crate) fn enqueue(&mut self, interface: u16, bytes: Vec<u8>) {
        self.outbound.push_back((interface, bytes));
    }
}
```

Add to `lib.rs`:
```rust
pub mod node;

use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Announce { dest_hash: [u8; 16], hops: u8 },
    Message { dest_hash: [u8; 16], plaintext: Vec<u8> },
    Error(NodeError),
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reticulum-node node_emits_announce` → PASS. Clippy clean (the `pub(crate)` helpers may warn as unused until Task 2.7/2.8 — add `#[allow(dead_code)]` on them for this task only and remove the allow when they're consumed).

- [ ] **Step 5: Commit**

```bash
git add crates/reticulum-node/src crates/reticulum-node/tests
git commit -m "feat(node): Node with local destinations + announce emission

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.7: `Node::handle_inbound` — process announces

**Files:**
- Modify: `crates/reticulum-node/src/node.rs`
- Test: `crates/reticulum-node/tests/node.rs`

**Interfaces:**
- Produces (on `Node`):
  - `pub fn handle_inbound(&mut self, bytes: &[u8], interface: u16) -> Vec<Event>` — decodes the packet; if `packet_type == ANNOUNCE`: parse the announce, verify its signature against the packet's `dest_hash`, and on success learn the path (`PathTable::insert` with the announced `PublicIdentity`) and return `[Event::Announce{dest_hash, hops}]`; on verify failure return `[Event::Error(...)]`; on malformed input return `[]` (drop). Non-announce packets fall through (handled in Task 2.8).

- [ ] **Step 1: Write the failing test** (append to `tests/node.rs`)

```rust
#[test]
fn node_learns_path_from_announce() {
    // Sender builds an announce; receiver processes it.
    let sender_id = Identity::from_private_bytes(&[3u8;32], &[4u8;32]);
    let mut sender = Node::new(sender_id);
    let dh = sender.register_single_destination("chat", &["v1"]);
    let mut rng = SeededRng::new(1);
    sender.send_announce(&dh, b"hello", &mut rng, 0);
    let (_iface, ann_bytes) = sender.poll_outbound().unwrap();

    let recv_id = Identity::from_private_bytes(&[5u8;32], &[6u8;32]);
    let mut receiver = Node::new(recv_id);
    let events = receiver.handle_inbound(&ann_bytes, 2);
    assert_eq!(events.len(), 1);
    match &events[0] {
        reticulum_node::Event::Announce { dest_hash, .. } => assert_eq!(*dest_hash, dh),
        other => panic!("expected Announce, got {other:?}"),
    }
    assert!(receiver.knows_path(&dh)); // helper added below
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reticulum-node node_learns_path` → FAIL.

- [ ] **Step 3: Implement** (add to `node.rs`; add a `pub fn knows_path(&self, dh:&[u8;16])->bool` test helper)

```rust
use crate::path_table::PathEntry;
use crate::{Event, NodeError};
use reticulum_core::announce::Announce;
use reticulum_core::identity::PublicIdentity;
use reticulum_core::packet::{Packet, ANNOUNCE};

impl Node {
    pub fn handle_inbound(&mut self, bytes: &[u8], interface: u16) -> Vec<Event> {
        let packet = match Packet::decode(bytes) {
            Ok(p) => p,
            Err(_) => return Vec::new(), // drop malformed
        };
        let dest_hash: [u8; 16] = match packet.dest_hash.as_slice().try_into() {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        match packet.packet_type {
            ANNOUNCE => self.handle_announce(&packet, &dest_hash, interface),
            _ => Vec::new(), // DATA handled in Task 2.8
        }
    }

    fn handle_announce(&mut self, packet: &Packet, dest_hash: &[u8; 16], interface: u16) -> Vec<Event> {
        let ann = match Announce::parse(&packet.data) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };
        if ann.verify(dest_hash).is_err() {
            return alloc::vec![Event::Error(NodeError::Core(reticulum_core::CoreError::BadSignature))];
        }
        let public = match PublicIdentity::from_bytes(&ann.public) {
            Ok(p) => p,
            Err(e) => return alloc::vec![Event::Error(NodeError::Core(e))],
        };
        self.paths.insert(*dest_hash, PathEntry { interface, hops: packet.hops, public });
        alloc::vec![Event::Announce { dest_hash: *dest_hash, hops: packet.hops }]
    }

    pub fn knows_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.paths.get(dest_hash).is_some()
    }
}
```

Remove any `#[allow(dead_code)]` added in Task 2.6 for helpers now used.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reticulum-node node_learns_path` → PASS. Clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/reticulum-node/src/node.rs crates/reticulum-node/tests/node.rs
git commit -m "feat(node): handle_inbound learns paths from verified announces

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.8: `Node` — receive + decrypt DATA to a local destination

**Files:**
- Modify: `crates/reticulum-node/src/node.rs`
- Test: `crates/reticulum-node/tests/node.rs`

**Interfaces:**
- Extends `handle_inbound`: when `packet_type == DATA` and `dest_hash` is a local destination, run `token::decrypt(self.identity, &packet.data)`; on success return `[Event::Message{dest_hash, plaintext}]`; on failure return `[Event::Error(...)]`. DATA for non-local dests returns `[]` (no multi-hop in M1).

- [ ] **Step 1: Write the failing test** (append to `tests/node.rs`)

```rust
#[test]
fn node_decrypts_data_to_local_destination() {
    use reticulum_core::packet::Packet;
    use reticulum_core::token;

    // Receiver owns a destination.
    let recv_id = Identity::from_private_bytes(&[10u8;32], &[11u8;32]);
    let mut receiver = Node::new(recv_id.clone_for_test()); // see note
    let dh = receiver.register_single_destination("chat", &["v1"]);

    // Sender encrypts to the receiver's public identity and builds a DATA packet.
    let recipient_pub = recv_id.public();
    let ct = token::encrypt(&recipient_pub, b"secret", &[9u8;32], &[3u8;16]);
    let packet = Packet::data_single(&dh, ct);

    let events = receiver.handle_inbound(&packet.encode(), 0);
    assert_eq!(events.len(), 1);
    match &events[0] {
        reticulum_node::Event::Message { dest_hash, plaintext } => {
            assert_eq!(*dest_hash, dh);
            assert_eq!(plaintext, b"secret");
        }
        other => panic!("expected Message, got {other:?}"),
    }
}
```

> Note: `Identity` currently has no `Clone`. Rather than a test-only clone, construct two `Identity` values from the same private bytes: replace `recv_id.clone_for_test()` by building the receiver node with `Identity::from_private_bytes(&[10u8;32], &[11u8;32])` and computing `recipient_pub` from a separately built `Identity::from_private_bytes(&[10u8;32], &[11u8;32]).public()`. Do NOT add `Clone` to `Identity` (it holds secret key material).

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reticulum-node node_decrypts_data` → FAIL.

- [ ] **Step 3: Implement** (extend the `match` in `handle_inbound`)

```rust
use reticulum_core::packet::DATA;
use reticulum_core::token;

// inside handle_inbound's match:
            DATA => self.handle_data(&packet, &dest_hash),

// new method:
impl Node {
    fn handle_data(&mut self, packet: &Packet, dest_hash: &[u8; 16]) -> Vec<Event> {
        if !self.is_local(dest_hash) {
            return Vec::new(); // no multi-hop forwarding in Milestone 1
        }
        match token::decrypt(&self.identity, &packet.data) {
            Ok(plaintext) => alloc::vec![Event::Message { dest_hash: *dest_hash, plaintext }],
            Err(e) => alloc::vec![Event::Error(NodeError::Core(e))],
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reticulum-node node_decrypts_data` → PASS. Clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/reticulum-node/src/node.rs crates/reticulum-node/tests/node.rs
git commit -m "feat(node): decrypt DATA packets addressed to local destinations

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.9: `Node::send_message` — encrypt + enqueue DATA to a known dest

**Files:**
- Modify: `crates/reticulum-node/src/node.rs`
- Test: `crates/reticulum-node/tests/node.rs`

**Interfaces:**
- Produces (on `Node`):
  - `pub fn send_message<R: EntropySource>(&mut self, dest_hash: &[u8;16], plaintext: &[u8], rng: &mut R) -> Result<(), NodeError>` — looks up the path (must exist, learned via announce); draws a fresh 32-byte ephemeral X25519 secret + 16-byte IV from `rng`; `token::encrypt` to the path's `PublicIdentity`; wraps in `Packet::data_single`; enqueues on the path's interface. Returns `Err(NodeError::Unknown)` if no path known.

- [ ] **Step 1: Write the failing test** (append to `tests/node.rs`)

```rust
#[test]
fn node_sends_encrypted_message_to_known_path() {
    // receiver announces; sender learns path; sender sends; receiver decrypts.
    let recv_id = Identity::from_private_bytes(&[10u8;32], &[11u8;32]);
    let mut receiver = Node::new(Identity::from_private_bytes(&[10u8;32], &[11u8;32]));
    let dh = receiver.register_single_destination("chat", &["v1"]);
    let mut rng_r = SeededRng::new(1);
    receiver.send_announce(&dh, b"", &mut rng_r, 0);
    let (_i, ann) = receiver.poll_outbound().unwrap();

    let mut sender = Node::new(Identity::from_private_bytes(&[20u8;32], &[21u8;32]));
    sender.handle_inbound(&ann, 5);
    let mut rng_s = SeededRng::new(99);
    sender.send_message(&dh, b"secret", &mut rng_s).unwrap();
    let (iface, data_bytes) = sender.poll_outbound().unwrap();
    assert_eq!(iface, 5); // path's interface

    let events = receiver.handle_inbound(&data_bytes, 0);
    assert!(matches!(&events[0], reticulum_node::Event::Message { plaintext, .. } if plaintext == b"secret"));
    let _ = recv_id;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p reticulum-node node_sends_encrypted_message` → FAIL.

- [ ] **Step 3: Implement**

```rust
impl Node {
    pub fn send_message<R: EntropySource>(
        &mut self,
        dest_hash: &[u8; 16],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(), NodeError> {
        let (interface, public) = match self.paths.get(dest_hash) {
            Some(e) => (e.interface, e.public.clone()),
            None => return Err(NodeError::Unknown),
        };
        let mut ephemeral = [0u8; 32];
        let mut iv = [0u8; 16];
        rng.fill(&mut ephemeral);
        rng.fill(&mut iv);
        let ct = reticulum_core::token::encrypt(&public, plaintext, &ephemeral, &iv);
        let packet = Packet::data_single(dest_hash, ct);
        self.outbound.push_back((interface, packet.encode()));
        Ok(())
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p reticulum-node node_sends_encrypted_message` → PASS. Clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/reticulum-node/src/node.rs crates/reticulum-node/tests/node.rs
git commit -m "feat(node): send_message encrypts + enqueues DATA to a learned path

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2.10: Two-node in-memory integration test (Phase 2 gate)

**Files:**
- Test: `crates/reticulum-node/tests/node.rs`

- [ ] **Step 1: Write the integration test** (append)

```rust
#[test]
fn two_nodes_announce_and_message_both_directions() {
    let mut a = Node::new(Identity::from_private_bytes(&[1u8;32], &[2u8;32]));
    let mut b = Node::new(Identity::from_private_bytes(&[3u8;32], &[4u8;32]));
    let a_dh = a.register_single_destination("chat", &["a"]);
    let b_dh = b.register_single_destination("chat", &["b"]);
    let mut ra = SeededRng::new(10);
    let mut rb = SeededRng::new(20);

    // both announce, deliver to each other
    a.send_announce(&a_dh, b"", &mut ra, 0);
    b.send_announce(&b_dh, b"", &mut rb, 0);
    let (_i, a_ann) = a.poll_outbound().unwrap();
    let (_i, b_ann) = b.poll_outbound().unwrap();
    b.handle_inbound(&a_ann, 1);
    a.handle_inbound(&b_ann, 1);
    assert!(a.knows_path(&b_dh) && b.knows_path(&a_dh));

    // a -> b
    a.send_message(&b_dh, b"ping", &mut ra).unwrap();
    let (_i, m1) = a.poll_outbound().unwrap();
    let e1 = b.handle_inbound(&m1, 1);
    assert!(matches!(&e1[0], reticulum_node::Event::Message { plaintext, .. } if plaintext == b"ping"));

    // b -> a
    b.send_message(&a_dh, b"pong", &mut rb).unwrap();
    let (_i, m2) = b.poll_outbound().unwrap();
    let e2 = a.handle_inbound(&m2, 1);
    assert!(matches!(&e2[0], reticulum_node::Event::Message { plaintext, .. } if plaintext == b"pong"));
}
```

- [ ] **Step 2: Run + verify** `cargo test -p reticulum-node two_nodes` → PASS. Full workspace: `cargo test --workspace`. Cross-compile: `cargo build --workspace --target wasm32-unknown-unknown && cargo build --workspace --target thumbv7em-none-eabihf`. Clippy clean.

- [ ] **Step 3: Commit**

```bash
git add crates/reticulum-node/tests/node.rs
git commit -m "test(node): two-node announce + bidirectional message integration

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# PHASE 3 — TCP Interface + Daemon + Live Interop

> Phase 3 introduces `std`/tokio. Wire details (TCP framing, IFAC, connection handshake) MUST be confirmed against RNS 1.4.1 source (`.venv/.../RNS/Interfaces/TCPInterface.py`) and a live node — do not guess.

### Task 3.1: `reticulum-tokio` crate + OS entropy source

**Files:**
- Modify: `Cargo.toml` (members)
- Create: `crates/reticulum-tokio/Cargo.toml`, `crates/reticulum-tokio/src/lib.rs`
- Test: inline

**Interfaces:**
- Produces: `pub struct OsEntropy;` implementing `reticulum_node::rng::EntropySource` via `getrandom`/`rand::rngs::OsRng` (fresh OS randomness each `fill`).

- [ ] **Step 1: Manifest**

`crates/reticulum-tokio/Cargo.toml`:
```toml
[package]
name = "reticulum-tokio"
edition.workspace = true
version.workspace = true
license.workspace = true

[dependencies]
reticulum-core = { path = "../reticulum-core" }
reticulum-node = { path = "../reticulum-node" }
reticulum-interface = { path = "../reticulum-interface" }
tokio = { version = "1", features = ["net", "io-util", "rt", "rt-multi-thread", "macros", "sync", "time"] }
getrandom = "0.2"

[dev-dependencies]
tokio = { version = "1", features = ["macros", "rt"] }
```

- [ ] **Step 2: Failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_node::rng::EntropySource;
    #[test]
    fn os_entropy_fills_nonzero_and_varies() {
        let mut e = OsEntropy;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        e.fill(&mut a);
        e.fill(&mut b);
        assert_ne!(a, [0u8;32]);
        assert_ne!(a, b); // two draws differ (overwhelmingly likely)
    }
}
```

- [ ] **Step 3: Run (fail), implement, run (pass)**

`crates/reticulum-tokio/src/lib.rs`:
```rust
pub mod tcp;
pub mod driver;

use reticulum_node::rng::EntropySource;

/// OS-backed CSPRNG entropy source for production use.
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        getrandom::getrandom(out).expect("OS entropy must be available");
    }
}
```
Run `cargo test -p reticulum-tokio os_entropy` → PASS. (Create empty `tcp.rs`/`driver.rs` stubs so the module declarations compile.)

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock crates/reticulum-tokio
git commit -m "feat(tokio): reticulum-tokio crate + OS CSPRNG entropy source

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3.2: `TcpClientInterface` — connect + HDLC framed read/write

> **Read first:** `.venv/lib/python3.*/site-packages/RNS/Interfaces/TCPInterface.py`. Confirm: (1) TCP payloads are HDLC-framed with flag `0x7E` and the same byte-stuffing our `hdlc` module implements; (2) whether any bytes are exchanged on connect before packets flow (KISS/IFAC/spawn handshake). Encode findings as tests.

**Files:**
- Create/replace: `crates/reticulum-tokio/src/tcp.rs`
- Test: `crates/reticulum-tokio/src/tcp.rs` inline (loopback test)

**Interfaces:**
- Produces:
  - `pub struct TcpClientInterface { /* framed reader/writer over TcpStream */ }`
  - `impl TcpClientInterface`:
    - `pub async fn connect(addr: &str) -> std::io::Result<TcpClientInterface>`
    - `pub async fn send_packet(&mut self, raw: &[u8]) -> std::io::Result<()>` — HDLC-frames `raw` and writes it.
    - `pub async fn recv_packet(&mut self) -> std::io::Result<Option<Vec<u8>>>` — reads bytes, accumulates into a frame buffer split on `0x7E`, returns the next deframed raw packet (`None` on clean EOF).

- [ ] **Step 1: Failing loopback test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn framed_roundtrip_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut iface = TcpClientInterface::from_stream(stream);
            let pkt = iface.recv_packet().await.unwrap().unwrap();
            iface.send_packet(&pkt).await.unwrap(); // echo
        });

        let mut client = TcpClientInterface::connect(&addr).await.unwrap();
        let payload = vec![0x7E, 0x11, 0x7D, 0x22, 0x7E, 0x00]; // includes flag/esc bytes
        client.send_packet(&payload).await.unwrap();
        let echoed = client.recv_packet().await.unwrap().unwrap();
        assert_eq!(echoed, payload);
        server.await.unwrap();
    }
}
```

- [ ] **Step 2: Run (fail), implement, run (pass)**

Implement `tcp.rs` using `tokio::io::{AsyncReadExt, AsyncWriteExt}` and `reticulum_interface::hdlc::{frame, deframe}`. Maintain a read buffer; a frame is the bytes between two `0x7E` flags (inclusive) — accumulate until a complete `FLAG .. FLAG` is present, then `deframe`. Add a `from_stream(TcpStream)` constructor for the test. Handle partial reads and multiple frames per read.

Run `cargo test -p reticulum-tokio framed_roundtrip` → PASS.

> If the loopback test passes but the byte accounting for split flags is fragile, add a second test that sends two packets back-to-back in one write and asserts both deframe correctly.

- [ ] **Step 3: Commit**

```bash
git add crates/reticulum-tokio/src/tcp.rs
git commit -m "feat(tokio): TcpClientInterface with HDLC framed packet read/write

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3.3: Driver — pump interface ↔ `Node`

**Files:**
- Create/replace: `crates/reticulum-tokio/src/driver.rs`
- Test: `crates/reticulum-tokio/src/driver.rs` inline (two drivers over loopback)

**Interfaces:**
- Produces:
  - `pub struct Driver { node: Node, /* interface(s), entropy */ }`
  - `pub async fn run(...)` style loop: on each received packet call `node.handle_inbound`, surface `Event`s (via an `mpsc` channel or callback), and after handling drain `node.poll_outbound()` writing each frame to the matching interface. Provide `pub async fn announce_all(...)` and `pub async fn send(dest_hash, plaintext)` control methods (via an `mpsc` command channel).
  - Keep the concrete shape minimal: one interface (index 0) is enough for Milestone 1.

- [ ] **Step 1: Failing test** — two `Driver`s connected over a loopback `TcpListener`/`connect`, one announces, the other receives an `Event::Announce`, then sends a message the first decrypts as `Event::Message`. Use `tokio::sync::mpsc` to observe events. (Mirror the Task 2.10 flow but over real TCP framing.)

- [ ] **Step 2: Run (fail), implement, run (pass)**

Implement the select-loop: `tokio::select!` between (a) `interface.recv_packet()` and (b) a command-channel receiver. On inbound packet → `handle_inbound` → emit events → drain outbound → `send_packet`. On command → mutate node (announce/send) → drain outbound. Use `OsEntropy` for randomness.

Run `cargo test -p reticulum-tokio driver` → PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/reticulum-tokio/src/driver.rs
git commit -m "feat(tokio): Driver pumping TCP interface into the sans-IO Node

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3.4: `reticulum-cli` daemon + config + identity persistence

**Files:**
- Modify: `Cargo.toml` (members)
- Create: `crates/reticulum-cli/Cargo.toml`, `src/main.rs`, `src/config.rs`

**Interfaces:**
- Produces a binary `reticulumd` that: loads/creates a persistent `Identity` (64 private bytes to a file, `0600`), reads config (TCP server host:port to connect to, app_name/aspects to announce), starts a `Driver`, announces on start, and logs `Event`s. CLI subcommands: `run`, `announce`, `send <dest_hash_hex> <text>` (the latter two via a local control socket OR simply a `run`-and-announce daemon for M1 — keep minimal).

- [ ] **Step 1: Failing test** — a unit test for `config` parse + identity load/save roundtrip (write identity, reload, assert same public hash). Keep daemon wiring thin and covered by the Phase-4 live gate rather than unit tests.

```rust
// crates/reticulum-cli/src/config.rs tests
#[test]
fn identity_persist_roundtrip() {
    let dir = tempdir();
    let path = dir.path().join("id");
    let id = save_or_create_identity(&path).unwrap();
    let reloaded = save_or_create_identity(&path).unwrap();
    assert_eq!(id.hash(), reloaded.hash());
}
```
(Add `tempfile` as a dev-dependency.)

- [ ] **Step 2: Run (fail), implement, run (pass)** — implement `save_or_create_identity` (generate via `OsEntropy` if absent, persist 64 private bytes, `0600`), a small `Config` struct + parse (env or a TOML file), and `main.rs` wiring `#[tokio::main]` → connect → `Driver::run`. Run `cargo test -p reticulum-cli` → PASS. `cargo build -p reticulum-cli` → produces the binary.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock crates/reticulum-cli
git commit -m "feat(cli): reticulumd daemon with persistent identity + config

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3.5: Ratcheted announce handling (resolves carry-forward #3)

> RNS 1.4.1 destinations with ratchets enabled emit a 32-byte ratchet in the announce and set the packet context flag. The Phase-1 parser assumes no ratchet and will misparse these. Capture a ratcheted announce vector and handle it.

**Files:**
- Modify: `tools/capture_vectors.py` (emit `vectors/announce_ratchet.json`)
- Modify: `crates/reticulum-core/src/announce.rs`
- Modify: `crates/reticulum-node/src/node.rs` (pass the packet's `context_flag` into announce parsing)
- Test: `crates/reticulum-core/tests/vectors.rs`

**Interfaces:**
- `vectors/announce_ratchet.json`: same schema as `announce.json` plus `"ratchet": hex(32)` and `"context_flag": true`.
- Change `Announce::parse` → `Announce::parse(payload: &[u8], has_ratchet: bool) -> Result<Announce,CoreError>`; add `pub ratchet: Option<[u8;32]>` to `Announce`. Update `verify` and `to_payload` to include the ratchet between `random_hash` and `signature` when present, matching RNS `Destination.py::announce`. Update all Phase-1 call sites (they pass `has_ratchet=false`). Node passes `packet.context_flag`.

- [ ] **Step 1: Capture** — extend `capture_vectors.py` to build a destination WITH ratchets enabled (see `RNS/Destination.py` `enable_ratchets`) and emit `announce_ratchet.json`. Verify the 32-byte ratchet field is present and `context_flag` is true.

- [ ] **Step 2: Failing test**

```rust
#[test]
fn announce_with_ratchet_parses_and_verifies() {
    use reticulum_core::announce::Announce;
    let v = load("announce_ratchet.json");
    let raw = hexf(&v, "bytes");
    let payload = &raw[19..];
    let a = Announce::parse(payload, true).expect("parse ratchet");
    assert_eq!(a.ratchet.unwrap().to_vec(), hexf(&v, "ratchet"));
    let dh: [u8;16] = hexf(&v, "dest_hash").try_into().unwrap();
    assert!(a.verify(&dh).is_ok());
}
```
Also keep the existing non-ratchet test passing (update it to `parse(payload, false)`).

- [ ] **Step 3: Run (fail), implement, run (pass)** — read `RNS/Destination.py` for the EXACT signed-data + payload layout with a ratchet (order of ratchet vs signature, and whether the ratchet is in the signed message). Vector is authoritative. Update `parse`/`verify`/`to_payload`, all call sites, and node's inbound path. Run `cargo test --workspace` → all PASS. Clippy clean.

- [ ] **Step 4: Commit**

```bash
git add tools/capture_vectors.py vectors/announce_ratchet.json crates/reticulum-core/src/announce.rs crates/reticulum-node/src/node.rs crates/reticulum-core/tests/vectors.rs
git commit -m "feat: parse + verify ratcheted RNS announces (context-flag driven)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3.6: Live interop gate — Rust daemon ↔ Python RNS over TCP

> Manual/scripted verification against a real Python RNS 1.4.1 node. This is a gate, not a unit test; script it so it is repeatable.

**Files:**
- Create: `tools/interop/rns_server_config` (RNS config enabling a `TCPServerInterface`), `tools/interop/run_interop.sh`, `tools/interop/README.md`

- [ ] **Step 1: Stand up a Python RNS node** with a `TCPServerInterface` on a local port (document the `~/.reticulum/config` stanza). Start it with `rnsd` and confirm with `rnstatus`.
- [ ] **Step 2: Run the Rust daemon** (`reticulumd run`) configured to connect to that TCP server and announce a SINGLE destination.
- [ ] **Step 3: Verify** the Rust node's announce appears in the Python node's `rnstatus` / path table (`rnpath` for the announced destination hash). Capture the output in `tools/interop/README.md`.
- [ ] **Step 4: Commit** the interop scripts + captured evidence.

```bash
git add tools/interop
git commit -m "test(interop): scripted Rust-daemon <-> Python RNS announce over TCP

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

> If announces do not appear: diff the Rust announce packet bytes against a Python-captured announce for the same inputs; the discrepancy is the bug. Do not proceed to Phase 4 until this gate passes.

---

# PHASE 4 — First Encrypted Message (Milestone 1)

### Task 4.1: Rust → Python — send an encrypted message a real RNS node decrypts

**Files:**
- Modify: `crates/reticulum-cli/src/main.rs` (a `send` path/command)
- Create: `tools/interop/recv_and_print.py` (a tiny RNS app registering the destination and printing received plaintext)
- Modify: `tools/interop/run_interop.sh`

- [ ] **Step 1** — Write `recv_and_print.py`: an RNS program that creates a SINGLE destination (same app_name/aspects the Rust node will target), registers a packet/message callback that prints received plaintext, and announces itself so the Rust node learns the path.
- [ ] **Step 2** — Rust daemon receives the Python node's announce (learns path + PublicIdentity), then `send_message(dest_hash, b"hello from rust")`.
- [ ] **Step 3 (gate)** — Confirm `recv_and_print.py` prints `hello from rust`. This exercises `token::encrypt` (validated byte-exact in Task 2.3) against a real RNS decrypt. Capture output in the interop README.
- [ ] **Step 4** — Commit scripts + evidence.

> If decryption fails on the Python side: the salt/ephemeral/IV layout differs from Task 2.3's assumptions under live conditions (e.g. ratchet-derived keys). Re-verify against `RNS/Identity.py::decrypt` and Task 2.3's vector. The encrypt vector is the contract.

---

### Task 4.2: Python → Rust — receive + decrypt a message from a real RNS node

**Files:**
- Create: `tools/interop/send_from_python.py`
- Modify: `tools/interop/run_interop.sh`, `crates/reticulum-cli/src/main.rs` (log decrypted `Event::Message`)

- [ ] **Step 1** — `send_from_python.py`: an RNS program that learns the Rust node's announced destination and sends it an encrypted message.
- [ ] **Step 2** — The Rust daemon receives the DATA packet, decrypts via `token::decrypt` (already vector-validated), and logs `Event::Message { plaintext }`.
- [ ] **Step 3 (gate)** — Confirm the Rust daemon logs the exact plaintext sent from Python. Capture output.
- [ ] **Step 4** — Commit scripts + evidence.

---

### Task 4.3: Milestone 1 documentation + end-to-end demo script

**Files:**
- Create: `docs/MILESTONE1.md`
- Modify: `tools/interop/run_interop.sh` (one script running both directions)

- [ ] **Step 1** — `run_interop.sh` starts the Python RNS server, the Rust daemon, runs both directions (Rust→Python and Python→Rust), and asserts both plaintexts arrived (grep the outputs; non-zero exit on failure).
- [ ] **Step 2** — `docs/MILESTONE1.md`: prerequisites (`pip install rns==1.4.1`, build `reticulumd`), exact commands, expected output, and a short architecture recap.
- [ ] **Step 3 (final gate)** — Run `run_interop.sh` end-to-end; it must exit 0 with both messages delivered. Run `cargo test --workspace` (all green), `cargo clippy --workspace --all-targets -- -D warnings` (clean), and the cross-compile builds. 
- [ ] **Step 4** — Commit.

```bash
git add docs/MILESTONE1.md tools/interop/run_interop.sh
git commit -m "docs: Milestone 1 end-to-end interop demo (Rust <-> Python RNS)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (design doc → tasks):**
- Node sans-I/O state machine → Tasks 2.5–2.10.
- Announce build/emit/parse/verify → 2.2, 2.6, 2.7, 3.5.
- Direct-delivery path table → 2.5, 2.7.
- Encrypt/decrypt DATA to SINGLE dest → 2.3, 2.8, 2.9.
- TCP interface + HDLC over the wire → 3.2.
- Daemon (`reticulumd`) + identity persistence → 3.4.
- First message both directions vs Python RNS → 4.1, 4.2, 4.3.
- CSPRNG discipline → 2.1 (trait) + 3.1 (OsEntropy) + 2.9 (per-message draw).
- Carry-forwards resolved: token-encrypt vector (2.3), ratcheted announce (3.5), CSPRNG (2.1/3.1). HEADER_2/multi-hop explicitly deferred.

**Placeholder scan:** No TBD/TODO. Two values are marked "measure/confirm against the vector" with an explicit measurement command (`Packet::SINGLE` in 2.4) or an authoritative vector/source (RNS wire layout in 3.2/3.5/4.x) — these are verification instructions with a concrete oracle, not deferred work.

**Type consistency:** `EntropySource::fill` used uniformly (2.1, 2.6, 2.9, 3.1). `Node` methods (`register_single_destination`, `send_announce`, `handle_inbound`, `send_message`, `poll_outbound`, `knows_path`) are consistent across tasks and tests. `Event`/`NodeError` defined in 2.1/2.6 and consumed in 2.7–2.10. `Announce::parse` signature change in 3.5 explicitly updates all Phase-1 call sites. `PublicIdentity` gains `Clone` in 2.5 (needed by PathEntry + send_message).

**Scope:** Focused on Milestone 1 (direct delivery, SINGLE destinations, one TCP interface). Multi-hop transport, Links, Resources, other interfaces, WASM/embedded full nodes, mobile, LXMF are out of scope by design.

**Known risks flagged for the implementer:** live wire details in Phase 3/4 (TCP handshake, ratchet-derived message keys) may require reading RNS source and capturing additional vectors — the plan says so at each such gate and never fabricates wire bytes.
