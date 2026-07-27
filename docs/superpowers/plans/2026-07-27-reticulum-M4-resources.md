# Reticulum Rust Port — Milestone 4: Resources (full TDD)

> **For Codex:** Full TDD plan expanding M4 from the master program plan. Execute task-by-task, in order; each ends green with a commit. Fail-first every test. Every wire detail is confirmed against a captured RNS 1.4.1 vector and/or the RNS source (`.venv/lib/python3.14/site-packages/RNS/Resource.py`, `Packet.py`, `vendor/umsgpack.py`) — never guessed. Resources are large and stateful; keep the transfer state machine sans-I/O (time via `Clock`). Stop for review at the milestone gate (Task M4.10).

**Goal:** Transfer arbitrary-size data over an established Link as an RNS Resource — advertisement, hashmap-driven part requests, windowed part transfer with retries, integrity + proof, reassembly, and optional bz2 compression. **Acceptance:** a multi-KB payload transfers intact Rust↔Python RNS 1.4.1 over a link, both directions (`tools/interop/run_resource_interop.sh` exits 0 with captured evidence).

## Two architectural decisions (baked in — do not deviate)

1. **Compression (bz2) is `std`-feature-gated.** RNS auto-compresses with bz2 (`Resource.compressed` flag bit). No viable `no_std` bz2 exists.
   - `reticulum-core` gets a `compression` cargo feature (OFF by default, so the crate stays `no_std`). When ON (enabled by the std crates via the `bzip2` crate), Resources compress outbound (when it helps + under the size limit) and decompress compressed inbound.
   - With the feature OFF (no_std builds): send only UNCOMPRESSED resources (clear the compressed flag); a compressed INBOUND resource returns `CoreError::Unsupported` (add this variant) rather than panicking. Document this in the module docs.
   - The Resource wire protocol (advertisement, hashmap, parts, proofs, flow control) is ALWAYS in the no_std core/node — only the bz2 codec is feature-gated.
2. **msgpack via `rmp`** (`rmp` crate, `no_std` + `alloc`, `default-features=false`). The `ResourceAdvertisement` is a msgpack map; use `rmp` to encode/decode it. Map field order is irrelevant for interop (msgpack maps are unordered) — validate by round-tripping a captured RNS advertisement, not by byte-identity.

## RNS 1.4.1 facts (from source — authoritative, still vector-verify)

- **Packet contexts** (over a link; add to `packet.rs`): `RESOURCE = 0x01` (a part), `RESOURCE_ADV = 0x02` (advertisement), `RESOURCE_REQ = 0x03` (part request), `RESOURCE_HMU = 0x04` (hashmap update), `RESOURCE_PRF = 0x05` (proof), `RESOURCE_ICL = 0x06` (initiator cancel), `RESOURCE_RCL = 0x07` (receiver cancel). All carried as link data packets (dest_hash = link_id, LINK dest_type) with these contexts.
- **ResourceAdvertisement** = msgpack dict with keys: `t` transfer(compressed/encrypted) size, `d` total uncompressed data size, `n` number of parts, `h` resource hash, `r` random hash, `o` original (first-segment) hash, `i` segment index, `l` total segments, `q` (request/expected — confirm), `m` hashmap (bytes), `f` flags. `flags f = (x<<5)|(p<<4)|(u<<3)|(s<<2)|(c<<1)|e` where `e`=encrypted, `c`=compressed, `s`=split, `u`,`p`,`x`=other bits (read `ResourceAdvertisement.__init__`/`unpack` for exact meanings). Confirm the full key set + flag bit meanings from `Resource.py:1247-1360`.
- **Constants:** `WINDOW=4`, `WINDOW_MIN=2`, `WINDOW_MAX_SLOW=10`, `WINDOW_MAX_FAST=75`, `MAPHASH_LEN=4`, `RANDOM_HASH_SIZE=4`, `MAX_EFFICIENT_SIZE=1MiB-1` (segment size), `SDU = Packet.MDU` (part size), `MAX_RETRIES=16`, `HASHMAP_IS_EXHAUSTED=0xFF`. Read exact values from `Resource.py:58-140`.
- **Map hash:** each part has a `MAPHASH_LEN`(4)-byte map hash = truncated part hash (read `get_map_hash`/hashmap build). The hashmap in the advertisement is the concatenation of all parts' map hashes.
- **Resource hash:** `h` = hash over the (compressed) data + random hash; `o` = original/first-segment hash. Read the exact hashing (`Resource.__init__`).
- **Part request** (`RESOURCE_REQ`, `Resource.py:971`): `request_data` = resource hash + msgpack([...requested indices/hashes...]); confirm exact structure from source.
- **Hashmap update** (`RESOURCE_HMU`, line 1063): `hash + msgpack([segment, hashmap])`.
- **Proof** (`RESOURCE_PRF`, PROOF packet, line 762): proof over the full received resource; receiver sends it on completion. Confirm `expected_data`/`proof_data` layout (lines 658, 762).
- **Cancels:** `RESOURCE_ICL`/`RESOURCE_RCL` carry the resource hash.
- **Segmentation:** data > `MAX_EFFICIENT_SIZE` splits into segments (each its own advertisement, `i`/`l`); for M4, support single-segment resources first (payload ≤ ~1 MiB) and add multi-segment only if the interop test needs it — note this scope in Task M4.4.

---

## File structure

```
crates/reticulum-core/
  Cargo.toml        + rmp (no_std) dep; + [features] compression = ["bzip2"]; optional bzip2
  src/packet.rs     + RESOURCE* context consts; resource link-packet constructors
  src/resource.rs   NEW: ResourceAdvertisement (pack/unpack), map hashes, part split/reassemble,
                    hash/random-hash, flags; compression behind `compression` feature
  src/lib.rs        + pub mod resource; + CoreError::Unsupported
  tests/vectors.rs
crates/reticulum-node/
  src/resource_state.rs  NEW: outbound + inbound Resource transfer state machines (windowed,
                         retries via Clock), keyed by resource hash within a link
  src/node.rs            + send_resource / handle resource contexts / emit Resource events / tick integration
  src/lib.rs             + Event::{ResourceStarted,ResourceProgress,ResourceComplete,ResourceFailed}
crates/reticulum-tokio/  driver: resource commands/events; enable `compression` feature
crates/reticulum-cli/    send-file / receive-file subcommands; enable `compression` feature
tools/
  capture_vectors.py     + resource_advertisement.json, resource_maphash.json, (small) resource_flow vectors
  interop/run_resource_interop.sh, resource_peer.py
vectors/
  resource_advertisement.json, resource_maphash.json, resource_proof.json  NEW
```

## Global constraints (inherited)

Target RNS 1.4.1; core/node stay `no_std + alloc` (compression feature OFF by default) and cross-compile to wasm32 + thumbv7em; sans-I/O (randomness via `EntropySource`, time via `Clock`); no panics on untrusted input; TDD + vector-driven; commit per task.

---

### Task M4.1: `CoreError::Unsupported`, resource contexts + link-packet constructors

**Files:** `crates/reticulum-core/src/lib.rs`, `src/packet.rs`, tests.

- [ ] Add `CoreError::Unsupported`. Add context consts `RESOURCE=0x01`, `RESOURCE_ADV=0x02`, `RESOURCE_REQ=0x03`, `RESOURCE_HMU=0x04`, `RESOURCE_PRF=0x05`, `RESOURCE_ICL=0x06`, `RESOURCE_RCL=0x07`. Add `Packet::link_context(link_id, context, ciphertext)` (a link data packet with a given context; note link payloads are ALSO keyed-Token-encrypted like link data — confirm resource parts/adv are sent through `link.encrypt`, i.e. the RESOURCE_* packet `data` is the keyed-Token seal of the plaintext resource bytes). TDD: constructor sets packet_type=DATA, correct context, dest_hash=link_id, decode round-trips. Commit.

> Confirm in `Resource.py`/`Link` whether advertisement/parts go through `link.encrypt` (keyed Token) — they do (resource traffic rides the encrypted link). So every RESOURCE_* payload is `seal_with_key(link.derived_key, plaintext, iv)`; the node layer seals on send and opens on receive before dispatching by context.

### Task M4.2: `rmp` dependency + ResourceAdvertisement pack/unpack

**Files:** `crates/reticulum-core/Cargo.toml`, `src/resource.rs`, `capture_vectors.py`, `vectors/resource_advertisement.json`, tests.

**Interfaces:** `pub struct ResourceAdvertisement { t,d:u64, n:u32, h:Vec<u8>, r:Vec<u8>, o:Vec<u8>, i:u32, l:u32, m:Vec<u8>, f:u8, /* + any confirmed keys */ }`; `pub fn pack(&self) -> Vec<u8>` (msgpack map); `pub fn unpack(data:&[u8]) -> Result<ResourceAdvertisement, CoreError>`.

- [ ] **Step 1:** `capture_vectors.py` → `resource_advertisement.json`: build an RNS `Resource` from fixed data over a stub link, call `ResourceAdvertisement(res).pack()`, record `{ packed_hex, fields:{t,d,n,h,r,o,i,l,f,m} }`.
- [ ] **Step 2:** Failing test: `unpack(packed_hex)` yields the recorded fields; and `pack(unpack(x))` re-unpacks to the same fields (round-trip; not byte-identity).
- [ ] **Step 3–4:** Add `rmp` (no_std, alloc) dep; implement pack/unpack; run (pass); clippy; cross-compile (feature off). Commit `feat(core): resource advertisement msgpack pack/unpack`.

### Task M4.3: Resource hashing, random hash, map hashes, part split/reassemble

**Files:** `src/resource.rs`, `capture_vectors.py`, `vectors/resource_maphash.json`, tests.

**Interfaces:** `pub fn split_parts(data:&[u8], sdu:usize) -> Vec<Vec<u8>>`; `pub fn map_hash(part:&[u8]) -> [u8;4]`; `pub fn hashmap(parts:&[Vec<u8>]) -> Vec<u8>` (concat of map hashes); `pub fn resource_hash(...) -> Vec<u8>` + `random_hash`; `pub fn reassemble(parts) -> Vec<u8>`. Match RNS exactly (read `Resource.__init__`, `get_map_hash`).

- [ ] Vector `resource_maphash.json`: fixed data → RNS parts + map hashes + resource hash. TDD: our `map_hash`/`hashmap`/`resource_hash` reproduce them byte-exact; `reassemble(split_parts(d))==d`. Commit.

### Task M4.4: Outbound resource state machine (advertise + serve parts)

**Files:** `crates/reticulum-node/src/resource_state.rs`, tests (in-memory).

**Interfaces:** `OutboundResource::new(data, link_key, sdu, rng, clock_now) -> (Self, advertisement_packet_plaintext)`; `on_request(req) -> Vec<part_packets>`; `on_proof(proof) -> completed?`; window/retry bookkeeping via injected now. Single-segment scope for M4 (payload ≤ MAX_EFFICIENT_SIZE); if the live test needs multi-segment, add segmentation in a follow-up task M4.4b (note it, don't silently skip).

- [ ] TDD: create outbound resource from fixed data → advertisement fields correct (n parts, hashmap); simulate a part request → correct part packets returned; simulate proof → marked complete. Commit.

### Task M4.5: Inbound resource state machine (request parts, reassemble, prove)

**Files:** `crates/reticulum-node/src/resource_state.rs`, tests.

**Interfaces:** `InboundResource::from_advertisement(adv) -> Self`; `next_request(window, now) -> Option<request_packet>`; `on_part(part) -> Progress`; `is_complete() -> bool`; `finalize() -> Result<Vec<u8>, CoreError>` (verify hashmap + resource hash, decompress if compressed+feature-on else `Unsupported`); `proof_packet() -> Vec<u8>`.

- [ ] TDD: feed an advertisement + the parts (from an OutboundResource in the same test) → requests generated, parts accepted, `finalize()` returns the original data, integrity verified; a corrupted part is rejected. Commit.

### Task M4.6: Windowed flow control + retries + timeouts

**Files:** `crates/reticulum-node/src/resource_state.rs`, tests.

- [ ] Implement adaptive window (`WINDOW`..`WINDOW_MAX`), part timeouts (`PART_TIMEOUT_FACTOR` × RTT via `Clock`), `MAX_RETRIES`, and hashmap-update (`RESOURCE_HMU`) for maps too large for one advertisement. TDD with `TestClock`: dropped part → retried after timeout; exceeding MAX_RETRIES → `ResourceFailed`; window grows/shrinks per rate. Commit.

### Task M4.7: Compression (std feature)

**Files:** `crates/reticulum-core/Cargo.toml` (`[features] compression=["dep:bzip2"]`), `src/resource.rs`, tests.

- [ ] Behind `#[cfg(feature="compression")]`: bz2 compress on send (only if it reduces size and ≤ limit; set the `c` flag), bz2 decompress on `finalize` when `c` set. Feature-off: never set `c`; `finalize` of a `c`-flagged resource returns `Unsupported`. TDD (feature on): compress→decompress round-trip; a resource compressed by RNS (capture a compressed advertisement+data vector) decompresses to the original. Run tests with `--features compression`. Keep default (no feature) cross-compiling to no_std. Commit.

### Task M4.8: Node integration (send_resource + context dispatch + events)

**Files:** `crates/reticulum-node/src/node.rs`, `src/lib.rs`, tests.

**Interfaces:** `Node::send_resource<R>(link_id, data, rng) -> Result<[u8;? ] resource_hash, NodeError>`; in `handle_inbound`, after opening a link data packet, dispatch by context to the resource state machines (adv→create inbound + emit `ResourceStarted`; req→outbound serves parts; part→inbound progress + `ResourceProgress`; prf→outbound complete; hmu/icl/rcl handled). Emit `Event::{ResourceStarted{hash,size}, ResourceProgress{hash,fraction}, ResourceComplete{hash,data}, ResourceFailed{hash}}`. Wire `node.tick()` to drive resource timeouts/retries.

- [ ] TDD: two in-memory nodes with an established link (reuse M3 link test setup) transfer a multi-KB blob end to end → receiver emits `ResourceComplete` with identical bytes; progress events fire. Commit.

### Task M4.9: Driver + CLI wiring

**Files:** `crates/reticulum-tokio/src/driver.rs`, `crates/reticulum-cli` (enable `compression` feature), tests.

- [ ] `DriverHandle::send_resource(link_id, data)`; surface Resource events; CLI `send-file <link_id> <path>` + `receive-file <out_dir>` (writes completed resources). Driver-level test over loopback TCP transfers a file. Commit.

### Task M4.10: Live interop gate (Milestone 4 gate)

**Files:** `tools/interop/resource_peer.py`, `run_resource_interop.sh`, README.

- [ ] `resource_peer.py`: RNS program that (A) accepts a link + receives a Resource and writes it, and (B) establishes a link + sends a Resource from a file.
- [ ] `run_resource_interop.sh`: **Rust→Python** (Rust sends a multi-KB file over a link, Python receives identical bytes — verify sha256) and **Python→Rust** (reverse). Test BOTH an uncompressed and a compressible payload (to exercise bz2 both ways). Exit 0 only if all transfers match; capture evidence.
- [ ] Run it; capture evidence in README. Commit `test(interop): live Rust<->Python RNS resource transfer`.

> If transfers fail: diff the advertisement fields / map hashes / proof against RNS-captured vectors for the same data. Common culprits: flag bits (compressed/encrypted), map-hash algorithm, resource-hash input, or msgpack key set. Vectors are authoritative.

**M4 acceptance:** `cargo test --workspace` green; `cargo test -p reticulum-core --features compression` green; clippy `-D warnings` clean; no_std cross-compile (default features) green; `run_resource_interop.sh` exits 0 with sha256-matched transfers both directions + committed evidence.

---

## Self-Review

**Coverage vs M4 outline:** hashing+segmentation+map hashes (M4.3), compression std-gated (M4.7), advertisement + accept (M4.2/M4.5), windowed transfer + part proofs + retransmit (M4.4/M4.5/M4.6), reassembly + integrity + completion (M4.5), node/driver/CLI wiring (M4.8/M4.9), live interop (M4.10). Multi-segment (>1 MiB) is explicitly scoped as an optional follow-up (M4.4) — single-segment first, matching typical payloads.

**Placeholder scan:** none. Exact msgpack keys, flag-bit meanings, map-hash/resource-hash algorithms, and part-request/proof layouts are marked "confirm from `Resource.py`" with a captured vector as the oracle — verification steps, not deferred work.

**Type consistency:** `ResourceAdvertisement`, `map_hash`/`hashmap`/`resource_hash`/`split_parts`/`reassemble`, `OutboundResource`/`InboundResource`, `seal_with_key`/`open_with_key` (from M3), and `Event::Resource*` are named consistently core→node→driver→cli. Resource traffic reuses the M3 keyed-Token link cipher.

**Architectural decisions flagged:** (1) bz2 compression is a `compression` cargo feature (std only; no_std sends uncompressed, errors on compressed inbound via `CoreError::Unsupported`) — keeps core no_std; (2) msgpack via `rmp` (no_std). Both are called out at their tasks and in the constraints so they are not silent.

**Risk:** the resource flow control (windowing/retries) is the most stateful code in the project so far — the sans-I/O `Clock`-driven design keeps it deterministically testable (M4.6). The live gate (M4.10) is the real proof; the in-memory node test (M4.8) must pass first.
