# Reticulum Rust Port — Milestone 7: Platform reach (WASM / embedded / mobile) (full TDD)

> **For Codex:** Full TDD plan expanding M7 from the master program plan. Execute task-by-task, in order. This milestone delivers the three target platforms as REAL runnable nodes (beyond core merely compiling for them). Each platform is an outer crate that wraps the unchanged sans-I/O `reticulum-node` with a platform-specific I/O loop + interface. The node/core do NOT change. Stop for review at each platform's acceptance gate.

**Goal:** Ship `reticulum-wasm` (browser), `reticulum-embedded` (no_std MCU/QEMU), and `reticulum-ffi` (mobile via uniffi) as working nodes. **Acceptance:** each platform runs a node that exchanges an encrypted message with a Python RNS 1.4.1 node through its documented transport, proven by a per-platform gate.

## Design invariant (do not violate)

`reticulum-core` + `reticulum-node` stay sans-I/O and unchanged. Every platform crate supplies: (1) an `EntropySource` backed by that platform's CSPRNG, (2) a `Clock`, (3) one or more transports implementing the byte-moving interface, and (4) an event pump. If a platform needs a node/core change, STOP and surface it — the sans-I/O boundary is the whole point of this architecture.

## Global constraints (inherited)

Target RNS 1.4.1 interop. `reticulum-core`/`node`/`interface` remain `no_std + alloc`. No panics on untrusted input. CSPRNG per platform. TDD where deterministic; per-platform demo/interop gate otherwise. Commit per task.

---

# Part A — `reticulum-wasm` (browser)

**Transport reality:** browsers have no raw TCP/UDP. RNS reachability from a browser uses a WebSocket↔TCP bridge (a small proxy that relays HDLC frames between a WS and a real RNS `TCPServerInterface`). The wasm node speaks HDLC over a WebSocket; the bridge forwards to Python RNS.

### Task M7.1: `reticulum-wasm` crate + WASM entropy/clock

**Files:** `crates/reticulum-wasm/Cargo.toml`, `src/lib.rs`, tests (`wasm-bindgen-test`).

**Interfaces:** `wasm-bindgen` exports. `WasmEntropy` (via `getrandom` with the `js` feature → `crypto.getRandomValues`) implementing `EntropySource`; `WasmClock` (via `js_sys::Date::now`) implementing `Clock`.

- [ ] Manifest: `crate-type=["cdylib"]`, deps `reticulum-core`, `reticulum-node`, `wasm-bindgen`, `js-sys`, `web-sys` (WebSocket, MessageEvent, BinaryType), `getrandom` (feature `js`). Add to CI a `wasm-pack build`/`cargo build --target wasm32-unknown-unknown -p reticulum-wasm` job.
- [ ] TDD (`wasm-bindgen-test`, headless): `WasmEntropy::fill` returns non-zero, varying; `WasmClock::now_secs` is monotonic-ish. Commit `feat(wasm): reticulum-wasm crate + browser entropy/clock`.

### Task M7.2: WebSocket interface + node bindings

**Files:** `crates/reticulum-wasm/src/ws.rs`, `src/node_api.rs`, tests.

**Interfaces:** a `web-sys::WebSocket`-backed transport that HDLC-frames outbound and deframes inbound binary messages (reuse `reticulum-interface::hdlc`), feeding a `Node`. Exported JS API: `new ReticulumNode(identity_hex)`, `register_single_destination(app, aspects) -> dest_hash_hex`, `connect_ws(url)`, `announce()`, `send(dest_hash_hex, text)`, and an `onmessage`/`ondelivered` callback surface. Drive the node on WS message + a `setInterval`-style tick for `node.tick()`.

- [ ] TDD: unit-test the framing bridge logic (HDLC over a mock WS) where possible; the full path is proven by M7.3. Commit `feat(wasm): WebSocket interface + node JS bindings`.

### Task M7.3: WS↔TCP bridge + browser demo + gate

**Files:** `tools/wasm/bridge.py` (WS server ↔ RNS TCP client), `tools/wasm/index.html` (loads the wasm, connects, sends), `tools/interop/run_wasm_interop.sh`, README.

- [ ] `bridge.py`: a WebSocket server that, per WS connection, opens a TCP connection to a Python RNS `TCPServerInterface` and relays HDLC frames both ways verbatim.
- [ ] Demo page: instantiate the node, `connect_ws(bridge_url)`, announce, send a message to a Python RNS destination; display received messages.
- [ ] Gate (headless, e.g. via `wasm-bindgen-test` in a headless browser OR a scripted Playwright/puppeteer run — pick what the environment supports): the browser node exchanges an encrypted message with a Python RNS node through the bridge; assert both directions. Capture evidence. If no headless browser is available in CI, provide the manual demo + a Node.js `ws`-based harness that loads the wasm and runs the same exchange, and gate on that.
- [ ] Commit `test(wasm): browser<->Python RNS message via WS-TCP bridge`.

**Part A acceptance:** wasm builds; the browser/Node harness exchanges a message with Python RNS through the bridge; evidence captured.

---

# Part B — `reticulum-embedded` (no_std MCU / QEMU)

**Target:** a `no_std` node on `thumbv7em-none-eabihf` (real MCU or QEMU `lm3s6965`/`mps2-an385`), using `embassy` for async + a UART/serial transport (KISS framing from M6). Proven against the Rust desktop daemon (or Python RNS) over serial.

### Task M7.4: `reticulum-embedded` crate skeleton + HAL entropy/clock

**Files:** `crates/reticulum-embedded/Cargo.toml`, `src/lib.rs`, `.cargo/config.toml` (runner = QEMU), `memory.x`.

**Interfaces:** `no_std` binary. `EmbeddedEntropy` (from the MCU RNG peripheral or an `embassy` RNG; for QEMU without an RNG, a documented seeded fallback ONLY for the demo — clearly marked non-secure), `EmbeddedClock` (embassy `Instant`). Deps: `embassy-executor`, `embassy-time`, HAL crate for the target, `reticulum-core`, `reticulum-node`, `reticulum-interface` (default no_std features).

- [ ] Build gate: `cargo build -p reticulum-embedded --target thumbv7em-none-eabihf` succeeds. If a QEMU machine is wired, `cargo run` boots. Commit `feat(embedded): reticulum-embedded no_std skeleton + HAL entropy/clock`.

### Task M7.5: UART/KISS transport + embedded node loop

**Files:** `crates/reticulum-embedded/src/uart.rs`, `src/main.rs`, tests (host-side logic tests where possible).

**Interfaces:** an `embassy`-driven UART reader/writer that KISS-frames (M6 `kiss`) packets to/from the `Node`; a main loop pumping inbound → `handle_inbound` → drain `poll_outbound` → UART, plus `node.tick()` on an embassy timer.

- [ ] Gate: the embedded node (QEMU or hardware) announces a destination and exchanges an encrypted message over serial with a host running `reticulumd` configured with a `serial` interface (M6.4). Capture evidence (QEMU serial log). If neither QEMU nor hardware is available, deliver the code + a host-side unit test of the UART/KISS pump logic and mark the live gate as hardware-deferred with exact run instructions. Commit `feat(embedded): UART/KISS node over embassy`.

**Part B acceptance:** embedded crate builds for thumbv7em; the node exchanges a message over serial with a host daemon (or the gate is hardware-deferred with runnable instructions + host-side logic tests green).

---

# Part C — `reticulum-ffi` (mobile via uniffi)

**Target:** `uniffi`-generated Kotlin (Android) + Swift (iOS) bindings exposing Node/Link/Resource so a mobile app drives Reticulum over a TCP interface.

### Task M7.6: `reticulum-ffi` crate + uniffi interface

**Files:** `crates/reticulum-ffi/Cargo.toml`, `src/lib.rs`, `src/reticulum.udl` (or proc-macro uniffi), tests.

**Interfaces:** a `uniffi`-exported façade wrapping a tokio-driven node (reuse `reticulum-tokio`): `ReticulumClient(identity_bytes)`, `register_single_destination`, `connect_tcp(addr)`, `announce`, `send(dest_hash, text)`, and a callback interface for inbound messages / delivery. std crate (`crate-type=["cdylib","staticlib"]`).

- [ ] TDD: uniffi scaffolding builds; a Rust-side test drives the façade (connect two façades over loopback TCP, exchange a message) — this exercises the same surface the mobile bindings expose. Generate the Kotlin + Swift bindings (`uniffi-bindgen`) and check them into `bindings/`. Commit `feat(ffi): uniffi Reticulum client (Kotlin + Swift bindings)`.

### Task M7.7: Mobile sample + gate

**Files:** `tools/mobile/README.md`, a minimal Android (`androidTest`) or a `uniffi` test harness, `tools/interop/run_ffi_interop.sh`.

- [ ] Gate: via the uniffi test harness (or an `androidTest` if the Android SDK/emulator is present), the FFI client exchanges an encrypted message with a Python RNS node over TCP; assert both directions. If no Android/iOS toolchain is available in CI, gate on the Rust-side façade test (M7.6) + document the exact steps to build the `.aar`/`.xcframework` and run the sample. Commit `test(ffi): mobile client<->Python RNS message (or documented device steps)`.

**Part C acceptance:** uniffi bindings build for Kotlin + Swift; the FFI façade exchanges a message with Python RNS (via the harness) or the device gate is documented with the façade test green.

---

## Self-Review

**Coverage vs M7 outline:** WASM full node + browser I/O via WS-TCP bridge (M7.1–M7.3); embedded no_std node over embassy/serial (M7.4–M7.5); mobile uniffi FFI (M7.6–M7.7).

**Placeholder scan:** none. Each platform has a concrete transport (WS bridge, UART/KISS, TCP), CSPRNG source, and clock. Where CI can't host a platform (headless browser, QEMU, Android emulator), the plan specifies a fallback harness AND a documented manual gate — not a silent skip.

**Design invariant honored:** node/core are untouched; each platform crate only supplies entropy + clock + transport + pump. If any task finds it needs a core change, it must surface it (the plan says so) rather than fork the sans-I/O boundary.

**Type consistency:** every platform reuses `EntropySource`, `Clock`, `Node` (`handle_inbound`/`poll_outbound`/`tick`), and `hdlc`/`kiss` framing. The WASM/FFI façades expose the same conceptual API (register/connect/announce/send + callbacks); the embedded node uses the same loop shape as `reticulum-tokio`'s driver.

**Risk:** CI platform availability (browser/QEMU/Android) is the main uncertainty — mitigated by fallback harnesses (Node.js `ws` for wasm, host-side logic tests for embedded, uniffi harness for FFI) so the milestone has runnable gates even in a bare CI, with device/browser gates documented for full environments.
