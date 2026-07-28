# Reticulum Rust Port — Remove WASM, Build a 100% Decentralized TUI (full TDD)

> **For Codex:** Full TDD plan. Execute task-by-task, in order; each ends green with a commit. Fail-first every test. The overriding requirement is **100% decentralization** (see Global Constraints) — any task that would reintroduce a central dependency is a plan violation; stop and flag instead. Stop for review at the acceptance gate (Task D.1).

**Goal:** Remove the browser/WASM stack (which needs a central WebSocket↔TCP bridge) and turn the project into a **terminal UI (TUI)** node that reaches the mesh over fully decentralized, infrastructure-free transports — **AutoInterface** (LAN, zero-config peer discovery) by default, plus serial/LoRa for off-grid radio. No bridge, no hub, no central server.

## Why

The WASM console can never be fully decentralized: browsers cannot open raw TCP/UDP/radio, so every browser node depends on a bridge server (a central point). A native TUI has no such limit — two nodes on a LAN (AutoInterface) or two radios (serial/LoRa) form a mesh with zero infrastructure. This change makes the whole project honestly decentralized.

## Global Constraints (bind every task)

- **100% decentralized — no central components.** The default transport is **AutoInterface** (IPv6 link-local multicast discovery: nodes find each other directly, no server, no config). Serial/LoRa are the off-grid options. **Do NOT** add or keep a bridge, relay-as-a-service, hub, tracker, bootstrap server, DNS, or any component every node must reach. Direct peer-to-peer TCP (each node dials a known peer) is allowed as an *optional* interface, but it is not the default and must not be a required hub. If a task seems to need a central component, stop and flag it.
- **Reuse the existing stack unchanged.** `reticulum-core`/`node`/`interface`/`lxmf` (no_std) and `reticulum-tokio` (Driver + AutoInterface/serial) already implement everything. The TUI is a new front-end over `reticulum-tokio::Driver` — do not modify the sans-I/O core/node.
- **TUI stack:** `ratatui` + `crossterm`. State model is pure and unit-tested; rendering is tested with `ratatui`'s `TestBackend`.
- No panics on untrusted input (inherited). `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt --all -- --check` stay green after every task. The `no_std` crates keep cross-compiling to `wasm32-unknown-unknown` + `thumbv7em-none-eabihf` in CI.
- TDD + frequent commits.

## Existing APIs to reuse (do not reinvent)

- `reticulum-cli` `config`: `Config::load(Option<&Path>)`, `save_or_create_identity(&Path) -> io::Result<Identity>`, `InterfaceConfig` enum (`TcpClient`/`TcpServer`/`Udp`/`Auto`/`Serial`), `IfacSettings`.
- `reticulum-tokio`:
  - `interface::AsyncInterface` (trait: `id`, `recv_packet`, `send_packet`), `with_id(u16)`, `with_ifac(...)`.
  - `auto::AutoInterface::new_with_ports(group_id, discovery_port, data_port, iface_name).await`.
  - `serial::SerialInterface::open(port, baud)` (feature `serial`).
  - `driver::Driver::new_interfaces(node, Vec<Box<dyn AsyncInterface>>, events_tx) -> (Driver, DriverHandle)` (and `new_dynamic` for TCP servers — not needed for the decentralized default).
  - `DriverHandle`: `announce_all(&[u8])`, `send([u8;16], &[u8])`, `send_with_receipt`, `send_group`, `send_plain`, `establish_link([u8;16]) -> [u8;16]`, `link_send`, `close_link`, `lxmf_send_direct`/`lxmf_send_opportunistic`, `snapshot() -> DriverSnapshot`, `request_path`, `shutdown`.
  - `DriverSnapshot { identity_hash:[u8;16], interfaces:Vec<InterfaceSnapshot{id,online,rx_packets,rx_bytes,tx_packets,tx_bytes}>, paths:Vec<PathSnapshot{destination,interface,next_hop_transport_id,hops,expires_at,timestamp}> }`.
  - `reticulum_node::Event` on the events channel: `Announce{dest_hash,hops}`, `Message{dest_hash,plaintext}`, `Delivered{packet_hash}`, `LinkEstablished/LinkData/LinkClosed`, `LxmfMessage{...}`, `Error(..)`.

---

# PHASE A — Remove the browser/WASM stack

### Task A.1: Delete WASM + bridge + Pages, fix the workspace

**Files:**
- Delete: `crates/reticulum-wasm/`, `crates/reticulum-bridge/`, `tools/wasm/`, `.github/workflows/pages.yml`, `tools/interop/run_wasm_interop.sh`
- Modify: root `Cargo.toml` (remove both members), `README.md` (drop WASM/bridge/Pages sections)

- [ ] **Step 1: Remove**
```bash
git rm -r crates/reticulum-wasm crates/reticulum-bridge tools/wasm \
  .github/workflows/pages.yml tools/interop/run_wasm_interop.sh
```
- [ ] **Step 2:** Edit root `Cargo.toml` `members` — remove `"crates/reticulum-wasm"` and `"crates/reticulum-bridge"`.
- [ ] **Step 3:** Remove WASM/bridge/Pages content from `README.md` (the "Browser console (WASM)" section, the `reticulum-wasm`/`reticulum-bridge` rows in the crate table, the wasm interop-gate line). Leave a placeholder note that a TUI replaces it (filled in by Task D.2).
- [ ] **Step 4: Verify** the workspace is intact without them:
```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p reticulum-core -p reticulum-interface -p reticulum-node -p reticulum-lxmf --target wasm32-unknown-unknown
cargo build -p reticulum-core -p reticulum-interface -p reticulum-node -p reticulum-lxmf --target thumbv7em-none-eabihf
cargo fmt --all -- --check
```
Expected: all pass; no dangling references to the removed crates.
- [ ] **Step 5: Commit** `chore: remove WASM console + WS/TCP bridge + Pages (browser stack needs a central bridge)`.

> `.github/workflows/ci.yml` cross-compiles only the no_std crates, so it needs no change. Confirm no other file references `reticulum-wasm`/`reticulum-bridge`/`tools/wasm` (`grep -rn "reticulum-wasm\|reticulum-bridge\|tools/wasm" --include=*.rs --include=*.toml --include=*.md --include=*.yml .`).

---

# PHASE B — Expose reusable runtime from reticulum-cli

The TUI must reuse the CLI's identity/config + interface-and-driver wiring (DRY). Turn `reticulum-cli` into a lib + bin.

### Task B.1: `reticulum-cli` library surface

**Files:**
- Create: `crates/reticulum-cli/src/lib.rs`
- Modify: `crates/reticulum-cli/Cargo.toml` (add `[lib]`), `crates/reticulum-cli/src/main.rs` (consume the lib), `crates/reticulum-cli/src/config.rs` (make `pub`), and factor the interface-building loop out of `main.rs`.

**Interfaces (produced):**
- `pub mod config;` (already exists — re-export `Config`, `InterfaceConfig`, `IfacSettings`, `save_or_create_identity`).
- `pub async fn build_interfaces(config: &Config) -> io::Result<Vec<Box<dyn AsyncInterface>>>` — extract the exact match arms already in `main.rs` that construct `TcpClient`/`Udp`/`Auto`/`Serial` interfaces (skip `TcpServer` here; server mode stays in the bin's `new_dynamic` path). This is the shared builder the TUI calls.

- [ ] **Step 1:** Failing test in `crates/reticulum-cli/src/lib.rs` (or `tests/`): a `Config` with a single `Auto` interface produces one `AsyncInterface` from `build_interfaces` (assert `.len() == 1`). Use a config that binds AutoInterface on non-default ports so the test is host-safe.
- [ ] **Step 2:** Run (fail — `build_interfaces` not found). 
- [ ] **Step 3:** Add `[lib]` to `Cargo.toml` (`name = "reticulum_cli"`, `path = "src/lib.rs"`) alongside the existing `[[bin]]`. Create `lib.rs` re-exporting `config` and defining `build_interfaces` by moving the interface-construction loop out of `main.rs`; `main.rs` now calls it. Keep the existing daemon behavior identical.
- [ ] **Step 4:** Run (pass). `cargo test -p reticulum-cli`, clippy, `cargo run -p reticulum-cli -- --help` still works.
- [ ] **Step 5: Commit** `refactor(cli): expose config + build_interfaces as a library for reuse`.

---

# PHASE C — The TUI

### Task C.1: `reticulum-tui` crate + decentralized default config

**Files:**
- Modify: root `Cargo.toml` (add member `crates/reticulum-tui`)
- Create: `crates/reticulum-tui/Cargo.toml`, `crates/reticulum-tui/src/main.rs` (stub), `crates/reticulum-tui/src/config.rs`

**Interfaces:**
- `pub fn default_config() -> reticulum_cli::config::Config` — a config whose ONLY interface is `Auto` (AutoInterface), so a fresh TUI is decentralized out of the box with no flags. App name/aspects default to something like `("reticulum_tui", ["chat"])`.
- CLI flags (via `clap` or hand-rolled): `--config <path>` (optional TOML, same schema as the daemon), `--identity <path>`. With no config, use `default_config()` (AutoInterface only).

- [ ] **Step 1:** `Cargo.toml` deps: `reticulum-tokio`, `reticulum-node`, `reticulum-core`, `reticulum-cli` (lib), `tokio` (rt-multi-thread, macros, sync, time), `ratatui = "0.28"`, `crossterm = "0.28"`. Optional `serial` feature forwarding to `reticulum-tokio/serial`.
- [ ] **Step 2:** Failing test: `default_config()` has exactly one interface and it is `InterfaceConfig::Auto{..}` (assert the variant). This encodes the decentralization default.
- [ ] **Step 3:** Implement `config.rs` (`default_config`) + a `main.rs` stub that parses flags and prints the resolved config (no TUI yet).
- [ ] **Step 4:** Run (pass); `cargo build -p reticulum-tui`; clippy.
- [ ] **Step 5: Commit** `feat(tui): reticulum-tui crate with AutoInterface-only default config`.

### Task C.2: App state model (pure, unit-tested)

**Files:** `crates/reticulum-tui/src/app.rs`, tests inline.

**Interfaces:** a pure `AppState` with NO I/O, mutated by typed inputs so it is fully unit-testable:
- `pub struct Peer { pub dest: [u8;16], pub hops: u8, pub seen: u32, pub last_secs: u64 }`
- `pub struct AppState { pub identity: [u8;16], pub roster: Vec<Peer>, pub selected: usize, pub log: Vec<LogEntry>, pub input: String, pub interfaces: Vec<InterfaceSnapshot>, pub focus: Focus }`
- `pub enum LogKind { Sys, Tx, Rx, Announce, Delivered, Err }`, `pub struct LogEntry { pub kind: LogKind, pub at_secs: u64, pub text: String }`
- Methods (all pure): `on_announce(dest, hops, now)` (upsert roster, keep sorted by last-seen), `on_message(dest, text, now)`, `on_delivered(hash, now)`, `on_error(text, now)`, `apply_snapshot(DriverSnapshot, now)` (refresh interfaces + merge paths into roster), `select_next()/select_prev()`, `selected_peer() -> Option<[u8;16]>`, `push_input(char)/backspace()/take_input() -> String`, `log(kind, text, now)`.

- [ ] **Step 1:** Failing tests: two `on_announce` for the same dest → one roster entry, `seen == 2`, sorted by recency; `select_next` wraps; `apply_snapshot` adds paths not already in the roster; `take_input` clears the buffer.
- [ ] **Step 2–4:** Implement; run (pass); clippy. Keep `AppState` free of ratatui/tokio types (pure logic).
- [ ] **Step 5: Commit** `feat(tui): pure app-state model for roster, log, input, selection`.

### Task C.3: Rendering (ratatui, TestBackend snapshot tests)

**Files:** `crates/reticulum-tui/src/ui.rs`, tests inline.

**Interfaces:** `pub fn draw(frame: &mut ratatui::Frame, state: &AppState)` — a layout with: a **status bar** (identity fingerprint, interface list + online + rx/tx counts, peer count, "DECENTRALIZED · AutoInterface" indicator), a **roster** pane (peers: hash, hops, seen, last — selected row highlighted), a **log** pane (colored by `LogKind`), and an **input** line showing the current target + `state.input`.

- [ ] **Step 1:** Failing test using `ratatui::backend::TestBackend` + `Terminal::draw`: render an `AppState` seeded with one peer + one log line and assert the `Buffer` contains the peer hash substring and the status indicator text. (Assert on buffer content, not exact geometry.)
- [ ] **Step 2–4:** Implement `draw`; run (pass); clippy.
- [ ] **Step 5: Commit** `feat(tui): ratatui rendering with status/roster/log/input panes`.

### Task C.4: Event loop — crossterm input + driver events + snapshots

**Files:** `crates/reticulum-tui/src/main.rs`, `crates/reticulum-tui/src/runtime.rs`, tests where feasible.

**Interfaces:** the async run loop:
1. Load identity + config (`default_config()` if none), build node (register a SINGLE destination + a PLAIN one), `build_interfaces(&config)`, `Driver::new_interfaces(...)`, spawn `driver.run()`, get `DriverHandle` + `events_rx`.
2. Enter raw mode + alternate screen (crossterm); guarantee restore on exit/panic (RAII guard).
3. `tokio::select!` over: crossterm key events (via `crossterm::event::EventStream`), `events_rx.recv()` (map `Event` → `AppState` mutations), and a `tokio::time::interval` tick (poll `handle.snapshot()` → `apply_snapshot`, refresh clocks, redraw). Redraw on any change.
4. Keybindings: printable chars → `push_input`; Backspace; **Enter** → `handle.send(selected_peer, input)` (or `send_plain`/`link_send` per a mode toggle) + log Tx; **↑/↓** or Tab → select peer; **a** → `announce_all`; **q**/Ctrl-C → shutdown + restore terminal; **?** → help overlay. Announce automatically on startup and on an interval (decentralized presence).

- [ ] **Step 1:** A unit test for the pure key→intent mapping (extract `fn key_to_action(KeyEvent, &AppState) -> Action` and test: Enter with non-empty input + a selected peer → `Action::Send{dest,text}`; 'q' → `Action::Quit`; char → `Action::Input(c)`). The async loop itself is covered by the D.1 gate.
- [ ] **Step 2–4:** Implement the loop + terminal guard; run the unit test (pass); `cargo build -p reticulum-tui`; clippy. Manual smoke: `cargo run -p reticulum-tui` shows the UI, announces, and exits cleanly restoring the terminal.
- [ ] **Step 5: Commit** `feat(tui): async event loop wiring input, driver events, snapshots`.

### Task C.5: Messaging wired end to end (in-process)

**Files:** `crates/reticulum-tui/src/runtime.rs` + a test harness, tests.

- [ ] **Step 1:** Integration test (no terminal): build two nodes + drivers connected over an **in-memory or loopback AutoInterface pair on distinct ports**, drive them through the same `Action`/handle path the TUI uses — node A announces, B's `AppState` gains A in its roster (via `on_announce`), B sends to A, A's `AppState` logs the received message. Assert the roster + log transitions. (This exercises the TUI's runtime glue without a real terminal.)
- [ ] **Step 2–4:** Implement any glue needed; run (pass); `cargo test -p reticulum-tui`; clippy; fmt.
- [ ] **Step 5: Commit** `test(tui): two-node messaging through the TUI runtime`.

---

# PHASE D — Decentralization gate + docs

### Task D.1: Live decentralized interop gate (acceptance)

**Files:** `tools/interop/run_decentralized_interop.sh`, README evidence.

- [ ] **Step 1:** Script two **native** nodes on one host communicating ONLY over **AutoInterface** (distinct discovery/data ports to avoid the one-host bind clash — AutoInterface::new_with_ports supports this), with **no bridge, no TCP server, no hub**. Use the `reticulumd` daemon (or a tiny headless harness reusing `build_interfaces`) for both ends: node A announces + registers a destination; node B learns A's path purely via AutoInterface multicast and sends it an encrypted message; assert A receives it. Then reverse. If a single host cannot run two AutoInterface instances even on distinct ports, fall back to a two-network-namespace / documented two-host run — but the transport MUST remain AutoInterface (no bridge).
- [ ] **Step 2:** Assert the run uses zero central components (grep the configs: no `TcpServer`, no bridge, no external host). Exit 0 only if the message arrived over AutoInterface.
- [ ] **Step 3:** Capture evidence into the README.
- [ ] **Step 4: Commit** `test(interop): 100% decentralized AutoInterface message exchange (no bridge/hub)`.

### Task D.2: Docs — README rewrite

**Files:** `README.md`, `crates/reticulum-tui/README.md`

- [ ] Rewrite the README: the project is now a **decentralized TUI mesh node**. Cover: run `cargo run -p reticulum-tui` (AutoInterface by default → two machines on a LAN mesh with zero config), keybindings, serial/LoRa for off-grid, and an explicit "No central components" section (no bridge, no hub, no DNS/CA, self-generated addresses). Remove all WASM/bridge/Pages references. Add the `reticulum-tui` crate to the crate table; drop `reticulum-wasm`/`reticulum-bridge`. Point to `run_decentralized_interop.sh` as the decentralization proof.
- [ ] **Commit** `docs: README for the decentralized TUI (WASM removed)`.

**Acceptance:** `cargo test --workspace` + clippy `-D warnings` + fmt + no_std cross-compiles all green; `run_decentralized_interop.sh` exits 0 with two nodes messaging over AutoInterface and **no central component**; `cargo run -p reticulum-tui` launches a working terminal node that announces, lists mesh clients, and sends/receives messages.

---

## Self-Review

**Coverage:** remove browser stack (A.1); reusable runtime (B.1); TUI crate + decentralized default (C.1); pure state model (C.2); rendering (C.3); event loop + keybinds (C.4); end-to-end messaging (C.5); decentralization gate (D.1); docs (D.2).

**Placeholder scan:** none. The one-host AutoInterface constraint (M6 known limit) is handled explicitly in D.1 (distinct ports / documented two-host fallback), not glossed.

**Decentralization is enforced, not assumed:** the default config is AutoInterface-only (C.1 test asserts the variant), the acceptance gate forbids central components (D.1 asserts no TcpServer/bridge), and the Global Constraints forbid reintroducing any hub/bridge/tracker. Direct P2P TCP remains an optional non-default interface.

**Type consistency:** `AppState`/`Peer`/`LogKind`, `build_interfaces`, `default_config`, `key_to_action`/`Action`, and the `DriverHandle`/`DriverSnapshot`/`Event` types are used consistently across cli-lib → tui. The TUI reuses `reticulum-tokio::Driver` unchanged; core/node are untouched (sans-I/O boundary preserved).

**Risk:** the TUI event loop is the least unit-testable piece — mitigated by extracting pure helpers (`AppState`, `key_to_action`) that ARE unit-tested (C.2/C.4) and by the D.1 live gate. ratatui/crossterm 0.28 API drift: pin the versions in Cargo.toml and adjust to the actual API at build time (the TestBackend + EventStream shapes are stable).
