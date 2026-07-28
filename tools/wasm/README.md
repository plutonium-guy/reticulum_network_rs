# Reticulum WASM node — browser console

Two pages ship here:

- **`app.html`** — the operator console UI with a passphrase-encrypted identity
  vault (login). This is the app for humans.
- **`index.html`** — a minimal, headless test harness driven by
  `run_wasm_interop.sh` (exposes `window.__reticulumEvidence`). Do not use it
  as the UI; it exists for the automated interop gate.

## Why a bridge?

Browsers cannot open raw TCP/UDP, so a WASM Reticulum node speaks HDLC frames
over a **WebSocket** and a small proxy (`bridge.py`) relays them to a real RNS
`TCPServerInterface`. Mesh reachability from the browser = WASM ⇄ WS ⇄ bridge ⇄
RNS TCP.

## Run it

```bash
# 1. Build the wasm package (once, or after core changes)
wasm-pack build crates/reticulum-wasm --target web --out-dir ../../tools/wasm/pkg

# 2. Start a Python RNS node with a TCPServerInterface, then the bridge:
python tools/wasm/bridge.py            # WS :8765  ->  RNS TCP

# 3. Serve this directory (any static server; browsers block file:// modules)
python -m http.server --directory tools/wasm 8080

# 4. Open the console
open http://127.0.0.1:8080/app.html
```

## Login / identity vault

- On first use, **Forge identity**: a 64-byte keypair (32B X25519 ‖ 32B Ed25519)
  is generated in-browser with `crypto.getRandomValues`, then sealed with your
  passphrase (**PBKDF2-SHA256, 210k iters → AES-256-GCM**) and stored **only in
  this browser's `localStorage`**. It never leaves the device.
- Returning: **Unlock** with the same passphrase. A wrong passphrase fails the
  AES-GCM auth tag and is rejected — there is no recovery, so keep it.
- **Import hex** loads an existing 128-hex identity; **Wipe vault** deletes the
  stored keypair from this device.
- **Lock** clears the in-memory identity + session and returns to the vault.

## Console

Connect the bridge, register a SINGLE destination (`app` + `aspects`), announce
it, then transmit encrypted messages to a peer's 32-hex destination hash.
Inbound messages, delivery proofs, and errors stream into the traffic log.

Security note: the vault protects the identity **at rest in this browser**. It
is a client-side keystore for the user's own node, not an authentication server.
