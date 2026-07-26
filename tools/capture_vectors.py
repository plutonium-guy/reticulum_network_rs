#!/usr/bin/env python3
"""Capture byte-exact test vectors from Python RNS 1.4.1.

Run inside a venv with `pip install rns==1.4.1`. Writes vectors/*.json.

Deterministic where RNS allows fixed key material (identity keys are derived
from fixed seeds below, so identity.json and destination.json are
byte-for-byte reproducible across runs). Several fields are inherently
ephemeral and are captured as-produced rather than pinned:
  - `token.json`'s ciphertext: `Identity.encrypt()` generates a fresh
    ephemeral X25519 key internally on every call, with no parameter to
    pin it.
  - `packet_data.json`'s `bytes`/`data`: RNS.Destination.encrypt() for a
    SINGLE destination calls `Identity.encrypt()` too, so every DATA
    packet is encrypted with a newly derived ephemeral AES-256 key by
    design (this is what gives Reticulum per-packet forward secrecy) --
    the ciphertext differs on every run even with a fixed identity.
  - `announce.json`'s `random_hash`: generated internally by
    `Destination.announce()` from `os.urandom` plus a timestamp.
The Rust side validates these by *parsing* the captured vector (structure,
lengths, and round-trip decrypt/verify against the accompanying fixed
plaintext/identity), not by regenerating the random parts byte-for-byte.

RNS attribute/method names actually used here (verified against the RNS
1.4.1 sources under `.venv/lib/python*/site-packages/RNS/`):
  - Identity: `Identity.from_bytes(prv_bytes)`, `idty.prv_bytes`,
    `idty.sig_prv_bytes`, `idty.get_public_key()`, `idty.hash`.
  - Destination: `RNS.Destination(idty, RNS.Destination.IN,
    RNS.Destination.SINGLE, app_name, *aspects)`, `dest.name_hash`,
    `dest.hash`. Direction must be `IN` (not `OUT`) because only `IN`
    destinations can call `.announce()`.
  - Token/AES: there is no `Token.AES_KEY_SIZE` constant in RNS 1.4.1. The
    encryption sub-key RNS derives and feeds to `RNS.Cryptography.AES` is
    32 bytes (see `RNS/Cryptography/Token.py`: a 64-byte derived key splits
    into a 32-byte HMAC signing key and a 32-byte AES key, selecting
    `AES_256_CBC` from `RNS/Cryptography/AES.py`). So `aes_key_bits = 256`,
    recorded directly rather than read off a nonexistent attribute.
  - Packet: `RNS.Packet(dest, plaintext, RNS.Packet.DATA)` then `.pack()`
    sets `.raw`/`.data`, but `.destination_type` is only populated by
    `.unpack()` (parsed from the flags byte), not by `.pack()`. So the
    packet is re-parsed via `RNS.Packet(None, raw).unpack()` to read
    `header_type` / `packet_type` / `destination_type` / `hops` / `context`
    / `data` back out, matching exactly how a receiving peer would parse
    the wire bytes.
  - Announce: `dest.announce(app_data=..., send=False)` returns an
    unpacked `RNS.Packet` (raw is None until `.pack()` is called
    explicitly, since `send=False` skips the internal `.pack()` call
    inside `.send()`). After `.pack()`, the announce payload layout
    (see `RNS.Identity.validate_announce` and `RNS.Destination.announce`)
    with no ratchet (context flag unset, since this destination has no
    ratchets configured) is:
      pub (64) | name_hash (10) | random_hash (10) | signature (64) | app_data (rest)
    `random_hash` and `signature` are sliced out of `up.data` at those
    fixed offsets (64, 74, 84, 148).
  - HDLC: `RNS.Interfaces.TCPInterface.HDLC` (not `RNS.Interfaces.Interface`,
    which has no HDLC class) defines `FLAG = 0x7E`, `ESC = 0x7D`,
    `ESC_MASK = 0x20`, and `HDLC.escape()`. The escape function below
    reimplements that logic exactly (verified against the source) so this
    script has no import-time dependency on interface modules.

Instantiating a live `RNS.Reticulum()` would try to create `~/.reticulum`,
open a shared-instance socket, and spawn interface threads -- all
undesirable side effects for a vector-capture script. `Destination.__init__`
unconditionally calls `RNS.Transport.register_destination(self)`, which reads
`RNS.Transport.owner.is_connected_to_shared_instance`. We stub `Transport.owner`
with a minimal object instead of booting the full stack.
"""
import json
import os
import hashlib

import RNS
from RNS.Cryptography import Token  # RNS's Fernet-like primitive


class _StubOwner:
    is_connected_to_shared_instance = False


# Avoid booting a full Reticulum instance (no config dir, no sockets).
RNS.Transport.owner = _StubOwner()

OUT = os.path.join(os.path.dirname(__file__), "..", "vectors")
os.makedirs(OUT, exist_ok=True)


def w(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def hx(b):
    return b.hex()


def seed(label):
    """Deterministic 32-byte seed derived from a fixed label."""
    return hashlib.sha256(f"reticulum-rust-vectors:{label}".encode("utf-8")).digest()


# --- identity ---
# Fixed private-key seed so identity.json / destination.json / packet_data.json
# / announce.json (everything not involving an ephemeral key) is reproducible.
prv_x25519 = seed("identity/x25519")
prv_ed25519 = seed("identity/ed25519")
idty = RNS.Identity.from_bytes(prv_x25519 + prv_ed25519)
assert idty is not None, "failed to load deterministic identity"

pub = idty.get_public_key()  # 64 bytes: X25519 pub || Ed25519 pub
w(
    "identity.json",
    {
        "prv_x25519": hx(idty.prv_bytes),
        "prv_ed25519": hx(idty.sig_prv_bytes),
        "pub": hx(pub),
        "hash": hx(idty.hash),
    },
)

# --- destination ---
app_name, aspects = "example_app", ["messaging", "user"]
# Direction must be IN: only IN destinations can call .announce().
dest = RNS.Destination(
    idty, RNS.Destination.IN, RNS.Destination.SINGLE, app_name, *aspects
)
w(
    "destination.json",
    {
        "app_name": app_name,
        "aspects": aspects,
        "identity_hash": hx(idty.hash),
        "name_hash": hx(dest.name_hash),  # 10 bytes
        "dest_hash": hx(dest.hash),  # 16 bytes
    },
)

# --- token (encryption primitive) ---
plaintext = b"hello reticulum"
token = idty.encrypt(plaintext)  # ephemeral X25519 + AES-256-CBC + HMAC
w(
    "token.json",
    {
        # RNS 1.4.1 has no Token.AES_KEY_SIZE constant. The derived key Token
        # receives is 64 bytes (Identity.DERIVED_KEY_LENGTH = 512 // 8), split
        # into a 32-byte HMAC key and a 32-byte AES key -> AES_256_CBC
        # (see RNS/Cryptography/Token.py and RNS/Cryptography/AES.py).
        "aes_key_bits": 256,
        "recipient_prv_x25519": hx(idty.prv_bytes),
        "plaintext": hx(plaintext),
        "token": hx(token),
    },
)

# --- packet (DATA to SINGLE) ---
pkt = RNS.Packet(dest, plaintext, RNS.Packet.DATA)
pkt.pack()

# .pack() does not populate .destination_type (that only happens in
# .unpack(), parsed from the flags byte) -- so re-parse the raw wire bytes
# the way a receiving peer would.
parsed_pkt = RNS.Packet(None, pkt.raw)
parsed_pkt.unpack()

w(
    "packet_data.json",
    {
        "bytes": hx(pkt.raw),
        "header_type": parsed_pkt.header_type,
        "packet_type": parsed_pkt.packet_type,
        "dest_type": parsed_pkt.destination_type,
        "hops": parsed_pkt.hops,
        "dest_hash": hx(dest.hash),
        "context": parsed_pkt.context,
        "data": hx(parsed_pkt.data),
    },
)

# --- announce ---
app_data = b"greeting"
ann = dest.announce(app_data=app_data, send=False)  # send=False -> not packed yet
ann.pack()
raw = ann.raw

parsed_ann = RNS.Packet(None, raw)
parsed_ann.unpack()
data = parsed_ann.data

# Announce payload layout (no ratchet, since `dest` has no ratchets
# configured -> context flag unset): see RNS.Identity.validate_announce
# and RNS.Destination.announce for the authoritative byte layout.
KEYSIZE = 64  # RNS.Identity.KEYSIZE // 8
NAME_HASH_LEN = 10  # RNS.Identity.NAME_HASH_LENGTH // 8
SIG_LEN = 64  # RNS.Identity.SIGLENGTH // 8

off = 0
parsed_pub = data[off : off + KEYSIZE]
off += KEYSIZE
parsed_name_hash = data[off : off + NAME_HASH_LEN]
off += NAME_HASH_LEN
random_hash = data[off : off + 10]
off += 10
signature = data[off : off + SIG_LEN]
off += SIG_LEN
parsed_app_data = data[off:]

assert parsed_pub == pub
assert parsed_name_hash == dest.name_hash
assert parsed_app_data == app_data
assert len(random_hash) == 10
assert len(signature) == 64

w(
    "announce.json",
    {
        "bytes": hx(raw),
        "dest_hash": hx(dest.hash),
        "pub": hx(pub),
        "name_hash": hx(dest.name_hash),
        "random_hash": hx(random_hash),
        "signature": hx(signature),
        "app_data": hx(app_data),
    },
)

# --- hdlc framing ---
# Reimplements RNS.Interfaces.TCPInterface.HDLC exactly (FLAG = 0x7E,
# ESC = 0x7D, ESC_MASK = 0x20); that class lives in TCPInterface.py, not
# Interfaces/Interface.py, and there is no reason to import interface
# modules (which have side effects) just for two integer constants.
FLAG, ESC, ESC_MASK = 0x7E, 0x7D, 0x20
raw_bytes = bytes([0x7E, 0x11, 0x7D, 0x22, 0x7E])


def hdlc_escape(data):
    data = data.replace(bytes([ESC]), bytes([ESC, ESC ^ ESC_MASK]))
    data = data.replace(bytes([FLAG]), bytes([ESC, FLAG ^ ESC_MASK]))
    return bytes([FLAG]) + data + bytes([FLAG])


w("hdlc.json", {"raw": hx(raw_bytes), "framed": hx(hdlc_escape(raw_bytes))})

print("wrote vectors to", os.path.abspath(OUT))
