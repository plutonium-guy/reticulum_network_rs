#!/usr/bin/env python3
"""Capture byte-exact test vectors from Python RNS 1.4.1.

Run inside a venv with `pip install rns==1.4.1`. Writes vectors/*.json.

Deterministic where RNS allows fixed key material (identity keys are derived
from fixed seeds below, so identity.json and destination.json are
byte-for-byte reproducible across runs). Random sources are temporarily
patched for the dedicated deterministic encrypt vector. Several other fields
are captured as-produced rather than pinned:
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
import importlib
import sys
import tempfile

import RNS
from RNS.Cryptography import Token  # RNS's Fernet-like primitive


class _StubOwner:
    is_connected_to_shared_instance = False


# Avoid booting a full Reticulum instance (no config dir, no sockets).
RNS.Transport.owner = _StubOwner()

OUT = os.path.join(os.path.dirname(__file__), "..", "vectors")
os.makedirs(OUT, exist_ok=True)
RATCHET_ONLY = "--ratchet-only" in sys.argv
TRANSPORT_ONLY = "--transport-only" in sys.argv
PATH_REQUEST_ONLY = "--path-request-only" in sys.argv
KEYED_TOKEN_ONLY = "--keyed-token-only" in sys.argv
LINK_ONLY = "--link-only" in sys.argv
RESOURCE_ONLY = "--resource-only" in sys.argv
DESTTYPES_ONLY = "--desttypes-only" in sys.argv
IFAC_ONLY = "--ifac-only" in sys.argv
LXMF_ONLY = "--lxmf-only" in sys.argv
LXMF_VECTOR_NAMES = {
    "lxmf_message.json",
    "lxmf_propagation.json",
    "lxmf_stamp.json",
}
LINK_VECTOR_NAMES = {
    "linkrequest.json",
    "link_handshake.json",
    "link_proof.json",
    "link_data.json",
}
RESOURCE_VECTOR_NAMES = {
    "resource_advertisement.json",
    "resource_maphash.json",
    "resource_proof.json",
}
DESTTYPES_VECTOR_NAMES = {
    "group_destination.json",
    "proof.json",
    "proof_destination.json",
}


def w(name, obj):
    if RATCHET_ONLY and name != "announce_ratchet.json":
        return
    if TRANSPORT_ONLY and name != "packet_header2.json":
        return
    if PATH_REQUEST_ONLY and name != "path_request.json":
        return
    if KEYED_TOKEN_ONLY and name != "token_keyed.json":
        return
    if LINK_ONLY and name not in LINK_VECTOR_NAMES:
        return
    if RESOURCE_ONLY and name not in RESOURCE_VECTOR_NAMES:
        return
    if DESTTYPES_ONLY and name not in DESTTYPES_VECTOR_NAMES:
        return
    if IFAC_ONLY and name != "ifac_frame.json":
        return
    if LXMF_ONLY and name not in LXMF_VECTOR_NAMES:
        return
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

# --- GROUP destination and keyed Token ---
# RNS 1.4.1 requires a non-PLAIN destination to hold an Identity. GROUP
# encryption uses a separate symmetric Token key, while address derivation
# still includes the Identity hash.
group_app_name, group_aspects = "example_group", ["messaging", "shared"]
group_key = seed("group/signing") + seed("group/encryption")
group_dest = RNS.Destination(
    idty,
    RNS.Destination.OUT,
    RNS.Destination.GROUP,
    group_app_name,
    *group_aspects,
)
group_dest.load_private_key(group_key)
group_plaintext = b"deterministic group message"
group_iv = seed("group/iv")[:16]
real_urandom = os.urandom
try:
    os.urandom = lambda length: group_iv if length == 16 else real_urandom(length)
    group_ciphertext = group_dest.encrypt(group_plaintext)
finally:
    os.urandom = real_urandom

w(
    "group_destination.json",
    {
        "app_name": group_app_name,
        "aspects": group_aspects,
        "identity_hash": hx(idty.hash),
        "name_hash": hx(group_dest.name_hash),
        "name_only_dest_hash": hx(
            RNS.Destination.hash(None, group_app_name, *group_aspects)
        ),
        "dest_hash": hx(group_dest.hash),
        "group_key": hx(group_key),
        "iv": hx(group_iv),
        "plaintext": hx(group_plaintext),
        "ciphertext": hx(group_ciphertext),
    },
)

# --- explicit packet proof + ProofDestination ---
# RNS uses the full SHA-256 packet hash in explicit proofs (32 bytes) and
# truncates only the ProofDestination routing address to 16 bytes.
proof_plain_dest = RNS.Destination(
    None,
    RNS.Destination.OUT,
    RNS.Destination.PLAIN,
    "example_proof",
    "message",
)
proof_packet = RNS.Packet(proof_plain_dest, b"prove this packet", RNS.Packet.DATA)
proof_packet.pack()
proved_hash = proof_packet.get_hash()
proof_data = proved_hash + idty.sign(proved_hash)
proof_destination = proof_packet.generate_proof_destination()
proof_wire_packet = RNS.Packet(
    proof_destination,
    proof_data,
    RNS.Packet.PROOF,
)
proof_wire_packet.pack()

w(
    "proof.json",
    {
        "dest_prv_x": hx(idty.prv_bytes),
        "dest_prv_ed": hx(idty.sig_prv_bytes),
        "dest_pub": hx(pub),
        "proved_packet": hx(proof_packet.raw),
        "packet_hash": hx(proved_hash),
        "proof_data": hx(proof_data),
        "proof_packet": hx(proof_wire_packet.raw),
    },
)
w(
    "proof_destination.json",
    {
        "packet_hash": hx(proved_hash),
        "proof_destination_hash": hx(proof_destination.hash),
    },
)

# --- interface access code ---
ifac_network_name = "reticulum-rust-ifac"
ifac_passphrase = "correct horse battery staple"
ifac_size = 16
ifac_origin = (
    RNS.Identity.full_hash(ifac_network_name.encode("utf-8"))
    + RNS.Identity.full_hash(ifac_passphrase.encode("utf-8"))
)
ifac_key = RNS.Cryptography.hkdf(
    length=64,
    derive_from=RNS.Identity.full_hash(ifac_origin),
    salt=RNS.Reticulum.IFAC_SALT,
    context=None,
)
ifac_identity = RNS.Identity.from_bytes(ifac_key)
ifac_plain = proof_packet.raw
ifac = ifac_identity.sign(ifac_plain)[-ifac_size:]
ifac_mask = RNS.Cryptography.hkdf(
    length=len(ifac_plain) + ifac_size,
    derive_from=ifac,
    salt=ifac_key,
    context=None,
)
ifac_wire = bytes([ifac_plain[0] | 0x80, ifac_plain[1]]) + ifac + ifac_plain[2:]
ifac_wire = bytes(
    (byte ^ ifac_mask[index] | 0x80)
    if index == 0
    else (byte ^ ifac_mask[index])
    if index == 1 or index > ifac_size + 1
    else byte
    for index, byte in enumerate(ifac_wire)
)
w(
    "ifac_frame.json",
    {
        "network_name": ifac_network_name,
        "passphrase": ifac_passphrase,
        "ifac_size": ifac_size,
        "ifac_key": hx(ifac_key),
        "plain_frame": hx(ifac_plain),
        "ifac_frame": hx(ifac_wire),
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

# --- deterministic token encryption ---
# Identity.encrypt draws through the configured X25519 provider, which may be
# the internal implementation or the PyCA proxy. Patch the classmethod used by
# Identity directly so the vector is provider-independent. Token.encrypt draws
# its 16-byte IV through os.urandom().
fixed_ephemeral = seed("token-encrypt/ephemeral-x25519")
fixed_iv = seed("token-encrypt/iv")[:16]
real_urandom = os.urandom
identity_module = importlib.import_module("RNS.Identity")
x25519_private = identity_module.X25519PrivateKey
real_generate = x25519_private.__dict__["generate"]


def deterministic_urandom(length):
    if length == 32:
        return fixed_ephemeral
    if length == 16:
        return fixed_iv
    return real_urandom(length)


try:
    x25519_private.generate = classmethod(
        lambda cls: cls.from_private_bytes(fixed_ephemeral)
    )
    os.urandom = deterministic_urandom
    deterministic_plaintext = b"deterministic encrypt vector"
    deterministic_token = idty.encrypt(deterministic_plaintext)
finally:
    x25519_private.generate = real_generate
    os.urandom = real_urandom

w(
    "token_encrypt.json",
    {
        "recipient_pub": hx(pub),
        "ephemeral_prv_x25519": hx(fixed_ephemeral),
        "iv": hx(fixed_iv),
        "plaintext": hx(deterministic_plaintext),
        "token": hx(deterministic_token),
    },
)

# --- deterministic raw-keyed token (Link cipher) ---
link_derived_key = seed("link/token/signing") + seed("link/token/encryption")
link_iv = seed("link/token/iv")[:16]
link_plaintext = b"keyed link token"
real_urandom = os.urandom
try:
    os.urandom = lambda length: link_iv if length == 16 else real_urandom(length)
    link_token = Token(link_derived_key).encrypt(link_plaintext)
finally:
    os.urandom = real_urandom

w(
    "token_keyed.json",
    {
        "derived_key": hx(link_derived_key),
        "iv": hx(link_iv),
        "plaintext": hx(link_plaintext),
        "token": hx(link_token),
    },
)

# --- Link request, handshake, proof and encrypted DATA ---
initiator_link_x_prv = seed("link/initiator/x25519")
initiator_link_ed_prv = seed("link/initiator/ed25519")
responder_link_x_prv = seed("link/responder/x25519")
initiator_link_x_key = RNS.Cryptography.X25519PrivateKey.from_private_bytes(
    initiator_link_x_prv
)
initiator_link_ed_key = RNS.Cryptography.Ed25519PrivateKey.from_private_bytes(
    initiator_link_ed_prv
)
responder_link_x_key = RNS.Cryptography.X25519PrivateKey.from_private_bytes(
    responder_link_x_prv
)
initiator_link_x_pub = initiator_link_x_key.public_key().public_bytes()
initiator_link_ed_pub = initiator_link_ed_key.public_key().public_bytes()
responder_link_x_pub = responder_link_x_key.public_key().public_bytes()
link_request_payload = initiator_link_x_pub + initiator_link_ed_pub
link_request_packet = RNS.Packet(
    dest, link_request_payload, packet_type=RNS.Packet.LINKREQUEST
)
link_request_packet.pack()
link_id = RNS.Link.link_id_from_lr_packet(link_request_packet)

w(
    "linkrequest.json",
    {
        "x25519_prv": hx(initiator_link_x_prv),
        "x25519_pub": hx(initiator_link_x_pub),
        "ed25519_prv": hx(initiator_link_ed_prv),
        "ed25519_pub": hx(initiator_link_ed_pub),
        "dest_hash": hx(dest.hash),
        "lr_packet_bytes": hx(link_request_packet.raw),
        "link_id": hx(link_id),
    },
)

shared_key = initiator_link_x_key.exchange(
    RNS.Cryptography.X25519PublicKey.from_public_bytes(responder_link_x_pub)
)
link_derived_key = RNS.Cryptography.hkdf(
    length=64, derive_from=shared_key, salt=link_id, context=None
)
w(
    "link_handshake.json",
    {
        "own_x25519_prv": hx(initiator_link_x_prv),
        "peer_x25519_pub": hx(responder_link_x_pub),
        "link_id": hx(link_id),
        "derived_key": hx(link_derived_key),
    },
)

proof_signed_data = link_id + responder_link_x_pub + idty.sig_pub_bytes
proof_signature = idty.sign(proof_signed_data)
proof_data = proof_signature + responder_link_x_pub
w(
    "link_proof.json",
    {
        "dest_identity_prv_x": hx(idty.prv_bytes),
        "dest_identity_prv_ed": hx(idty.sig_prv_bytes),
        "dest_pub": hx(idty.get_public_key()),
        "link_id": hx(link_id),
        "responder_x25519_pub": hx(responder_link_x_pub),
        "proof_data": hx(proof_data),
    },
)


class _VectorLink:
    type = RNS.Destination.LINK
    status = RNS.Link.ACTIVE
    mtu = RNS.Reticulum.MTU
    mdu = RNS.Link.MDU
    rtt = 0.1
    traffic_timeout_factor = 6

    def __init__(self, vector_link_id, vector_key):
        self.hash = vector_link_id
        self.link_id = vector_link_id
        self.vector_key = vector_key

    def encrypt(self, plaintext):
        return Token(self.vector_key).encrypt(plaintext)


link_plaintext = b"encrypted link data"
link_iv = seed("link/data/iv")[:16]
vector_link = _VectorLink(link_id, link_derived_key)
real_urandom = os.urandom
try:
    os.urandom = lambda length: link_iv if length == 16 else real_urandom(length)
    link_data_packet = RNS.Packet(vector_link, link_plaintext, RNS.Packet.DATA)
    link_data_packet.pack()
finally:
    os.urandom = real_urandom

w(
    "link_data.json",
    {
        "derived_key": hx(link_derived_key),
        "iv": hx(link_iv),
        "link_id": hx(link_id),
        "plaintext": hx(link_plaintext),
        "packet_bytes": hx(link_data_packet.raw),
        "dest_type": RNS.Destination.LINK,
    },
)

# --- deterministic Resource advertisement, hashmap and proof ---
# Resource encrypts its entire random-prefix+payload stream once and then
# slices that token into RESOURCE parts. The parts themselves are not
# individually encrypted by Packet.pack().
resource_plaintext = (b"reticulum-resource-vector-" * 50)[:1200]
resource_prefix_source = seed("resource/prefix/source")[:16]
resource_token_iv = seed("resource/token/iv")[:16]
resource_map_source = seed("resource/map/source")[:16]
resource_urandom_values = iter(
    [resource_prefix_source, resource_token_iv, resource_map_source]
)


def resource_urandom(length):
    value = next(resource_urandom_values)
    assert length == 16 and len(value) == length
    return value


real_urandom = os.urandom
try:
    os.urandom = resource_urandom
    resource = RNS.Resource(
        resource_plaintext,
        vector_link,
        advertise=False,
        auto_compress=False,
    )
finally:
    os.urandom = real_urandom

resource_adv = RNS.ResourceAdvertisement(resource).pack()
# The prefix and resource random hash are SHA-256-truncated outputs of the
# deterministic 16-byte sources above.
prefix = hashlib.sha256(resource_prefix_source).digest()[:16][: RNS.Resource.RANDOM_HASH_SIZE]
assert Token(link_derived_key).decrypt(b"".join(part.data for part in resource.parts)) == (
    prefix + resource_plaintext
)

w(
    "resource_advertisement.json",
    {
        "packed_hex": hx(resource_adv),
        "fields": {
            "t": resource.size,
            "d": resource.total_size,
            "n": len(resource.parts),
            "h": hx(resource.hash),
            "r": hx(resource.random_hash),
            "o": hx(resource.original_hash),
            "i": resource.segment_index,
            "l": resource.total_segments,
            "q": None,
            "f": RNS.ResourceAdvertisement(resource).f,
            "m": hx(resource.hashmap),
        },
    },
)
w(
    "resource_maphash.json",
    {
        "derived_key": hx(link_derived_key),
        "iv": hx(resource_token_iv),
        "random_prefix": hx(prefix),
        "random_hash": hx(resource.random_hash),
        "plaintext": hx(resource_plaintext),
        "encrypted_stream": hx(b"".join(part.data for part in resource.parts)),
        "sdu": resource.sdu,
        "parts": [hx(part.data) for part in resource.parts],
        "map_hashes": [hx(part.map_hash) for part in resource.parts],
        "hashmap": hx(resource.hashmap),
        "resource_hash": hx(resource.hash),
    },
)
w(
    "resource_proof.json",
    {
        "resource_hash": hx(resource.hash),
        "proof": hx(resource.expected_proof),
        "proof_data": hx(resource.hash + resource.expected_proof),
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

# --- transport path request ---
path_request_destination = RNS.Destination(
    None,
    RNS.Destination.OUT,
    RNS.Destination.PLAIN,
    RNS.Transport.APP_NAME,
    "path",
    "request",
)
requested_destination = seed("path-request/target")[:16]
requester_transport_id = seed("path-request/requester")[:16]
request_tag = seed("path-request/tag")[:16]
path_request_data = requested_destination + requester_transport_id + request_tag
path_request = RNS.Packet(
    path_request_destination,
    path_request_data,
    packet_type=RNS.Packet.DATA,
    transport_type=RNS.Transport.BROADCAST,
    header_type=RNS.Packet.HEADER_1,
)
path_request.pack()
parsed_path_request = RNS.Packet(None, path_request.raw)
parsed_path_request.unpack()
w(
    "path_request.json",
    {
        "bytes": hx(path_request.raw),
        "dest_hash": hx(path_request_destination.hash),
        "target": hx(requested_destination),
        "requester_transport_id": hx(requester_transport_id),
        "tag": hx(request_tag),
        "data": hx(parsed_path_request.data),
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

# --- transported announce (HEADER_2) ---
# RNS emits this shape when a transport node forwards a valid announce:
# flags | hops | next-hop transport identity | destination | context | data.
transport_id = seed("transport-id")[:16]
transported_announce = RNS.Packet(
    dest,
    data,
    RNS.Packet.ANNOUNCE,
    header_type=RNS.Packet.HEADER_2,
    transport_type=RNS.Transport.TRANSPORT,
    transport_id=transport_id,
)
transported_announce.hops = 3
transported_announce.pack()
parsed_transport = RNS.Packet(None, transported_announce.raw)
parsed_transport.unpack()

w(
    "packet_header2.json",
    {
        "bytes": hx(transported_announce.raw),
        "header_type": parsed_transport.header_type,
        "packet_type": parsed_transport.packet_type,
        "dest_type": parsed_transport.destination_type,
        "propagation": parsed_transport.transport_type,
        "hops": parsed_transport.hops,
        "transport_id": hx(parsed_transport.transport_id),
        "dest_hash": hx(parsed_transport.destination_hash),
        "context": parsed_transport.context,
        "data": hx(parsed_transport.data),
    },
)

# --- announce with ratchet ---
ratchet_dest = RNS.Destination(
    idty,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "example_ratchet",
    "messaging",
)
with tempfile.TemporaryDirectory() as ratchet_dir:
    ratchet_dest.enable_ratchets(os.path.join(ratchet_dir, "ratchets"))
    ratchet_app_data = b"ratcheted"
    # A standalone capture has no Reticulum storage path. Suppress only the
    # background cache persistence; it does not affect announce construction.
    real_remember_ratchet = RNS.Identity.__dict__["_remember_ratchet"]
    try:
        RNS.Identity._remember_ratchet = staticmethod(lambda _dest, _ratchet: None)
        ratchet_announce = ratchet_dest.announce(
            app_data=ratchet_app_data, send=False
        )
    finally:
        RNS.Identity._remember_ratchet = real_remember_ratchet
    ratchet_announce.pack()
    ratchet_raw = ratchet_announce.raw

ratchet_packet = RNS.Packet(None, ratchet_raw)
ratchet_packet.unpack()
ratchet_data = ratchet_packet.data
ratchet_off = 0
ratchet_pub = ratchet_data[ratchet_off : ratchet_off + KEYSIZE]
ratchet_off += KEYSIZE
ratchet_name_hash = ratchet_data[
    ratchet_off : ratchet_off + NAME_HASH_LEN
]
ratchet_off += NAME_HASH_LEN
ratchet_random_hash = ratchet_data[ratchet_off : ratchet_off + 10]
ratchet_off += 10
ratchet_public = ratchet_data[ratchet_off : ratchet_off + 32]
ratchet_off += 32
ratchet_signature = ratchet_data[ratchet_off : ratchet_off + SIG_LEN]
ratchet_off += SIG_LEN
ratchet_parsed_app_data = ratchet_data[ratchet_off:]

assert ratchet_pub == pub
assert ratchet_name_hash == ratchet_dest.name_hash
assert len(ratchet_public) == 32
assert ratchet_packet.context_flag == RNS.Packet.FLAG_SET
assert ratchet_parsed_app_data == ratchet_app_data

w(
    "announce_ratchet.json",
    {
        "bytes": hx(ratchet_raw),
        "dest_hash": hx(ratchet_dest.hash),
        "pub": hx(ratchet_pub),
        "name_hash": hx(ratchet_name_hash),
        "random_hash": hx(ratchet_random_hash),
        "ratchet": hx(ratchet_public),
        "signature": hx(ratchet_signature),
        "app_data": hx(ratchet_app_data),
        "context_flag": True,
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

# --- LXMF 1.1.0 signed message ---
# LXMessage.pack() is the wire-format oracle. Fixed private material, hashes,
# timestamp, bytes and insertion-ordered fields make this vector reproducible.
import LXMF
import RNS.vendor.umsgpack as msgpack

lxmf_destination_identity = RNS.Identity.from_bytes(
    seed("lxmf/destination/x25519") + seed("lxmf/destination/ed25519")
)
lxmf_source = RNS.Destination(
    idty, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery"
)
lxmf_destination = RNS.Destination(
    lxmf_destination_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "lxmf",
    "delivery",
)
lxmf_fields = {
    1: b"attachment-metadata",
    "custom": [1, True, b"opaque"],
}
lxmf_timestamp = 1720000000.25
lxmf_title = b"Vector title"
lxmf_content = b"Vector content \x00\xff"
lxmf = LXMF.LXMessage(
    lxmf_destination,
    lxmf_source,
    title=lxmf_title,
    content=lxmf_content,
    fields=lxmf_fields,
)
lxmf.timestamp = lxmf_timestamp
lxmf.pack()

w(
    "lxmf_message.json",
    {
        "source_prv_x": hx(idty.prv_bytes),
        "source_prv_ed": hx(idty.sig_prv_bytes),
        "source_public": hx(idty.get_public_key()),
        "destination": hx(lxmf_destination.hash),
        "source": hx(lxmf_source.hash),
        "timestamp": lxmf_timestamp,
        "title": hx(lxmf_title),
        "content": hx(lxmf_content),
        "fields_msgpack": hx(msgpack.packb(lxmf_fields)),
        "payload_msgpack": hx(msgpack.packb(lxmf.payload)),
        "packed_hex": hx(lxmf.packed),
        "hash": hx(lxmf.hash),
        "signature": hx(lxmf.signature),
    },
)

# --- LXMF 1.1.0 propagation envelope ---
# LXMessage's propagated representation encrypts everything after the leading
# delivery hash to the recipient, then wraps one or more resulting blobs in
# [timebase, [binary...]]. Pin the X25519 secret and Token IV exactly as in
# token_encrypt.json so the complete envelope is byte-for-byte reproducible.
propagation_ephemeral = seed("lxmf/propagation/ephemeral-x25519")
propagation_iv = seed("lxmf/propagation/iv")[:16]
propagation_timestamp = 1720000001.5
real_urandom = os.urandom
identity_module = importlib.import_module("RNS.Identity")
x25519_private = identity_module.X25519PrivateKey
real_generate = x25519_private.__dict__["generate"]

try:
    x25519_private.generate = classmethod(
        lambda cls: cls.from_private_bytes(propagation_ephemeral)
    )
    os.urandom = (
        lambda length: propagation_iv if length == 16 else real_urandom(length)
    )
    propagation_encrypted = lxmf_destination.encrypt(
        lxmf.packed[LXMF.LXMessage.DESTINATION_LENGTH :]
    )
finally:
    x25519_private.generate = real_generate
    os.urandom = real_urandom

propagation_lxmf_data = (
    lxmf.packed[: LXMF.LXMessage.DESTINATION_LENGTH] + propagation_encrypted
)
propagation_packed = msgpack.packb(
    [propagation_timestamp, [propagation_lxmf_data]]
)
propagation_identity = RNS.Identity.from_bytes(
    seed("lxmf/propagation-node/x25519")
    + seed("lxmf/propagation-node/ed25519")
)
propagation_destination = RNS.Destination(
    propagation_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "lxmf",
    "propagation",
)

w(
    "lxmf_propagation.json",
    {
        "recipient_public": hx(lxmf_destination_identity.get_public_key()),
        "recipient_prv_x": hx(lxmf_destination_identity.prv_bytes),
        "recipient_prv_ed": hx(lxmf_destination_identity.sig_prv_bytes),
        "propagation_node_public": hx(propagation_identity.get_public_key()),
        "propagation_node_destination": hx(propagation_destination.hash),
        "ephemeral_prv_x25519": hx(propagation_ephemeral),
        "iv": hx(propagation_iv),
        "timestamp": propagation_timestamp,
        "message_packed": hx(lxmf.packed),
        "encrypted": hx(propagation_encrypted),
        "lxmf_data": hx(propagation_lxmf_data),
        "transient_id": hx(RNS.Identity.full_hash(propagation_lxmf_data)),
        "propagation_packed": hx(propagation_packed),
    },
)

# --- LXMF 1.1.0 delivery stamps ---
# Keep the PoW cost deliberately low for a fast deterministic oracle, while
# retaining the production 3000-round workblock expansion.
from LXMF import LXStamper

stamp_cost = 4
stamp_workblock = LXStamper.stamp_workblock(lxmf.hash)
stamp_counter = 0
while True:
    stamp = stamp_counter.to_bytes(LXStamper.STAMP_SIZE, byteorder="big")
    if LXStamper.stamp_valid(stamp, stamp_cost, stamp_workblock):
        break
    stamp_counter += 1

ticket = seed("lxmf/stamp/ticket")
ticket_stamp = RNS.Identity.truncated_hash(ticket + lxmf.hash)
stamped_payload = [lxmf_timestamp, lxmf_title, lxmf_content, lxmf_fields, stamp]
stamped_packed = lxmf.packed[: 2 * LXMF.LXMessage.DESTINATION_LENGTH + LXMF.LXMessage.SIGNATURE_LENGTH]
stamped_packed += msgpack.packb(stamped_payload)

w(
    "lxmf_stamp.json",
    {
        "message_id": hx(lxmf.hash),
        "stamp_cost": stamp_cost,
        "expand_rounds": LXStamper.WORKBLOCK_EXPAND_ROUNDS,
        "workblock_sha256": hx(RNS.Identity.full_hash(stamp_workblock)),
        "stamp": hx(stamp),
        "stamp_value": LXStamper.stamp_value(stamp_workblock, stamp),
        "ticket": hx(ticket),
        "ticket_stamp": hx(ticket_stamp),
        "stamped_packed": hx(stamped_packed),
    },
)

print("wrote vectors to", os.path.abspath(OUT))
