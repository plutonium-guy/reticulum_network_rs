# Test vectors

Captured from **Python RNS 1.4.1** (PyPI `rns==1.4.1`).

## Regenerate

    python3 -m venv .venv && source .venv/bin/activate
    pip install rns==1.4.1
    python tools/capture_vectors.py

The committed `*.json` files are the interop contract for `reticulum-core`.
Do not edit them by hand. Bumping the RNS version is a deliberate, separate
change — update this file and the workspace `Global Constraints` together.

## Notes on determinism

`identity.json` and `destination.json` are derived from fixed private-key
seeds in `tools/capture_vectors.py` and are byte-for-byte reproducible
across runs. `token.json` (ciphertext), `packet_data.json` (`bytes`/`data`),
and `announce.json` (`random_hash`) each depend on an ephemeral key or
random value that RNS 1.4.1 generates internally with no way to pin it from
the outside — these are captured as-produced. Rust tests validate them by
parsing the captured vector (structure, lengths, round-trip decrypt/verify
against the accompanying fixed plaintext/identity), not by regenerating the
random parts and expecting an exact byte match.

`aes_key_bits` in `token.json` is `256`: RNS 1.4.1 has no
`Token.AES_KEY_SIZE` constant. The 64-byte key `Identity.encrypt()` derives
via HKDF splits into a 32-byte HMAC signing key and a 32-byte AES key,
which selects `AES_256_CBC` (see `RNS/Cryptography/Token.py` and
`RNS/Cryptography/AES.py` in the installed package).
