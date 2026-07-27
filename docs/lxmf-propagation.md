# LXMF propagation support

The Rust LXMF crate implements the LXMF 1.1.0 propagation upload envelope,
recipient encryption, safe envelope parsing, recipient decryption, and upload
over an established `lxmf.propagation` link.

Full queue synchronisation remains a follow-up. LXMF 1.1.0 requires the client
to identify its link, issue the `/get/messages` request first with
`[nil, nil]`, request selected transient IDs with `[wants, haves, limit_kb]`,
and finally acknowledge received IDs with `[nil, haves]`. The Reticulum Rust
link layer does not yet expose the request/response and link-identification
subprotocols needed to implement that flow without introducing a second,
incompatible protocol path.
