# RNS 1.4.1 interoperability evidence

The scripted gate uses an isolated Python RNS 1.4.1 shared instance with a
`TCPServerInterface` on `127.0.0.1:42428`. The Rust daemon connects with native
RNS HDLC framing.

Verified on 2026-07-26:

```text
PASS Rust -> Python: hello from rust
PASS Python -> Rust: hello from python
```

The gate also asserts that `rnpath -t` contains the active Rust destination
while the daemon's TCP interface is connected.

The Python receiver logged:

```text
PYTHON_RECEIVED hello from rust
```

The Rust daemon logged:

```text
message <rust-destination-hash> hello from python
```

Run `./tools/interop/run_interop.sh` to regenerate the evidence with fresh,
temporary identities. Logs are retained in the temporary directory printed by
the script.

Milestone 2 adds a separate three-node transport gate:

```text
Python endpoint A <-> Rust transport relay <-> Python endpoint C
```

Run `./tools/interop/run_transport_interop.sh`. It starts two isolated RNS
1.4.1 transport instances, verifies that each endpoint learns the other at
multiple hops, sends encrypted payloads in both directions, and asserts that
the Rust relay log never contains either plaintext.

Verified on 2026-07-26:

```text
PASS endpoint C -> Rust relay -> endpoint A
PASS endpoint A -> Rust relay -> endpoint C
PASS both endpoint path tables report multi-hop routes
PASS relay log contains no end-to-end plaintext
```

In the acceptance run, each remote Python destination appeared at `hops: 2`
in the opposite RNS path table.

## Milestone 3 Links

Run `./tools/interop/run_link_interop.sh` to exercise both Link roles against
Python RNS 1.4.1 over the TCP interface. The gate requires an authenticated
LINKREQUEST/PROOF handshake, encrypted payload delivery, and an encrypted echo
in each direction.

Verified on 2026-07-27:

```text
PASS Rust -> Python Link: link hello from rust (echo received)
PASS Python -> Rust Link: link hello from python (echo received)
```

The Python responder and Rust initiator logged:

```text
PYTHON_LINK_ESTABLISHED 6665d133b64fd725f153c6178ebe12e4
PYTHON_LINK_RECEIVED link hello from rust
link established 6665d133b64fd725f153c6178ebe12e4
link data 6665d133b64fd725f153c6178ebe12e4 link hello from rust
```

The Python initiator and Rust responder logged:

```text
PYTHON_LINK_SENT link hello from python
PYTHON_LINK_RECEIVED link hello from python
link established 2bd5d3f2b30d4e1c252a104b28aa1aab
link data 2bd5d3f2b30d4e1c252a104b28aa1aab link hello from python
```

Temporary identities make link IDs differ on every run.
