# Reticulum interfaces

The Tokio runtime accepts any packet medium implementing
`reticulum_tokio::interface::AsyncInterface`. Implementations receive and
return complete, unframed Reticulum packets; transport framing stays inside
the interface. Optional IFAC wrapping is transport-independent and is applied
before HDLC/KISS framing.

## Implemented

- TCP client and TCP server (RNS HDLC framing, MTU 262144)
- UDP (one raw packet per datagram, MTU 1064)
- AutoInterface (authenticated IPv6 link-local discovery, raw peer datagrams,
  MTU 1196)
- Serial KISS behind the `serial` Cargo feature (MTU 564)
- RNS 1.4.1-compatible IFAC authentication and masking

## Deferred: RNode/LoRa

RNode support requires physical RNode-compatible hardware (or its TCP/BLE
bridge), regulatory-domain-appropriate radio settings, and a hardware live
gate. The RNS configuration includes `port`, `frequency`, `bandwidth`,
`txpower`, `spreadingfactor`, and `codingrate`; RNS then configures the radio
and carries packets in the RNode firmware protocol.

A Rust implementation should add an `RNodeInterface` in `reticulum-tokio`
behind an `rnode` feature. Its codec/state machine belongs in
`reticulum-interface` so command encoding, escaping, flow control, and MTU
checks remain independently testable and `no_std`. The Tokio adapter would
own serial/TCP/BLE I/O and implement `AsyncInterface`; the existing driver and
IFAC wrapper require no changes.

Implementation is deferred until compatible hardware is available. Required
acceptance evidence is a bidirectional RNS 1.4.1 packet exchange plus verified
radio parameter readback and disconnect/reconnect behavior.

## Deferred: I2P

RNS I2P support requires a running I2P router exposing SAM and persistent
destination-key storage. Its RNS configuration consists of `connectable` and
an optional `peers` list of I2P destinations. RNS creates SAM client/server
tunnels, then runs its TCP-style HDLC packet stream over the resulting local
sockets.

A Rust implementation should place SAM session and destination lifecycle code
in a feature-gated `I2pInterface` in `reticulum-tokio`. Each established SAM
stream can reuse the TCP HDLC codec and register as a spawned
`AsyncInterface`, exactly like `TcpServerInterface`. Destination keys must be
persisted atomically and never logged.

Implementation is deferred until an I2P router is available. The live gate
must cover inbound and outbound SAM streams, persistent address reuse,
multiple peers, IFAC wrapping, and router restart recovery.
