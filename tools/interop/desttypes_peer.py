#!/usr/bin/env python3
"""RNS 1.4.1 peer for GROUP, PLAIN and explicit-proof interop."""

import argparse
import os
import threading
import time

import RNS


def load_or_create_identity(path):
    identity = RNS.Identity.from_file(path) if os.path.isfile(path) else None
    if identity is None:
        identity = RNS.Identity()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not identity.to_file(path):
            raise OSError(f"could not write identity to {path}")
    return identity


def group_identity(key):
    identity = RNS.Identity.from_bytes(key)
    if identity is None:
        raise ValueError("could not derive GROUP identity from key")
    return identity


def serve(args):
    key = bytes.fromhex(args.group_key)
    single = RNS.Destination(
        load_or_create_identity(args.identity),
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "python_proof",
        "message",
    )
    plain = RNS.Destination(
        None,
        RNS.Destination.IN,
        RNS.Destination.PLAIN,
        "python_plain",
        "message",
    )
    group = RNS.Destination(
        group_identity(key),
        RNS.Destination.IN,
        RNS.Destination.GROUP,
        "python_group",
        "message",
    )
    group.load_private_key(key)
    single.set_proof_strategy(RNS.Destination.PROVE_ALL)

    received = set()
    complete = threading.Event()
    lock = threading.Lock()

    def callback(label):
        def receive(data, _packet):
            with lock:
                received.add(label)
                print(f"PYTHON_{label}_RECEIVED {data.decode('utf-8')}", flush=True)
                if len(received) == 3:
                    complete.set()

        return receive

    single.set_packet_callback(callback("PROOF"))
    plain.set_packet_callback(callback("PLAIN"))
    group.set_packet_callback(callback("GROUP"))
    print(f"PYTHON_PROOF_DESTINATION {single.hexhash}", flush=True)
    print(f"PYTHON_PLAIN_DESTINATION {plain.hexhash}", flush=True)
    print(f"PYTHON_GROUP_DESTINATION {group.hexhash}", flush=True)

    deadline = time.monotonic() + args.timeout
    while not complete.is_set() and time.monotonic() < deadline:
        single.announce(app_data=b"python proof receiver")
        complete.wait(1)
    if not complete.is_set():
        return 1

    rust_identity = RNS.Identity.from_bytes(bytes.fromhex(args.rust_private))
    if rust_identity is None:
        raise ValueError("could not load deterministic Rust identity")
    rust_single = RNS.Destination(
        rust_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "reticulum_rust",
        "message",
    )
    args.proof_destination = rust_single.hexhash
    args.plain_destination = RNS.Destination.hash(
        None, "reticulum_rust", "message"
    ).hex()
    rust_group = RNS.Destination(
        group_identity(key),
        RNS.Destination.OUT,
        RNS.Destination.GROUP,
        "reticulum_rust",
        "message",
    )
    rust_group.load_private_key(key)
    args.group_destination = rust_group.hexhash
    print(f"EXPECTED_RUST_PROOF_DESTINATION {args.proof_destination}", flush=True)
    print(f"EXPECTED_RUST_PLAIN_DESTINATION {args.plain_destination}", flush=True)
    print(f"EXPECTED_RUST_GROUP_DESTINATION {args.group_destination}", flush=True)
    return send(args)


def wait_for_path(destination_hash, deadline):
    while not RNS.Transport.has_path(destination_hash) and time.monotonic() < deadline:
        RNS.Transport.request_path(destination_hash)
        time.sleep(0.1)
    return RNS.Transport.has_path(destination_hash)


def send(args):
    key = bytes.fromhex(args.group_key)
    plain = RNS.Destination(
        None,
        RNS.Destination.OUT,
        RNS.Destination.PLAIN,
        "reticulum_rust",
        "message",
    )
    group = RNS.Destination(
        group_identity(key),
        RNS.Destination.OUT,
        RNS.Destination.GROUP,
        "reticulum_rust",
        "message",
    )
    group.load_private_key(key)
    if plain.hash.hex() != args.plain_destination:
        raise ValueError("Rust PLAIN destination does not match RNS derivation")
    if group.hash.hex() != args.group_destination:
        raise ValueError("Rust GROUP destination does not match RNS derivation")

    time.sleep(0.5)
    RNS.Packet(
        plain,
        b"plain hello from python",
        create_receipt=False,
    ).send()
    print("PYTHON_PLAIN_SENT", flush=True)
    RNS.Packet(
        group,
        b"group hello from python",
        create_receipt=False,
    ).send()
    print("PYTHON_GROUP_SENT", flush=True)

    target = bytes.fromhex(args.proof_destination)
    deadline = time.monotonic() + args.timeout
    if not wait_for_path(target, deadline):
        print("PYTHON_PROOF_PATH_TIMEOUT", flush=True)
        return 1
    identity = RNS.Identity.recall(target)
    if identity is None:
        print("PYTHON_PROOF_IDENTITY_MISSING", flush=True)
        return 1
    destination = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "reticulum_rust",
        "message",
    )
    receipt = RNS.Packet(destination, b"proved hello from python").send()
    if not receipt:
        return 1
    delivered = threading.Event()
    receipt.set_delivery_callback(lambda _receipt: delivered.set())
    delivered.wait(max(0, deadline - time.monotonic()))
    if not delivered.is_set():
        print("PYTHON_PROOF_TIMEOUT", flush=True)
        return 1
    print(f"PYTHON_PROOF_DELIVERED {receipt.hash.hex()}", flush=True)
    time.sleep(0.5)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("serve", "send"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--group-key", required=True)
    parser.add_argument("--identity", default="python-desttypes.identity")
    parser.add_argument("--rust-private")
    parser.add_argument("--proof-destination")
    parser.add_argument("--plain-destination")
    parser.add_argument("--group-destination")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if args.mode == "serve" and not args.rust_private:
        parser.error("serve requires --rust-private")
    if args.mode == "send" and not all(
        (
            args.proof_destination,
            args.plain_destination,
            args.group_destination,
        )
    ):
        parser.error("send requires all three destination hashes")
    RNS.Reticulum(configdir=args.config, loglevel=6)
    return serve(args) if args.mode == "serve" else send(args)


if __name__ == "__main__":
    raise SystemExit(main())
