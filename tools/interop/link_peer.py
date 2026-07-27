#!/usr/bin/env python3
"""RNS 1.4.1 Link peer used by the Rust interoperability gate."""

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


def accept(args):
    identity = load_or_create_identity(args.identity)
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        args.app_name,
        *args.aspects.split(","),
    )
    received = threading.Event()

    def established(link):
        print(f"PYTHON_LINK_ESTABLISHED {link.link_id.hex()}", flush=True)

        def packet_received(data, _packet):
            plaintext = data.decode("utf-8", errors="replace")
            print(f"PYTHON_LINK_RECEIVED {plaintext}", flush=True)
            RNS.Packet(link, data).send()
            print(f"PYTHON_LINK_ECHOED {plaintext}", flush=True)
            received.set()

        link.set_packet_callback(packet_received)

    destination.set_link_established_callback(established)
    print(f"PYTHON_LINK_DESTINATION {destination.hexhash}", flush=True)
    deadline = time.monotonic() + args.timeout
    while not received.is_set() and time.monotonic() < deadline:
        destination.announce(app_data=b"python link peer")
        received.wait(1)
    if received.is_set():
        time.sleep(1)
        return 0
    return 1


def connect(args):
    target = bytes.fromhex(args.destination)
    if len(target) != RNS.Reticulum.TRUNCATED_HASHLENGTH // 8:
        raise ValueError("destination must be a 16-byte hexadecimal hash")
    deadline = time.monotonic() + args.timeout
    while not RNS.Transport.has_path(target) and time.monotonic() < deadline:
        RNS.Transport.request_path(target)
        time.sleep(0.1)
    if not RNS.Transport.has_path(target):
        print(f"PYTHON_LINK_PATH_TIMEOUT {args.destination}", flush=True)
        return 1

    identity = RNS.Identity.recall(target)
    if identity is None:
        print(f"PYTHON_LINK_IDENTITY_UNKNOWN {args.destination}", flush=True)
        return 1
    destination = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        args.app_name,
        *args.aspects.split(","),
    )
    if destination.hash != target:
        raise ValueError("target hash does not match configured app name/aspects")

    received = threading.Event()

    def established(link):
        print(f"PYTHON_LINK_ESTABLISHED {link.link_id.hex()}", flush=True)

        def packet_received(data, _packet):
            print(
                f"PYTHON_LINK_RECEIVED {data.decode('utf-8', errors='replace')}",
                flush=True,
            )
            received.set()

        link.set_packet_callback(packet_received)
        RNS.Packet(link, args.message.encode("utf-8")).send()
        print(f"PYTHON_LINK_SENT {args.message}", flush=True)

    RNS.Link(destination, established_callback=established)
    received.wait(max(0, deadline - time.monotonic()))
    return 0 if received.is_set() else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("accept", "connect"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--identity", default="python-link.identity")
    parser.add_argument("--destination")
    parser.add_argument("--message", default="link hello from python")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--app-name", default="reticulum_rust")
    parser.add_argument("--aspects", default="message")
    args = parser.parse_args()
    if args.mode == "connect" and not args.destination:
        parser.error("connect requires --destination")

    RNS.Reticulum(configdir=args.config, loglevel=3)
    return accept(args) if args.mode == "accept" else connect(args)


if __name__ == "__main__":
    raise SystemExit(main())
