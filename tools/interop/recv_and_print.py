#!/usr/bin/env python3
"""Receive one encrypted RNS packet and print its plaintext."""

import argparse
import os
import threading
import time

import RNS


APP_NAME = "python_peer"
ASPECTS = ("message",)


def load_or_create_identity(path):
    identity = RNS.Identity.from_file(path) if os.path.isfile(path) else None
    if identity is None:
        identity = RNS.Identity()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not identity.to_file(path):
            raise OSError(f"could not write identity to {path}")
    return identity


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--output")
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args()

    RNS.Reticulum(configdir=args.config, loglevel=3)
    identity = load_or_create_identity(args.identity)
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        APP_NAME,
        *ASPECTS,
    )
    received = threading.Event()

    def packet_received(data, _packet):
        plaintext = data.decode("utf-8", errors="replace")
        print(f"PYTHON_RECEIVED {plaintext}", flush=True)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as output:
                output.write(plaintext)
        received.set()

    destination.set_packet_callback(packet_received)
    print(f"PYTHON_DESTINATION {destination.hexhash}", flush=True)

    deadline = time.monotonic() + args.timeout
    while not received.is_set() and time.monotonic() < deadline:
        destination.announce(app_data=b"python interop receiver")
        received.wait(1)

    return 0 if received.is_set() else 1


if __name__ == "__main__":
    raise SystemExit(main())
