#!/usr/bin/env python3
"""Send one encrypted RNS packet to the Rust interop destination."""

import argparse
import time

import RNS


APP_NAME = "reticulum_rust"
ASPECTS = ("message",)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--message", required=True)
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args()

    target = bytes.fromhex(args.destination)
    if len(target) != RNS.Reticulum.TRUNCATED_HASHLENGTH // 8:
        raise ValueError("destination must be a 16-byte hexadecimal hash")

    RNS.Reticulum(configdir=args.config, loglevel=3)
    deadline = time.monotonic() + args.timeout
    while not RNS.Transport.has_path(target) and time.monotonic() < deadline:
        time.sleep(0.1)
    if not RNS.Transport.has_path(target):
        print(f"PYTHON_PATH_TIMEOUT {args.destination}", flush=True)
        return 1

    identity = RNS.Identity.recall(target)
    if identity is None:
        print(f"PYTHON_IDENTITY_UNKNOWN {args.destination}", flush=True)
        return 1
    destination = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        APP_NAME,
        *ASPECTS,
    )
    if destination.hash != target:
        raise ValueError("target hash does not match the configured app name/aspects")

    packet = RNS.Packet(destination, args.message.encode("utf-8"), RNS.Packet.DATA)
    packet.send()
    print(f"PYTHON_SENT {args.message}", flush=True)
    time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
