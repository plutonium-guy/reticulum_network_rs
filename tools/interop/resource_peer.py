#!/usr/bin/env python3
"""RNS 1.4.1 Resource peer for bidirectional Rust interop testing."""

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
    os.makedirs(args.output_dir, exist_ok=True)
    lock = threading.Lock()
    received = []
    complete = threading.Event()

    def established(link):
        print(f"PYTHON_RESOURCE_LINK {link.link_id.hex()}", flush=True)

        def concluded(resource):
            if resource.status != RNS.Resource.COMPLETE:
                print(f"PYTHON_RESOURCE_FAILED {resource.hash.hex()}", flush=True)
                return
            with lock:
                index = len(received) + 1
                path = os.path.join(args.output_dir, f"received-{index}.bin")
                payload = resource.data
                if hasattr(payload, "read"):
                    if hasattr(payload, "seek"):
                        payload.seek(0)
                    payload = payload.read()
                with open(path, "wb") as output:
                    output.write(payload)
                received.append(path)
                print(
                    f"PYTHON_RESOURCE_RECEIVED {resource.hash.hex()} {path}",
                    flush=True,
                )
                if len(received) >= args.count:
                    complete.set()

        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_concluded_callback(concluded)

    destination.set_link_established_callback(established)
    print(f"PYTHON_RESOURCE_DESTINATION {destination.hexhash}", flush=True)
    deadline = time.monotonic() + args.timeout
    while not complete.is_set() and time.monotonic() < deadline:
        destination.announce(app_data=b"python resource receiver")
        complete.wait(1)
    return 0 if complete.is_set() else 1


def connect(args):
    target = bytes.fromhex(args.destination)
    deadline = time.monotonic() + args.timeout
    while not RNS.Transport.has_path(target) and time.monotonic() < deadline:
        RNS.Transport.request_path(target)
        time.sleep(0.1)
    identity = RNS.Identity.recall(target)
    if identity is None:
        print(f"PYTHON_RESOURCE_PATH_TIMEOUT {args.destination}", flush=True)
        return 1
    destination = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        args.app_name,
        *args.aspects.split(","),
    )
    data = open(args.file, "rb").read()
    complete = threading.Event()
    resources = []

    def established(link):
        print(f"PYTHON_RESOURCE_LINK {link.link_id.hex()}", flush=True)

        def concluded(resource):
            if resource.status == RNS.Resource.COMPLETE:
                print(f"PYTHON_RESOURCE_SENT {resource.hash.hex()}", flush=True)
                complete.set()
            else:
                print(f"PYTHON_RESOURCE_FAILED {resource.hash.hex()}", flush=True)

        resources.append(
            RNS.Resource(
                data,
                link,
                auto_compress=not args.no_compress,
                callback=concluded,
            )
        )

    RNS.Link(destination, established_callback=established)
    complete.wait(max(0, deadline - time.monotonic()))
    return 0 if complete.is_set() else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("accept", "connect"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--identity", default="python-resource.identity")
    parser.add_argument("--destination")
    parser.add_argument("--file")
    parser.add_argument("--output-dir", default="received-resources")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--no-compress", action="store_true")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--app-name", default="reticulum_rust")
    parser.add_argument("--aspects", default="message")
    args = parser.parse_args()
    if args.mode == "connect" and (not args.destination or not args.file):
        parser.error("connect requires --destination and --file")
    RNS.Reticulum(configdir=args.config, loglevel=3)
    return accept(args) if args.mode == "accept" else connect(args)


if __name__ == "__main__":
    raise SystemExit(main())
