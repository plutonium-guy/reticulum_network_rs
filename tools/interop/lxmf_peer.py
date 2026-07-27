#!/usr/bin/env python3
"""LXMF 1.1.0 peer used by the Rust milestone-8 interoperability gate."""

import argparse
import os
import threading
import time

import LXMF
import RNS


def load_or_create_identity(path):
    identity = RNS.Identity.from_file(path) if os.path.isfile(path) else None
    if identity is None:
        identity = RNS.Identity()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not identity.to_file(path):
            raise OSError(f"could not write identity to {path}")
    return identity


def create_router(args):
    identity = load_or_create_identity(args.identity)
    os.makedirs(args.storage, exist_ok=True)
    router = LXMF.LXMRouter(identity=identity, storagepath=args.storage)
    source = router.register_delivery_identity(
        identity, display_name="Python LXMF interop", stamp_cost=None
    )
    return router, source


def receive(args):
    router, destination = create_router(args)
    received = threading.Event()

    def delivered(message):
        title = message.title.decode("utf-8", errors="replace")
        content = message.content.decode("utf-8", errors="replace")
        print(
            f"PYTHON_LXMF_RECEIVED title={title} content={content} "
            f"fields={message.fields!r}",
            flush=True,
        )
        received.set()

    router.register_delivery_callback(delivered)
    print(f"PYTHON_LXMF_DESTINATION {destination.hexhash}", flush=True)
    deadline = time.monotonic() + args.timeout
    while not received.is_set() and time.monotonic() < deadline:
        destination.announce()
        received.wait(1)
    return 0 if received.is_set() else 1


def send(args):
    router, source = create_router(args)
    target = bytes.fromhex(args.destination)
    if len(target) != RNS.Reticulum.TRUNCATED_HASHLENGTH // 8:
        raise ValueError("destination must be a 16-byte hexadecimal hash")

    source.announce()
    deadline = time.monotonic() + args.timeout
    while not RNS.Transport.has_path(target) and time.monotonic() < deadline:
        RNS.Transport.request_path(target)
        time.sleep(0.1)
    if not RNS.Transport.has_path(target):
        print(f"PYTHON_LXMF_PATH_TIMEOUT {args.destination}", flush=True)
        return 1

    target_identity = RNS.Identity.recall(target)
    if target_identity is None:
        print(f"PYTHON_LXMF_IDENTITY_UNKNOWN {args.destination}", flush=True)
        return 1
    destination = RNS.Destination(
        target_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery",
    )
    if destination.hash != target:
        raise ValueError("target is not an lxmf.delivery destination")

    method = (
        LXMF.LXMessage.DIRECT
        if args.method == "direct"
        else LXMF.LXMessage.OPPORTUNISTIC
    )
    message = LXMF.LXMessage(
        destination,
        source,
        title=args.title,
        content=args.content,
        fields={42: b"python-field"},
        desired_method=method,
    )
    router.handle_outbound(message)
    while (
        message.state
        not in (
            LXMF.LXMessage.SENT,
            LXMF.LXMessage.DELIVERED,
            LXMF.LXMessage.FAILED,
            LXMF.LXMessage.REJECTED,
        )
        and time.monotonic() < deadline
    ):
        time.sleep(0.05)
    if message.state in (LXMF.LXMessage.FAILED, LXMF.LXMessage.REJECTED):
        print(f"PYTHON_LXMF_SEND_FAILED state={message.state}", flush=True)
        return 1
    if message.state not in (LXMF.LXMessage.SENT, LXMF.LXMessage.DELIVERED):
        print(f"PYTHON_LXMF_SEND_TIMEOUT state={message.state}", flush=True)
        return 1
    print(
        f"PYTHON_LXMF_SENT method={args.method} title={args.title} "
        f"content={args.content}",
        flush=True,
    )
    time.sleep(1)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("receive", "send"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--storage", required=True)
    parser.add_argument("--destination")
    parser.add_argument("--method", choices=("direct", "opportunistic"), default="opportunistic")
    parser.add_argument("--title", default="Python title")
    parser.add_argument("--content", default="hello from python lxmf")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if args.mode == "send" and not args.destination:
        parser.error("send requires --destination")

    RNS.Reticulum(configdir=args.config, loglevel=4)
    return receive(args) if args.mode == "receive" else send(args)


if __name__ == "__main__":
    raise SystemExit(main())
