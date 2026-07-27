#!/usr/bin/env python3
"""Binary WebSocket to TCP bridge for browser Reticulum nodes."""

import argparse
import asyncio

from websockets.asyncio.server import serve


async def bridge_connection(websocket, tcp_host, tcp_port):
    reader, writer = await asyncio.open_connection(tcp_host, tcp_port)

    async def websocket_to_tcp():
        async for message in websocket:
            if isinstance(message, str):
                await websocket.close(code=1003, reason="binary frames required")
                return
            writer.write(message)
            await writer.drain()

    async def tcp_to_websocket():
        while data := await reader.read(65536):
            await websocket.send(data)

    tasks = {
        asyncio.create_task(websocket_to_tcp()),
        asyncio.create_task(tcp_to_websocket()),
    }
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    writer.close()
    await writer.wait_closed()
    for task in done:
        task.result()


async def main_async(args):
    async def handler(websocket):
        await bridge_connection(websocket, args.tcp_host, args.tcp_port)

    async with serve(
        handler,
        args.listen_host,
        args.listen_port,
        max_size=None,
        compression=None,
    ):
        print(
            f"WS_BRIDGE_READY ws://{args.listen_host}:{args.listen_port} "
            f"-> {args.tcp_host}:{args.tcp_port}",
            flush=True,
        )
        await asyncio.Future()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8765)
    parser.add_argument("--tcp-host", default="127.0.0.1")
    parser.add_argument("--tcp-port", type=int, default=42428)
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
