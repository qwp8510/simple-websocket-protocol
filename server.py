import asyncio
from functools import partial
import logging
from protocols import WebsocketServerProtocol


async def handler(ws_server: WebsocketServerProtocol):
    async for data in ws_server.recv():
        print('hanler reveive:', data)
        await ws_server.send(f'server has received your message: {data}')


class Serve():
    def __init__(
        self,
        handler: asyncio.coroutine,
        host,
        port,
    ):
        self.handler = handler
        self.host = host
        self.port = port
        self.ws_server = None

    async def __aenter__(self):
        loop = asyncio.get_event_loop()
        _ws_server = partial(WebsocketServerProtocol, self.handler)
        self.ws_server = await loop.create_server(
            _ws_server, self.host, self.port
        )
        await self.ws_server.serve_forever()

    async def __aexit__(self, exc_type, exc_value, traceback):
        self.ws_server.close()


async def main():
    server = Serve(handler, '127.0.0.1', 6633)
    async with server:
        print('in')
    print('close')


asyncio.run(main())
