import asyncio
from typing import Optional
from asyncio.exceptions import LimitOverrunError


class ReaderProtocol(asyncio.Protocol):
    def __init__(self) -> None:
        self.loop = asyncio.get_event_loop()
        self._reader = StreamReader(self, loop=self.loop)
        # self._reader = asyncio.StreamReader()
        self.is_paused = False
        self.transport: Optional[asyncio.Transport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def pause_reading(self):
        if self.transport is not None:
            self.transport.pause_reading()
            self.is_paused = True

    def resume_reading(self):
        if self.is_paused and self.transport is not None:
            self.is_paused = True
            self.transport.resume_reading()


class StreamReader:
    def __init__(self, protocol: ReaderProtocol, limit_size=2**16, loop=None):
        self._loop = loop or asyncio.get_running_loop()
        self._limit_size = limit_size
        self._buffer = bytearray()
        self._protocol = protocol
        self._waiter: Optional[asyncio.Future] = None
        self.eof = None

    def set_buffer_size(self, size):
        self._limit_size = size

    def feed_data(self, data: bytes):
        assert not self.eof, "feed_data after feed_eof"
        self._buffer.extend(data)
        self._wakeup_waiter()

        if not self._protocol.is_paused and len(self._buffer) > 2 * self._limit_size:
            self._protocol.pause_reading()

    def at_eof(self):
        return self.eof and not self._buffer

    def feed_eof(self):
        self.eof = True
        self._wakeup_waiter()

    def _wakeup_waiter(self):
        waiter = self._waiter
        if self._waiter is not None:
            self._waiter = None
            if not waiter.done():
                waiter.set_result(None)

    async def _wait(self, func_name):
        if self._waiter is not None:
            raise RuntimeError(f'{func_name} try to wait, but another coroutine is waiting \
                for incoming data')
        self._waiter = self._loop.create_future()
        try:
            # avoding unexpected error, like cancelError
            await self._waiter
        finally:
            self._waiter = None

    async def readexactly(self, n):
        needed_n = n
        if n < 0:
            print('readexactly size can not be less than zero')
        elif n == 0:
            return b''
        blocks = []
        while n:
            if self.eof:
                incomplete = bytes(self._buffer)
                self._buffer.clear()
                raise asyncio.exceptions.IncompleteReadError(incomplete, needed_n)
            block = await self.read(n)
            blocks.append(block)
            n -= len(block)
        return b''.join(blocks)

    async def read(self, n=-1):
        """ read up to n bytes from the stream

        if n is -1, read until EOF and return all read bytes
        if n is positive, this read func 'try' to read n bytes, and may return
        less or equal bytes than requested

        """
        if n == 0:
            return b''
        if n < 0:
            blocks = []
            while True:
                block = await self.read(self._limit_size)
                if not block:
                    break
                blocks.append(block)
            return b''.join(blocks)

        if not self._buffer and not self.eof:
            await self._wait('read')

        data = bytes(self._buffer[:n])
        del self._buffer[:n]

        self._protocol.resume_reading()
        return data

    async def readline(self, sep: bytes = b"\n"):
        sep_length = len(sep)
        if sep_length == 0:
            raise ValueError('separator must be at least one byte')

        offset = 0
        while True:
            buffer_length = len(self._buffer)
            if buffer_length - offset >= sep_length:
                sep_index = self._buffer.find(sep, offset)
                if sep_index != -1:
                    if sep_index > self._limit_size:
                        raise LimitOverrunError(
                            'Receiving separator, but chunck excced the limit size', sep_index)
                    break

            offset = buffer_length + 1 - sep_length
            if offset > self._limit_size:
                raise LimitOverrunError('chunck excced the limit size before receiving separator', offset)

            if self.eof:
                chunk = bytes(self._buffer)
                self._buffer.clear()
                return chunk

            await self._wait('readline')

        chunk = bytes(self._buffer[:sep_index + sep_length])
        del self._buffer[:sep_index + sep_length]
        self._protocol.resume_reading()
        return chunk
