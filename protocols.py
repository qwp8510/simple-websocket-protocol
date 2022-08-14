import asyncio
import logging
import struct
from https import read_http
from exceptions import InvalidHandshake, InvalidHeader, FrameError, ValidationError, InvalidCloseFrame, \
    ConnectionClosed
import base64
import hashlib
import sys
import secrets
from streams import ReaderProtocol

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebsocketProtocol(ReaderProtocol):
    is_client = False

    def __init__(self):
        super().__init__()
        self.messages = asyncio.Queue()

    def data_received(self, data: bytes) -> None:
        """allow us reading data by StreamReader"""
        self._reader.feed_data(data)

    def eof_received(self) -> None:
        """Close the transport after receiving EOF."""
        self._reader.feed_eof()

    def start_connections(self):
        asyncio.create_task(self.read_message())

    async def recv(self):
        try:
            while True:
                message = await self.messages.get()
                yield message

        except Exception as err:
            raise ValidationError(f'recv WebsocketProtocol error: {err}') from err

    async def send(self, message):
        # TODO: support binary data
        await self.write(False, 0x01, message.encode('utf-8'))
        await self.write(True, 0x00, b'')  # final fragment

    async def read_message(self):
        try:
            while True:
                message = await self.read_frame()
                if not message:
                    break
                self.messages.put_nowait(message)

        except EOFError as err:
            # TODO: handle IncompleteReadError unexpected close exception
            pass
        except asyncio.CancelledError:
            raise
        except Exception as err:
            raise ValidationError(f'read_message WebsocketProtocol error: {err}') from err
        finally:
            self.close_transfer()

    async def read_frame(self):
        while True:
            frame = await Frame.deserialize(self._reader)
            if frame.fin and frame.opcode == 'TEXT':
                return frame.payload.decode()
            elif frame.opcode == 'PING':
                await self.pong(frame.payload)
            elif frame.opcode == 'CLOSE':
                await self.write_close(frame.payload)
                return

    async def pong(self, payload):
        await self.write(True, 0x0A, payload)

    async def write_close(self, payload):
        if len(payload) >= 2:
            # first two bytes must be status code
            status_code = struct.unpack('!H', payload[:2])
            reason = payload[2:].decode('utf-8')
            data = payload
        elif len(payload) == 0:
            status_code, reason = 1005, ''
            data = struct.pack('!H', status_code) + reason.encode('utf-8')
        else:
            raise InvalidCloseFrame('invalid length of close frame payload')

        # TODO: defin checking statuscode
        await self.write(True, 0x08, data)

    def close_transfer(self):
        self.transport.close()

    async def write(self, fin, opcode, payload):
        frame = Frame(fin, opcode, payload)
        data = await frame.serialize(self.is_client)
        self.transport.write(data)

    def connection_lost(self, exc: Exception) -> None:
        """websocket connection close"""
        self._reader.feed_eof()

class WebsocketServerProtocol(WebsocketProtocol):
    def __init__(self, handler):
        super().__init__()
        self.handler = handler
        self.handler_task: asyncio.Task[None]

    def connection_made(self, transport: asyncio.transports.BaseTransport) -> None:
        super().connection_made(transport)
        self.handler_task = asyncio.create_task(self.new_handler())

    async def new_handler(self):
        try:
            await self.handshake()
        except asyncio.CancelledError:
            raise

        try:
            await self.handler(self)
        except asyncio.CancelledError as err:
            if err == 'connectionClosed':
                raise ConnectionClosed()
            raise err

    async def handshake(self):
        """websocket initially handshake by http get request"""
        try:
            self.path, headers = await read_http(self._reader)
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as err:
            raise InvalidHandshake(f"receive Invalid HTTP handshake {err}")

        self.check_headers(headers)
        self.write_http_response(headers['Sec-WebSocket-Key'])
        self.start_connections()

    def check_headers(self, headers):
        if not headers.get('Upgrade') == 'websocket':
            raise InvalidHeader(f"HTTP handshake header invalid Upgrade:{headers.get('Upgrade')}")
        if not headers.get('Connection') == 'Upgrade':
            raise InvalidHeader(f"HTTP handshake header invalid Connection:{headers.get('Connection')}")
        sec_websocket_key = headers.get('Sec-WebSocket-Key')
        if not sec_websocket_key:
            raise InvalidHeader(f"HTTP handshake header unfind Sec-WebSocket-Key:{headers.get('Sec-WebSocket-Ke')}")
        decode_key = base64.b64decode(sec_websocket_key)
        if len(decode_key) != 16:
            raise InvalidHeader('Sec-WebSocket-Key invalid length')
        if not headers.get('Sec-WebSocket-Version') == '13':
            raise InvalidHeader("Sec-WebSocket-Version invalid version")
        # check Sec-WebSocket-Protocol

    def write_http_response(self, key):
        rsp_header = (
            'HTTP/1.1 101 Switching Protocols\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Accept: {sign_key(key)}\r\n'
            '\r\n'
        )
        self.transport.write(rsp_header.encode('utf-8'))

    def close_transfer(self):
        self.handler_task.cancel('connectionClosed')
        super().close_transfer()


class FrameParser():
    MASK_KEY_LENGTH = 4
    FIN_BINARY = 0b10000000
    RSV1_BINARY = 0b01000000
    RSV2_BINARY = 0b00100000
    RSV3_BINARY = 0b00010000
    OPCODE_BINARY = 0b00001111
    IS_MASK_BINARY = 0b10000000
    LENGTH_BINARY = 0b01111111

    def parse_fin(self, data: int):
        return True if data & self.FIN_BINARY else False

    def parse_rsv(self, data: int):
        return (True if data & self.RSV1_BINARY else False,
                True if data & self.RSV2_BINARY else False,
                True if data & self.RSV3_BINARY else False)

    def parse_opcode(self, data: int):
        return data & self.OPCODE_BINARY

    def parse_mask(self, data: int):
        return True if data & self.IS_MASK_BINARY else False

    async def parse_length(self, stream, data: int):
        length = data & self.LENGTH_BINARY
        if length == 126:
            byte = await stream.readexactly(2)
            (length,) = struct.unpack('!H', byte)
        elif length == 127:
            byte = await stream.readexactly(8)
            (length,) = struct.unpack('!Q', byte)
        return length

    async def parse_payload(self, stream, data_length, is_mask) -> bytes:
        if is_mask:
            mask_key_byte = await stream.readexactly(4)
            if len(mask_key_byte) != self.MASK_KEY_LENGTH:
                raise FrameError(f'error length of mask_key: {mask_key_byte}')

        payload_byte = await stream.readexactly(data_length)
        if is_mask:
            return self.mask(mask_key_byte, payload_byte)
        return payload_byte

    def mask(self, key, payload) -> bytes:
        extended_key = self._extend_mask_by_payload(key, len(payload))
        key_decimal = int.from_bytes(extended_key, byteorder=sys.byteorder)
        payload_decimal = int.from_bytes(payload, byteorder=sys.byteorder)
        return (key_decimal ^ payload_decimal).to_bytes(len(payload), sys.byteorder)

    def _extend_mask_by_payload(self, key, payload_length):
        return key * (payload_length // self.MASK_KEY_LENGTH) + key[:payload_length % self.MASK_KEY_LENGTH]


parser = FrameParser()


class Frame():
    OPCODE_MAP = {
        0x00: 'CONTINUATION',
        0x01: 'TEXT',
        0x02: 'BINARY',
        0x08: 'CLOSE',
        0x09: 'PING',
        0x0A: 'PONG',
    }

    def __init__(self, fin, opcode, payload, rsv1=False, rsv2=False, rsv3=False):
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv2 = rsv2
        self.rsv3 = rsv3
        self._opcode = opcode
        self.payload = payload

    def __repr__(self) -> str:
        return (f'FIN:{self.fin}, rsv1~3:{self.rsv1}-{self.rsv2}-{self.rsv3},'
                f'opcode:{self.opcode}, payload:{self.payload}')

    @property
    def opcode(self):
        return self.OPCODE_MAP[self._opcode]

    @classmethod
    async def deserialize(cls, stream):
        byte = await stream.readexactly(1)
        (data,) = struct.unpack('!B', byte)
        fin = parser.parse_fin(data)
        rsv1, rsv2, rsv3 = parser.parse_rsv(data)
        opcode = parser.parse_opcode(data)
        if opcode not in cls.OPCODE_MAP:
            raise FrameError(f'frame unsupported opcode: {opcode}')

        byte = await stream.readexactly(1)
        (data,) = struct.unpack('!B', byte)
        is_mask = parser.parse_mask(data)
        length = await parser.parse_length(stream, data)
        payload_byte = await parser.parse_payload(
            stream,
            data_length=length,
            is_mask=is_mask
        )
        return cls(fin, opcode, payload_byte, rsv1, rsv2, rsv3)

    async def serialize(self, mask):
        data = bytearray()
        byte1 = (
            (parser.FIN_BINARY if self.fin else 0) |
            (parser.RSV1_BINARY if self.rsv1 else 0) |
            (parser.RSV2_BINARY if self.rsv2 else 0) |
            (parser.RSV3_BINARY if self.rsv3 else 0) |
            self._opcode
        )
        byte2 = parser.IS_MASK_BINARY if mask else 0

        length = len(self.payload)
        if length < 126:
            data.extend(struct.pack('!BB', byte1, byte2 | length))
        elif length < 65536:
            data.extend(struct.pack('!BBH', byte1, byte2 | 126, length))
        else:
            data.extend(struct.pack('!BBQ', byte1, byte2 | 127, length))

        if mask:
            mask_key = secrets.token_bytes(4)
            data.extend(mask_key)
            data.extend(parser.mask(self.payload, mask_key))
        else:
            data.extend(self.payload)
        return bytes(data)


def sign_key(key):
    key += GUID
    digest = hashlib.sha1(key.encode('utf-8')).digest()
    return base64.b64encode(digest).decode()
