import asyncio
from exceptions import InvalidHandshake

MAX_HEADERS = 256


async def _read(stream):
    try:
        data = await stream.readline()
    except EOFError as err:
        raise EOFError(f'connection closed while http handshake {err}')
    if not data.endswith(b'\r\n'):
        raise ValueError('http reading data without CRLF')
    return data[:-2]  # skip \r\n


async def read_http(stream: asyncio.StreamReader):
    request_data = await _read(stream)
    request_data = request_data.decode('utf-8')
    try:
        method, path, http_v = request_data.split(' ')
    except ValueError:
        raise ValueError(f'http request {request_data} unpack fail')

    if method != 'GET':
        raise InvalidHandshake(f'illegal http method: {method}')
    if http_v != 'HTTP/1.1':
        raise InvalidHandshake(f'illegal http version: {http_v}')

    headers = {}
    for _ in range(MAX_HEADERS + 1):
        data = await _read(stream)
        if data == b'':
            break

        data = data.decode('utf-8')
        key, value = data.split(':', 1)
        headers[key] = value.strip()

    return path, headers
