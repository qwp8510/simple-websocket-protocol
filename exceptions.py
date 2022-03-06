class WebsocketException(Exception):
    """Base websockets exception"""
    code: int = 50000
    message: str = "websocket unknown exception"


class InvalidHandshake(WebsocketException):
    code = 50001
    message = 'invalid handshade'


class InvalidHeader(InvalidHandshake):
    code = 50002
    message = 'invalid handshade header'


class FrameError(WebsocketException):
    code = 50003
    message = 'frame error'


class ValidationError(WebsocketException):
    code = 50004
    message = 'validate error'
    