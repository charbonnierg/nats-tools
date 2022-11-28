import json
import re
import typing as t

from .constants import _CRLF_, _SPC_, CRLF_SIZE, MSG_OP, PING_OP, PONG_OP
from .errors import NATSServerError, parse_error_message
from .headers import Headers
from .structures.server_info import ServerInfo

__all__ = [
    "INFO",
    "MSG",
    "HMSG",
    "OK",
    "ERR",
    "PING",
    "PONG",
    "Message",
    "MessageT",
]


HMSG_RE = re.compile(
    b"\\AHMSG\\s+([^\\s]+)\\s+([^\\s]+)\\s+(([^\\s]+)[^\\S\r\n]+)?([\\d]+)\\s+(\\d+)\r\n"
)
MSG_RE = re.compile(
    b"\\AMSG\\s+([^\\s]+)\\s+([^\\s]+)\\s+(([^\\s]+)[^\\S\r\n]+)?(\\d+)\r\n"
)
OK_RE = re.compile(b"\\A\\+OK\\s*\r\n")
ERR_RE = re.compile(b"\\A-ERR\\s+('.+')?\r\n")
PING_RE = re.compile(b"\\APING\\s*\r\n")
PONG_RE = re.compile(b"\\APONG\\s*\r\n")
INFO_RE = re.compile(b"\\AINFO\\s+([^\r\n]+)\r\n")
DELSUB_RE = re.compile(b"\\ADELSUB\\s+(\\d+)\r\n")

PING_PROTO = f"{PING_OP}{_CRLF_}".encode("utf-8")
PONG_PROTO = f"{PONG_OP}{_CRLF_}".encode("utf-8")


class INFO:

    __slots__ = ["info"]

    def __init__(self, info: ServerInfo) -> None:
        """Create a new INFO command."""
        self.info = info

    def encode(self) -> bytes:
        """Encode INFO command into bytes."""
        return json.dumps(self.info.to_values()).encode()

    @classmethod
    def decode(cls, buffer: bytes) -> "INFO":
        """Decode INFO command from bytes."""
        return cls(ServerInfo(**json.loads(buffer.decode())))

    @classmethod
    def parse(cls, buffer: bytes) -> t.Tuple[t.Optional["INFO"], t.Optional[int]]:
        """Decode INFO command only if buffer matches command regexp.

        Return parse command and command length.
        """
        info_match = INFO_RE.match(buffer)
        if info_match:
            info_line = info_match.groups()[0]
            return cls.decode(info_line), info_match.end()
        return None, None


class MSG:

    __slots__ = ["subject", "sid", "reply", "size", "payload"]

    def __init__(
        self,
        subject: str,
        sid: int,
        reply: str,
        size: int,
        payload: bytes,
    ) -> None:
        self.subject = subject
        self.sid = sid
        self.reply = reply
        self.size = size
        self.payload = payload

    def encode(self) -> bytes:
        """Encode MSG command to bytes."""
        base = f"{MSG_OP}{_SPC_}{self.subject}{_SPC_}{self.sid}{_SPC_}"
        if self.reply:
            base += self.reply + _SPC_ + f"{self.size}{_CRLF_}"
        else:
            base += f"{self.size}{_CRLF_}"
        return base.encode() + self.payload + _CRLF_.encode()

    @classmethod
    def decode(cls, buffer: bytes) -> "MSG":
        msg, end = cls.parse_msg_line(buffer)
        if msg is None or end is None:
            raise ValueError("Invalid bytes")
        msg.parse_msg_payload(buffer)
        return msg

    @classmethod
    def parse_msg_line(
        cls, buffer: bytes
    ) -> t.Tuple[t.Optional["MSG"], t.Optional[int]]:
        """Parse a MSG command from buffer.

        It's possible to return a message without payload.
        """
        msg = MSG_RE.match(buffer)
        if not msg:
            return None, None
        subject, sid, _, reply, needed_bytes = msg.groups()
        if subject is None:
            raise ValueError("Invalid subject")
        subject_str = subject.decode()
        reply_str = reply.decode() if reply else ""
        return (
            cls(
                subject=subject_str,
                sid=int(sid),
                reply=reply_str,
                size=int(needed_bytes),
                payload=b"",
            ),
            msg.end(),
        )

    def parse_msg_payload(self, buffer: bytes) -> t.Optional[int]:
        if len(buffer) >= self.size + CRLF_SIZE:
            self.payload = bytes(buffer[: self.size])
            return self.size + CRLF_SIZE
        return None


class HMSG:

    __slots__ = [
        "subject",
        "sid",
        "reply",
        "headers_size",
        "total_size",
        "headers",
        "payload",
    ]

    def __init__(
        self,
        subject: str,
        sid: int,
        reply: str,
        headers_size: int,
        total_size: int,
        headers: Headers,
        payload: bytes,
    ) -> None:
        self.subject = subject
        self.sid = sid
        self.reply = reply
        self.headers_size = headers_size
        self.total_size = total_size
        self.headers = headers
        self.payload = payload

    def encode(self) -> bytes:
        """Encode MSG command to bytes."""
        base = f"{MSG_OP}{_SPC_}{self.subject}{_SPC_}{self.sid}{_SPC_}"
        if self.reply:
            base += self.reply + _SPC_
        base += f"{self.headers_size}{_SPC_}{self.total_size}{_CRLF_}"
        return base.encode() + self.headers.encode() + self.payload + _CRLF_.encode()

    @classmethod
    def decode(self, buffer: bytes) -> "HMSG":
        msg, end = self.parse_msg_line(buffer)
        if msg is None or end is None:
            raise ValueError("Invalid bytes")
        msg.parse_msg_payload(buffer)
        return msg

    @classmethod
    def parse_msg_line(
        cls, buffer: bytes
    ) -> t.Tuple[t.Optional["HMSG"], t.Optional[int]]:
        """Parse a HMSG command from buffer.

        It's possible to return a message without payload nor headers.
        """
        msg = HMSG_RE.match(buffer)
        if not msg:
            return None, None
        subject, sid, _, reply, headers_size, total_size = msg.groups()
        if subject is None:
            raise ValueError("Invalid subject")
        subject_str = subject.decode()
        reply_str = reply.decode() if reply else ""
        return (
            cls(
                subject=subject_str,
                sid=int(sid),
                reply=reply_str,
                headers_size=int(headers_size),
                total_size=int(total_size),
                payload=b"",
                headers=Headers(),
            ),
            msg.end(),
        )

    def parse_msg_payload(self, buffer: bytes) -> t.Optional[int]:
        if len(buffer) >= self.total_size + CRLF_SIZE:
            self.headers = Headers.decode(bytes(buffer[: self.headers_size]))
            self.payload = bytes(buffer[self.headers_size : self.total_size])
            return self.total_size + CRLF_SIZE
        return None


class DELSUB:
    def __init__(self, sid: int) -> None:
        self.sid = sid

    def encode(self) -> bytes:
        return f"DELSUB {self.sid}".encode()

    @classmethod
    def decode(cls, value: bytes) -> "DELSUB":
        pass

    @classmethod
    def parse(cls, buffer: bytes) -> t.Tuple[t.Optional["DELSUB"], t.Optional[int]]:
        delsub = DELSUB_RE.match(buffer)
        if delsub:
            raw_sid, _ = delsub.groups()
            return cls(int(raw_sid)), delsub.end()
        return None, None


class OK:
    def __init__(self) -> None:
        pass

    def encode(self) -> bytes:
        return f"+OK{_CRLF_}".encode()

    @classmethod
    def decode(cls, value: bytes) -> "OK":
        if value == f"+OK{_CRLF_}".encode():
            return cls()
        raise ValueError("Invalid bytes")

    @classmethod
    def parse(cls, buffer: bytes) -> t.Tuple[t.Optional["OK"], t.Optional[int]]:
        ok = OK_RE.match(buffer)
        if ok:
            return cls(), ok.end()
        return None, None


class ERR:

    __slots__ = ["error"]

    def __init__(self, error: str) -> None:
        self.error = error

    def encode(self) -> bytes:
        return f"-ERR{_SPC_}{self.error}{_CRLF_}".encode()

    @classmethod
    def decode(cls, value: bytes) -> "ERR":
        err, _ = cls.parse(value)
        if err is None:
            raise ValueError("Invalid bytes")
        return err

    @classmethod
    def parse(cls, buffer: bytes) -> t.Tuple[t.Optional["ERR"], t.Optional[int]]:
        err = ERR_RE.match(buffer)
        if err:
            raw_message = err.groups()
            message = raw_message[0].decode().lower()
            return cls(message), err.end()
        return None, None

    def get_error(self) -> NATSServerError:
        return parse_error_message(self.error)


class PING:
    """PING keep-alive message.

    https://docs.nats.io/reference/reference-protocols/nats-protocol#ping-pong
    """

    def encode(self) -> bytes:
        """Serialize PING command to bytes."""
        return PING_PROTO

    @classmethod
    def decode(cls, buffer: bytes) -> "PING":
        if buffer == PING_PROTO:
            return cls()
        raise ValueError("Invalid bytes")

    @classmethod
    def parse(cls, buffer: bytes) -> t.Tuple[t.Optional["PING"], t.Optional[int]]:
        ping = PING_RE.match(buffer)
        if ping:
            return cls(), ping.end()
        return None, None


class PONG:
    """PONG keep-alive response.

    https://docs.nats.io/reference/reference-protocols/nats-protocol#ping-pong
    """

    @classmethod
    def decode(cls, buffer: bytes) -> "PONG":
        if buffer == PONG_PROTO:
            return cls()
        raise ValueError("Invalid bytes")

    def encode(self) -> bytes:
        """Serialize PONG command to bytes."""
        return PONG_PROTO

    @classmethod
    def parse(cls, buffer: bytes) -> t.Tuple[t.Optional["PONG"], t.Optional[int]]:
        pong = PONG_RE.match(buffer)
        if pong:
            return cls(), pong.end()
        return None, None


Message = t.Union[
    DELSUB,
    INFO,
    MSG,
    HMSG,
    OK,
    ERR,
    PING,
    PONG,
]
MessageT = t.TypeVar(
    "MessageT", bound=t.Union[DELSUB, INFO, MSG, HMSG, OK, ERR, PING, PONG]
)
