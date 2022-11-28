import json
import typing as t

from .constants import _CRLF_, _SPC_, CONNECT_OP, HPUB_OP, PUB_OP, SUB_OP, UNSUB_OP
from .headers import Headers
from .messages import PING, PONG
from .structures.connect_options import ConnectOptions

__all__ = [
    "CONNECT",
    "HPUB",
    "PUB",
    "SUB",
    "UNSUB",
    "PING",
    "PONG",
    "Command",
    "CommandT",
]


class PUB:
    """Publish a message to a subject, with optional reply subject.

    Reference: https://docs.nats.io/reference/reference-protocols/nats-protocol#pub
    """

    __slots__ = ["subject", "reply", "payload"]

    def __init__(self, subject: str, reply: str, payload: bytes) -> None:
        """Create a new PUB command"""
        self.subject = subject
        self.reply = reply
        self.payload = payload

    def encode(self) -> bytes:
        """Encode PUB command to bytes"""
        return (
            f"{PUB_OP} {self.subject} {self.reply} {len(self.payload)}{_CRLF_}".encode()
            + self.payload
            + _CRLF_.encode()
        )


class HPUB:
    """Publish a message to a subject including NATS headers, with optional reply subject.

    Reference: https://docs.nats.io/reference/reference-protocols/nats-protocol#hpub
    """

    __slots__ = ["headers", "subject", "reply", "payload"]

    def __init__(
        self, subject: str, reply: str, headers: Headers, payload: bytes
    ) -> None:
        """Create a new HPUB command"""
        self.subject = subject
        self.reply = reply
        self.headers = headers
        self.payload = payload

    def encode(self) -> bytes:
        """Encode HPUB command to bytes"""
        hdr = self.headers.encode()
        hdr_size = len(hdr)
        total_size = len(self.payload) + hdr_size
        return (
            f"{HPUB_OP} {self.subject} {self.reply} {hdr_size} {total_size}{_CRLF_}".encode()
            + hdr
            + self.payload
            + _CRLF_.encode()
        )


class SUB:
    """Subscribe to a subject (or subject wildcard).

    Reference: https://docs.nats.io/reference/reference-protocols/nats-protocol#sub
    """

    __slots__ = ["subject", "queue", "sid"]

    def __init__(self, subject: str, queue: str, sid: int) -> None:
        """Create a new SUB command."""
        self.subject = subject
        self.queue = queue
        self.sid = sid

    def encode(self) -> bytes:
        """Encode SUB command to bytes."""
        return f"{SUB_OP} {self.subject} {self.queue} {self.sid}{_CRLF_}".encode()


class UNSUB:
    """Unsubscribe (or auto-unsubscribe) from subject.

    Reference: https://docs.nats.io/reference/reference-protocols/nats-protocol#unsub
    """

    __slots__ = ["sid", "limit"]

    def __init__(self, sid: int, limit: int) -> None:
        """Create a new UNSUB command."""
        self.sid = sid
        self.limit = limit

    def encode(self) -> bytes:
        """Encode UNSUB command to bytes."""
        limit_s = "" if self.limit == 0 else f"{self.limit}"
        return f"{UNSUB_OP} {self.sid} {limit_s}{_CRLF_}".encode()


class CONNECT:
    """Command sent to server to specify connection information.

    Reference: https://docs.nats.io/reference/reference-protocols/nats-protocol#connect
    """

    __slots__ = ["options"]

    def __init__(self, options: ConnectOptions) -> None:
        """Create a new CONNECT command."""
        self.options = options

    def encode(self) -> bytes:
        """Encode CONNECT command to bytes."""
        connect_opts = json.dumps(self.options.to_values(), sort_keys=True)
        return "".join([CONNECT_OP + _SPC_ + connect_opts + _CRLF_]).encode()


Command = t.Union[CONNECT, HPUB, PUB, SUB, UNSUB, PING, PONG]
CommandT = t.TypeVar(
    "CommandT", bound=t.Union[CONNECT, HPUB, PUB, SUB, UNSUB, PING, PONG]
)
