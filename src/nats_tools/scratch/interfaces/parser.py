"""
NATS network protocol parser.
"""
import abc
import typing as t
from enum import Enum

from ..protocol.messages import DELSUB, ERR, HMSG, INFO, MSG, OK, PING, PONG, MessageT


class State(Enum):
    AWAITING_CONTROL_LINE = 1
    AWAITING_MSG_PAYLOAD = 2
    AWAITING_HMSG_PAYLOAD = 3


class Parser(metaclass=abc.ABCMeta):
    """Parser interface."""

    @abc.abstractmethod
    def reset(self) -> None:
        """Reset the parser state."""
        ...

    @abc.abstractmethod
    def parse(
        self, data: bytes = b""
    ) -> t.Iterator[t.Union[INFO, OK, ERR, MSG, HMSG, PING, PONG, DELSUB]]:
        """
        Parses the wire protocol from NATS for the client
        and dispatches the subscription callbacks.
        """
        ...

    def read(
        self, iterator: t.Iterator[bytes]
    ) -> t.Iterator[t.Union[INFO, OK, ERR, MSG, HMSG, PING, PONG, DELSUB]]:
        for line in iterator:
            for message in self.parse(line):
                yield message

    async def read_async(
        self, iterator: t.AsyncIterator[bytes]
    ) -> t.AsyncIterator[t.Union[INFO, OK, ERR, MSG, HMSG, PING, PONG, DELSUB]]:
        async for line in iterator:
            for message in self.parse(line):
                yield message

    def expect(self, message: t.Type[MessageT], reader: t.Iterator[bytes]) -> MessageT:
        # Wait for line
        for msg in self.read(reader):
            if isinstance(msg, message):
                return msg
            else:
                raise TypeError("Unexpected message")
        raise ValueError("Not enough bytes")

    async def expect_async(
        self, message: t.Type[MessageT], reader: t.AsyncIterator[bytes]
    ) -> MessageT:
        """Wait for message to be received by transport.

        If next message is not the expected message, an error is raised.
        """
        # Wait for info line
        async for msg in self.read_async(reader):
            if isinstance(msg, message):
                return msg
            else:
                raise TypeError("Unexpected message")
        raise ValueError("Not enough bytes")
