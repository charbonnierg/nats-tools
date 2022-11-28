import asyncio
import typing as t

from ..concurrency import FutureEvent, wait_for
from ..errors import StateConnectionError
from ..interfaces.message import Msg
from ..interfaces.parser import Parser
from ..interfaces.session import SessionOptions, SessionState
from ..interfaces.transport import Transport
from ..protocol.messages import DELSUB, ERR, HMSG, INFO, MSG, OK, PING, PONG
from ..protocol.structures.server_info import ServerInfo
from .writer import Priority, Writer


class Reader:
    def __init__(
        self,
        state: SessionState,
        options: SessionOptions,
        transport: Transport,
        writer: Writer,
        parser: Parser,
    ) -> None:
        self.state = state
        self.options = options
        self.transport = transport
        self.writer = writer
        self.parser = parser
        self.next_pong = FutureEvent[None]()
        self.server_info = FutureEvent[ServerInfo]()
        self.should_close = FutureEvent[None]()
        self.did_close = FutureEvent[None]()
        # Initialize attribute holding task
        self.task: t.Optional[asyncio.Task[None]] = None

    def closed_callback(self, task: "asyncio.Task[None]") -> None:
        if task.cancelled():
            self.did_close.notify(None)
        else:
            error = task.exception()
            if error:
                self.did_close.notify_exception(error)
            else:
                self.did_close.notify(None)

    async def loop(self) -> None:
        """Read incoming data from NATS server."""
        outstanding_ping = 0
        while True:
            if self.transport.at_eof():
                return
            try:
                # Stop waiting in case should_close event is set
                # We do not bother checking pong replies as long as server is receiving message
                line = await wait_for(
                    self.transport.readline(), timeout=self.options.ping_interval
                )
            # Check outstanding ping in case no line is read before ping interval
            except asyncio.TimeoutError:
                outstanding_ping += 1
                if outstanding_ping > self.options.max_outstanding_ping:
                    raise StateConnectionError(
                        interval=self.options.ping_interval,
                        max_outstanding=self.options.max_outstanding_ping,
                        outstanding=outstanding_ping,
                    )
                # Send a ping to force server to send back a pong
                self.writer.send_ping(priority=Priority.LAST)
                # Continue to wait for pong
                continue
            # Parse messages read from transport
            for message in self.parser.parse(line):
                # Process PING
                if isinstance(message, PING):
                    # Send PONG
                    self.writer.send_pong(priority=Priority.LAST)
                # Process PONG
                elif isinstance(message, PONG):
                    # Reset outstanding ping
                    outstanding_ping = 0
                    self.next_pong.notify(None)
                # Process ERR
                elif isinstance(message, ERR):
                    # Let caller decide what to do
                    raise message.get_error()
                # Process MSG
                elif isinstance(message, MSG):
                    if message.sid in self.state.subscriptions:
                        self.state.subscriptions[message.sid].deliver(
                            Msg.from_msg(message)
                        )
                # Process HMSG
                elif isinstance(message, HMSG):
                    if message.sid in self.state.subscriptions:
                        self.state.subscriptions[message.sid].deliver(
                            Msg.from_hsmsg(message)
                        )
                # Process OK (do nothing)
                elif isinstance(message, OK):
                    pass
                # Process INFO
                elif isinstance(message, INFO):
                    self.server_info.notify(message.info)
                # Process DELSUB
                elif isinstance(message, DELSUB):
                    self.state.subscriptions.pop(message.sid, None)

    async def start(self) -> None:
        self.task = asyncio.create_task(self.loop())
        self.task.add_done_callback(self.closed_callback)

    async def stop(self) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
            await self.did_close.wait()
