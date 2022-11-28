import asyncio
import typing as t
from urllib.parse import ParseResult

from ..protocol.commands import CONNECT
from ..protocol.headers import Headers
from ..protocol.messages import INFO, PING, PONG
from ..protocol.structures.connect_options import ConnectOptions
from ..protocol.structures.server_info import ServerInfo
from ..services.reader import Reader
from ..services.writer import Priority, Writer
from .message import Msg
from .mux import InboxGenerator, RequestMultiplexer
from .observable import Subscription
from .parser import Parser
from .transport import Transport

if t.TYPE_CHECKING:
    from .session import SessionOptions, SessionState


class Connection:
    def __init__(
        self,
        uri: ParseResult,
        options: "SessionOptions",
        state: "SessionState",
        transport: Transport,
        parser: Parser,
        inbox_generator: InboxGenerator,
        resp_mux: RequestMultiplexer,
        resp_mux_sid: int,
        subscription_factory: t.Type[Subscription[Msg]],
    ) -> None:
        self.uri = uri
        self.transport = transport
        self.options = options
        self.state = state
        self.parser = parser
        self.resp_mux = resp_mux
        self.resp_mux_sid = resp_mux_sid
        self.inbox_generator = inbox_generator
        self.writer = Writer(
            state=self.state, options=self.options, transport=self.transport
        )
        self.reader = Reader(
            state=self.state,
            options=self.options,
            transport=self.transport,
            writer=self.writer,
            parser=self.parser,
        )
        self.subscription_factory = subscription_factory
        self._server_info: t.Optional[ServerInfo] = None

    def get_connect_options(self, info: ServerInfo) -> ConnectOptions:
        # FIXME: Support nkey auth and JWT auth
        return ConnectOptions(
            name=self.options.client_name,
            lang="python3-nats_tools",
            version="0.1.0",
            protocol=1,
            headers=True,
        )

    def get_server_info(self) -> ServerInfo:
        if self._server_info is None:
            raise Exception("Bus is not connected yet")
        return self._server_info

    async def ping(self, timeout: t.Optional[float] = None) -> None:
        """Send a PING request and wait for a PONG reply"""
        # Future will be done when next pong is received
        future = self.reader.next_pong.future()
        # Ping and flush
        await self.writer.ping(timeout=timeout)
        # Wait for pong
        await asyncio.wait_for(future, timeout=timeout)

    async def publish(
        self,
        subject: str,
        payload: t.Optional[bytes] = None,
        reply: t.Optional[str] = None,
        headers: t.Optional[Headers] = None,
        priority: Priority = Priority.LAST,
        timeout: t.Optional[float] = None,
    ) -> None:
        """Publish a message"""
        payload = b""
        payload_size = len(payload)
        if (
            len(self.state.pending_bytes) + payload_size > self.options.max_pending_size
        ) or timeout:
            await self.writer.publish(
                subject=subject,
                payload=payload,
                reply=reply,
                headers=headers,
                priority=priority,
                timeout=timeout,
            )
        else:
            self.writer.send_publish(
                subject=subject,
                payload=payload,
                reply=reply,
                headers=headers,
                priority=priority,
            )

    async def request(
        self,
        subject: str,
        payload: t.Optional[bytes] = None,
        headers: t.Optional[Headers] = None,
        priority: Priority = Priority.LAST,
        timeout: t.Optional[float] = None,
    ) -> Msg:
        if self.resp_mux_sid not in self.state.subscriptions:
            await self.subscribe(self.resp_mux.subject, timeout=timeout)
        reply_subject = self.resp_mux.create_future_reply()
        await self.publish(
            subject=subject,
            payload=payload,
            reply=reply_subject,
            headers=headers,
            priority=priority,
        )
        return await self.resp_mux.wait_future_reply(reply_subject, timeout=timeout)

    async def subscribe(
        self,
        subject: str,
        sid: t.Optional[int] = None,
        queue: t.Optional[str] = None,
        limit: t.Optional[int] = None,
        drain_timeout: t.Optional[int] = None,
        timeout: t.Optional[float] = None,
    ) -> Subscription[Msg]:
        """Subscribe to a subject"""
        sub = self.subscription_factory(
            self,
            sid=sid or self.state.next_sid(),
            subject=subject,
            limit=limit,
            queue=queue,
            drain_timeout=drain_timeout,
        )
        sid = sub.get_sid()
        await sub.start(timeout=timeout)
        return sub

    async def unsubscribe(
        self,
        sid: int,
    ) -> None:
        """Unsubscribe from a subject"""
        subscription = self.state.subscriptions.pop(sid, None)
        if subscription is None:
            return
        await subscription.drain()

    async def start(self) -> None:
        await self.transport.connect(
            uri=self.uri,
            connect_timeout=self.options.transport_connect_timeout,
            buffer_size=self.options.transport_buffer_size,
        )
        # Read INFO protocol message
        info_msg = await self.parser.expect_async(INFO, self.transport)
        self._server_info = info = info_msg.info
        # FIXME: Upgrade to TLS when required
        if info.tls_required:
            raise NotImplementedError("TLS transport is not supported yet")
        # Send CONNECT protocol message
        self.transport.write(CONNECT(self.get_connect_options(info)).encode())
        self.transport.write(PING().encode())
        await self.transport.drain()
        # Expect ping
        await self.parser.expect_async(PONG, self.transport)
        # Start reader and writer loop
        await self.reader.start()
        await self.writer.start()
        # Start all subscriptions
        for subscription in self.state.subscriptions.values():
            await subscription.start(
                self, timeout=self.options.transport_connect_timeout
            )

    async def close(self) -> None:
        subs = list(self.state.subscriptions.values())
        try:
            await asyncio.gather(sub.drain() for sub in subs)
        finally:
            await self.reader.stop()
            await self.writer.stop()
            self.transport.close()
            await self.transport.wait_closed()
