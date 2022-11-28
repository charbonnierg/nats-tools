import typing as t
from urllib.parse import urlparse

from .adapters.generators.nuid import NUID
from .adapters.observables.subscription import ObservableSubscription
from .adapters.parsers.nats import NATSParser
from .adapters.transports.tcp import TCPTransport
from .interfaces.connection import Connection
from .interfaces.mux import RequestMultiplexer
from .interfaces.session import (
    AvailableServers,
    ClientSession,
    SessionOptions,
    SessionState,
)
from .protocol.headers import Headers
from .protocol.structures.server_info import ServerInfo
from .services.writer import Priority

if t.TYPE_CHECKING:
    from .interfaces.message import Msg
    from .interfaces.mux import InboxGenerator
    from .interfaces.observable import Subscription
    from .interfaces.parser import Parser
    from .interfaces.transport import Transport


class Client:
    def __init__(
        self,
        name: str,
        servers: t.Union[str, t.List[str]] = "nats://localhost:4222",
        ping_interval: float = 30,
        max_outstanding_ping: int = 2,
        drain_timeout: float = 30,
        max_pending_size: int = 1024 * 1024,
        inbox_prefix: t.Optional[str] = None,
        transport_connect_timeout: t.Optional[float] = None,
        transport_buffer_size: int = 32768,
        pending_bytes: t.Optional[bytearray] = None,
        subscriptions: t.Optional[t.Dict[int, "Subscription[Msg]"]] = None,
        # FIXME: Use a context or something similar which can be dynamic
        # For example, transport factory should be guessed based on scheme
        mux_factory: t.Type["RequestMultiplexer"] = RequestMultiplexer,
        inbox_factory: t.Type["InboxGenerator"] = NUID,
        subscription_factory: t.Type["Subscription[Msg]"] = ObservableSubscription,
        parser_factory: t.Type["Parser"] = NATSParser,
        transport_factory: t.Type["Transport"] = TCPTransport,
    ) -> None:
        servers = (
            [server.strip() for server in servers.split(",")]
            if isinstance(servers, str)
            else servers
        )
        self.options = SessionOptions(
            client_name=name,
            servers=servers,
            ping_interval=ping_interval,
            max_outstanding_ping=max_outstanding_ping,
            drain_timeout=drain_timeout,
            max_pending_size=max_pending_size,
            inbox_prefix=inbox_prefix,
            transport_connect_timeout=transport_connect_timeout,
            transport_buffer_size=transport_buffer_size,
        )
        self.state = SessionState(
            pending_bytes=pending_bytes,
            subscriptions=subscriptions,
            servers=AvailableServers(
                [urlparse(server) for server in self.options.servers]
            ),
        )
        self.session = ClientSession(
            self.state,
            self.options,
            mux_factory=mux_factory,
            inbox_factory=inbox_factory,
            subscription_factory=subscription_factory,
            parser_factory=parser_factory,
            transport_factory=transport_factory,
            connection_factory=Connection,
        )

    async def connect(self) -> None:
        await self.session.start()

    async def close(self) -> None:
        await self.session.stop()

    def get_connection(self) -> Connection:
        if self.session is None or self.session.connection is None:
            raise Exception("Client is not connected")
        return self.session.connection

    def get_server_info(self) -> ServerInfo:
        return self.get_connection().get_server_info()

    async def ping(self, timeout: t.Optional[float] = None) -> None:
        """Send a PING request and wait for a PONG reply"""
        return await self.get_connection().ping()

    async def publish(
        self,
        subject: str,
        payload: t.Optional[bytes] = None,
        reply: t.Optional[str] = None,
        headers: t.Optional[t.Mapping[str, str]] = None,
        priority: Priority = Priority.LAST,
        timeout: t.Optional[float] = None,
    ) -> None:
        """Publish a message"""
        return await self.get_connection().publish(
            subject=subject,
            payload=payload,
            reply=reply,
            headers=Headers(headers) if headers else None,
            priority=priority,
            timeout=timeout,
        )

    async def request(
        self,
        subject: str,
        payload: t.Optional[bytes] = None,
        headers: t.Optional[t.Mapping[str, str]] = None,
        priority: Priority = Priority.LAST,
        timeout: t.Optional[float] = None,
    ) -> "Msg":
        return await self.get_connection().request(
            subject=subject,
            payload=payload,
            headers=Headers(headers),
            priority=priority,
            timeout=timeout,
        )

    async def subscribe(
        self,
        subject: str,
        sid: t.Optional[int] = None,
        queue: t.Optional[str] = None,
        limit: t.Optional[int] = None,
        drain_timeout: t.Optional[int] = None,
        timeout: t.Optional[float] = None,
    ) -> "Subscription[Msg]":
        """Subscribe to a subject"""
        return await self.get_connection().subscribe(
            subject=subject,
            sid=sid,
            queue=queue,
            limit=limit,
            drain_timeout=drain_timeout,
            timeout=timeout,
        )

    async def unsubscribe(
        self,
        sid: int,
    ) -> None:
        """Unsubscribe from a subject"""
        return await self.get_connection().unsubscribe(
            sid=sid,
        )
