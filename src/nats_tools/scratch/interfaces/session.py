import typing as t
from random import randint
from urllib.parse import ParseResult

if t.TYPE_CHECKING:
    from .connection import Connection
    from .message import Msg
    from .mux import InboxGenerator, RequestMultiplexer
    from .observable import Subscription
    from .parser import Parser
    from .transport import Transport


class AvailableServers:
    def __init__(self, servers: t.List[ParseResult]) -> None:
        self.servers = servers.copy()

    def next(self, randomize: bool = False) -> ParseResult:
        if not self.servers:
            raise Exception("No more server to connect to")
        if randomize:
            return self.servers[randint(0, len(self.servers))]
        # By default return first server
        return self.servers[0]

    def remove(self, server: ParseResult) -> None:
        try:
            self.servers.remove(server)
        except ValueError:
            pass


class SessionState:
    def __init__(
        self,
        pending_bytes: t.Optional[bytearray] = None,
        subscriptions: t.Optional[t.Dict[int, "Subscription[Msg]"]] = None,
        servers: t.Optional[AvailableServers] = None,
    ) -> None:
        self.pending_bytes = pending_bytes or bytearray()
        self.subscriptions = subscriptions or {}
        self.servers = servers or AvailableServers([])

    def find_susbcription_by_subject(self, subject: str) -> "Subscription[Msg]":
        for sub in self.subscriptions.values():
            if sub.get_subject() == subject:
                return sub
        raise KeyError(f"No subscription for subject: {subject}")

    def next_sid(self) -> int:
        if not self.subscriptions:
            return 1
        return max(self.subscriptions) + 1


class SessionOptions:
    def __init__(
        self,
        client_name: str,
        servers: t.List[str],
        randomize_servers: bool = False,
        ping_interval: float = 30,
        max_outstanding_ping: int = 2,
        drain_timeout: float = 30,
        max_pending_size: int = 1024 * 1024,
        inbox_prefix: t.Optional[str] = None,
        transport_connect_timeout: t.Optional[float] = None,
        transport_buffer_size: int = 32768,
    ) -> None:
        self.client_name = client_name
        self.servers = servers
        self.randomize_servers = randomize_servers
        self.drain_timeout = drain_timeout
        self.ping_interval = ping_interval
        self.max_outstanding_ping = max_outstanding_ping
        self.inbox_prefix = inbox_prefix
        self.max_pending_size = max_pending_size
        self.transport_connect_timeout = transport_connect_timeout
        self.transport_buffer_size = transport_buffer_size


class ClientSession:
    def __init__(
        self,
        state: SessionState,
        options: SessionOptions,
        mux_factory: t.Type["RequestMultiplexer"],
        inbox_factory: t.Type["InboxGenerator"],
        subscription_factory: t.Type["Subscription[Msg]"],
        parser_factory: t.Type["Parser"],
        transport_factory: t.Type["Transport"],
        connection_factory: t.Type["Connection"],
    ) -> None:
        self.options = options
        self.state = state
        self.connection: t.Optional["Connection"] = None
        self.connection_factory = connection_factory
        self.mux_factory = mux_factory
        self.inbox_factory = inbox_factory
        self.subscription_factory = subscription_factory
        self.parser_factory = parser_factory
        self.transport_factory = transport_factory

    async def do_connection(self) -> None:
        server = self.state.servers.next()
        parser = self.parser_factory()
        inbox_generator = self.inbox_factory()
        mux = self.mux_factory(
            self.options.inbox_prefix, inbox_generator=inbox_generator
        )
        try:
            mux_sid = self.state.find_susbcription_by_subject(mux.subject).get_sid()
        except KeyError:
            mux_sid = self.state.next_sid()
        if server.scheme == "tls" or server.scheme == "nats":
            transport = self.transport_factory()
        else:
            # FIXME: Implement support for websocket
            raise NotImplementedError("Transport scheme not supported")
        connection = self.connection_factory(
            uri=server,
            options=self.options,
            state=self.state,
            transport=transport,
            parser=parser,
            resp_mux=mux,
            resp_mux_sid=mux_sid,
            inbox_generator=inbox_generator,
            subscription_factory=self.subscription_factory,
        )
        await connection.start()
        self.connection = connection

    async def start(self) -> None:
        if self.connection is None:
            await self.do_connection()

    async def stop(self) -> None:
        if self.connection:
            await self.connection.close()
