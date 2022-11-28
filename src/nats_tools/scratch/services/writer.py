import asyncio
import enum
import typing as t

from ..concurrency import FutureEvent
from ..interfaces.session import SessionOptions, SessionState
from ..interfaces.transport import Transport
from ..protocol.commands import HPUB, PING, PONG, PUB, SUB, UNSUB, Command
from ..protocol.headers import Headers


class Priority(enum.Enum):
    BYPASS = 0
    LAST = -1


class Writer:
    def __init__(
        self,
        state: SessionState,
        options: SessionOptions,
        transport: Transport,
    ) -> None:
        # Save transport and pending bytes
        self.transport = transport
        self.state = state
        self.options = options
        # Use a future event (may be set several times)
        self.should_flush = FutureEvent[None]()
        self.did_flush = FutureEvent[None]()
        self.should_close = FutureEvent[None]()
        self.did_close = FutureEvent[None]()
        # Initialize attribute holding task
        self.task: t.Optional[asyncio.Task[None]] = None

    def closed_callback(self, task: "asyncio.Task[None]") -> None:
        if task.cancelled():
            self.did_flush.notify(None)
            self.did_close.notify(None)
        else:
            error = task.exception()
            self.flushed_callback(error)
            if error:
                self.did_close.notify_exception(error)
            else:
                self.did_close.notify(None)

    def flushed_callback(self, exception: t.Optional[BaseException]) -> None:
        if exception:
            self.did_flush.notify_exception(exception)
        else:
            self.did_flush.notify(None)

    async def loop(
        self,
    ) -> None:
        """Coroutine continuously writing pending messages to transport."""
        cancelled: t.Optional[asyncio.CancelledError] = None
        while True:
            try:
                await self.should_flush.wait()
            except asyncio.CancelledError as exc:
                cancelled = exc
            # Write pending messages
            inflight_bytes = self.state.pending_bytes.copy()
            # Clear pending messages
            self.state.pending_bytes.clear()
            # Drain transport
            try:
                self.transport.write(inflight_bytes)
                await asyncio.wait_for(
                    self.transport.drain(), timeout=self.options.drain_timeout
                )
            except BaseException as exc:
                inflight_bytes.extend(self.state.pending_bytes)
                self.state.pending_bytes.clear()
                self.state.pending_bytes.extend(inflight_bytes)
                self.did_flush.notify_exception(exc)
                raise
            else:
                self.did_flush.notify(None)
            # Raise back cancelled error
            if cancelled:
                raise cancelled

    async def start(self) -> None:
        self.task = asyncio.create_task(self.loop())
        self.task.add_done_callback(self.closed_callback)

    async def stop(self) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
            await self.did_close.wait()

    def notify_flush(
        self,
        waiter: t.Optional["asyncio.Future[None]"] = None,
    ) -> None:
        self.should_flush.notify(None)
        if waiter:
            self.did_flush.subscribe(waiter)

    def send_command(
        self,
        command: Command,
        priority: Priority = Priority.LAST,
        waiter: t.Optional["asyncio.Future[None]"] = None,
    ) -> None:
        # Extend pending message
        if priority == Priority.BYPASS:
            pending_bytes = bytearray(command.encode())
            pending_bytes.extend(self.state.pending_bytes)
            self.state.pending_bytes.clear()
            self.state.pending_bytes.extend(pending_bytes)
        else:
            # Write message to pending bytes
            self.state.pending_bytes.extend(command.encode())
        # Always notify flusher
        self.notify_flush(waiter)

    def send_ping(
        self,
        priority: Priority = Priority.LAST,
        waiter: "t.Optional[asyncio.Future[None]]" = None,
    ) -> None:
        """Send a PING protocol message."""
        self.send_command(
            PING(),
            priority=priority,
            waiter=waiter,
        )

    def send_pong(
        self,
        priority: Priority = Priority.LAST,
        waiter: t.Optional["asyncio.Future[None]"] = None,
    ) -> None:
        """Send a PONG protocol message."""
        self.send_command(
            PONG(),
            priority=priority,
            waiter=waiter,
        )

    def send_publish(
        self,
        subject: str,
        payload: t.Optional[bytes] = None,
        reply: t.Optional[str] = None,
        headers: t.Optional[Headers] = None,
        priority: Priority = Priority.LAST,
        waiter: t.Optional["asyncio.Future[None]"] = None,
    ) -> None:
        """Send a PUB or HPUB protocol message."""
        reply = reply or ""
        payload = payload or b""

        if headers is None:
            self.send_command(
                PUB(subject=subject, reply=reply or "", payload=payload or b""),
                priority=priority,
                waiter=waiter,
            )
        else:
            self.send_command(
                HPUB(
                    subject=subject,
                    reply=reply or "",
                    headers=headers or Headers(),
                    payload=payload,
                ),
                priority=priority,
                waiter=waiter,
            )

    def send_subscribe(
        self,
        subject: str,
        sid: int,
        queue: t.Optional[str] = None,
        priority: Priority = Priority.LAST,
        waiter: t.Optional["asyncio.Future[None]"] = None,
    ) -> None:
        """Send a SUB protocol message."""
        queue = queue or ""
        self.send_command(
            SUB(subject=subject, sid=sid, queue=queue),
            priority=priority,
            waiter=waiter,
        )

    def send_unsubscribe(
        self,
        sid: int,
        limit: t.Optional[int] = None,
        priority: Priority = Priority.LAST,
        waiter: t.Optional["asyncio.Future[None]"] = None,
    ) -> None:
        """Send an UNSUB protocol message."""
        limit = limit or 0
        self.send_command(
            UNSUB(sid=sid, limit=limit),
            priority=priority,
            waiter=waiter,
        )

    async def flush(self, timeout: t.Optional[float] = None) -> None:
        self.notify_flush()
        await self.did_flush.wait(timeout=timeout)

    async def ping(
        self, priority: Priority = Priority.LAST, timeout: t.Optional[float] = None
    ) -> None:
        waiter: asyncio.Future[None] = asyncio.Future()
        self.send_ping(priority=priority, waiter=waiter)
        await asyncio.wait_for(waiter, timeout=timeout)

    async def pong(
        self, priority: Priority = Priority.LAST, timeout: t.Optional[float] = None
    ) -> None:
        waiter: asyncio.Future[None] = asyncio.Future()
        self.send_pong(priority=priority, waiter=waiter)
        await asyncio.wait_for(waiter, timeout=timeout)

    async def publish(
        self,
        subject: str,
        payload: t.Optional[bytes] = None,
        reply: t.Optional[str] = None,
        headers: t.Optional[Headers] = None,
        priority: Priority = Priority.LAST,
        timeout: t.Optional[float] = None,
    ) -> None:
        waiter: asyncio.Future[None] = asyncio.Future()
        self.send_publish(
            subject=subject,
            payload=payload,
            reply=reply,
            headers=headers,
            priority=priority,
            waiter=waiter,
        )
        await asyncio.wait_for(waiter, timeout=timeout)

    async def subscribe(
        self,
        subject: str,
        sid: int,
        queue: t.Optional[str] = None,
        priority: Priority = Priority.LAST,
        timeout: t.Optional[float] = None,
    ) -> None:
        waiter: asyncio.Future[None] = asyncio.Future()
        self.send_subscribe(
            subject=subject, sid=sid, queue=queue, priority=priority, waiter=waiter
        )
        await asyncio.wait_for(waiter, timeout=timeout)

    async def unsubscribe(
        self,
        sid: int,
        limit: t.Optional[int] = None,
        priority: Priority = Priority.LAST,
        timeout: t.Optional[float] = None,
    ) -> None:
        """Send an UNSUB protocol message."""
        waiter: asyncio.Future[None] = asyncio.Future()
        self.send_unsubscribe(sid=sid, limit=limit, priority=priority, waiter=waiter)
        await asyncio.wait_for(waiter, timeout=timeout)
