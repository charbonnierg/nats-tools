import asyncio
import types
import typing as t

from ...errors import (
    SlowObserverError,
    SubcriptionStoppedError,
    SubscriptionCancelledError,
    SubscriptionDrainingError,
)
from ...interfaces.connection import Connection
from ...interfaces.message import Msg
from ...interfaces.observable import Subscription
from ...interfaces.observer import Observer, Status, TooManyPendingMessagesError
from ..observers import SubscriptionCallback, SubscriptionIterator


class ObservableSubscription(Subscription[Msg]):
    def __init__(
        self,
        connection: Connection,
        sid: int,
        subject: str,
        queue: t.Optional[str],
        limit: t.Optional[int],
        drain_timeout: t.Optional[float] = None,
    ) -> None:
        self.connection = connection
        self.subject = subject
        self.queue = queue
        self.sid = sid
        self.limit = limit
        self.status = Status.CREATED
        self.drain_timeout = drain_timeout
        self.observers: t.List[Observer[Msg]] = []

    def update_connection(self, connection: Connection) -> None:
        self.connection = connection

    def get_sid(self) -> int:
        return self.sid

    def get_subject(self) -> str:
        return self.subject

    def get_queue(self) -> str:
        return self.queue or ""

    def get_limit(self) -> int:
        return self.limit or 0

    def deliver(self, msg: Msg) -> None:
        if self.status != Status.STARTED:
            return
        for subscriber in self.observers:
            try:
                subscriber.put_no_wait(msg)
            except TooManyPendingMessagesError:
                raise SlowObserverError(msg, self, subscriber)

    def cancel(self) -> None:
        if self.status == Status.CANCELLED or self.status == Status.STOPPED:
            return
        self.status = Status.CANCELLED

    async def start(
        self,
        connection: t.Optional[Connection] = None,
        timeout: t.Optional[float] = None,
    ) -> None:
        if self.status == Status.STOPPED:
            raise SubcriptionStoppedError(self)
        if self.status == Status.DRAINING:
            raise SubscriptionDrainingError(self)
        if self.status == Status.CANCELLED:
            raise SubscriptionCancelledError(self)
        self.status = Status.STARTED
        if connection:
            self.update_connection(connection)
        await self.connection.writer.subscribe(
            subject=self.subject,
            sid=self.sid,
            queue=self.queue,
            timeout=timeout,
        )
        self.connection.state.subscriptions[self.sid] = self

    async def kill(self) -> None:
        await self.connection.writer.unsubscribe(
            sid=self.sid, limit=0, timeout=self.drain_timeout
        )
        self.connection.state.subscriptions.pop(self.sid, None)
        if self.status == Status.CANCELLED or self.status == Status.STOPPED:
            return
        self.cancel()
        await asyncio.gather(*[subscriber.kill() for subscriber in self.observers])

    async def drain(self) -> None:
        await self.connection.writer.unsubscribe(
            sid=self.sid, limit=0, timeout=self.drain_timeout
        )
        self.connection.state.subscriptions.pop(self.sid, None)
        self.status = Status.DRAINING
        try:
            await asyncio.gather(*[subscriber.drain() for subscriber in self.observers])
        finally:
            self.status = Status.STOPPED

    def add_observer(self, observer: Observer[Msg]) -> None:
        if self.status == Status.STOPPED:
            raise SubcriptionStoppedError(self)
        if self.status == Status.DRAINING:
            raise SubscriptionDrainingError(self)
        if self.status == Status.CANCELLED:
            raise SubscriptionCancelledError(self)
        self.observers.append(observer)

    def remove_observer(self, observer: "Observer[Msg]") -> None:
        try:
            self.observers.remove(observer)
        except ValueError:
            pass

    def create_callback(
        self,
        function: t.Callable[[Msg], t.Awaitable[None]],
        error_callback: t.Callable[[Msg, Exception], t.Awaitable[None]],
        max_pending_msgs: t.Optional[int] = None,
    ) -> "SubscriptionCallback":
        if self.status == Status.STOPPED:
            raise SubcriptionStoppedError(self)
        if self.status == Status.DRAINING:
            raise SubscriptionDrainingError(self)
        if self.status == Status.CANCELLED:
            raise SubscriptionCancelledError(self)
        observer = SubscriptionCallback(
            self,
            function=function,
            error_callback=error_callback,
            max_pending_msgs=max_pending_msgs,
        )
        self.add_observer(observer)
        return observer

    def create_iterator(
        self, max_pending_msgs: t.Optional[int] = None
    ) -> "SubscriptionIterator":
        if self.status == Status.STOPPED:
            raise SubcriptionStoppedError(self)
        if self.status == Status.DRAINING:
            raise SubscriptionDrainingError(self)
        if self.status == Status.CANCELLED:
            raise SubscriptionCancelledError(self)
        observer = SubscriptionIterator(self, max_pending_msgs=max_pending_msgs)
        self.add_observer(observer)
        return observer

    async def __aenter__(self) -> "ObservableSubscription":
        await self.start(self.connection)
        return self

    async def __aexit__(
        self,
        exc_type: t.Optional[t.Type[BaseException]] = None,
        exc: t.Optional[BaseException] = None,
        tb: t.Optional[types.TracebackType] = None,
    ) -> None:
        await self.drain()
