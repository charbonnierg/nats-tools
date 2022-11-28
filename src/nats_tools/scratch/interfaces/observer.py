import abc
import asyncio
import collections
import enum
import types
import typing as t

if t.TYPE_CHECKING:
    from .observable import Subscription


T = t.TypeVar("T")


class SubscriberError(Exception):
    def __init__(
        self,
        subscriber: "Observer[t.Any]",
    ) -> None:
        self.susbcriber = subscriber


class NoMessageError(SubscriberError):
    pass


class TooManyPendingMessagesError(SubscriberError):
    pass


class TooManyGettersError(SubscriberError):
    pass


class TooManySettersError(SubscriberError):
    pass


class SubscriberStatusError(SubscriberError):
    def __init__(
        self,
        status: "Status",
        expected: t.Union["Status", t.Iterable["Status"]],
        subscriber: "Observer[t.Any]",
    ) -> None:
        super().__init__(subscriber)
        self.status = status
        self.expected_status = (
            (expected,) if isinstance(expected, Status) else tuple(expected)
        )


class Status(enum.Enum):
    CREATED = "created"
    STARTED = "started"
    DRAINING = "draining"
    CANCELLED = "cancelled"
    STOPPED = "stopped"
    FAILED = "failed"


StatusT = t.TypeVar("StatusT", bound=Status)


class Observer(t.Generic[T]):
    """This class is an attempt to somehow imitate the behaviour of asyncio.Queue, while providing explicit methods to cancel waiters and setters.

    Usage:
    >>> subscriber = Subscriber()
    >>> subscriber.put_no_wait(1)
    >>> subscriber.get_no_wait()
    1
    >>> await subscriber.put(2)
    >>> await subscriber.get()
    2
    >>> task = asyncio.create_task(subscriber.get())
    >>> await subscriber.put(2)
    >>> await task
    2
    """

    def __init__(
        self,
        observable: "Subscription[t.Any]",
        max_pending_msgs: t.Optional[int] = None,
        max_setters: t.Optional[int] = None,
        max_getters: t.Optional[int] = None,
        drain_timeout: t.Optional[float] = None,
    ) -> None:
        # Store reference to observable
        self.observable = observable
        # Each subscriber can save pending messages in memory up to max_pending_msgs
        self.max_pending_msgs = max_pending_msgs
        self.max_getters = max_getters
        self.max_setters = max_setters
        self.drain_timeout = drain_timeout
        # Subscriber is a finite state machine, it has a status
        self.status = Status.CREATED
        # It's possible for waiters to subscribe to status update
        self.waiters: t.List["asyncio.Future[Status]"] = []
        # Pending messages are stored within deque
        self.deque: t.Deque[T] = collections.deque()
        # Pending getters are stored within deque
        self.getters: t.Deque["asyncio.Future[T]"] = collections.deque()
        # Pending setters are stored within deque
        self.setters: t.Deque["asyncio.Future[None]"] = collections.deque()
        # An observer may run an asyncio task
        self.task: t.Optional[asyncio.Task[t.Any]] = None

    def task_cleanup(self, task: "asyncio.Task[None]") -> None:
        if self.done():
            return
        # Make sure every future is cancelled
        self.cancel()
        # Remove observer from observable
        self.observable.remove_observer(self)

    @abc.abstractmethod
    def task_factory(self) -> t.Optional["asyncio.Task[t.Any]"]:
        raise NotImplementedError

    def expect_status(self, *expected_status: StatusT) -> StatusT:
        """Expect observer status to be one of status provided as arguments."""
        if self.status in expected_status:
            return self.status  # type: ignore[return-value]
        else:
            raise SubscriberStatusError(
                status=self.status, expected=expected_status, subscriber=self
            )

    def notify_status(self, status: Status) -> None:
        """Notify a change of observer status."""
        if status == self.status:
            return
        self.status = Status(status)
        waiters = list(self.waiters)
        self.waiters.clear()
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(self.status)

    def done(self) -> bool:
        """Return True when observer is either stopped or cancelled."""
        # Check if we can consider subscriber stopped draining
        if self.status == Status.DRAINING and not (self.deque or self.getters):
            if self.task is None:
                self.notify_status(Status.STOPPED)
            elif self.task.done():
                if self.task.cancelled():
                    self.notify_status(Status.STOPPED)
                elif self.task.exception():
                    self.notify_status(Status.FAILED)
                else:
                    self.notify_status(Status.STOPPED)
        # Check if subscriber is stopped
        if (
            self.status == Status.CANCELLED
            or self.status == Status.STOPPED
            or self.status == Status.FAILED
        ):
            if self.task is None or self.task.done():
                return True
        return False

    def cancel(self) -> None:
        """Cancel observer and all futures associated with it."""
        # Cancel everything
        while self.getters:
            self.getters.pop().cancel()
        while self.setters:
            self.setters.pop().cancel()
        self.deque.clear()
        # Notify draining state
        if self.task is None or self.task.done():
            self.notify_status(Status.CANCELLED)
        else:
            self.task.add_done_callback(lambda _: self.notify_status(Status.CANCELLED))
            self.task.cancel()

    async def wait_for_next_status(self) -> Status:
        """Wait for next status and return status.

        If subscriber is done, subscriber status is returned immediatly.
        """
        if self.done():
            return self.status
        future: asyncio.Future[Status] = asyncio.Future()
        self.waiters.append(future)
        return await asyncio.wait_for(future, timeout=None)

    async def wait_for_status(self, *expected_status: StatusT) -> StatusT:
        if self.status in expected_status:
            return self.status  # type: ignore[return-value]
        while True:
            if self.done():
                self.expect_status(*expected_status)
            status = await self.wait_for_next_status()
            if status in expected_status:
                return status  # type: ignore[return-value]

    def notify_drain(self) -> None:
        self.expect_status(Status.STARTED)
        self.notify_status(Status.DRAINING)
        # Cancel getters when draining if any exist
        # (having getters means that deque is empty)
        while self.getters:
            self.getters.pop().cancel()

    def get_no_wait(self) -> T:
        """Get an item from the subscription without waiting"""
        # Check if we should stop
        self.expect_status(Status.STARTED, Status.DRAINING)
        # Fetch from deque
        try:
            msg = self.deque.popleft()
        except IndexError:
            raise NoMessageError(subscriber=self)
        # Notify next setter that there's a free slot
        while self.setters:
            future = self.setters.popleft()
            if not future.done():
                future.set_result(None)
                break
        # Check if we're done
        self.done()
        return msg

    async def get(self) -> T:
        """Get an item from the subscription or wait until next item before returning item"""
        # Try to fetch from deque first
        try:
            return self.get_no_wait()
        except NoMessageError:
            pass
        # Check that it's possible to add a getter
        if self.max_getters and len(self.getters) >= self.max_getters:
            raise TooManyGettersError(subscriber=self)
        # Create a new getter (future)
        future: "asyncio.Future[T]" = asyncio.Future()
        self.getters.append(future)
        # Await getter
        msg = await asyncio.wait_for(future, timeout=None)
        # Check if we need to update status
        self.done()
        return msg

    def put_no_wait(self, item: T) -> None:
        """Put an item without waiting"""
        # Put is allowed only when status is PENDING
        self.expect_status(Status.STARTED)
        # Check if pending messages number exceeds limit
        if self.max_pending_msgs and len(self.deque) >= self.max_pending_msgs:
            raise TooManyPendingMessagesError(subscriber=self)
        # If there are getters which are still waiting
        if self.getters:
            while self.getters:
                future = self.getters.popleft()
                if not future.done():
                    # Deliver item directly to waiter (I.E, no need to store within deque)
                    future.set_result(item)
                    return
        # Append item to deque if there is not getter
        self.deque.append(item)

    async def put(self, item: T) -> None:
        """Put an item or wait for free slot before putting the item"""
        try:
            self.put_no_wait(item)
            return
        except TooManyPendingMessagesError:
            pass
        if self.max_setters and len(self.setters) >= self.max_setters:
            raise TooManySettersError(subscriber=self)
        # Create a new future and append it to setters deque
        future: "asyncio.Future[None]" = asyncio.Future()
        self.setters.append(future)
        await asyncio.wait_for(future, timeout=None)
        # Call put_no_wait again
        self.put_no_wait(item)

    async def kill(self) -> None:
        """Stop without waiting for pending messages to be processed"""
        if self.done():
            return
        self.cancel()
        all_tasks = list(self.getters) + list(self.setters)
        if self.task:
            all_tasks += [self.task]
        if all_tasks:
            await asyncio.wait(
                all_tasks,
                return_when=asyncio.ALL_COMPLETED,
                timeout=None,
            )

    async def drain(self) -> None:
        """Drain the subscriber."""
        if self.done():
            return
        self.notify_drain()
        try:
            await self.wait_for_status(Status.STOPPED, Status.CANCELLED, Status.FAILED)
        except asyncio.TimeoutError:
            await self.kill()
            raise

    async def join(self) -> None:
        if self.done():
            return
        await self.wait_for_status(Status.STOPPED, Status.CANCELLED, Status.FAILED)

    async def reset(self) -> None:
        await self.kill()
        self.notify_status(Status.CREATED)
        await self.start()

    async def start(self) -> None:
        self.expect_status(Status.CREATED)
        task = self.task_factory()
        if task is None:
            self.notify_status(Status.STARTED)
            return
        task.add_done_callback(self.task_cleanup)
        self.task = task

    async def __aenter__(self) -> "Observer[T]":
        if self.status == Status.STARTED:
            return self
        else:
            await self.start()
            return self

    async def __aexit__(
        self,
        exc_type: t.Optional[t.Type[BaseException]] = None,
        exc: t.Optional[BaseException] = None,
        tb: t.Optional[types.TracebackType] = None,
    ) -> None:
        await self.drain()
