import abc
import asyncio
import typing as t

from .message import Msg


class InboxGenerator(metaclass=abc.ABCMeta):
    """Any implementation of generator of unique identifiers used for inboxes in NATS."""

    @abc.abstractmethod
    def next(self) -> str:
        """
        next returns the next unique identifier.
        """
        raise NotImplementedError


class RequestMultiplexer:
    def __init__(
        self, prefix: t.Optional[str], inbox_generator: InboxGenerator
    ) -> None:
        self.inbox_generator = inbox_generator
        self.prefix = prefix or f"_RMUX.{inbox_generator.next()}"
        while self.prefix.endswith("."):
            self.prefix = self.prefix[:-1]
        self.subject = f"{prefix}.>"
        self.replies_map: t.Dict[str, "asyncio.Future[Msg]"] = {}

    def __call__(self, msg: Msg) -> None:
        subject = msg.subject
        if subject and subject in self.replies_map:
            future = self.replies_map[subject]
            if not future.done():
                future.set_result(msg)

    def __future_callback__(
        self, subject: str
    ) -> t.Callable[["asyncio.Future[Msg]"], None]:
        def _callback(_: "asyncio.Future[Msg]") -> None:
            self.replies_map.pop(subject, None)

        return _callback

    def cancel(self) -> t.List["asyncio.Future[Msg]"]:
        futures: t.List["asyncio.Future[Msg]"] = []
        while self.replies_map:
            _, future = self.replies_map.popitem()
            if not future.done():
                future.cancel()
                futures.append(future)
        return futures

    def create_future_reply(self) -> str:
        subject = self.prefix + "." + self.inbox_generator.next()
        future = self.replies_map[subject] = asyncio.Future()
        future.add_done_callback(self.__future_callback__(subject))
        return subject

    def cancel_future_reply(self, subject: str) -> None:
        future = self.replies_map.get(subject, None)
        if future and not future.done():
            future.cancel()

    async def wait_future_reply(
        self, subject: str, timeout: t.Optional[float] = None
    ) -> Msg:
        """Wait for reply before timeout.

        It timeout is reached, future is cancelled, and timeout
        """
        future = self.replies_map.get(subject, None)
        if future is None:
            raise KeyError("No pending request for subject")
        if future.done():
            return future.result()
        return await asyncio.wait_for(future, timeout=timeout)

    async def close(self, timeout: t.Optional[float] = None) -> None:
        await asyncio.wait(self.cancel(), timeout=timeout)
