import abc
import types
import typing as t

if t.TYPE_CHECKING:
    from .connection import Connection
    from .observer import Observer

T = t.TypeVar("T")
SubscriptionT = t.TypeVar("SubscriptionT", bound="Subscription[t.Any]")


class Subscription(t.Generic[T], metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __init__(
        self,
        connection: "Connection",
        sid: int,
        subject: str,
        queue: t.Optional[str],
        limit: t.Optional[int],
        drain_timeout: t.Optional[float] = None,
    ) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def get_sid(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def get_subject(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_queue(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_limit(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def deliver(self, item: T) -> None:
        ...

    @abc.abstractmethod
    def add_observer(self, observer: "Observer[T]") -> None:
        ...

    @abc.abstractmethod
    def remove_observer(self, observer: "Observer[T]") -> None:
        ...

    @abc.abstractmethod
    def cancel(self) -> None:
        ...

    @abc.abstractmethod
    async def start(
        self,
        connection: t.Optional["Connection"] = None,
        timeout: t.Optional[float] = None,
    ) -> None:
        ...

    @abc.abstractmethod
    async def kill(self) -> None:
        ...

    @abc.abstractmethod
    async def drain(self) -> None:
        ...

    @abc.abstractmethod
    async def __aenter__(self: SubscriptionT) -> SubscriptionT:
        ...

    @abc.abstractmethod
    async def __aexit__(
        self,
        exc_type: t.Optional[t.Type[BaseException]] = None,
        exc: t.Optional[BaseException] = None,
        tb: t.Optional[types.TracebackType] = None,
    ) -> None:
        ...
