import typing as t

if t.TYPE_CHECKING:
    from .interfaces.message import Msg
    from .interfaces.observable import Subscription
    from .interfaces.observer import Observer


# Client errors
class NATSClientError(Exception):
    def __init__(self, msg: str) -> None:
        self.error = msg

    def __repr__(self) -> str:
        return f"NATSClientError(type={self.__class__.__name__}, error={self.error})"


class StateConnectionError(NATSClientError):
    def __init__(self, interval: float, max_outstanding: int, outstanding: int) -> None:
        super().__init__(f"{outstanding} outstanding pings")
        self.interval = interval
        self.outstanding = outstanding
        self.max_outstanding = max_outstanding


class SubscriptionError(NATSClientError):
    def __init__(self, error: str, subscription: "Subscription[t.Any]") -> None:
        super().__init__(error)
        self.subscription = subscription


class SubcriptionStoppedError(SubscriptionError):
    def __init__(self, subscription: "Subscription[t.Any]") -> None:
        super().__init__("Subscription is stopped", subscription)


class SubscriptionDrainingError(SubscriptionError):
    def __init__(self, subscription: "Subscription[t.Any]") -> None:
        super().__init__("Subscription is draining", subscription)


class SubscriptionCancelledError(SubscriptionError):
    def __init__(self, subscription: "Subscription[t.Any]") -> None:
        super().__init__("Subscription was cancelled", subscription)


class ObserverError(SubscriptionError):
    def __init__(
        self,
        error: str,
        subscription: "Subscription[t.Any]",
        observer: "Observer[t.Any]",
    ) -> None:
        super().__init__(error, subscription)
        self.observer = observer


class SlowObserverError(ObserverError):
    def __init__(
        self,
        msg: "Msg",
        subscription: "Subscription[t.Any]",
        observer: "Observer[t.Any]",
    ) -> None:
        super().__init__("Slow observer", subscription, observer)
        self.msg = msg
