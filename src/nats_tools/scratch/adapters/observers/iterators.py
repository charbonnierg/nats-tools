import asyncio
import typing as t

from ...interfaces.message import Msg
from ...interfaces.observable import Subscription
from ...interfaces.observer import Observer


class SubscriptionIterator(Observer[Msg]):
    def __init__(
        self,
        subscription: Subscription[Msg],
        max_pending_msgs: t.Optional[int] = None,
    ) -> None:
        super().__init__(
            subscription,
            max_pending_msgs=max_pending_msgs,
            max_getters=1,
            max_setters=1,
        )
        self.iterator_getters: t.List[asyncio.Task[Msg]] = []

    def task_factory(self) -> None:
        return None

    def cleanup_getter(self, task: "asyncio.Task[Msg]") -> None:
        try:
            self.iterator_getters.remove(task)
        except ValueError:
            pass

    def __aiter__(self) -> "SubscriptionIterator":
        return self

    async def __anext__(self) -> Msg:
        getter = asyncio.create_task(self.get())
        self.iterator_getters.append(getter)
        getter.add_done_callback(self.cleanup_getter)
        return await getter
