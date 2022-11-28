import asyncio
import typing as t

from ...interfaces.message import Msg
from ...interfaces.observable import Subscription
from ...interfaces.observer import NoMessageError, Observer, Status


class SubscriptionCallback(Observer[Msg]):
    def __init__(
        self,
        subscription: Subscription[Msg],
        function: t.Callable[[Msg], t.Awaitable[None]],
        error_callback: t.Callable[[Msg, Exception], t.Awaitable[None]],
        max_pending_msgs: t.Optional[int] = None,
    ) -> None:
        super().__init__(
            subscription,
            max_pending_msgs=max_pending_msgs,
            max_getters=1,
            max_setters=1,
        )
        self.function = function
        self.error_callback = error_callback
        self.task: t.Optional["asyncio.Task[None]"] = None

    def task_factory(self) -> "asyncio.Task[t.Any]":
        return asyncio.create_task(self.loop())

    async def loop(self) -> None:
        while True:
            # Exit when susbcriber is done
            if self.done():
                return
            try:
                msg = self.get_no_wait()
            except NoMessageError:
                if self.status == Status.DRAINING:
                    return
                else:
                    # Wait for next message until subscriber is stopped
                    msg = await self.get()
            # Execute callback
            try:
                await self.function(msg)
            except Exception as exc:
                try:
                    await self.error_callback(msg, exc)
                except Exception:
                    pass
