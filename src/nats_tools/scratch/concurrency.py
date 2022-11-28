import asyncio
import typing as t

import typing_extensions as t_

T = t.TypeVar("T")
T_Return = t.TypeVar("T_Return")
T_Params = t_.ParamSpec("T_Params")


def get_event_loop_time() -> float:
    """Get current event loop time. Do not use as timestamp !"""
    return asyncio.get_event_loop().time()


def get_deadline(
    timeout: t.Optional[float] = None,
    deadline: t.Optional[float] = None,
    clock: t.Callable[[], float] = get_event_loop_time,
) -> float:
    """Get a deadline from either a timeout or a deadline.
    If both are None, float("inf") is returned.

    Deadline argument takes precedence over timeout argument.

    Arguments:
        timeout: value in seconds
        deadline: clock time (by default event loop time)
        clock (optional): a callable providing current time as float

    Returns:
        A float representing event loop time at which point timeout is reached
    """
    return deadline if deadline else clock() + timeout if timeout else float("inf")


def get_timeout(
    timeout: t.Optional[float] = None,
    deadline: t.Optional[float] = None,
    clock: t.Callable[[], float] = get_event_loop_time,
) -> float:
    """Get a timeout from either a timeout or a deadline.
    If both are None, float("inf") is returned.

    Deadline argument takes precedence over timeout argument.

    Arguments:
        timeout: value in seconds
        deadline: clock time (by default event loop time)
        clock (optional): a callable providing current time as float

    Returns:
        A float representing number of seconds to wait before timeout is reached
    """
    return deadline - clock() if deadline else timeout if timeout else float("inf")


def check_deadline(
    value: float,
    clock: t.Callable[[], float] = get_event_loop_time,
) -> bool:
    """Check if deadline is not expired

    Arguments:
        value: clock time (by default event loop time)
        clock (optional): a callable providing current time as float

    Returns:
        True if clock time is greater than deadline, else False
    """
    return value > clock()


async def wait_for_cancelled(
    task_or_future: "asyncio.Future[T]",
    timeout: t.Optional[float] = None,
    deadline: t.Optional[float] = None,
    clock: t.Callable[[], float] = get_event_loop_time,
) -> t.Optional[T]:
    """Cancel a task or future and wait until it is actually cancelled.

    This function may return in value in case task or future is already finished.
    Moreover, if an exception was encountered within task or future, exception is
    raised back.

    Arguments:
        task_or_future: an asyncio task or future which should be cancelled

    Result:
        None if task or future is cancelled, else task or future result.
    """
    timeout = get_timeout(timeout=timeout, deadline=deadline, clock=clock)
    if not task_or_future.done():
        task_or_future.cancel()
        _, pending = await asyncio.wait([task_or_future], timeout=timeout)
        if pending:
            raise asyncio.TimeoutError("Cancelled tasks are still pending")
    if task_or_future.cancelled():
        return None
    else:
        return task_or_future.result()


async def wait_for(
    awaitable: t.Awaitable[T],
    timeout: t.Optional[float] = None,
    deadline: t.Optional[float] = None,
    shield: bool = False,
    clock: t.Callable[[], float] = get_event_loop_time,
) -> T:
    """Wait for a single awaitable to complete.

    By default, if awaitable did not complete on time,
    it is cancelled, unless shield is set to True.

    If the wait is cancelled, the awaitable is also cancelled.

    Arguments:
        awaitable: a coroutine, a task or a future to wait for
        timeout: value in seconds
        deadline: clock time (by default event loop time)
        shield: when set to True, cancel scope is shielded against external cancellations
        clock (optional): a callable providing current time as float

    Returns:
        The awaitable result

    Raises:
        asyncio.TimeoutError: When awaitable did not finish on time
    """
    timeout = get_timeout(timeout, deadline, clock=clock)
    if not shield:
        return await asyncio.wait_for(awaitable, timeout=timeout)
    else:
        return await asyncio.wait_for(asyncio.shield(awaitable), timeout=timeout)


async def wait(
    awaitable: t.Iterable[t.Awaitable[T]],
    timeout: t.Optional[float] = None,
    deadline: t.Optional[float] = None,
    return_when: str = asyncio.ALL_COMPLETED,
    clock: t.Callable[[], float] = get_event_loop_time,
) -> t.Tuple[t.Set["asyncio.Task[T]"], t.Set["asyncio.Task[T]"]]:
    """Wait for a bunch of awaitable to complete.

    When return_when argument is set to `asyncio.FIRST_COMPLETE` or
    `asyncio.FIRST_EXCEPTION`, pending tasks are NOT cancelled before
    returning.

    Arguments:
        awaitable: an iterable or coroutines,tasks or futures to wait for
        timeout: value in seconds
        deadline: clock time (by default event loop time)
        return_when: either `asyncio.ALL_COMPLETED`, `asyncio.FIRST_COMPLETE` or `asyncio.FIRST_EXCEPTION`
        clock (optional): a callable providing current time as float

    """
    timeout = get_timeout(timeout, deadline, clock=clock)
    return await asyncio.wait(awaitable, timeout=timeout, return_when=return_when)


async def wait_first(**kwargs: t.Awaitable[T]) -> t.Tuple[str, T]:
    """Wait for one coroutine to finish amongst several coroutines and return result.

    All pending coroutines (when first coroutine is done) are cancelled.

    I always find it difficult to wait for the first
    of two tasks to complete when I need to access task result.
    As such, I only use wait() when I don't need to access task result.
    This function exists so that we can easily wait for one task amongst severals
    and access task result.

    Function usage is a bit unconventional, keyword argument names are used as keys
    identifying each coroutine or task provided as argument value.
    It returns a tuple (key, value) where key is the argument name of the first
    coroutine or task to finish, and value is the return value of said coroutine or task.

    NOTE: All coroutines/tasks are guaranteed to be finished when this function returns.
    All coroutines/tasks which are not done on time are cancelled and functions awaits until
    tasks are actually cancelled.

    Examples:
    >>> name, result = await wait_first(a=asyncio.sleep(1, result=10), b=asyncio.sleep(3600, result=1000))
    >>> print(name)  # The keyword argument name of first coroutineto finish
    "a"
    >>> print(result)  # The result of the first coroutine to finish
    10
    """
    cancelled_future: "asyncio.Future[None]" = asyncio.Future()
    kwargs["__cancelled_future__"] = cancelled_future  # type: ignore[assignment]
    tasks_to_names = {value: key for key, value in kwargs.items()}
    coros = list(tasks_to_names)
    try:
        done, pending = await asyncio.wait(
            coros, timeout=None, return_when=asyncio.FIRST_COMPLETED
        )
    except asyncio.CancelledError:
        # Set result of cancelled future, this will make sure that asyncio.wait will return immedialty
        cancelled_future.set_result(None)
        # It's useful to get back tasks, because it's the only way I know to cancel awaitable provided as coroutines
        done, pending = await asyncio.wait(
            coros, timeout=None, return_when=asyncio.FIRST_COMPLETED
        )
        # Cancel all tasks
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.wait(pending, timeout=None, return_when=asyncio.ALL_COMPLETED)
        # Raise error back
        raise
    if not pending:
        # Return first task accoring to argument order
        all_submitted = list(tasks_to_names)
        for task in done:
            if task in all_submitted:
                if task != all_submitted[0]:
                    continue
                return tasks_to_names[task], task.result()
            else:
                coro = task.get_coro()
                if coro != all_submitted[0]:
                    continue
                return tasks_to_names[coro], task.result()  # type: ignore[index]
    try:
        for task in done:
            if task in tasks_to_names:
                return tasks_to_names[task], task.result()
            else:
                coro = task.get_coro()
                return tasks_to_names[coro], task.result()  # type: ignore[index]
    finally:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.wait(pending, timeout=None, return_when=asyncio.ALL_COMPLETED)

    raise Exception("Unexpected error. At least one task should have finished")


async def wait_unless(
    awaitable: t.Awaitable[T], condition: "asyncio.Future[t.Any]"
) -> T:
    """Wait for coroutine result unless condition finishes before.

    Arguments:
        awaitable: an awaitable (coroutine, task or future) to wait for
        condition: an asyncio future (or task) which should trigger cancellation of awaitable when done

    Returns:
        The result of the awaitable provided as argument

    Raises:
        AbortedError: When condition is done before awaitable
    """
    future: asyncio.Future[t.Optional[None]] = asyncio.Future()

    # Create a callback to execute when NATS client is stopped
    def callback(task: "asyncio.Future[t.Any]") -> None:
        """Notify asyncio.Future that client is closed"""
        futures = getattr(task, "__waiters__")
        for future in futures:
            if not future.done():
                future.set_result(None)
        futures.clear()

    # Avoiding adding too many done callbacks
    if not hasattr(condition, "__waiters__"):
        setattr(condition, "__waiters__", [future])
        condition.add_done_callback(callback)
    else:
        condition.__waiters__.append(future)  # type: ignore[attr-defined]

    # Wait until awaitable or future is done and cancel pending task
    first, result = await wait_first(target=awaitable, early_stop=future)
    # Check if awaitable or condition ended first, and cleanup future when required
    if first == "early_stop":
        raise AbortedError("Coroutine did not finish before condition")
    else:
        try:
            condition.__waiters__.remove(future)  # type: ignore[attr-defined]
        except ValueError:
            pass
    # Return result
    return t.cast(T, result)


async def wait_until(
    awaitable: t.Awaitable[T],
    timeout: t.Optional[float] = None,
    deadline: t.Optional[float] = None,
    clock: t.Callable[[], float] = get_event_loop_time,
) -> T:
    task = asyncio.create_task(
        asyncio.sleep(get_timeout(timeout, deadline, clock=clock))
    )
    try:
        result = await wait_unless(awaitable, task)
    except AbortedError:
        await wait_for_cancelled(task)
        raise asyncio.TimeoutError("Deadline exceeded")
    # Await task
    await task
    # Return result
    return result


class FutureEvent(t.Generic[T]):
    def __init__(self) -> None:
        self.subscribers: t.List["asyncio.Future[T]"] = []

    def future(self) -> "asyncio.Future[T]":
        future: asyncio.Future[T] = asyncio.Future()
        self.subscribers.append(future)
        return future

    def subscribe(self, future: "asyncio.Future[T]") -> None:
        if not future.done():
            self.subscribers.append(future)

    async def wait(
        self,
        timeout: t.Optional[float] = None,
        deadline: t.Optional[float] = None,
        clock: t.Callable[[], float] = get_event_loop_time,
    ) -> T:
        future = self.future()
        return await wait_for(future, timeout=timeout, deadline=deadline, clock=clock)

    def notify(self, value: T) -> None:
        all_subscribers = list(self.subscribers)
        self.subscribers.clear()
        for subscriber in all_subscribers:
            if not subscriber.done():
                subscriber.set_result(value)

    def notify_exception(self, exception: BaseException) -> None:
        all_subscribers = list(self.subscribers)
        self.subscribers.clear()
        for subscriber in all_subscribers:
            if not subscriber.done():
                subscriber.set_exception(exception)


class AbortedError(Exception):
    pass
