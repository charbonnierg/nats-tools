"""A proof-of-concept for a Python implementation of NATS isolation context client."""
import asyncio
import base64
from datetime import datetime, timezone
import logging
import types
import typing as t
from nats import NATS
from nats.aio.client import (
    DEFAULT_SUB_PENDING_MSGS_LIMIT,
    DEFAULT_SUB_PENDING_BYTES_LIMIT,
)
from nats.aio.msg import Msg
from nats.aio.subscription import Subscription
import nats.errors

from nats_tools import jwts
from nats_tools import nkeys
from nats_tools.auth.providers.protocol import CredsProvider

import jinja2


logger = logging.getLogger("nats_tools.client")


LIFECYCLE_EVENT = t.Literal[
    "disconnected", "reconnected", "discovered_server", "connected", "closed"
]
LIFECYCLE_CB_NAME = t.Literal[
    "disconnected_cb", "reconnected_cb", "discovered_server_cb", "closed_cb"
]
LIFECYCLE_CB = t.Callable[[], t.Coroutine[None, None, None]]
ERROR_CB = t.Callable[[Exception], t.Coroutine[None, None, None]]


class LifecycleEvent:
    def __init__(
        self,
        typ: LIFECYCLE_EVENT,
        server_info: t.Optional[t.Dict[str, t.Any]],
        discovered_servers: t.Optional[t.List[str]] = None,
        client_options: t.Optional[t.Dict[str, t.Any]] = None,
        last_error: t.Optional[Exception] = None,
        timestamp: t.Optional[datetime] = None,
    ) -> None:
        self.typ = typ
        self.server_info = server_info
        self.client_options = client_options
        self.discovered_servers = discovered_servers
        self.last_error = last_error
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_values(self) -> t.Dict[str, t.Any]:
        values: t.Dict[str, t.Any] = {
            "typ": self.typ,
            "server_info": self.server_info,
            "last_error": repr(self.last_error),
            "timestamp": self.timestamp.isoformat(),
        }
        if self.client_options:
            values["client_options"] = self.client_options
        if self.discovered_servers:
            values["discovered_servers"] = self.discovered_servers

        return values

    def __repr__(self) -> str:
        return repr(self.to_values())


class LifecycleSubscription:
    def __init__(
        self,
        context: "NATSContext",
        max_events: t.Optional[int] = None,
        max_history: int = 100,
    ) -> None:
        self.stopped: t.Optional[bool] = None
        self.maxsize = max_history
        self.max_events = max_events
        self.context = context
        self.queue: "t.Optional[asyncio.Queue[LifecycleEvent]]" = None
        self._counter = 0

    async def start(self) -> None:
        if self.stopped is False:
            return
        self.queue = asyncio.Queue(maxsize=self.maxsize)
        self._counter = 0
        self.context._lifecycle_events_subscribers.append(self)
        self.stopped = False

    async def unsubscribe(self) -> None:
        try:
            self.context._lifecycle_events_subscribers.remove(self)
        except ValueError:
            pass
        self.stopped = True

    async def __aenter__(self) -> "LifecycleSubscription":
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: t.Optional[t.Type[BaseException]] = None,
        exc: t.Optional[BaseException] = None,
        traceback: t.Optional[types.TracebackType] = None,
    ) -> None:
        await self.unsubscribe()

    def deliver(self, event: LifecycleEvent) -> None:
        queue = self.queue
        if queue is None:
            return
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            # Evict oldest entry in queue
            queue.get_nowait()
            queue.task_done()
            # And put back in queue
            queue.put_nowait(event)

    async def events(self) -> t.AsyncIterator[LifecycleEvent]:
        if self.queue is None:
            raise ValueError("Subscriber is not started yet")
        while True:
            yield await self.queue.get()
            self._counter += 1
            if self.max_events and self._counter >= self.max_events:
                return


class NATSContext:
    """An NATS Context can be used to connect to NATS servers using NKEY/JWT authentication/authorization.

    It providers helper methods to fetch infos regarding both the user and the account client connects to.

    In order to use an NATSContext, client must be in possession of NATS Credentials. In order to facilitate
    credentials retrieval, the `nats_tools.auth.CredsProvider` class can be used.
    """

    def __init__(
        self,
        creds: CredsProvider,
        account_id: t.Optional[str] = None,
        scope: t.Optional[str] = None,
        verify: bool = True,
        debug: bool = False,
        options: t.Optional[t.Mapping[str, t.Any]] = None,
        account_jwt_subject: str = "$SYS.REQ.ACCOUNT.CLAIMS.LOOKUP",
    ) -> None:
        """Create a new NATS broker."""
        self.creds = creds
        self.options: t.Dict[str, t.Any] = dict(options or {})
        self.client_id = account_id
        self.scope = scope
        self.verify = verify
        self.nc: t.Optional[NATS] = None
        self.debug = debug
        # Subject used to lookup account claims
        self._account_jwt_subject = account_jwt_subject
        # Initialize variables holding JWT claims
        self._user: t.Optional[jwts.types.ScopedUserClaims] = None
        self._account: t.Optional[jwts.types.AccountClaims] = None
        # Initialize template environment
        self._template_environment = jinja2.Environment(
            undefined=jinja2.StrictUndefined
        )
        self._template_arguments: t.Dict[str, t.Any] = {}
        # Initialize client event queue
        self._lifecycle_events_subscribers: t.List[LifecycleSubscription] = []

    def __deliver_event(self, event: LifecycleEvent) -> None:
        # Deliver lifecycle event to subscribers
        subscribers = list(self._lifecycle_events_subscribers)
        for idx, subscriber in enumerate(subscribers):
            queue = subscriber.queue
            if queue is None:
                continue
            if subscriber.stopped:
                self._lifecycle_events_subscribers.pop(idx)
                continue
            subscriber.deliver(event)

    async def __process_event(
        self, typ: LIFECYCLE_EVENT, cb: LIFECYCLE_CB_NAME
    ) -> None:
        if self.nc is None:
            return
        nc = self.nc
        event = LifecycleEvent(
            typ,
            discovered_servers=nc.discovered_servers,
            last_error=nc.last_error,
            server_info=nc._server_info,
            client_options=nc.options,
        )
        self.__deliver_event(event)
        # Optionally run cb
        callback: t.Optional[LIFECYCLE_CB] = self.options.get(cb, None)
        if callback:
            try:
                await callback()
            except Exception as exc:
                await self.__error_cb(exc)

    async def __disconnected_cb(self) -> None:
        """Callback executed when client is disconnected."""
        if self.debug:
            logger.warning("NATS client is disconnected")
        await self.__process_event("disconnected", "disconnected_cb")

    async def __reconnected_cb(self) -> None:
        """Callback executed when client is reconnected."""
        if self.debug:
            logger.warning("NATS client is reconnected")
        await self.__process_event("reconnected", "reconnected_cb")

    async def __closed_cb(self) -> None:
        """Callback executed when client is closed."""
        if self.debug and self.nc:
            logger.warning("NATS client is closed")
        await self.__process_event("closed", "closed_cb")

    async def __discovered_cb(self) -> None:
        """Callback executed when client notifies discovery of an NATS server"""
        if self.debug and self.nc:
            logger.warning(
                f"NATS client discovered servers ({self.nc.discovered_servers})"
            )
        await self.__process_event("discovered_server", "discovered_server_cb")

    async def __error_cb(self, exception: Exception) -> None:
        """Callback executed when client encounters an error"""
        if self.debug:
            logger.warning(f"NATS client encountered error: {repr(exception)}")
        cb = self.options.get("error_cb", None)
        if cb:
            try:
                await cb(exception)
            except Exception as exc:
                logger.error("Uncatched exception in error callback", exc_info=exc)

    def __signature_cb(self, nonce: str) -> bytes:
        """Callback executed when NATS server requires client to sign a NKEY challenge."""
        seed = self.creds.get_seed()
        raw_signature = nkeys.sign(seed, data=nonce.encode("utf-8"))
        return base64.b64encode(raw_signature)

    def __user_jwt_cb(self) -> bytes:
        """Callback executed when NATS client lookup user JWT"""
        return self.creds.get_token(
            self.client_id, self.scope, verify=self.verify
        ).encode("utf-8")

    def get_statistics(self) -> t.Dict[str, int]:
        """Get client statistics"""
        if self.nc is None:
            return {}
        return self.nc.stats

    def get_expire_timestamp(self) -> t.Optional[datetime]:
        """Get expiration timestamp from user JWT"""
        claims = self.get_user_claims()
        return claims.get_expire_timestamp()

    def get_user(self) -> str:
        """Get user public key from user JWT"""
        if self._user is None:
            raise ValueError("User has not been authenticated yet")
        return self._user.sub

    def get_name(self) -> str:
        """Get user name found in user JWT"""
        return self.get_user_claims().name

    def get_account(self) -> str:
        """Get account public key from user JWT."""
        claims = self.get_user_claims()
        # When user is signed by a signing key, "nats.issuer_account" is the account public key.
        if claims.nats.issuer_account is not None:
            return claims.nats.issuer_account
        # When user is signed by the account key, "iss" field is the account public key.
        return claims.iss

    def get_user_limits(self) -> t.Dict[str, t.Any]:
        """Get user limits from user JWT."""
        account_claims = self.get_account_claims()
        user_claims = self.get_user_claims()
        if account_claims.nats.signing_keys is None:
            return user_claims.nats.to_values()
        for key in account_claims.nats.signing_keys:
            if isinstance(key, jwts.types.SigningKey):
                if nkeys.encoding.decode_public_key(
                    key.key
                ) == nkeys.encoding.decode_public_key(user_claims.iss):
                    if key.template is None:
                        return user_claims.nats.to_values()
                    return key.template.to_values()
        return user_claims.nats.to_values()

    def get_account_limits(self) -> t.Dict[str, t.Any]:
        """Get user limits from account JWT."""
        account_claims = self.get_account_claims()
        if account_claims.nats.limits is None:
            return {}
        return account_claims.nats.limits.to_values()

    def get_user_claims(self) -> jwts.types.ScopedUserClaims:
        """Get user claims from  user JWT"""
        if self._user is None:
            raise ValueError("User has not been authenticated yet")
        return self._user

    def get_account_claims(self) -> jwts.types.AccountClaims:
        """Get account claims from account JWT"""
        if self._account is None:
            raise ValueError("Account has not been retrieved yet")
        return self._account

    def get_context_variables(self) -> t.Dict[str, t.Any]:
        """Get context variables which can be used in subject when publishing, requesting or subscribing."""
        user_claims = self.get_user_claims()
        account_claims = self.get_account_claims()
        variables = self._template_arguments.copy()
        variables.update(
            {
                "user_id": user_claims.sub,
                "username": user_claims.name,
                "tags": user_claims.nats.parse_tags(),
                "account_id": account_claims.sub,
                "account_name": account_claims.name,
                "user_claims": user_claims,
                "account_claims": account_claims,
            }
        )
        return variables

    def set_context_variable(self, key: str, value: t.Any) -> None:
        """Set a context variable available when templating subjects and queues"""
        self._template_arguments[key] = value

    def update_context_variables(self, values: t.Mapping[str, t.Any]) -> None:
        """Update context variables available when templating subjects and queues"""
        self._template_arguments.update(values)

    def clear_context_variables(self) -> None:
        """Remove user provided context variables available when templating subjects and queues"""
        self._template_arguments.clear()

    def get_nats_options(self) -> t.Dict[str, t.Any]:
        """Get options used by NATS clients"""
        options = self.options.copy()
        options["signature_cb"] = self.__signature_cb
        options["user_jwt_cb"] = self.__user_jwt_cb
        options["disconnected_cb"] = self.__disconnected_cb
        options["reconnected_cb"] = self.__reconnected_cb
        options["discovered_server_cb"] = self.__discovered_cb
        options["error_cb"] = self.__error_cb
        options["closed_cb"] = self.__closed_cb
        if self._user and "inbox_prefix" not in options:
            options["inbox_prefix"] = f"_INBOX.{self._user.sub}".encode("utf-8")
        return options

    def set_nats_option(self, key: str, value: t.Any) -> None:
        """Set an option used by NATS clients

        WARNING: Options are only used on first connection. The "reconnect" method must be called to apply changes.
        """
        self.options[key] = value

    def update_nats_options(self, values: t.Mapping[str, t.Any]) -> None:
        """Update options used by NATS clients.

        WARNING: Options are only used on first connection. The "reconnect" method must be called to apply changes.
        """
        self.options.update(values)

    def clear_nats_options(self) -> None:
        """Remove options used by NATS clients.

        WARNING: Options are only used on first connection. The "reconnect" method must be called to apply changes.
        """
        self.options.clear()

    def list_imported_services(self) -> t.List[jwts.types.Import]:
        """List services imported within context"""
        claims = self.get_account_claims()
        if claims.nats.imports is None:
            return []
        return [
            import_spec
            for import_spec in claims.nats.imports
            if import_spec.type == jwts.types.ActivationType.SERVICE
        ]

    def list_imported_streams(self) -> t.List[jwts.types.Import]:
        """List streams imported within context"""
        claims = self.get_account_claims()
        if claims.nats.imports is None:
            return []
        return [
            import_spec
            for import_spec in claims.nats.imports
            if import_spec.type == jwts.types.ActivationType.STREAM
        ]

    def list_exported_services(self) -> t.List[jwts.types.Export]:
        """List services exported within context"""
        claims = self.get_account_claims()
        if claims.nats.exports is None:
            return []
        return [
            export_spec
            for export_spec in claims.nats.exports
            if export_spec.type == jwts.types.ActivationType.SERVICE
        ]

    def list_exported_streams(self) -> t.List[jwts.types.Export]:
        """List streams exported within context"""
        claims = self.get_account_claims()
        if claims.nats.exports is None:
            return []
        return [
            export_spec
            for export_spec in claims.nats.exports
            if export_spec.type == jwts.types.ActivationType.STREAM
        ]

    async def refresh_account_claims(self) -> jwts.types.AccountClaims:
        # Fetch account JWT
        # This require a particular setup.
        # It's not trivial, and should not be described here, but that will suffice until a proper doc is written
        # The following export needs to be created on SYS account:
        # {"account_token_position": 4, "name": "Account JWT Service","response_type": "Singleton", "subject": "$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP", "type": "service"}
        # All accounts should import this export in order to be able to query their own JWT.
        # It's useful because it allows anyone to discover imports and exports on connection
        # In order to facilitate things, the following signing key can be used for many accounts
        # {
        #   "kind": "user_scope",
        #   "template": {
        #     "pub": {"allow": ["$SYS.REQ.ACCOUNT.CLAIMS.LOOKUP", "{{subject()}}.\u003e"]},
        #     "sub": {"allow": ["_INBOX.{{subject()}}.\u003e", "{{subject()}}.\u003e"]}
        #   }
        # }
        if self.nc is None:
            raise ValueError("NATS context is not connected yet")
        reply = await self.nc.request(self._account_jwt_subject, timeout=1)
        self._account = jwts.decode_account(reply.data)
        return self._account

    async def connect(self) -> NATS:
        """Connect to NATS context."""
        if self.nc is not None:
            if self.nc.is_connected:
                return self.nc
            if self.nc.is_connecting:
                raise ValueError("NATS client is already connecting")
            if self.nc.is_reconnecting:
                raise ValueError("NATS client is already reconnecting")
            if self.nc.is_draining or self.nc.is_draining_pubs:
                raise ValueError("NATS client is draining connection")
            if self.nc.is_closed:
                raise ValueError(
                    "NATS client is closed. Use .reconnect() method to connect a closed client."
                )
        # Decode user claims from token
        self._user = jwts.decode_user(self.creds.get_token())
        # Create and connect a new NATS client within context
        nc = NATS()
        # Connect to NATS
        await nc.connect(**self.get_nats_options())
        # Fetch account JWT
        try:
            reply = await nc.request(self._account_jwt_subject, timeout=1)
            self._account = jwts.decode_account(reply.data)
        except nats.errors.TimeoutError as exc:
            # Account does not exist
            await nc.close()
            raise ValueError("Account JWT not found") from exc
        except nats.errors.NoRespondersError:
            # Account is not authorized
            await nc.close()
            raise ValueError(
                "Account configuration does not export the Account JWT service"
            )
        # Set NATS client on context
        self.nc = nc
        event = LifecycleEvent(
            "connected",
            server_info=nc._server_info,
            discovered_servers=nc.discovered_servers,
            client_options=nc.options,
        )
        self.__deliver_event(event)
        # Immediately exit context manager so that credentials are removed
        return nc

    async def reconnect(self) -> NATS:
        """Connect a new client to NATS context before draining the one currently used."""
        if self.nc is None:
            return await self.connect()
        # Fetch old client
        old_connection = self.nc
        # Connect new client
        new_connection = await self.connect()
        # Disconnect old client now that new client is connected
        try:
            await old_connection.drain()
        except (
            nats.errors.ConnectionClosedError,
            nats.errors.StaleConnectionError,
        ):
            pass
        # Return new connection
        return new_connection

    async def drain(self) -> None:
        """Disconnect client from NATS context after processing pending messages in subscriptions."""
        if self.nc is None:
            return
        try:
            await self.nc.drain()
        except (
            nats.errors.ConnectionClosedError,
            nats.errors.ConnectionDrainingError,
            nats.errors.StaleConnectionError,
        ):
            pass

    async def disconnect(self) -> None:
        """Disconnect client from NATS context without caring for pending messages in subscriptions.

        WARNING: If there are still pending messages within subscriptions, those message will be left unprocessed and taks will be cancelled.
        """
        if self.nc is None:
            return
        try:
            await self.nc.close()
        except (
            nats.errors.ConnectionClosedError,
            nats.errors.ConnectionDrainingError,
            nats.errors.StaleConnectionError,
        ):
            pass
        # Reset NATS client
        self.nc = None

    def format_subject(self, subject: str) -> str:
        """Format a subject using context variables"""
        try:
            return self._template_environment.from_string(subject).render(
                **self.get_context_variables()
            )
        except jinja2.UndefinedError as exc:
            raise ValueError(exc.message) from exc

    async def publish(
        self,
        subject: str,
        payload: t.Optional[bytes] = None,
        reply: t.Optional[str] = None,
        headers: t.Optional[t.Mapping[str, str]] = None,
    ) -> None:
        if self.nc is None:
            raise ValueError("NATS context is not connected yet")
        subject = self.format_subject(subject)
        if reply:
            reply = self.format_subject(subject)
        await self.nc.publish(
            subject=subject,
            payload=payload or b"",
            reply=reply or "",
            headers=dict(headers or {}),
        )

    async def request(
        self,
        subject: str,
        payload: t.Optional[bytes] = None,
        headers: t.Optional[t.Mapping[str, str]] = None,
        timeout: t.Optional[float] = None,
    ) -> Msg:
        """Send a request and receive a reply"""
        if self.nc is None:
            raise ValueError("NATS context is not connected yet")
        subject = self.format_subject(subject)
        return await self.nc.request(
            subject=subject,
            payload=payload or b"",
            timeout=timeout or 1,
            headers=dict(headers or {}),
        )

    async def subscribe(
        self,
        subject: str,
        queue: t.Optional[str] = None,
        max_msgs: t.Optional[int] = None,
        pending_msgs_limit: int = DEFAULT_SUB_PENDING_MSGS_LIMIT,
        pending_bytes_limit: int = DEFAULT_SUB_PENDING_BYTES_LIMIT,
    ) -> Subscription:
        if self.nc is None:
            raise ValueError("NATS context is not connected yet")
        subject = self.format_subject(subject)
        if queue:
            queue = self.format_subject(queue)
        else:
            queue = ""
        return await self.nc.subscribe(
            subject,
            queue=queue,
            max_msgs=max_msgs or 0,
            pending_msgs_limit=pending_msgs_limit,
            pending_bytes_limit=pending_bytes_limit,
        )

    async def subscribe_callback(
        self,
        subject: str,
        cb: t.Callable[[Msg], t.Coroutine[None, None, t.Any]],
        queue: t.Optional[str] = None,
        max_msgs: t.Optional[int] = None,
        pending_msgs_limit: int = DEFAULT_SUB_PENDING_MSGS_LIMIT,
        pending_bytes_limit: int = DEFAULT_SUB_PENDING_BYTES_LIMIT,
    ) -> Subscription:
        if self.nc is None:
            raise ValueError("NATS context is not connected yet")
        subject = self.format_subject(subject)
        if queue:
            queue = self.format_subject(queue)
        else:
            queue = ""
        return await self.nc.subscribe(
            subject,
            queue=queue,
            cb=cb,
            max_msgs=max_msgs or 0,
            pending_msgs_limit=pending_msgs_limit,
            pending_bytes_limit=pending_bytes_limit,
        )

    async def subscribe_lifecycle_events(
        self, max_events: t.Optional[int] = None, max_history: int = 100
    ) -> LifecycleSubscription:
        """Watch lifecycle events of NATS client.

        Event can be:
            - disconnected
            - reconnected
            - connected
            - closed
            - discovered_server
        """
        sub = LifecycleSubscription(
            self, max_events=max_events, max_history=max_history
        )
        await sub.start()
        return sub
