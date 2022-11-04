import types
import typing as t
from enum import Enum

import httpx


class SortOption(str, Enum):
    # Connection ID
    CID = "cid"
    # Connection start time, same as CID
    START = "start"
    # Number of subscriptions
    SUBS = "subs"
    # Amount of data in bytes waiting to be sent to client
    PENDING = "pending"
    # Number of messages sent
    MSGS_TO = "msgs_to"
    # Number of messages received
    MSGS_FROM = "msgs_from"
    # Number of bytes sent
    BYTES_TO = "bytes_to"
    # Number of bytes received
    BYTES_FROM = "bytes_from"
    # Last activity
    LAST = "last"
    # Amount of inactivity
    IDLE = "idle"
    # Lifetime of the connection
    UPTIME = "uptime"
    # Stop time for a closed connection
    STOP = "stop"
    # Reason for a closed connection
    REASON = "reason"


class SubsOption(Enum):
    FALSE = False
    TRUE = True
    DETAIL = "detail"


class StateOption(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    ANY = "any"


class NATSMonitor:
    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint
        self._client: t.Optional[httpx.Client] = None

    def _request(self, endpoint: str, **params: t.Any) -> t.Dict[str, t.Any]:
        if self._client is None:
            self._client = httpx.Client(base_url=self.endpoint)
        response = self._client.get(endpoint, params=params)
        response.raise_for_status()
        return t.cast(t.Dict[str, t.Any], response.json())

    def varz(self) -> t.Dict[str, t.Any]:
        """The /varz endpoint returns general information about the server state and configuration.

        Example: https://demo.nats.io:8222/varz
        """
        return self._request("/varz")

    def jsz(
        self,
        acc: t.Optional[str] = None,
        accounts: t.Optional[bool] = None,
        streams: t.Optional[bool] = None,
        consumers: t.Optional[bool] = None,
        config: t.Optional[bool] = None,
        leader_only: bool = False,
        offset: int = 0,
        limit: int = 1024,
    ) -> t.Dict[str, t.Any]:
        """The /jsz endpoint reports more detailed information on JetStream.

        For accounts, it uses a paging mechanism that defaults to 1024 connections.

        NOTE: If you're in a clustered environment, it is recommended to retrieve the information
              from the stream's leader in order to get the most accurate and up-to-date data.

        Arguments:
            acc: include metrics for the specified account only. Omitted by default.
            accounts: include account specific jetstream information. Default is False.
            streams: include streams. When set, implies `accounts=True`. Default is False.
            consumers: include consumers. When set, implies `stream=True`. Default is False.
            config: when stream or consumer are requested, include their respective configuration. Default is False.
            leader_only: only the leader responds. Default is False.
            offset: pagination offset. Default is 0.
            limit: number of results to return. Default is 1024.

        Returns:
            results as a dictionary.
        """
        params: t.Dict[str, t.Any] = {
            "leader-only": leader_only,
            "limit": limit,
            "offset": offset,
        }
        if accounts:
            params["accounts"] = accounts
        if streams:
            params["streams"] = streams
        if consumers:
            params["consumers"] = consumers
        if config:
            params["config"] = config
        if acc:
            params["acc"] = acc
        return self._request("/jsz", **params)

    def connz(
        self,
        sort: t.Union[str, SortOption] = SortOption.CID,
        auth: bool = False,
        subs: t.Union[bool, str, SubsOption] = SubsOption.FALSE,
        offset: int = 0,
        limit: int = 1024,
        cid: t.Optional[int] = None,
        state: t.Union[str, StateOption] = StateOption.OPEN,
        mqtt_client: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /connz endpoint reports more detailed information on current and recently closed connections.

        It uses a paging mechanism which defaults to 1024 connections.

        Arguments:
            sort: sorts the results. Default is connection ID.
            auth: include username. Default is False.
            subs: include subscriptions. Default is False. When set to "detail", a list with more detailed subscription information is returned.
            offset: pagination offset. Default is 0.
            limit: number of results to return. Default is 1024.
            cid: return result for a single connection by its id. Omitted by default.
            state: return results for connections of particular state. Default is "open".
            mqtt_client: return results for connections with this MQTT client id. Omitted by default.

        Returns:
            results as a dictionary.
        """
        if not isinstance(sort, SortOption):
            sort = SortOption(sort)
        if not isinstance(subs, SubsOption):
            subs = SubsOption(subs)
        if not isinstance(state, StateOption):
            state = StateOption(state)
        params = {
            "sort": sort.value,
            "auth": 1 if auth else 0,
            "subs": subs.value,
            "offset": offset,
            "limit": limit,
        }
        if cid:
            params["cid"] = int(cid)
        if mqtt_client:
            params["mqtt_client"] = mqtt_client
        return self._request("/connz", **params)

    def accountz(self, acc: t.Optional[str] = None) -> t.Dict[str, t.Any]:
        """The /accountz endpoint reports information on a server's active accounts.

        The default behavior is to return a list of all accounts known to the server.

        Arguments:
            acc: include metrics for the specified account only. Default is empty. When not set
                a list of all accounts is included.
        """
        params: t.Dict[str, t.Any] = {}
        if acc:
            params["acc"] = acc
        return self._request("/accountz", **params)

    def accstatz(self, unused: bool = False) -> t.Dict[str, t.Any]:
        """The /accstatz endpoint reports per-account statistics such as the number of connections, messages/bytes in/out, etc.

        Arguments:
            unused: include accounts that do not have any current connections when True. Default is False.

        Returns:
            results as a dictionary.
        """
        return self._request("/accstatz", unused=unused)

    def subsz(
        self,
        subs: bool = False,
        offset: int = 0,
        limit: int = 1024,
        test: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /subsz endpoint reports detailed information about the current subscriptions and the routing data structure.
        It is not normally used.

        Arguments:
            subs: include subscriptions. Default is false.
            offset: pagination offset. Default is 0.
            limit: number of results to return. Default is 1024.
            test: test whether a subscription exists.

        Returns:
            results as a dictionary.
        """
        params: t.Dict[str, t.Any] = {
            "subs": subs,
            "offset": offset,
            "limit": limit,
        }
        if test:
            params["test"] = test
        return self._request("/subsz", **params)

    def routez(
        self, subs: t.Union[bool, str, SubsOption] = SubsOption.FALSE
    ) -> t.Dict[str, t.Any]:
        """The /routez endpoint reports information on active routes for a cluster.

        Routes are expected to be low, so there is no paging mechanism with this endpoint.

        Arguments:
            subs: include subscriptions. Default is False. When set to "detail", a list with more details subscription information is returned.

        Returns:
            results as a dictionary.
        """
        if not isinstance(subs, SubsOption):
            subs = SubsOption(subs)
        return self._request("/routez", subs=subs.value)

    def leafz(self, subs: bool = False) -> t.Dict[str, t.Any]:
        """The /leafz endpoint reports detailed information about the leaf node connections.

        Arguments:
            subs: include internal subscriptions. Default is False.

        Returns:
            results as dict
        """
        return self._request("/leafz", subs=subs)

    def gatewayz(
        self,
        accs: bool = False,
        gw_name: t.Optional[str] = None,
        acc_name: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /gatewayz endpoint reports information about gateways used to create a NATS supercluster.

        Like routes, the number of gateways are expected to be low, so there is no paging mechanism with this endpoint.

        Arguments:
            accs: include account information. Default is false.
            gw_name: return only remote gateways with this name. Omitted by default.
            acc_name: limit the list of accounts to this account name. Omitted by default.

        Returns:
            results as dict
        """
        params: t.Dict[str, t.Any] = {"accs": bool(accs)}
        if gw_name:
            params["gw_name"] = gw_name
        if acc_name:
            params["acc_name"] = acc_name
        return self._request("/gatewayz", **params)

    def healthz(
        self,
        js_enabled: bool = False,
        js_server_only: bool = False,
    ) -> t.Dict[str, t.Any]:
        """The /healthz endpoint returns OK if the server is able to accept connections.

        Arguments:
            js_enabled: returns an error if jetstream is disabled. Omitted by default.
            js_server_only: skip healthcheck of accounts, streams and consumers. Omitted by default.

        Returns:
            results as dictionary.
        """
        params: t.Dict[str, t.Any] = {}
        if js_enabled:
            params["js_enabled"] = 1
        if js_server_only:
            params["js_server_only"] = 1
        return self._request("/healthz", **params)


class AsyncNATSMonitor:
    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint
        self._client: t.Optional[httpx.AsyncClient] = None

    async def _request(self, endpoint: str, **params: t.Any) -> t.Dict[str, t.Any]:
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.endpoint)
        response = await self._client.get(endpoint, params=params)
        response.raise_for_status()
        return t.cast(t.Dict[str, t.Any], response.json())

    async def varz(self) -> t.Dict[str, t.Any]:
        """The /varz endpoint returns general information about the server state and configuration.

        Example: https://demo.nats.io:8222/varz
        """
        return await self._request("/varz")

    async def jsz(
        self,
        acc: t.Optional[str] = None,
        accounts: t.Optional[bool] = None,
        streams: t.Optional[bool] = None,
        consumers: t.Optional[bool] = None,
        config: t.Optional[bool] = None,
        leader_only: bool = False,
        offset: int = 0,
        limit: int = 1024,
    ) -> t.Dict[str, t.Any]:
        """The /jsz endpoint reports more detailed information on JetStream.

        For accounts, it uses a paging mechanism that defaults to 1024 connections.

        NOTE: If you're in a clustered environment, it is recommended to retrieve the information
              from the stream's leader in order to get the most accurate and up-to-date data.

        Arguments:
            acc: include metrics for the specified account only. Omitted by default.
            accounts: include account specific jetstream information. Default is False.
            streams: include streams. When set, implies `accounts=True`. Default is False.
            consumers: include consumers. When set, implies `stream=True`. Default is False.
            config: when stream or consumer are requested, include their respective configuration. Default is False.
            leader_only: only the leader responds. Default is False.
            offset: pagination offset. Default is 0.
            limit: number of results to return. Default is 1024.

        Returns:
            results as a dictionary.
        """
        params: t.Dict[str, t.Any] = {
            "leader-only": leader_only,
            "limit": limit,
            "offset": offset,
        }
        if accounts:
            params["accounts"] = accounts
        if streams:
            params["streams"] = streams
        if consumers:
            params["consumers"] = consumers
        if config:
            params["config"] = config
        if acc:
            params["acc"] = acc
        return await self._request("/jsz", **params)

    async def connz(
        self,
        sort: t.Union[str, SortOption] = SortOption.CID,
        auth: bool = False,
        subs: t.Union[bool, str, SubsOption] = SubsOption.FALSE,
        offset: int = 0,
        limit: int = 1024,
        cid: t.Optional[int] = None,
        state: t.Union[str, StateOption] = StateOption.OPEN,
        mqtt_client: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /connz endpoint reports more detailed information on current and recently closed connections.

        It uses a paging mechanism which defaults to 1024 connections.

        Arguments:
            sort: sorts the results. Default is connection ID.
            auth: include username. Default is False.
            subs: include subscriptions. Default is False. When set to "detail", a list with more detailed subscription information is returned.
            offset: pagination offset. Default is 0.
            limit: number of results to return. Default is 1024.
            cid: return result for a single connection by its id. Omitted by default.
            state: return results for connections of particular state. Default is "open".
            mqtt_client: return results for connections with this MQTT client id. Omitted by default.

        Returns:
            results as a dictionary.
        """
        if not isinstance(sort, SortOption):
            sort = SortOption(sort)
        if not isinstance(subs, SubsOption):
            subs = SubsOption(subs)
        if not isinstance(state, StateOption):
            state = StateOption(state)
        params = {
            "sort": sort.value,
            "auth": 1 if auth else 0,
            "subs": subs.value,
            "offset": offset,
            "limit": limit,
        }
        if cid:
            params["cid"] = int(cid)
        if mqtt_client:
            params["mqtt_client"] = mqtt_client
        return await self._request("/connz", **params)

    async def accountz(self, acc: t.Optional[str] = None) -> t.Dict[str, t.Any]:
        """The /accountz endpoint reports information on a server's active accounts.

        The default behavior is to return a list of all accounts known to the server.

        Arguments:
            acc: include metrics for the specified account only. Default is empty. When not set
                a list of all accounts is included.
        """
        params: t.Dict[str, t.Any] = {}
        if acc:
            params["acc"] = acc
        return await self._request("/accountz", **params)

    async def accstatz(self, unused: bool = False) -> t.Dict[str, t.Any]:
        """The /accstatz endpoint reports per-account statistics such as the number of connections, messages/bytes in/out, etc.

        Arguments:
            unused: include accounts that do not have any current connections when True. Default is False.

        Returns:
            results as a dictionary.
        """
        return await self._request("/accstatz", unused=unused)

    async def subsz(
        self,
        subs: bool = False,
        offset: int = 0,
        limit: int = 1024,
        test: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /subsz endpoint reports detailed information about the current subscriptions and the routing data structure.
        It is not normally used.

        Arguments:
            subs: include subscriptions. Default is false.
            offset: pagination offset. Default is 0.
            limit: number of results to return. Default is 1024.
            test: test whether a subscription exists.

        Returns:
            results as a dictionary.
        """
        params: t.Dict[str, t.Any] = {
            "subs": subs,
            "offset": offset,
            "limit": limit,
        }
        if test:
            params["test"] = test
        return await self._request("/subsz", **params)

    async def routez(
        self, subs: t.Union[bool, str, SubsOption] = SubsOption.FALSE
    ) -> t.Dict[str, t.Any]:
        """The /routez endpoint reports information on active routes for a cluster.

        Routes are expected to be low, so there is no paging mechanism with this endpoint.

        Arguments:
            subs: include subscriptions. Default is False. When set to "detail", a list with more details subscription information is returned.

        Returns:
            results as a dictionary.
        """
        if not isinstance(subs, SubsOption):
            subs = SubsOption(subs)
        return await self._request("/routez", subs=subs.value)

    async def leafz(self, subs: bool = False) -> t.Dict[str, t.Any]:
        """The /leafz endpoint reports detailed information about the leaf node connections.

        Arguments:
            subs: include internal subscriptions. Default is False.

        Returns:
            results as dict
        """
        return await self._request("/leafz", subs=subs)

    async def gatewayz(
        self,
        accs: bool = False,
        gw_name: t.Optional[str] = None,
        acc_name: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /gatewayz endpoint reports information about gateways used to create a NATS supercluster.

        Like routes, the number of gateways are expected to be low, so there is no paging mechanism with this endpoint.

        Arguments:
            accs: include account information. Default is false.
            gw_name: return only remote gateways with this name. Omitted by default.
            acc_name: limit the list of accounts to this account name. Omitted by default.

        Returns:
            results as dict
        """
        params: t.Dict[str, t.Any] = {"accs": bool(accs)}
        if gw_name:
            params["gw_name"] = gw_name
        if acc_name:
            params["acc_name"] = acc_name
        return await self._request("/gatewayz", **params)

    async def healthz(
        self,
        js_enabled: bool = False,
        js_server_only: bool = False,
    ) -> t.Dict[str, t.Any]:
        """The /healthz endpoint returns OK if the server is able to accept connections.

        Arguments:
            js_enabled: returns an error if jetstream is disabled. Omitted by default.
            js_server_only: skip healthcheck of accounts, streams and consumers. Omitted by default.

        Returns:
            results as dictionary.
        """
        params: t.Dict[str, t.Any] = {}
        if js_enabled:
            params["js_enabled"] = 1
        if js_server_only:
            params["js_server_only"] = 1
        return await self._request("/healthz", **params)

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncNATSMonitor":
        return self

    async def __aexit__(
        self,
        error_type: t.Optional[t.Type[BaseException]] = None,
        error: t.Optional[BaseException] = None,
        traceback: t.Optional[types.TracebackType] = None,
    ) -> None:
        await self.close()
