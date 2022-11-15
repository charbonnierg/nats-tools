import json
import typing as t

from nats import NATS

from .protocol import AsyncNATSMonitor, SortOption, StateOption, SubsOption


class SysAccountNATSMonitor(AsyncNATSMonitor):
    def __init__(self, nc: NATS) -> None:
        self.nc = nc

    async def _request(
        self, endpoint: str, timeout: float = 2, **params: t.Any
    ) -> t.Dict[str, t.Any]:
        payload = json.dumps(params).encode("utf-8")
        # FIXME: Each server replies with a single message
        # Request/reply should not be used.
        # A subscription should be used instead.
        response = await self.nc.request(endpoint, payload, timeout=timeout)
        return t.cast(t.Dict[str, t.Any], json.loads(response.data))

    async def varz(
        self,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /varz endpoint returns general information about the server state and configuration.

        Example: https://demo.nats.io:8222/varz
        """
        params: t.Dict[str, t.Any] = {}
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request("$SYS.REQ.SERVER.PING.VARZ", **params)

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
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
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
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request("$SYS.REQ.SERVER.PING.JSZ", **params)

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
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
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
            "auth": auth,
            "subs": subs.value,
            "offset": offset,
            "limit": limit,
        }
        if cid:
            params["cid"] = int(cid)
        if mqtt_client:
            params["mqtt_client"] = mqtt_client
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request("$SYS.REQ.SERVER.PING.CONNZ", **params)

    async def accountz(
        self,
        acc: t.Optional[str] = None,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /accountz endpoint reports information on a server's active accounts.

        The default behavior is to return a list of all accounts known to the server.

        Arguments:
            acc: include metrics for the specified account only. Default is empty. When not set
                a list of all accounts is included.
        """
        params: t.Dict[str, t.Any] = {}
        if acc:
            params["acc"] = acc
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request("$SYS.REQ.SERVER.PING.ACCOUNTZ", **params)

    async def accstatz(self, unused: bool = False) -> t.Dict[str, t.Any]:
        """The /accstatz endpoint reports per-account statistics such as the number of connections, messages/bytes in/out, etc.

        Arguments:
            unused: include accounts that do not have any current connections when True. Default is False.

        Returns:
            results as a dictionary.
        """

        return await self._request("$SYS.REQ.SERVER.PING.STATSZ", unused=unused)

    async def subsz(
        self,
        subs: bool = False,
        offset: int = 0,
        limit: int = 1024,
        test: t.Optional[str] = None,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
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
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request("$SYS.REQ.SERVER.PING.SUBSZ", **params)

    async def routez(
        self,
        subs: t.Union[bool, str, SubsOption] = SubsOption.FALSE,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /routez endpoint reports information on active routes for a cluster.

        Routes are expected to be low, so there is no paging mechanism with this endpoint.

        Arguments:
            subs: include subscriptions. Default is False. When set to "detail", a list with more details subscription information is returned.

        Returns:
            results as a dictionary.
        """
        params: t.Dict[str, t.Any] = {}
        if not isinstance(subs, SubsOption):
            subs = SubsOption(subs)
        if subs:
            params["subs"] = subs.value
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request("$SYS.REQ.SERVER.PING.ROUTEZ", **params)

    async def leafz(
        self,
        subs: bool = False,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /leafz endpoint reports detailed information about the leaf node connections.

        Arguments:
            subs: include internal subscriptions. Default is False.

        Returns:
            results as dict
        """
        params: t.Dict[str, t.Any] = {}
        if subs:
            params["subs"] = subs
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request("$SYS.REQ.SERVER.PING.LEAFZ", **params)

    async def gatewayz(
        self,
        accs: bool = False,
        gw_name: t.Optional[str] = None,
        acc_name: t.Optional[str] = None,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
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
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request("$SYS.REQ.SERVER.PING.GATEWAYZ", **params)

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
        raise NotImplementedError


class AccountNATSMonitor(AsyncNATSMonitor):
    def __init__(self, nc: NATS, account_id: str) -> None:
        self.nc = nc
        self.account_id = account_id

    async def _request(
        self, endpoint: str, timeout: float = 2, **params: t.Any
    ) -> t.Dict[str, t.Any]:
        payload = json.dumps(params).encode("utf-8")
        # FIXME: Each server replies with a single message
        # Request/reply should not be used.
        # A subscription should be used instead.
        response = await self.nc.request(endpoint, payload, timeout=timeout)
        return t.cast(t.Dict[str, t.Any], json.loads(response.data))

    async def varz(
        self,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /varz endpoint returns general information about the server state and configuration.

        Example: https://demo.nats.io:8222/varz
        """
        raise NotImplementedError

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
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
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
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request(f"$SYS.REQ.ACCOUNT.{self.account_id}.JSZ", **params)

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
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
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
            "auth": auth,
            "subs": subs.value,
            "offset": offset,
            "limit": limit,
        }
        if cid:
            params["cid"] = int(cid)
        if mqtt_client:
            params["mqtt_client"] = mqtt_client
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request(
            f"$SYS.REQ.ACCOUNT.{self.account_id}.CONNZ", **params
        )

    async def accountz(
        self,
        acc: t.Optional[str] = None,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /accountz endpoint reports information on a server's active accounts.

        The default behavior is to return a list of all accounts known to the server.

        Arguments:
            acc: include metrics for the specified account only. Default is empty. When not set
                a list of all accounts is included.
        """
        params: t.Dict[str, t.Any] = {}
        if acc:
            params["acc"] = acc
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request(f"$SYS.REQ.ACCOUNT.{self.account_id}.INFO", **params)

    async def accstatz(self, unused: bool = False) -> t.Dict[str, t.Any]:
        """The /accstatz endpoint reports per-account statistics such as the number of connections, messages/bytes in/out, etc.

        Arguments:
            unused: include accounts that do not have any current connections when True. Default is False.

        Returns:
            results as a dictionary.
        """

        raise NotImplementedError

    async def subsz(
        self,
        subs: bool = False,
        offset: int = 0,
        limit: int = 1024,
        test: t.Optional[str] = None,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
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
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request(
            f"$SYS.REQ.ACCOUNT.{self.account_id}.SUBSZ", **params
        )

    async def routez(
        self,
        subs: t.Union[bool, str, SubsOption] = SubsOption.FALSE,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /routez endpoint reports information on active routes for a cluster.

        Routes are expected to be low, so there is no paging mechanism with this endpoint.

        Arguments:
            subs: include subscriptions. Default is False. When set to "detail", a list with more details subscription information is returned.

        Returns:
            results as a dictionary.
        """
        raise NotImplementedError

    async def leafz(
        self,
        subs: bool = False,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
    ) -> t.Dict[str, t.Any]:
        """The /leafz endpoint reports detailed information about the leaf node connections.

        Arguments:
            subs: include internal subscriptions. Default is False.

        Returns:
            results as dict
        """
        params: t.Dict[str, t.Any] = {}
        if subs:
            params["subs"] = subs
        if server_name:
            params["server_name"] = server_name
        if cluster:
            params["cluster"] = cluster
        if tags:
            params["tags"] = tags
        if host:
            params["host"] = host
        return await self._request(
            f"$SYS.REQ.ACCOUNT.{self.account_id}.LEAFZ", **params
        )

    async def gatewayz(
        self,
        accs: bool = False,
        gw_name: t.Optional[str] = None,
        acc_name: t.Optional[str] = None,
        server_name: t.Optional[str] = None,
        cluster: t.Optional[str] = None,
        host: t.Optional[str] = None,
        tags: t.Optional[str] = None,
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
        raise NotImplementedError

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
        raise NotImplementedError
