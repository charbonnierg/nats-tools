import typing as t
from pathlib import Path

from .utils import load_template_from_name, load_template_from_path


class ConfigGenerator:
    def __init__(self, template: t.Union[str, Path] = "default.conf.j2") -> None:
        """Create a new instance of config generator.

        Arguments:
            template: the template used to render configuration.
        """
        if isinstance(template, Path):
            self.template = load_template_from_path(template)
        elif Path(template).is_file():
            self.template = load_template_from_path(template)
        else:
            self.template = load_template_from_name(template)

    def render(
        self,
        address: str = "127.0.0.1",
        port: int = 4222,
        client_advertise: t.Optional[str] = None,
        server_name: t.Optional[str] = None,
        server_tags: t.Optional[t.Dict[str, str]] = None,
        user: t.Optional[str] = None,
        password: t.Optional[str] = None,
        users: t.Optional[t.List[t.Dict[str, t.Any]]] = None,
        token: t.Optional[str] = None,
        http_port: int = 8222,
        debug: t.Optional[bool] = None,
        trace: t.Optional[bool] = None,
        trace_verbose: t.Optional[bool] = None,
        logtime: t.Optional[bool] = None,
        pid_file: t.Union[str, Path, None] = None,
        port_file_dir: t.Union[str, Path, None] = None,
        log_file: t.Union[str, Path, None] = None,
        log_size_limit: t.Optional[int] = None,
        tls_cert: t.Union[str, Path, None] = None,
        tls_key: t.Union[str, Path, None] = None,
        tls_ca_cert: t.Union[str, Path, None] = None,
        cluster_name: t.Optional[str] = None,
        cluster_url: t.Optional[str] = None,
        cluster_listen: t.Optional[str] = None,
        routes: t.Optional[t.List[str]] = None,
        no_advertise: t.Optional[bool] = None,
        with_jetstream: bool = False,
        jetstream_domain: t.Optional[str] = None,
        store_directory: t.Union[str, Path, None] = None,
        max_memory_store: t.Optional[int] = None,
        max_file_store: t.Optional[int] = None,
        max_outstanding_catchup: t.Optional[int] = None,
        allow_leafnodes: bool = False,
        leafnodes_listen_address: t.Optional[str] = None,
        leafnodes_listen_port: t.Optional[int] = None,
        leafnode_remotes: t.Optional[t.Dict[str, t.Any]] = None,
        websocket_listen_address: t.Optional[str] = None,
        websocket_listen_port: t.Optional[int] = None,
        websocket_advertise_url: t.Optional[str] = None,
        websocket_tls: t.Optional[bool] = None,
        websocket_tls_cert: t.Union[str, Path, None] = None,
        websocket_tls_key: t.Union[str, Path, None] = None,
        websocket_same_origin: t.Optional[bool] = None,
        websocket_allowed_origins: t.Optional[t.List[str]] = None,
        websocket_compression: t.Optional[bool] = None,
        jwt_path: t.Union[str, Path, None] = None,
        operator: t.Optional[str] = None,
        system_account: t.Optional[str] = None,
        system_account_jwt: t.Optional[str] = None,
        allow_delete_jwt: t.Optional[bool] = None,
        compare_jwt_interval: t.Optional[str] = None,
        resolver_preload: t.Optional[t.Dict[str, str]] = None,
    ) -> str:
        """Render configuration according to arguments."""
        kwargs: t.Dict[str, t.Any] = {}

        kwargs["server_host"] = address
        kwargs["server_port"] = port
        kwargs["client_advertise"] = client_advertise
        kwargs["server_name"] = server_name
        kwargs["http_port"] = http_port

        if debug is not None:
            kwargs["debug"] = debug
        if trace is not None:
            kwargs["trace"] = trace
        if trace_verbose is not None:
            kwargs["trace_verbose"] = trace_verbose
        if logtime is not None:
            kwargs["logtime"] = logtime
        if pid_file is not None:
            kwargs["pid_file"] = Path(pid_file).as_posix()
        if port_file_dir is not None:
            kwargs["port_file_dir"] = Path(port_file_dir).as_posix()
        if log_file is not None:
            kwargs["log_file"] = Path(log_file).as_posix()
        if log_size_limit is not None:
            kwargs["log_size_limit"] = log_size_limit
        if server_tags:
            kwargs["server_tags"] = [
                f"{key}:{value}" for key, value in server_tags.items()
            ]

        cluster = False
        if cluster_listen or cluster_url:
            if cluster_listen is None:
                cluster_listen = cluster_url
            cluster = True
            kwargs["cluster_listen"] = cluster_listen
            if cluster_url is not None:
                kwargs["cluster_url"] = cluster_url
            if routes is not None:
                kwargs["routes"] = routes
            if no_advertise is not None:
                kwargs["no_advertise"] = no_advertise
            if cluster_name is not None:
                kwargs["cluster_name"] = cluster_name
        kwargs["cluster"] = cluster

        tls = False
        if tls_cert or tls_key:
            if not (tls_cert and tls_key):
                raise ValueError(
                    "tls_cert and tls_key argument must be provided together"
                )
            tls = True
            tls_cert_file = Path(tls_cert).as_posix()
            tls_key_file = Path(tls_key).as_posix()
            kwargs["tls_cert_file"] = tls_cert_file
            kwargs["tls_key_file"] = tls_key_file
            if tls_ca_cert:
                tls_ca_file = Path(tls_ca_cert).as_posix()
                kwargs["tls_ca_file"] = tls_ca_file
        kwargs["tls"] = tls
        kwargs["enable_jetstream"] = with_jetstream
        kwargs["jetstream_domain"] = jetstream_domain
        kwargs["max_file_store"] = max_file_store
        kwargs["max_memory_store"] = max_memory_store
        kwargs["max_outstanding_catchup"] = max_outstanding_catchup
        if store_directory is not None:
            kwargs["jetstream_store_dir"] = store_directory

        if user or password:
            if not (user and password):
                raise ValueError(
                    "Both user and password argument must be provided together"
                )

        if token:
            if user:
                raise ValueError(
                    "token argument cannot be used together with user and password"
                )

        if users:
            if token or user:
                raise ValueError(
                    "users argument cannot be used with token or user and password"
                )

        if operator:
            if users or token or user:
                raise ValueError(
                    "operator argument cannot be used with any of users, token, user and password arguments"
                )
            if system_account is None:
                raise ValueError("system_account argument must be provided")
            if system_account_jwt is None:
                raise ValueError("system_account_jwt argument must be provided")
            if jwt_path is None:
                raise ValueError("jwt_path argument must be provided")

        kwargs["user"] = user
        kwargs["password"] = password
        kwargs["users"] = users
        kwargs["token"] = token

        kwargs["operator"] = operator
        kwargs["system_account"] = system_account
        kwargs["jwt_path"] = jwt_path
        jwts = resolver_preload or {}
        if system_account and system_account_jwt:
            jwts[system_account] = system_account_jwt
        kwargs["jwts"] = jwts
        kwargs["allow_delete_jwt"] = allow_delete_jwt or False
        kwargs["compare_jwt_interval"] = compare_jwt_interval or "2m"

        if leafnodes_listen_address or leafnodes_listen_port:
            leafnodes_listen_address = leafnodes_listen_address or address
            leafnodes_listen_port = leafnodes_listen_port or 7422
            allow_leafnodes = True
            kwargs["leafnodes_listen_address"] = leafnodes_listen_address
            kwargs["leafnodes_listen_port"] = leafnodes_listen_port
        kwargs["allow_leafnodes"] = allow_leafnodes
        kwargs["leafnode_remotes"] = leafnode_remotes

        websocket = False
        if websocket_listen_port or websocket_listen_address:
            if websocket_listen_address is None:
                websocket_listen_address = address
            if websocket_listen_port is None:
                if websocket_tls or websocket_tls_cert:
                    websocket_listen_port = 443
            websocket = True
            kwargs["websocket_listen_port"] = websocket_listen_port
            kwargs["websocket_listen_address"] = websocket_listen_address
            if websocket_advertise_url:
                kwargs["websocket_advertise_url"] = websocket_advertise_url
            if websocket_tls_cert and websocket_tls_key:
                if not websocket_tls_cert and websocket_tls_key:
                    raise ValueError(
                        "websocket_tls_cert and websocket_tls_key must be provided to enable websocket TLS"
                    )
            if (
                (tls and websocket_tls) or (tls and websocket_tls is None)
            ) and websocket_tls_cert is None:
                if tls_cert is None or tls_key is None:
                    raise ValueError(
                        "websocket_tls_cert and websocket_tls_key must be provided to enable websocket TLS"
                    )
                websocket_tls_cert = Path(tls_cert).as_posix()
                websocket_tls_key = Path(tls_key).as_posix()
            websocket_tls = False
            if websocket_tls_cert:
                websocket_tls = True
                kwargs["websocket_tls_cert_file"] = websocket_tls_cert
                kwargs["websocket_tls_key_file"] = websocket_tls_key
            kwargs["websocket_tls"] = websocket_tls
            if websocket_tls:
                if websocket_same_origin is not None:
                    kwargs["websocket_same_origin"] = websocket_same_origin
                kwargs["websocket_allowed_origins"] = websocket_allowed_origins
            if websocket_compression is not None:
                kwargs["websocket_compression"] = websocket_compression
        kwargs["websocket"] = websocket

        return self.template.render(**kwargs)
