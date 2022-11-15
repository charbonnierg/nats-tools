import typing as t
from pathlib import Path

import pytest
from _pytest.fixtures import SubRequest

from nats_tools.auth import Operator
from nats_tools.natsd import NATSD

F = t.TypeVar("F", bound=t.Callable[..., t.Any])


@pytest.fixture
def nats_server(request: SubRequest) -> t.Iterator[NATSD]:
    if hasattr(request, "param"):
        params = dict(request.param)
    else:
        params = {"debug": True, "trace": True}
    if params.get("debug", None) is None:
        params["debug"] = True
    if params.get("trace", None) is None:
        params["trace"] = True
    nats = NATSD(**params)
    nats.start(wait=True)
    try:
        yield nats
    finally:
        if nats.proc and nats.proc.poll() is None:
            nats.stop()


@pytest.fixture
def nats_operator(request: SubRequest) -> Operator:
    if hasattr(request, "param"):
        params = dict(request.param)
    else:
        params = {}
    if "name" not in params:
        params["name"] = "TEST"
    _, operator = Operator.create(**params)
    return operator


def parametrize_nats_server(
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
    config_file: t.Union[str, Path, None] = None,
    max_cpus: t.Optional[float] = None,
    start_timeout: float = 1,
) -> t.Callable[[F], F]:
    options = dict(
        address=address,
        port=port,
        client_advertise=client_advertise,
        server_name=server_name,
        server_tags=server_tags,
        user=user,
        password=password,
        users=users,
        token=token,
        http_port=http_port,
        debug=debug,
        trace=trace,
        trace_verbose=trace_verbose,
        logtime=logtime,
        pid_file=pid_file,
        port_file_dir=port_file_dir,
        log_file=log_file,
        log_size_limit=log_size_limit,
        tls_cert=tls_cert,
        tls_key=tls_key,
        tls_ca_cert=tls_ca_cert,
        cluster_name=cluster_name,
        cluster_url=cluster_url,
        cluster_listen=cluster_listen,
        routes=routes,
        no_advertise=no_advertise,
        with_jetstream=with_jetstream,
        jetstream_domain=jetstream_domain,
        store_directory=store_directory,
        max_memory_store=max_memory_store,
        max_file_store=max_file_store,
        max_outstanding_catchup=max_outstanding_catchup,
        allow_leafnodes=allow_leafnodes,
        leafnodes_listen_address=leafnodes_listen_address,
        leafnodes_listen_port=leafnodes_listen_port,
        leafnode_remotes=leafnode_remotes,
        websocket_listen_address=websocket_listen_address,
        websocket_listen_port=websocket_listen_port,
        websocket_advertise_url=websocket_advertise_url,
        websocket_tls=websocket_tls,
        websocket_tls_cert=websocket_tls_cert,
        websocket_tls_key=websocket_tls_key,
        websocket_same_origin=websocket_same_origin,
        websocket_allowed_origins=websocket_allowed_origins,
        websocket_compression=websocket_compression,
        jwt_path=jwt_path,
        operator=operator,
        system_account=system_account,
        system_account_jwt=system_account_jwt,
        allow_delete_jwt=allow_delete_jwt,
        compare_jwt_interval=compare_jwt_interval,
        resolver_preload=resolver_preload,
        config_file=config_file,
        start_timeout=start_timeout,
        max_cpus=max_cpus,
    )
    return pytest.mark.parametrize("nats_server", [options], indirect=True)
