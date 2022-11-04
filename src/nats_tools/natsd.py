import os
import shutil
import signal
import subprocess
import tempfile
import time
import types
import typing as t
import weakref
from enum import Enum
from pathlib import Path

import httpx

from nats_tools.monitor import NATSMonitor
from nats_tools.templates import ConfigGenerator

DEFAULT_BIN_DIR = Path.home().joinpath("nats-server").absolute()


class Signal(Enum):
    # Kill the process immediatley
    KILL = signal.SIGKILL
    # Kills the process immediately and perform a core dump
    QUIT = signal.SIGQUIT
    # Stops the server grafefully
    STOP = signal.SIGTERM
    # Reopens the log file for log rotation
    REOPEN = signal.SIGUSR1
    # Reload server configuration
    RELOAD = signal.SIGHUP
    # Stops the server after evicting all clients
    LDM = signal.SIGUSR2


class NATSD:
    def __init__(
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
        config_file: t.Union[str, Path, None] = None,
        max_cpus: t.Optional[float] = None,
        start_timeout: float = 1,
    ) -> None:
        """Create a new instance of nats-server daemon.

        Arguments:
            address: host address nats-server should listen to. Default is 127.0.0.1 (localhost).
            port: tcp port nats-server should listen to. Clients can connect to this port. Default is 4222.
            server_name: the server name. Default to auto-generated name.
            user: username required for connections. Omitted by default.
            password: password required for connections. Omitted by default.
            token: authorization token required for connections. Omitted by default.
            http_port: port for http monitoring. Default is 8222.
            debug: enable debugging output. Default is False.
            trace: enable raw traces. Default is False.
            pid_file: file to write process ID to. Omitted by default.
            log_file: file to redirect log output to. Omitted by default.
            tls_cert: server certificate file (TLS is enabled when both cert and key are provided)
            tls_key: server key file (TLS is enabled when both cert and key are provided)
            tls_ca_cert: client certificate for CA verification (mutual TLS is enabled when ca cert is provided)
            cluster_name: the cluster name. Default to auto-generated name when clustering is enabled.
            cluster_url: cluster URL for sollicited routes.
            cluster_listen: cluster URL from which members can solicite routes. Enable cluster mode when set.
            routes: routes to solicit and connect.
            no_advertise: do not advertise known cluster information to clients.
            with_jetstream: enable jetstream engine when True. Disabled by default.
            store_directory: path to jetstream store directory. Default to a temporary directory.
            config_file: path to a configuration file. None by default.
            max_cpus: maximum number of CPU configured using GOMAXPROCS environment variable. By default all CPUs can be used.
            start_timeout: amount of time to wait before raising an error when starting the daemon with wait=True.
        """
        if config_file is None:
            config_file = Path(tempfile.mkdtemp()).joinpath("nats.conf")
            generator = ConfigGenerator()
            config_str = generator.render(
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
            )
            config_file.write_text(config_str)
            weakref.finalize(self, shutil.rmtree, config_file.parent, True)
        self.server_name = server_name
        self.address = address
        self.port = port
        self.user = user
        self.password = password
        self.timeout = start_timeout
        self.http_port = http_port
        self.token = token
        self.bin_name = "nats-server"
        self.bin_path: t.Optional[str] = None
        self.config_file = Path(config_file) if config_file else None
        self.debug = debug or os.environ.get("DEBUG_NATS_TEST", "") in (
            "true",
            "1",
            "y",
            "yes",
            "on",
        )
        self.trace = trace or os.environ.get("DEBUG_NATS_TEST", "") in (
            "true",
            "1",
            "y",
            "yes",
            "on",
        )
        self.pid_file = Path(pid_file).absolute().as_posix() if pid_file else None
        self.log_file = Path(log_file).absolute().as_posix() if log_file else None
        self.max_cpus = max_cpus

        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.tls_ca_cert = tls_ca_cert
        if self.tls_ca_cert and self.tls_cert and self.tls_key:
            self.tls_verify = True
            self.tls = False
        elif self.tls_cert and self.tls_key:
            self.tls_verify = False
            self.tls = True
        elif self.tls_ca_cert:
            raise ValueError(
                "Both certificate and key files must be provided with a CA certificate"
            )
        elif self.tls_cert or self.tls_key:
            raise ValueError("Both certificate and key files must be provided")
        else:
            self.tls = False
            self.tls_verify = False

        self.cluster_name = cluster_name
        self.cluster_url = cluster_url
        self.cluster_listen = cluster_listen
        self.routes = routes
        self.no_advertise = no_advertise

        self.jetstream_enabled = with_jetstream
        if store_directory:
            self.store_dir = Path(store_directory)
            self._store_dir_is_temporary = False
        else:
            self.store_dir = Path(tempfile.mkdtemp()).resolve(True)
            self._store_dir_is_temporary = True
            weakref.finalize(self, shutil.rmtree, self.store_dir.as_posix(), True)

        self.proc: t.Optional["subprocess.Popen[bytes]"] = None
        self.monitor = NATSMonitor(f"http://{self.address}:{self.http_port}")

    def _cleanup_on_exit(self) -> None:
        if self.proc and self.proc.poll() is None:
            print(
                "[\033[0;31mWARNING\033[0;0m] Stopping server listening on %d."
                % self.port
            )
            self.kill()

    def start(self, wait: bool = False) -> "NATSD":
        # Check if there is an nats-server binary in the current working directory
        if Path(self.bin_name).is_file():
            self.bin_path = Path(self.bin_name).resolve(True).as_posix()
        # Path in `../scripts/install_nats.sh`
        elif DEFAULT_BIN_DIR.joinpath(self.bin_name).is_file():
            self.bin_path = DEFAULT_BIN_DIR.joinpath(self.bin_name).as_posix()
        # This directory contains binary
        else:
            self.bin_path = shutil.which(self.bin_name)
            if self.bin_path is None:
                raise FileNotFoundError("nats-server executable not found")

        cmd = [
            self.bin_path,
            "-p",
            "%d" % self.port,
            "-m",
            "%d" % self.http_port,
            "-a",
            self.address,
        ]

        if self.config_file is not None:
            if not self.config_file.exists():
                raise FileNotFoundError(self.config_file)
            else:
                config_file = self.config_file.absolute().as_posix()
            cmd.append("--config")
            cmd.append(config_file)

        env = os.environ.copy()

        if self.max_cpus:
            env["GOMAXPROCS"] = format(self.max_cpus, ".2f")

        if self.debug:
            self.proc = subprocess.Popen(cmd, env=env)
        else:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env
            )

        if self.debug:
            print(
                "[\033[0;33mDEBUG\033[0;0m] Server listening on port %d started."
                % self.port
            )
        if wait:
            deadline = time.time() + self.timeout or float("inf")
            while True:
                status = self.proc.poll()
                if status is not None:
                    if self.debug:
                        print(
                            "[\033[0;31mWARNING\033[0;0m] Server listening on port {port} already finished running with exit {ret}".format(
                                port=self.port, ret=self.proc.returncode
                            )
                        )
                    raise subprocess.CalledProcessError(
                        returncode=self.proc.returncode, cmd=self.proc.args
                    )
                if time.time() > deadline:
                    self.stop()
                    raise TimeoutError(
                        f"nats-server failed to start before timeout ({self.timeout:.3f}s)"
                    )
                try:
                    self.monitor.varz()
                    break
                except httpx.HTTPError as exc:
                    print(
                        f"[\033[0;31mDEBUG\033[0;0m] Waiting for server to be up. Last error: {type(exc).__name__} - {repr(exc)}."
                    )
                    time.sleep(0.1)
                    continue

        weakref.finalize(self, self._cleanup_on_exit)
        return self

    def stop(self, timeout: t.Optional[float] = 10) -> None:
        if self.debug:
            print(
                "[\033[0;33mDEBUG\033[0;0m] Server listening on %d will stop."
                % self.port
            )

        if self.proc is None:
            if self.debug:
                print(
                    "[\033[0;31mWARNING\033[0;0m] Failed terminating server listening on port %d"
                    % self.port
                )

        elif self.proc.returncode is not None:
            if self.debug:
                print(
                    "[\033[0;31mWARNING\033[0;0m] Server listening on port {port} already finished running with exit {ret}".format(
                        port=self.port, ret=self.proc.returncode
                    )
                )
        else:
            try:
                self.term(timeout=timeout)
            except TimeoutError:
                self.kill()
            if self.debug:
                print(
                    "[\033[0;33mDEBUG\033[0;0m] Server listening on %d was stopped."
                    % self.port
                )
        if self.proc and self.proc.returncode != 1:
            raise subprocess.CalledProcessError(
                self.proc.returncode, cmd=self.proc.args
            )

    def wait(self, timeout: t.Optional[float] = None) -> int:
        """Wait for process to finish and return status code.

        Possible status codes (non-exhaustive):
            -1: process is not started yet.
            0: process has been stopped after entering lame duck mode.
            1: process has been stopped due to TERM signal.
            2: process has been stopped due to QUIT signal.
            -9: process has been stopped due to KILL signal.
        """
        if self.proc is None:
            return 0
        status = self.proc.poll()
        if status is not None:
            return status
        return self.proc.wait(timeout=timeout)

    def send_signal(self, sig: t.Union[int, signal.Signals, Signal]) -> None:
        if self.proc is None:
            raise TypeError("Process is not started yet")
        status = self.proc.poll()
        if status is not None:
            raise subprocess.CalledProcessError(status, cmd=self.proc.args)
        if not isinstance(sig, Signal):
            sig = signal.Signals(sig)
            sig = Signal(sig)
        os.kill(self.proc.pid, sig.value)

    def quit(self, timeout: t.Optional[float] = None) -> None:
        self.send_signal(Signal.QUIT)
        self.wait(timeout=timeout)

    def kill(self, timeout: t.Optional[float] = None) -> None:
        self.send_signal(Signal.KILL)
        self.wait(timeout=timeout)

    def term(self, timeout: t.Optional[float] = 10) -> None:
        self.send_signal(Signal.STOP)
        self.wait(timeout=timeout)

    def reopen_log_file(self) -> None:
        self.send_signal(Signal.REOPEN)

    def enter_lame_duck_mode(self) -> None:
        self.send_signal(Signal.LDM)

    def reload_config(self) -> None:
        self.send_signal(Signal.RELOAD)

    def __enter__(self) -> "NATSD":
        return self.start(wait=True)

    def __exit__(
        self,
        error_type: t.Optional[t.Type[BaseException]] = None,
        error: t.Optional[BaseException] = None,
        traceback: t.Optional[types.TracebackType] = None,
    ) -> None:
        self.stop()
