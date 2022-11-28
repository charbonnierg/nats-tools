from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from .version import SemverVersion


@dataclass
class ServerInfo:
    """Infos returned by NATS server with INFO command.

    Reference: https://github.com/nats-io/nats-server/blob/main/server/server.go#L60
    """

    server_id: str
    server_name: str
    version: str
    proto: int
    go: str
    host: str
    port: int
    headers: bool
    max_payload: int

    auth_required: Optional[bool] = None
    tls_required: Optional[bool] = None
    tls_verify: Optional[bool] = None
    tls_available: Optional[bool] = None
    git_commit: Optional[str] = None
    jetstream: Optional[bool] = None
    ip: Optional[str] = None
    client_id: Optional[str] = None
    client_ip: Optional[str] = None
    nonce: Optional[str] = None
    cluster: Optional[str] = None
    cluster_dynamic: Optional[bool] = None
    domain: Optional[str] = None
    connect_urls: Optional[List[str]] = None
    ws_connect_urls: Optional[List[str]] = None
    ldm: Optional[bool] = None

    def to_values(self) -> Dict[str, Any]:
        """Return options as dictionary. None values are excluded."""
        values = asdict(self)
        return {key: value for key, value in values.items() if value is not None}

    def get_semver_version(self) -> SemverVersion:
        """Return parsed server version."""
        return SemverVersion(self.version)
