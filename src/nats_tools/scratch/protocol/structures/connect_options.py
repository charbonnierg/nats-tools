from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class ConnectOptions:
    """Connecion options provided to NATS server with CONNECT command.

    Reference: https://github.com/nats-io/nats-server/blob/main/server/client.go#L545
    """

    name: str
    lang: str
    version: str
    protocol: int
    echo: bool = True
    verbose: bool = False
    pedantic: bool = False
    tls_required: bool = False
    nkey: Optional[str] = None
    jwt: Optional[str] = None
    sig: Optional[str] = None
    auth_token: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None
    account: Optional[str] = None
    new_account: Optional[bool] = None
    headers: Optional[bool] = None
    no_responders: Optional[bool] = None

    def to_values(self) -> Dict[str, Any]:
        """Return options as dictionary. None values are excluded."""
        values = asdict(self)
        password = values.pop("password", None)
        if password:
            values["pass"] = password
        return {key: value for key, value in values.items() if value is not None}
