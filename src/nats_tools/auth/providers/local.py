from pathlib import Path
import typing as t

from .protocol import CredsProvider

from nats_tools import jwts


class LocalCredsProvider(CredsProvider):
    """Obtain an already signed JWT from a file on disk or an environment variable.

    Issuer can be configured to verify the user JWT public key, name, account public key and scope,
    but it cannot update the JWT.
    In case loaded JWT does not match arguments provided to `get_token()` method, an error is raised.
    """

    def __init__(
        self,
        creds: t.Union[str, Path],
    ) -> None:
        """Create a new memory issuer. A memory issuer loads a token into memory and can return token value later."""
        if not Path(creds).expanduser().exists():
            raise FileNotFoundError(creds)
        self._creds = jwts.creds.CredentialsFile(creds)

    def get_seed(self) -> str:
        """Optional method"""
        return self._creds.read_seed()

    def get_token(
        self,
        client_id: t.Optional[str] = None,
        scope: t.Optional[str] = None,
        verify: bool = True,
    ) -> str:
        """Optional method"""
        token = self._creds.read_token()
        if verify:
            jwts.decode_user(
                token, account_public_key=client_id, scope=scope, verify=verify
            )
        return token
