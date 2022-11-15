import typing as t
from .protocol import CredsProvider
from .client import AccountServiceClient

from nats_tools import nkeys


class NKEYCredsProvider(CredsProvider):
    """Obtain a JWT signed remotely by an NATS account using an HTTP client and an NKEY seed.

    NKEY authentication may be required depending if the account is public or private.
    User public  key (user ID) is extracted from provided NKEY seed.
    """

    def __init__(self, seed: str, account_service_url: str) -> None:
        """Create a new account service issuer."""
        self._seed = seed
        self._client = AccountServiceClient(account_service_url=account_service_url)

    def get_seed(self) -> str:
        """Get user NKEY seed."""
        return self._seed

    def get_token(
        self,
        client_id: str,
        entity: t.Optional[str] = None,
        scope: t.Optional[str] = None,
    ) -> str:
        """Get an user JWT as an encoded JWT token.

        Arguments:
            user: the user public key.
            client_id: the account public key.
            entity (optional): either set or verify the JWT name (depending on the type of issuer)
            scope (optional): limit permissions associated with JWT
        """
        kp = nkeys.from_seed(self._seed)
        params = {"user": kp.public_key.decode("utf-8")}
        if entity:
            params["entity"] = entity
        if scope:
            params["scope"] = scope
        # Obtain a token
        data = self._token_request(client_id, params)
        # Return the token
        return data["user_token"]  # type: ignore
