import typing as t
import httpx
from .protocol import CredsProvider


class OIDCCredsProvider(CredsProvider):
    """Obtain a JWT signed remotely by an NATS using an HTTP client after performing OIDC authentication.

    Account service MUST already always validate ID token, so why do it on client side ?
    If we do validate on client side, it means that we must be able to reach the OIDC Auth provider.
    But it also mean that we can perform various OAuth2 flows:
        - Username/Password authentication
        - Client ID/Client Secret authentication
        - Device Code authentication (a bit weird, but maybe for CLI tools on remote gateways when we want to intervene manually ?)
        - I'm not sure that Authorization Code is pertinent without a server-side implementation

    What's great, is that we only obtain an ID token, not an access to NATS.
    It's the role of the account service to check if an entity is linked to such ID token.
    And then it checks the permissions of the entity.

    If no entity is provided, client application is assumed to run under NKEY publick key behalf
    """

    def __init__(
        self,
        account_service_url: str,
        oidc_client_id: str,
        oidc_client_secret: t.Optional[str] = None,
    ) -> None:
        self.account_service_url = account_service_url
        self.oidc_client_id = oidc_client_id
        self._oidc_client_id = oidc_client_secret
        self._seed: t.Optional[str] = None
        self._client: t.Optional[httpx.Client] = None

    def _init_client(self) -> httpx.Client:
        """Create a new HTTP client"""
        return httpx.Client(base_url=self.account_service_url)

    def _seed_request(self) -> t.Dict[str, t.Any]:
        """Send a request to get a seed."""
        # Initialie client if required
        if self._client is None:
            self._client = self._init_client()
        # Perform OIDC login
        id_token = ""
        # Send POST request
        response = self._client.post(
            "/identities/nkey_endpoint", params={"id_token": id_token}
        )
        # Check status code
        response.raise_for_status()
        # Return response data
        return response.json()  # type: ignore

    def get_seed(self) -> str:
        """Get NKEY seed"""
        if self._seed is not None:
            return self._seed
        data = self._seed_request()
        return data["nkey_seed"]  # type: ignore
