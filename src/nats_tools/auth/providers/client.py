import httpx
import typing as t


class AccountServiceClient:
    """Interact with QUARA NATS Credentials API"""

    def __init__(
        self,
        account_service_url: str,
    ) -> None:
        """Create a new client"""
        self.account_service_url = account_service_url
        self._client: t.Optional[httpx.Client] = None

    def _init_client(self) -> httpx.Client:
        """Create a new HTTP client"""
        return httpx.Client(base_url=self.account_service_url)

    def _post_request(
        self,
        endpoint: str,
        params: t.Mapping[str, str],
        payload: t.Optional[t.Mapping[str, t.Any]] = None,
        **kwargs: t.Any,
    ) -> httpx.Response:
        """Send an HTTP POST request"""
        # Initialie client if required
        if self._client is None:
            self._client = self._init_client()
        # Use kwargs as options to httpx.Client.post
        options: t.Dict[str, t.Any] = kwargs.copy()
        # Override params and JSON
        if params:
            options["params"] = params
        if payload is not None:
            options["json"] = payload
        # Send request with options
        return self._client.post(endpoint, **options)

    def token_request(
        self,
        client_id: str,
        params: t.Mapping[str, str],
        payload: t.Optional[t.Mapping[str, t.Any]] = None,
        **kwargs: t.Any,
    ) -> t.Dict[str, t.Any]:
        """Send a request to token endpoint.

        Authentication may be required by the issuer account.
        If authentication method is allowed by account and argument is provided
        then client attempts to authenticate.
        """
        # Send unauthenticated POST request
        response = self._post_request(
            f"/accounts/{client_id}/token_endpoint",
            params=params,
            payload=payload,
            **kwargs,
        )
        # Check all status codes
        # Basically 200 <= value <= 299 with nice error hanling
        response.raise_for_status()
        # Return response data
        return response.json()  # type: ignore
