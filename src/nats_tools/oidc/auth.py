import types
import typing as t
import urllib.parse
from dataclasses import dataclass, field

import httpx
import jwt
import jwt.algorithms
import jwt.exceptions

ScopeType = t.Union[str, t.List[str], t.Tuple[str], t.Set[str]]


@dataclass
class UntrustedGrant:
    """JSON data received from OIDC token endpoint"""

    access_token: str
    id_token: t.Optional[str] = None
    refresh_token: t.Optional[str] = None
    expires_in: t.Optional[int] = None
    refresh_expires_in: t.Optional[int] = None
    token_type: t.Optional[str] = None
    not_before_policy: t.Optional[str] = None
    session_state: t.Optional[str] = None
    scope: t.Optional[str] = None


@dataclass
class BaseJWT:
    """Common fields between OIDC ID Token and OAuth2 Access Token"""

    acr: str
    aud: str
    azp: str
    email: str
    email_verified: bool
    exp: int
    family_name: str
    given_name: str
    iat: int
    iss: str
    jti: str
    name: str
    preferred_username: str
    session_state: str
    sid: str
    sub: str
    typ: str


@dataclass
class Access:
    """Access holds a list of roles"""

    roles: t.List[str] = field(default_factory=list)


@dataclass
class AccessToken(BaseJWT):
    """Access token received from OIDC provider"""

    typ: t.Literal["Bearer"]
    allowed_origins: t.List[str]
    realm_access: Access
    resource_access: t.Dict[str, Access]
    scope: str


@dataclass
class IDToken(BaseJWT):
    """ID token received from OIDC provider"""

    typ: t.Literal["ID"]
    at_hash: str
    auth_time: int


@dataclass
class Grant:
    """Validated data received from the OIDC token endpoint"""

    access_token: AccessToken
    id_token: t.Optional[IDToken] = None
    refresh_token: t.Optional[str] = None


class OIDCAuthenticator:
    """An OIDCAuthenticator communicates with an OIDC provider to perform one of the
    following grants:
        - Password grant
        - Client credentials grant
        - Authorization code grant
        - Refresh grant
    """

    def __init__(
        self,
        well_known_uri: str,
    ) -> None:
        """Create a new OIDCAuthenticator instance.
        Arguments:
            well_known_uri: An URL pointing to well known OIDC configuration.
        """
        self.client = httpx.AsyncClient()
        self.default_algorithms = jwt.algorithms.get_default_algorithms()
        self.well_known_uri = well_known_uri
        self.well_known: t.Dict[str, t.Any] = {}
        self._issuer_public_key: t.Optional[t.Any] = None
        self._algorithm: t.Optional[str] = None

    async def __aenter__(self) -> "OIDCAuthenticator":
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: t.Optional[BaseException] = None,
        exc: t.Optional[BaseException] = None,
        tb: t.Optional[types.TracebackType] = None,
    ) -> None:
        await self.stop()
        return None

    async def start(self) -> None:
        """Start the OIDCAuthenticator."""
        well_known = await self.client.get(self.well_known_uri)
        well_known.raise_for_status()
        self.well_known.update(well_known.json())
        await self.refresh_issuer_public_key()

    async def stop(self) -> None:
        """Stop the OIDCAuthenticator."""
        await self.client.aclose()

    def get_url(self, endpoint: str) -> str:
        """Get the URl for given endpoint.
        Arguments:
            endpoint: a valid endpoint name from the OpenID Connect Discovery 1.0 specification
        Examples:
            >>> async with OIDCAuthenticator() as auth:
            >>>     auth_url = auth.get_url("authorization_endpoint")
            >>>     token_url = auth.get_url("token_endpoint")
        """
        try:
            return str(self.well_known[endpoint])
        except KeyError:
            raise KeyError(f"No URL configured for endpoint: {endpoint}")

    def get_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        *,
        scope: t.Optional[ScopeType] = None,
        state: t.Optional[str] = None,
        response_type: str = "code",
    ) -> str:
        """
        Get authorization URL to redirect the resource owner to.
        https://tools.ietf.org/html/rfc6749#section-4.1.1
        Arguments:
            client_id: OIDC client ID
            redirect_uri: Absolute URL of the client where the user-agent will be redirected to.
            scope: Space delimited list of strings, or iterable of strings.
            state: An opaque value used by the client to maintain state between the request and callback.
            response_type: Use "code" to perform authorization grant, or "token" to perform implicit grant.
        Return:
            URL to redirect the resource owner to.
        """
        optional_parameters: t.Dict[str, t.Any] = {}
        if state:
            optional_parameters["state"] = state
        params = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "response_type": response_type,
                "redirect_uri": redirect_uri,
                "scope": self.write_scope(scope),
                **optional_parameters,
            }
        )
        url = self.get_url("authorization_endpoint")
        return "{}?{}".format(url, params)

    def get_client(
        self,
        client_id: str,
        client_secret: t.Optional[str] = None,
        *,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: bool = True,
        verify_signature: bool = True,
        scope: t.Optional[ScopeType] = None,
    ) -> "OIDCClientAuthenticator":
        """Get an OIDCAuthenticator client dedicated to a single OIDC client."""
        return OIDCClientAuthenticator(
            self,
            client_id=client_id,
            client_secret=client_secret,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
            scope=scope,
        )

    async def refresh_issuer_public_key(self) -> None:
        """Fetch the issuer public key from remote OIDC provider."""
        jwks_url = self.get_url("jwks_uri")
        response = await self.client.get(jwks_url)
        response.raise_for_status()
        jwks: t.List[t.Dict[str, t.Any]] = response.json()["keys"]
        for key in jwks:
            if "alg" in key and key["alg"] in self.default_algorithms:
                self._algorithm = key["alg"]
                self._issuer_public_key = self.default_algorithms[
                    self._algorithm
                ].from_jwk(key)
                break
        else:
            raise KeyError(
                f"No public found with supported algorithm ({list(self.default_algorithms)})"
            )

    def get_algorithm(self) -> str:
        """Get algorithm used to validate JWT"""
        if self._algorithm:
            return self._algorithm
        raise ValueError(
            "Algorithm is not configured. Make sure OIDCAuthenticator is started."
        )

    def get_issuer_public_key(self) -> t.Any:
        """Get public key used to validate JWT."""
        if self._issuer_public_key:
            return self._issuer_public_key
        raise ValueError(
            "Issuer public key is not configured. Make sure OIDCAuthenticator is started."
        )

    def decode_token(
        self,
        token: str,
        audience: t.Optional[str] = None,
        *,
        verify_signature: bool = True,
        verify_audience: bool = True,
    ) -> t.Dict[str, t.Any]:
        """Decode a JWT using issuer public key.
        By default JWT signature is verified and audience is verified.
        Arguments:
            token: The token to decode as a string.
            audience: Value to check for audience claim. Ignored when verify_audience is False.
            verify_signature: Do not verify the JWT signature when False. True by default.
            verify_audience: Do no verify the access token audience when False. True by default.
        Returns:
            A dictionary holding fields found within JWT.
        """
        key = self.get_issuer_public_key()
        algorithm = self.get_algorithm()
        options: t.Dict[str, t.Any] = {"verify_signature": verify_signature}
        if verify_audience:
            options["verify_aud"] = True
        else:
            options["verify_aud"] = False
        return jwt.decode(
            token,
            key=key,
            algorithms=[algorithm],
            audience=audience,
            options=options,
        )

    def decode_access_token(
        self,
        token: str,
        audience: t.Optional[str] = None,
        *,
        verify_signature: bool = True,
        verify_audience: bool = True,
    ) -> AccessToken:
        """Decode an OIDC access token using issuer public key.
        Access token hold informations regarding user identity, just like ID tokens,
        but they also hold authorization information such as:
          - realm access (roles)
          - resource access (roles)
          - scopes
        Arguments:
            token: The token to decode as a string.
            audience: Value to check for audience claim. Ignored when verify_audience is False.
            verify_signature: Do not verify the JWT signature when False. True by default.
            verify_audience: Do no verify the access token audience when False. True by default.
        Returns:
            An AccessToken instance.
        """
        values = self.decode_token(
            token,
            audience=audience,
            verify_signature=verify_signature,
            verify_audience=verify_audience,
        )
        values["allowed_origins"] = values.pop("allowed_origins", [])
        return AccessToken(**values)

    def decode_id_token(
        self,
        token: str,
        audience: t.Optional[str] = None,
        *,
        verify_signature: bool = True,
        verify_audience: bool = True,
    ) -> IDToken:
        """Decode an OIDC ID token using issuer public key.
        ID tokens can be used to prove that user is AUTHENTICATED.
        It holds information regarding IDENTITY of the user.
        They should never be used for authorization purpose.
        Use the access token instead.
        Arguments:
            token: The token to decode as a string.
            audience: Value to check for audience claim. Ignored when verify_audience is False.
            verify_signature: Do not verify the JWT signature when False. True by default.
            verify_audience: Do no verify the access token audience when False. True by default.
        Returns:
            An IDToken instance.
        """
        return IDToken(
            **self.decode_token(
                token,
                audience=audience,
                verify_signature=verify_signature,
                verify_audience=verify_audience,
            )
        )

    async def oidc_token_request(
        self,
        client_id: str,
        grant_type: str,
        *,
        scope: t.Optional[ScopeType] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: bool = True,
        verify_signature: bool = True,
        **kwargs: t.Any,
    ) -> Grant:
        """Send a request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        Arguments:
            client_id: OIDC client ID.
            grant_type: One of "authorization_code", "refresh_token", "password", "client_credentials".
            scope: Space delimited list of strings, or iterable of strings.
            access_token_audience: Value to check for access token audience claim. Ignored when verify_audience is False.
            id_token_audience: Value to check for id token audience claim. Ignored when verify_audience is False.
            verify_signature: Do not verify the JWT signature when False. True by default.
            verify_audience: Do no verify the access token audience when False. True by default.
            kwargs: Extra arguments specific to each grant type.
        Returns:
            A Grant instance holding access token.
        """
        scope = self.write_scope(scope)
        response = await self.client.post(
            self.well_known["token_endpoint"],
            data={
                "client_id": client_id,
                "grant_type": grant_type,
                "scope": scope,
                **kwargs,
            },
        )
        response.raise_for_status()
        values = response.json()
        values["not_before_policy"] = values.pop("not-before-policy", None)
        untrusted = UntrustedGrant(**values)
        return Grant(
            access_token=self.decode_access_token(
                untrusted.access_token,
                audience=access_token_audience,
                verify_audience=verify_audience,
                verify_signature=verify_signature,
            ),
            id_token=self.decode_id_token(
                untrusted.id_token,
                audience=id_token_audience,
                verify_audience=verify_audience,
                verify_signature=verify_signature,
            )
            if untrusted.id_token
            else None,
            refresh_token=untrusted.refresh_token,
        )

    async def oidc_password_grant(
        self,
        client_id: str,
        username: str,
        password: str,
        *,
        client_secret: t.Optional[str] = None,
        scope: t.Optional[ScopeType] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: bool = True,
        verify_signature: bool = True,
    ) -> Grant:
        """Send a password grant request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        Arguments:
            client_id: OIDC client ID.
            username: Name of user.
            password: Password of user.
            scope: Space delimited list of strings, or iterable of strings.
            access_token_audience: Value to check for access token audience claim. Ignored when verify_audience is False.
            id_token_audience: Value to check for id token audience claim. Ignored when verify_audience is False.
            verify_signature: Do not verify the JWT signature when False. True by default.
            verify_audience: Do no verify the access token audience when False. True by default.
        Returns:
            A Grant instance holding access token.
        """
        kwargs = {"client_secret": client_secret} if client_secret else {}
        return await self.oidc_token_request(
            client_id=client_id,
            grant_type="password",
            scope=scope,
            username=username,
            password=password,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
            **kwargs,
        )

    async def oidc_authorization_code_grant(
        self,
        client_id: str,
        code: str,
        redirect_uri: str,
        *,
        client_secret: t.Optional[str] = None,
        state: t.Optional[str] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: bool = True,
        verify_signature: bool = True,
    ) -> Grant:
        """Send an authorization code grant request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        This method is mostly useful when an HTTP server is listening for requests.
        Arguments:
            client_id: OIDC client ID.
            code: The value of authorization code received as request query param.
            redirect_uri: The exact redirect URI used when generating the authorization URL visited to obtain authorization code.
            state: An opaque value used by the client to maintain state between the request and callback.
            access_token_audience: Value to check for access token audience claim. Ignored when verify_audience is False.
            id_token_audience: Value to check for id token audience claim. Ignored when verify_audience is False.
            verify_signature: Do not verify the JWT signature when False. True by default.
            verify_audience: Do no verify the access token audience when False. True by default.
        Returns:
            A Grant instance holding access token.
        """
        optional_parameters: t.Dict[str, t.Any] = {}
        if state:
            optional_parameters["state"] = state
        if client_secret:
            optional_parameters["client_secret"] = client_secret
        return await self.oidc_token_request(
            client_id=client_id,
            grant_type="authorization_code",
            code=code,
            redirect_uri=redirect_uri,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
            **optional_parameters,
        )

    async def oidc_refresh_token_grant(
        self,
        client_id: str,
        refresh_token: str,
        *,
        client_secret: t.Optional[str] = None,
        scope: t.Optional[ScopeType] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: bool = True,
        verify_signature: bool = True,
    ) -> Grant:
        """Send a refresh token grant request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        This method should not be used for used for access tokens retrieved from client_credentials grant according to RFC6749 (Section 4.4.3).
        Arguments:
            client_id: OIDC client ID.
            refresh_token: The value of the refresh token.
            scope: Space delimited list of strings, or iterable of strings.
            access_token_audience: Value to check for access token audience claim. Ignored when verify_audience is False.
            id_token_audience: Value to check for id token audience claim. Ignored when verify_audience is False.
            verify_signature: Do not verify the JWT signature when False. True by default.
            verify_audience: Do no verify the access token audience when False. True by default.
        Returns:
            A Grant instance holding access token.
        """
        kwargs = {"client_secret": client_secret} if client_secret else {}
        return await self.oidc_token_request(
            client_id=client_id,
            grant_type="refresh_token",
            refresh_token=refresh_token,
            scope=scope,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
            **kwargs,
        )

    async def oidc_client_credentials_grant(
        self,
        client_id: str,
        client_secret: str,
        *,
        scope: t.Optional[ScopeType] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: bool = True,
        verify_signature: bool = True,
    ) -> Grant:
        """Send a client credential grant request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        Arguments:
            client_id: OIDC client ID.
            client_secret: The value of the OIDC client secret.
            scope: Space delimited list of strings, or iterable of strings.
            access_token_audience: Value to check for access token audience claim. Ignored when verify_audience is False.
            id_token_audience: Value to check for id token audience claim. Ignored when verify_audience is False.
            verify_signature: Do not verify the JWT signature when False. True by default.
            verify_audience: Do no verify the access token audience when False. True by default.
        Returns:
            A Grant instance holding access token.
        """
        return await self.oidc_token_request(
            client_id=client_id,
            grant_type="client_credentials",
            client_secret=client_secret,
            scope=scope,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
        )

    @staticmethod
    def write_scope(
        scope: t.Optional[ScopeType],
        offline_access: bool = False,
        openid: bool = False,
    ) -> str:
        """Write scopes as a space-delimited string."""
        if isinstance(scope, str):
            scope = scope.split(" ")
        elif scope is None:
            scope = scope = []
        else:
            scope = list(scope)

        if offline_access:
            if "offline_access" not in scope:
                scope.insert(0, "offline_access")

        if openid:
            if "email" not in scope:
                scope.insert(0, "email")
            if "profile" not in scope:
                scope.insert(0, "profile")
            if "openid" not in scope:
                scope.insert(0, "openid")

        return " ".join(scope)


class OIDCClientAuthenticator:
    def __init__(
        self,
        OIDCAuthenticator: OIDCAuthenticator,
        client_id: str,
        client_secret: t.Optional[str] = None,
        *,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: bool = True,
        verify_signature: bool = True,
        scope: t.Optional[ScopeType] = None,
    ) -> None:
        self.authenticator = OIDCAuthenticator
        self.client_id = client_id
        self.client_secret = client_secret or None
        self.access_token_audience = access_token_audience or "account"
        self.id_token_audience = id_token_audience or self.client_id
        self.verify_audience = verify_audience
        self.verify_signature = verify_signature
        self.scope = scope

    def set_access_token_audience(self, audience: str) -> "OIDCClientAuthenticator":
        self.access_token_audience = audience
        return self

    def set_id_token_audience(self, audience: str) -> "OIDCClientAuthenticator":
        self.id_token_audience = audience
        return self

    def set_client_secret(self, secret: str) -> "OIDCClientAuthenticator":
        self.client_secret = secret
        return self

    def decode_access_token(
        self,
        token: str,
        audience: t.Optional[str] = None,
        *,
        verify_signature: t.Optional[bool] = None,
        verify_audience: t.Optional[bool] = None,
    ) -> AccessToken:
        """Decode an access token using issuer public key.
        Access token hold informations regarding user identity, just like ID tokens,
        but they also hold authorization information such as:
          - realm access (roles)
          - resource access (roles)
          - scopes
        By default JWT signature is verified and audience is verified.
        """
        audience = audience or self.access_token_audience
        if verify_audience is None:
            verify_audience = self.verify_audience
        if verify_signature is None:
            verify_signature = self.verify_signature
        return self.authenticator.decode_access_token(
            token=token,
            audience=audience,
            verify_signature=verify_signature,
            verify_audience=verify_audience,
        )

    def decode_id_token(
        self,
        token: str,
        audience: t.Optional[str] = None,
        *,
        verify_signature: t.Optional[bool] = None,
        verify_audience: t.Optional[bool] = None,
    ) -> IDToken:
        """Decode an ID token using issuer public key.
        ID tokens can be used to prove that user is AUTHENTICATED.
        It holds information regarding IDENTITY of the user.
        They should never be used for authorization purpose.
        Use the access token instead.
        By default JWT signature is verified and audience is verified.
        """
        audience = audience or self.id_token_audience
        if verify_audience is None:
            verify_audience = self.verify_audience
        if verify_signature is None:
            verify_signature = self.verify_signature
        return self.authenticator.decode_id_token(
            token=token,
            audience=audience,
            verify_signature=verify_signature,
            verify_audience=verify_audience,
        )

    async def oidc_password_grant(
        self,
        username: str,
        password: str,
        client_secret: t.Optional[str] = None,
        *,
        scope: t.Optional[ScopeType] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: t.Optional[bool] = None,
        verify_signature: t.Optional[bool] = None,
    ) -> Grant:
        """Send a password grant request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        Arguments:
            username: Name of user.
            password: Password of user.
            scope: Space delimited list of strings, or iterable of strings.
        Returns:
            A Grant instance holding access token.
        """
        client_secret = client_secret or self.client_secret
        scope = scope or self.scope
        access_token_audience = access_token_audience or self.access_token_audience
        id_token_audience = id_token_audience or self.id_token_audience
        if verify_audience is None:
            verify_audience = self.verify_audience
        if verify_signature is None:
            verify_signature = self.verify_signature
        return await self.authenticator.oidc_password_grant(
            client_id=self.client_id,
            username=username,
            password=password,
            client_secret=client_secret,
            scope=scope,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
        )

    async def oidc_authorization_code_grant(
        self,
        code: str,
        redirect_uri: str,
        client_secret: t.Optional[str] = None,
        *,
        state: t.Optional[str] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: t.Optional[bool] = None,
        verify_signature: t.Optional[bool] = None,
    ) -> Grant:
        """Send an authorization code grant request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        This method is mostly useful when an HTTP server is listening for requests.
        Arguments:
            code: The value of authorization code received as request query param.
            redirect_uri: The exact redirect URI used when generating the authorization URL visited to obtain authorization code.
        Returns:
            A Grant instance holding access token.
        """
        client_secret = client_secret or self.client_secret
        access_token_audience = access_token_audience or self.access_token_audience
        id_token_audience = id_token_audience or self.id_token_audience
        if verify_audience is None:
            verify_audience = self.verify_audience
        if verify_signature is None:
            verify_signature = self.verify_signature
        return await self.authenticator.oidc_authorization_code_grant(
            client_id=self.client_id,
            code=code,
            redirect_uri=redirect_uri,
            client_secret=client_secret,
            state=state,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
        )

    async def oidc_refresh_token_grant(
        self,
        refresh_token: str,
        client_secret: t.Optional[str] = None,
        *,
        scope: t.Optional[ScopeType] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: t.Optional[bool] = None,
        verify_signature: t.Optional[bool] = None,
    ) -> Grant:
        """Send a refresh token grant request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        This method should not be used for used for access tokens retrieved from client_credentials grant according to RFC6749 (Section 4.4.3).
        Arguments:
            refresh_token: The value of the refresh token.
            scope: Space delimited list of strings, or iterable of strings.
        Returns:
            A Grant instance holding access token.
        """
        scope = scope or self.scope
        client_secret = client_secret or self.client_secret
        access_token_audience = access_token_audience or self.access_token_audience
        id_token_audience = id_token_audience or self.id_token_audience
        if verify_audience is None:
            verify_audience = self.verify_audience
        if verify_signature is None:
            verify_signature = self.verify_signature
        return await self.authenticator.oidc_refresh_token_grant(
            client_id=self.client_id,
            refresh_token=refresh_token,
            client_secret=client_secret,
            scope=scope,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
        )

    async def oidc_client_credentials_grant(
        self,
        client_secret: t.Optional[str] = None,
        *,
        scope: t.Optional[ScopeType] = None,
        access_token_audience: t.Optional[str] = None,
        id_token_audience: t.Optional[str] = None,
        verify_audience: t.Optional[bool] = None,
        verify_signature: t.Optional[bool] = None,
    ) -> Grant:
        """Send a client credential grant request to the token endpoint to obtain an access token, an ID token, and optionally a refresh token.
        Arguments:
            client_id: OIDC client ID.
            client_secret: The value of the OIDC client secret.
            scope: Space delimited list of strings, or iterable of strings.
        Returns:
            A Grant instance holding access token.
        """
        scope = scope or self.scope
        client_secret = client_secret or self.client_secret
        if client_secret is None:
            raise ValueError("Client secret must be provided")
        access_token_audience = access_token_audience or self.access_token_audience
        id_token_audience = id_token_audience or self.id_token_audience
        if verify_audience is None:
            verify_audience = self.verify_audience
        if verify_signature is None:
            verify_signature = self.verify_signature
        return await self.authenticator.oidc_client_credentials_grant(
            client_id=self.client_id,
            client_secret=client_secret,
            scope=scope,
            access_token_audience=access_token_audience,
            id_token_audience=id_token_audience,
            verify_audience=verify_audience,
            verify_signature=verify_signature,
        )
