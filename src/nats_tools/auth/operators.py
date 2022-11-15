"""Manage NATS operators.

This module exposes the `Operator` class.

`Operator` instances are created using either a JWT, or keyword arguments.
They do not save private key or seed within their state, instead, all methods
requiring a seed expect the seed to be provided as method argument.
"""
import typing as t
from datetime import datetime
from time import time

from nats_tools import nkeys
from nats_tools import jwts
from nats_tools.jwts.api import _iat, _jti

from .accounts import Account


class Operator:
    def __init__(
        self,
        name: str,
        public_key: t.Union[str, bytes, bytearray],
        nats: t.Optional[jwts.types.Operator] = None,
        audience: t.Optional[str] = None,
        not_after: t.Optional[int] = None,
        not_before: t.Optional[int] = None,
        iat: t.Optional[int] = None,
        jti: t.Optional[str] = None,
        **kwargs: t.Any,
    ) -> None:
        """An NATS operator."""
        operator_public_key = nkeys.encoding._to_bytes(public_key)
        prefix, public_bytes = nkeys.encoding.decode_public_key(
            public_key=operator_public_key
        )
        if prefix != nkeys.constants.PREFIX_BYTE_OPERATOR:
            raise nkeys.errors.InvalidPublicKeyError()
        self.public_key = nkeys.encoding.encode_public_key(prefix, public_bytes).decode(
            "utf-8"
        )
        self.name = name
        self.audience = audience
        self.not_after = not_after
        self.not_before = not_before
        self.iat = iat
        self.jti = jti
        self.nats = nats or jwts.types.Operator.from_values(kwargs)

    @classmethod
    def create(
        cls,
        name: str,
        nats: t.Optional[jwts.types.Operator] = None,
        audience: t.Optional[str] = None,
        not_after: t.Optional[int] = None,
        not_before: t.Optional[int] = None,
        iat: t.Optional[int] = None,
        jti: t.Optional[str] = None,
    ) -> t.Tuple[nkeys.KeyPair, "Operator"]:
        kp = nkeys.create_keypair("operator")
        return kp, cls(
            name=name,
            nats=nats,
            public_key=kp.public_key,
            audience=audience,
            not_after=not_after,
            not_before=not_before,
            iat=iat,
            jti=jti,
        )

    def encode(self, seed: t.Union[str, bytes, bytearray]) -> str:
        """Return operator JWT"""
        kp = nkeys.from_seed(seed)
        public_key = kp.public_key
        if public_key.decode("utf-8") != self.public_key:
            raise nkeys.errors.InvalidPublicKeyError()
        if self.iat is None:
            self.iat = _iat()
        if self.jti is None:
            self.jti = _jti()
        return jwts.encode_operator(
            name=self.name,
            operator_seed=kp.seed,
            operator=self.nats,
            audience=self.audience,
            not_after=self.not_after,
            not_before=self.not_before,
            iat=self.iat,
            jti=self.jti,
        )

    @classmethod
    def decode(
        cls,
        token: t.Union[str, bytes],
        public_key: t.Union[str, bytes, None] = None,
        verify: bool = True,
    ) -> "Operator":
        """Create a new Operator from operator JWT"""
        if public_key is None:
            # Do not verify issuer because operators are self-signed
            claims = jwts.decode_operator(
                token, operator_public_key=None, verify=verify
            )
            # Verify subject manually
            if claims.iss != claims.sub:
                raise ValueError("Invalid JWT")
        elif public_key:
            claims = jwts.decode_operator(
                token, operator_public_key=public_key, verify=verify
            )
        else:
            raise nkeys.errors.InvalidPublicKeyError()
        return cls(
            name=claims.name,
            public_key=claims.iss.encode("utf-8"),
            nats=claims.nats,
            audience=claims.aud,
            not_after=claims.exp,
            not_before=claims.nbf,
            iat=claims.iat,
            jti=claims.jti,
        )

    def __repr__(self) -> str:
        return f"Operator(name={self.name}, public_key={self.public_key})"

    def to_values(self) -> t.Dict[str, t.Any]:
        values = {
            "name": self.name,
            "public_key": self.public_key,
            "nats": self.nats.to_values(),
            "audience": self.audience,
            "not_after": self.not_after,
            "not_before": self.not_before,
            "iat": self.iat,
            "jti": self.jti,
        }
        return {key: value for key, value in values.items() if value is not None}

    def add_signing_key(
        self, public_key: t.Union[str, bytes, bytearray, nkeys.KeyPair]
    ) -> "Operator":
        public_signing_key = (
            public_key.decode("utf-8")
            if isinstance(public_key, (bytes, bytearray))
            else public_key.public_key.decode("utf-8")
            if isinstance(public_key, nkeys.KeyPair)
            else public_key
        )
        if self.nats.signing_keys is None:
            self.nats.signing_keys = []
        if public_signing_key not in [
            key.key if isinstance(key, jwts.types.SigningKey) else key
            for key in self.nats.signing_keys
        ]:
            self.nats.signing_keys.append(public_signing_key)
            self.iat = None
            self.jti = None
        return self

    def remove_signing_key(
        self, public_key: t.Union[str, bytes, bytearray, nkeys.KeyPair]
    ) -> "Operator":
        if self.nats.signing_keys is None:
            return self
        public_signing_key = (
            public_key.decode("utf-8")
            if isinstance(public_key, (bytes, bytearray))
            else public_key.public_key.decode("utf-8")
            if isinstance(public_key, nkeys.KeyPair)
            else public_key
        )

        old_keys = self.nats.signing_keys.copy()
        self.nats.signing_keys = [
            key
            for key in self.nats.signing_keys
            if (
                (key.key != public_signing_key)
                if isinstance(key, jwts.types.SigningKey)
                else (key != public_signing_key)
            )
        ]
        if old_keys != self.nats.signing_keys:
            self.iat = None
            self.jti = None
        return self

    def set_signing_keys(
        self, signing_keys: t.List[t.Union[str, bytes, jwts.types.SigningKey]]
    ) -> "Operator":
        keys = [
            key.decode("utf-8")
            if isinstance(key, bytes)
            else (key.key if isinstance(key, jwts.types.SigningKey) else key)
            for key in signing_keys
        ]
        if self.nats.signing_keys and sorted(
            [
                key.key if isinstance(key, jwts.types.SigningKey) else key
                for key in self.nats.signing_keys
            ]
        ) == sorted(keys):
            return self
        if self.nats.signing_keys:
            self.nats.signing_keys.clear()
            self.nats.signing_keys.extend(keys)
        else:
            self.nats.signing_keys = list(keys)
        self.iat = None
        self.jti = None
        return self

    def set_expiration(self, value: t.Union[int, datetime]) -> "Operator":
        if isinstance(value, datetime):
            value = int(value.timestamp())
        if value <= int(time()):
            raise ValueError("Cannot set expiration timestamp to a past value")
        if self.not_after == value:
            return self
        self.not_after = value
        self.iat = None
        self.jti = None
        return self

    def set_activation(self, value: t.Union[int, datetime]) -> "Operator":
        if isinstance(value, datetime):
            value = int(value.timestamp())
        if self.not_before == value:
            return self
        self.not_before = value
        self.iat = None
        self.jti = None
        return self

    def set_audience(self, value: str) -> "Operator":
        if self.audience == value:
            return self
        self.audience = value
        self.iat = None
        self.jti = None
        return self

    def set_account_server_url(self, value: str) -> "Operator":
        if self.nats.account_server_url == value:
            return self
        self.nats.account_server_url = value
        self.iat = None
        self.jti = None
        return self

    def add_operator_services_url(self, value: str) -> "Operator":
        if self.nats.operator_service_urls is None:
            self.nats.operator_service_urls = []
        if value not in self.nats.operator_service_urls:
            self.nats.operator_service_urls.append(value)
            self.iat = None
            self.jti = None
        return self

    def set_operator_services_url(self, values: t.List[str]) -> "Operator":
        if self.nats.operator_service_urls and sorted(
            self.nats.operator_service_urls
        ) == sorted(values):
            return self
        self.nats.operator_service_urls = values
        self.iat = None
        self.jti = None
        return self

    def set_system_account(self, value: t.Union[str, bytes]) -> "Operator":
        public_key = value.decode("utf-8") if isinstance(value, bytes) else value
        if self.nats.system_account == public_key:
            return self
        self.nats.system_account = public_key
        self.iat = None
        self.jti = None
        return self

    def verify_account(
        self, token: t.Union[str, bytes], subject: t.Optional[str] = None
    ) -> Account:
        keys: t.List[t.Union[str, jwts.types.SigningKey]] = [self.public_key]
        if self.nats.signing_keys:
            keys.extend(self.nats.signing_keys)
        last_exc: t.Optional[Exception] = None
        for key in keys:
            public_key = key.key if isinstance(key, jwts.types.SigningKey) else key
            try:
                return Account.decode(
                    token,
                    operator_public_key=public_key,
                    account_public_key=subject,
                    verify=True,
                )
            except (
                jwts.errors.jwt.exceptions.InvalidTokenError,
                nkeys.errors.NkeysError,
            ) as exc:
                last_exc = exc
                continue
        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected error. Please open an issue.")

    def sign_account(
        self,
        signing_key: t.Union[str, bytes, bytearray],
        name: str,
        public_key: t.Union[str, bytes, bytearray],
        account: t.Union[t.Mapping[str, t.Any], jwts.types.Account, None] = None,
        audience: t.Optional[str] = None,
        not_after: t.Optional[int] = None,
        not_before: t.Optional[int] = None,
        iat: t.Optional[int] = None,
        jti: t.Optional[str] = None,
    ) -> str:
        signing_keypair = nkeys.from_seed(signing_key)
        signing_public_key = signing_keypair.public_key
        # Check that signing key is valid for the operator
        if signing_public_key.decode("utf-8") != self.public_key:
            if not self.nats.signing_keys:
                raise nkeys.errors.InvalidSeedError()
            for key in self.nats.signing_keys:
                pubkey = key.key if isinstance(key, jwts.types.SigningKey) else key
                if signing_public_key == pubkey:
                    break
            else:
                raise nkeys.errors.InvalidSeedError()
        # Validate account public key
        prefix, public_bytes = nkeys.encoding.decode_public_key(public_key)
        if prefix != nkeys.constants.PREFIX_BYTE_ACCOUNT:
            raise nkeys.errors.InvalidPrefixByteError()
        account_public_key = nkeys.encoding.encode_public_key(prefix, public_bytes)
        # Encode account
        return jwts.encode_account(
            name=name,
            account_public_key=account_public_key,
            operator_seed=signing_key,
            account=account,
            audience=audience,
            not_after=not_after,
            not_before=not_before,
            iat=iat,
            jti=jti,
        )

    def create_account(
        self,
        signing_key: t.Union[str, bytes, bytearray],
        name: str,
        account: t.Union[t.Mapping[str, t.Any], jwts.types.Account, None] = None,
        audience: t.Optional[str] = None,
        not_after: t.Optional[int] = None,
        not_before: t.Optional[int] = None,
        iat: t.Optional[int] = None,
        jti: t.Optional[str] = None,
    ) -> t.Tuple[nkeys.KeyPair, Account]:
        account_keypair = nkeys.KeyPair.create("account")
        account_public_key = account_keypair.public_key.decode("utf-8")
        token = self.sign_account(
            signing_key=signing_key,
            name=name,
            public_key=account_public_key,
            account=account,
            audience=audience,
            not_after=not_after,
            not_before=not_before,
            iat=iat,
            jti=jti,
        )
        return account_keypair, self.verify_account(token, subject=account_public_key)
