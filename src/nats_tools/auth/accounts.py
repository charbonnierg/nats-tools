import typing as t
from datetime import datetime
from time import time

from nats_tools.jwts.api import (
    _iat,
    _jti,
    decode_account,
    decode_user,
    encode_account,
    encode_user,
)
from nats_tools.jwts.types import Account as NATSAccount
from nats_tools.jwts.types import ScopedUser, ScopedUserClaims, SigningKey
from nats_tools.nkeys import KeyPair, constants, errors, load_keypair_from_seed, parser


class Account:
    def __init__(
        self,
        name: str,
        public_key: t.Union[str, bytes, bytearray],
        operator_public_key: t.Union[str, bytes, bytearray],
        nats: t.Optional[NATSAccount] = None,
        audience: t.Optional[str] = None,
        not_after: t.Optional[int] = None,
        not_before: t.Optional[int] = None,
        iat: t.Optional[int] = None,
        jti: t.Optional[str] = None,
        seed: t.Union[None, str, bytes, bytearray] = None,
        **kwargs: t.Any,
    ) -> None:
        """An NATS account."""
        self.name = name
        self.audience = audience
        self.not_after = not_after
        self.not_before = not_before
        self.iat = iat
        self.jti = jti
        self.nats = nats or NATSAccount.from_values(kwargs)
        self._kp: t.Optional[KeyPair] = None
        # Validate account public key
        prefix, public_bytes = parser.decode_public_key(public_key=public_key)
        if prefix != constants.PREFIX_BYTE_ACCOUNT:
            raise errors.InvalidPublicKeyError()
        self.public_key = parser.encode_public_key(prefix, public_bytes).decode("utf-8")
        # Validate operator public key
        operator_prefix, operator_public_bytes = parser.decode_public_key(
            public_key=operator_public_key
        )
        if operator_prefix != constants.PREFIX_BYTE_OPERATOR:
            raise errors.InvalidPublicKeyError()
        self.operator_public_key = parser.encode_public_key(
            operator_prefix, operator_public_bytes
        ).decode("utf-8")
        # Validate account seed
        if seed:
            kp = load_keypair_from_seed(seed)
            if kp.public_key.decode("utf-8") != self.public_key:
                raise errors.InvalidPublicKeyError()
            self._kp = kp
        del prefix
        del public_bytes

    def encode(self, operator_seed: t.Union[str, bytes, bytearray, None] = None) -> str:
        """Return account JWT"""
        if operator_seed is None:
            raise errors.CannotSignError()
        kp = load_keypair_from_seed(operator_seed)
        if kp.public_key.decode("utf-8") != self.operator_public_key:
            raise errors.InvalidPublicKeyError()
        if self.iat is None:
            self.iat = _iat()
        if self.jti is None:
            self.jti = _jti()
        return encode_account(
            name=self.name,
            account_public_key=self.public_key,
            operator_seed=kp.seed,
            account=self.nats,
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
        operator_public_key: t.Union[str, bytes, None] = None,
        account_public_key: t.Union[str, bytes, None] = None,
        account_seed: t.Optional[str] = None,
        verify: bool = True,
    ) -> "Account":
        """Create a new Account from account JWT"""
        # Optionally fetch public key from seed
        if account_seed and account_public_key is None:
            account_public_key = load_keypair_from_seed(account_seed).public_key
        # Decode account
        claims = decode_account(
            token,
            operator_public_key=operator_public_key,
            account_public_key=account_public_key,
            verify=verify,
        )
        # Create new Account instance
        return cls(
            name=claims.name,
            public_key=claims.sub,
            operator_public_key=claims.iss,
            seed=account_seed,
            nats=claims.nats,
            audience=claims.aud,
            not_after=claims.exp,
            not_before=claims.nbf,
            iat=claims.iat,
            jti=claims.jti,
        )

    def __repr__(self) -> str:
        return f"Account(name={self.name}, public_key={self.public_key})"

    def to_values(self) -> t.Dict[str, t.Any]:
        values = {
            "name": self.name,
            "public_key": self.public_key,
            "operator_public_key": self.operator_public_key,
            "nats": self.nats.to_values(),
            "audience": self.audience,
            "not_after": self.not_after,
            "not_before": self.not_before,
            "iat": self.iat,
            "jti": self.jti,
        }
        return {key: value for key, value in values.items() if value is not None}

    def add_signing_key(self, public_key: t.Union[str, bytes, bytearray]) -> "Account":
        public_signing_key = (
            public_key.decode("utf-8")
            if isinstance(public_key, (bytes, bytearray))
            else public_key
        )
        if self.nats.signing_keys is None:
            self.nats.signing_keys = []
        if public_signing_key not in self.nats.signing_keys:
            self.nats.signing_keys.append(public_signing_key)
            self.iat = None
            self.jti = None
        return self

    def remove_signing_key(self, public_key: t.Union[str, bytes]) -> "Account":
        if self.nats.signing_keys is None:
            return self
        public_signing_key = (
            public_key.decode("utf-8") if isinstance(public_key, bytes) else public_key
        )
        if public_signing_key in self.nats.signing_keys:
            self.nats.signing_keys = [
                key for key in self.nats.signing_keys if key != public_signing_key
            ]
            self.iat = None
            self.jti = None
        return self

    def set_signing_keys(
        self, signing_keys: t.List[t.Union[str, bytes, SigningKey]]
    ) -> "Account":
        keys = [
            key.decode("utf-8")
            if isinstance(key, bytes)
            else (key.key if isinstance(key, SigningKey) else key)
            for key in signing_keys
        ]
        if self.nats.signing_keys and sorted(
            [
                key.key if isinstance(key, SigningKey) else key
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

    def set_expiration(self, value: t.Union[int, datetime]) -> "Account":
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

    def set_activation(self, value: t.Union[int, datetime]) -> "Account":
        if isinstance(value, datetime):
            value = int(value.timestamp())
        if self.not_before == value:
            return self
        self.not_before = value
        self.iat = None
        self.jti = None
        return self

    def set_audience(self, value: str) -> "Account":
        if self.audience == value:
            return self
        self.audience = value
        self.iat = None
        self.jti = None
        return self

    def verify_user(
        self, token: t.Union[str, bytes], subject: t.Optional[str] = None
    ) -> ScopedUserClaims:
        keys: t.List[t.Union[str, SigningKey]] = [self.public_key]
        if self.nats.signing_keys:
            keys.extend(self.nats.signing_keys)
        last_exc: t.Optional[Exception] = None
        for key in keys:
            public_key = key.key if isinstance(key, SigningKey) else key
            try:
                return decode_user(
                    token,
                    account_public_key=public_key,
                    user_public_key=subject,
                    verify=True,
                )
            # FIXME: Catch invalid signature / invalid issuer only
            except Exception as exc:
                last_exc = exc
                continue
        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected error. Please open an issue.")

    def sign_user(
        self,
        user_name: str,
        user_public_key: t.Union[str, bytes, bytearray],
        user: t.Union[t.Mapping[str, t.Any], ScopedUser, None] = None,
        audience: t.Optional[str] = None,
        not_after: t.Optional[int] = None,
        not_before: t.Optional[int] = None,
        iat: t.Optional[int] = None,
        jti: t.Optional[str] = None,
        signing_key: t.Union[None, str, bytes, bytearray] = None,
    ) -> str:
        if signing_key is None:
            if self._kp is None:
                raise errors.CannotSignError()
            else:
                signing_key = self._kp.seed
        # Make sure that signing key is valid
        else:
            signing_keypair = load_keypair_from_seed(signing_key)
            signing_public_key = signing_keypair.public_key
            if signing_public_key != self.public_key:
                if not self.nats.signing_keys:
                    raise errors.InvalidSeedError()
                for key in self.nats.signing_keys:
                    pubkey = key.key if isinstance(key, SigningKey) else key
                    if signing_public_key == pubkey:
                        break
                else:
                    raise errors.InvalidSeedError()
        # decode user
        if user is None:
            user = ScopedUser(data=-1, payload=-1, subs=-1)
        # Encode account
        return encode_user(
            name=user_name,
            user_public_key=user_public_key,
            account_seed=signing_key,
            user=user,
            audience=audience,
            not_after=not_after,
            not_before=not_before,
            iat=iat,
            jti=jti,
        )
