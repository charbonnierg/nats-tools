import base64
import secrets
import struct
import time
import typing as t

import jwt
import jwt.exceptions

import nats_tools.nkeys as nkeys
import nats_tools.nkeys.encoding as encoding
from nats_tools.nkeys.algorithms import ED25519Nkey

from . import errors
from .types import (
    Account,
    AccountClaims,
    Claims,
    Operator,
    OperatorClaims,
    ScopedUser,
    ScopedUserClaims,
)


def _jti() -> str:
    """Generate a jti value"""
    value = base64.b32encode(struct.pack("f", time.time()) + secrets.token_bytes(28))
    return value[:52].decode("utf-8")


def _iat() -> int:
    """Generate iat value"""
    return int(time.time())


def decode(
    token: t.Union[str, bytes],
    issuer: t.Union[str, bytes, bytearray, None] = None,
    subject: t.Union[str, bytes, bytearray, None] = None,
    verify: bool = True,
) -> Claims:
    """Decode an NATS JWT.

    By default, JWT signature is verified, as well as "iat", "nbf", and "exp" fields.
    When issuer_public_key is provided, the "iss" field of the JWT is also verified.
    When subject_public_key is provided, the "sub" field of the JWT is also verified.
    """
    # RFC8725 Best Practices 3.7: Use UTF-8
    # https://www.rfc-editor.org/rfc/rfc8725.html#name-use-utf-8
    token = token.decode("utf-8") if isinstance(token, bytes) else token
    header = jwt.get_unverified_header(token)
    # RFC8725 Best Practices 3.1: Perform algorithm verification
    # https://www.rfc-editor.org/rfc/rfc8725.html#name-perform-algorithm-verificat
    if "alg" not in header:
        raise jwt.exceptions.InvalidAlgorithmError()
    if header["alg"] != ED25519Nkey:
        raise jwt.exceptions.InvalidAlgorithmError()
    # RFC8725 Best Practices 3.11: Use explicit typing
    # https://www.rfc-editor.org/rfc/rfc8725.html#name-use-explicit-typing
    if "typ" not in header:
        raise errors.InvalidTypeError()
    if header["typ"] != "JWT":
        raise errors.InvalidTypeError()
    # First decode JWT without validation, then decode the JWT with validation, using issuer indicated in JWT.
    # This is, in practice, equivalent to not verifying the issuer.
    # Signature, expiration, activation, and iat are still verified though.
    # Note that this is not recommended, and issuer should always be verified
    if verify and issuer is None:
        # See pyjwt.decode docs
        # https://pyjwt.readthedocs.io/en/latest/api.html#jwt.decode
        untrusted_claims = jwt.decode(
            token,
            verify=False,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
        try:
            issuer = untrusted_claims["iss"]
        except KeyError as exc:
            raise jwt.exceptions.InvalidIssuerError() from exc
    # RFC8725 Best Practices 3.8: Validate issuer
    # https://www.rfc-editor.org/rfc/rfc8725.html#name-validate-issuer-and-subject
    if verify and issuer:
        if isinstance(issuer, (bytes, bytearray)):
            issuer = issuer.decode("utf-8")
        elif isinstance(issuer, str):
            issuer = issuer
        # See pyjwt.decode docs
        # https://pyjwt.readthedocs.io/en/latest/api.html#jwt.decode
        claims = jwt.decode(
            token,
            verify=verify,
            key=issuer,
            algorithms=[ED25519Nkey],
            issuer=issuer,
            options={
                "verify_signature": True,
                "verify_issuer": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
            },
        )
    # Do not verify anything
    # Not recommended: This will not check signature, nor issuer, expiration, activation, or issued at fields.
    else:
        claims = jwt.decode(
            token,
            verify=False,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    # When decoding operators JWT or account JWT, it is highly recommended to verify the subject found in JWT.
    # RFC8725 Best Practices 3.8: Validate subject
    # https://www.rfc-editor.org/rfc/rfc8725.html#name-validate-issuer-and-subject
    if "sub" not in claims:
        raise errors.InvalidSubjectError()
    if subject:
        if isinstance(subject, (bytes, bytearray)):
            sub = subject.decode("utf-8")
        else:
            sub = subject
        if claims["sub"] != sub:
            raise errors.InvalidSubjectError()
    # Return strucutred JWT
    return Claims.from_values(claims)


def decode_operator(
    token: t.Union[str, bytes],
    operator_public_key: t.Union[str, bytes, bytearray, None] = None,
    verify: bool = True,
) -> OperatorClaims:
    claims = decode(
        token, issuer=operator_public_key, subject=operator_public_key, verify=verify
    )
    if not isinstance(claims.nats, Operator):
        raise Exception(f"Invalid NATS claims: {claims.nats}")
    return OperatorClaims(
        jti=claims.jti,
        iat=claims.iat,
        iss=claims.iss,
        name=claims.name,
        sub=claims.sub,
        nats=claims.nats,
        aud=claims.aud,
        exp=claims.exp,
        nbf=claims.nbf,
    )


def decode_account(
    token: t.Union[str, bytes],
    operator_public_key: t.Union[str, bytes, bytearray, None] = None,
    account_public_key: t.Union[str, bytes, bytearray, None] = None,
    verify: bool = True,
) -> AccountClaims:
    claims = decode(
        token, issuer=operator_public_key, subject=account_public_key, verify=verify
    )
    if not isinstance(claims.nats, Account):
        raise errors.InvalidAccessTypeError()
    return AccountClaims(
        jti=claims.jti,
        iat=claims.iat,
        iss=claims.iss,
        name=claims.name,
        sub=claims.sub,
        nats=claims.nats,
        aud=claims.aud,
        exp=claims.exp,
        nbf=claims.nbf,
    )


def decode_user(
    token: t.Union[str, bytes],
    account_public_key: t.Union[str, bytes, bytearray, None] = None,
    issuer_public_key: t.Union[str, bytes, bytearray, None] = None,
    user_public_key: t.Union[str, bytes, bytearray, None] = None,
    scope: t.Optional[str] = None,
    verify: bool = True,
) -> ScopedUserClaims:
    if issuer_public_key:
        claims = decode(
            token, issuer=issuer_public_key, subject=user_public_key, verify=verify
        )
    else:
        claims = decode(token, issuer=None, subject=user_public_key, verify=verify)
    if not isinstance(claims.nats, ScopedUser):
        raise errors.InvalidAccessTypeError()
    # Verify account public key
    if account_public_key:
        if claims.nats.issuer_account is not None:
            if nkeys.encoding.decode_public_key(
                claims.nats.issuer_account
            ) != nkeys.encoding.decode_public_key(account_public_key):
                raise errors.jwt.exceptions.InvalidIssuerError()
        elif nkeys.encoding.decode_public_key(
            claims.iss
        ) != nkeys.encoding.decode_public_key(account_public_key):
            raise errors.jwt.exceptions.InvalidIssuerError()
    # Verify scope
    if scope:
        if claims.nats.tags is None:
            raise errors.InvalidScopeError()
        if f"scope:{scope}" not in claims.nats.tags:
            raise errors.InvalidScopeError()
    user_claims = ScopedUserClaims(
        jti=claims.jti,
        iat=claims.iat,
        iss=claims.iss,
        name=claims.name,
        sub=claims.sub,
        nats=claims.nats,
        aud=claims.aud,
        exp=claims.exp,
        nbf=claims.nbf,
    )
    return user_claims


def encode(
    claims: t.Union[Claims, OperatorClaims, AccountClaims, ScopedUserClaims],
    seed: t.Union[str, bytes, bytearray, nkeys.KeyPair],
) -> str:
    keypair = seed if isinstance(seed, nkeys.KeyPair) else nkeys.from_seed(seed)
    encoded_jwt = jwt.encode(
        claims.to_values(),
        key=keypair.private_key.decode("utf-8"),
        algorithm=ED25519Nkey,
        headers={"typ": "JWT"},
    )
    return encoded_jwt


def encode_operator(
    name: str,
    operator_seed: t.Union[str, bytes, bytearray],
    operator: t.Union[t.Mapping[str, t.Any], Operator, None] = None,
    audience: t.Optional[str] = None,
    not_after: t.Optional[int] = None,
    not_before: t.Optional[int] = None,
    iat: t.Optional[int] = None,
    jti: t.Optional[str] = None,
) -> str:
    kp = nkeys.from_seed(operator_seed)
    public_key = kp.public_key.decode("utf-8")
    claims = OperatorClaims(
        jti=jti or _jti(),
        iat=iat or _iat(),
        iss=kp.public_key.decode("utf-8"),
        name=name,
        sub=public_key,
        nats=Operator.from_values(operator or {}),
        aud=audience,
        exp=not_after,
        nbf=not_before,
    )
    return encode(claims, seed=operator_seed)


def encode_account(
    name: str,
    account_public_key: t.Union[str, bytes, bytearray],
    operator_seed: t.Union[str, bytes, bytearray],
    account: t.Union[t.Mapping[str, t.Any], Account, None] = None,
    audience: t.Optional[str] = None,
    not_after: t.Optional[int] = None,
    not_before: t.Optional[int] = None,
    iat: t.Optional[int] = None,
    jti: t.Optional[str] = None,
) -> str:
    prefix, public_bytes = encoding.decode_public_key(account_public_key)
    public_key = encoding.encode_public_key(prefix, public_bytes)
    kp = nkeys.from_seed(operator_seed)
    claims = AccountClaims(
        jti=jti or _jti(),
        iat=iat or _iat(),
        iss=kp.public_key.decode("utf-8"),
        name=name,
        sub=public_key.decode("utf-8"),
        nats=Account.from_values(account or {}),
        aud=audience,
        exp=not_after,
        nbf=not_before,
    )
    return encode(claims, seed=operator_seed)


def encode_user(
    name: str,
    user_public_key: t.Union[str, bytes, bytearray],
    account_seed: t.Union[str, bytes, bytearray],
    user: t.Union[t.Mapping[str, t.Any], ScopedUser],
    audience: t.Optional[str] = None,
    not_after: t.Optional[int] = None,
    not_before: t.Optional[int] = None,
    iat: t.Optional[int] = None,
    jti: t.Optional[str] = None,
) -> str:
    prefix, public_bytes = encoding.decode_public_key(user_public_key)
    public_key = encoding.encode_public_key(prefix, public_bytes).decode("utf-8")
    kp = nkeys.from_seed(account_seed)
    claims = ScopedUserClaims(
        jti=jti or _jti(),
        iat=iat or _iat(),
        iss=kp.public_key.decode("utf-8"),
        name=name,
        sub=public_key,
        nats=ScopedUser.from_values(user or {}),
        aud=audience,
        exp=not_after,
        nbf=not_before,
    )
    return encode(claims, seed=account_seed)
