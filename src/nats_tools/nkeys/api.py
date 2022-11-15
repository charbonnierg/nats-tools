import typing as t

import cryptography.exceptions
import typing_extensions as t_

from . import encoding, errors, kp


def sign(private_bytes: t.Union[str, bytes, bytearray], data: bytes) -> bytes:
    """Sign some data using a seed"""
    if not private_bytes:
        raise errors.InvalidSeedError()
    key = encoding.decode_ed25519_private_key(private_bytes)
    return key.sign(data)


def verify(
    public_bytes: t.Union[str, bytes, bytearray], signature: bytes, data: bytes
) -> bool:
    if not public_bytes:
        raise errors.InvalidPublicKeyError()
    key = encoding.decode_ed25519_public_key(public_bytes)
    try:
        key.verify(signature, data)
        return True
    except cryptography.exceptions.InvalidSignature as exc:
        raise errors.InvalidSignatureError() from exc


def create_keypair(prefix: t_.Literal["user", "account", "operator"]) -> kp.KeyPair:
    """Create a new keypair"""
    return kp.KeyPair.create(prefix=prefix)


def from_seed(seed: t.Union[str, bytes, bytearray]) -> kp.KeyPair:
    """Load a new keypair from seed.

    An ED25519 public key or private key is not sufficient to generate a KeyPair, because
    it does not include the access type (operator, account or user).

    As such, it is necessary to provide a seed to get the associated KeyPair, which has then access
    to both the public signing key and the private signing key.

    Arguments:
        seed: the seed decode.

    Returns:
        A KeyPair instance.
    """
    return kp.KeyPair.from_seed(seed)


def from_private_bytes(
    prefix: int, private_bytes: t.Union[str, bytes, bytearray]
) -> kp.KeyPair:
    """Load a new keypair from private bytes and prefix"""
    return kp.KeyPair.from_private_bytes(prefix=prefix, private_bytes=private_bytes)
