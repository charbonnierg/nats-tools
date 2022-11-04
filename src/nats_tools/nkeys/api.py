import typing as t

import cryptography.exceptions
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import errors, parser
from .keypair import KeyPair


def sign(seed: t.Union[str, bytes, bytearray], data: bytes) -> bytes:
    """Sign some data using a seed"""
    if not seed:
        raise errors.InvalidSeedError()
    if seed[0] == 80:
        ed25519_key = load_ed25519_private_key(seed)
    elif seed[0] == 83:
        ed25519_key = load_keypair_from_seed(seed).signing_key
    else:
        raise errors.InvalidSeedError()
    return ed25519_key.sign(data)


def verify(
    public_key: t.Union[str, bytes, bytearray], signature: bytes, data: bytes
) -> bool:
    public_key = parser._encode(public_key)
    if not public_key:
        raise errors.InvalidPublicKeyError()
    if public_key[0] == 80:
        ed25519_key = load_ed25519_private_key(public_key).public_key()
    elif public_key[0] == 83:
        ed25519_key = load_keypair_from_seed(public_key).signing_key.public_key()
    else:
        ed25519_key = load_ed25519_public_key(public_key=public_key)
    try:
        ed25519_key.verify(signature, data)
        return True
    except cryptography.exceptions.InvalidSignature:
        raise errors.InvalidSignatureError()


def create_keypair(prefix: t.Literal["user", "account", "operator"]) -> KeyPair:
    """Create a new keypair"""
    return KeyPair.create(prefix=prefix)


def load_keypair_from_seed(seed: t.Union[str, bytes, bytearray]) -> KeyPair:
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
    return KeyPair.from_seed(seed)


def load_keypair_from_private_key(
    prefix: int, private_key: t.Union[str, bytes, bytearray]
) -> KeyPair:
    """Load a new keypair from private key and prefix"""
    return KeyPair.from_private_key(prefix=prefix, private_key=private_key)


def load_ed25519_public_key(
    public_key: t.Union[str, bytes, bytearray]
) -> ed25519.Ed25519PublicKey:
    """Parse an ED25519 public key from an encoded NATS public key.

    Arguments:
        key: a public NATS key (prefix + public key + crc, the whole thing being encoded as base32)

    Returns:
        An ED25519 public key which can be used to verify signatures.
    """
    _, public_bytes = parser.decode_public_key(public_key)
    ed25519_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    del public_bytes
    return ed25519_key


def load_ed25519_private_key(
    private_key: t.Union[str, bytes, bytearray]
) -> ed25519.Ed25519PrivateKey:
    """Parse an ED25519 private key from an encoded NATS private key.

    Arguments:
        key: a private NATS key  (prefix + private key + public bytes, the whole thing being encoded as base32)

    Returns:
        An ED25519 private key which can be used to sign payloads.
    """
    _, private_bytes = parser.decode_private_key(private_key)
    ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    del private_bytes
    return ed25519_key


def load_ed25519_key(
    key: t.Union[str, bytes, bytearray]
) -> t.Union[ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey]:
    """Load a public or a private key from either an encoded public key, an encoded private key, or an encoded seed."""
    key = parser._encode(key)
    if key[0] == 80:
        return load_ed25519_private_key(key)
    elif key[0] == 83:
        return load_keypair_from_seed(key).signing_key
    else:
        return load_ed25519_public_key(key)
