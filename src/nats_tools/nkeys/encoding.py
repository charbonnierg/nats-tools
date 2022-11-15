import base64
import binascii
import typing as t

from cryptography.hazmat.primitives.serialization import (
    PublicFormat,
    PrivateFormat,
    Encoding,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from . import constants, crc, errors


def _to_bytes(src: t.Union[str, bytes, bytearray]) -> bytes:
    """Make sure string is encoded to bytes"""
    if isinstance(src, str):
        return src.encode("utf-8")
    return bytes(src)


def valid_public_prefix_byte(prefix: int) -> bool:
    """Validate public prefix bytes."""
    if (
        prefix == constants.PREFIX_BYTE_OPERATOR
        or prefix == constants.PREFIX_BYTE_SERVER
        or prefix == constants.PREFIX_BYTE_CLUSTER
        or prefix == constants.PREFIX_BYTE_ACCOUNT
        or prefix == constants.PREFIX_BYTE_USER
    ):
        return True
    else:
        return False


def encode_seed(prefix: int, private_bytes: bytes) -> bytes:
    """Encode a seed from prefix and private bytes"""
    # Validate public prefix
    valid_public_prefix_byte(prefix)
    # Initialize first two bytes
    raw0, raw1 = constants.PREFIX_BYTE_SEED, prefix
    # Encode first two bytes
    first_byte = raw0 | (raw1 >> 5)
    second_byte = (raw1 & 31) << 3
    seed = bytearray([first_byte, second_byte])
    # Append private bytes
    remaining = bytearray(private_bytes[:32])
    seed += remaining
    # Append crc16 checksum
    crc_int = crc.crc16(seed)
    crc_bytes = crc_int.to_bytes(2, byteorder="little")
    seed.extend(crc_bytes)
    # Encode seed
    return base64.b32encode(seed)


def encode_public_key(prefix: int, public_bytes: bytes) -> bytes:
    """Encode a public key from prefix and public bytes"""
    public_key = bytearray(public_bytes)
    public_key.insert(0, prefix)
    # Calculate and include crc16 checksum
    crc_int = crc.crc16(public_key)
    crc_bytes = crc_int.to_bytes(2, byteorder="little")
    public_key.extend(crc_bytes)
    # Encode to base32
    return base64.b32encode(public_key)


def encode_private_key(private_bytes: bytes, public_bytes: bytes) -> bytes:
    """Encode a private key from private bytes and public bytes"""
    private_key = bytearray(private_bytes)
    private_key += bytearray(public_bytes)
    private_key.insert(0, constants.PREFIX_BYTE_PRIVATE)
    # Calculate and include crc16 checksum
    crc_int = crc.crc16(private_key)
    crc_bytes = crc_int.to_bytes(2, byteorder="little")
    private_key.extend(crc_bytes)
    # Encode to base32
    return base64.b32encode(private_key)


def decode_seed(seed: t.Union[str, bytes, bytearray]) -> t.Tuple[int, bytes]:
    """Decode a seed into prefix and private bytes."""
    seed = _to_bytes(seed)
    # Add missing padding if required.
    padding = bytearray()
    padding += b"=" * (-len(seed) % 8)
    try:
        base32_decoded = base64.b32decode(seed + padding)
        raw = base32_decoded[: (len(base32_decoded) - 2)]
    except binascii.Error:
        raise errors.InvalidSeedError()
    # Check length (seed prefix + public prefix + private bytes)
    if len(raw) < 34:
        raise errors.InvalidSeedError()
    # Check seed prefix
    # 248 = 11111000
    seed_prefix = raw[0] & 248
    if seed_prefix != constants.PREFIX_BYTE_SEED:
        raise errors.InvalidSeedError()
    # Check public prefix
    # 7 = 00000111
    public_prefix = (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)
    if not valid_public_prefix_byte(public_prefix):
        raise errors.InvalidPrefixByteError()
    # Extract private bytes
    private_bytes = raw[2 : (len(raw))][:32]
    return (public_prefix, private_bytes)


def decode_public_key(
    public_key: t.Union[str, bytes, bytearray]
) -> t.Tuple[int, bytes]:
    """Decode a public key into prefix and public bytes."""
    public_key = _to_bytes(public_key)
    # Add missing padding if required.
    padding = bytearray()
    padding += b"=" * (-len(public_key) % 8)
    try:
        base32_decoded = base64.b32decode(public_key + padding)
        raw = base32_decoded[: (len(base32_decoded) - 2)]
    except binascii.Error:
        raise errors.InvalidPublicKeyError()
    # Check length (public prefix + public bytes)
    if len(raw) < 33:
        raise errors.InvalidPublicKeyError()
    # Check public prefix
    # 248 = 11111000
    public_prefix = raw[0] & 248
    if not valid_public_prefix_byte(public_prefix):
        raise errors.InvalidPublicKeyError()
    # Extract public bytes
    public_bytes = raw[1 : (len(raw))][:32]
    return (public_prefix, public_bytes)


def decode_private_key(
    private_key: t.Union[str, bytes, bytearray]
) -> t.Tuple[None, bytes]:
    """Decode a private key into a tuple (None, private_bytes).

    A tuple is returned to be consistent with decode_public_key and decode_seed which both
    return a tuple.
    """
    private_key = _to_bytes(private_key)
    # Add missing padding if required.
    padding = bytearray()
    padding += b"=" * (-len(private_key) % 8)
    try:
        base32_decoded = base64.b32decode(private_key + padding)
        raw = base32_decoded[: (len(base32_decoded) - 2)]
    except binascii.Error:
        raise errors.InvalidPublicKeyError()
    # Check length (prefix + private bytes)
    if len(raw) < 33:
        raise errors.InvalidPublicKeyError()
    # Check private prefix
    # 248 = 11111000
    private_prefix = raw[0] & 248
    if private_prefix != constants.PREFIX_BYTE_PRIVATE:
        raise errors.InvalidKeyError()
    # Extract private bytes
    private_bytes = raw[1 : (len(raw))][:32]
    # Return a tuple to be consistent with decode_public_key and decode_seed
    return None, private_bytes


def decode_ed25519_public_key(
    src: t.Union[str, bytes, bytearray]
) -> ed25519.Ed25519PublicKey:
    """Decode a public key into prefix and public bytes."""
    # If key is of type bytes or bytearray and is of length 32, consider it to be public bytes
    if isinstance(src, (bytes, bytearray)) and len(src) == 32:
        return ed25519.Ed25519PublicKey.from_public_bytes(src)
    # Else consider the key to be an NATS public key
    key = _to_bytes(src)
    # Still check if we received a private NATS key
    if key[0] == constants.PREFIX_BYTE_PRIVATE:
        _, private_bytes = decode_private_key(key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes).public_key()
    # Or a private NATS seed
    elif key[0] == constants.PREFIX_BYTE_SEED:
        _, private_bytes = decode_seed(key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes).public_key()
    # In all other cases, consider key to be a public NATS key
    else:
        # Rountrip to check that seed is valid
        _, public_bytes = decode_public_key(key)
        return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)


def decode_ed25519_private_key(
    private_key: t.Union[str, bytes, bytearray]
) -> ed25519.Ed25519PrivateKey:
    """Decode a private key into a tuple (None, private_bytes).

    A tuple is returned to be consistent with decode_public_key and decode_seed which both
    return a tuple.
    """
    # If key is of type bytes or bytearray and is of length 32, consider it to be public bytes
    if isinstance(private_key, (bytes, bytearray)) and len(private_key) == 32:
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    # Else consider the key to be an NATS public key
    key = _to_bytes(private_key)
    # Still check if we received a private NATS key
    if key[0] == constants.PREFIX_BYTE_PRIVATE:
        _, private_bytes = decode_private_key(key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    # Or a private NATS seed
    elif key[0] == constants.PREFIX_BYTE_SEED:
        _, private_bytes = decode_seed(key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    # In all other cases, consider key to be a NKEY seed
    else:
        # Rountrip to check that seed is valid
        _, private_bytes = decode_seed(key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)


def encode_ed25519_public_key(key: ed25519.Ed25519PublicKey) -> bytes:
    """Encode an ed25519 public key into bytes"""
    return key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def encode_ed25519_private_key(key: ed25519.Ed25519PrivateKey) -> bytes:
    """Encode an ed25519 private key key into bytes"""
    return key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
