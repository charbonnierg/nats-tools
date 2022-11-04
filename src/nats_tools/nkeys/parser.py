import base64
import binascii
import typing as t

from . import constants, crc, errors


def _encode(src: t.Union[str, bytes, bytearray]) -> bytes:
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
    # Append padding
    padding = bytearray()
    padding += b"=" * (-len(seed) % 8)
    # Encode seed
    encoded_seed = base64.b32encode(seed + padding)
    del seed
    # Return encoded seed
    return encoded_seed


def encode_public_key(prefix: int, public_bytes: bytes) -> bytes:
    """Encode a public key from prefix and public bytes"""
    public_key = bytearray(public_bytes)
    public_key.insert(0, prefix)
    # Calculate and include crc16 checksum
    crc_int = crc.crc16(public_key)
    crc_bytes = crc_int.to_bytes(2, byteorder="little")
    public_key.extend(crc_bytes)
    # Encode to base32
    base32_encoded = base64.b32encode(public_key)
    del public_key
    # Return encoded public key
    return base32_encoded


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
    base32_encoded = base64.b32encode(private_key)
    del private_key
    # Return encoded private key
    return base32_encoded


def decode_seed(seed: t.Union[str, bytes, bytearray]) -> t.Tuple[int, bytes]:
    """Decode a seed into prefix and private bytes."""
    seed = _encode(seed)
    # Add missing padding if required.
    padding = bytearray()
    padding += b"=" * (-len(seed) % 8)

    try:
        base32_decoded = base64.b32decode(seed + padding)
        raw = base32_decoded[: (len(base32_decoded) - 2)]
    except binascii.Error:
        raise errors.InvalidSeedError()

    if len(raw) < 32:
        raise errors.InvalidSeedError()

    # 248 = 11111000
    b1 = raw[0] & 248

    # 7 = 00000111
    b2 = (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)

    if b1 != constants.PREFIX_BYTE_SEED:
        raise errors.InvalidSeedError()
    elif not valid_public_prefix_byte(b2):
        raise errors.InvalidPrefixByteError()

    prefix = b2
    result = raw[2 : (len(raw))]
    return (prefix, result)


def decode_public_key(
    public_key: t.Union[str, bytes, bytearray]
) -> t.Tuple[int, bytes]:
    """Decode a public key into prefix and public bytes."""
    public_key = _encode(public_key)
    # Add missing padding if required.
    padding = bytearray()
    padding += b"=" * (-len(public_key) % 8)

    try:
        base32_decoded = base64.b32decode(public_key + padding)
        raw = base32_decoded[: (len(base32_decoded) - 2)]
    except binascii.Error:
        raise errors.InvalidPublicKeyError()

    if len(raw) < 32:
        raise errors.InvalidPublicKeyError()

    # 248 = 11111000
    b1 = raw[0] & 248

    if not valid_public_prefix_byte(b1):
        raise errors.InvalidPublicKeyError()

    result = raw[1 : (len(raw))]
    prefix = b1
    return (prefix, result)


def decode_private_key(
    private_key: t.Union[str, bytes, bytearray]
) -> t.Tuple[None, bytes]:
    """Decode a private key into a tuple (None, private_bytes).

    A tuple is returned to be consistent with decode_public_key and decode_seed which both
    return a tuple.
    """
    private_key = _encode(private_key)
    # Add missing padding if required.
    padding = bytearray()
    padding += b"=" * (-len(private_key) % 8)

    try:
        base32_decoded = base64.b32decode(private_key + padding)
        private_bytes = base32_decoded[: (len(base32_decoded) - 2)]
    except binascii.Error:
        raise errors.InvalidPublicKeyError()

    # Check key length
    if len(private_bytes) < 32:
        raise errors.InvalidPublicKeyError()

    # 248 = 11111000
    b1 = private_bytes[0] & 248

    # Check prefix
    if b1 != constants.PREFIX_BYTE_PRIVATE:
        raise errors.InvalidKeyError()

    result = private_bytes[1 : (len(private_bytes))]
    del private_bytes
    return None, result[:32]
