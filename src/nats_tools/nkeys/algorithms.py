import typing as t

import jwt
import jwt.algorithms
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import errors, encoding

ED25519Nkey = "ed25519-nkey"


def register_ed25519_nkeys_algorithm() -> None:
    """Register the ed25519-nkey algorithm.

    Once registered, algorithm can be used by `jwt.decode()` and `jwt.encode()` methods.
    """
    if ED25519Nkey in jwt.api_jws._jws_global_obj._algorithms:
        jwt.unregister_algorithm(ED25519Nkey)
    jwt.register_algorithm(ED25519Nkey, ED25519NkeyAlgorithm())


class ED25519NkeyAlgorithm(jwt.algorithms.Algorithm):
    """JWT algorithm implementation for ed25519-nkey algorithm.

    Allowed key formats are:
      - NATS seed or NATS private key when signing
      - NATS seed, NATS private key or NATS public key when verifying
    """

    def prepare_key(
        self, key: str
    ) -> t.Union[ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey]:
        """Expect either an encoded public key, an encoded private key, or an encoded seed."""
        values = encoding._to_bytes(key)
        # Private key
        if values[0] == 80:
            return encoding.decode_ed25519_private_key(values)
        # Seed
        elif values[0] == 83:
            return encoding.decode_ed25519_private_key(values)
        # Public key
        else:
            return encoding.decode_ed25519_public_key(values)

    def sign(
        self,
        msg: bytes,
        key: t.Union[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    ) -> bytes:
        """Expect either an encoded private key, or an encoded seed."""
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key.sign(msg)
        if isinstance(key, ed25519.Ed25519PublicKey):
            raise errors.PublicKeyOnlyError()
        raise errors.CannotSignError()

    def verify(
        self,
        msg: bytes,
        key: t.Union[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
        sig: bytes,
    ) -> bool:
        """Expect either an encoded public key, an encoded private key, or an encoded seed."""
        if isinstance(key, ed25519.Ed25519PrivateKey):
            key.public_key().verify(sig, msg)
            return True
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, msg)
            return True
        raise errors.InvalidPublicKeyError()


register_ed25519_nkeys_algorithm()
