import typing as t

import jwt
import jwt.algorithms
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import errors
from .api import load_ed25519_key

ED25519Nkey = "ed25519-nkey"


class ED25519NkeyAlgorithm(jwt.algorithms.Algorithm):
    def prepare_key(
        self, key: str
    ) -> t.Union[ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey]:
        """Expect either an encoded public key, an encoded private key, or an encoded seed."""
        return load_ed25519_key(key)

    def sign(
        self,
        msg: bytes,
        key: t.Union[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    ) -> bytes:
        """Expect either an encoded private key, or an encoded seed."""
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key.sign(msg)
        elif isinstance(key, ed25519.Ed25519PublicKey):
            raise errors.PublicKeyOnlyError()
        else:
            raise errors.CannotSignError()

    def verify(
        self,
        msg: bytes,
        key: t.Union[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
        sig: bytes,
    ) -> bool:
        """Expect either an encoded public key, an encoded private key, or an encoded seed."""
        if isinstance(key, ed25519.Ed25519PrivateKey):
            key = key.public_key()
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, msg)
            return True
        else:
            raise errors.InvalidPublicKeyError()


def register_ed25519_nkeys_algorithm() -> None:
    if ED25519Nkey in jwt.api_jws._jws_global_obj._algorithms:
        jwt.unregister_algorithm(ED25519Nkey)
    jwt.register_algorithm(ED25519Nkey, ED25519NkeyAlgorithm())


register_ed25519_nkeys_algorithm()
