import secrets
import typing as t

import cryptography.exceptions
import typing_extensions as t_
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import constants, encoding, errors


class KeyPair:
    def __init__(self, prefix: int, signing_key: ed25519.Ed25519PrivateKey):
        """
        NKEYS KeyPair used to sign and verify data.

        Arguments:
            prefix: The public prefix of the nkey.
            private_bytes: The private bytes of the nkey.

        Returns:
            A KeyPair that can be used to sign and verify data.
        """
        self.prefix = prefix
        self.signing_key = signing_key

    @property
    def public_key(self) -> bytes:
        """
        Return the NATS encoded public key associated with the KeyPair.

        Returns:
            public key associated with the key pair
        """
        public_bytes = encoding.encode_ed25519_public_key(self.signing_key.public_key())
        public_key = encoding.encode_public_key(self.prefix, public_bytes)
        return public_key

    @property
    def private_key(self) -> bytes:
        """
        Return the NATS encoded private key associated with the KeyPair.

        Returns:
            private key associated with the key pair
        """
        private_bytes = encoding.encode_ed25519_private_key(self.signing_key)
        public_bytes = encoding.encode_ed25519_public_key(self.signing_key.public_key())
        return encoding.encode_private_key(
            private_bytes=private_bytes, public_bytes=public_bytes
        )

    @property
    def seed(self) -> bytes:
        """Return the NATS encoded seed associated with the KeyPair"""
        private_bytes = encoding.encode_ed25519_private_key(self.signing_key)
        return encoding.encode_seed(prefix=self.prefix, private_bytes=private_bytes)

    def sign(self, data: bytes) -> bytes:
        """Sign some data using Ed25519PrivateKey

        Arguments:
            data: The payload in bytes to sign.

        Returns:
            The raw bytes representing the signed data.
        """
        return self.signing_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> t_.Literal[True]:
        """Verify some data and signature using Ed25519PublicKey

        Arguments:
            data: The payload in bytes that was signed.
            sig: The signature in bytes that will be verified.

        Returns:
            boolean expressing that the signature is valid.
        """
        kp = self.signing_key.public_key()

        try:
            kp.verify(signature, data)
            return True
        except cryptography.exceptions.InvalidSignature:
            raise errors.InvalidSignatureError()

    @classmethod
    def from_seed(cls, seed: t.Union[str, bytes, bytearray]) -> "KeyPair":
        """Load a keypair from encoded seed."""
        # Extract private bytes
        public_prefix, private_bytes = encoding.decode_seed(seed)
        signing_key = encoding.decode_ed25519_private_key(private_bytes)
        return cls(prefix=public_prefix, signing_key=signing_key)

    @classmethod
    def from_private_bytes(
        cls, prefix: int, private_bytes: t.Union[str, bytes, bytearray]
    ) -> "KeyPair":
        """Create a new keypair from private bytes (either seed or private key). Prefix must be provided as argument."""
        # Load signing key
        signing_key = encoding.decode_ed25519_private_key(private_bytes)
        # Generate keypair, wipe private bytes and return keypair
        return cls(prefix=prefix, signing_key=signing_key)

    @classmethod
    def create(cls, prefix: t_.Literal["user", "account", "operator"]) -> "KeyPair":
        """Create an NATS nkeys keypair. Keypairs must be issued for a specific access type, one of:
        - user
        - account
        - operator

        Arguments:
            prefix: access type

        Returns:
            A KeyPair instance.
        """
        if prefix == "user":
            public_prefix = constants.PREFIX_BYTE_USER
        elif prefix == "account":
            public_prefix = constants.PREFIX_BYTE_ACCOUNT
        elif prefix == "operator":
            public_prefix = constants.PREFIX_BYTE_OPERATOR
        else:
            raise TypeError(
                f"Invalid prefix: {prefix}. Allowed values: 'operator', 'account', 'user'"
            )
        return cls.from_private_bytes(public_prefix, secrets.token_bytes(32))
