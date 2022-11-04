import secrets
import typing as t

import cryptography.exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import constants, errors, parser


class KeyPair:
    def __init__(
        self,
        seed: bytes,
        keys: ed25519.Ed25519PrivateKey,
        public_key: t.Optional[bytes] = None,
        private_key: t.Optional[bytes] = None,
    ):
        """
        NKEYS KeyPair used to sign and verify data.

        Arguments:
            seed: The seed as a bytearray used to create the keypair.
            keys: The keypair that can be used for signing.
            public_key: The public key as a bytearray.
            private_key: The private key as a bytearray.

        Returns:
            A KeyPair that can be used to sign and verify data.
        """
        self._seed: t.Optional[bytes] = seed
        self._keys: t.Optional[ed25519.Ed25519PrivateKey] = keys
        self._public_key = public_key
        self._private_key = private_key

    @property
    def signing_key(self) -> ed25519.Ed25519PrivateKey:
        if self._keys is None:
            raise errors.CannotSignError()
        return self._keys

    def sign(self, input: bytes) -> bytes:
        """Sign some data.

        Arguments:
            The payload in bytes to sign.

        Returns:
            The raw bytes representing the signed data.
        """
        return self.signing_key.sign(input)

    def verify(self, input: bytes, sig: bytes) -> t.Literal[True]:
        """Verify some data and signature.

        Arguments:
            input: The payload in bytes that was signed.
            sig: The signature in bytes that will be verified.

        Returns:
            boolean expressing that the signature is valid.
        """
        kp = self.signing_key.public_key()

        try:
            kp.verify(sig, input)
            return True
        except cryptography.exceptions.InvalidSignature:
            raise errors.InvalidSignatureError()

    @property
    def public_key(self) -> bytes:
        """
        Return the encoded public key associated with the KeyPair.

        Returns:
            public key associated with the key pair
        """
        # If already generated then just return.
        if self._public_key is not None:
            return self._public_key
        # Get the public key from the seed to verify later.
        prefix, _ = parser.decode_seed(self.seed)
        public_bytes = self.signing_key.public_key().public_bytes(
            format=serialization.PublicFormat.Raw, encoding=serialization.Encoding.Raw
        )
        public_key = parser.encode_public_key(prefix, public_bytes)
        del public_bytes
        return public_key

    @property
    def private_key(self) -> bytes:
        """
        Return the encoded private key associated with the KeyPair.

        Returns:
            private key associated with the key pair
        """
        if self._private_key is not None:
            return self._private_key
        private_bytes = self.signing_key.private_bytes(
            format=serialization.PrivateFormat.Raw,
            encoding=serialization.Encoding.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = self.signing_key.public_key().public_bytes(
            format=serialization.PublicFormat.Raw, encoding=serialization.Encoding.Raw
        )
        private_key = parser.encode_private_key(
            private_bytes=private_bytes, public_bytes=public_bytes
        )
        del private_bytes
        del public_bytes
        return private_key

    @property
    def seed(self) -> bytes:
        if not hasattr(self, "_seed"):
            raise errors.InvalidSeedError()
        if self._seed is None:
            raise errors.InvalidSeedError()
        return self._seed

    def wipe(self) -> None:
        self._seed = None
        self._keys = None
        self._public_key = None
        self._private_key = None
        del self._seed
        del self._keys
        del self._public_key
        del self._private_key

    @classmethod
    def from_seed(cls, seed: t.Union[str, bytes, bytearray]) -> "KeyPair":
        """Load a keypair from encoded seed."""
        # Extract private bytes
        _, private_bytes = parser.decode_seed(seed)
        # Load private key
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes[:32])
        # Generate keypair, wipe private bytes and return keypair
        keypair = cls(seed=parser._encode(seed), keys=private_key)
        del private_bytes
        return keypair

    @classmethod
    def from_private_key(
        cls, prefix: int, private_key: t.Union[str, bytes, bytearray]
    ) -> "KeyPair":
        """Create a new keypair from encoded private key. Prefix must be provided as argument."""
        _, private_bytes = parser.decode_private_key(private_key)
        seed = parser.encode_seed(prefix, private_bytes=private_bytes)
        del private_bytes
        return cls.from_seed(seed)

    @classmethod
    def create(cls, prefix: t.Literal["user", "account", "operator"]) -> "KeyPair":
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
            raw_prefix = constants.PREFIX_BYTE_USER
        elif prefix == "account":
            raw_prefix = constants.PREFIX_BYTE_ACCOUNT
        elif prefix == "operator":
            raw_prefix = constants.PREFIX_BYTE_OPERATOR
        else:
            raise TypeError(
                f"Invalid prefix: {prefix}. Allowed values: 'operator', 'account', 'user'"
            )
        encoded_seed = parser.encode_seed(
            raw_prefix, private_bytes=secrets.token_bytes(32)
        )
        return cls.from_seed(encoded_seed)
