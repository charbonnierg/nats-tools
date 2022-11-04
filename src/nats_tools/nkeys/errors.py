class NkeysError(Exception):
    pass


class InvalidSeedError(NkeysError):
    def __str__(self) -> str:
        return "nkeys: invalid seed"


class InvalidPrefixByteError(NkeysError):
    def __str__(self) -> str:
        return "nkeys: invalid prefix byte"


class InvalidKeyError(NkeysError):
    def __str__(self) -> str:
        return "nkeys: invalid key"


class InvalidPublicKeyError(NkeysError):
    def __str__(self) -> str:
        return "nkeys: invalid public key"


class InvalidSeedLengthError(NkeysError):
    def __str__(self) -> str:
        return "nkeys: invalid seed length"


class InvalidEncodingError(NkeysError):
    def __str__(self) -> str:
        return "nkeys: invalid encoded key"


class InvalidSignatureError(NkeysError):
    def __str__(self) -> str:
        return "nkeys: signature verification failed"


class CannotSignError(NkeysError):
    def __str__(self) -> str:
        return "nkeys: can not sign, no private key available"


class PublicKeyOnlyError(CannotSignError):
    def __str__(self) -> str:
        return "nkeys: no seed or private key available"
