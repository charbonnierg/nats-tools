from .protocol import CredsProvider


class NebulaCredsProvider(CredsProvider):
    """Obtain JWT signed remotely by an NATS account using an HTTP client.

    Authentication is performed using a Nebula certificate.
    In order to be authenticated:
        - Nebula certificate must be valid (not expired, valid signature, ...)
        - Client must send an authenticated token
        - User found within Nebula certificate should have at least one associated identity.

    NKEY seed is returned encrypted using ED25519 algorithm, based on a derived key using HKDF + some AAD.
    I'm not sure how it is secured, we should investigate. But it would be really handy for servers !
    """

    def __init__(self, nebula_cert: str, nebula_key: str) -> None:
        self.nebula_cert = nebula_cert
        self.nebula_key = nebula_key
