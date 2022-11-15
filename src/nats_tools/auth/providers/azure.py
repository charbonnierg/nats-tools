from .protocol import CredsProvider


class AzureCredsProvider(CredsProvider):
    """Obtain JWT signed remotely by an NATS account using an HTTP client/

    Authentication is performed using Azure Credentials.
    In order to be authenticated:
        - Azure default credentials must authenticate and authorized user
        - User found wthin Azure ID token should have at least on associated identity.
    """
