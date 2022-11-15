from nats_tools.auth.providers.local import LocalCredsProvider
from nats_tools.client.client import NATSContext

ACCOUNT_ID = "AAOA7ZMK4ZMRJ7X2CSDKXERAZGEPC3AOHCT7R37THU365K24EXQECYZC"

provider = LocalCredsProvider("./investigations/multiple-accounts/charbonnierg.creds")

ctx = NATSContext(provider, account_id=ACCOUNT_ID, scope="user", debug=True)
