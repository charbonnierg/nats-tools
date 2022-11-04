# NATS NKEYS

> NATS NKEYS library.

## Usage

1. Create a keypair:

```python
from nats_tools.nkeys import KeyPair, create_keypair

operator_kp = create_keypair("operator")
account_kp = create_keypair("operator")
user_kp = create_keypair("user")
```

2. Load a keypair from a seed:

```python
from nats_tools.keys import load_keypair_from_seed

# Accept string
kp = load_keypair_from_seed("SOAMJ4USJU7UYAGOET2H4MTOLYI3LNBBTLW77B64PM2KRVQ6OWERN2R5HU6T2PJ5")

# Accept bytes
kp = load_keypair_from_seed(b"SOAMJ4USJU7UYAGOET2H4MTOLYI3LNBBTLW77B64PM2KRVQ6OWERN2R5HU6T2PJ5")
```
