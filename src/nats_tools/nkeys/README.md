# NATS NKEYS

> NATS NKEYS library.

This module can be considered feature-complete. It should not evolve much in the future.

## Features

- [x] Create new keypair
- [x] Load keypair from seed
- [x] Sign and verify data using keypair
- [x] Verify signed data using public key


## Usage

1. Create a keypair:

```python
from nats_tools import nkeys

operator_kp = nkeys.create_keypair("operator")
account_kp = nkeys.create_keypair("operator")
user_kp = nkeys.create_keypair("user")
```

2. Load a keypair from a seed:

```python
from nats_tools import nkeys

# Accept string
kp = nkeys.from_seed("SOAMJ4USJU7UYAGOET2H4MTOLYI3LNBBTLW77B64PM2KRVQ6OWERN2R5HU6T2PJ5")

# Accept bytes
kp = nkeys.from_seed(b"SOAMJ4USJU7UYAGOET2H4MTOLYI3LNBBTLW77B64PM2KRVQ6OWERN2R5HU6T2PJ5")
```
