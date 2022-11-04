# NATS Tools

> Tools to work with NATS server from Python.

## `NATSD`

Use this class to easily start/stop NATS servers:

```python
from nats_tools import NATSD


# Create a new nats-server daemon
natsd = NATSD(debug=True)

# Start the server
natsd.start()

# Stop the server
natsd.stop()
```

- Can be used as a context manager:

```python
with NATSD(debug=True) as natsd:
    print(natsd.proc.pid)
```

- Can be used to interact with monitoring API:

```python
with NATSD(debug=True) as natsd:
    # Show /varz endpoint
    print(natsd.monitor.varz())
    # Show /jsz endpoint
    print(natsd.monitor.jsz())
    # Show /connz endpoint
    print(natsd.monitor.connz())
```


## Templates

Use this module to generate NATS servers configuration files:

```python
from nats_tools.templates import ConfigGenerator


generator = ConfigGenerator()

config = generator.render(address="0.0.0.0", port=4223)
```

## Nkeys

Use this module to generate nkeys, or verify / sign payloads using nkeys.

```python
from nats_tools.nkeys import create_keypair

# Create a keypair for an operator
kp = create_keypair("operator")
# kp = create_keypair("account")
# kp = create_keypair("user")

# Sign some data
signed = kp.sign(b"hello")

# Verify some data with some signature
kp.verify(b"hello", sig=signed)
```

It's also possible to import nkeys from seeds:

```python
from nats_tools.nkeys import load_keypair_from_seed


kp = load_keypair_from_seed(b"SOAMJ4USJU7UYAGOET2H4MTOLYI3LNBBTLW77B64PM2KRVQ6OWERN2R5HU6T2PJ5")
```


## JWTs

> `nats_tools.auth` provides an object-oriented API to manage operators and accounts. It can also be used to generate JWTs.

Use this module to generate NATS JWTs for operators, accounts and users.

```python
from nats_tools.nkeys import create_keypair
from nats_tools import jwts

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJLTzdSVUtXWlBYU0c3QVQ2RkpYN09CS1E2QTJNQk1UWjNRQ1ZYWlA0TFRSQkRJWExOV0xRIiwiaWF0IjoxNjY2NDUzODI2LCJpc3MiOiJBQkhLNktQRjZVTE80MlIzUlMyWkJCT01WTUFGUEtXUkFSTEJQNklYSkVaQ01JTE9DNUc0R1FKViIsIm5hbWUiOiJkZW1vLXVzZXIiLCJzdWIiOiJVQ1RYSk5TVTdWMlo3UllFTkRQWTM3UldKRk9ZM0xHT0czWVlQUU1RQzNWRzdYWERVT1BCNEtUWCIsIm5hdHMiOnsicHViIjp7fSwic3ViIjp7fSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwiaXNzdWVyX2FjY291bnQiOiJBRFdMVUVZM1dJU1NDVldCTVdRN0czNFNONUtKQ0tKRzNEMzZaSUJWN1FRMlI1VllHQlg1NDRPQSIsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.QcO4rEteWYbIiWoqmDnMbdZiQ6X7lkdB2pwt8XtPmBYhg7RLwpin-5wXv1BZLhhb6DTaplTPLfpyf3m1S0AlCQ"

# Decode raw jwt
generic_jwt = jwts.decode(token)

# Decode a specific jwt type
user_jwt = jwts.decode_user(token)

# Encode an operator JWT
operator_kp = create_keypair("operator")
operator_jwt = jwts.encode_operator(
    name="test",
    operator_seed=operator_kp.seed,
)

# Decode operator jwt
operator_claims = jwts.decode_operator(operator_jwt)

# Encode an account JWT
account_kp = create_keypair("account")
account_jwt = jwts.encode_account(
    name="demo",
    account_public_key=account_kp.public_key,operator_seed=operator_kp.seed,
)

# Verify the account JWT
account_claims = jwts.decode_account(
    account_jwt,
    operator_public_key=operator_kp.public_key,
)
```

## Auth

Manage NATS operators and accounts.

```python
from nats_tools.auth import Operator, Account
from nats_tools.nkeys import create_keypair


keypair, op = Operator.create(name="test")

account_kp = create_keypair("account")

account_jwt = op.sign_account("demo", account_public_key=account_kp.public_key)
```
