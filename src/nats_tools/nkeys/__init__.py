from .api import (
    create_keypair,
    load_ed25519_private_key,
    load_ed25519_public_key,
    load_keypair_from_private_key,
    load_keypair_from_seed,
    sign,
    verify,
)
from .keypair import KeyPair

# To ensure compatibility with nats-py
from_keypair = load_keypair_from_seed


__all__ = [
    "KeyPair",
    "load_ed25519_private_key",
    "load_ed25519_public_key",
    "load_keypair_from_private_key",
    "load_keypair_from_seed",
    "create_keypair",
    "sign",
    "verify",
]
