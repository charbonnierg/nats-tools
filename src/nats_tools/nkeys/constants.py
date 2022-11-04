# PREFIX_BYTE_SEED is the version byte used for encoded NATS Seeds
PREFIX_BYTE_SEED = 18 << 3  # Base32-encodes to 'S...'

# PREFIX_BYTE_PRIVATE is the version byte used for encoded NATS Private keys
PREFIX_BYTE_PRIVATE = 15 << 3  # Base32-encodes to 'P...'

# PREFIX_BYTE_SERVER is the version byte used for encoded NATS Servers
PREFIX_BYTE_SERVER = 13 << 3  # Base32-encodes to 'N...'

# PREFIX_BYTE_CLUSTER is the version byte used for encoded NATS Clusters
PREFIX_BYTE_CLUSTER = 2 << 3  # Base32-encodes to 'C...'

# PREFIX_BYTE_OPERATOR is the version byte used for encoded NATS Operators
PREFIX_BYTE_OPERATOR = 14 << 3  # Base32-encodes to 'O...'

# PREFIX_BYTE_ACCOUNT is the version byte used for encoded NATS Accounts
PREFIX_BYTE_ACCOUNT = 0  # Base32-encodes to 'A...'

# PREFIX_BYTE_USER is the version byte used for encoded NATS Users
PREFIX_BYTE_USER = 20 << 3  # Base32-encodes to 'U...'
