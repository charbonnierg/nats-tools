__all__ = [
    "_CRLF_",
    "_SPC_",
    "CRLF_SIZE",
    "CONNECT_OP",
    "HPUB_OP",
    "MSG_OP",
    "PING_OP",
    "PONG_OP",
    "PUB_OP",
    "SUB_OP",
    "UNSUB_OP",
]

_CRLF_ = "\r\n"
_SPC_ = " "
CRLF_SIZE = len(_CRLF_)

CONNECT_OP = "CONNECT"
HPUB_OP = "HPUB"
MSG_OP = "MSG"
PING_OP = "PING"
PONG_OP = "PONG"
PUB_OP = "PUB"
SUB_OP = "SUB"
UNSUB_OP = "UNSUB"

HEADERS_PREFIX = "NATS/1.0"
HEADERS_PREFIX_SIZE = len(HEADERS_PREFIX)

STATUS_MSG_LEN = 3
