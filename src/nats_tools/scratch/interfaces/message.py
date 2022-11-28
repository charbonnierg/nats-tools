import typing as t
from dataclasses import dataclass

from ..protocol.headers import Headers
from ..protocol.messages import HMSG, MSG


@dataclass
class Msg:
    """
    Msg represents a message delivered by NATS.
    """

    subject: str
    reply: t.Optional[str] = None
    data: t.Optional[bytes] = None
    headers: t.Optional[Headers] = None

    @classmethod
    def from_msg(cls, msg: MSG) -> "Msg":
        return cls(subject=msg.subject, reply=msg.reply, data=msg.payload, headers=None)

    @classmethod
    def from_hsmsg(cls, hmsg: HMSG) -> "Msg":
        return cls(
            subject=hmsg.subject,
            reply=hmsg.reply,
            data=hmsg.payload,
            headers=hmsg.headers,
        )
