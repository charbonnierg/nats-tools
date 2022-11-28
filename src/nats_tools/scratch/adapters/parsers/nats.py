"""
NATS network protocol parser.
"""
from typing import Iterator, Optional, Union

from ...interfaces.parser import Parser, State
from ...protocol.messages import DELSUB, ERR, HMSG, INFO, MSG, OK, PING, PONG


class NATSParser(Parser):
    """NATS Protocol parser.

    This class expose a `.parse` method which can be used to parse incoming bytes.
    """

    def __init__(self) -> None:
        self.reset()

    def __repr__(self) -> str:
        return f"NATSParser(state={self.state}, buffer_size={len(self.buffer)})"

    def reset(self) -> None:
        self.buffer = bytearray()
        self.state = State.AWAITING_CONTROL_LINE
        self.needed = 0
        self.header_needed = 0
        self.pending_msg: Optional[MSG] = None
        self.pending_hmsg: Optional[HMSG] = None

    def parse(
        self, data: bytes = b""
    ) -> Iterator[Union[DELSUB, INFO, OK, ERR, MSG, HMSG, PING, PONG]]:
        """
        Parses the wire protocol from NATS for the client
        and dispatches the subscription callbacks.
        """
        self.buffer.extend(data)
        while self.buffer:
            if self.state == State.AWAITING_CONTROL_LINE:
                # Try to parse message
                msg, msg_end = MSG.parse_msg_line(self.buffer)
                if msg:
                    del self.buffer[:msg_end]
                    self.state = State.AWAITING_MSG_PAYLOAD
                    self.pending_msg = msg
                    continue
                # Try to parse message with header
                hmsg, hmsg_end = HMSG.parse_msg_line(self.buffer)
                if hmsg:
                    del self.buffer[:hmsg_end]
                    self.state = State.AWAITING_HMSG_PAYLOAD
                    self.pending_hmsg = hmsg
                    continue
                # Try to parse OK message
                ok, ok_end = OK.parse(self.buffer)
                if ok:
                    del self.buffer[:ok_end]
                    yield ok
                    continue
                # Try to parse ERR message
                err, err_end = ERR.parse(self.buffer)
                if err:
                    del self.buffer[:err_end]
                    yield err
                    continue
                # Try to parse PING message
                ping, ping_end = PING.parse(self.buffer)
                if ping:
                    del self.buffer[:ping_end]
                    yield ping
                    continue
                # Try to parse PONG message
                pong, pong_end = PONG.parse(self.buffer)
                if pong:
                    del self.buffer[:pong_end]
                    yield pong
                    continue
                # Try to parse INFO message
                info, info_end = INFO.parse(self.buffer)
                if info:
                    del self.buffer[:info_end]
                    yield info
                    continue
                # Try to parse DELSUB message
                delsub, delsub_end = DELSUB.parse(self.buffer)
                if delsub:
                    del self.buffer[:delsub_end]
                    yield delsub
                    continue
                # Buffer does not hold enough data
                break
            elif self.state == State.AWAITING_HMSG_PAYLOAD:
                # Try to parse message (with headers) payload
                if self.pending_hmsg:
                    pending_hmsg = self.pending_hmsg
                    payload_end = self.pending_hmsg.parse_msg_payload(self.buffer)
                    if payload_end:
                        del self.buffer[:payload_end]
                        self.pending_hmsg = None
                        self.state = State.AWAITING_CONTROL_LINE
                        yield pending_hmsg
                        continue
                # Wait until we have enough bytes in buffer.
                break
            elif self.state == State.AWAITING_MSG_PAYLOAD:
                # Try to parse message (without headers) payload
                if self.pending_msg:
                    pending_msg = self.pending_msg
                    payload_end = self.pending_msg.parse_msg_payload(self.buffer)
                    if payload_end:
                        del self.buffer[:payload_end]
                        self.pending_msg = None
                        self.state = State.AWAITING_CONTROL_LINE
                        yield pending_msg
                        continue
                # Wait until we have enough bytes in buffer.
                break
            # Code should never reach here
            raise TypeError("Invalid parser state")
