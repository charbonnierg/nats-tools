class NATSerror(Exception):
    pass


class NATSServerError(NATSerror):
    """An error received by NATS server"""

    MSG: str = ""
    DESCRIPTION: str = ""
    CRITICAL: bool = False

    def __init__(self, message: str) -> None:
        self.message = message

    def is_critical(self) -> bool:
        return self.CRITICAL


class CriticalNATSServerError(NATSServerError):
    """An error received by NATS server which lead to closing client connection"""

    CRITICAL = True


class UnknownProtocolError(CriticalNATSServerError):
    MSG = "Unknown Protocol Operation"
    DESCRIPTION = "Unknown protocol error"


class ConnectAttemptToRoutePortError(CriticalNATSServerError):
    MSG = "Attempted To Connect To Route Port"
    DESCRIPTION = (
        "Client attempted to connect to a route port instead of the client port"
    )


class AuthorizationViolationError(CriticalNATSServerError):
    MSG = "Authorization Violation"
    DESCRIPTION = "Client failed to authenticate to the server with credentials specified in the CONNECT message"


class AuthorizationTimeoutError(CriticalNATSServerError):
    MSG = "Authorization Timeout"
    DESCRIPTION = "Client took too long to authenticate to the server after establishing a connection (default 1 second)"


class InvalidClientProtocolError(CriticalNATSServerError):
    MSG = "Invalid Client Protocol"
    DESCRIPTION = "Client specified an invalid protocol version in the CONNECT message"


class MaximumControlLineExceededError(CriticalNATSServerError):
    MSG = "Maximum Control Line Exceeded"
    DESCRIPTION = " Message destination subject and reply subject length exceeded the maximum control line value specified by the max_control_line server option. The default is 1024 bytes."


class ParserError(CriticalNATSServerError):
    MSG = "Parser Error"
    DESCRIPTION = "Cannot parse the protocol message sent by the client"


class TLSRequiredError(CriticalNATSServerError):
    MSG = "Secure Connection - TLS Required"
    DESCRIPTION = "The server requires TLS and the client does not have TLS enabled"


class StaleConnectionError(CriticalNATSServerError):
    MSG = "Stale Connection"
    DESCRIPTION = "The server hasn't received a message from the client, including a PONG in too long."


class MaximumConnectionExceededError(CriticalNATSServerError):
    MSG = "Maximum Connections Exceeded"
    DESCRIPTION = "This error is sent by the server when creating a new connection and the server has exceeded the maximum number of connections specified by the max_connections server option. The default is 64k."


class SlowConsumerError(CriticalNATSServerError):
    MSG = "Slow Consumer"
    DESCRIPTION = "The server pending data size for the connection has reached the maximum size (default 10MB)."


class MaximumPayloadViolation(CriticalNATSServerError):
    MSG = "Maximum Payload Violation"
    DESCRIPTION = "Client attempted to publish a message with a payload size that exceeds the max_payload size configured on the server. This value is supplied to the client upon connection in the initial INFO message. The client is expected to do proper accounting of byte size to be sent to the server in order to handle this error synchronously."


# Non critical error


class ToleratedNATSServerError(NATSServerError):
    CRITICAL = False


class InvalidSubjectError(ToleratedNATSServerError):
    MSG = "Invalid Subject"
    DESCRIPTION = "Client sent a malformed subject (e.g. sub foo. 90)"


class PermissionViolationForSubjectError(ToleratedNATSServerError):
    MSG = "Permissions Violation for Subscription to"
    DESCRIPTION = "The user specified in the CONNECT message does not have permission to subscribe to the subject."

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.subject = message.split("for Subscription to")[-1].strip()


class PermissionViolationForSubscriptionError(ToleratedNATSServerError):
    MSG = "Permissions Violation for Publish to"
    DESCRIPTION = "The user specified in the CONNECT message does not have permissions to publish to the subject."

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.subject = message.split("for Publish to")[-1].strip()


# Unknown error


class UnknownNATSServerError(NATSServerError):
    MSG = ""
    DESCRIPTION = "Error not recognized by python client"


def parse_error_message(err: str) -> NATSServerError:
    """Parse a string into an NATS Server error"""
    # Check critical errors
    if UnknownProtocolError.MSG in err:
        return UnknownProtocolError(err)
    if ConnectAttemptToRoutePortError.MSG in err:
        return ConnectAttemptToRoutePortError(err)
    if AuthorizationViolationError.MSG in err:
        return AuthorizationViolationError(err)
    if AuthorizationTimeoutError.MSG in err:
        return AuthorizationTimeoutError(err)
    if InvalidClientProtocolError.MSG in err:
        return InvalidClientProtocolError(err)
    if MaximumControlLineExceededError.MSG in err:
        return MaximumControlLineExceededError(err)
    if ParserError.MSG in err:
        return ParserError(err)
    if TLSRequiredError.MSG in err:
        return TLSRequiredError(err)
    if StaleConnectionError.MSG in err:
        return StaleConnectionError(err)
    if MaximumConnectionExceededError.MSG in err:
        return MaximumConnectionExceededError(err)
    if SlowConsumerError.MSG in err:
        return SlowConsumerError(err)
    if MaximumPayloadViolation.MSG in err:
        return MaximumPayloadViolation(err)
    # Check tolerated errors
    if InvalidSubjectError.MSG in err:
        return InvalidSubjectError(err)
    if PermissionViolationForSubjectError.MSG in err:
        return PermissionViolationForSubjectError(err)
    if PermissionViolationForSubscriptionError.MSG in err:
        return PermissionViolationForSubscriptionError(err)
    # Return a generic error
    return NATSServerError(err)
