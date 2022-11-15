import jwt.exceptions


class InvalidTypeError(jwt.exceptions.InvalidTokenError):
    def __str__(self) -> str:
        return "jwt: invalid type"


class InvalidSubjectError(jwt.exceptions.InvalidTokenError):
    def __str__(self) -> str:
        return "jwt: invalid issuer"


class InvalidAccessTypeError(jwt.exceptions.InvalidTokenError):
    def __str__(self) -> str:
        return "jwt: invalid access type"


class InvalidScopeError(jwt.exceptions.InvalidTokenError):
    def __str__(self) -> str:
        return "jwt: invalid scope"
