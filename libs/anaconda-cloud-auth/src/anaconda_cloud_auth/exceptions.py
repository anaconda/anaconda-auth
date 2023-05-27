class AuthenticationError(Exception):
    pass


class InvalidTokenError(AuthenticationError):
    pass


class TokenNotFoundError(Exception):
    pass
