from fastapi import status

default_exception_message = "Something went wrong. We're looking into it."


class ApplicationError(Exception):
    def __init__(
        self,
        msg="We could not process the request.",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        *args,
    ):
        self.msg = msg
        self.status_code = status_code
        super().__init__(msg, status_code, *args)


class NotFoundError(ApplicationError):
    def __init__(
        self,
        msg="Requested resource was not found.",
        status_code=status.HTTP_404_NOT_FOUND,
        *args,
    ):
        super().__init__(msg, status_code, *args)


class InvalidRequestError(ApplicationError):
    def __init__(
        self, msg="Invalid request.", status_code=status.HTTP_400_BAD_REQUEST, *args
    ):
        super().__init__(msg, status_code, *args)


class ConflictError(ApplicationError):
    def __init__(self, msg="Conflict.", status_code=status.HTTP_409_CONFLICT, *args):
        super().__init__(msg, status_code, *args)


class InvalidToken(ApplicationError):
    def __init__(
        self,
        msg: str = "Invalid authentication token",
        *args,
    ):
        super().__init__(msg, status.HTTP_401_UNAUTHORIZED, *args)


class ForbiddenError(ApplicationError):
    def __init__(self, msg: str = "Forbidden", *args):
        super().__init__(msg, status.HTTP_403_FORBIDDEN, *args)


class UnauthorizedError(ApplicationError):
    def __init__(self, msg: str = "Unauthorized", *args):
        super().__init__(msg, status.HTTP_401_UNAUTHORIZED, *args)


class RateLimitError(ApplicationError):
    def __init__(self, msg: str = "Too many requests", *args):
        super().__init__(msg, status.HTTP_429_TOO_MANY_REQUESTS, *args)
