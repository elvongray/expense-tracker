import uuid
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from src.auth.utils import decode_token
from src.core.exceptions import InvalidToken, UnauthorizedError
from src.db.dependencies import DbSession
from src.user.models import User

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: DbSession,
) -> User:
    if credentials is None or not credentials.credentials:
        raise UnauthorizedError("Missing authentication token")

    try:
        payload = decode_token(credentials.credentials)
    except ValueError as exc:
        raise InvalidToken() from exc

    if payload.get("type") != "access":
        raise InvalidToken("Invalid access token")

    user_id = payload.get("sub")
    if not user_id:
        raise InvalidToken("Invalid token payload")

    try:
        user_uuid = uuid.UUID(str(user_id))
    except ValueError as exc:
        raise InvalidToken("Invalid token subject") from exc

    result = await session.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if not user or user.is_deleted:
        raise UnauthorizedError("Unauthorized")

    if payload.get("token_version") != user.token_version:
        raise InvalidToken("Token has been revoked")

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
