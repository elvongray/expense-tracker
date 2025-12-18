from fastapi import HTTPException, status
from user.service import get_user_by_username

from src.auth.utils import create_access_token, verify_password

from .schemas import LoginRequest, Token


async def login_user(data: LoginRequest) -> Token:
    user = await get_user_by_username(data.username)
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    token = create_access_token({"sub": user.id})
    return Token(access_token=token)
