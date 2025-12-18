from fastapi import APIRouter

from .schemas import LoginRequest, Token
from .service import login_user

router = APIRouter()


@router.post("/login", response_model=Token)
async def login(data: LoginRequest):
    return await login_user(data)
