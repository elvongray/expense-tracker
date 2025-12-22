import logging

from fastapi import APIRouter

from src.auth.dependencies import CurrentUser
from src.auth.schemas import (
    AccessToken,
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshRequest,
    RequestPasswordResetRequest,
    ResendVerificationCodeRequest,
    ResetPasswordRequest,
    SignupRequest,
    Token,
    VerifyEmailRequest,
)
from src.auth.service import (
    change_password,
    login_user,
    refresh_access_token,
    request_password_reset,
    resend_verification_code,
    reset_password,
    signup_user,
    verify_email,
)
from src.db.dependencies import DbSession

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/signup", response_model=MessageResponse)
async def signup(data: SignupRequest, session: DbSession):
    logger.info("POST /auth/signup", extra={"email": data.email})
    return await signup_user(data, session)


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email_code(data: VerifyEmailRequest, session: DbSession):
    logger.info("POST /auth/verify-email", extra={"email": data.email})
    return await verify_email(data, session)


@router.post("/resend-verification-code", response_model=MessageResponse)
async def resend_code(data: ResendVerificationCodeRequest, session: DbSession):
    logger.info("POST /auth/resend-verification-code", extra={"email": data.email})
    return await resend_verification_code(data, session)


@router.post("/login", response_model=Token)
async def login(data: LoginRequest, session: DbSession):
    logger.info("POST /auth/login", extra={"email": data.email})
    return await login_user(data, session)


@router.post("/refresh", response_model=AccessToken)
async def refresh(data: RefreshRequest, session: DbSession):
    logger.info("POST /auth/refresh")
    return await refresh_access_token(data, session)


@router.post("/request-password-reset", response_model=MessageResponse)
async def request_reset(data: RequestPasswordResetRequest, session: DbSession):
    logger.info("POST /auth/request-password-reset", extra={"email": data.email})
    return await request_password_reset(data, session)


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password_code(data: ResetPasswordRequest, session: DbSession):
    logger.info("POST /auth/reset-password", extra={"email": data.email})
    return await reset_password(data, session)


@router.post("/change-password", response_model=MessageResponse)
async def change_password_endpoint(
    data: ChangePasswordRequest,
    session: DbSession,
    user: CurrentUser,
):
    logger.info("POST /auth/change-password", extra={"user_id": str(user.id)})
    return await change_password(data, session, user)
