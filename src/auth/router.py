from auth.dependencies import CurrentUser
from auth.schemas import (
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
from auth.service import (
    change_password,
    login_user,
    refresh_access_token,
    request_password_reset,
    resend_verification_code,
    reset_password,
    signup_user,
    verify_email,
)
from db.dependencies import DbSession
from fastapi import APIRouter

router = APIRouter()


@router.post("/signup", response_model=MessageResponse)
async def signup(data: SignupRequest, session: DbSession):
    return await signup_user(data, session)


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email_code(data: VerifyEmailRequest, session: DbSession):
    return await verify_email(data, session)


@router.post("/resend-verification-code", response_model=MessageResponse)
async def resend_code(data: ResendVerificationCodeRequest, session: DbSession):
    return await resend_verification_code(data, session)


@router.post("/login", response_model=Token)
async def login(data: LoginRequest, session: DbSession):
    return await login_user(data, session)


@router.post("/refresh", response_model=AccessToken)
async def refresh(data: RefreshRequest, session: DbSession):
    return await refresh_access_token(data, session)


@router.post("/request-password-reset", response_model=MessageResponse)
async def request_reset(data: RequestPasswordResetRequest, session: DbSession):
    return await request_password_reset(data, session)


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password_code(data: ResetPasswordRequest, session: DbSession):
    return await reset_password(data, session)


@router.post("/change-password", response_model=MessageResponse)
async def change_password_endpoint(
    data: ChangePasswordRequest,
    session: DbSession,
    user: CurrentUser,
):
    return await change_password(data, session, user)
