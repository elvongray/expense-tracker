import pytest
from sqlalchemy import select

from src.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    RequestPasswordResetRequest,
    ResetPasswordRequest,
    SignupRequest,
    VerifyEmailRequest,
)
from src.auth.service import (
    change_password,
    login_user,
    refresh_access_token,
    request_password_reset,
    reset_password,
    signup_user,
    verify_email,
)
from src.core.exceptions import ConflictError, ForbiddenError, InvalidRequestError
from src.user.models import EmailVerificationCode, PasswordResetCode, User
from tests.auth.factories import (
    PasswordResetCodeFactory,
)
from tests.user.factories import UserFactory

pytestmark = pytest.mark.asyncio


async def test_signup_user_creates_user_and_code(async_db_session):
    data = SignupRequest(
        email="service@example.com", username="serviceuser", password="password123"
    )
    await signup_user(data, async_db_session)

    user = (
        await async_db_session.execute(select(User).where(User.email == data.email))
    ).scalar_one()
    codes = (
        (
            await async_db_session.execute(
                select(EmailVerificationCode).where(
                    EmailVerificationCode.user_id == user.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(codes) == 1
    assert codes[0].code


async def test_signup_user_duplicate_raises_conflict(async_db_session):
    user = UserFactory()
    async_db_session.add(user)
    await async_db_session.flush()

    with pytest.raises(ConflictError):
        await signup_user(
            SignupRequest(
                email=user.email,
                username="duplicateuser",
                password="password123",
            ),
            async_db_session,
        )


async def test_login_user_requires_verified(async_db_session):
    user = UserFactory(is_email_verified=False, plain_password="password123")
    async_db_session.add(user)
    await async_db_session.flush()

    with pytest.raises(ForbiddenError):
        await login_user(
            LoginRequest(email=user.email, password="password123"),
            async_db_session,
        )


async def test_login_user_success(async_db_session):
    user = UserFactory(is_email_verified=True, plain_password="password123")
    async_db_session.add(user)
    await async_db_session.flush()

    token = await login_user(
        LoginRequest(email=user.email, password="password123"),
        async_db_session,
    )
    assert token.access_token
    assert token.refresh_token
    assert token.expires_in > 0


async def test_refresh_access_token(async_db_session):
    user = UserFactory(is_email_verified=True, plain_password="password123")
    async_db_session.add(user)
    await async_db_session.flush()

    token = await login_user(
        LoginRequest(email=user.email, password="password123"),
        async_db_session,
    )
    refreshed = await refresh_access_token(
        RefreshRequest(refresh_token=token.refresh_token),
        async_db_session,
    )
    assert refreshed.access_token
    assert refreshed.expires_in > 0


async def test_change_password_bumps_token_version(async_db_session):
    user = UserFactory(is_email_verified=True, plain_password="password123")
    async_db_session.add(user)
    await async_db_session.flush()

    await change_password(
        ChangePasswordRequest(
            current_password="password123", new_password="newpassword123"
        ),
        async_db_session,
        user,
    )

    await async_db_session.refresh(user)
    assert user.token_version == 1


async def test_request_password_reset_creates_code(async_db_session):
    user = UserFactory(is_email_verified=True)
    async_db_session.add(user)
    await async_db_session.flush()

    await request_password_reset(
        RequestPasswordResetRequest(email=user.email),
        async_db_session,
    )

    codes = (
        (
            await async_db_session.execute(
                select(PasswordResetCode).where(PasswordResetCode.user_id == user.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(codes) == 1
    assert codes[0].code


async def test_reset_password_consumes_code(async_db_session):
    user = UserFactory(is_email_verified=True, token_version=2)
    async_db_session.add(user)
    await async_db_session.flush()

    code = PasswordResetCodeFactory(user=user, raw_code="654321")
    async_db_session.add(code)
    await async_db_session.flush()

    await reset_password(
        ResetPasswordRequest(
            email=user.email, code="654321", new_password="brandnew123"
        ),
        async_db_session,
    )

    await async_db_session.refresh(user)
    await async_db_session.refresh(code)
    assert code.consumed_at is not None
    assert user.token_version == 2


async def test_verify_email_invalid_code_raises(async_db_session):
    user = UserFactory(is_email_verified=False)
    async_db_session.add(user)
    await async_db_session.flush()

    with pytest.raises(InvalidRequestError):
        await verify_email(
            VerifyEmailRequest(email=user.email, code="000000"),
            async_db_session,
        )
