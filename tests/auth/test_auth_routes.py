import pytest
from sqlalchemy import select

from src.auth.utils import verify_password
from src.user.models import EmailVerificationCode, PasswordResetCode, User
from tests.auth.factories import (
    EmailVerificationCodeFactory,
    PasswordResetCodeFactory,
)
from tests.user.factories import UserFactory


@pytest.mark.asyncio
async def test_signup_creates_user_and_verification_code(client, async_db_session):
    payload = {
        "email": "newuser@example.com",
        "username": "newuser",
        "password": "password123",
    }
    resp = await client.post("/auth/signup", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["message"] == "Account created. Verification code sent."

    user = (
        await async_db_session.execute(
            select(User).where(User.email == payload["email"])
        )
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


@pytest.mark.asyncio
async def test_verify_email_marks_verified(client, async_db_session):
    user = UserFactory(is_email_verified=False)
    async_db_session.add(user)
    await async_db_session.flush()

    code = EmailVerificationCodeFactory(user=user, raw_code="123456")
    async_db_session.add(code)
    await async_db_session.flush()

    resp = await client.post(
        "/auth/verify-email", json={"email": user.email, "code": "123456"}
    )
    assert resp.status_code == 200
    await async_db_session.refresh(user)
    await async_db_session.refresh(code)
    assert user.is_email_verified is True
    assert code.consumed_at is not None


@pytest.mark.asyncio
async def test_login_requires_verified_email(client, async_db_session):
    user = UserFactory(is_email_verified=False, plain_password="password123")
    async_db_session.add(user)
    await async_db_session.flush()

    resp = await client.post(
        "/auth/login", json={"email": user.email, "password": "password123"}
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Email not verified"


@pytest.mark.asyncio
async def test_login_success_returns_tokens(client, async_db_session):
    user = UserFactory(is_email_verified=True, plain_password="password123")
    async_db_session.add(user)
    await async_db_session.flush()

    resp = await client.post(
        "/auth/login", json={"email": user.email, "password": "password123"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_refresh_returns_new_access_token(client, async_db_session):
    user = UserFactory(is_email_verified=True, plain_password="password123")
    async_db_session.add(user)
    await async_db_session.flush()

    login = await client.post(
        "/auth/login", json={"email": user.email, "password": "password123"}
    )
    refresh_token = login.json()["refresh_token"]

    resp = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_change_password_increments_token_version(client, async_db_session):
    user = UserFactory(is_email_verified=True, plain_password="password123")
    async_db_session.add(user)
    await async_db_session.flush()

    login = await client.post(
        "/auth/login", json={"email": user.email, "password": "password123"}
    )
    access_token = login.json()["access_token"]

    resp = await client.post(
        "/auth/change-password",
        json={
            "current_password": "password123",
            "new_password": "newpassword123",
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 200
    await async_db_session.refresh(user)
    assert user.token_version == 1
    assert verify_password("newpassword123", user.password_hash)


@pytest.mark.asyncio
async def test_request_password_reset_creates_code(client, async_db_session):
    user = UserFactory(is_email_verified=True)
    async_db_session.add(user)
    await async_db_session.flush()

    resp = await client.post("/auth/request-password-reset", json={"email": user.email})
    assert resp.status_code == 200

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


@pytest.mark.asyncio
async def test_reset_password_updates_hash_without_bumping_token_version(
    client, async_db_session
):
    user = UserFactory(is_email_verified=True, token_version=2)
    async_db_session.add(user)
    await async_db_session.flush()

    code = PasswordResetCodeFactory(user=user, raw_code="654321")
    async_db_session.add(code)
    await async_db_session.flush()

    resp = await client.post(
        "/auth/reset-password",
        json={
            "email": user.email,
            "code": "654321",
            "new_password": "brandnew123",
        },
    )
    assert resp.status_code == 200

    await async_db_session.refresh(user)
    await async_db_session.refresh(code)
    assert verify_password("brandnew123", user.password_hash)
    assert user.token_version == 2
    assert code.consumed_at is not None
