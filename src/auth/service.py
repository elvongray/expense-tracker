import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update

from src.auth.constants import (
    CODE_REQUEST_LIMIT_PER_HOUR,
    PASSWORD_RESET_CODE_EXP_MINUTES,
    VERIFICATION_CODE_EXP_MINUTES,
)
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
from src.auth.utils import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_numeric_code,
    hash_password,
    verify_password,
)
from src.core.config import settings
from src.core.exceptions import (
    ConflictError,
    ForbiddenError,
    InvalidRequestError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
)
from src.db.dependencies import DbSession
from src.user.models import EmailVerificationCode, PasswordResetCode, User

logger = logging.getLogger(__name__)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _normalize_username(username: str) -> str:
    return username.strip().lower()


async def _get_user_by_email(session: DbSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def _get_user_by_username(session: DbSession, username: str) -> User | None:
    result = await session.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def _rate_limit_exceeded(session: DbSession, model, user_id) -> bool:
    window_start = datetime.now(timezone.utc) - timedelta(hours=1)
    result = await session.execute(
        select(func.count())
        .select_from(model)
        .where(model.user_id == user_id, model.created_at >= window_start)
    )
    return (result.scalar_one() or 0) >= CODE_REQUEST_LIMIT_PER_HOUR


async def signup_user(data: SignupRequest, session: DbSession) -> MessageResponse:
    email = _normalize_email(data.email)
    username = _normalize_username(data.username)

    existing_email = await _get_user_by_email(session, email)
    existing_username = await _get_user_by_username(session, username)
    if existing_email or existing_username:
        raise ConflictError("Email or username already registered")

    try:
        password_hash = hash_password(data.password)
    except ValueError as exc:
        raise InvalidRequestError(str(exc)) from exc

    logger.info("Signup initiated", extra={"email": email, "username": username})
    user = User(
        email=email,
        username=username,
        password_hash=password_hash,
        is_email_verified=False,
        token_version=0,
        is_deleted=False,
    )
    session.add(user)
    await session.flush()

    await _create_verification_code(session, user)

    return MessageResponse(message="Account created. Verification code sent.")


async def _create_verification_code(session: DbSession, user: User) -> None:
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=VERIFICATION_CODE_EXP_MINUTES
    )

    await session.execute(
        update(EmailVerificationCode)
        .where(
            EmailVerificationCode.user_id == user.id,
            EmailVerificationCode.consumed_at.is_(None),
        )
        .values(consumed_at=datetime.now(timezone.utc))
    )

    code = generate_numeric_code()
    verification = EmailVerificationCode(
        user_id=user.id,
        code=code,
        expires_at=expires_at,
        consumed_at=None,
    )
    session.add(verification)
    logger.info("Verification code issued", extra={"user_id": str(user.id)})


async def verify_email(data: VerifyEmailRequest, session: DbSession) -> MessageResponse:
    email = _normalize_email(data.email)
    user = await _get_user_by_email(session, email)
    if not user or user.is_deleted:
        raise NotFoundError("User not found")

    if user.is_email_verified:
        return MessageResponse(message="Email verified.")

    now = datetime.now(timezone.utc)
    result = await session.execute(
        select(EmailVerificationCode)
        .where(
            EmailVerificationCode.user_id == user.id,
            EmailVerificationCode.code == data.code,
            EmailVerificationCode.consumed_at.is_(None),
            EmailVerificationCode.expires_at > now,
        )
        .order_by(EmailVerificationCode.created_at.desc())
        .limit(1)
    )
    record = result.scalar_one_or_none()
    if not record:
        raise InvalidRequestError("Invalid code")

    record.consumed_at = now
    user.is_email_verified = True
    logger.info("Email verified", extra={"user_id": str(user.id)})
    await session.flush()
    return MessageResponse(message="Email verified.")


async def resend_verification_code(
    data: ResendVerificationCodeRequest, session: DbSession
) -> MessageResponse:
    email = _normalize_email(data.email)
    user = await _get_user_by_email(session, email)
    if not user:
        return MessageResponse(message="Verification code sent.")

    if user.is_deleted:
        return MessageResponse(message="Verification code sent.")

    if user.is_email_verified:
        return MessageResponse(message="Verification code sent.")

    if await _rate_limit_exceeded(session, EmailVerificationCode, user.id):
        logger.warning(
            "Verification code rate limit hit", extra={"user_id": str(user.id)}
        )
        raise RateLimitError()

    await _create_verification_code(session, user)

    return MessageResponse(message="Verification code sent.")


async def login_user(data: LoginRequest, session: DbSession) -> Token:
    email = _normalize_email(data.email)
    user = await _get_user_by_email(session, email)
    if not user or user.is_deleted:
        raise UnauthorizedError("Invalid credentials")

    if not user.is_email_verified:
        raise ForbiddenError("Email not verified")

    try:
        password_ok = verify_password(data.password, user.password_hash)
    except ValueError as exc:
        raise InvalidRequestError(str(exc)) from exc

    if not password_ok:
        raise UnauthorizedError("Invalid credentials")

    payload = {
        "sub": str(user.id),
        "email": user.email,
        "token_version": user.token_version,
    }
    access_token = create_access_token({**payload, "type": "access"})
    refresh_token = create_refresh_token({**payload, "type": "refresh"})
    logger.info("User logged in", extra={"user_id": str(user.id)})

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=60 * settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )


async def refresh_access_token(data: RefreshRequest, session: DbSession) -> AccessToken:
    try:
        payload = decode_token(data.refresh_token)
    except ValueError as exc:
        raise UnauthorizedError("Invalid token") from exc

    if payload.get("type") != "refresh":
        raise UnauthorizedError("Invalid token type")

    user_id = payload.get("sub")
    if not user_id:
        raise UnauthorizedError("Invalid token")

    try:
        user_uuid = uuid.UUID(str(user_id))
    except ValueError as exc:
        raise UnauthorizedError("Invalid token") from exc

    result = await session.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if not user or user.is_deleted:
        raise UnauthorizedError("Unauthorized")

    if payload.get("token_version") != user.token_version:
        raise UnauthorizedError("Token revoked")

    access_token = create_access_token(
        {
            "sub": str(user.id),
            "email": user.email,
            "token_version": user.token_version,
            "type": "access",
        }
    )
    logger.info("Access token refreshed", extra={"user_id": str(user.id)})
    return AccessToken(
        access_token=access_token,
        expires_in=60 * settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )


async def request_password_reset(
    data: RequestPasswordResetRequest, session: DbSession
) -> MessageResponse:
    email = _normalize_email(data.email)
    user = await _get_user_by_email(session, email)
    if not user or user.is_deleted:
        return MessageResponse(message="If the email exists, a reset code was sent.")

    if await _rate_limit_exceeded(session, PasswordResetCode, user.id):
        logger.warning("Password reset rate limit hit", extra={"user_id": str(user.id)})
        raise RateLimitError()

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=PASSWORD_RESET_CODE_EXP_MINUTES
    )
    code = generate_numeric_code()
    reset_code = PasswordResetCode(
        user_id=user.id,
        code=code,
        expires_at=expires_at,
        consumed_at=None,
    )
    session.add(reset_code)
    logger.info("Password reset code issued", extra={"user_id": str(user.id)})

    return MessageResponse(message="If the email exists, a reset code was sent.")


async def reset_password(
    data: ResetPasswordRequest, session: DbSession
) -> MessageResponse:
    email = _normalize_email(data.email)
    user = await _get_user_by_email(session, email)
    if not user or user.is_deleted:
        raise InvalidRequestError("Invalid code")

    now = datetime.now(timezone.utc)
    result = await session.execute(
        select(PasswordResetCode)
        .where(
            PasswordResetCode.user_id == user.id,
            PasswordResetCode.code == data.code,
            PasswordResetCode.consumed_at.is_(None),
            PasswordResetCode.expires_at > now,
        )
        .order_by(PasswordResetCode.created_at.desc())
        .limit(1)
    )
    record = result.scalar_one_or_none()
    if not record:
        raise InvalidRequestError("Invalid code")

    record.consumed_at = now
    try:
        user.password_hash = hash_password(data.new_password)
        await session.flush()
    except ValueError as exc:
        raise InvalidRequestError(str(exc)) from exc
    logger.info("Password reset completed", extra={"user_id": str(user.id)})

    return MessageResponse(message="Password has been reset.")


async def change_password(
    data: ChangePasswordRequest, session: DbSession, user: User
) -> MessageResponse:
    if not verify_password(data.current_password, user.password_hash):
        raise UnauthorizedError("Invalid credentials")

    try:
        user.password_hash = hash_password(data.new_password)
    except ValueError as exc:
        raise InvalidRequestError(str(exc)) from exc
    user.token_version += 1
    await session.flush()
    logger.info("Password changed", extra={"user_id": str(user.id)})

    return MessageResponse(message="Password changed.")
