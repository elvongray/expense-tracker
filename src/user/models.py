import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func, text

from src.core.uuid import uuid7
from src.db.base import SchemaBase


class User(SchemaBase):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_email_lower", func.lower("email"), unique=True),
        Index("ix_users_username_lower", func.lower("username"), unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid7
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    username: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_email_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    token_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    is_deleted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    verification_codes = relationship("EmailVerificationCode", back_populates="user")
    reset_codes = relationship("PasswordResetCode", back_populates="user")
    categories = relationship("Category", back_populates="owner")
    expenses = relationship("Expense", back_populates="user")


class EmailVerificationCode(SchemaBase):
    __tablename__ = "email_verification_codes"
    __table_args__ = (
        Index(
            "ix_email_verification_codes_user_expires",
            "user_id",
            "expires_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid7
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), index=True, nullable=False
    )
    code: Mapped[str] = mapped_column(String(20), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False
    )
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))

    user = relationship("User", back_populates="verification_codes")


class PasswordResetCode(SchemaBase):
    __tablename__ = "password_reset_codes"
    __table_args__ = (
        Index(
            "ix_password_reset_codes_user_expires",
            "user_id",
            "expires_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid7
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), index=True, nullable=False
    )
    code: Mapped[str] = mapped_column(String(20), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False
    )
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))

    user = relationship("User", back_populates="reset_codes")
