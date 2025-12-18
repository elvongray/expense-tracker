import uuid
from datetime import date
from decimal import Decimal

from sqlalchemy import Boolean, Date, ForeignKey, Index, Numeric, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import text

from core.uuid import uuid7
from db.base import SchemaBase


class Expense(SchemaBase):
    __tablename__ = "expenses"
    __table_args__ = (
        Index("ix_expenses_user_deleted", "user_id", "is_deleted"),
        Index("ix_expenses_user_currency", "user_id", "currency"),
        Index("ix_expenses_user_category", "user_id", "category_id"),
        Index(
            "ix_expenses_user_date_desc",
            "user_id",
            text("expense_date DESC"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid7
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), index=True, nullable=False
    )
    category_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("categories.id"), index=True, nullable=False
    )
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    expense_date: Mapped[date] = mapped_column(Date, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    is_deleted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    user = relationship("User", back_populates="expenses")
    category = relationship("Category", back_populates="expenses")
