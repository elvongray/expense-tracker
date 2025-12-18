import uuid

from sqlalchemy import Boolean, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func, text

from core.uuid import uuid7
from db.base import SchemaBase


class Category(SchemaBase):
    __tablename__ = "categories"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid7
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), index=True, nullable=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    color: Mapped[str | None] = mapped_column(String(20))
    is_deleted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    owner = relationship("User", back_populates="categories")
    expenses = relationship("Expense", back_populates="category")

    __table_args__ = (
        Index(
            "uq_categories_owner_name_active",
            "owner_user_id",
            func.lower(text("name")),
            unique=True,
            postgresql_where=text("owner_user_id is not null and is_deleted = false"),
        ),
    )
