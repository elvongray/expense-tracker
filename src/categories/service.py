from sqlalchemy import func, select

from src.categories.models import Category
from src.categories.schemas import (
    CategoryCreate,
    CategoryListResponse,
    CategoryOut,
    CategoryUpdate,
)
from src.core.exceptions import (
    ConflictError,
    ForbiddenError,
    InvalidRequestError,
    NotFoundError,
)
from src.db.dependencies import DbSession
from src.expenses.models import Expense
from src.user.models import User


def _normalize_name(name: str) -> str:
    return name.strip().lower()


async def list_categories(
    session: DbSession, user: User, include_deleted: bool = False
) -> CategoryListResponse:
    base_system = select(Category).where(Category.owner_user_id.is_(None))
    system_categories = (await session.execute(base_system)).scalars().all()

    custom_query = select(Category).where(Category.owner_user_id == user.id)
    if not include_deleted:
        custom_query = custom_query.where(Category.is_deleted.is_(False))

    custom_categories = (await session.execute(custom_query)).scalars().all()
    return CategoryListResponse(
        system=[CategoryOut.model_validate(cat) for cat in system_categories],
        custom=[CategoryOut.model_validate(cat) for cat in custom_categories],
    )


async def create_category(
    session: DbSession, user: User, data: CategoryCreate
) -> CategoryOut:
    name_norm = _normalize_name(data.name)
    existing = await session.execute(
        select(Category).where(
            Category.owner_user_id == user.id,
            func.lower(Category.name) == name_norm,
            Category.is_deleted.is_(False),
        )
    )
    if existing.scalar_one_or_none():
        raise ConflictError("Category name already exists")

    category = Category(
        owner_user_id=user.id,
        name=data.name,
        color=data.color,
        is_deleted=False,
    )
    session.add(category)
    await session.flush()
    return CategoryOut.model_validate(category)


async def _get_user_category(
    session: DbSession, user: User, category_id: str
) -> Category:
    result = await session.execute(
        select(Category).where(
            Category.id == category_id, Category.owner_user_id == user.id
        )
    )
    category = result.scalar_one_or_none()
    if not category:
        raise NotFoundError("Category not found")
    if category.is_deleted:
        raise NotFoundError("Category not found")
    return category


async def update_category(
    session: DbSession, user: User, category_id: str, data: CategoryUpdate
) -> CategoryOut:
    category = await _get_user_category(session, user, category_id)
    if category.owner_user_id is None:
        raise ForbiddenError("Cannot modify system category")

    if data.name:
        name_norm = _normalize_name(data.name)
        existing = await session.execute(
            select(Category).where(
                Category.owner_user_id == user.id,
                func.lower(Category.name) == name_norm,
                Category.is_deleted.is_(False),
                Category.id != category.id,
            )
        )
        if existing.scalar_one_or_none():
            raise ConflictError("Category name already exists")
        category.name = data.name

    if data.color is not None:
        category.color = data.color

    await session.flush()
    return CategoryOut.model_validate(category)


async def delete_category(session: DbSession, user: User, category_id: str) -> None:
    category = await _get_user_category(session, user, category_id)
    if category.owner_user_id is None:
        raise ForbiddenError("Cannot delete system category")

    linked_expenses = await session.execute(
        select(func.count())
        .select_from(Expense)
        .where(
            Expense.category_id == category.id,
            Expense.is_deleted.is_(False),
        )
    )
    if (linked_expenses.scalar_one() or 0) > 0:
        raise InvalidRequestError("Category cannot be deleted while expenses exist")

    category.is_deleted = True
    await session.flush()
