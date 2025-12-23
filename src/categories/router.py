import logging
from typing import Annotated

from fastapi import APIRouter, Query

from src.auth.dependencies import CurrentUser
from src.categories.schemas import (
    CategoryCreate,
    CategoryListResponse,
    CategoryOut,
    CategoryUpdate,
)
from src.categories.service import (
    create_category,
    delete_category,
    list_categories,
    update_category,
)
from src.db.dependencies import DbSession

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("", response_model=CategoryListResponse)
async def get_categories(
    session: DbSession,
    user: CurrentUser,
    include_deleted: Annotated[bool, Query(False)] = False,
):
    logger.info(
        "GET /categories",
        extra={"user_id": str(user.id), "include_deleted": include_deleted},
    )
    return await list_categories(session, user, include_deleted=include_deleted)


@router.post("", response_model=CategoryOut, status_code=201)
async def create_category_endpoint(
    data: CategoryCreate,
    session: DbSession,
    user: CurrentUser,
):
    logger.info("POST /categories", extra={"user_id": str(user.id)})
    return await create_category(session, user, data)


@router.patch("/{category_id}", response_model=CategoryOut)
async def update_category_endpoint(
    category_id: str,
    data: CategoryUpdate,
    session: DbSession,
    user: CurrentUser,
):
    logger.info(
        "PATCH /categories/{category_id}",
        extra={"user_id": str(user.id), "category_id": category_id},
    )
    return await update_category(session, user, category_id, data)


@router.delete("/{category_id}", status_code=200)
async def delete_category_endpoint(
    category_id: str,
    session: DbSession,
    user: CurrentUser,
):
    logger.info(
        "DELETE /categories/{category_id}",
        extra={"user_id": str(user.id), "category_id": category_id},
    )
    await delete_category(session, user, category_id)
    return {"message": "Category deleted."}
