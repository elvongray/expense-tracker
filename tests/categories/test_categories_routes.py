from datetime import date

import pytest

from src.auth.utils import create_access_token
from src.categories.models import Category
from src.expenses.models import Expense
from tests.user.factories import UserFactory

pytestmark = pytest.mark.asyncio


def _auth_headers(user):
    token = create_access_token(
        {
            "sub": str(user.id),
            "email": user.email,
            "token_version": user.token_version,
            "type": "access",
        }
    )
    return {"Authorization": f"Bearer {token}"}


async def test_list_categories_returns_system_and_custom(client, async_db_session):
    user = UserFactory()
    async_db_session.add(user)
    await async_db_session.flush()

    system_cat = Category(
        owner_user_id=None, name="Groceries", color=None, is_deleted=False
    )
    user_cat = Category(
        owner_user_id=user.id, name="Gym", color="#00FFAA", is_deleted=False
    )
    async_db_session.add_all([system_cat, user_cat])
    await async_db_session.flush()

    resp = await client.get("/categories", headers=_auth_headers(user))
    assert resp.status_code == 200
    data = resp.json()
    assert any(cat["name"] == "Groceries" for cat in data["system"])
    assert any(cat["name"] == "Gym" for cat in data["custom"])


async def test_create_category_enforces_uniqueness(client, async_db_session):
    user = UserFactory()
    async_db_session.add(user)
    await async_db_session.flush()

    async_db_session.add(Category(owner_user_id=user.id, name="Home", color=None))
    await async_db_session.flush()

    resp = await client.post(
        "/categories",
        json={"name": "home", "color": None},
        headers=_auth_headers(user),
    )
    assert resp.status_code == 409


async def test_update_category_changes_fields(client, async_db_session):
    user = UserFactory()
    async_db_session.add(user)
    await async_db_session.flush()

    cat = Category(owner_user_id=user.id, name="Old", color=None)
    async_db_session.add(cat)
    await async_db_session.flush()

    resp = await client.patch(
        f"/categories/{cat.id}",
        json={"name": "New Name", "color": "#FFFFFF"},
        headers=_auth_headers(user),
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["name"] == "New Name"
    assert updated["color"] == "#FFFFFF"


async def test_delete_blocked_when_expenses_exist(client, async_db_session):
    user = UserFactory()
    async_db_session.add(user)
    await async_db_session.flush()

    cat = Category(owner_user_id=user.id, name="Travel", color=None)
    async_db_session.add(cat)
    await async_db_session.flush()

    expense = Expense(
        user_id=user.id,
        category_id=cat.id,
        amount=10,
        currency="USD",
        expense_date=date(2024, 1, 1),
        note=None,
        is_deleted=False,
    )
    async_db_session.add(expense)
    await async_db_session.flush()

    resp = await client.delete(f"/categories/{cat.id}", headers=_auth_headers(user))
    assert resp.status_code == 400


async def test_delete_category_success(client, async_db_session):
    user = UserFactory()
    async_db_session.add(user)
    await async_db_session.flush()

    cat = Category(owner_user_id=user.id, name="Books", color=None)
    async_db_session.add(cat)
    await async_db_session.flush()

    resp = await client.delete(f"/categories/{cat.id}", headers=_auth_headers(user))
    assert resp.status_code == 200
    await async_db_session.refresh(cat)
    assert cat.is_deleted is True
