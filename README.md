# Expense Tracker API

FastAPI + PostgreSQL API for tracking expenses with email-based authentication and JWT access/refresh tokens.

## Features

- Email signup, verification codes, login, refresh tokens
- Password reset and change password with token versioning
- Expense tracking with categories and filters
- Cursor pagination and summary endpoints
- CORS-ready for frontend integration

## Tech Stack

- FastAPI
- PostgreSQL
- SQLAlchemy + Alembic
- JWT (python-jose)

## Project Structure

- `src/app.py`: FastAPI application
- `src/auth`: auth routes, services, schemas, utils
- `src/user`: user models and services
- `src/categories`: category models
- `src/expenses`: expense models
- `src/db`: database session and Alembic
- `tests`: test suite

## Environment Variables

Create a `.env` file in the project root:

```
JWT_SECRET_KEY=change-me
DATABASE_URL=postgresql+psycopg2://user:password@localhost:5432/expense_tracker
BACKEND_CORS_ORIGINS=["http://localhost:3000"]
FRONTEND_HOST=http://localhost:3000
```

Notes:

- `DATABASE_URL` is used for both sync and async engines.
- `BACKEND_CORS_ORIGINS` should be a JSON list string.

## Local Development

Install dependencies (using uv):

```
uv sync
```

Run the app:

```
uvicorn src.app:app --reload
```

## Database

Create migrations:

```
alembic revision --autogenerate -m "init"
```

Run migrations:

```
alembic upgrade head
```

## API Overview

Auth:

- `POST /auth/signup`
- `POST /auth/verify-email`
- `POST /auth/resend-verification-code`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/request-password-reset`
- `POST /auth/reset-password`
- `POST /auth/change-password`

Categories (auth required):

- `GET /categories`
- `POST /categories`
- `PATCH /categories/{id}`
- `DELETE /categories/{id}`

Expenses (auth required):

- `POST /expenses`
- `GET /expenses`
- `GET /expenses/{id}`
- `PATCH /expenses/{id}`
- `DELETE /expenses/{id}`
- `GET /expenses/summary`

Health:

- `GET /health`

## Testing

```
pytest
```
