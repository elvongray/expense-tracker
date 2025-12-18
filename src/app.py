from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import settings

# from src.auth.router import router as auth_router
from src.core.error_handler import add_exception_handlers

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.all_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# app.include_router(auth_router, prefix="/auth", tags=["auth"])

add_exception_handlers(app)
