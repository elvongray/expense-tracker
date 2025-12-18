from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.core.exceptions import ApplicationError


def add_exception_handlers(app: FastAPI):
    @app.exception_handler(ApplicationError)
    async def http_exception_handler(_, exc: ApplicationError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.msg},
        )
