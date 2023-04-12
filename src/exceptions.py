from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from starlette.responses import JSONResponse, Response

from src.utils import prepare_encrypted


async def http_exception_handler(request, exc):
    return Response(
        status_code=exc.status_code,
        content=exc.detail,
        media_type="application/octet-stream"
    )


async def validation_exception_handler(request, exc):
    return Response(
        status_code=422
    )
