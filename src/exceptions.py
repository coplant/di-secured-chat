from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from starlette import status
from starlette.responses import Response


async def http_exception_handler(request, exc):
    return Response(
        status_code=exc.status_code,
        content=exc.detail,
        media_type="application/octet-stream"
    )


async def validation_exception_handler(request, exc):
    return Response(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    media_type="application/octet-stream")
