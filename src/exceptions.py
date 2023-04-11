from fastapi import HTTPException
from pydantic import ValidationError
from starlette.responses import JSONResponse


async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "data": None, "details": exc.detail}
    )


async def validation_exception_handler(request, exc):
    errors = []
    for error in exc.errors():
        if isinstance(error, ValidationError):
            errors.append({
                "loc": error.loc,
                "msg": error.msg,
                "type": error.type,
            })
        else:
            errors.append({
                "loc": error.get("loc", None),
                "msg": error.get("msg", None),
                "type": error.get("type", None),
            })
    return JSONResponse(
        status_code=422,
        content={"status": "error", "data": None, "details": errors},
    )
