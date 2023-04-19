import sys

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRouter
from pydantic import ValidationError

sys.path.append("..")

from auth.router import router as auth_router
from chat.router import router as chat_router
from exceptions import http_exception_handler, validation_exception_handler
from utils import RSA

# keys setup
public_key, private_key = RSA.get_keys()
if not public_key or not private_key:
    public_key, private_key = RSA.setup_keys()

app = FastAPI()
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
route = APIRouter(prefix="/api", tags=[])

route.include_router(auth_router)
route.include_router(chat_router)
app.include_router(route)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
