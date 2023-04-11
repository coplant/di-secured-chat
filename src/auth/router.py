import base64
import binascii
import hashlib
import json
import secrets
from datetime import datetime

import bcrypt
import rsa
from fastapi import APIRouter, Depends, HTTPException, Query
from pyasn1 import error
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.responses import JSONResponse

from src.auth.models import User
from src.auth.schemas import PublicKeySchema, UserSchema, TokenResponseSchema, LogoutResponseModel
from src.auth.utils import decrypt_dict
from src.config import HASH_TYPE
from src.database import get_async_session
from src.schemas import ResponseSchema, ValidationResponseSchema
from src.utils import get_public_key, get_private_key, is_valid_signature, get_current_user

router = APIRouter(tags=['Authentication'], prefix='/auth')


@router.get("/login", response_model=PublicKeySchema, response_description="Get a server public key")
async def get_public_key(server_public_key: rsa.PublicKey = Depends(get_public_key)):
    public_key = server_public_key.save_pkcs1(format="DER")
    data = {"public_key": base64.b64encode(public_key).decode(),
            "signature": base64.b64encode(rsa.sign(public_key, get_private_key(), HASH_TYPE)).decode()}
    return JSONResponse(status_code=status.HTTP_200_OK,
                        content={"status": "error", "data": data, "details": ""})


@router.post("/login", response_model=TokenResponseSchema,
             response_description="Log into the server",
             responses={422: {"model": ValidationResponseSchema}})
async def login(encrypted_user: UserSchema,
                server_private_key: rsa.PrivateKey = Depends(get_private_key),
                session: AsyncSession = Depends(get_async_session)):
    message = encrypted_user.copy()
    del message.signature
    try:
        user_public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(encrypted_user.public_key.encode()), format="DER")
    except error.SubstrateUnderrunError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid public key")

    try:
        is_valid = is_valid_signature(message.json().encode(),
                                      base64.b64decode(encrypted_user.signature.encode()),
                                      user_public_key)
    # invalid signature
    except (binascii.Error,):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid signature")
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid signature")

    # valid signature
    decrypted_user = UserSchema(**decrypt_dict(encrypted_user.dict(), server_private_key))
    query = select(User).filter_by(username=decrypted_user.username)
    result = await session.execute(query)
    user: User = result.scalars().unique().first()

    # invalid credentials
    if not (bcrypt.checkpw(decrypted_user.password.encode(), user.hashed_password.encode())
            and user.uid == decrypted_user.uid):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid credentials")

    # successful authentication
    token = secrets.token_hex(32)
    user.hashed_token = hashlib.sha256(token.encode()).hexdigest()
    user.logged_at = datetime.utcnow()
    user.public_key = encrypted_user.public_key
    session.add(user)
    await session.commit()
    encrypted_token = rsa.encrypt(token.encode(), user_public_key)
    data = {
        "token": base64.b64encode(encrypted_token).decode(),
        "signature": base64.b64encode(rsa.sign(encrypted_token, server_private_key, HASH_TYPE)).decode()
    }
    return JSONResponse(status_code=status.HTTP_200_OK,
                        content={"status": "success", "data": data, "details": None})


@router.get("/logout", response_model=LogoutResponseModel)
async def logout(user: User = Depends(get_current_user),
                 session: AsyncSession = Depends(get_async_session)):
    if user:
        user.hashed_token = ""
        session.add(user)
        await session.commit()
        return JSONResponse(status_code=status.HTTP_200_OK,
                            content={"status": "success", "data": None, "details": "logged out"})
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid token")
