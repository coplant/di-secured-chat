import base64
import binascii
import hashlib
import json
import secrets
from datetime import datetime, timedelta

import bcrypt
import rsa
from fastapi import APIRouter, Depends, HTTPException, Body, Response
from pyasn1 import error
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.responses import JSONResponse

from src.auth.utils import Roles
from src.auth.models import User
from src.auth.schemas import (PublicKeySchema, LogoutResponseSchema,
                              ChangePasswordSchema, RequestSchema)
from src.config import HASH_TYPE
from src.database import get_async_session
from src.schemas import ResponseSchema, ValidationResponseSchema
from src.utils import RSA, get_current_user, prepare_encrypted, get_user_by_token

router = APIRouter(tags=['Authentication'], prefix='/auth')


@router.get("/login", response_model=PublicKeySchema, response_description="Get a server public key")
async def get_public_key(server_public_key: rsa.PublicKey = Depends(RSA.get_public_key)):
    public_key = server_public_key.save_pkcs1(format="DER")
    data = {"public_key": base64.b64encode(public_key).decode(),
            "signature": base64.b64encode(rsa.sign(public_key, RSA.get_private_key(), HASH_TYPE)).decode()}
    return JSONResponse(status_code=status.HTTP_200_OK,
                        content={"status": "success", "data": data, "details": ""})


@router.post("/login",
             response_model=RequestSchema,
             response_description="Log into the server",
             responses={422: {"model": ""}})
async def login(encrypted: bytes = Body(..., media_type="application/octet-stream"),
                server_private_key: rsa.PrivateKey = Depends(RSA.get_private_key),
                session: AsyncSession = Depends(get_async_session)):
    decrypted = RequestSchema.parse_obj(json.loads(RSA.decrypt(encrypted, server_private_key)))
    try:
        user_public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(decrypted.data.payload.public_key), format="DER")
    except error.SubstrateUnderrunError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    try:
        is_valid = RSA.verify_signature(decrypted.data.json().encode(),
                                        base64.b64decode(decrypted.signature),
                                        user_public_key)
    except (binascii.Error,):
        data = {
            "status": "error",
            "data": None,
            "details": "invalid signature"
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)
    if not is_valid:
        data = {
            "status": "error",
            "data": None,
            "details": "invalid signature"
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)

    # valid signature
    query = select(User).filter_by(username=decrypted.data.payload.username)
    result = await session.execute(query)
    user: User = result.scalars().unique().first()

    if not user:
        data = {
            "status": "error",
            "data": None,
            "details": "invalid credentials"
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)

    # # invalid credentials
    if not (bcrypt.checkpw(decrypted.data.payload.password.encode(), user.hashed_password.encode())
            and user.uid == hashlib.sha256(decrypted.data.payload.uid.encode()).hexdigest()):
        data = {
            "status": "error",
            "data": None,
            "details": "invalid credentials"
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)

    # successful authentication
    token = secrets.token_hex(32)
    user.hashed_token = hashlib.sha256(token.encode()).hexdigest()
    user.logged_at = datetime.utcnow()
    user.public_key = decrypted.data.payload.public_key

    # check if password still valid
    if datetime.utcnow() - user.changed_at >= timedelta(days=60):
        user.has_changed_password = False

    session.add(user)
    await session.commit()
    status_code = status.HTTP_307_TEMPORARY_REDIRECT if not user.has_changed_password else status.HTTP_200_OK
    status_info = "temporary" if not user.has_changed_password else "success"
    details = "password expired" if not user.has_changed_password else None

    data = {
        "status": status_info,
        "data": {"token": token},
        "details": details
    }
    encrypted = prepare_encrypted(data, server_private_key, user_public_key)
    response = Response(status_code=status_code, content=encrypted, media_type="application/octet-stream")
    return response


@router.get("/logout", response_model=LogoutResponseSchema, responses={422: {"model": ""}})
async def logout(encrypted: tuple[dict, User] = Depends(get_user_by_token),
                 server_private_key: rsa.PrivateKey = Depends(RSA.get_private_key),
                 session: AsyncSession = Depends(get_async_session)):
    decrypted, user = encrypted
    if not user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    data = {
        "status": "success",
        "data": None,
        "details": "logged out"
    }
    encrypted = prepare_encrypted(data,
                                  server_private_key,
                                  rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), format="DER"))
    response = Response(status_code=status.HTTP_200_OK, content=encrypted, media_type="application/octet-stream")
    user.hashed_token = ""
    session.add(user)
    await session.commit()
    return response


@router.post("/create-user", responses={422: {"model": ""}})
async def create_user(encrypted: tuple[RequestSchema, User] = Depends(get_user_by_token),
                      server_private_key: rsa.PrivateKey = Depends(RSA.get_private_key),
                      session: AsyncSession = Depends(get_async_session)):
    decrypted, user = encrypted
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
    user_public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER")
    try:
        is_valid = RSA.verify_signature(decrypted.data.json().encode(),
                                        base64.b64decode(decrypted.signature),
                                        user_public_key)
    except (binascii.Error,):
        data = {
            "status": "error",
            "data": None,
            "details": "invalid signature"
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)

    if user.role_id == Roles.ADMIN.value and user.has_changed_password:
        try:
            user_data = {
                "uid": hashlib.sha256(decrypted.data.payload.uid.encode()).hexdigest(),
                "name": decrypted.data.payload.name,
                "username": decrypted.data.payload.username
            }
            bcrypt_salt = bcrypt.gensalt()
            user_data["hashed_password"] = bcrypt.hashpw(decrypted.data.payload.password.encode(), bcrypt_salt).decode()
            user_data["role_id"] = 0
            user_to_add = User(**user_data)
            session.add(user_to_add)
            await session.commit()
            data = {
                "status": "success",
                "data": None,
                "details": "created successfully"
            }
            encrypted = prepare_encrypted(data, server_private_key,
                                          rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), format="DER"))
            response = Response(status_code=status.HTTP_201_CREATED, content=encrypted,
                                media_type="application/octet-stream")
            return response
        except Exception:
            data = {
                "status": "error",
                "data": None,
                "details": "invalid data"
            }
            encrypted = prepare_encrypted(data, server_private_key, user_public_key)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)
    else:
        data = {
            "status": "error",
            "data": None,
            "details": "invalid permissions"
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)


@router.patch("/change-password", responses={422: {"model": ""}})
async def change_password(data: ChangePasswordSchema,
                          user: User = Depends(get_current_user),
                          session: AsyncSession = Depends(get_async_session)):
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
    try:
        user_password = rsa.decrypt(base64.b64decode(data.password), RSA.get_private_key()).decode()
        bcrypt_salt = bcrypt.gensalt()
        user.hashed_password = bcrypt.hashpw(user_password.encode(), bcrypt_salt).decode()
        user.hashed_token = ""
        user.changed_at = datetime.utcnow()
        user.has_changed_password = True
        session.add(user)
        await session.commit()
        return JSONResponse(status_code=status.HTTP_200_OK,
                            content={"status": "success", "data": None, "details": "password changed"})
    except Exception:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid data")
