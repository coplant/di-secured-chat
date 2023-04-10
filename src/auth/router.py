import base64
import json

import rsa
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.schemas import EncryptedUserSchema, PublicKeySchema
from src.config import HASH_TYPE
from src.database import get_async_session
from src.utils import get_public_key, get_private_key, is_valid_signature

router = APIRouter(tags=['Authentication'], prefix='/auth')


@router.get("/login", response_model=PublicKeySchema, response_description="Get a server public key")
async def get_public_key(raw_public_key: rsa.PublicKey = Depends(get_public_key)):
    public_key = raw_public_key.save_pkcs1("PEM")
    return {"public_key": base64.b64encode(public_key),
            "signature": base64.b64encode(rsa.sign(public_key, get_private_key(), HASH_TYPE))}


@router.post("/login")
async def login(encrypted_user: EncryptedUserSchema,
                # private_key: rsa.PrivateKey = Depends(get_private_key),
                # public_key: rsa.PublicKey = Depends(get_public_key),
                session: AsyncSession = Depends(get_async_session)):
    message = encrypted_user.copy()
    del message.signature
    user_public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(encrypted_user.public_key.encode()))
    is_valid = is_valid_signature(message.json().encode(),
                                  base64.b64decode(encrypted_user.signature.encode()),
                                  user_public_key)
    if is_valid:
        return {"status": "success"}
