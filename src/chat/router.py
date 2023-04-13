import base64

import rsa
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.responses import Response

from src.auth.models import User
from src.auth.schemas import RequestSchema
from src.chat.schemas import GetUsersSchema, GetUserSchema
from src.database import get_async_session
from src.utils import get_user_by_token, prepare_encrypted, RSA

router = APIRouter(tags=["Chat"], prefix="/chat")


@router.post("/get-users", responses={422: {"model": ""}})
async def get_users(encrypted: tuple[RequestSchema, User] = Depends(get_user_by_token),
                    server_private_key: rsa.PrivateKey = Depends(RSA.get_private_key),
                    session: AsyncSession = Depends(get_async_session)):
    decrypted, user = encrypted
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    user_public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER")
    if not user.has_changed_password:
        data = {
            "status": "error",
            "data": None,
            "details": "password expired"
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)
    try:
        query = select(User).filter_by(is_active=True)
        result = await session.execute(query)
        result = result.scalars().all()
        user_public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER")
        data = [GetUserSchema(id=item.id, name=item.name, username=item.username).dict() for item in result]
        data = {
            "status": "success",
            "data": data,
            "details": None
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        response = Response(status_code=status.HTTP_200_OK, content=encrypted,
                            media_type="application/octet-stream")
        return response
    except Exception:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
