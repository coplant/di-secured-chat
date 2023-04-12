import base64

import rsa
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.responses import JSONResponse

from src.auth.models import User
from src.chat.schemas import GetUsersSchema, GetUserSchema
from src.database import get_async_session
from src.schemas import ValidationResponseSchema
from src.utils import get_current_user

router = APIRouter(tags=["Chat"], prefix="/chat")


@router.get("/get-users", response_model=GetUsersSchema, responses={422: {"model": ValidationResponseSchema}})
async def get_users(user: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_async_session)):
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
    if not user.has_changed_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="password expired")
    try:
        query = select(User).filter_by(is_active=True)
        result = await session.execute(query)
        result = result.scalars().all()
        user_public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER")
        data = [GetUserSchema(id=base64.b64encode(rsa.encrypt(str(item.id).encode(), user_public_key)).decode(),
                              name=base64.b64encode(rsa.encrypt(item.name.encode(), user_public_key)).decode(),
                              username=base64.b64encode(rsa.encrypt(item.username.encode(), user_public_key)).decode()
                              ).dict() for item in result]
        return JSONResponse(status_code=status.HTTP_200_OK,
                            content={"status": "success", "data": data, "details": ""})
    except Exception:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="unauthorized")
