import base64

import rsa
from fastapi import APIRouter, Depends, HTTPException, WebSocket, Header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.responses import Response
from starlette.websockets import WebSocketDisconnect

from src.auth.models import User
from src.chat.models import Chat, ChatUser
from src.chat.schemas import RequestSchema, GetUserSchema
from src.chat.utils import ConnectionManager, get_user_by_token_ws
from src.database import get_async_session
from src.utils import get_user_by_token, prepare_encrypted, RSA, get_current_user

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


connection = ConnectionManager()


@router.post("/new", responses={422: {"model": ""}})
async def create_chat(encrypted: tuple[RequestSchema, User] = Depends(get_user_by_token),
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
        encrypted = prepare_encrypted(data, RSA.get_private_key(), user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)
    try:
        users = decrypted.data.payload.users
        name = decrypted.data.payload.name or "New Chat"
        chat_type = 1 if len(users) > 1 else 0
        chat = Chat(type_id=chat_type, name=name)
        try:
            session.add(chat)
            await session.flush()
            session.add_all([ChatUser(chat_id=chat.id, user_id=chat_user) for chat_user in users])
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()
        data = {
            "status": "success",
            "data": {"chat_id": chat.id},
            "details": None
        }
        encrypted = prepare_encrypted(data, RSA.get_private_key(), user_public_key)
        response = Response(status_code=status.HTTP_201_CREATED,
                            content=encrypted, media_type="application/octet-stream")
        return response
    except Exception as ex:
        await session.rollback()
        data = {
            "status": "error",
            "data": None,
            "details": "invalid data"
        }
        encrypted = prepare_encrypted(data, RSA.get_private_key(), user_public_key)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=encrypted)


@router.websocket("/")
async def websocket_rooms(websocket: WebSocket,
                          session: AsyncSession = Depends(get_async_session),
                          user: User = Depends(get_user_by_token_ws)):
    try:
        await connection.connect(websocket, user, session)
        while True:
            data = await websocket.receive_bytes()
            print("Received: ", data)
            # Send the message to all the clients
            await connection.broadcast(data)

    except WebSocketDisconnect:
        connection.disconnect(websocket)
    except Exception as err:
        # todo: переписать исключение
        await websocket.send_bytes(str(err).encode())
        await websocket.close()

# @router.websocket("/{chat_id}")
# async def websocket_chat(websocket: WebSocket, chat_id: int):
#     await websocket.accept()
#     for i in range(10):
#         await websocket.send_text(str(chat_id))
#     await websocket.close()
