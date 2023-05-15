import base64
import json

import rsa
import sympy
from fastapi import APIRouter, Depends, HTTPException, WebSocket, Header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from starlette import status
from starlette.responses import Response
from starlette.websockets import WebSocketDisconnect

from src.auth.models import User
from src.chat.models import Chat, ChatUser, ChatPrime
from src.chat.schemas import RequestSchema, GetUserSchema, ReceiveChatSchema
from src.chat.utils import ConnectionManager, get_user_by_token_ws
from src.database import get_async_session
from src.utils import get_user_by_token, prepare_encrypted, RSA, get_current_user

router = APIRouter(tags=["Chat"], prefix="/chat")


@router.post("/get-users", responses={422: {"model": ""}})
async def get_users(encrypted: tuple[RequestSchema, User] = Depends(get_user_by_token),
                    server_private_key: rsa.PrivateKey = Depends(RSA.get_private_key),
                    session: AsyncSession = Depends(get_async_session)):
    decrypted, user = encrypted
    if not user or not user.public_key:
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


@router.post("/new", responses={422: {"model": ""}})
async def create_chat(encrypted: tuple[RequestSchema, User] = Depends(get_user_by_token),
                      session: AsyncSession = Depends(get_async_session)):
    decrypted, user = encrypted
    if not user or not user.public_key:
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
        chat_type = 1 if len(users) > 1 else 0
        users.append(user.id)
        name = decrypted.data.payload.name or "New Chat"
        g = sympy.randprime(int(0x1000000000000000000000000000000000000000000000000000000000000000),
                            int(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))
        p = 2 * g + 1
        while not sympy.isprime(p):
            g = sympy.randprime(int(0x1000000000000000000000000000000000000000000000000000000000000000),
                                int(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))
            p = 2 * g + 1

        chat = Chat(type_id=chat_type, name=name)
        try:
            session.add(chat)
            await session.flush()
            session.add_all([ChatUser(chat_id=chat.id, user_id=chat_user) for chat_user in users])
            session.add(ChatPrime(p=str(p), g=str(g), chat_id=chat.id))
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()
            await session.refresh(chat)
        active_users = connection.find_all_chat_users(users)
        data = {
            "status": "success",
            "data": ReceiveChatSchema(id=chat.id,
                                      type=chat.type_id,
                                      name=chat.name,
                                      users=[GetUserSchema(id=u.id,
                                                           username=u.username,
                                                           name=u.name).dict() for u in chat.users]
                                      ).dict(),
            "details": None
        }
        # message = prepare_encrypted(data, RSA.get_private_key(),
        #                             rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER"))
        for au in active_users:
            await connection.send_message_to(au, json.dumps({"data": data, "signature": "signature"}).encode())
        data = {
            "status": "success",
            "data": {"chat_id": chat.id, "p": str(p), "g": str(g)},
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


@router.patch("/{chat_id}", responses={422: {"model": ""}})
async def update_chat(chat_id: int,
                      encrypted: tuple[RequestSchema, User] = Depends(get_user_by_token),
                      session: AsyncSession = Depends(get_async_session)):
    decrypted, user = encrypted
    if not user or not user.public_key:
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
        query = select(Chat).filter_by(id=chat_id)
        result = await session.execute(query)
        chat: Chat = result.scalars().unique().first()
        users = decrypted.data.payload.users
        users.append(user.id)
        query = select(User).filter(User.id.in_(users))
        result = await session.execute(query)
        new_users = result.scalars().unique().all()
        name = decrypted.data.payload.name or chat.name
        chat.name = name
        chat.users = new_users
        # todo: можно менять тип чата в зависимости от кол-ва юзеров
        # chat.type_id = 1 if len(new_users) > 1 else 0
        try:
            session.add(chat)
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()
        data = {
            "status": "success",
            "data": {"users": users, "name": name},
            "details": None
        }
        encrypted = prepare_encrypted(data, RSA.get_private_key(), user_public_key)
        response = Response(status_code=status.HTTP_200_OK,
                            content=encrypted, media_type="application/octet-stream")
        return response
    except Exception as ex:
        data = {
            "status": "error",
            "data": None,
            "details": "invalid data"
        }
        encrypted = prepare_encrypted(data, RSA.get_private_key(), user_public_key)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=encrypted)


connection = ConnectionManager()


@router.websocket("/ws")
async def websocket_rooms(websocket: WebSocket,
                          session: AsyncSession = Depends(get_async_session),
                          user: User = Depends(get_user_by_token_ws)):
    try:
        await connection.connect(websocket, user)
        ids, message = await connection.receive_chats(websocket, user, session)
        await connection.send_message_to(websocket, message)
        await connection.receive_messages(websocket, user, session, ids)
        while True:
            await websocket.receive_bytes()
    except WebSocketDisconnect:
        connection.disconnect(websocket)
    except Exception as err:
        # todo: переписать исключение
        await websocket.send_bytes(str(err).encode())
        await websocket.close(code=status.WS_1006_ABNORMAL_CLOSURE)


@router.websocket("/ws/{chat_id}")
async def websocket_rooms(chat_id: int,
                          websocket: WebSocket,
                          session: AsyncSession = Depends(get_async_session),
                          user: User = Depends(get_user_by_token_ws)):
    try:
        await connection.connect_to_chat(websocket, session, user, chat_id)
        ids, _ = await connection.receive_chats(websocket, user, session)
        if chat_id not in ids:
            raise WebSocketDisconnect
        await connection.receive_messages_from_chat(websocket, session, chat_id)

        async for message in websocket.iter_bytes():
            # todo: если есть секретный ключ, то отправлять другим методом - сырые байты, без RSA и тп
            await connection.send_message(websocket, session, user.id, chat_id, message)
        #     todo: полученные байты
        #     а) если группа - отправить на клиенты + сохранить в бд (всё хранится в виде байтов)
        #     б) если личные - отправить на клиенты (убедиться, что сообщение доставлено
    except WebSocketDisconnect:
        connection.disconnect(websocket)
    except Exception as err:
        # todo: переписать исключение
        await websocket.close(code=status.WS_1006_ABNORMAL_CLOSURE)


@router.post("/send-keys", responses={422: {"model": ""}})
async def send_keys(encrypted: tuple[RequestSchema, User] = Depends(get_user_by_token),
                    session: AsyncSession = Depends(get_async_session)):
    decrypted, user = encrypted
    decrypted = RequestSchema.parse_obj(decrypted)
    if not user or not user.public_key:
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
        query = select(ChatUser).filter_by(chat_id=decrypted.data.payload.chat_id).filter_by(user_id=user.id)
        result = await session.execute(query)
        result = result.scalars().first()
        try:
            result.public_key = decrypted.data.payload.public_key
            session.add(result)
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()
            await session.refresh(result)
        active_users = connection.find_chat_active_users(decrypted.data.payload.chat_id)

        query = select(ChatPrime).filter_by(chat_id=decrypted.data.payload.chat_id)
        result = await session.execute(query)
        chat_primes = result.scalars().unique().first()

        query = select(ChatUser).filter_by(chat_id=decrypted.data.payload.chat_id)
        result = await session.execute(query)
        chat_public = result.scalars().unique().all()
        user_primes = []
        for item in chat_public:
            user_primes.append({
                "user_id": item.user_id,
                "key": str(item.public_key)
            })

        data = {
            "status": "success",
            "data": {"chat_id": decrypted.data.payload.chat_id, "p": str(chat_primes.p), "g": str(chat_primes.g),
                     "public_keys": user_primes},
            "details": None
        }
        # message = prepare_encrypted(data, RSA.get_private_key(),
        #                             rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER"))
        for au in active_users:
            try:
                await connection.send_message_to(au.get("ws"),
                                                 # json.dumps({"data": data, "signature": "signature"}).encode())
                                                 json.dumps(data).encode())
            except Exception as ex:
                # todo: отключение вебсокетов
                del connection.active_connections[au]

        data = {
            "status": "success",
            "data": None,
            "details": "sent successfully"
        }
        encrypted = prepare_encrypted(data, RSA.get_private_key(), user_public_key)
        response = Response(status_code=status.HTTP_200_OK,
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
