import base64
import datetime
import json
from dataclasses import dataclass

import rsa
from fastapi import WebSocket, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload
from sqlalchemy.sql.operators import and_
from starlette import status

from src.auth.models import User
from src.chat.models import Chat, ChatUser, Message, ChatPrime
from src.chat.schemas import ChatSchema, GetUserSchema, ReceiveChatSchema, ReceiveMessageSchema
from src.database import async_session_maker, get_async_session
from src.utils import RSA, get_current_user, prepare_encrypted


async def get_user_by_token_ws(websocket: WebSocket, session: AsyncSession = Depends(get_async_session)):
    token = websocket.headers.get("Authorization")
    if token is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
    else:
        token = RSA.decrypt(base64.b64decode(token), RSA.get_private_key())
        return await get_current_user(token, session)


@dataclass
class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict = {}
        self.active_chats: dict = {}

    async def receive_chats(self, websocket: WebSocket, user: User, session):
        try:
            query = select(Chat).join(ChatUser).join(User).options(
                selectinload(Chat.users).selectinload(User.chats)).filter(User.id == user.id)
            result = await session.execute(query)
            result = result.scalars().unique().all()
            ids = [item.id for item in result]
            data = {
                "status": "success",
                "data": [ReceiveChatSchema(id=item.id,
                                           type=item.type_id,
                                           name=item.name,
                                           users=[GetUserSchema(id=u.id,
                                                                username=u.username,
                                                                name=u.name).dict() for u in item.users],
                                           # p=item.primes.p,  # todo: можно раскомментировать это
                                           # g=item.primes.g
                                           ).dict() for item in result],
                "details": None
            }
            # message = prepare_encrypted(data, RSA.get_private_key(),
            #                             rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER"))
            return ids, json.dumps({"data": data, "signature": "signature"}).encode()
        except Exception as ex:
            print(ex)
            self.disconnect(websocket)

    async def receive_messages(self, websocket: WebSocket, user: User, session, ids: list[int]):
        try:
            subq = select(Message.chat_id, func.max(Message.id).label('max_id')).group_by(Message.chat_id).filter(
                Message.chat_id.in_(ids)).subquery()
            query = select(Message).join(subq, and_(Message.chat_id == subq.c.chat_id, Message.id == subq.c.max_id))
            result = await session.execute(query)
            result = result.scalars().unique().all()
            for message in result:
                data = {
                    "status": "success",
                    "data": ReceiveMessageSchema(id=message.id,
                                                 author_id=message.author_id,
                                                 chat_id=message.chat_id,
                                                 body=base64.b64encode(message.body).decode(),
                                                 timestamp=message.timestamp.timestamp()).dict(),
                    "details": None
                }
                message = json.dumps({"data": data, "signature": "signature"}).encode()
                # message = prepare_encrypted(data, RSA.get_private_key(),
                #                             rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER"))
                await self.send_message_to(websocket, message)
        except Exception as ex:
            print(ex)
            self.disconnect(websocket)

    async def receive_messages_from_chat(self, websocket: WebSocket, session, chat_id: int, offset: int = 0):
        try:
            query = select(Message).filter_by(chat_id=chat_id).order_by(
                Message.timestamp.desc()).limit(30).offset(offset)
            result = await session.execute(query)
            result = result.scalars().unique().all()
            for message in result:
                data = {
                    "status": "success",
                    "data": ReceiveMessageSchema(author_id=message.author_id,
                                                 chat_id=message.chat_id,
                                                 body=base64.b64encode(message.body).decode(),
                                                 timestamp=message.timestamp.timestamp()).dict(),
                    "details": None
                }
                message = json.dumps({"data": data, "signature": "signature"}).encode()
                # message = prepare_encrypted(data, RSA.get_private_key(),
                #                             rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER"))
                await self.send_message_to(websocket, message)
        except Exception as ex:
            print(ex)
            self.disconnect(websocket)

    async def connect(self, websocket: WebSocket, user: User):
        await websocket.accept()
        self.active_connections.setdefault("background", []).append({"ws": websocket, "user": user.id})

    async def connect_to_chat(self, websocket: WebSocket, session, user: User, chat_id: int):
        await websocket.accept()
        query = select(ChatPrime).filter_by(chat_id=chat_id)
        result = await session.execute(query)
        result = result.scalars().unique().first()
        message = {
            "status": "success",
            "data": {"chat_id": chat_id, "p": result.p, "g": result.g},
            "details": None
        }
        encrypted = json.dumps(message).encode()
        # encrypted = prepare_encrypted(data, RSA.get_private_key(), user_public_key)
        await self.send_message_to(websocket, encrypted)
        self.active_connections.setdefault(chat_id, []).append({"ws": websocket, "user": user.id})

    def disconnect(self, websocket: WebSocket):
        key, value = self.find_connection_id(websocket)
        del self.active_connections[key][value]
        if len(self.active_connections[key]) == 0:
            del self.active_connections[key]
        return key, value

    def find_connection_id(self, websocket: WebSocket):
        for key, value in self.active_connections.items():
            for item in value:
                if item.get('ws') == websocket:
                    return key, value.index(item)

    def find_chat_active_users(self, chat_id: int):
        return self.active_connections.get(chat_id)

    def find_all_chat_users(self, users: list[int]) -> list[WebSocket]:
        if self.active_connections.get("background"):
            return [ws.get("ws") for ws in self.active_connections.get("background") if ws.get("user") in users]
        return []

    async def send_message(self, websocket, session, author_id: int, chat_id: int, body: bytes):
        query = select(Chat).options(joinedload(Chat.users)).filter_by(id=chat_id)
        results = await session.execute(query)
        chat = results.scalars().unique().first()
        if chat.type_id == 1:
            message = Message(body=body, author_id=author_id, chat_id=chat_id)
            session.add(message)
            await session.commit()
            session.refresh(message)
        # todo: зашифровать сообщение
        # todo: поменять формат
        message = {
            "status": "success",
            "data": ReceiveMessageSchema(author_id=author_id,
                                         chat_id=chat_id,
                                         body=base64.b64encode(body).decode(),
                                         timestamp=datetime.datetime.utcnow().timestamp()).dict(),
            "details": None
        }
        encrypted = json.dumps(message).encode()
        # encrypted = prepare_encrypted(data, RSA.get_private_key(), user_public_key)
        users = [user.id for user in chat.users]
        for ws in self.find_all_chat_users(users):
            await self.send_message_to(ws, encrypted)
        for user in self.find_chat_active_users(chat_id):
            if author_id != user.get("user"):
                await self.send_message_to(user.get("ws"), encrypted)

    async def send_message_to(self, websocket: WebSocket, message: bytes):
        await websocket.send_bytes(message)

    async def broadcast(self, message: bytes):
        for ws in self.active_connections.get("background"):
            await self.send_message_to(ws.get("ws"), message)
