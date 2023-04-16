import base64
import json
from dataclasses import dataclass

import rsa
from fastapi import WebSocket, HTTPException, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from src.auth.models import User
from src.auth.schemas import RequestSchema
from src.chat.models import Chat
from src.chat.schemas import ChatSchema, GetUserSchema
from src.database import async_session_maker, get_async_session
from src.utils import RSA, get_current_user, prepare_encrypted


async def get_user_by_token_ws(websocket: WebSocket, session: AsyncSession = Depends(get_async_session)):
    token = websocket.headers.get("Authorization")
    if token is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
    else:
        token = RSA.decrypt(base64.b64decode(token), RSA.get_private_key())
        return await get_current_user(token, session)


#
# async def get_user_by_token(encrypted: bytes) -> tuple[RequestSchema, User]:
#     try:
#         decrypted = RequestSchema.parse_obj(json.loads(RSA.decrypt(encrypted, RSA.get_private_key())))
#         async with async_session_maker() as session:
#             user = await get_current_user(decrypted.data.token.encode(), session)
#         return decrypted, user
#     except Exception:
#         raise HTTPException(status_code=status.WS_1007_INVALID_FRAME_PAYLOAD_DATA)
#         # raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


@dataclass
class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict = {}

    # async def authenticate(self, websocket):
    #     try:
    #         encrypted: bytes = await websocket.receive_bytes()
    #         decrypted, user = await get_user_by_token(encrypted)
    #         self.active_connections[user.id] = websocket
    #         return user
    #     except Exception as ex:
    #         print(ex)
    #         self.disconnect(websocket)
    #         websocket.close(code=status.WS_1008_POLICY_VIOLATION)

    async def connect(self, websocket: WebSocket, user: User, session):
        await websocket.accept()
        self.active_connections[user.id] = websocket
        try:
            # todo: получить список чатов? каким образом? можно только групповые
            # todo: возможно убрать вывод
            query = select(Chat)  # .filter_by(type_id=0)
            result = await session.execute(query)
            result = result.scalars().unique().all()
            data = {
                "status": "success",
                "data": [ChatSchema(id=item.id,
                                    type=item.type_id,
                                    name=item.name,
                                    users=[GetUserSchema(id=u.id, username=u.username, u=user.name) for u in item.users]
                                    ).dict() for item in result],
                "details": None
            }
            # message = prepare_encrypted(data, RSA.get_private_key(),
            #                             rsa.PublicKey.load_pkcs1(base64.b64decode(user.public_key), "DER"))
            message = json.dumps({"data": data, "signature": "signature"}).encode()

            await self.send_message_to(websocket, message)
        except Exception as ex:
            print(ex)
            self.disconnect(websocket)

    def disconnect(self, websocket: WebSocket):
        id = self.find_connection_id(websocket)
        del self.active_connections[id]
        return id

    def find_connection_id(self, websocket: WebSocket):
        val_list = list(self.active_connections.values())
        key_list = list(self.active_connections.keys())
        id = val_list.index(websocket)
        return key_list[id]

    async def send_message_to(self, websocket: WebSocket, message: bytes):
        await websocket.send_bytes(message)

    async def broadcast(self, message: bytes):
        for connection in self.active_connections.values():
            await connection.send_bytes(message)
