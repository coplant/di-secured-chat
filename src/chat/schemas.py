from datetime import datetime
from typing import Union

from pydantic import Field, BaseModel

from src.auth.models import User
from src.schemas import ResponseSchema


class UserIDSchema(BaseModel):
    id: int


class GetUserSchema(UserIDSchema):
    username: str
    name: str


class ChatSchema(BaseModel):
    users: list[int]
    name: Union[str, None]


class GetUsersSchema(ResponseSchema):
    data: list[GetUserSchema]


class KeysSchema(BaseModel):
    chat_id: int
    public_key: str


class PayloadSchema(BaseModel):
    payload: Union[KeysSchema, ChatSchema, dict]


class PayloadTokenSchema(PayloadSchema):
    token: str


class RequestSchema(BaseModel):
    data: Union[PayloadTokenSchema, PayloadSchema]
    signature: str


class ReceiveMessageSchema(BaseModel):
    id: Union[int, None]
    author_id: int
    chat_id: int
    body: str
    timestamp: str


class ReceiveChatSchema(BaseModel):
    id: int
    type: int
    name: str
    users: list[GetUserSchema]
    # p: str
    # g: str
