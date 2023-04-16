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


class PayloadSchema(BaseModel):
    payload: Union[ChatSchema, dict]


class PayloadTokenSchema(PayloadSchema):
    token: str


class RequestSchema(BaseModel):
    data: Union[PayloadTokenSchema, PayloadSchema]
    signature: str


class Message(BaseModel):
    id: int
    username: str
    # todo: body type
    # body: bytes
    timestamp: datetime

# class ChatSchema(BaseModel):
#     id: int
#     type: int
#     name: str
#     users: list[GetUserSchema]
#     # todo: messages?
#     # messages: list[Message] = []
