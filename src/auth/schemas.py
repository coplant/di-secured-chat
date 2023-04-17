from typing import Union

from pydantic import BaseModel, Field

from src.schemas import ResponseSchema


# class UserIDSchema(BaseModel):
#     id: int


class ChatSchema(BaseModel):
    users: list[int]
    name: Union[str, None]


class UserSchema(BaseModel):
    username: str
    password: str
    uid: str


class LoginUserSchema(UserSchema):
    public_key: str


class CreateUserSchema(UserSchema):
    name: str


class ChangePasswordSchema(BaseModel):
    password: str


class PayloadSchema(BaseModel):
    payload: Union[CreateUserSchema, LoginUserSchema, ChangePasswordSchema, ChatSchema, dict]


class PayloadTokenSchema(PayloadSchema):
    token: str


class RequestSchema(BaseModel):
    data: Union[PayloadTokenSchema, PayloadSchema]
    signature: str


class PublicKeySchema(ResponseSchema):
    data: dict


class LogoutResponseSchema(ResponseSchema):
    details: str = Field(..., example="logged out")

