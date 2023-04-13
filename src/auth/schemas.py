from typing import Union

from pydantic import BaseModel, Field

from src.schemas import ResponseSchema


class UserSchema(BaseModel):
    username: str = Field(..., example="username")
    password: str = Field(..., example="password")
    uid: str = Field(..., example="uid")


class LoginUserSchema(UserSchema):
    public_key: str = Field(..., example="base64 encoded uid")


class CreateUserSchema(UserSchema):
    name: str = Field(..., example="name")


class ChangePasswordSchema(BaseModel):
    password: str = Field(..., example="password")


class PayloadSchema(BaseModel):
    payload: Union[CreateUserSchema, LoginUserSchema, ChangePasswordSchema, dict]


class PayloadTokenSchema(PayloadSchema):
    token: str


class RequestSchema(BaseModel):
    data: Union[PayloadTokenSchema, PayloadSchema]
    signature: str


class PublicKeySchema(ResponseSchema):
    data: dict = Field(..., example={"public_key": "base64 encoded public key",
                                     "signature": "base64 encoded signature of public key"})


################################################


class LogoutResponseSchema(ResponseSchema):
    details: str = Field(..., example="logged out")

