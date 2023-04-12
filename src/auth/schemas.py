from pydantic import BaseModel, Field

from src.schemas import ResponseSchema


class UserSchema(BaseModel):
    username: str = Field(..., example="username")
    password: str = Field(..., example="password")
    uid: str = Field(..., example="uid")


class LoginUserSchema(UserSchema):
    public_key: str = Field(..., example="base64 encoded uid")


class RequestSchema(BaseModel):
    data: dict = Field(..., example="nested json data")
    signature: str = Field(..., example="base64 encoded signature of data")


class LoginRequestSchema(RequestSchema):
    data: LoginUserSchema


class PublicKeySchema(ResponseSchema):
    data: dict = Field(..., example={"public_key": "base64 encoded public key",
                                     "signature": "base64 encoded signature of public key"})


class LogoutResponseModel(ResponseSchema):
    details: str = Field(..., example="logged out")


class CreateUserSchema(UserSchema):
    name: str = Field(..., example="name")


class ChangePasswordSchema(BaseModel):
    password: str = Field(..., example="password")
