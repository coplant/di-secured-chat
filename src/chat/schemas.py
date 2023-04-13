from typing import Union

from pydantic import Field, BaseModel

from src.schemas import ResponseSchema


class GetUserSchema(BaseModel):
    id: str
    username: str
    name: str


class GetUsersSchema(ResponseSchema):
    data: list[GetUserSchema]


class PayloadSchema(BaseModel):
    payload: Union[dict]


class PayloadTokenSchema(PayloadSchema):
    token: str


class RequestSchema(BaseModel):
    data: Union[PayloadTokenSchema, PayloadSchema]
    signature: str
