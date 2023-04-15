from datetime import datetime
from typing import Union
from pydantic import BaseModel
from src.schemas import ResponseSchema


class GetUserSchema(BaseModel):
    id: int
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
