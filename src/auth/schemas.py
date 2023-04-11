from datetime import datetime
from typing import Optional, Union

from pydantic import BaseModel, Field

from src.schemas import ResponseSchema


class UserSchema(BaseModel):
    username: str = Field(..., example="base64 encoded username")
    password: str = Field(..., example="base64 encoded password")
    uid: str = Field(..., example="base64 encoded uid")
    public_key: str = Field(..., example="base64 encoded uid")
    signature: str = Field(..., example="base64 encoded signature of whole data")


class PublicKeySchema(ResponseSchema):
    data: dict = Field(..., example={"public_key": "base64 encoded public key",
                                     "signature": "base64 encoded signature of public key"})
