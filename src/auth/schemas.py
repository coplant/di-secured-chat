from datetime import datetime
from typing import Optional, Union

from pydantic import BaseModel, Field


class UserSchema(BaseModel):
    username: str
    password: str
    public_key: Union[None, str] = None


class EncryptedUserSchema(BaseModel):
    username: str = Field(..., example="Base64 encoded username")
    password: str = Field(..., example="Base64 encoded password")
    uid: str = Field(..., example="Base64 encoded uid")
    public_key: str = Field(..., example="Base64 encoded uid")
    signature: str = Field(..., example="Base64 encoded signature of whole data")


class PublicKeySchema(BaseModel):
    public_key: bytes = Field(..., example="Base64 encoded public key")
    signature: bytes = Field(..., example="Base64 encoded signature")
