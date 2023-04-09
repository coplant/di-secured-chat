from datetime import datetime
from typing import Optional, Union

from pydantic import BaseModel


class UserSchema(BaseModel):
    username: str
    password: str
    public_key: Union[None, str] = None


class HashedUserSchema(BaseModel):
    hashed_data: str


class PublicKeySchema(BaseModel):
    public_key: str
