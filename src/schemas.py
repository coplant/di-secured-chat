from typing import Union, Any

from pydantic import BaseModel, Field


class ResponseSchema(BaseModel):
    status: str
    data: dict
    details: Union[Any, None]


class ValidationResponseSchema(ResponseSchema):
    details: dict = Field(..., example={
        "loc": ("loc", 0),
        "msg": "msg",
        "type": "type",
    })
