from typing import Union, Any

from pydantic import BaseModel


class ResponseSchema(BaseModel):
    status: str
    data: Union[str, bytes, Any]
    details: Union[Any, None]
