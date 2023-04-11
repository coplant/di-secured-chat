from typing import Union, Any

from pydantic import BaseModel


class ResponseSchema(BaseModel):
    status: str
    data: dict
    details: Union[Any, None]
