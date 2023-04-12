from pydantic import Field, BaseModel

from src.schemas import ResponseSchema


class GetUserSchema(BaseModel):
    id: str = Field(..., example="base64 encoded id")
    username: str = Field(..., example="base64 encoded username")
    name: str = Field(..., example="base64 encoded name")


class GetUsersSchema(ResponseSchema):
    data: list[GetUserSchema]
