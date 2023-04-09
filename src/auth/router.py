import rsa
from fastapi import APIRouter, Depends

from src.auth.schemas import HashedUserSchema, PublicKeySchema
from src.database import get_async_session
from src.utils import get_public_key

router = APIRouter(tags=['Authentication'], prefix='/auth')


@router.get("/login", response_model=PublicKeySchema)
async def get_public_key(public_key: rsa.PublicKey = Depends(get_public_key)):
    return {"public_key": public_key.save_pkcs1("PEM")}


@router.post("/login")
async def login(user: HashedUserSchema,
                session=Depends(get_async_session)):
    ...
