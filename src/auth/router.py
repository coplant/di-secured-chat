import base64
import rsa
from fastapi import APIRouter, Depends

from src.auth.schemas import HashedUserSchema, PublicKeySchema
from src.database import get_async_session
from src.utils import get_public_key, get_private_key

router = APIRouter(tags=['Authentication'], prefix='/auth')


@router.get("/login", response_model=PublicKeySchema)
async def get_public_key(raw_public_key: rsa.PublicKey = Depends(get_public_key)):
    public_key = raw_public_key.save_pkcs1("PEM")
    return {"public_key": base64.b64encode(public_key),
            "signature": base64.b64encode(rsa.sign(public_key, get_private_key(), "SHA-256"))}


@router.post("/login")
async def login(user: HashedUserSchema,
                session=Depends(get_async_session)):
    ...
