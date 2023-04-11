import base64
import hashlib

import rsa
from fastapi import Query, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.models import User
from src.config import PUBLIC_KEY, PRIVATE_KEY, HASH_TYPE
from src.database import get_async_session


# RSA Keys
def get_public_key() -> rsa.PublicKey:
    if PUBLIC_KEY.is_file():
        with open(PUBLIC_KEY, "rb") as file:
            public_key = rsa.PublicKey.load_pkcs1(file.read(), format="DER")
        return public_key


def get_private_key() -> rsa.PrivateKey:
    if PRIVATE_KEY.is_file():
        with open(PRIVATE_KEY, "rb") as file:
            private_key = rsa.PrivateKey.load_pkcs1(file.read(), format="DER")
        return private_key


def get_keys() -> (rsa.PublicKey, rsa.PrivateKey):
    public_key = get_public_key()
    private_key = get_private_key()
    return public_key, private_key


def setup_keys() -> (rsa.PublicKey, rsa.PrivateKey):
    public_key, private_key = rsa.newkeys(1024)
    with open(PUBLIC_KEY, "wb") as file:
        file.write(public_key.save_pkcs1(format="DER"))
    with open(PRIVATE_KEY, "wb") as file:
        file.write(private_key.save_pkcs1(format="DER"))
    return public_key, private_key


# is valid signature
def is_valid_signature(message, signature, public_key):
    try:
        return rsa.verify(message, signature, public_key) == HASH_TYPE
    except rsa.pkcs1.VerificationError:
        return False


async def get_current_user(token: str = Query(...),
                           session: AsyncSession = Depends(get_async_session)):
    try:
        token = rsa.decrypt(base64.urlsafe_b64decode(token), get_private_key())
        query = select(User).filter_by(hashed_token=hashlib.sha256(token).hexdigest())
        result = await session.execute(query)
        user = result.scalars().unique().first()
        return user
    except Exception:
        raise HTTPException(status_code=403, detail="invalid token")

#     token = secrets.token_hex(32)
#     user.hashed_token = hashlib.sha256(token.encode()).hexdigest()
#     user.logged_at = datetime.utcnow()
#     user.public_key = encrypted_user.public_key
#     session.add(user)
#     await session.commit()
#     encrypted_token = rsa.encrypt(token.encode(), user_public_key)
