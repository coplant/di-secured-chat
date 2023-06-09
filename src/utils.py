import base64
import binascii
import hashlib
import json

import rsa
from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.requests import Request
from starlette.websockets import WebSocket

from src.auth.models import User
from src.auth.schemas import RequestSchema
from src.config import PUBLIC_KEY, PRIVATE_KEY, HASH_TYPE, DECRYPTION_CHUNK_SIZE
from src.database import async_session_maker, get_async_session


# RSA Keys
class RSA:
    DECRYPTION_CHUNK_SIZE = DECRYPTION_CHUNK_SIZE
    ENCRYPTION_CHUNK_SIZE = DECRYPTION_CHUNK_SIZE - 11

    @staticmethod
    def get_public_key() -> rsa.PublicKey:
        if PUBLIC_KEY.is_file():
            with open(PUBLIC_KEY, "rb") as file:
                public_key = rsa.PublicKey.load_pkcs1(file.read(), format="DER")
            return public_key

    @staticmethod
    def get_private_key() -> rsa.PrivateKey:
        if PRIVATE_KEY.is_file():
            with open(PRIVATE_KEY, "rb") as file:
                private_key = rsa.PrivateKey.load_pkcs1(file.read(), format="DER")
            return private_key

    @staticmethod
    def get_keys() -> (rsa.PublicKey, rsa.PrivateKey):
        public_key = RSA.get_public_key()
        private_key = RSA.get_private_key()
        return public_key, private_key

    @staticmethod
    def setup_keys() -> (rsa.PublicKey, rsa.PrivateKey):
        public_key, private_key = rsa.newkeys(1024)
        with open(PUBLIC_KEY, "wb") as file:
            file.write(public_key.save_pkcs1(format="DER"))
        with open(PRIVATE_KEY, "wb") as file:
            file.write(private_key.save_pkcs1(format="DER"))
        return public_key, private_key

    # encrypt plaintext in chunks
    @staticmethod
    def encrypt(plaintext: bytes, public_key: rsa.PublicKey):
        ciphertext = b''
        for i in range(0, len(plaintext), RSA.ENCRYPTION_CHUNK_SIZE):
            chunk = plaintext[i:i + RSA.ENCRYPTION_CHUNK_SIZE]
            encrypted_chunk = rsa.encrypt(chunk, public_key)
            ciphertext += encrypted_chunk
        return ciphertext

    # decrypt ciphertext in chunks
    @staticmethod
    def decrypt(ciphertext: bytes, private_key: rsa.PrivateKey):
        plaintext = b''
        for i in range(0, len(ciphertext), RSA.DECRYPTION_CHUNK_SIZE):
            chunk = ciphertext[i:i + RSA.DECRYPTION_CHUNK_SIZE]
            decrypted_chunk = rsa.decrypt(chunk, private_key)
            plaintext += decrypted_chunk
        return plaintext

    # is valid signature
    @staticmethod
    def verify_signature(message: bytes, signature: bytes, public_key: rsa.PublicKey):
        try:
            return rsa.verify(message, signature, public_key) == HASH_TYPE
        except rsa.pkcs1.VerificationError:
            return False


async def parse_body(request: Request):
    data: bytes = await request.body()
    return data


async def get_current_user(token: bytes, session, websocket: WebSocket = None):
    try:
        query = select(User).filter_by(hashed_token=hashlib.sha256(token).hexdigest())
        result = await session.execute(query)
        user = result.scalars().unique().one()
        return user
    except Exception as err:
        print(err)
        if websocket:
            await websocket.close(code=status.WS_1006_ABNORMAL_CLOSURE)
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


async def get_user_by_token(encrypted: bytes = Depends(parse_body),
                            server_private_key: rsa.PrivateKey = Depends(RSA.get_private_key),
                            session: AsyncSession = Depends(get_async_session)):
    try:
        decrypted = RequestSchema.parse_obj(json.loads(RSA.decrypt(encrypted, server_private_key)))
        user = await get_current_user(decrypted.data.token.encode(), session)
        return decrypted, user
    except Exception:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def validate_signature(decrypted, server_private_key, user_public_key):
    is_valid = True
    if not is_valid:
        try:
            is_valid = RSA.verify_signature(decrypted.data.json().encode(),
                                            base64.b64decode(decrypted.signature),
                                            user_public_key)
        except (binascii.Error,):
            data = {
                "status": "error",
                "data": None,
                "details": "invalid signature"
            }
            encrypted = prepare_encrypted(data, server_private_key, user_public_key)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)
    if not is_valid:
        data = {
            "status": "error",
            "data": None,
            "details": "invalid signature"
        }
        encrypted = prepare_encrypted(data, server_private_key, user_public_key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=encrypted)


def prepare_encrypted(data: dict, from_private_key: rsa.PrivateKey, to_public_key: rsa.PublicKey):
    signature = base64.b64encode(rsa.sign(json.dumps(data).encode(), from_private_key, HASH_TYPE)).decode()
    to_send = {"data": data, "signature": signature}
    to_send = json.dumps(to_send)
    return RSA.encrypt(to_send.encode(), to_public_key)
