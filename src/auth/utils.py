import base64
from enum import Enum

import rsa
from fastapi import HTTPException
from starlette import status


class Roles(Enum):
    ADMIN = 100
    USER = 0


def decrypt_dict(data: dict, private_key: rsa.PrivateKey):
    new_dict = {}
    for key, value in data.items():
        try:
            new_dict[key] = rsa.decrypt(base64.b64decode(value), private_key).decode()
        except rsa.pkcs1.DecryptionError:
            new_dict[key] = value
        except ValueError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid signature")
    return new_dict
