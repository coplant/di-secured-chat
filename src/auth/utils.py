import base64

import rsa


def decrypt_dict(data: dict, private_key: rsa.PrivateKey) -> dict:
    new_dict = {}
    for key, value in data.items():
        try:
            new_dict[key] = rsa.decrypt(base64.b64decode(value), private_key).decode()
        except rsa.pkcs1.DecryptionError:
            new_dict[key] = value
    return new_dict
