import base64

import rsa

from tests.conftest import get_keys


def get_token_from_client(raw_token, get_keys):
    server_private_key, server_public_key, user_private_key, user_public_key = get_keys
    b64_token_to_usr = base64.b64decode(raw_token)
    raw_token = rsa.decrypt(b64_token_to_usr, user_private_key)
    token = rsa.encrypt(raw_token, server_public_key)
    return base64.urlsafe_b64encode(token).decode()
