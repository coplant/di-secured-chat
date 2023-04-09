import base64

import pytest
import rsa
from httpx import Response

from src.config import PUBLIC_KEY, PRIVATE_KEY
from tests.conftest import client


def test_get_public_key():
    response: Response = client.get('/api/auth/login')
    with open(PUBLIC_KEY, 'rb') as file:
        raw_public_key = rsa.PublicKey.load_pkcs1(file.read())
    with open(PRIVATE_KEY, 'rb') as file:
        raw_private_key = rsa.PrivateKey.load_pkcs1(file.read())
    raw_signature = rsa.sign(raw_public_key.save_pkcs1("PEM"), raw_private_key, 'SHA-256')
    public_key = base64.b64decode(response.json()['public_key'])
    signature = rsa.sign(public_key, raw_private_key, 'SHA-256')

    assert response.status_code == 200
    assert rsa.PublicKey.load_pkcs1(public_key) == raw_public_key
    assert base64.b64decode(response.json()['signature']) == raw_signature
    assert rsa.verify(public_key, signature, raw_public_key) == 'SHA-256'
    assert signature == raw_signature
