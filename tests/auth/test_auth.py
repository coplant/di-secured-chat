import base64
import hashlib
import json
from datetime import datetime

import bcrypt
import pytest
import rsa
from httpx import Response, AsyncClient
from sqlalchemy import insert, select

from src.auth.models import User, Role
from src.config import PUBLIC_KEY, PRIVATE_KEY, BASE_DIR, HASH_TYPE
from src.utils import RSA, get_current_user
from tests.auth.utils import get_token_from_client
from tests.conftest import client, async_session_maker


def check_signature(raw: dict, public_key: rsa.PublicKey):
    signature = raw.get("signature")
    data = raw.get("data")
    return RSA.verify_signature(json.dumps(data).encode(), base64.b64decode(signature), public_key)


def test_get_public_key():
    response: Response = client.get('/api/auth/login')
    with open(PUBLIC_KEY, 'rb') as file:
        raw_public_key = rsa.PublicKey.load_pkcs1(file.read(), format="DER")
    with open(PRIVATE_KEY, 'rb') as file:
        raw_private_key = rsa.PrivateKey.load_pkcs1(file.read(), format="DER")
    raw_signature = rsa.sign(raw_public_key.save_pkcs1(format="DER"), raw_private_key, HASH_TYPE)
    public_key = base64.b64decode(response.json()['data']['public_key'])
    signature = rsa.sign(public_key, raw_private_key, HASH_TYPE)

    assert raw_public_key == RSA.get_public_key()
    assert raw_private_key == RSA.get_private_key()

    assert response.status_code == 200
    assert rsa.PublicKey.load_pkcs1(public_key, format="DER") == raw_public_key
    assert base64.b64decode(response.json()['data']['signature']) == raw_signature
    assert rsa.verify(public_key, signature, raw_public_key) == HASH_TYPE
    assert signature == raw_signature


async def test_add_roles():
    async with async_session_maker() as session:
        roles_data = [
            {'id': 100, 'name': 'admin'},
            {'id': 0, 'name': 'user'}
        ]
        stmt = insert(Role).values(roles_data)
        await session.execute(stmt)
        await session.commit()

        query = select(Role)
        result = await session.execute(query)
        items = [{"id": item.id, "name": item.name} for item in result.scalars().all()]
        assert items == [
            {'id': 100, 'name': 'admin'},
            {'id': 0, 'name': 'user'}
        ], "Roles have not been added"


async def test_add_admin():
    async with async_session_maker() as session:
        admin_data = {
            'uid': 'f1a082a1ff4c1beae32891b4297cae4120f2ee94a2bf6b3b219ef0ad3549cf83',
            'name': 'Администратор',
            'username': 'admin',
            'hashed_password': '$2b$12$dUyyyO13yyyoEJBrGWund.ZuT2dOkvBydCRCehEmc5ir1xCJ2Eu9O',
            'has_changed_password': True,
            'logged_at': datetime.utcnow(),
            'created_at': datetime.utcnow(),
            'changed_at': datetime.utcnow(),
            'role_id': 100,
            'is_active': True
        }
        session.add(User(**admin_data))
        await session.commit()

        query = select(User)
        result = await session.execute(query)
        expected_user = User(**admin_data)
        actual_user = result.scalars().first()
        assert expected_user.uid == actual_user.uid
        assert expected_user.name == actual_user.name
        assert expected_user.username == actual_user.username
        assert expected_user.hashed_password == actual_user.hashed_password
        assert expected_user.has_changed_password == actual_user.has_changed_password
        assert expected_user.logged_at == actual_user.logged_at
        assert expected_user.created_at == actual_user.created_at
        assert expected_user.changed_at == actual_user.changed_at
        assert expected_user.role_id == actual_user.role_id
        assert expected_user.is_active == actual_user.is_active


async def test_login(ac: AsyncClient, get_keys, data=None):
    server_private_key, server_public_key, user_private_key, user_public_key = get_keys

    # то, что вводит клиент
    if not data:
        data = {
            "payload": {
                "username": "admin",
                "password": "kxAf_f_qGfM5-kTv",
                "uid": "CCE94688-C176-4D12-8115-A96CEC9B809F",
                "public_key": base64.b64encode(user_public_key.save_pkcs1(format="DER")).decode(),
            }
        }
    signature = base64.b64encode(rsa.sign(json.dumps(data).encode(), user_private_key, HASH_TYPE)).decode()
    to_send = {"data": data, "signature": signature}
    to_send = json.dumps(to_send)
    encrypted_msg = RSA.encrypt(to_send.encode(), server_public_key)

    # собираем словарь — зашифровываем уязвимые данные, передаем при помощи base64
    response = await ac.post(url='/api/auth/login',
                             content=encrypted_msg,
                             headers={"Content-Type": 'application/octet-stream'})

    decrypted = json.loads(RSA.decrypt(response.content, user_private_key))
    is_valid = check_signature(decrypted, server_public_key)
    assert response.status_code == 200
    assert decrypted['data']['data']
    assert is_valid is True
    assert decrypted['data']['status'] == 'success'
    token = decrypted['data']['data']['token']
    return token


async def test_register_user(ac: AsyncClient, get_keys, data=None):
    server_private_key, server_public_key, user_private_key, user_public_key = get_keys
    if data is None:
        data = {
            "payload": {
                "username": "new_user",
                "password": "ThatsMyPassword",
                "uid": "0F8AB0AA-1AB3-4839-898D-DFBA43257F45",
                "name": "Olga"
            },
            "token": await test_login(ac, get_keys)
        }

    # собираем словарь — зашифровываем уязвимые данные, передаем при помощи base64
    # data["token"] = await test_login(ac, get_keys)
    signature = base64.b64encode(rsa.sign(json.dumps(data).encode(), user_private_key, HASH_TYPE)).decode()
    to_send = {"data": data, "signature": signature}
    to_send = json.dumps(to_send)
    encrypted_msg = RSA.encrypt(to_send.encode(), server_public_key)
    response = await ac.post(url='/api/auth/create-user',
                             content=encrypted_msg,
                             headers={"Content-Type": 'application/octet-stream'})

    decrypted = json.loads(RSA.decrypt(response.content, user_private_key))
    is_valid = check_signature(decrypted, server_public_key)
    assert response.status_code == 201
    assert is_valid is True
    assert decrypted["data"]["status"] == "success"
    assert decrypted["data"]["details"]

    query = select(User).filter_by(username=data["payload"]["username"])
    async with async_session_maker() as session:
        user = await session.execute(query)
        user = user.scalars().unique().first()

    assert hashlib.sha256(data["payload"]["uid"].encode()).hexdigest() == user.uid
    assert data["payload"]["name"] == user.name
    assert bcrypt.checkpw(data["payload"]["password"].encode(), user.hashed_password.encode()) is True


async def test_valid_logout(ac: AsyncClient, get_keys, data=None):
    server_private_key, server_public_key, user_private_key, user_public_key = get_keys
    if data is None:
        data = {
            "payload": {},
            "token": await test_login(ac, get_keys)
        }
    signature = base64.b64encode(rsa.sign(json.dumps(data).encode(), user_private_key, HASH_TYPE)).decode()
    to_send = {"data": data, "signature": signature}
    to_send = json.dumps(to_send)
    encrypted_msg = RSA.encrypt(to_send.encode(), server_public_key)
    response = await ac.post(url="/api/auth/logout",
                             content=encrypted_msg,
                             headers={"Content-Type": "application/octet-stream"})
    assert response.status_code == 200
    decrypted = json.loads(RSA.decrypt(response.content, user_private_key))
    is_valid = check_signature(decrypted, server_public_key)
    assert is_valid is True
    assert decrypted["data"]["status"] == "success"
    assert decrypted["data"]["details"] == "logged out"


async def test_change_password(ac: AsyncClient, get_keys):
    server_private_key, server_public_key, user_private_key, user_public_key = get_keys
    raw_user_data = {
        "password": "MyNewPassword",
    }
    # то, что отправится после обработки
    encrypted_user_data = {
        "password": base64.b64encode(
            rsa.encrypt(raw_user_data["password"].encode(), server_public_key)).decode()
    }

    # собираем словарь — зашифровываем уязвимые данные, передаем при помощи base64
    token = await test_login(ac, get_keys)
    token = get_token_from_client(token, get_keys)
    response = await ac.patch(url=f'/api/auth/change-password?token={token}', json=encrypted_user_data)
    assert response.status_code == 200
    assert response.json()['status'] == 'success'
    assert response.json()['details']

    token = await test_login(ac, get_keys, raw_user_data={
        "username": "admin",
        "password": "MyNewPassword",
        "uid": "B272CE72-DA23-4D68-AB4F-26ABFD9735CA",
    })
    token = get_token_from_client(token, get_keys)
    token = rsa.decrypt(base64.urlsafe_b64decode(token), RSA.get_private_key())
    query = select(User).filter_by(hashed_token=hashlib.sha256(token).hexdigest())
    async with async_session_maker() as session:
        result = await session.execute(query)
    user = result.scalars().unique().first()
    assert bcrypt.checkpw(raw_user_data["password"].encode(), user.hashed_password.encode()) is True
