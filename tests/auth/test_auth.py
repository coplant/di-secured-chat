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
from src.utils import get_public_key, get_private_key
from tests.conftest import client, async_session_maker


def test_get_public_key():
    response: Response = client.get('/api/auth/login')
    with open(PUBLIC_KEY, 'rb') as file:
        raw_public_key = rsa.PublicKey.load_pkcs1(file.read(), format="DER")
    with open(PRIVATE_KEY, 'rb') as file:
        raw_private_key = rsa.PrivateKey.load_pkcs1(file.read(), format="DER")
    raw_signature = rsa.sign(raw_public_key.save_pkcs1(format="DER"), raw_private_key, HASH_TYPE)
    public_key = base64.b64decode(response.json()['data']['public_key'])
    signature = rsa.sign(public_key, raw_private_key, HASH_TYPE)

    assert raw_public_key == get_public_key()
    assert raw_private_key == get_private_key()

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
            'uid': '41119e27d08d48105c425c1e5102f9626a1b25627eb23da5fce27d791efe3f81',
            'name': 'Администратор',
            'username': 'admin',
            'hashed_password': '$2b$12$8UcA8nUE7nBBp8s6GvkGi.J.Jlt3Wi6UvvsrcUb8tm3gXwv9vwKny',
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


async def test_login(ac: AsyncClient, get_keys):
    server_private_key, server_public_key, user_private_key, user_public_key = get_keys

    # то, что вводит клиент
    raw_user_data = {
        "username": "admin",
        "password": "uZqXYrK3Mu_Fg-7w",
        "uid": "B272CE72-DA23-4D68-AB4F-26ABFD9735CA",
    }
    # то, что отправится после обработки
    encrypted_user_data = {}

    # собираем словарь — зашифровываем уязвимые данные, передаем при помощи base64
    encrypted_user_data["username"] = base64.b64encode(
        rsa.encrypt(raw_user_data["username"].encode(), server_public_key)).decode()
    encrypted_user_data["password"] = base64.b64encode(
        rsa.encrypt(raw_user_data["password"].encode(), server_public_key)).decode()
    encrypted_user_data["uid"] = base64.b64encode(
        rsa.encrypt(hashlib.sha256(raw_user_data["uid"].encode()).hexdigest().encode(), server_public_key)).decode()
    encrypted_user_data["public_key"] = base64.b64encode(
        user_public_key.save_pkcs1(format="DER")).decode()
    encrypted_user_data["signature"] = base64.b64encode(
        rsa.sign(json.dumps(encrypted_user_data).encode(), user_private_key, HASH_TYPE)).decode()
    response = await ac.post(url='/api/auth/login', json=encrypted_user_data)

    token = response.json()['data']['token']
    signature = response.json()['data']['signature']

    assert response.status_code == 200
    assert response.json()['status'] == 'success'
    assert response.json()['data']
    assert rsa.verify(base64.b64decode(token), base64.b64decode(signature), server_public_key) == HASH_TYPE
    return token


async def test_register_user(ac: AsyncClient, get_keys):
    server_private_key, server_public_key, user_private_key, user_public_key = get_keys
    raw_user_data = {
        "username": "new_user",
        "password": "ThatsMyPassword",
        "uid": "0F8AB0AA-1AB3-4839-898D-DFBA43257F45",
        "name": "Olga"
    }
    # то, что отправится после обработки
    encrypted_user_data = {}

    # собираем словарь — зашифровываем уязвимые данные, передаем при помощи base64
    encrypted_user_data["username"] = base64.b64encode(
        rsa.encrypt(raw_user_data["username"].encode(), server_public_key)).decode()
    encrypted_user_data["password"] = base64.b64encode(
        rsa.encrypt(raw_user_data["password"].encode(), server_public_key)).decode()
    encrypted_user_data["uid"] = base64.b64encode(
        rsa.encrypt(hashlib.sha256(raw_user_data["uid"].encode()).hexdigest().encode(), server_public_key)).decode()
    encrypted_user_data["name"] = base64.b64encode(
        rsa.encrypt(raw_user_data["name"].encode(), server_public_key)).decode()
    token = await test_login(ac, get_keys)
    b64_token_to_usr = base64.b64decode(token)
    raw_token = rsa.decrypt(b64_token_to_usr, user_private_key)
    token = rsa.encrypt(raw_token, server_public_key)
    b64_token_to_srv = base64.urlsafe_b64encode(token).decode()
    response = await ac.post(url=f'/api/auth/create-user?token={b64_token_to_srv}', json=encrypted_user_data)
    assert response.status_code == 201

    query = select(User).filter_by(username=raw_user_data["username"])
    async with async_session_maker() as session:
        user = await session.execute(query)
        user = user.scalars().unique().first()

    assert hashlib.sha256(raw_user_data["uid"].encode()).hexdigest() == user.uid
    assert raw_user_data["name"] == user.name
    assert bcrypt.checkpw(raw_user_data["password"].encode(), user.hashed_password.encode()) is True


async def test_valid_logout(ac: AsyncClient, get_keys):
    server_private_key, server_public_key, user_private_key, user_public_key = get_keys
    token = await test_login(ac, get_keys)
    b64_token_to_usr = base64.b64decode(token)
    raw_token = rsa.decrypt(b64_token_to_usr, user_private_key)
    token = rsa.encrypt(raw_token, server_public_key)
    b64_token_to_srv = base64.urlsafe_b64encode(token).decode()
    response = await ac.get(f"/api/auth/logout?token={b64_token_to_srv}")
    assert response.status_code == 200
    assert response.json()['status'] == 'success'
    assert response.json()['details'] == 'logged out'


async def test_invalid_logout(ac: AsyncClient):
    response = await ac.get("/api/auth/logout?token=abc")
    assert response.status_code == 403

