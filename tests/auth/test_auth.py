import base64
import hashlib
import json
from datetime import datetime

import pytest
import rsa
from httpx import Response, AsyncClient
from sqlalchemy import insert, select

from src.auth.models import User, Role
from src.config import PUBLIC_KEY, PRIVATE_KEY, BASE_DIR
from src.utils import get_public_key, get_private_key
from tests.conftest import client, async_session_maker


def test_get_public_key():
    response: Response = client.get('/api/auth/login')
    with open(PUBLIC_KEY, 'rb') as file:
        raw_public_key = rsa.PublicKey.load_pkcs1(file.read())
    with open(PRIVATE_KEY, 'rb') as file:
        raw_private_key = rsa.PrivateKey.load_pkcs1(file.read())
    raw_signature = rsa.sign(raw_public_key.save_pkcs1("PEM"), raw_private_key, 'SHA-256')
    public_key = base64.b64decode(response.json()['public_key'])
    signature = rsa.sign(public_key, raw_private_key, 'SHA-256')

    assert raw_public_key == get_public_key()
    assert raw_private_key == get_private_key()

    assert response.status_code == 200
    assert rsa.PublicKey.load_pkcs1(public_key) == raw_public_key
    assert base64.b64decode(response.json()['signature']) == raw_signature
    assert rsa.verify(public_key, signature, raw_public_key) == 'SHA-256'
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
            'id': 1,
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
        stmt = insert(User).values(**admin_data)
        await session.execute(stmt)
        await session.commit()

        query = select(User)
        result = await session.execute(query)
        expected_user = User(**admin_data)
        actual_user = result.scalars().first()
        assert expected_user.id == actual_user.id
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


async def test_login(ac: AsyncClient):
    # то, что вводит клиент
    raw_user_data = {
        "username": "admin",
        "password": "uZqXYrK3Mu_Fg-7w",
        "uid": "B272CE72-DA23-4D68-AB4F-26ABFD9735CA",
    }
    # то, что отправится
    encrypted_user_data = {}

    # получаем ключи клиента
    with open(BASE_DIR / "keys" / "user_private.pem", "rb") as file:
        user_private_key = rsa.PrivateKey.load_pkcs1(file.read())
    with open(BASE_DIR / "keys" / "user_public.pem", "rb") as file:
        user_public_key = rsa.PublicKey.load_pkcs1(file.read())

    # собираем словарь — зашифровываем уязвимые данные, передаем при помощи base64
    encrypted_user_data["username"] = base64.b64encode(
        rsa.encrypt(raw_user_data["username"].encode(), get_public_key())).decode()
    encrypted_user_data["password"] = base64.b64encode(
        rsa.encrypt(raw_user_data["password"].encode(), get_public_key())).decode()
    encrypted_user_data["uid"] = base64.b64encode(
        rsa.encrypt(hashlib.sha256(raw_user_data["uid"].encode()).digest(), get_public_key())).decode()
    encrypted_user_data["public_key"] = base64.b64encode(
        user_public_key.save_pkcs1("PEM")).decode()
    encrypted_user_data["signature"] = base64.b64encode(
        rsa.sign(json.dumps(encrypted_user_data).encode(), user_private_key, "SHA-256")).decode()
    response = await ac.post(url='/api/auth/login', json=encrypted_user_data)
    assert response.status_code == 200
