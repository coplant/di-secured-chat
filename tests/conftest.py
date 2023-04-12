import asyncio
import os
from typing import AsyncGenerator

import pytest
import rsa
from fastapi.testclient import TestClient
from httpcore import HTTPProxy
from httpx import AsyncClient, Proxy
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from src.database import get_async_session, Base
from src.config import (DB_HOST_TEST, DB_NAME_TEST, DB_PASS_TEST, DB_PORT_TEST,
                        DB_USER_TEST, BASE_DIR)
from src.main import app as application
from src.utils import RSA

# DATABASE
DATABASE_URL_TEST = f"postgresql+asyncpg://{DB_USER_TEST}:{DB_PASS_TEST}@{DB_HOST_TEST}:{DB_PORT_TEST}/{DB_NAME_TEST}"

engine_test = create_async_engine(DATABASE_URL_TEST)
async_session_maker = async_sessionmaker(engine_test, expire_on_commit=False)
Base.metadata.bind = engine_test


async def override_get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session


application.dependency_overrides[get_async_session] = override_get_async_session


@pytest.fixture(autouse=True, scope='session')
async def prepare_database():
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# SETUP
@pytest.fixture(scope='session')
def event_loop(request):
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


client = TestClient(application)


# os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8888'
# proxies = Proxy(url='http://127.0.0.1:8888')


@pytest.fixture(scope="session")
async def ac() -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(app=application, base_url="http://test", ) as ac:
        yield ac


@pytest.fixture(scope="session")
async def get_keys():
    with open(BASE_DIR / "keys" / "user_private.der", "rb") as file:
        user_private_key = rsa.PrivateKey.load_pkcs1(file.read(), format="DER")
    with open(BASE_DIR / "keys" / "user_public.der", "rb") as file:
        user_public_key = rsa.PublicKey.load_pkcs1(file.read(), format="DER")

    server_public_key = RSA.get_public_key()
    server_private_key = RSA.get_private_key()

    return server_private_key, server_public_key, user_private_key, user_public_key
