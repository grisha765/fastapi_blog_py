import pytest
import asyncio
from httpx import AsyncClient
from fastapi import status
from fastapi.testclient import TestClient
from main import app, init_db  # предполагая, что ваш код находится в файле main.py

@pytest.fixture(scope="module")
def anyio_backend():
    return 'asyncio'

@pytest.fixture(scope="module")
async def initialize_db():
    await init_db()
    yield
    # You can add any teardown code here if necessary

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
async def async_client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.mark.anyio
async def test_register_user(async_client: AsyncClient, initialize_db):
    response = await async_client.post("/register", json=[{"name": "testuser", "password": "testpass"}])
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["data"]["name"] == "testuser"

@pytest.mark.anyio
async def test_login_user(async_client: AsyncClient):
    response = await async_client.post("/login", data={"username": "testuser", "password": "testpass"})
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()

@pytest.mark.anyio
async def test_get_user(async_client: AsyncClient):
    login_response = await async_client.post("/login", data={"username": "testuser", "password": "testpass"})
    token = login_response.json()["access_token"]
    response = await async_client.get("/user", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "testuser"

@pytest.mark.anyio
async def test_add_post(async_client: AsyncClient):
    login_response = await async_client.post("/login", data={"username": "testuser", "password": "testpass"})
    token = login_response.json()["access_token"]
    response = await async_client.post("/post", json=[{"title": "Test Post", "text": "This is a test post"}], headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == 200

@pytest.mark.anyio
async def test_get_posts(async_client: AsyncClient):
    response = await async_client.get("/posts")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) > 0

@pytest.mark.anyio
async def test_logout_user(async_client: AsyncClient):
    login_response = await async_client.post("/login", data={"username": "testuser", "password": "testpass"})
    token = login_response.json()["access_token"]
    response = await async_client.get("/logout", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Successfully logged out"
