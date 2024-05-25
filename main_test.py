import pytest
from httpx import AsyncClient, ASGITransport
from main import app

@pytest.mark.asyncio
async def test_get_user():
    transport = ASGITransport(app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/users/1")
    assert response.status_code == 200
    assert response.json() == [{"id": 1, "name": "Grisha", "role": "admin"}]

@pytest.mark.asyncio
async def test_add_user():
    transport = ASGITransport(app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        new_user = [{"name": "Ivan", "role": "user"}]
        response = await ac.post("/users", json=new_user)
    assert response.status_code == 200
    data = response.json()["data"]
    assert data[0]["name"] == "Ivan"
    assert data[0]["role"] == "user"

@pytest.mark.asyncio
async def test_change_user_name():
    transport = ASGITransport(app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        new_name = {"new_name": "Ivan"}
        response = await ac.post("/users/1", json=new_name)
    assert response.status_code == 200
    assert response.json() == {"status": 200, "new_name": "Ivan"}

@pytest.mark.asyncio
async def test_get_user_posts():
    transport = ASGITransport(app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/posts/1")
    assert response.status_code == 200
    assert len(response.json()) == 3

@pytest.mark.asyncio
async def test_get_posts():
    transport = ASGITransport(app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/posts")
    assert response.status_code == 200
    assert len(response.json()) <= 5

@pytest.mark.asyncio
async def test_add_post():
    transport = ASGITransport(app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        new_posts = [{"title": "New title", "text": "New text"}]
        response = await ac.post("/post", params={"user_id": 1}, json=new_posts)
    assert response.status_code == 200
    data = response.json()["data"]
    assert any(post["title"] == "New title" for post in data)
