import aiosqlite
from fastapi import FastAPI, HTTPException, Depends, status, Request, Response, Security
from fastapi.responses import JSONResponse 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Optional
from fastapi_jwt import JwtAccessBearer, JwtAuthorizationCredentials
from datetime import timedelta

db_file = "data.db"

app = FastAPI(title="FastAPI_PY")

# Secret key for JWT
SECRET_KEY = "123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

jwt_access = JwtAccessBearer(secret_key=SECRET_KEY, algorithm=ALGORITHM)

tokenUrl = "login"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=tokenUrl)

class UserGet(BaseModel):
    id: int = Field(ge=0)
    name: str
    role: str
    password: str

class UserPost(BaseModel):
    name: str = Field(json_schema_extra={"example": "Example name"})
    password: str = Field(json_schema_extra={"example": "Example password"})

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    id: int
    name: Optional[str]
    role: str

class PostPost(BaseModel):
    title: str = Field(max_length=20, json_schema_extra={"example": "Example title"})
    text: str = Field(json_schema_extra={"example": "Example text"})

class CommentGet(BaseModel):
    id: int
    name: str
    text: str

class CommentPost(BaseModel):
    text: str

class PostGet(BaseModel):
    id: int = Field(ge=0)
    title: str = Field(max_length=20)
    text: str
    comments: List[CommentGet]

class PostsGet(BaseModel):
    id: int = Field(ge=0)
    posts: List[PostGet]

# Функция для инициализации базы данных
async def init_db():
    async with aiosqlite.connect(db_file) as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                name TEXT NOT NULL,
                                role TEXT NOT NULL,
                                password TEXT NOT NULL
                            )''')
        await db.execute('''CREATE TABLE IF NOT EXISTS posts (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user_id INTEGER,
                                title TEXT NOT NULL,
                                text TEXT NOT NULL,
                                FOREIGN KEY(user_id) REFERENCES users(id)
                            )''')
        await db.execute('''CREATE TABLE IF NOT EXISTS comments (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                post_id INTEGER,
                                name TEXT NOT NULL,
                                text TEXT NOT NULL,
                                FOREIGN KEY(post_id) REFERENCES posts(id)
                            )''')
        await db.commit()

@app.on_event("startup")
async def startup():
    await init_db()

# Функция авторизации пользователя
async def authenticate_user(name: str, password: str):
    async with aiosqlite.connect(db_file) as db:
        cursor = await db.execute("SELECT * FROM users WHERE name = ? AND password = ?", (name, password))
        user = await cursor.fetchone()
        if user:
            return {"id": user[0], "name": user[1], "role": user[2], "pass": user[3]}
    return None

# Создание JWT токена
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    if expires_delta is not None:
        to_encode = data.copy()
        to_encode.update({"exp": expires_delta.total_seconds()})
        return jwt_access.create_access_token(subject=to_encode)
    else:
        return jwt_access.create_access_token(subject=data)

# Логин пользователя
@app.post(f"/{tokenUrl}", response_model=Token)
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"id": user['id'], "name": user['name'], "role": user['role']},
                                       expires_delta=access_token_expires)
    response = JSONResponse(content={"access_token": access_token, "token_type": "bearer"})
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

# Чтение куки и добавления его в заголовок авторизации
@app.middleware("http")
async def add_cookie_to_request(request: Request, call_next):
    token = request.cookies.get("access_token")
    if token:
        request.headers.__dict__["_list"].append(
            (b"authorization", f"Bearer {token}".encode())
        )
    response = await call_next(request)
    return response

# Разлогин пользователя
@app.get("/logout", response_class=JSONResponse)
async def logout_for_access_token(response: Response):
    response = JSONResponse(content={"message": "Successfully logged out"})
    response.delete_cookie(key="access_token")
    return response

# Получение авторизованного пользователя
@app.get("/user")
async def get_login_user(credentials: JwtAuthorizationCredentials = Security(jwt_access)):
    user_id: int = credentials["id"]
    username: str = credentials["name"]
    role: str = credentials["role"]
    if username is None or user_id is None or role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )   
    async with aiosqlite.connect(db_file) as db:
        cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = await cursor.fetchone()
        if user:
            return {"id": user[0], "name": user[1], "role": user[2]}
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

# Добавление пользователя
@app.post("/register")
async def add_register_user(add_user: List[UserPost]):
    async with aiosqlite.connect(db_file) as db:
        for user in add_user:
            await db.execute("INSERT INTO users (name, role, password) VALUES (?, ?, ?)", (user.name, "user", user.password))
            cursor = await db.execute("SELECT last_insert_rowid()")
            user_id = await cursor.fetchone()
            await db.commit()
            return {"status": 200, "data": {"id": user_id[0], "name": user.name, "role": "user", "password": user.password}}

# Изменение имени авторизованного пользователя
@app.post("/user")
async def change_name_login_user(new_name: str, credentials: JwtAuthorizationCredentials = Security(jwt_access)):
    user_id: int = credentials["id"]
    username: str = credentials["name"]
    role: str = credentials["role"]
    if username is None or user_id is None or role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    async with aiosqlite.connect(db_file) as db:
        await db.execute("UPDATE users SET name = ? WHERE id = ?", (new_name, user_id))
        await db.commit()
        return {"status": 200, "new_name": new_name}

# Получение постов по user_id
@app.get("/posts/{user_id}", response_model=List[PostGet])
async def get_api_user_posts(user_id: int):
    async with aiosqlite.connect(db_file) as db:
        cursor = await db.execute("SELECT * FROM posts WHERE user_id = ?", (user_id,))
        posts = await cursor.fetchall()
        if posts:
            result = []
            for post in posts:
                cursor = await db.execute("SELECT * FROM comments WHERE post_id = ?", (post[0],))
                comments = await cursor.fetchall()
                result.append(PostGet(id=post[0], title=post[2], text=post[3], comments=[CommentGet(id=comment[0], name=comment[2], text=comment[3]) for comment in comments]))
            return result
        else:
            raise HTTPException(status_code=404, detail="Posts not found for user")

# Получение всех постов и комментариев под ними
@app.get("/posts", response_model=List[PostGet])
async def get_api_posts(limit: int = 5, offset: int = 0):
    async with aiosqlite.connect(db_file) as db:
        cursor = await db.execute("SELECT * FROM posts LIMIT ? OFFSET ?", (limit, offset))
        posts = await cursor.fetchall()
        result = []
        for post in posts:
            cursor = await db.execute("SELECT * FROM comments WHERE post_id = ?", (post[0],))
            comments = await cursor.fetchall()
            result.append(PostGet(id=post[0], title=post[2], text=post[3], comments=[CommentGet(id=comment[0], name=comment[2], text=comment[3]) for comment in comments]))
        return result

# Проверка и создание новых постов для авторизованных пользователей
@app.post("/post")
async def add_login_user_post(add_posts: List[PostPost], credentials: JwtAuthorizationCredentials = Security(jwt_access)):
    user_id: int = credentials["id"]
    username: str = credentials["name"]
    role: str = credentials["role"]
    if username is None or user_id is None or role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    async with aiosqlite.connect(db_file) as db:
        for post_data in add_posts:
            await db.execute("INSERT INTO posts (user_id, title, text) VALUES (?, ?, ?)", (user_id, post_data.title, post_data.text))
        await db.commit()
        cursor = await db.execute("SELECT * FROM posts WHERE user_id = ?", (user_id,))
        posts = await cursor.fetchall()
        result = []
        for post in posts:
            cursor = await db.execute("SELECT * FROM comments WHERE post_id = ?", (post[0],))
            comments = await cursor.fetchall()
            result.append(PostGet(id=post[0], title=post[2], text=post[3], comments=[CommentGet(id=comment[0], name=comment[2], text=comment[3]) for comment in comments]))
        return {"status": 200, "data": result}

# Получение комментариев от определенного поста пользователя
@app.get("/comments/{user_id}/{post_id}", response_model=List[CommentGet])
async def comments_get(user_id: int, post_id: int):
    async with aiosqlite.connect(db_file) as db:
        cursor = await db.execute("SELECT * FROM posts WHERE user_id = ? AND id = ?", (user_id, post_id))
        post = await cursor.fetchone()
        if post:
            cursor = await db.execute("SELECT * FROM comments WHERE post_id = ?", (post[0],))
            comments = await cursor.fetchall()
            return [CommentGet(id=comment[0], name=comment[2], text=comment[3]) for comment in comments]
        else:
            raise HTTPException(status_code=404, detail="Post not found")

# Отправка комментариев от авторизованных пользователей под определенный пост определенного пользователя
@app.post("/comment")
async def add_comment(user_post_id: int, post_id: int, add_comment: CommentPost, credentials: JwtAuthorizationCredentials = Security(jwt_access)):
    user_id: int = credentials["id"]
    username: str = credentials["name"]
    role: str = credentials["role"]

    if username is None or user_id is None or role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    async with aiosqlite.connect(db_file) as db:
        cursor = await db.execute("SELECT * FROM posts WHERE user_id = ? AND id = ?", (user_post_id, post_id))
        post = await cursor.fetchone()
        if post:
            await db.execute("INSERT INTO comments (post_id, name, text) VALUES (?, ?, ?)", (post[0], username, add_comment.text))
            await db.commit()
            cursor = await db.execute("SELECT * FROM comments WHERE post_id = ?", (post[0],))
            comments = await cursor.fetchall()
            return {"status": 200, "data": [CommentGet(id=comment[0], name=comment[2], text=comment[3]) for comment in comments]}
        else:
            raise HTTPException(status_code=404, detail=f"No post found with id: {post_id}")
