from fastapi import FastAPI, HTTPException, Depends, status, Request, Response, Security
from fastapi.responses import JSONResponse 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional
from fastapi_jwt import JwtAccessBearer, JwtAuthorizationCredentials
from datetime import timedelta

db_file = "data.db"

app = FastAPI(
    title="FastAPI_PY"
)

# Secret key for JWT
SECRET_KEY = "123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

jwt_access = JwtAccessBearer(secret_key=SECRET_KEY, algorithm=ALGORITHM)

tokenUrl="login"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=tokenUrl)

users = [
    {"id":1, "name":"Grisha", "role":"admin", "pass": "123"},
    {"id":2, "name":"Dima", "role":"user", "pass": "1234"},
    {"id":3, "name":"Pasha", "role":"mute", "pass": "1235"}
    ]

posts = [
    {"id":1, "posts":[
        {"id":1, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Dima", "text":"text1"},
            {"id": 2, "name":"Dima", "text":"text2"},
        ]},
        {"id":2, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Dima", "text":"text3"},
            {"id": 2, "name":"Dima", "text":"text4"},
        ]},
        {"id":3, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Dima", "text":"text5"},
            {"id": 2, "name":"Dima", "text":"text6"},
        ]}
        ]
    },
    {"id":2, "posts":[
        {"id":1, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Grisha", "text":"text1"},
            {"id": 2, "name":"Grisha", "text":"text2"},
        ]},
        {"id":2, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Grisha", "text":"text3"},
            {"id": 2, "name":"Grisha", "text":"text4"},
        ]},
        {"id":3, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Grisha", "text":"text5"},
            {"id": 2, "name":"Grisha", "text":"text6"},
        ]}
        ]
    },
    {"id":3, "posts":[
        {"id":1, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Pasha", "text":"text1"},
            {"id": 2, "name":"Pasha", "text":"text2"},
        ]},
        {"id":2, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Pasha", "text":"text3"},
            {"id": 2, "name":"Pasha", "text":"text4"},
        ]},
        {"id":3, "title":"title", "text":"text", "comments": [
            {"id": 1, "name":"Pasha", "text":"text5"},
            {"id": 2, "name":"Pasha", "text":"text6"},
        ]}
        ]
    }
]

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
    text: str =  Field(json_schema_extra={"example": "Example text"})

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

class Posts_get(BaseModel):
    id: int = Field(ge=0)
    posts: List[PostGet]

# функция авторизации
def authenticate_user(name: str, password: str):
    for user in users:
        if user['name'] == name and user['pass'] == password:
            return user
    return None

# создание jwt токена
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    if expires_delta is not None:
        to_encode = data.copy()
        to_encode.update({"exp": expires_delta.total_seconds()})
        return jwt_access.create_access_token(subject=to_encode)
    else:
        return jwt_access.create_access_token(subject=data)

# логин пользователя
@app.post(f"/{tokenUrl}", response_model=Token)
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
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

# чтение куки и добавления его в заголовок авторизации
@app.middleware("http")
async def add_cookie_to_request(request: Request, call_next):
    token = request.cookies.get("access_token")
    if token:
        request.headers.__dict__["_list"].append(
            (b"authorization", f"Bearer {token}".encode())
        )
    response = await call_next(request)
    return response

# разлогин пользователя
@app.get("/logout", response_class=JSONResponse)
async def logout_for_access_token(response: Response):
    response = JSONResponse(content={"message": "Successfully logged out"})
    response.delete_cookie(key="access_token")
    return response

# получение авторизованного пользователя
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
    for user in users:
        if user["id"] == user_id:
            return {"id":user["id"], "name":user["name"], "role":user["role"]}

# добавление пользователя по user_id
# а также создаётся posts для него
@app.post("/register")
async def add_register_user(add_user: List[UserPost]):
    max_id = max((user["id"] for user in users), default=0) + 1
    for user in add_user:
        user_model = UserGet(id=max_id, role="user", **user.model_dump())
        user = {"id": max_id, "name": user_model.name, "role":user_model.role, "pass": user_model.password}
        posts.append({"id": max_id, "posts": []})
        users.append(user)
        return {"status": 200, "data": user}

# изменение имени авторизованного пользователя
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
    for user in users:
        if user["id"] == user_id:
            user["name"] = new_name
            return {"status": 200, "new_name": new_name}

# получение постов по user_id
@app.get("/posts/{user_id}", response_model=List[PostGet])
async def get_api_user_posts(user_id: int):
    for post in posts:
        if post["id"] == user_id:
            return post["posts"]
    raise HTTPException(status_code=404, detail="Posts not found for user")

# получение всех постов и комментариев под ним
@app.get("/posts", response_model=List[Posts_get])
async def get_api_posts(limit: int = 5, offset: int = 0):
    return posts[offset:][:limit]

# проверка и создание новых постов для авторизованных пользователей
@app.post("/post")
async def add_login_user_post(add_posts: List[PostPost], credentials: JwtAuthorizationCredentials = Security(jwt_access)):
    new_post_models = []
    user_id: int = credentials["id"]
    username: str = credentials["name"]
    role: str = credentials["role"]
    if username is None or user_id is None or role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    for post_data in add_posts:
        try:
            max_id = max((post['id'] for category in posts for post in category['posts']), default=0) + 1
            new_post_model = PostGet(id=max_id, **post_data.model_dump(), comments=[])
            new_post_models.append(new_post_model)
        except ValidationError as e:
            raise ValueError({"status": 422, "data": "Validation error", "details": e.errors()})
    for item in posts:
        if item['id'] == user_id:
            for new_post in new_post_models:
                item['posts'].append(new_post.model_dump())
            return {"status": 200, "data": item['posts']}
    else:
        raise HTTPException(status_code=404, detail=f"No post list found with id: {user_id}")

# получение комментариев от отпределённого поста пользователя
@app.get("/comments/{user_id}/{post_id}", response_model=List[CommentGet])
async def comments_get(user_id: int, post_id: int):
    for post in posts:
        if post["id"] == user_id:
            for comments in post["posts"]:
                if comments["id"] == post_id:
                    return comments["comments"]

# отправка комментариев от авторизированных пользователей под определнный пост определенного пользователя
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

    for user_posts in posts:
        if user_posts["id"] == user_id:
            for post in user_posts["posts"]:
                if post["id"] == user_post_id:
                    max_id = max((comment['id'] for comment in post['comments']), default=0) + 1
                    new_comment_model = CommentGet(id=max_id, name=username, text=add_comment.text)
                    post["comments"].append(new_comment_model.model_dump())
                    return {"status": 200, "data": post["comments"]}
    
    raise HTTPException(status_code=404, detail=f"No post found with id: {post_id}")



