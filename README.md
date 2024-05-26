# fastapi_blog_py
FastAPI application with JWT authentication, user management, and post/comment handling. It is designed to handle asynchronous operations using SQLite database and provides a secure login system with JWT tokens.

### Initial Setup

1. **Clone the repository**: Clone this repository using `git clone`.
2. **Create Virtual Env**: Create a Python Virtual Environment `venv` to download the required dependencies and libraries.
3. **Download Dependencies**: Download the required dependencies into the Virtual Environment `venv` using `pip`.

```shell
git clone https://github.com/grisha765/fastapi_blog_py.git
cd FastAPI_PY
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

### Run Application

1. Start the FastAPI Application: Start the application from the venv virtual environment.

```shell
venv/bin/uvicorn main:app --reload
```

### Features

1. JWT Authentication: Secure login system with JWT tokens.
2. User Management: Register new users, authenticate existing users, and manage user details.
3. Post and Comment Handling: Create, read, and manage posts and comments for authenticated users.
3. Asynchronous Operations: Utilizes asynchronous operations with SQLite for efficient database handling.

### Endpoints

1. `/login`: Endpoint for user login. Requires username and password.
2. `/logout`: Endpoint for user logout. Clears the JWT token.
3. `/register`: Endpoint to register a new user.
4. `/user`: Endpoint to get the details of the authenticated user.
4. `/posts/{user_id}`: Endpoint to get all posts by a specific user.
5. `/posts`: Endpoint to get all posts with pagination support.
5. `/post`: Endpoint to create a new post for the authenticated user.
6. `/comments/{user_id}/{post_id}`: Endpoint to get all comments for a specific post by a specific user.
7. `/comment`: Endpoint to add a comment to a specific post by the authenticated user.

### Models

1. **UserGet**: Model for getting user details.
2. **UserPost**: Model for registering a new user.
3. **UserLogin**: Model for user login.
4. **Token**: Model for JWT token response.
5. **TokenData**: Model for data stored in JWT token.
6. **PostPost**: Model for creating a new post.
7. **CommentGet**: Model for getting comment details.
8. **CommentPost**: Model for creating a new comment.
9. **PostGet**: Model for getting post details.
10. **PostsGet**: Model for getting multiple posts with comments.

### Database Initialization

1. The database is initialized on startup with the necessary tables for users, posts, and comments.
2. Example Usage

***Register a new user***

```shell
curl -X POST "http://localhost:8000/register" -H "Content-Type: application/json" -d '[{"name": "username", "password": "password"}]'
```

***Login***

```shell
curl -X POST "http://localhost:8000/login" -d "username=username&password=password" -H "Content-Type: application/x-www-form-urlencoded"
```

***Create a new post***

```shell
curl -X POST "http://localhost:8000/post" -H "Authorization: Bearer <JWT_TOKEN>" -H "Content-Type: application/json" -d '[{"title": "Post Title", "text": "Post text"}]'
```

***Get all posts by user***

```shell
curl -X GET "http://localhost:8000/posts/1" -H "Authorization: Bearer <JWT_TOKEN>"
```

For more detailed information, please <http://localhost:8000/docs>.
