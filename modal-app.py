# main.py  
  
import os  
import jwt  
import datetime  
from typing import Dict, Optional  
  
from fastapi import FastAPI, HTTPException, Body, Depends, Header, status  
from fastapi.responses import JSONResponse  
from fastapi.middleware.cors import CORSMiddleware  
from pydantic import BaseModel, Field  
from passlib.context import CryptContext  
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError  
import modal  
from pymongo import MongoClient  
from bson.objectid import ObjectId  
  
# --- Configuration ---  
  
# Load environment variables or set default values  
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')  
JWT_ALGORITHM = 'HS256'  
ACCESS_TOKEN_EXPIRE_MINUTES = 15  
REFRESH_TOKEN_EXPIRE_DAYS = 180  # Approximately 6 months  
  
# MongoDB configuration  
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')  
  
# --- Modal Setup ---  
  
# Define the image with necessary Python libraries.  
image = modal.Image.debian_slim(python_version="3.12").pip_install(  
    "fastapi[standard]==0.115.4",  
    "pymongo==4.7.2",  
    "pydantic==2.7.1",  
    "passlib==1.7.4",  
    "PyJWT==2.8.0"  
)  
  
# Create a Modal App instance.  
app = modal.App("jwt-auth-api", image=image)  
  
# --- FastAPI App Setup ---  
  
# Create the FastAPI app.  
web_app = FastAPI(  
    title="JWT Auth API",  
    description="An API with JWT authentication using FastAPI, Modal, and MongoDB.",  
)  
  
# Allow CORS for development purposes  
web_app.add_middleware(  
    CORSMiddleware,  
    allow_origins=["*"],  # For development, consider specifying origins  
    allow_credentials=True,  
    allow_methods=["*"],  
    allow_headers=["*"],  
)  
  
# --- Set up CryptContext for password hashing ---  
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  
  
# --- Initialize MongoDB client ---  
client = MongoClient(MONGO_URI)  
db = client.auth_db  # Use a dedicated database for authentication  
users_collection = db.users  
refresh_tokens_collection = db.refresh_tokens  
  
# --- Pydantic Models ---  
  
class UserRegister(BaseModel):  
    username: str = Field(..., example="user1")  
    password: str = Field(..., min_length=8, example="password123")  
  
class UserAuth(BaseModel):  
    username: str = Field(..., example="user1")  
    password: str = Field(..., example="password123")  
  
class TokenResponse(BaseModel):  
    status: str  
    access_token: str  
    refresh_token: str  
  
class TokenRefreshRequest(BaseModel):  
    refresh_token: str  
  
class ProtectedResponse(BaseModel):  
    status: str  
    message: str  
  
# --- Helper Functions ---  
  
def create_access_token(username: str) -> str:  
    payload = {  
        'sub': username,  
        'iat': datetime.datetime.utcnow(),  
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  
    }  
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
    return token  
  
def create_refresh_token(username: str) -> str:  
    payload = {  
        'sub': username,  
        'iat': datetime.datetime.utcnow(),  
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  
    }  
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
    return token  
  
# --- API Endpoints ---  
  
@web_app.post('/register', tags=["Authentication"])  
def register(user: UserRegister):  
    """Registers a new user."""  
    if not user.username or not user.password:  
        raise HTTPException(status_code=400, detail="Username and password are required.")  
  
    if len(user.password) < 8:  
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")  
  
    if users_collection.find_one({'username': user.username}):  
        raise HTTPException(status_code=400, detail="User already exists.")  
  
    # Hash the password for secure storage  
    password_hash = pwd_context.hash(user.password)  
  
    users_collection.insert_one({  
        'username': user.username,  
        'password_hash': password_hash  
    })  
  
    return {'status': 'ok', 'message': 'User registered successfully.'}  
  
@web_app.post('/authenticate', response_model=TokenResponse, tags=["Authentication"])  
def authenticate(user: UserAuth):  
    """Authenticates a user and returns JWT tokens."""  
    db_user = users_collection.find_one({'username': user.username})  
    if not db_user:  
        raise HTTPException(status_code=404, detail="User not found.")  
  
    if not pwd_context.verify(user.password, db_user['password_hash']):  
        raise HTTPException(status_code=401, detail="Invalid credentials.")  
  
    # Generate tokens  
    access_token = create_access_token(user.username)  
    refresh_token = create_refresh_token(user.username)  
  
    # Store refresh token  
    refresh_tokens_collection.insert_one({  
        'refresh_token': refresh_token,  
        'username': user.username  
    })  
  
    return {  
        'status': 'ok',  
        'access_token': access_token,  
        'refresh_token': refresh_token  
    }  
  
@web_app.post('/refresh', response_model=TokenResponse, tags=["Authentication"])  
def refresh_token(data: TokenRefreshRequest):  
    """Generates new access and refresh tokens."""  
    stored_token = refresh_tokens_collection.find_one({'refresh_token': data.refresh_token})  
  
    if not stored_token:  
        raise HTTPException(status_code=400, detail="Invalid refresh token.")  
  
    try:  
        payload = jwt.decode(data.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  
        username = payload.get('sub')  
  
        # Generate new tokens  
        access_token = create_access_token(username)  
        new_refresh_token = create_refresh_token(username)  
  
        # Update refresh tokens  
        refresh_tokens_collection.delete_one({'refresh_token': data.refresh_token})  
        refresh_tokens_collection.insert_one({  
            'refresh_token': new_refresh_token,  
            'username': username  
        })  
  
        return {  
            'status': 'ok',  
            'access_token': access_token,  
            'refresh_token': new_refresh_token  
        }  
  
    except ExpiredSignatureError:  
        raise HTTPException(status_code=400, detail="Refresh token expired.")  
    except InvalidTokenError:  
        raise HTTPException(status_code=400, detail="Invalid refresh token.")  
    except Exception as e:  
        raise HTTPException(status_code=400, detail=str(e))  
  
@web_app.get('/protected', response_model=ProtectedResponse, tags=["Protected"])  
def protected(Authorization: str = Header(None)):  
    """A protected endpoint that requires a valid access token."""  
    if not Authorization:  
        raise HTTPException(status_code=401, detail="Missing Authorization header.")  
  
    try:  
        token_type, token = Authorization.split()  
        if token_type != 'Bearer':  
            raise HTTPException(status_code=401, detail="Invalid token type.")  
  
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  
        username = payload.get('sub')  
  
        return {'status': 'ok', 'message': f'Hello, {username}!'}  
  
    except ExpiredSignatureError:  
        raise HTTPException(status_code=401, detail="Access token expired.")  
    except Exception as e:  
        raise HTTPException(status_code=401, detail=str(e))  
  
# --- Mount the FastAPI app with Modal ---  
  
@app.function()  
@modal.asgi_app()  
def fastapi_app():  
    """Serves the FastAPI application."""  
    return web_app  