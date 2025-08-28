# main.py

import os
import jwt
import datetime
from typing import Dict, Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Body, Depends, Header, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from passlib.context import CryptContext
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import modal
from pymongo import MongoClient, ASCENDING
from pymongo.database import Database
from bson import ObjectId

# --- Centralized Configuration ---
class Settings(BaseSettings):
    """Manages application settings and secrets from environment variables."""
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding='utf-8', extra='ignore')
    
    JWT_SECRET: str = Field(..., description="Secret key for signing JWTs. MUST be set.")
    MONGO_URI: str = Field("mongodb://localhost:27017/", description="MongoDB connection string.")
    DEFAULT_PROJECT_ID: str = "default_project"
    
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 180

settings = Settings()

# --- Modal Setup ---
image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "fastapi[standard]==0.115.4",
    "pymongo==4.7.2",
    "pydantic==2.7.1",
    "pydantic-settings==2.3.4",
    "passlib[bcrypt]==1.7.4",
    "PyJWT==2.8.0"
)
app = modal.App("wishlist-api", image=image)

# --- Database Connection Management ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage DB connection and ensure indexes on startup."""
    app.mongodb_client = MongoClient(settings.MONGO_URI)
    app.database = app.mongodb_client.moonshop
    # Create a compound index to ensure username is unique per project_id
    app.database.users.create_index([("username", ASCENDING), ("project_id", ASCENDING)], unique=True)
    print("🚀 Database connection established and indexes ensured.")
    yield
    app.mongodb_client.close()
    print("Database connection closed.")

# --- FastAPI App Setup ---
web_app = FastAPI(
    title="Wishlist API with Authentication",
    description="An API to manage items in a wishlist with JWT authentication, supporting multi-tenancy via project_id.",
    lifespan=lifespan
)

web_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security & Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Pydantic Models (Schemas) ---
class UserBase(BaseModel):
    username: str = Field(..., example="user1")
    project_id: str = Field(default=settings.DEFAULT_PROJECT_ID, example="project_alpha")

class UserRegister(UserBase):
    password: str = Field(..., min_length=8, example="password123")

class UserAuth(UserRegister):
    pass

class TokenResponse(BaseModel):
    status: str = "ok"
    access_token: str
    refresh_token: str

class TokenRefreshRequest(BaseModel):
    refresh_token: str

# --- Database Dependency ---
def get_db(request: object) -> Database:
    return request.app.database

# --- Security Helper Functions ---
def create_access_token(username: str, project_id: str) -> str:
    payload = {
        'sub': username,
        'prj': project_id, # Added project_id to token payload
        'iat': datetime.datetime.now(datetime.timezone.utc),
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(username: str, project_id: str) -> str:
    payload = {
        'sub': username,
        'prj': project_id, # Added project_id to token payload
        'iat': datetime.datetime.now(datetime.timezone.utc),
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def get_current_user(Authorization: str = Header(...), db: Database = Depends(get_db)) -> Dict:
    """Decodes access token, extracts user and project, and returns the user document."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token_type, token = Authorization.split()
        if token_type.lower() != 'bearer':
            raise credentials_exception
        
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        username: str = payload.get("sub")
        project_id: str = payload.get("prj") # Extract project_id
        if not username or not project_id:
            raise credentials_exception
            
    except (ExpiredSignatureError, InvalidTokenError, ValueError):
        raise credentials_exception
    
    user = get_user(db, username=username, project_id=project_id)
    if user is None:
        raise credentials_exception
    return user

# --- CRUD (Database Operations) ---
def get_user(db: Database, username: str, project_id: str) -> Optional[Dict]:
    return db.users.find_one({'username': username, 'project_id': project_id})

def create_user(db: Database, user: UserRegister) -> None:
    password_hash = pwd_context.hash(user.password)
    db.users.insert_one({
        'username': user.username, 
        'password_hash': password_hash, 
        'project_id': user.project_id,
        'wishlist': []
    })

def store_refresh_token(db: Database, token: str, username: str, project_id: str) -> None:
    db.refresh_tokens.insert_one({
        'refresh_token': token, 
        'username': username,
        'project_id': project_id
    })

def find_refresh_token(db: Database, token: str) -> Optional[Dict]:
    return db.refresh_tokens.find_one({'refresh_token': token})

def delete_refresh_token(db: Database, token: str) -> None:
    db.refresh_tokens.delete_one({'refresh_token': token})

# --- Authentication Endpoints ---
@web_app.post('/register', tags=["Authentication"], status_code=status.HTTP_201_CREATED)
def register(user: UserRegister, db: Database = Depends(get_db)):
    """Registers a new user within a specific project."""
    if get_user(db, username=user.username, project_id=user.project_id):
        raise HTTPException(status_code=400, detail=f"Username '{user.username}' already registered in project '{user.project_id}'.")
    
    create_user(db, user)
    return {'status': 'ok', 'message': 'User registered successfully.'}

@web_app.post('/authenticate', response_model=TokenResponse, tags=["Authentication"])
def authenticate(user: UserAuth, db: Database = Depends(get_db)):
    """Authenticates a user within a project and returns JWTs."""
    db_user = get_user(db, username=user.username, project_id=user.project_id)
    if not db_user or not pwd_context.verify(user.password, db_user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid username or password for the specified project.")

    access_token = create_access_token(user.username, user.project_id)
    refresh_token = create_refresh_token(user.username, user.project_id)
    store_refresh_token(db, refresh_token, user.username, user.project_id)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)

@web_app.post('/refresh', response_model=TokenResponse, tags=["Authentication"])
def refresh_token(data: TokenRefreshRequest, db: Database = Depends(get_db)):
    """Generates new tokens using a valid refresh token."""
    refresh_token_str = data.refresh_token
    stored_token = find_refresh_token(db, refresh_token_str)
    
    if not stored_token:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")
    
    delete_refresh_token(db, refresh_token_str)
    
    try:
        payload = jwt.decode(refresh_token_str, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        username = payload.get('sub')
        project_id = payload.get('prj') # Extract project_id from the old token
        
        new_access_token = create_access_token(username, project_id)
        new_refresh_token = create_refresh_token(username, project_id)
        
        store_refresh_token(db, new_refresh_token, username, project_id)
        
        return TokenResponse(access_token=new_access_token, refresh_token=new_refresh_token)
        
    except (ExpiredSignatureError, InvalidTokenError):
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

@web_app.post('/logout', tags=["Authentication"], status_code=status.HTTP_204_NO_CONTENT)
def logout(data: TokenRefreshRequest, db: Database = Depends(get_db)):
    """Invalidates a refresh token."""
    delete_refresh_token(db, data.refresh_token)
    return None

# --- Example Protected Endpoint ---
@web_app.get('/wishlist', tags=["Wishlist"])
def get_wishlist(current_user: Dict = Depends(get_current_user)):
    """A protected endpoint that returns the user's wishlist for their project."""
    username = current_user.get("username")
    project_id = current_user.get("project_id")
    wishlist_items = current_user.get("wishlist", [])
    return {
        "status": "ok", 
        "username": username, 
        "project_id": project_id,
        "wishlist": wishlist_items
    }

# --- Mount the FastAPI app with Modal ---
@app.function()
@modal.asgi_app()
def fastapi_app():
    """Serves the FastAPI application."""
    return web_app
