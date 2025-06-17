# modal-JWTauth-demo


---

# Building a Secure Authentication System with MongoDB, JWT, and a Browser Extension Using Modal  
   
In today's digital landscape, secure authentication mechanisms are paramount. Whether you're building a web application, a mobile app, or even a browser extension, ensuring that only authorized users can access certain resources is a critical concern. In this blog post, we'll explore how to create a secure authentication system using **MongoDB**, **JSON Web Tokens (JWT)**, and a **browser extension**, all powered by **Modal**.  
   
## Introduction  
   
We'll walk through the process of building a secure API with user registration and authentication, leveraging MongoDB for data storage and JWT for token-based authentication. We'll also create a simple browser extension that interacts with our API, allowing users to register, log in, and access protected resources.  
   
But first, let's get acquainted with the technologies we'll be using.  
   
## Technologies Used  
   
- **MongoDB**: A NoSQL database renowned for its flexibility and scalability, ideal for storing user data and tokens securely.  
    
- **JSON Web Tokens (JWT)**: An open standard for creating tokens that assert some number of claims, commonly used for authentication and secure data exchange.  
    
- **FastAPI**: A modern, fast (high-performance) web framework for building APIs with Python 3.7+ based on standard Python type hints.  
    
- **Modal**: A cloud function platform that simplifies the deployment and scaling of applications, removing the need to manage underlying infrastructure.  
    
- **Browser Extension**: We'll create a simple browser extension with a user interface for interacting with our API, demonstrating how client applications can utilize our authentication system.  
   
## Prerequisites  
   
Before diving in, ensure you have the following set up:  
   
- A **Modal** account. Sign up at [modal.com](https://modal.com) if you haven't already.  
- Basic knowledge of Python and JavaScript.  
- Familiarity with concepts like APIs, JWT, and browser extensions.  
   
## Setting Up the Backend with FastAPI and MongoDB  
   
### 1. Setting Up the Project Structure  
   
Create a new directory for your project and initialize a Python environment.  
   
```bash  
mkdir jwt-auth-api  
cd jwt-auth-api  
python -m venv venv  
source venv/bin/activate  # On Windows use `venv\Scripts\activate`  
```  
   
### 2. Installing Dependencies  
   
Install the necessary Python packages:  
   
```bash  
pip install fastapi[standard]==0.115.4 pymongo==4.7.2 pydantic==2.7.1 passlib==1.7.4 PyJWT==2.8.0 modal  
```  
   
### 3. The `main.py` File  
   
Create a `main.py` file and paste the following code:  
   
```python  
import os  
import jwt  
import datetime  
from typing import Optional  
from fastapi import FastAPI, HTTPException, Header  
from fastapi.middleware.cors import CORSMiddleware  
from pydantic import BaseModel, Field  
from passlib.context import CryptContext  
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError  
import modal  
from pymongo import MongoClient  
   
# --- Configuration ---  
   
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')  
JWT_ALGORITHM = 'HS256'  
ACCESS_TOKEN_EXPIRE_MINUTES = 15  
REFRESH_TOKEN_EXPIRE_DAYS = 180  # Approximately 6 months  
   
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')  
   
# --- Modal Setup ---  
   
image = modal.Image.debian_slim(python_version="3.12").pip_install(  
    "fastapi[standard]==0.115.4",  
    "pymongo==4.7.2",  
    "pydantic==2.7.1",  
    "passlib==1.7.4",  
    "PyJWT==2.8.0"  
)  
   
app = modal.App("jwt-auth-api", image=image)  
   
# --- FastAPI App Setup ---  
   
web_app = FastAPI(  
    title="JWT Auth API",  
    description="An API with JWT authentication using FastAPI, Modal, and MongoDB.",  
)  
   
web_app.add_middleware(  
    CORSMiddleware,  
    allow_origins=["*"],  
    allow_credentials=True,  
    allow_methods=["*"],  
    allow_headers=["*"],  
)  
   
# --- Set up CryptContext for password hashing ---  
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  
   
# --- Initialize MongoDB client ---  
client = MongoClient(MONGO_URI)  
db = client.auth_db  
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
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
   
def create_refresh_token(username: str) -> str:  
    payload = {  
        'sub': username,  
        'iat': datetime.datetime.utcnow(),  
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  
    }  
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
   
# --- API Endpoints ---  
   
@web_app.post('/register', tags=["Authentication"])  
def register(user: UserRegister):  
    """Registers a new user."""  
    if users_collection.find_one({'username': user.username}):  
        raise HTTPException(status_code=400, detail="User already exists.")  
  
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
    if not db_user or not pwd_context.verify(user.password, db_user['password_hash']):  
        raise HTTPException(status_code=401, detail="Invalid credentials.")  
  
    access_token = create_access_token(user.username)  
    refresh_token = create_refresh_token(user.username)  
  
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
  
        access_token = create_access_token(username)  
        new_refresh_token = create_refresh_token(username)  
  
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
    except Exception:  
        raise HTTPException(status_code=401, detail="Invalid token.")  
   
# --- Mount the FastAPI app with Modal ---  
   
@app.function()  
@modal.asgi_app()  
def fastapi_app():  
    """Serves the FastAPI application."""  
    return web_app  
```  
   
#### Key Components Explained:  
   
- **Modal Setup**: We define an image with the necessary dependencies and create a `Modal` app to deploy our FastAPI application.  
    
- **MongoDB Connection**: Using `pymongo`, we connect to our MongoDB instance to manage user data and refresh tokens.  
    
- **Password Hashing**: Passwords are hashed using `passlib`'s `CryptContext` to ensure they're securely stored.  
    
- **JWT Token Generation**: We have helper functions to create access and refresh tokens, embedding the username and expiration time.  
    
- **API Endpoints**:  
  - `/register`: Allows new users to register.  
  - `/authenticate`: Authenticates users and provides JWT tokens.  
  - `/refresh`: Generates new tokens using a valid refresh token.  
  - `/protected`: A secured endpoint that requires a valid access token.  
   
### 4. Deploying with Modal  
   
With Modal, deploying our application is straightforward. Ensure you've logged in via the CLI:  
   
```bash  
modal token new  
```  
   
Then, run your Modal app:  
   
```bash  
modal run main.py  
```  
   
Modal takes care of building the container, deploying the application, and scaling as needed.  
   
## Creating the Browser Extension  
   
Now, let's create a simple browser extension that interacts with our API.  
   
### 1. The `manifest.json` File  
   
Create a `manifest.json` file to define our browser extension:  
   
```json  
{  
  "manifest_version": 3,  
  "name": "Password Auth Demo",  
  "version": "1.0",  
  "description": "A demo browser extension for JWT authentication",  
  "action": {  
    "default_popup": "popup.html"  
  },  
  "permissions": [  
    "storage"  
  ]  
}  
```  
   
### 2. The `popup.html` File  
   
Create a `popup.html` file for the extension's user interface:  
   
```html  
<!DOCTYPE html>  
<html>  
<head>  
  <title>Password Auth Demo</title>  
  <!-- Inline CSS for simplicity -->  
  <style>  
    /* Your CSS styles here */  
  </style>  
</head>  
<body>  
  <h1>Password Auth</h1>  
  <div class="container">  
    <div id="status" class=""></div>  
    <div id="auth-section">  
      <div class="input-group">  
        <input type="text" id="username" placeholder="Username" autocomplete="username" />  
      </div>  
      <div class="input-group">  
        <input type="password" id="password" placeholder="Password (min 8 chars)" autocomplete="current-password" />  
      </div>  
      <button id="register">Register</button>  
      <button id="login">Login</button>  
      <button id="accessProtected">Access Protected Resource</button>  
      <button id="logout" class="hidden">Logout</button>  
    </div>  
  </div>  
  <script src="popup.js"></script>  
</body>  
</html>  
```  
   
### 3. The `popup.js` File  
   
Create a `popup.js` file for the extension's functionality:  
   
```javascript  
document.addEventListener('DOMContentLoaded', () => {  
  init();  
});  
   
function init() {  
  document.getElementById('register').addEventListener('click', register);  
  document.getElementById('login').addEventListener('click', login);  
  document.getElementById('logout').addEventListener('click', logout);  
  document.getElementById('accessProtected').addEventListener('click', accessProtected);  
  
  // Check if user is logged in  
  checkLoginStatus();  
}  
   
async function checkLoginStatus() {  
  try {  
    const tokens = await getStoredTokens();  
    if (tokens) {  
      showLogoutButton();  
    } else {  
      hideLogoutButton();  
    }  
  } catch {  
    hideLogoutButton();  
  }  
}  
   
function showLogoutButton() {  
  document.getElementById('logout').classList.remove('hidden');  
}  
   
function hideLogoutButton() {  
  document.getElementById('logout').classList.add('hidden');  
}  
   
async function register() {  
  const username = document.getElementById('username').value.trim();  
  const password = document.getElementById('password').value;  
  
  if (!username || !password) {  
    setStatus('Please enter a username and password.', 'error');  
    return;  
  }  
  
  if (password.length < 8) {  
    setStatus('Password must be at least 8 characters long.', 'error');  
    return;  
  }  
  
  try {  
    const response = await fetch('<YOUR_MODAL_APP_URL>/register', {  
      method: 'POST',  
      headers: {  
        'Content-Type': 'application/json'  
      },  
      body: JSON.stringify({  
        username: username,  
        password: password  
      })  
    });  
  
    const result = await response.json();  
    if (response.ok && result.status === 'ok') {  
      localStorage.setItem('username', username);  
      setStatus('Registration successful.', 'success');  
      document.getElementById('password').value = '';  
    } else {  
      setStatus('Registration failed: ' + result.message, 'error');  
    }  
  } catch (error) {  
    setStatus('Registration failed: ' + error.message, 'error');  
  }  
}  
   
async function login() {  
  // Similar to the register function, but hitting the /authenticate endpoint  
}  
   
async function logout() {  
  // Clear tokens and user data  
}  
   
async function accessProtected() {  
  // Use the stored access token to access the protected endpoint  
}  
   
// Helper functions (setStatus, getStoredTokens, storeTokens, etc.)  
```  
   
#### Notes:  
   
- Replace `<YOUR_MODAL_APP_URL>` with the URL where your Modal app is running.  
    
- The extension allows users to register, log in, and access a protected resource. Tokens are stored using the browser's storage API.  
   
### 4. Loading the Extension  
   
To test the extension:  
   
1. Open your browser's extension management page (e.g., `chrome://extensions/` in Chrome).  
2. Enable "Developer mode".  
3. Click "Load unpacked" and select the directory containing your `manifest.json`, `popup.html`, and `popup.js` files.  
   
## How It All Works Together  
   
1. **User Registration**: The user enters a username and password in the extension, which sends a request to the `/register` endpoint. The API hashes the password and stores the user in MongoDB.  
   
2. **User Authentication**: When logging in, the extension sends credentials to the `/authenticate` endpoint. The API verifies the credentials, generates JWT access and refresh tokens, and returns them to the extension.  
   
3. **Accessing Protected Resources**: The extension uses the access token to make authenticated requests to protected endpoints like `/protected`. If the access token is expired, it uses the refresh token to obtain a new access token via the `/refresh` endpoint.  
   
4. **Token Storage and Management**: Tokens are securely stored in the browser's local storage, and the extension handles token expiration and refreshing transparently to the user.  
   
5. **Deployment with Modal**: Modal simplifies deployment by handling containerization and scaling. We define our environment and application in code, and Modal takes care of the rest.  
   
## Advantages of Using Modal  
   
- **Simplicity**: No need to manage servers or infrastructure; focus on writing your application.  
    
- **Scalability**: Modal automatically scales your application based on demand.  
    
- **Cost-Efficiency**: Pay only for the compute resources you use.  
    
- **Speed**: Quick deployment and instant scalability mean your application can be up and running in no time.  
   
## Conclusion  
   
Building a secure authentication system doesn't have to be daunting. By leveraging powerful tools like MongoDB, JWT, FastAPI, and Modal, we can create robust applications that scale seamlessly. Additionally, integrating with client-side applications like browser extensions demonstrates the flexibility of our API.  
   
**Next Steps**:  
   
- **Enhancements**: Add features like email verification, password reset, or multi-factor authentication.  
    
- **Security Audits**: Ensure that your application follows best security practices, such as rate limiting and input validation.  
    
- **Deployment**: Move from a development environment to a production-ready setup, possibly integrating with CI/CD pipelines.  
   
## Resources  
   
- [MongoDB Documentation](https://docs.mongodb.com/)  
- [JWT Introduction](https://jwt.io/introduction)  
- [FastAPI Documentation](https://fastapi.tiangolo.com/)  
- [Modal Documentation](https://modal.com/docs)  
   
---  
   
*Happy coding! Secure your applications and deliver robust solutions with ease.*

---

# modal-JWTauth-demo  
   
---  
   
# Building a Secure Authentication System with MongoDB, JWT, and a Browser Extension Using Modal    
  
In today's digital landscape, secure authentication mechanisms are paramount. Whether you're building a web application, a mobile app, or even a browser extension, ensuring that only authorized users can access certain resources is a critical concern. In this blog post, we'll explore how to create a secure authentication system using **MongoDB**, **JSON Web Tokens (JWT)**, and a **browser extension**, all powered by **Modal**.    
  
## Introduction    
  
We'll walk through the process of building a secure API with user registration and authentication, leveraging MongoDB for data storage and JWT for token-based authentication. We'll also create a simple browser extension that interacts with our API, allowing users to register, log in, and access protected resources.    
  
But first, let's get acquainted with the technologies we'll be using.    
  
## Technologies Used    
  
- **MongoDB**: A NoSQL database renowned for its flexibility and scalability, ideal for storing user data and tokens securely.    
      
- **JSON Web Tokens (JWT)**: An open standard for creating tokens that assert some number of claims, commonly used for authentication and secure data exchange.    
      
- **FastAPI**: A modern, fast (high-performance) web framework for building APIs with Python 3.7+ based on standard Python type hints.    
      
- **Modal**: A cloud function platform that simplifies the deployment and scaling of applications, removing the need to manage underlying infrastructure.    
      
- **Browser Extension**: We'll create a simple browser extension with a user interface for interacting with our API, demonstrating how client applications can utilize our authentication system.    
  
## Prerequisites    
  
Before diving in, ensure you have the following set up:    
  
- A **Modal** account. Sign up at [modal.com](https://modal.com) if you haven't already.    
- Basic knowledge of Python and JavaScript.    
- Familiarity with concepts like APIs, JWT, and browser extensions.    
  
## Setting Up the Backend with FastAPI and MongoDB    
  
### 1. Setting Up the Project Structure    
  
Create a new directory for your project and initialize a Python environment.    
  
```bash    
mkdir jwt-auth-api    
cd jwt-auth-api    
python -m venv venv    
source venv/bin/activate  # On Windows use `venv\Scripts\activate`    
```    
  
### 2. Installing Dependencies    
  
Install the necessary Python packages:    
  
```bash    
pip install fastapi[standard]==0.115.4 pymongo==4.7.2 pydantic==2.7.1 passlib==1.7.4 PyJWT==2.8.0 modal    
```    
  
### 3. The `main.py` File    
  
Create a `main.py` file and paste the following code:    
  
```python    
import os    
import jwt    
import datetime    
from typing import Optional    
from fastapi import FastAPI, HTTPException, Header    
from fastapi.middleware.cors import CORSMiddleware    
from pydantic import BaseModel, Field    
from passlib.context import CryptContext    
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError    
import modal    
from pymongo import MongoClient    
  
# --- Configuration ---    
  
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')    
JWT_ALGORITHM = 'HS256'    
ACCESS_TOKEN_EXPIRE_MINUTES = 15    
REFRESH_TOKEN_EXPIRE_DAYS = 180  # Approximately 6 months    
  
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')    
  
# --- Modal Setup ---    
  
image = modal.Image.debian_slim(python_version="3.12").pip_install(    
    "fastapi[standard]==0.115.4",    
    "pymongo==4.7.2",    
    "pydantic==2.7.1",    
    "passlib==1.7.4",    
    "PyJWT==2.8.0"    
)    
  
app = modal.App("jwt-auth-api", image=image)    
  
# --- FastAPI App Setup ---    
  
web_app = FastAPI(    
    title="JWT Auth API",    
    description="An API with JWT authentication using FastAPI, Modal, and MongoDB.",    
)    
  
web_app.add_middleware(    
    CORSMiddleware,    
    allow_origins=["*"],    
    allow_credentials=True,    
    allow_methods=["*"],    
    allow_headers=["*"],    
)    
  
# --- Set up CryptContext for password hashing ---    
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")    
  
# --- Initialize MongoDB client ---    
client = MongoClient(MONGO_URI)    
db = client.auth_db    
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
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)    
  
def create_refresh_token(username: str) -> str:    
    payload = {    
        'sub': username,    
        'iat': datetime.datetime.utcnow(),    
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)    
    }    
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)    
  
# --- API Endpoints ---    
  
@web_app.post('/register', tags=["Authentication"])    
def register(user: UserRegister):    
    """Registers a new user."""    
    if users_collection.find_one({'username': user.username}):    
        raise HTTPException(status_code=400, detail="User already exists.")    
  
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
    if not db_user or not pwd_context.verify(user.password, db_user['password_hash']):    
        raise HTTPException(status_code=401, detail="Invalid credentials.")    
  
    access_token = create_access_token(user.username)    
    refresh_token = create_refresh_token(user.username)    
  
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
  
        access_token = create_access_token(username)    
        new_refresh_token = create_refresh_token(username)    
  
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
    except Exception:    
        raise HTTPException(status_code=401, detail="Invalid token.")    
  
# --- Mount the FastAPI app with Modal ---    
  
@app.function()    
@modal.asgi_app()    
def fastapi_app():    
    """Serves the FastAPI application."""    
    return web_app    
```    
  
#### Key Components Explained:    
  
- **Modal Setup**: We define an image with the necessary dependencies and create a `Modal` app to deploy our FastAPI application.    
      
- **MongoDB Connection**: Using `pymongo`, we connect to our MongoDB instance to manage user data and refresh tokens.    
      
- **Password Hashing**: Passwords are hashed using `passlib`'s `CryptContext` to ensure they're securely stored.    
      
- **JWT Token Generation**: We have helper functions to create access and refresh tokens, embedding the username and expiration time.    
      
- **API Endpoints**:    
  - `/register`: Allows new users to register.    
  - `/authenticate`: Authenticates users and provides JWT tokens.    
  - `/refresh`: Generates new tokens using a valid refresh token.    
  - `/protected`: A secured endpoint that requires a valid access token.    
  
### 4. Deploying with Modal    
  
With Modal, deploying our application is straightforward. Ensure you've logged in via the CLI:    
  
```bash    
modal token new    
```    
  
Then, run your Modal app:    
  
```bash    
modal run main.py    
```    
  
Modal takes care of building the container, deploying the application, and scaling as needed.    
  
## Creating the Browser Extension    
  
Now, let's create a simple browser extension that interacts with our API.    
  
### 1. The `manifest.json` File    
  
Create a `manifest.json` file to define our browser extension:    
  
```json    
{    
  "manifest_version": 3,    
  "name": "Password Auth Demo",    
  "version": "1.0",    
  "description": "A demo browser extension for JWT authentication",    
  "action": {    
    "default_popup": "popup.html"    
  },    
  "permissions": [    
    "storage"    
  ]    
}    
```    
  
### 2. The `popup.html` File    
  
Create a `popup.html` file for the extension's user interface:    
  
```html    
<!DOCTYPE html>    
<html>    
<head>    
  <title>Password Auth Demo</title>    
  <!-- Inline CSS for simplicity -->    
  <style>    
    /* Your CSS styles here */    
  </style>    
</head>    
<body>    
  <h1>Password Auth</h1>    
  <div class="container">    
    <div id="status" class=""></div>    
    <div id="auth-section">    
      <div class="input-group">    
        <input type="text" id="username" placeholder="Username" autocomplete="username" />    
      </div>    
      <div class="input-group">    
        <input type="password" id="password" placeholder="Password (min 8 chars)" autocomplete="current-password" />    
      </div>    
      <button id="register">Register</button>    
      <button id="login">Login</button>    
      <button id="accessProtected">Access Protected Resource</button>    
      <button id="logout" class="hidden">Logout</button>    
    </div>    
  </div>    
  <script src="popup.js"></script>    
</body>    
</html>    
```    
  
### 3. The `popup.js` File    
  
Create a `popup.js` file for the extension's functionality:    
  
```javascript    
document.addEventListener('DOMContentLoaded', () => {    
  init();    
});    
  
function init() {    
  document.getElementById('register').addEventListener('click', register);    
  document.getElementById('login').addEventListener('click', login);    
  document.getElementById('logout').addEventListener('click', logout);    
  document.getElementById('accessProtected').addEventListener('click', accessProtected);    
  
  // Check if user is logged in    
  checkLoginStatus();    
}    
  
async function checkLoginStatus() {    
  try {    
    const tokens = await getStoredTokens();    
    if (tokens) {    
      showLogoutButton();    
    } else {    
      hideLogoutButton();    
    }    
  } catch {    
    hideLogoutButton();    
  }    
}    
  
function showLogoutButton() {    
  document.getElementById('logout').classList.remove('hidden');    
}    
  
function hideLogoutButton() {    
  document.getElementById('logout').classList.add('hidden');    
}    
  
async function register() {    
  const username = document.getElementById('username').value.trim();    
  const password = document.getElementById('password').value;    
  
  if (!username || !password) {    
    setStatus('Please enter a username and password.', 'error');    
    return;    
  }    
  
  if (password.length < 8) {    
    setStatus('Password must be at least 8 characters long.', 'error');    
    return;    
  }    
  
  try {    
    const response = await fetch('<YOUR_MODAL_APP_URL>/register', {    
      method: 'POST',    
      headers: {    
        'Content-Type': 'application/json'    
      },    
      body: JSON.stringify({    
        username: username,    
        password: password    
      })    
    });    
  
    const result = await response.json();    
    if (response.ok && result.status === 'ok') {    
      localStorage.setItem('username', username);    
      setStatus('Registration successful.', 'success');    
      document.getElementById('password').value = '';    
    } else {    
      setStatus('Registration failed: ' + result.message, 'error');    
    }    
  } catch (error) {    
    setStatus('Registration failed: ' + error.message, 'error');    
  }    
}    
  
async function login() {    
  // Similar to the register function, but hitting the /authenticate endpoint    
}    
  
async function logout() {    
  // Clear tokens and user data    
}    
  
async function accessProtected() {    
  // Use the stored access token to access the protected endpoint    
}    
  
// Helper functions (setStatus, getStoredTokens, storeTokens, etc.)    
```    
  
#### Notes:    
  
- Replace `<YOUR_MODAL_APP_URL>` with the URL where your Modal app is running.    
      
- The extension allows users to register, log in, and access a protected resource. Tokens are stored using the browser's storage API.    
  
### 4. Loading the Extension    
  
To test the extension:    
  
1. Open your browser's extension management page (e.g., `chrome://extensions/` in Chrome).    
2. Enable "Developer mode".    
3. Click "Load unpacked" and select the directory containing your `manifest.json`, `popup.html`, and `popup.js` files.    
  
## How It All Works Together    
  
1. **User Registration**: The user enters a username and password in the extension, which sends a request to the `/register` endpoint. The API hashes the password and stores the user in MongoDB.    
  
2. **User Authentication**: When logging in, the extension sends credentials to the `/authenticate` endpoint. The API verifies the credentials, generates JWT access and refresh tokens, and returns them to the extension.    
  
3. **Accessing Protected Resources**: The extension uses the access token to make authenticated requests to protected endpoints like `/protected`. If the access token is expired, it uses the refresh token to obtain a new access token via the `/refresh` endpoint.    
  
4. **Token Storage and Management**: Tokens are securely stored in the browser's local storage, and the extension handles token expiration and refreshing transparently to the user.    
  
5. **Deployment with Modal**: Modal simplifies deployment by handling containerization and scaling. We define our environment and application in code, and Modal takes care of the rest.    
  
## Advantages of Using Modal    
  
- **Simplicity**: No need to manage servers or infrastructure; focus on writing your application.    
      
- **Scalability**: Modal automatically scales your application based on demand.    
      
- **Cost-Efficiency**: Pay only for the compute resources you use.    
      
- **Speed**: Quick deployment and instant scalability mean your application can be up and running in no time.    
  
## Conclusion    
  
Building a secure authentication system doesn't have to be daunting. By leveraging powerful tools like MongoDB, JWT, FastAPI, and Modal, we can create robust applications that scale seamlessly. Additionally, integrating with client-side applications like browser extensions demonstrates the flexibility of our API.    
  
**Next Steps**:    
  
- **Enhancements**: Add features like email verification, password reset, or multi-factor authentication.    
      
- **Security Audits**: Ensure that your application follows best security practices, such as rate limiting and input validation.    
      
- **Deployment**: Move from a development environment to a production-ready setup, possibly integrating with CI/CD pipelines.    
  
## Resources    
  
- [MongoDB Documentation](https://docs.mongodb.com/)    
- [JWT Introduction](https://jwt.io/introduction)    
- [FastAPI Documentation](https://fastapi.tiangolo.com/)    
- [Modal Documentation](https://modal.com/docs)    
  
---  
   
*Happy coding! Secure your applications and deliver robust solutions with ease.*  
   
---  

## Full Code:

```popup.js
document.addEventListener('DOMContentLoaded', () => {  
  init();  
});  
  
function init() {  
  document.getElementById('register').addEventListener('click', register);  
  document.getElementById('login').addEventListener('click', login);  
  document.getElementById('logout').addEventListener('click', logout);  
  document.getElementById('accessProtected').addEventListener('click', accessProtected);  
  
  // Check if user is logged in  
  checkLoginStatus();  
}  
  
async function checkLoginStatus() {  
  try {  
    const tokens = await getStoredTokens();  
    if (tokens) {  
      showLogoutButton();  
    } else {  
      hideLogoutButton();  
    }  
  } catch {  
    hideLogoutButton();  
  }  
}  
  
function showLogoutButton() {  
  document.getElementById('logout').classList.remove('hidden');  
}  
  
function hideLogoutButton() {  
  document.getElementById('logout').classList.add('hidden');  
}  
  
async function register() {  
  const username = document.getElementById('username').value.trim();  
  const password = document.getElementById('password').value;  
  
  if (!username || !password) {  
    setStatus('Please enter a username and password.', 'error');  
    return;  
  }  
  
  if (password.length < 8) {  
    setStatus('Password must be at least 8 characters long.', 'error');  
    return;  
  }  
  
  // Send username and password to server  
  try {  
    const response = await fetch('https://ranfysvalle02--jwt-auth-api-fastapi-app.modal.run/register', {  
      method: 'POST',  
      headers: {  
        'Content-Type': 'application/json'  
      },  
      body: JSON.stringify({  
        username: username,  
        password: password  
      })  
    });  
  
    const result = await response.json();  
    if (response.ok && result.status === 'ok') {  
      localStorage.setItem('username', username);  
      setStatus('Registration successful.', 'success');  
      document.getElementById('password').value = '';  
    } else {  
      setStatus('Registration failed: ' + result.message, 'error');  
    }  
  } catch (error) {  
    setStatus('Registration failed: ' + error.message, 'error');  
  }  
}  
  
async function login() {  
  const username = document.getElementById('username').value.trim();  
  const password = document.getElementById('password').value;  
  
  if (!username || !password) {  
    setStatus('Please enter your username and password.', 'error');  
    return;  
  }  
  
  try {  
    const response = await fetch('https://ranfysvalle02--jwt-auth-api-fastapi-app.modal.run/authenticate', {  
      method: 'POST',  
      headers: {  
        'Content-Type': 'application/json'  
      },  
      body: JSON.stringify({  
        username: username,  
        password: password  
      })  
    });  
  
    const result = await response.json();  
    if (response.ok && result.status === 'ok') {  
      // Store tokens securely  
      await storeTokens(result.access_token, result.refresh_token);  
      setStatus('Authentication successful.', 'success');  
      showLogoutButton();  
      document.getElementById('password').value = '';  
    } else {  
      setStatus('Authentication failed: ' + result.message, 'error');  
    }  
  } catch (error) {  
    setStatus('Authentication failed: ' + error.message, 'error');  
  }  
}  
  
async function logout() {  
  // Clear tokens and user data  
  await chrome.storage.local.remove('auth_tokens');  
  localStorage.removeItem('username');  
  setStatus('Logged out successfully.', 'success');  
  hideLogoutButton();  
}  
  
async function storeTokens(accessToken, refreshToken) {  
  const tokens = {  
    access_token: accessToken,  
    refresh_token: refreshToken,  
    access_token_expiry: getTokenExpiry(accessToken)  
  };  
  // Store tokens using storage API  
  await chrome.storage.local.set({ 'auth_tokens': tokens });  
}  
  
function getTokenExpiry(token) {  
  const payload = JSON.parse(atob(token.split('.')[1]));  
  return payload.exp * 1000; // Convert to milliseconds  
}  
  
async function getStoredTokens() {  
  return new Promise((resolve, reject) => {  
    chrome.storage.local.get('auth_tokens', (data) => {  
      if (chrome.runtime.lastError) {  
        reject(chrome.runtime.lastError);  
      } else {  
        resolve(data.auth_tokens);  
      }  
    });  
  });  
}  
  
async function getAccessToken() {  
  const tokens = await getStoredTokens();  
  
  if (!tokens) {  
    throw new Error('No tokens found. Please login.');  
  }  
  
  const currentTime = Date.now();  
  
  if (currentTime > tokens.access_token_expiry) {  
    // Access token expired, refresh it  
    const newTokens = await refreshAccessToken(tokens.refresh_token);  
    return newTokens.access_token;  
  } else {  
    return tokens.access_token;  
  }  
}  
  
async function refreshAccessToken(refreshToken) {  
  const response = await fetch('https://ranfysvalle02--jwt-auth-api-fastapi-app.modal.run/refresh', {  
    method: 'POST',  
    headers: {  
      'Content-Type': 'application/json'  
    },  
    body: JSON.stringify({  
      refresh_token: refreshToken  
    })  
  });  
  
  const result = await response.json();  
  if (response.ok && result.status === 'ok') {  
    await storeTokens(result.access_token, result.refresh_token);  
    return {  
      access_token: result.access_token,  
      refresh_token: result.refresh_token  
    };  
  } else {  
    throw new Error('Failed to refresh token: ' + result.message);  
  }  
}  
  
async function accessProtected() {  
  try {  
    const accessToken = await getAccessToken();  
  
    const response = await fetch('https://ranfysvalle02--jwt-auth-api-fastapi-app.modal.run/protected', {  
      method: 'GET',  
      headers: {  
        'Authorization': 'Bearer ' + accessToken  
      }  
    });  
  
    const result = await response.json();  
    if (response.ok && result.status === 'ok') {  
      setStatus(result.message, 'success');  
    } else {  
      setStatus('Failed to access protected resource: ' + result.message, 'error');  
    }  
  } catch (error) {  
    setStatus(error.message, 'error');  
  }  
}  
  
let statusTimeout;  
function setStatus(message, type) {  
  clearTimeout(statusTimeout);  
  const statusDiv = document.getElementById('status');  
  statusDiv.textContent = message;  
  statusDiv.className = '';  
  statusDiv.classList.add(type === 'error' ? 'error' : 'success');  
  statusDiv.classList.add('show');  
  statusTimeout = setTimeout(() => {  
    statusDiv.classList.remove('show');  
  }, 5000);  
}  
```

```popup.html

<!DOCTYPE html>  
<html>  
<head>  
  <title>Password Auth Demo</title>  
  <style>  
    body {  
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;  
      margin: 0;  
      padding: 20px; /* Added padding to the body */  
      width: 360px;  
      min-height: 500px;  
      box-sizing: border-box;  
      background: linear-gradient(to bottom right, #ffffff, #ece9e6);  
      display: flex;  
      flex-direction: column;  
      align-items: center;  
    }  
    .container {  
      width: 100%;  
    }  
    h1 {  
      margin-top: 30px;  
      font-size: 28px;  
      color: #333;  
      text-align: center;  
      animation: fadeInDown 0.5s ease-out;  
    }  
    .input-group {  
      position: relative;  
      margin-bottom: 20px;  
      animation: fadeInUp 0.5s ease-out;  
    }  
    .input-group:last-of-type {  
      margin-bottom: 30px;  
    }  
    input {  
      width: 85%;  
      padding: 15px 20px;  
      font-size: 16px;  
      border: none;  
      border-radius: 30px;  
      box-shadow: 0 3px 6px rgba(0,0,0,0.1);  
      outline: none;  
      transition: all 0.3s ease;  
      background-color: #fff;  
    }  
    input:focus {  
      box-shadow: 0 3px 6px rgba(0,0,0,0.2);  
    }  
    input::placeholder {  
      color: #aaa;  
    }  
    button {  
      width: 100%;  
      padding: 15px 20px;  
      font-size: 18px;  
      color: #fff;  
      background: linear-gradient(135deg, #6e8efb, #a777e3);  
      border: none;  
      border-radius: 30px;  
      cursor: pointer;  
      transition: transform 0.2s ease, box-shadow 0.2s ease;  
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);  
      margin-bottom: 15px;  
    }  
    button:hover {  
      box-shadow: 0 6px 8px rgba(0,0,0,0.15);  
    }  
    button:active {  
      transform: translateY(2px);  
      box-shadow: 0 3px 5px rgba(0,0,0,0.1);  
    }  
    #logout {  
      background: #ff6961;  
      background: linear-gradient(135deg, #ff7e5f, #feb47b);  
    }  
    #accessProtected {  
      background: #24c6dc;  
      background: linear-gradient(135deg, #24c6dc, #514a9d);  
    }  
    #status {  
      margin: 20px 0;  
      padding: 15px;  
      border-radius: 5px;  
      font-size: 16px;  
      text-align: center;  
      opacity: 0;  
      transform: translateY(-10px);  
      transition: opacity 0.3s ease, transform 0.3s ease;  
      max-width: 320px;  
      animation: fadeIn 0.5s ease-out;  
    }  
    #status.show {  
      opacity: 1;  
      transform: translateY(0);  
    }  
    #status.success {  
      background-color: #d4edda;  
      color: #155724;  
      border: 1px solid #c3e6cb;  
    }  
    #status.error {  
      background-color: #f8d7da;  
      color: #721c24;  
      border: 1px solid #f5c6cb;  
    }  
    .hidden {  
      display: none;  
    }  
    @keyframes fadeInUp {  
      from { opacity: 0; transform: translateY(20px); }  
      to { opacity: 1; transform: translateY(0); }  
    }  
    @keyframes fadeInDown {  
      from { opacity: 0; transform: translateY(-20px); }  
      to { opacity: 1; transform: translateY(0); }  
    }  
    @keyframes fadeIn {  
      from { opacity: 0; }  
      to { opacity: 1; }  
    }  
  </style>  
</head>  
<body>  
  <h1>Password Auth</h1>  
  <div class="container">  
    <div id="status" class=""></div>  
    <div id="auth-section">  
      <div class="input-group">  
        <input type="text" id="username" placeholder="Username" autocomplete="username" />  
      </div>  
      <div class="input-group">  
        <input type="password" id="password" placeholder="Password (min 8 chars)" autocomplete="current-password" />  
      </div>  
      <button id="register">Register</button>  
      <button id="login">Login</button>  
      <button id="accessProtected">Access Protected Resource</button>  
      <button id="logout" class="hidden">Logout</button>  
    </div>  
  </div>  
  <script src="popup.js"></script>  
</body>  
</html>

```

```modal-app.py
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
```

---

   
## Appendix: Using the Authentication System Without the Browser Extension  
   
While the browser extension provides a convenient interface for user interaction, our authentication system is built as a RESTful API, making it accessible to any client capable of making HTTP requests. This appendix explores how to use the authentication system without the browser extension, enabling integration with web applications, mobile apps, desktop applications, or direct interaction using tools like `curl` or Postman.  
   
### Interacting with the API Directly  
   
Our FastAPI application exposes several endpoints:  
   
- **POST `/register`**: Register a new user.  
- **POST `/authenticate`**: Authenticate a user and receive JWT tokens.  
- **POST `/refresh`**: Refresh expired access tokens using a refresh token.  
- **GET `/protected`**: Access a protected resource requiring a valid access token.  
   
### Using `curl` to Interact with the API  
   
You can test the API endpoints directly from the command line using `curl`.  
   
#### 1. Registering a New User  
   
```bash  
curl -X POST <YOUR_MODAL_APP_URL>/register \  
   -H 'Content-Type: application/json' \  
   -d '{  
     "username": "newuser",  
     "password": "securepassword"  
   }'  
```  
   
#### 2. Authenticating and Receiving Tokens  
   
```bash  
curl -X POST <YOUR_MODAL_APP_URL>/authenticate \  
   -H 'Content-Type: application/json' \  
   -d '{  
     "username": "newuser",  
     "password": "securepassword"  
   }'  
```  
   
This request returns a JSON response with `access_token` and `refresh_token`. Store these tokens securely for subsequent requests.  
   
#### 3. Accessing a Protected Resource  
   
```bash  
curl -X GET <YOUR_MODAL_APP_URL>/protected \  
   -H 'Authorization: Bearer <ACCESS_TOKEN>'  
```  
   
Replace `<ACCESS_TOKEN>` with the token from the authentication step.  
   
#### 4. Refreshing Tokens  
   
If the access token expires, refresh it using the refresh token:  
   
```bash  
curl -X POST <YOUR_MODAL_APP_URL>/refresh \  
   -H 'Content-Type: application/json' \  
   -d '{  
     "refresh_token": "<REFRESH_TOKEN>"  
   }'  
```  
   
### Integrating with Web Applications  
   
For web applications, you can use JavaScript or any front-end framework to interact with the API.  
   
#### Example Using JavaScript Fetch API  
   
```javascript  
// Register a new user  
fetch('<YOUR_MODAL_APP_URL>/register', {  
  method: 'POST',  
  headers: {  
    'Content-Type': 'application/json'  
  },  
  body: JSON.stringify({  
    username: 'newuser',  
    password: 'securepassword'  
  })  
})  
.then(response => response.json())  
.then(data => console.log('Registration Successful:', data))  
.catch(error => console.error('Error:', error));  
   
// Authenticate and receive tokens  
fetch('<YOUR_MODAL_APP_URL>/authenticate', {  
  method: 'POST',  
  headers: {  
    'Content-Type': 'application/json'  
  },  
  body: JSON.stringify({  
    username: 'newuser',  
    password: 'securepassword'  
  })  
})  
.then(response => response.json())  
.then(data => {  
  // Store tokens in local storage or cookies  
  localStorage.setItem('access_token', data.access_token);  
  localStorage.setItem('refresh_token', data.refresh_token);  
})  
.catch(error => console.error('Error:', error));  
   
// Access protected resource  
fetch('<YOUR_MODAL_APP_URL>/protected', {  
  method: 'GET',  
  headers: {  
    'Authorization': 'Bearer ' + localStorage.getItem('access_token')  
  }  
})  
.then(response => response.json())  
.then(data => console.log('Protected Data:', data))  
.catch(error => console.error('Error:', error));  
```  
   
### Mobile Application Integration  
   
For mobile apps, use native HTTP client libraries to interact with the API.  
   
#### Example in Swift (iOS)  
   
```swift  
import Foundation  
   
let url = URL(string: "<YOUR_MODAL_APP_URL>/authenticate")!  
var request = URLRequest(url: url)  
request.httpMethod = "POST"  
request.addValue("application/json", forHTTPHeaderField: "Content-Type")  
   
let parameters = ["username": "newuser", "password": "securepassword"]  
request.httpBody = try? JSONSerialization.data(withJSONObject: parameters)  
   
let task = URLSession.shared.dataTask(with: request) { data, response, error in  
    if let data = data {  
        let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: [])  
        print("Response: \(String(describing: jsonResponse))")  
    } else if let error = error {  
        print("Error: \(error)")  
    }  
}  
   
task.resume()  
```  
   
#### Example in Kotlin (Android)  
   
```kotlin  
val client = OkHttpClient()  
val json = """  
{  
  "username": "newuser",  
  "password": "securepassword"  
}  
""".trimIndent()  
   
val body = RequestBody.create(MediaType.parse("application/json"), json)  
val request = Request.Builder()  
    .url("<YOUR_MODAL_APP_URL>/authenticate")  
    .post(body)  
    .build()  
   
client.newCall(request).enqueue(object : Callback {  
    override fun onFailure(call: Call, e: IOException) {  
        println("Error: $e")  
    }  
  
    override fun onResponse(call: Call, response: Response) {  
        println("Response: ${response.body()?.string()}")  
    }  
})  
```  
   
### Testing with Postman  
   
Postman allows you to interact with the API endpoints without writing code.  
   
#### Steps:  
   
1. **Register a User**:  
   - Method: `POST`  
   - URL: `<YOUR_MODAL_APP_URL>/register`  
   - Headers: `Content-Type: application/json`  
   - Body (raw JSON):  
     ```json  
     {  
       "username": "newuser",  
       "password": "securepassword"  
     }  
     ```  
   
2. **Authenticate**:  
   - Method: `POST`  
   - URL: `<YOUR_MODAL_APP_URL>/authenticate`  
   - Same headers and body format as registration.  
   - Extract the `access_token` and `refresh_token` from the response.  
   
3. **Access Protected Resource**:  
   - Method: `GET`  
   - URL: `<YOUR_MODAL_APP_URL>/protected`  
   - Headers:  
     - `Authorization: Bearer <ACCESS_TOKEN>`  
   
4. **Refresh Token**:  
   - Method: `POST`  
   - URL: `<YOUR_MODAL_APP_URL>/refresh`  
   - Headers: `Content-Type: application/json`  
   - Body:  
     ```json  
     {  
       "refresh_token": "<REFRESH_TOKEN>"  
     }  
     ```  
   
### Desktop Application Integration  
   
For desktop applications, use libraries suited to your programming language.  
   
#### Example in Python  
   
```python  
import requests  
   
# Authenticate  
response = requests.post(  
    '<YOUR_MODAL_APP_URL>/authenticate',  
    json={'username': 'newuser', 'password': 'securepassword'}  
)  
tokens = response.json()  
access_token = tokens['access_token']  
   
# Access protected resource  
protected_response = requests.get(  
    '<YOUR_MODAL_APP_URL>/protected',  
    headers={'Authorization': f'Bearer {access_token}'}  
)  
print(protected_response.json())  
```  
   
### Security Best Practices  
   
- **Secure Token Storage**: Store tokens securely. In mobile and desktop apps, consider using secure storage mechanisms provided by the operating system.  
- **HTTPS**: Always use HTTPS to communicate with the API to prevent man-in-the-middle attacks.  
- **Token Handling**: Implement token refresh logic to handle expired access tokens.  
- **Error Handling**: Gracefully handle errors and provide appropriate feedback to the user without exposing sensitive information.  
   
### Deploying Without Modal  
   
Although we used Modal for deployment, you can deploy the FastAPI app on other platforms:  
   
- **Docker**: Containerize the application and deploy it to any Docker-compatible infrastructure.  
- **Cloud Platforms**: Deploy to AWS (e.g., using Elastic Beanstalk or ECS), Google Cloud Platform, or Azure.  
- **Heroku**: Suitable for smaller applications with free tiers available.  
- **On-Premises**: Run the application on your own server.  
   
#### Running Locally  
   
To run the application locally:  
   
1. Ensure MongoDB is running and accessible.  
2. Update `MONGO_URI` in `main.py` if necessary.  
3. Install Uvicorn if not already installed:  
  
   ```bash  
   pip install uvicorn  
   ```  
   
4. Run the FastAPI app:  
  
   ```bash  
   uvicorn main:web_app --reload  
   ```  
   
### Advantages of API-First Approach  
   
- **Flexibility**: Clients can be built using different technologies (web, mobile, desktop).  
- **Scalability**: The API can scale independently of the client applications.  
- **Reusability**: The same API serves multiple clients, reducing development effort.  
   
### Conclusion  
   
Our authentication system is a robust, scalable solution that can be integrated into various types of applications. By decoupling the client from the server, we provide flexibility in how users interact with our services. Whether through a browser extension, web app, or mobile application, the core authentication logic remains consistent.  
   
---  
   
*With this appendix, you're now equipped to leverage the authentication system across multiple platforms. Embrace the versatility of RESTful APIs and build secure, scalable applications tailored to your users' needs.*
